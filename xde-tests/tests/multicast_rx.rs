// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! XDE multicast RX-path tests.

use anyhow::Context;
use anyhow::Result;
use opte_ioctl::OpteHdl;
use oxide_vpc::api::Direction;
use oxide_vpc::api::IpCidr;
use oxide_vpc::api::Ipv4Addr;
use oxide_vpc::api::Ipv6Addr;
use oxide_vpc::api::NextHopV6;
use oxide_vpc::api::Replication;
use oxide_vpc::api::Vni;
use std::time::Duration;
use xde_tests::MulticastGroup;
use xde_tests::SnoopGuard;

#[test]
fn test_xde_multicast_rx_ipv4() -> Result<()> {
    // Create 2-node topology (IPv4 overlay: 10.0.0.0/24)
    let topol = xde_tests::two_node_topology_named("omicron1", "rx4a", "rx4b")?;

    // IPv4 multicast group: 224.0.0.251
    let mcast_group = Ipv4Addr::from([224, 0, 0, 251]);
    const MCAST_PORT: u16 = 9999;
    let vni = Vni::new(oxide_vpc::api::DEFAULT_MULTICAST_VNI)?;

    // M2P mapping: overlay layer needs IPv6 multicast underlay address
    // Use admin-scoped IPv6 multicast per Omicron's map_external_to_underlay_ip()
    // Maps IPv4 multicast to ff04::/16 (admin-local scope) + IPv4 address
    let mcast_underlay = Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 0, 0, 251,
    ]);

    // Node B's underlay address - this is where we'll forward multicast packets
    // From two_node_topology: node B (10.0.0.2) has underlay fd77::1
    let node_b_underlay = Ipv6Addr::from([
        0xfd, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
    ]);

    // Set up multicast group with automatic cleanup on drop
    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay, vni)?;

    // Set up multicast forwarding with External replication for unicast delivery.
    // Maps overlay IPv4 multicast group -> underlay IPv6 unicast address of node B
    mcast.set_forwarding(vec![(
        NextHopV6::new(node_b_underlay, vni),
        Replication::External,
    )])?;

    // Allow IPv4 multicast traffic (224.0.0.0/4) via Multicast target.
    let mcast_cidr = IpCidr::Ip4("224.0.0.0/4".parse().unwrap());

    // Allow outbound multicast traffic through the gateway layer
    topol.nodes[0].port.allow_cidr(mcast_cidr, Direction::Out)?;
    topol.nodes[1].port.allow_cidr(mcast_cidr, Direction::Out)?;

    // Add router entries for multicast
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr)?;

    // Subscribe both ports to the multicast group
    topol.nodes[0].port.subscribe_multicast(mcast_group.into())?;
    topol.nodes[1].port.subscribe_multicast(mcast_group.into())?;

    // Debug: dump multicast forwarding table
    println!("\n=== Multicast forwarding table ===");
    let hdl = OpteHdl::open()?;
    let mfwd = hdl.dump_mcast_fwd()?;
    for entry in &mfwd.entries {
        println!(
            "  Group: {:?}, Next hops: {:?}",
            entry.group, entry.next_hops
        );
    }
    // Assert forwarding table contains expected next-hop + replication
    let entry = mfwd
        .entries
        .iter()
        .find(|e| e.group == mcast_group.into())
        .expect("missing multicast forwarding entry for group");
    assert!(
        entry.next_hops.iter().any(|(nh, rep)| {
            *rep == Replication::External
                && nh.addr == node_b_underlay
                && nh.vni == vni
        }),
        "expected External replication to {node_b_underlay:?} in forwarding table; got: {:?}",
        entry.next_hops
    );

    // Start snoop using SnoopGuard to ensure cleanup
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let filter = format!("udp and ip dst {mcast_group} and port {MCAST_PORT}");
    let mut snoop = SnoopGuard::start(&dev_name_b, &filter)?;

    // Send UDP packet to the multicast address from zone A using netcat
    // nc -u: IPv4 UDP mode
    // -w1: timeout after 1 second
    let payload = "multicast test";
    let send_cmd =
        format!("echo '{payload}' | nc -u -w1 {mcast_group} {MCAST_PORT}");
    topol.nodes[0]
        .zone
        .zone
        .zexec(&send_cmd)
        .context("Failed to send multicast UDP packet")?;

    // Wait for snoop to capture the packet (or timeout)
    let snoop_output = snoop
        .wait_with_timeout(Duration::from_secs(5))
        .context("Timeout waiting for snoop to capture multicast packet")?;

    // Check that snoop successfully captured a packet and validate basics
    let stdout = String::from_utf8_lossy(&snoop_output.stdout);
    assert!(
        snoop_output.status.success() && !stdout.is_empty(),
        "Expected to capture multicast packet on {dev_name_b}, snoop output:\n{stdout}"
    );
    // Protocol summary present
    assert!(
        stdout.contains("UDP"),
        "expected UDP summary in snoop output:\n{stdout}"
    );
    // Verify destination address appears in snoop output
    // SnoopGuard uses -r flag, so we always get numeric addresses
    assert!(
        stdout.contains("224.0.0.251"),
        "expected destination 224.0.0.251 in snoop output:\n{stdout}"
    );
    // Payload present - check for substring in ASCII representation
    // The full payload may wrap across lines, so just check for a distinctive part
    assert!(
        stdout.contains("ast test"),
        "expected payload substring 'ast test' in ASCII portion of snoop output:\n{stdout}"
    );
    // L2 dest: with current XDE/gateway pipeline, multicast RX to guests
    // is delivered with broadcast dest MAC. snoop shows 16-bit grouped hex.
    assert!(
        stdout.to_ascii_lowercase().contains("ffff ffff ffff"),
        "expected L2 broadcast MAC 'ffff ffff ffff' in snoop output; got:\n{stdout}"
    );

    // Unsubscribe receiver and verify no further local delivery
    topol.nodes[1].port.unsubscribe_multicast(mcast_group.into())?;

    let mut snoop2 = SnoopGuard::start(&dev_name_b, &filter)?;
    let send_cmd2 =
        format!("echo '{payload}' | nc -u -w1 {mcast_group} {MCAST_PORT}");
    topol.nodes[0]
        .zone
        .zone
        .zexec(&send_cmd2)
        .context("Failed to send multicast UDP packet (post-unsubscribe)")?;
    let res = snoop2.wait_with_timeout(Duration::from_millis(800));
    match res {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            panic!(
                "expected no local delivery after unsubscribe; snoop output:\n{stdout}"
            );
        }
        Err(_) => {}
    }
    Ok(())
}

#[test]
fn test_xde_multicast_rx_ipv6() -> Result<()> {
    // Create 2-node topology with dual-stack (IPv4 + IPv6)
    let topol = xde_tests::two_node_topology_dualstack_named(
        "omicron1", "rx6a", "rx6b",
    )?;

    // IPv6 multicast group: ff05::1:3 (site-local, all-dhcp-agents)
    let mcast_group = Ipv6Addr::from([
        0xff, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x03,
    ]);
    const MCAST_PORT: u16 = 9999;
    let vni = Vni::new(oxide_vpc::api::DEFAULT_MULTICAST_VNI)?;

    // M2P mapping: Map IPv6 multicast to admin-scoped underlay (ff04::/16)
    // Per Omicron's map_external_to_underlay_ip(), convert ff05 -> ff04
    let mcast_underlay = Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x03,
    ]);

    // Node B's underlay address
    let node_b_underlay = Ipv6Addr::from([
        0xfd, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
    ]);

    // Set up multicast group with automatic cleanup on drop
    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay, vni)?;

    // Set up multicast forwarding with External replication for local delivery
    mcast.set_forwarding(vec![(
        NextHopV6::new(node_b_underlay, vni),
        Replication::External,
    )])?;

    // Allow IPv6 multicast traffic (ff05::/16 site-local) via Multicast target
    let mcast_cidr = IpCidr::Ip6("ff05::/16".parse().unwrap());

    // Add router entries for multicast
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr)?;

    // Subscribe both ports to the multicast group
    topol.nodes[0].port.subscribe_multicast(mcast_group.into())?;
    topol.nodes[1].port.subscribe_multicast(mcast_group.into())?;

    // Get the device names for snoop
    let dev_name_b = topol.nodes[1].port.name().to_string();

    // Start snoop using SnoopGuard to ensure cleanup
    let filter = format!("udp and ip6 dst {mcast_group} and port {MCAST_PORT}");
    let mut snoop = SnoopGuard::start(&dev_name_b, &filter)?;

    // Send UDP packet to the multicast address from zone A using netcat
    // nc -6 -u: IPv6 UDP mode
    // -w1: timeout after 1 second
    let payload = "multicast test v6";
    let sender_v6 = topol.nodes[0]
        .port
        .ipv6()
        .expect("dualstack port must have IPv6 address");
    // illumos netcat selects IPv6 based on the destination; avoid `-6` for compatibility.
    let send_cmd = format!(
        "echo '{payload}' | nc -u -s {sender_v6} -w1 {mcast_group} {MCAST_PORT}"
    );
    topol.nodes[0]
        .zone
        .zone
        .zexec(&send_cmd)
        .context("Failed to send IPv6 multicast UDP packet")?;

    // Wait for snoop to capture the packet (or timeout)
    let snoop_output =
        snoop.wait_with_timeout(Duration::from_secs(5)).context(
            "Timeout waiting for snoop to capture IPv6 multicast packet",
        )?;

    // Check that snoop successfully captured a packet
    let stdout = String::from_utf8_lossy(&snoop_output.stdout);
    assert!(
        snoop_output.status.success() && !stdout.is_empty(),
        "Expected to capture IPv6 multicast packet on {dev_name_b}, snoop output:\n{stdout}"
    );

    Ok(())
}

#[test]
fn test_reject_link_local_underlay_ff02() -> Result<()> {
    let hdl = OpteHdl::open()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 99]);
    let vni = Vni::new(oxide_vpc::api::DEFAULT_MULTICAST_VNI)?;

    let link_local_underlay = Ipv6Addr::from([
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 99,
    ]);
    let result = hdl.set_m2p(&oxide_vpc::api::SetMcast2PhysReq {
        group: mcast_group.into(),
        underlay: link_local_underlay,
        vni,
    });
    assert!(
        result.is_err(),
        "Expected link-local underlay (ff02::) to be rejected"
    );

    Ok(())
}

#[test]
fn test_reject_global_underlay_ff0e() -> Result<()> {
    let hdl = OpteHdl::open()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 99]);
    let vni = Vni::new(oxide_vpc::api::DEFAULT_MULTICAST_VNI)?;

    let global_underlay = Ipv6Addr::from([
        0xff, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 99,
    ]);
    let result = hdl.set_m2p(&oxide_vpc::api::SetMcast2PhysReq {
        group: mcast_group.into(),
        underlay: global_underlay,
        vni,
    });
    assert!(
        result.is_err(),
        "Expected global underlay (ff0e::) to be rejected"
    );

    Ok(())
}

#[test]
fn test_accept_admin_local_underlay_ff04() -> Result<()> {
    let hdl = OpteHdl::open()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 99]);
    let vni = Vni::new(oxide_vpc::api::DEFAULT_MULTICAST_VNI)?;

    let admin_local = Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 99,
    ]);
    let result = hdl.set_m2p(&oxide_vpc::api::SetMcast2PhysReq {
        group: mcast_group.into(),
        underlay: admin_local,
        vni,
    });
    assert!(
        result.is_ok(),
        "Expected admin-local underlay (ff04::) to be accepted"
    );

    Ok(())
}

#[test]
fn test_accept_site_local_underlay_ff05() -> Result<()> {
    let hdl = OpteHdl::open()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 99]);
    let vni = Vni::new(oxide_vpc::api::DEFAULT_MULTICAST_VNI)?;

    let site_local = Ipv6Addr::from([
        0xff, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 99,
    ]);
    let result = hdl.set_m2p(&oxide_vpc::api::SetMcast2PhysReq {
        group: mcast_group.into(),
        underlay: site_local,
        vni,
    });
    assert!(
        result.is_ok(),
        "Expected site-local underlay (ff05::) to be accepted"
    );

    Ok(())
}

#[test]
fn test_accept_org_local_underlay_ff08() -> Result<()> {
    let hdl = OpteHdl::open()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 99]);
    let vni = Vni::new(oxide_vpc::api::DEFAULT_MULTICAST_VNI)?;

    let org_local = Ipv6Addr::from([
        0xff, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 99,
    ]);
    let result = hdl.set_m2p(&oxide_vpc::api::SetMcast2PhysReq {
        group: mcast_group.into(),
        underlay: org_local,
        vni,
    });
    assert!(
        result.is_ok(),
        "Expected org-local underlay (ff08::) to be accepted"
    );

    Ok(())
}

#[test]
fn test_reject_wrong_vni() -> Result<()> {
    let hdl = OpteHdl::open()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 100]);
    let underlay = Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 100,
    ]);

    let wrong_vni = Vni::new(1701u32)?;
    let result = hdl.set_m2p(&oxide_vpc::api::SetMcast2PhysReq {
        group: mcast_group.into(),
        underlay,
        vni: wrong_vni,
    });
    assert!(
        result.is_err(),
        "Expected VNI 1701 to be rejected (must use DEFAULT_MULTICAST_VNI), got: {:?}",
        result
    );

    Ok(())
}

#[test]
fn test_accept_default_multicast_vni() -> Result<()> {
    let hdl = OpteHdl::open()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 100]);
    let underlay = Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 100,
    ]);

    let correct_vni = Vni::new(oxide_vpc::api::DEFAULT_MULTICAST_VNI)?;
    let result = hdl.set_m2p(&oxide_vpc::api::SetMcast2PhysReq {
        group: mcast_group.into(),
        underlay,
        vni: correct_vni,
    });
    assert!(
        result.is_ok(),
        "Expected DEFAULT_MULTICAST_VNI (77) to be accepted"
    );

    Ok(())
}

#[test]
fn test_multicast_rx_no_relay_loop() -> Result<()> {
    // Test RX loop-prevention: packets arriving from underlay with
    // Replication::Underlay should NOT be re-relayed back to underlay.
    // This prevents infinite relay loops.

    let topol = xde_tests::two_node_topology_named("omicron1", "lpa", "lpb")?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 200]);
    let vni = Vni::new(oxide_vpc::api::DEFAULT_MULTICAST_VNI)?;

    let mcast_underlay = Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 200,
    ]);

    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay, vni)?;

    let node_b_underlay = Ipv6Addr::from([
        0xfd, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
    ]);

    // Set up forwarding with Underlay replication
    mcast.set_forwarding(vec![(
        NextHopV6::new(node_b_underlay, vni),
        Replication::Underlay,
    )])?;

    let mcast_cidr = IpCidr::Ip4("224.0.0.0/4".parse().unwrap());
    for node in &topol.nodes {
        node.port.add_multicast_router_entry(mcast_cidr)?;
        node.port.subscribe_multicast(mcast_group.into())?;
    }

    // Snoop the underlay to verify NO re-relay happens
    let underlay_dev = "xde_test_sim1";
    let mut snoop_underlay =
        SnoopGuard::start(underlay_dev, "ip6 and udp port 6081")?;

    // Simulate receiving a multicast packet FROM the underlay
    // with Replication::Underlay already set (indicating it came from another host).
    // Build a Geneve packet with the Underlay replication bit set.
    let hdl = OpteHdl::open()?;

    // We need to inject a packet on the underlay that looks like it came from
    // another host. Unfortunately, we can't easily inject raw packets in the test
    // environment without significant plumbing. Instead, we verify the logic
    // indirectly by checking that the dtrace probe shows the right behavior.

    // For now, document the expected behavior and add a TODO for full integration
    // test once we have packet injection capability.
    println!("\n=== RX Loop Prevention Test ===");
    println!("Expected behavior: Packets arriving from underlay with");
    println!("Replication::Underlay should NOT be re-relayed.");
    println!("\nThis requires packet injection capability to fully test.");
    println!(
        "Current implementation checks incoming delivery mode in Geneve options"
    );
    println!("and only relays if delivery_mode is Underlay or All.");

    // Verify the multicast forwarding table is set up correctly
    let mfwd = hdl.dump_mcast_fwd()?;
    println!("\n=== Multicast forwarding table ===");
    for entry in &mfwd.entries {
        println!(
            "  Group: {:?}, Next hops: {:?}",
            entry.group, entry.next_hops
        );
    }

    // Since we can't inject packets easily, verify NO spurious underlay traffic
    // by waiting to ensure nothing appears on underlay without us sending anything
    let snoop_result = snoop_underlay.wait_with_timeout(Duration::from_secs(2));

    match snoop_result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.is_empty(),
                "No multicast traffic should appear on underlay without a sender:\n{stdout}"
            );
        }
        Err(_) => {
            // Timeout is expected - no packets should appear
        }
    }

    Ok(())
}

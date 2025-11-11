// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! XDE multicast RX-path tests.
//!
//! These validate that:
//! - Control-plane config (M2P map + forwarding) drives TX encapsulation only.
//! - Same-sled delivery is based purely on subscriptions and is independent of
//!   the Replication mode set for TX.
//! - Underlay multicast uses admin-local IPv6 (ff04::/16) and routes via the
//!   host underlay interface.
//! - Packets received from the underlay are delivered to subscribed ports and
//!   include the expected protocol and payload characteristics.

use anyhow::Result;
use opte_ioctl::OpteHdl;
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
    let mcast_underlay: Ipv6Addr = "ff04::e000:fb".parse().unwrap();

    // Set up multicast group with automatic cleanup on drop
    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    // Use node B's underlay address as the switch unicast address for routing.
    // OPTE uses this address to determine the underlay port (via DDM routing),
    // but the actual packet destination is the multicast underlay address.
    // Note: This is a single-sled test; all nodes share one underlay network.
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    // Set up TX forwarding with Underlay replication to test underlay RX path.
    // This causes packets to be sent to the underlay multicast address, then
    // received back via the underlay RX path for same-sled delivery.
    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::Underlay,
    )])?;

    // Add IPv6 multicast route so underlay packets can be routed
    xde_tests::ensure_underlay_admin_scoped_route_v6("xde_test_vnic0")?;

    // Allow IPv4 multicast traffic (224.0.0.0/4) via Multicast target.
    let mcast_cidr = IpCidr::Ip4("224.0.0.0/4".parse().unwrap());

    // Add router entries for multicast (allows both In and Out directions)
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr)?;

    // Subscribe both ports to the multicast group
    topol.nodes[0]
        .port
        .subscribe_multicast(mcast_group.into())
        .expect("subscribe port 0 should succeed");
    topol.nodes[1]
        .port
        .subscribe_multicast(mcast_group.into())
        .expect("subscribe port 1 should succeed");

    // Assert subscription state via ioctl dump before sending
    let hdl = OpteHdl::open()?;
    let subs = hdl.dump_mcast_subs()?;
    let s_entry = subs
        .entries
        .iter()
        .find(|e| e.underlay == mcast_underlay)
        .expect("missing multicast subscription entry for underlay group");
    let p0 = topol.nodes[0].port.name().to_string();
    let p1 = topol.nodes[1].port.name().to_string();
    assert!(
        s_entry.ports.contains(&p0) && s_entry.ports.contains(&p1),
        "expected both {p0} and {p1} to be subscribed; got {:?}",
        s_entry.ports
    );

    // Assert forwarding table contains expected next-hop + replication
    let mfwd = hdl.dump_mcast_fwd()?;
    let entry = mfwd
        .entries
        .iter()
        .find(|e| e.underlay == mcast_underlay)
        .expect("missing multicast forwarding entry for underlay group");
    assert!(
        entry.next_hops.iter().any(|(nexthop, rep)| {
            *rep == Replication::Underlay
                && nexthop.addr == fake_switch_addr
                && nexthop.vni == vni
        }),
        "expected Underlay replication to {fake_switch_addr:?} in forwarding table; got: {:?}",
        entry.next_hops
    );

    // Start snoop on RX side (matches IPv6 test pattern)
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let filter = format!("udp and ip dst {mcast_group} and port {MCAST_PORT}");
    let mut snoop_rx = SnoopGuard::start(&dev_name_b, &filter)?;

    // Send UDP packet from zone A using helper (pins source for deterministic egress)
    let payload = "multicast test";
    let sender_v4 = topol.nodes[0].port.ip();
    topol.nodes[0].zone.send_udp_v4(
        &sender_v4,
        &mcast_group.to_string(),
        MCAST_PORT,
        payload,
    )?;

    // Wait for RX snoop to capture the packet (or timeout)
    let snoop_rx_output = snoop_rx.wait_with_timeout(Duration::from_secs(5))?;

    let stdout = String::from_utf8_lossy(&snoop_rx_output.stdout);
    assert!(
        snoop_rx_output.status.success() && !stdout.is_empty(),
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
    assert!(
        stdout.contains("test"),
        "expected payload substring 'test' in ASCII portion of snoop output:\n{stdout}"
    );
    // L2 dest: with current XDE/gateway pipeline, multicast RX to guests
    // is delivered with broadcast dest MAC. snoop shows 16-bit grouped hex.
    assert!(
        stdout.to_ascii_lowercase().contains("ffff ffff ffff"),
        "expected L2 broadcast MAC 'ffff ffff ffff' in snoop output; got:\n{stdout}"
    );

    // Unsubscribe receiver and verify no further same-sled delivery
    topol.nodes[1]
        .port
        .unsubscribe_multicast(mcast_group.into())
        .expect("unsubscribe should succeed");

    // Assert subscription table reflects unsubscribe
    let subs2 = hdl.dump_mcast_subs()?;
    let s_entry2 = subs2
        .entries
        .iter()
        .find(|e| e.underlay == mcast_underlay)
        .expect("missing multicast subscription entry after unsubscribe");
    assert!(
        !s_entry2.ports.contains(&p1),
        "expected {p1} to be unsubscribed; got {:?}",
        s_entry2.ports
    );

    let mut snoop2 = SnoopGuard::start(&dev_name_b, &filter)?;
    topol.nodes[0].zone.send_udp_v4(
        &sender_v4,
        &mcast_group.to_string(),
        MCAST_PORT,
        payload,
    )?;
    if let Ok(out) = snoop2.wait_with_timeout(Duration::from_millis(800)) {
        let stdout = String::from_utf8_lossy(&out.stdout);
        panic!(
            "expected no same-sled delivery after unsubscribe; snoop output:\n{stdout}"
        );
    }
    Ok(())
}

#[test]
fn test_xde_multicast_rx_ipv6() -> Result<()> {
    // Create 2-node topology with dual-stack (IPv4 + IPv6)
    let topol = xde_tests::two_node_topology_dualstack_named(
        "omicron1", "rx6a", "rx6b",
    )?;

    // IPv6 multicast group: ff04::1:3 (admin-local scope)
    let mcast_group: Ipv6Addr = "ff04::1:3".parse().unwrap();
    const MCAST_PORT: u16 = 9999;
    let vni = Vni::new(oxide_vpc::api::DEFAULT_MULTICAST_VNI)?;

    // M2P mapping: Use same admin-local address for underlay
    let mcast_underlay: Ipv6Addr = "ff04::1:3".parse().unwrap();

    // Set up multicast group with automatic cleanup on drop
    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    // Use node B's underlay address as the switch unicast address for routing.
    // OPTE uses this address to determine the underlay port (via DDM routing),
    // but the actual packet destination is the multicast underlay address.
    // Note: This is a single-sled test; all nodes share one underlay network.
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    // Set up TX forwarding with Underlay replication to test underlay RX path.
    // This causes packets to be sent to the underlay multicast address, then
    // received back via the underlay RX path for same-sled delivery.
    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::Underlay,
    )])?;

    // Add IPv6 multicast route so underlay packets can be routed
    xde_tests::ensure_underlay_admin_scoped_route_v6("xde_test_vnic0")?;

    // Allow IPv6 multicast traffic (ff04::/16 admin-local) via Multicast target
    let mcast_cidr = IpCidr::Ip6("ff04::/16".parse().unwrap());

    // Add router entries for multicast (allows both In and Out directions)
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr)?;

    // Subscribe both ports to the multicast group
    topol.nodes[0]
        .port
        .subscribe_multicast(mcast_group.into())
        .expect("subscribe port 0 should succeed");
    topol.nodes[1]
        .port
        .subscribe_multicast(mcast_group.into())
        .expect("subscribe port 1 should succeed");

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
    topol.nodes[0].zone.send_udp_v6(
        &sender_v6,
        &mcast_group.to_string(),
        MCAST_PORT,
        payload,
    )?;

    // Wait for snoop to capture the packet (or timeout)
    let snoop_output = snoop.wait_with_timeout(Duration::from_secs(5))?;

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

    let link_local_underlay: Ipv6Addr = "ff02::e001:263".parse().unwrap();
    let result = hdl.set_m2p(&oxide_vpc::api::SetMcast2PhysReq {
        group: mcast_group.into(),
        underlay: link_local_underlay,
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

    let global_underlay: Ipv6Addr = "ff0e::e001:263".parse().unwrap();
    let result = hdl.set_m2p(&oxide_vpc::api::SetMcast2PhysReq {
        group: mcast_group.into(),
        underlay: global_underlay,
    });
    assert!(
        result.is_err(),
        "Expected global underlay (ff0e::) to be rejected"
    );

    Ok(())
}

#[test]
fn test_accept_admin_local_underlay_ff04() -> Result<()> {
    let mcast_group = Ipv4Addr::from([224, 1, 2, 99]);
    let admin_local: Ipv6Addr = "ff04::e001:263".parse().unwrap();

    // MulticastGroup::new calls set_m2p internally and cleans up on drop.
    // This test verifies that admin-local (ff04::/16) addresses are accepted,
    // in contrast to link-local (ff02::) and global (ff0e::) which are rejected.
    let result = MulticastGroup::new(mcast_group.into(), admin_local);
    assert!(
        result.is_ok(),
        "Expected admin-local (ff04::) underlay to be accepted"
    );

    Ok(())
}

#[test]
fn test_multicast_config_no_spurious_traffic() -> Result<()> {
    // Test that multicast configuration (subscriptions + forwarding entries)
    // doesn't spontaneously generate traffic on the underlay when no packets
    // are actually being sent.

    let topol = xde_tests::two_node_topology_named("omicron1", "lpa", "lpb")?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 200]);
    let vni = Vni::new(oxide_vpc::api::DEFAULT_MULTICAST_VNI)?;

    let mcast_underlay: Ipv6Addr = "ff04::e001:2c8".parse().unwrap();

    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    // Use node B's underlay address as the switch unicast address for routing.
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    // Set up forwarding with Underlay replication
    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::Underlay,
    )])?;

    let mcast_cidr = IpCidr::Ip4("224.0.0.0/4".parse().unwrap());
    for node in &topol.nodes {
        node.port.add_multicast_router_entry(mcast_cidr)?;
        node.port
            .subscribe_multicast(mcast_group.into())
            .expect("subscribe should succeed");
    }

    // Snoop the underlay to verify NO spurious traffic without sending
    let underlay_dev = "xde_test_sim1";
    let mut snoop_underlay =
        SnoopGuard::start(underlay_dev, "ip6 and udp port 6081")?;

    // Verify NO spurious underlay traffic (we're not sending any packets)
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

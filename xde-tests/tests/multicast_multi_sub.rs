// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! XDE multicast multiple subscriber tests.
//!
//! These validate Tx fanout and forwarding semantics across replication modes:
//! - Same-sled delivery (DELIVER action) is based purely on subscriptions and
//!   independent of Replication mode set for Tx.
//! - External replication sends Geneve to the multicast underlay address for
//!   delivery to the boundary switch, which then replicates to front-panel ports.
//! - Underlay replication sends Geneve to ff04::/16 multicast address for
//!   sled-to-sled delivery; receiving sleds perform same-sled delivery based on
//!   local subscriptions.
//! - "Both" replication instructs Tx to set bifurcated replication flags
//!   (External + Underlay) in the Geneve header for switch-side handling, while
//!   same-sled delivery still occurs independently based on subscriptions.

use anyhow::Result;
use opte_ioctl::OpteHdl;
use opte_test_utils::geneve_verify;
use oxide_vpc::api::DEFAULT_MULTICAST_VNI;
use oxide_vpc::api::IpCidr;
use oxide_vpc::api::Ipv4Addr;
use oxide_vpc::api::Ipv6Addr;
use oxide_vpc::api::MulticastUnderlay;
use oxide_vpc::api::NextHopV6;
use oxide_vpc::api::Replication;
use oxide_vpc::api::Vni;
use std::time::Duration;
use xde_tests::MulticastGroup;
use xde_tests::SnoopGuard;

#[test]
fn test_multicast_multiple_local_subscribers() -> Result<()> {
    // Create 3-node topology to test local fanout
    let topol = xde_tests::three_node_topology_named(
        "omicron1", "mlsa", "mlsb", "mlsc",
    )?;

    // IPv4 multicast group: 224.1.2.3
    let mcast_group = Ipv4Addr::from([224, 1, 2, 3]);
    const MCAST_PORT: u16 = 9999;
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    // M2P mapping - use admin-scoped IPv6 multicast per Omicron constraints
    let mcast_underlay = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 3,
    ]))
    .unwrap();

    // Set up multicast state with automatic cleanup on drop
    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    // Use node B's underlay address as the switch unicast address for routing.
    //
    // Note: This is a single-sled test - all nodes share one underlay.
    // In production, XDE would route toward this switch address to determine the
    // underlay port/MAC, but the packet dst would be the multicast address.
    // This test validates packet formatting, not actual multi-sled routing.
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    // Set up Tx forwarding with External replication mode.
    // Tx behavior: packet sent to underlay with Replication::External flag.
    // In production, switch receives this flag and replicates to front-panel ports.
    // Rx behavior: same-sled delivery is controlled by subscriptions, independent
    // of the Replication mode.
    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::External,
    )])?;

    // Allow IPv4 multicast traffic via Multicast target and subscribe to the group
    let mcast_cidr = IpCidr::Ip4("224.0.0.0/4".parse().unwrap());
    for node in &topol.nodes {
        node.port.add_multicast_router_entry(mcast_cidr)?;
        node.port
            .subscribe_multicast(mcast_group.into())
            .expect("subscribe should succeed");
    }

    // Assert subscription table reflects all three subscribers
    let hdl = OpteHdl::open()?;
    let subs = hdl.dump_mcast_subs()?;
    let s_entry = subs
        .entries
        .iter()
        .find(|e| e.underlay == mcast_underlay)
        .expect("missing multicast subscription entry for underlay group");
    let p0 = topol.nodes[0].port.name().to_string();
    let p1 = topol.nodes[1].port.name().to_string();
    let p2 = topol.nodes[2].port.name().to_string();
    assert!(
        s_entry.ports.contains(&p0)
            && s_entry.ports.contains(&p1)
            && s_entry.ports.contains(&p2),
        "expected {p0}, {p1}, {p2} to be subscribed; got {:?}",
        s_entry.ports
    );

    // Start snoops on nodes B and C using SnoopGuard
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let dev_name_c = topol.nodes[2].port.name().to_string();
    let filter = format!("udp and ip dst {mcast_group} and port {MCAST_PORT}");

    let mut snoop_b = SnoopGuard::start(&dev_name_b, &filter)?;
    let mut snoop_c = SnoopGuard::start(&dev_name_c, &filter)?;

    // Also snoop underlay to verify unicast Geneve Tx to boundary
    let underlay_dev = "xde_test_sim1";
    let mut snoop_underlay =
        SnoopGuard::start(underlay_dev, "ip6 and udp port 6081")?;

    // Send multicast packet from node A
    let payload = "fanout test";
    let sender_v4 = topol.nodes[0].port.ip();
    topol.nodes[0].zone.send_udp_v4(
        &sender_v4,
        &mcast_group.to_string(),
        MCAST_PORT,
        payload,
    )?;

    // Wait for both snoops to capture packets
    let snoop_output_b = snoop_b.wait_with_timeout(Duration::from_secs(5))?;
    let snoop_output_c = snoop_c.wait_with_timeout(Duration::from_secs(5))?;

    let stdout_b = String::from_utf8_lossy(&snoop_output_b.stdout);
    assert!(
        snoop_output_b.status.success() && stdout_b.contains("UDP"),
        "Expected to capture multicast UDP packet on node B, snoop output:\n{stdout_b}"
    );

    let stdout_c = String::from_utf8_lossy(&snoop_output_c.stdout);
    assert!(
        snoop_output_c.status.success() && stdout_c.contains("UDP"),
        "Expected to capture multicast UDP packet on node C, snoop output:\n{stdout_c}"
    );

    // Verify underlay multicast forwarding (External mode)
    // Parse the captured Geneve packet and assert:
    // - VNI == DEFAULT_MULTICAST_VNI
    // - Outer IPv6 dst == mcast_underlay (multicast group)
    // - Replication == External
    // Note: In production, the switch would see this External tag and replicate
    // to front panel. This test verifies the Geneve header is correctly formed.
    let snoop_underlay_out =
        snoop_underlay.wait_with_timeout(Duration::from_secs(5))?;
    let stdout_underlay = String::from_utf8_lossy(&snoop_underlay_out.stdout);
    assert!(
        snoop_underlay_out.status.success() && stdout_underlay.contains("UDP"),
        "Expected to capture Geneve packet on underlay for External replication, output:\n{stdout_underlay}"
    );

    let hex_str = geneve_verify::extract_snoop_hex(&stdout_underlay)
        .expect("Failed to extract hex from snoop output");
    let packet_bytes = geneve_verify::parse_snoop_hex(&hex_str)
        .expect("Failed to parse hex string");
    let geneve_info = geneve_verify::parse_geneve_packet(&packet_bytes)
        .expect("Failed to parse Geneve packet");

    assert_eq!(
        geneve_info.vni, vni,
        "Geneve VNI should be DEFAULT_MULTICAST_VNI ({})",
        DEFAULT_MULTICAST_VNI
    );
    assert_eq!(
        geneve_info.outer_ipv6_dst,
        Ipv6Addr::from(mcast_underlay),
        "External replication should use multicast address (outer IPv6 dst)"
    );
    assert_eq!(
        geneve_info.replication,
        Some(Replication::External),
        "Geneve replication mode should be External"
    );

    Ok(())
}

#[test]
fn test_multicast_underlay_replication() -> Result<()> {
    // Create 2-node topology to test Underlay replication mode
    let topol = xde_tests::two_node_topology_named("omicron1", "ura", "urb")?;

    // IPv4 multicast group
    let mcast_group = Ipv4Addr::from([224, 1, 2, 4]);
    const MCAST_PORT: u16 = 9999;
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    // M2P mapping - use admin-scoped IPv6 multicast per Omicron constraints
    let mcast_underlay = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 4,
    ]))
    .unwrap();

    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    let hdl = OpteHdl::open()?;

    // Use node B's underlay address as the switch unicast address for routing.
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    // Set up Tx forwarding with Underlay replication mode.
    // Tx behavior: forward to underlay with multicast encapsulation.
    // Rx behavior: same-sled delivery to subscribers (none in this test).
    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::Underlay,
    )])?;

    // Allow IPv4 multicast traffic via Multicast target
    //
    // Note: We deliberately do NOT subscribe any nodes. This tests Tx forwarding
    // with zero local subscribers (Rx delivery is based on subscriptions, not
    // Replication)
    let mcast_cidr = IpCidr::Ip4("224.0.0.0/4".parse().unwrap());
    for node in &topol.nodes {
        node.port.add_multicast_router_entry(mcast_cidr)?;
    }

    // Assert there are no local subscribers for this group
    let subs = hdl.dump_mcast_subs()?;
    assert!(
        !subs.entries.iter().any(|e| e.underlay == mcast_underlay),
        "expected no local subscribers for {mcast_underlay}, got: {:?}",
        subs.entries
    );

    // Add IPv6 multicast route for admin-scoped multicast (ff04::/16)
    // This tells the kernel to route multicast packets through the underlay interface
    xde_tests::ensure_underlay_admin_scoped_route_v6("xde_test_vnic0")?;

    // Start snoop on the UNDERLAY simnet device (not the OPTE port)
    // to verify the packet is forwarded to the underlay
    let underlay_dev = "xde_test_sim1"; // Underlay device
    let mut snoop_underlay =
        SnoopGuard::start(underlay_dev, "ip6 and udp port 6081")?; // Geneve port

    // Also snoop node B's OPTE port to verify NO local delivery with Underlay mode
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let filter_local =
        format!("udp and ip dst {mcast_group} and port {MCAST_PORT}");
    let mut snoop_local = SnoopGuard::start(&dev_name_b, &filter_local)?;

    // Clear UFT right before sending to ensure fresh flow computation
    hdl.clear_uft(topol.nodes[0].port.name())?;

    // Send multicast packet from node A
    let payload = "underlay test";
    let sender_v4 = topol.nodes[0].port.ip();
    topol.nodes[0].zone.send_udp_v4(
        &sender_v4,
        &mcast_group.to_string(),
        MCAST_PORT,
        payload,
    )?;

    // Wait for snoop to capture the underlay packet (one send expected)
    let snoop_output_underlay =
        snoop_underlay.wait_with_timeout(Duration::from_secs(5))?;

    let stdout_underlay =
        String::from_utf8_lossy(&snoop_output_underlay.stdout);

    assert!(
        snoop_output_underlay.status.success()
            && stdout_underlay.contains("UDP"),
        "Expected to capture Geneve packet on underlay, snoop output:\n{stdout_underlay}"
    );

    // Verify Geneve header fields (VNI, outer IPv6 dst, replication mode)
    let hex_str = geneve_verify::extract_snoop_hex(&stdout_underlay)
        .expect("Failed to extract hex from snoop output");

    let packet_bytes = geneve_verify::parse_snoop_hex(&hex_str)
        .expect("Failed to parse hex string");

    let geneve_info = geneve_verify::parse_geneve_packet(&packet_bytes)
        .expect("Failed to parse Geneve packet");

    assert_eq!(
        geneve_info.vni, vni,
        "Geneve VNI should be DEFAULT_MULTICAST_VNI ({})",
        DEFAULT_MULTICAST_VNI
    );
    assert_eq!(
        geneve_info.outer_ipv6_dst,
        Ipv6Addr::from(mcast_underlay),
        "Outer IPv6 dst should be multicast underlay address"
    );
    assert_eq!(
        geneve_info.replication,
        Some(Replication::Underlay),
        "Geneve replication mode should be Underlay"
    );

    // Verify NO same-sled delivery (no subscribers = no delivery)
    // Note: Rx delivery is independent of Replication mode - it's based on subscriptions
    if let Ok(output) = snoop_local.wait_with_timeout(Duration::from_secs(2)) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "Expected no same-sled delivery (zero subscribers), but captured:\n{stdout}"
        );
    }

    // Leaf-only Rx assertion: start a second underlay snoop and ensure there
    // is no additional multicast re-relay after Rx. We expect only the single
    // Tx underlay packet captured above.
    let mut snoop_underlay_2 =
        SnoopGuard::start(underlay_dev, "ip6 and udp port 6081")?;
    if let Ok(out) = snoop_underlay_2.wait_with_timeout(Duration::from_secs(2))
    {
        let stdout = String::from_utf8_lossy(&out.stdout);
        panic!(
            "Expected leaf-only Rx (no further underlay relay), got:\n{stdout}"
        );
    }

    Ok(())
}

#[test]
fn test_multicast_both_replication() -> Result<()> {
    // Test "Both" replication mode: validates that egress Tx (External + Underlay)
    // and local same-sled delivery both occur.
    let topol =
        xde_tests::three_node_topology_named("omicron1", "ara", "arb", "arc")?;

    // IPv4 multicast group
    let mcast_group = Ipv4Addr::from([224, 1, 2, 5]);
    const MCAST_PORT: u16 = 9999;
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    // M2P mapping - use admin-scoped IPv6 multicast per Omicron constraints
    let mcast_underlay = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 5,
    ]))
    .unwrap();

    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    // Use node B's underlay address as the switch unicast address for routing.
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    // Set up Tx forwarding with "Both" replication (drives egress encapsulation only)
    // Tx behavior: packet sent to underlay with Replication::Both flag set.
    // In production, switch receives this and bifurcates: External (to front panel)
    // + Underlay (sled-to-sled multicast).
    // Rx behavior: same-sled local delivery occurs independently, driven purely by
    // port subscriptions (not the replication mode).
    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::Both,
    )])?;

    // Allow IPv4 multicast traffic via Multicast target and subscribe to the group
    let mcast_cidr = IpCidr::Ip4("224.0.0.0/4".parse().unwrap());
    for node in &topol.nodes {
        node.port.add_multicast_router_entry(mcast_cidr)?;
        node.port
            .subscribe_multicast(mcast_group.into())
            .expect("subscribe should succeed");
    }

    // Assert subscription table reflects all three subscribers
    let hdl = OpteHdl::open()?;
    let subs = hdl.dump_mcast_subs()?;
    let s_entry = subs
        .entries
        .iter()
        .find(|e| e.underlay == mcast_underlay)
        .expect("missing multicast subscription entry for underlay group");
    let p0 = topol.nodes[0].port.name().to_string();
    let p1 = topol.nodes[1].port.name().to_string();
    let p2 = topol.nodes[2].port.name().to_string();
    assert!(
        s_entry.ports.contains(&p0)
            && s_entry.ports.contains(&p1)
            && s_entry.ports.contains(&p2),
        "expected {p0}, {p1}, {p2} to be subscribed; got {:?}",
        s_entry.ports
    );

    // Start snoop on node B (local delivery) and underlay (underlay forwarding)
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let filter_local =
        format!("udp and ip dst {mcast_group} and port {MCAST_PORT}");
    let mut snoop_local = SnoopGuard::start(&dev_name_b, &filter_local)?;

    let underlay_dev = "xde_test_sim1";
    let mut snoop_underlay =
        SnoopGuard::start(underlay_dev, "ip6 and udp port 6081")?;

    // Send multicast packet from node A
    let payload = "all replication test";
    let sender_v4 = topol.nodes[0].port.ip();
    topol.nodes[0].zone.send_udp_v4(
        &sender_v4,
        &mcast_group.to_string(),
        MCAST_PORT,
        payload,
    )?;

    // Wait for both snoops to capture packets
    let snoop_output_local =
        snoop_local.wait_with_timeout(Duration::from_secs(5))?;
    let snoop_output_underlay =
        snoop_underlay.wait_with_timeout(Duration::from_secs(5))?;

    // Verify same-sled local delivery (DELIVER action based on subscription)
    let stdout_local = String::from_utf8_lossy(&snoop_output_local.stdout);
    assert!(
        snoop_output_local.status.success() && stdout_local.contains("UDP"),
        "Expected same-sled delivery to subscribed node B, snoop output:\n{stdout_local}"
    );

    // Verify egress underlay forwarding with "Both" replication flag
    let stdout_underlay =
        String::from_utf8_lossy(&snoop_output_underlay.stdout);
    assert!(
        snoop_output_underlay.status.success()
            && stdout_underlay.contains("UDP"),
        "Expected egress underlay packet with 'Both' replication, snoop output:\n{stdout_underlay}"
    );

    // Parse the Geneve packet and verify the "Both" replication flag is set
    let hex_str = geneve_verify::extract_snoop_hex(&stdout_underlay)
        .expect("Failed to extract hex from snoop output");
    let packet_bytes = geneve_verify::parse_snoop_hex(&hex_str)
        .expect("Failed to parse hex string");
    let geneve_info = geneve_verify::parse_geneve_packet(&packet_bytes)
        .expect("Failed to parse Geneve packet");

    assert_eq!(
        geneve_info.vni, vni,
        "Geneve VNI should be DEFAULT_MULTICAST_VNI ({})",
        DEFAULT_MULTICAST_VNI
    );
    assert_eq!(
        geneve_info.outer_ipv6_dst,
        Ipv6Addr::from(mcast_underlay),
        "Outer IPv6 dst should be multicast underlay address"
    );
    assert_eq!(
        geneve_info.replication,
        Some(Replication::Both),
        "Geneve replication mode should be Both"
    );

    Ok(())
}

#[test]
fn test_partial_unsubscribe() -> Result<()> {
    // Test selective unsubscribe: subscribe 3 nodes, unsubscribe 1, verify
    // only the remaining 2 receive packets while forwarding state is unchanged.
    let topol =
        xde_tests::three_node_topology_named("omicron1", "pua", "pub", "puc")?;

    let mcast_group = Ipv4Addr::from([224, 1, 2, 6]);
    const MCAST_PORT: u16 = 9999;
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    let mcast_underlay = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 6,
    ]))
    .unwrap();

    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    // Use node B's underlay address as the switch unicast address for routing.
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::External,
    )])?;

    let mcast_cidr = IpCidr::Ip4("224.0.0.0/4".parse().unwrap());
    for node in &topol.nodes {
        node.port.add_multicast_router_entry(mcast_cidr)?;
        node.port
            .subscribe_multicast(mcast_group.into())
            .expect("subscribe should succeed");
    }

    let hdl = OpteHdl::open()?;
    let p0 = topol.nodes[0].port.name().to_string();
    let p1 = topol.nodes[1].port.name().to_string();
    let p2 = topol.nodes[2].port.name().to_string();

    let subs = hdl.dump_mcast_subs()?;
    let s_entry = subs
        .entries
        .iter()
        .find(|e| e.underlay == mcast_underlay)
        .expect("missing multicast subscription entry");
    assert!(
        s_entry.ports.contains(&p0)
            && s_entry.ports.contains(&p1)
            && s_entry.ports.contains(&p2),
        "expected all 3 ports subscribed initially; got {:?}",
        s_entry.ports
    );

    // Send packet and verify B and C receive (A is sender, won't receive its own)
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let dev_name_c = topol.nodes[2].port.name().to_string();
    let filter = format!("udp and ip dst {mcast_group} and port {MCAST_PORT}");

    let mut snoop_b = SnoopGuard::start(&dev_name_b, &filter)?;
    let mut snoop_c = SnoopGuard::start(&dev_name_c, &filter)?;

    let payload = "all three";
    let sender_v4 = topol.nodes[0].port.ip();
    topol.nodes[0].zone.send_udp_v4(
        &sender_v4,
        &mcast_group.to_string(),
        MCAST_PORT,
        payload,
    )?;

    // B and C should receive (A is sender, won't see its own packet)
    let snoop_b_out = snoop_b.wait_with_timeout(Duration::from_secs(5))?;
    let snoop_c_out = snoop_c.wait_with_timeout(Duration::from_secs(5))?;

    assert!(
        String::from_utf8_lossy(&snoop_b_out.stdout).contains("UDP"),
        "Node B should receive first packet"
    );
    assert!(
        String::from_utf8_lossy(&snoop_c_out.stdout).contains("UDP"),
        "Node C should receive first packet"
    );

    // Unsubscribe node B (middle node)
    topol.nodes[1]
        .port
        .unsubscribe_multicast(mcast_group.into())
        .expect("unsubscribe should succeed");

    // Verify subscription table now shows only A and C
    let subs2 = hdl.dump_mcast_subs()?;
    let s_entry2 = subs2
        .entries
        .iter()
        .find(|e| e.underlay == mcast_underlay)
        .expect("subscription entry should still exist");
    assert!(
        s_entry2.ports.contains(&p0) && s_entry2.ports.contains(&p2),
        "expected p0 and p2 to remain subscribed; got {:?}",
        s_entry2.ports
    );
    assert!(
        !s_entry2.ports.contains(&p1),
        "expected p1 to be unsubscribed; got {:?}",
        s_entry2.ports
    );

    // Verify forwarding table unchanged (forwarding is independent of local subs)
    let fwd = hdl.dump_mcast_fwd()?;
    let fwd_entry = fwd
        .entries
        .iter()
        .find(|e| e.underlay == mcast_underlay)
        .expect("forwarding entry should still exist");
    assert!(
        fwd_entry.next_hops.iter().any(|(nexthop, rep)| {
            *rep == Replication::External
                && nexthop.addr == fake_switch_addr
                && nexthop.vni == vni
        }),
        "forwarding table should be unchanged"
    );

    // Send another packet - only C should receive (A is sender, B unsubscribed)
    let mut snoop_b2 = SnoopGuard::start(&dev_name_b, &filter)?;
    let mut snoop_c2 = SnoopGuard::start(&dev_name_c, &filter)?;

    let payload2 = "only two";
    topol.nodes[0].zone.send_udp_v4(
        &sender_v4,
        &mcast_group.to_string(),
        MCAST_PORT,
        payload2,
    )?;

    // C should receive
    let snoop_c2_out = snoop_c2.wait_with_timeout(Duration::from_secs(5))?;
    assert!(
        String::from_utf8_lossy(&snoop_c2_out.stdout).contains("UDP"),
        "Node C should receive second packet"
    );

    // B should NOT receive (timeout expected)
    if let Ok(out) = snoop_b2.wait_with_timeout(Duration::from_millis(800)) {
        let stdout = String::from_utf8_lossy(&out.stdout);
        panic!("Node B should not receive after unsubscribe; got:\n{stdout}");
    }

    Ok(())
}

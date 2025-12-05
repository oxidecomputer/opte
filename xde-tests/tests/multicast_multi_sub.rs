// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! XDE multicast multiple subscriber tests.
//!
//! These validate Tx fanout and forwarding semantics across replication modes:
//! - Same-sled delivery is based purely on subscriptions and independent of the
//!   [`Replication`] mode set for Tx. Sender ports are always excluded from
//!   receiving their own multicast packets (sender self-exclusion).
//! - `Replication::External` sends Geneve to the multicast underlay address for
//!   delivery to the boundary switch, which then replicates to front-panel ports.
//! - `Replication::Underlay` sends Geneve to ff04::/16 multicast address for
//!   sled-to-sled delivery; receiving sleds perform same-sled delivery based on
//!   local subscriptions.
//! - `Replication::Both` instructs Tx to set bifurcated replication flags
//!   (External + Underlay) in the Geneve header for switch-side handling, while
//!   same-sled delivery still occurs independently based on subscriptions.
//!
//! Note: OPTE routes to NextHopV6::addr (unicast switch address) to determine
//! reachability and underlay egress, while the actual packet destination (outer
//! IPv6) is always the multicast address.

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
use xde_tests::GENEVE_UNDERLAY_FILTER;
use xde_tests::IPV4_MULTICAST_CIDR;
use xde_tests::MCAST_TEST_PORT;
use xde_tests::MulticastGroup;
use xde_tests::SnoopGuard;
use xde_tests::UNDERLAY_TEST_DEVICE;

#[test]
fn test_multicast_tx_forwarding_sender_only_subscribed() -> Result<()> {
    // Tests Tx underlay forwarding when only the sender is subscribed.
    //
    // This validates that underlay forwarding works independently of local
    // subscriptions: packets are sent to the underlay even when no local ports
    // (besides the sender) are subscribed.
    //
    // Test setup:
    // - Sender A is subscribed (will not receive its own packet due to self-exclusion)
    // - B and C are not subscribed (no same-sled delivery to them)
    // - Forwarding is configured with `Replication::External`
    // - Verifies underlay packet is sent with correct Geneve header

    let topol = xde_tests::three_node_topology()?;

    // IPv4 multicast group: 224.1.2.3
    let mcast_group = Ipv4Addr::from([224, 1, 2, 3]);
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    // M2P mapping - use admin-scoped IPv6 multicast per Omicron constraints
    let mcast_underlay = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 3,
    ]))
    .unwrap();

    // Set up multicast state with automatic cleanup on drop
    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    // Use node B's underlay address as the next hop to select underlay egress.
    //
    // Note: In this harness, the underlay is a single L2 segment effectively
    // hooked back to itself. Any address reachable from u1 provides a path to
    // send on that segment and receive the same packet on u2. This differs from
    // product multi-sled underlays. The unicast next hop only selects the
    // underlay egress; the actual packet destination is the multicast address.
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    // Set up Tx forwarding with `Replication::External` mode.
    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::External,
    )])?;

    // Allow IPv4 multicast traffic via Multicast target
    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    for node in &topol.nodes {
        node.port.add_multicast_router_entry(mcast_cidr)?;
    }

    // Subscribe ONLY sender A (sender self-exclusion means A won't receive its own packet)
    // B and C are not subscribed, so no same-sled delivery and no Rx delivery.
    topol.nodes[0]
        .port
        .subscribe_multicast(mcast_group.into())
        .expect("subscribe sender A should succeed");

    // Assert subscription table reflects only A subscribed
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
        s_entry.ports.contains(&p0),
        "expected {p0} to be subscribed; got {:?}",
        s_entry.ports
    );
    assert!(
        !s_entry.ports.contains(&p1) && !s_entry.ports.contains(&p2),
        "expected {p1} and {p2} not to be subscribed; got {:?}",
        s_entry.ports
    );

    // Start snoops on nodes B and C to verify no delivery (not subscribed)
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let dev_name_c = topol.nodes[2].port.name().to_string();
    let filter =
        format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");

    let mut snoop_b = SnoopGuard::start(&dev_name_b, &filter)?;
    let mut snoop_c = SnoopGuard::start(&dev_name_c, &filter)?;

    // Start underlay snoop to capture Geneve (UDP/6081) with External replication
    let mut snoop_underlay =
        SnoopGuard::start(UNDERLAY_TEST_DEVICE, GENEVE_UNDERLAY_FILTER)?;

    // Clear UFT before sending to ensure fresh flow computation
    hdl.clear_uft(topol.nodes[0].port.name())?;

    // Send multicast packet from node A
    let payload = "forwarding test";
    let sender_v4 = topol.nodes[0].port.ip();
    topol.nodes[0].zone.send_udp_v4(
        sender_v4,
        mcast_group,
        MCAST_TEST_PORT,
        payload,
    )?;

    // Verify B and C do not receive packets (not subscribed)
    snoop_b.assert_no_packet("on unsubscribed node B");
    snoop_c.assert_no_packet("on unsubscribed node C");

    // Verify underlay multicast forwarding (`Replication::External` mode)
    // Parse the captured Geneve packet and assert:
    // - VNI == DEFAULT_MULTICAST_VNI
    // - Outer IPv6 dst == mcast_underlay (multicast group)
    // - Replication == `Replication::External`
    // Note: In production, the switch would see this External tag and replicate
    // to front panel. This test verifies the Geneve header is correctly formed.
    let snoop_underlay_out =
        snoop_underlay.assert_packet("underlay External replication");
    let stdout_underlay = String::from_utf8_lossy(&snoop_underlay_out.stdout);

    geneve_verify::assert_geneve_packet(
        &stdout_underlay,
        vni,
        mcast_underlay,
        Replication::External,
    );

    Ok(())
}

#[test]
fn test_multicast_tx_same_sled_only() -> Result<()> {
    // Test Tx same-sled delivery in isolation without underlay forwarding.
    // This validates that OPTE's Tx path performs local replication to
    // subscribers on the same sled, independent of forwarding table entries.
    //
    // Behavior(s) tested:
    // - Tx same-sled delivery works without any forwarding entries
    // - Source port (A) does not receive its own packet (self-delivery skipped)
    // - Subscriber ports (B, C) receive packets via guest_loopback during Tx
    // - No packets are sent to the underlay (no forwarding configured)
    //
    // This test exercises Tx behavior by not programming the next hop.

    let topol = xde_tests::three_node_topology()?;

    let mcast_group = Ipv4Addr::from([224, 1, 2, 7]);

    // M2P mapping for multicast group
    let mcast_underlay = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 7,
    ]))
    .unwrap();

    let _mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    // We do NOT set up any forwarding entries. This ensures we're only testing
    // Tx same-sled delivery, not underlay forwarding
    // `mcast.set_forwarding(...)` is intentionally omitted

    // Allow IPv4 multicast traffic and subscribe all nodes
    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    for node in &topol.nodes {
        node.port.add_multicast_router_entry(mcast_cidr)?;
        node.port
            .subscribe_multicast(mcast_group.into())
            .expect("subscribe should succeed");
    }

    // Verify all three nodes are subscribed
    let hdl = OpteHdl::open()?;
    let subs = hdl.dump_mcast_subs()?;
    let s_entry = subs
        .entries
        .iter()
        .find(|e| e.underlay == mcast_underlay)
        .expect("missing multicast subscription entry");
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

    // Verify no forwarding entries exist
    let fwd = hdl.dump_mcast_fwd()?;
    assert!(
        !fwd.entries.iter().any(|e| e.underlay == mcast_underlay),
        "expected no forwarding entries for {mcast_underlay}, got: {:?}",
        fwd.entries
    );

    // Start snoops on nodes B and C (expect delivery) and underlay (expect nothing)
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let dev_name_c = topol.nodes[2].port.name().to_string();
    let filter =
        format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");

    let mut snoop_b = SnoopGuard::start(&dev_name_b, &filter)?;
    let mut snoop_c = SnoopGuard::start(&dev_name_c, &filter)?;

    // Start underlay snoop to verify no packets are sent (no forwarding configured)
    let mut snoop_underlay =
        SnoopGuard::start(UNDERLAY_TEST_DEVICE, GENEVE_UNDERLAY_FILTER)?;

    // Send multicast packet from node A
    let payload = "tx same-sled only";
    let sender_v4 = topol.nodes[0].port.ip();
    topol.nodes[0].zone.send_udp_v4(
        sender_v4,
        mcast_group,
        MCAST_TEST_PORT,
        payload,
    )?;

    // Verify B and C receive packets (essentially from Tx same-sled delivery only)
    snoop_b.assert_packet("Tx same-sled delivery to node B");
    snoop_c.assert_packet("Tx same-sled delivery to node C");

    // Verify no underlay packet was sent (no forwarding configured)
    snoop_underlay.assert_no_packet("(no forwarding entries)");

    Ok(())
}

#[test]
fn test_multicast_underlay_replication_no_local_subscribers() -> Result<()> {
    // Tests `Replication::Underlay` mode without local subscribers.
    //
    // Behavior(s) tested:
    // - Tx forwarding sends Geneve packets to ff04::/16 multicast underlay
    // - Geneve header contains `Replication::Underlay` flag
    // - No same-sled delivery occurs (zero subscribers)
    // - Leaf-only Rx

    // Create 2-node topology to test Underlay replication mode
    let topol = xde_tests::two_node_topology()?;

    // IPv4 multicast group
    let mcast_group = Ipv4Addr::from([224, 1, 2, 4]);
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    // M2P mapping - use admin-scoped IPv6 multicast per Omicron constraints
    let mcast_underlay = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 4,
    ]))
    .unwrap();

    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    let hdl = OpteHdl::open()?;

    // Use node B's underlay address as the next hop to select underlay egress.
    //
    // Note: In this harness, the underlay is a single L2 segment effectively
    // hooked back to itself. Any address reachable on the underlay provides a
    // path for packets to be sent and received on that segment. This differs
    // from product multi-sled underlays. The unicast next hop only selects the
    // underlay egress; the actual packet destination is the multicast address.
    // In production, receiving sleds would perform same-sled delivery to their
    // local subscribers based on the `Replication::Underlay` flag.
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    // Set up Tx forwarding with `Replication::Underlay` mode.
    // Tx behavior: forward to underlay with multicast encapsulation.
    // Rx behavior: same-sled delivery to subscribers (none in this test).
    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::Underlay,
    )])?;

    // Allow IPv4 multicast traffic via Multicast target.
    //
    // Note: We deliberately do not subscribe any nodes. This tests Tx forwarding
    // with zero local subscribers (Rx delivery is based on subscriptions, not
    // `Replication` mode).
    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
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

    // Start snoop on the UNDERLAY simnet device (not the OPTE port)
    // to verify the packet is forwarded to the underlay
    let mut snoop_underlay =
        SnoopGuard::start(UNDERLAY_TEST_DEVICE, GENEVE_UNDERLAY_FILTER)?;

    // Also snoop node B's OPTE port to verify no local delivery with `Replication::Underlay` mode
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let filter_local =
        format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");
    let mut snoop_local = SnoopGuard::start(&dev_name_b, &filter_local)?;

    // Clear UFT before sending to ensure fresh flow computation
    hdl.clear_uft(topol.nodes[0].port.name())?;

    // Send multicast packet from node A
    let payload = "underlay test";
    let sender_v4 = topol.nodes[0].port.ip();
    topol.nodes[0].zone.send_udp_v4(
        sender_v4,
        mcast_group,
        MCAST_TEST_PORT,
        payload,
    )?;

    // Wait for snoop to capture the underlay packet (one send expected)
    let snoop_output_underlay =
        snoop_underlay.assert_packet("underlay Underlay replication");
    let stdout_underlay =
        String::from_utf8_lossy(&snoop_output_underlay.stdout);

    // Verify Geneve header fields (VNI, outer IPv6 dst, replication mode)
    geneve_verify::assert_geneve_packet(
        &stdout_underlay,
        vni,
        mcast_underlay,
        Replication::Underlay,
    );

    // Verify no same-sled delivery (no subscribers = no delivery)
    // Note: Rx delivery is independent of `Replication` mode - it's based on subscriptions
    snoop_local.assert_no_packet("(zero subscribers)");

    // Leaf-only Rx assertion: start a second underlay snoop and ensure there
    // is no additional multicast re-relay after Rx. We expect only the single
    // Tx underlay packet captured above.
    let mut snoop_underlay_2 =
        SnoopGuard::start(UNDERLAY_TEST_DEVICE, GENEVE_UNDERLAY_FILTER)?;
    snoop_underlay_2.assert_no_packet("(leaf-only Rx, no further relay)");

    Ok(())
}

#[test]
fn test_multicast_external_replication_no_local_subscribers() -> Result<()> {
    // Tests `Replication::External` mode without local subscribers.
    // This validates that Tx forwarding works independently of subscription state,
    // mirroring `test_multicast_underlay_replication_no_local_subscribers`.
    //
    // Behavior(s) tested:
    // - Tx forwarding with `Replication::External` flag works without subscribers
    // - No same-sled delivery occurs (zero subscribers = zero local delivery)
    // - Geneve packet sent to underlay with `Replication::External` flag

    let topol = xde_tests::two_node_topology()?;

    // IPv4 multicast group
    let mcast_group = Ipv4Addr::from([224, 1, 2, 8]);
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    // M2P mapping - use admin-scoped IPv6 multicast per Omicron constraints
    let mcast_underlay = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 8,
    ]))
    .unwrap();

    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    let hdl = OpteHdl::open()?;

    // Use node B's underlay address as the next hop to select underlay egress.
    //
    // Note: In this harness, the underlay is a single L2 segment effectively
    // hooked back to itself. Any address reachable on the underlay provides a
    // path for packets to be sent and received on that segment. This differs
    // from product multi-sled underlays. The unicast next hop only selects the
    // underlay egress; the actual packet destination is the multicast address.
    // In production, the switch would see the `Replication::External` flag and
    // replicate to front-panel ports.
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    // Set up Tx forwarding with `Replication::External` mode.
    // Tx behavior: forward to underlay with `Replication::External` flag for
    // boundary switch replication.
    // Rx behavior: same-sled delivery to subscribers (none in this test).
    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::External,
    )])?;

    // Allow IPv4 multicast traffic via Multicast target
    //
    // Note: We deliberately do not subscribe any nodes. This tests Tx forwarding
    // with zero local subscribers (Rx delivery is based on subscriptions, not
    // `Replication` mode).
    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
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

    // Start snoop on the UNDERLAY simnet device (not the OPTE port)
    // to verify the packet is forwarded to the underlay
    let mut snoop_underlay =
        SnoopGuard::start(UNDERLAY_TEST_DEVICE, GENEVE_UNDERLAY_FILTER)?;

    // Also snoop node B's OPTE port to verify no local delivery with `Replication::External` mode
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let filter_local =
        format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");
    let mut snoop_local = SnoopGuard::start(&dev_name_b, &filter_local)?;

    // Clear UFT before sending to ensure fresh flow computation
    hdl.clear_uft(topol.nodes[0].port.name())?;

    // Send multicast packet from node A
    let payload = "external no subs";
    let sender_v4 = topol.nodes[0].port.ip();
    topol.nodes[0].zone.send_udp_v4(
        sender_v4,
        mcast_group,
        MCAST_TEST_PORT,
        payload,
    )?;

    // Wait for snoop to capture the underlay packet
    let snoop_output_underlay =
        snoop_underlay.assert_packet("underlay External no subscribers");
    let stdout_underlay =
        String::from_utf8_lossy(&snoop_output_underlay.stdout);

    // Verify Geneve header fields (VNI, outer IPv6 dst, replication mode)
    geneve_verify::assert_geneve_packet(
        &stdout_underlay,
        vni,
        mcast_underlay,
        Replication::External,
    );

    // Verify no same-sled delivery (no subscribers = no delivery)
    // Note: Rx delivery is independent of `Replication` mode - it's based on subscriptions
    snoop_local.assert_no_packet("(zero subscribers)");

    Ok(())
}

#[test]
fn test_multicast_both_replication() -> Result<()> {
    // Test `Replication::Both` mode: validates that egress Tx (External + Underlay)
    // and local same-sled delivery both occur.

    let topol = xde_tests::three_node_topology()?;

    // IPv4 multicast group
    let mcast_group = Ipv4Addr::from([224, 1, 2, 5]);
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    // M2P mapping - use admin-scoped IPv6 multicast per Omicron constraints
    let mcast_underlay = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 5,
    ]))
    .unwrap();

    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    // Use node B's underlay address as the next hop to select underlay egress.
    //
    // Note: In this harness, the underlay is a single L2 segment effectively
    // hooked back to itself. Any address reachable on the underlay provides a
    // path for packets to be sent and received on that segment. This differs
    // from product multi-sled underlays. The unicast next hop only selects the
    // underlay egress; the actual packet destination is the multicast address.
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    // Set up Tx forwarding with `Replication::Both` (drives egress encapsulation only)
    // Tx behavior: packet sent to underlay with `Replication::Both` flag set.
    // In production, switch receives this and bifurcates: `Replication::External`
    // (to front panel) & `Replication::Underlay` (sled-to-sled multicast).
    // Rx behavior: same-sled delivery occurs independently, driven purely by
    // port subscriptions (not the `Replication` mode).
    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::Both,
    )])?;

    // Allow IPv4 multicast traffic via Multicast target and subscribe to the group
    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
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

    // Start snoops on nodes B and C (same-sled delivery) and underlay
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let dev_name_c = topol.nodes[2].port.name().to_string();
    let filter_local =
        format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");
    let mut snoop_local_b = SnoopGuard::start(&dev_name_b, &filter_local)?;
    let mut snoop_local_c = SnoopGuard::start(&dev_name_c, &filter_local)?;

    let mut snoop_underlay =
        SnoopGuard::start(UNDERLAY_TEST_DEVICE, GENEVE_UNDERLAY_FILTER)?;

    // Send multicast packet from node A
    let payload = "all replication test";
    let sender_v4 = topol.nodes[0].port.ip();
    topol.nodes[0].zone.send_udp_v4(
        sender_v4,
        mcast_group,
        MCAST_TEST_PORT,
        payload,
    )?;

    // Wait for snoops to capture packets
    snoop_local_b.assert_packet("same-sled delivery to node B");
    snoop_local_c.assert_packet("same-sled delivery to node C");
    let snoop_output_underlay =
        snoop_underlay.assert_packet("underlay Replication::Both");
    let stdout_underlay =
        String::from_utf8_lossy(&snoop_output_underlay.stdout);

    // Parse the Geneve packet and verify the `Replication::Both` flag is set
    geneve_verify::assert_geneve_packet(
        &stdout_underlay,
        vni,
        mcast_underlay,
        Replication::Both,
    );

    Ok(())
}

#[test]
fn test_multicast_sender_self_exclusion() -> Result<()> {
    // Test that sender does not receive its own multicast packets.
    // This validates a critical correctness property: senders must be excluded
    // from same-sled delivery to prevent self-delivery loops.
    //
    // Setup:
    // - Single sender (node A) subscribed to the multicast group it sends to
    // - Send packet from A to the group
    // - Verify A does not receive its own packet (timeout expected on snoop)

    let topol = xde_tests::three_node_topology()?;

    let mcast_group = Ipv4Addr::from([224, 1, 2, 9]);

    // M2P mapping for multicast group
    let mcast_underlay = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 9,
    ]))
    .unwrap();

    let _mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    // Allow IPv4 multicast traffic and subscribe ALL nodes (including sender A)
    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    for node in &topol.nodes {
        node.port.add_multicast_router_entry(mcast_cidr)?;
        node.port
            .subscribe_multicast(mcast_group.into())
            .expect("subscribe should succeed");
    }

    // Verify all three nodes are subscribed (including sender A)
    let hdl = OpteHdl::open()?;
    let subs = hdl.dump_mcast_subs()?;
    let s_entry = subs
        .entries
        .iter()
        .find(|e| e.underlay == mcast_underlay)
        .expect("missing multicast subscription entry");
    let p0 = topol.nodes[0].port.name().to_string();
    let p1 = topol.nodes[1].port.name().to_string();
    let p2 = topol.nodes[2].port.name().to_string();
    assert!(
        s_entry.ports.contains(&p0)
            && s_entry.ports.contains(&p1)
            && s_entry.ports.contains(&p2),
        "expected all 3 ports subscribed (including sender A); got {:?}",
        s_entry.ports
    );

    // Start snoops on ALL nodes (A, B, C)
    let dev_name_a = topol.nodes[0].port.name().to_string();
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let dev_name_c = topol.nodes[2].port.name().to_string();
    let filter =
        format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");

    let mut snoop_a = SnoopGuard::start(&dev_name_a, &filter)?;
    let mut snoop_b = SnoopGuard::start(&dev_name_b, &filter)?;
    let mut snoop_c = SnoopGuard::start(&dev_name_c, &filter)?;

    // Send multicast packet from node A (which is subscribed to the group)
    let payload = "sender exclusion test";
    let sender_v4 = topol.nodes[0].port.ip();
    topol.nodes[0].zone.send_udp_v4(
        sender_v4,
        mcast_group,
        MCAST_TEST_PORT,
        payload,
    )?;

    // Verify B and C receive packets (from Tx same-sled delivery)
    snoop_b.assert_packet("Tx same-sled delivery to node B");
    snoop_c.assert_packet("Tx same-sled delivery to node C");

    // Verify A does not receive its own packet (sender self-exclusion)
    // Even though A is subscribed, it must not receive packets it sends
    snoop_a.assert_no_packet("(sender self-exclusion)");

    Ok(())
}

#[test]
fn test_partial_unsubscribe() -> Result<()> {
    // Test selective unsubscribe: subscribe 3 nodes, unsubscribe 1, verify
    // only the remaining 2 receive packets while forwarding state is unchanged.
    let topol = xde_tests::three_node_topology()?;

    let mcast_group = Ipv4Addr::from([224, 1, 2, 6]);
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    let mcast_underlay = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 6,
    ]))
    .unwrap();

    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    // Use node B's underlay address as the next hop to select underlay egress.
    //
    // Note: In this harness, the underlay is a single L2 segment effectively
    // hooked back to itself. Any address reachable on the underlay provides a
    // path for packets to be sent and received on that segment. This differs
    // from product multi-sled underlays. The unicast next hop only selects the
    // underlay egress; the actual packet destination is the multicast address.
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::External,
    )])?;

    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
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
    let filter =
        format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");

    let mut snoop_b = SnoopGuard::start(&dev_name_b, &filter)?;
    let mut snoop_c = SnoopGuard::start(&dev_name_c, &filter)?;

    let payload = "all three";
    let sender_v4 = topol.nodes[0].port.ip();
    topol.nodes[0].zone.send_udp_v4(
        sender_v4,
        mcast_group,
        MCAST_TEST_PORT,
        payload,
    )?;

    // B and C should receive (A is sender, won't see its own packet)
    snoop_b.assert_packet("on node B (first packet)");
    snoop_c.assert_packet("on node C (first packet)");

    // Unsubscribe node B
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
        sender_v4,
        mcast_group,
        MCAST_TEST_PORT,
        payload2,
    )?;

    // C should receive
    snoop_c2.assert_packet("on node C (second packet)");

    // B should not receive (timeout expected)
    snoop_b2.assert_no_packet("on node B after unsubscribe");

    Ok(())
}

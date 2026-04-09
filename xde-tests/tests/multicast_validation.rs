// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Validation tests covering multicast operations.
//!
//! These cover control‑plane validation and idempotence:
//! - Subscribing requires an M2P map unless the group is already a ff04::/16
//!   underlay address.
//! - Subscribing with non‑multicast addresses is rejected.
//! - Double subscribe is idempotent and does not duplicate delivery.
//! - Unsubscribe is idempotent and safe when not previously subscribed.

use anyhow::Result;
use opte_ioctl::OpteHdl;
use oxide_vpc::api::ClearMcast2PhysReq;
use oxide_vpc::api::ClearMcastForwardingReq;
use oxide_vpc::api::DEFAULT_MULTICAST_VNI;
use oxide_vpc::api::IpCidr;
use oxide_vpc::api::Ipv4Addr;
use oxide_vpc::api::Ipv6Addr;
use oxide_vpc::api::McastForwardingNextHop;
use oxide_vpc::api::McastSubscribeReq;
use oxide_vpc::api::McastUnsubscribeAllReq;
use oxide_vpc::api::McastUnsubscribeReq;
use oxide_vpc::api::MulticastUnderlay;
use oxide_vpc::api::NextHopV6;
use oxide_vpc::api::Replication;
use oxide_vpc::api::SourceFilter;
use oxide_vpc::api::Vni;
use xde_tests::GENEVE_UNDERLAY_FILTER;
use xde_tests::IPV4_MULTICAST_CIDR;
use xde_tests::MCAST_TEST_PORT;
use xde_tests::MulticastGroup;
use xde_tests::SNOOP_TIMEOUT_EXPECT_NONE;
use xde_tests::SnoopGuard;
use xde_tests::UNDERLAY_TEST_DEVICE;

#[test]
fn test_subscribe_without_m2p_mapping() -> Result<()> {
    let topol = xde_tests::two_node_topology()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 99]);

    let res = topol.nodes[0].port.subscribe_multicast(mcast_group.into());

    assert!(
        res.is_err(),
        "Expected error when subscribing without M2P mapping, got Ok"
    );

    Ok(())
}

#[test]
fn test_subscribe_ff04_direct_without_m2p() -> Result<()> {
    let topol = xde_tests::two_node_topology()?;

    // IPv6 admin-scoped multicast (ff04::/16) - already an underlay address
    let underlay_mcast = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 99,
    ]))
    .unwrap();

    let res = topol.nodes[0]
        .port
        .subscribe_multicast(Ipv6Addr::from(underlay_mcast).into());

    assert!(
        res.is_ok(),
        "Expected ff04::/16 subscription to succeed without M2P, got error: {res:?}"
    );

    // Assert subscription present
    let hdl = OpteHdl::open()?;
    let subs = hdl.dump_mcast_subs()?;
    let entry = subs
        .entries
        .iter()
        .find(|e| e.underlay == underlay_mcast)
        .expect("missing multicast subscription entry for ff04 group");
    let p0 = topol.nodes[0].port.name().to_string();
    assert!(
        entry.has_port(&p0),
        "expected {p0} to be subscribed; got {:?}",
        entry.subscribers
    );

    Ok(())
}

#[test]
fn test_subscribe_nonexistent_port() -> Result<()> {
    let hdl = OpteHdl::open()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 100]);

    let res = hdl.mcast_subscribe(&McastSubscribeReq {
        port_name: "this_port_does_not_exist_anywhere".to_string(),
        group: mcast_group.into(),
        filter: SourceFilter::default(),
    });

    assert!(
        res.is_err(),
        "Expected error when subscribing non-existent port, got Ok"
    );

    Ok(())
}

#[test]
fn test_subscribe_unicast_ip_as_group() -> Result<()> {
    let topol = xde_tests::two_node_topology()?;
    let hdl = OpteHdl::open()?;

    let unicast_ip = Ipv4Addr::from([10, 0, 0, 1]);
    let res = hdl.mcast_subscribe(&McastSubscribeReq {
        port_name: topol.nodes[0].port.name().to_string(),
        group: unicast_ip.into(),
        filter: SourceFilter::default(),
    });

    let err = res.expect_err("Expected error when subscribing to unicast IP");
    assert!(
        format!("{err:?}").contains("not a multicast address"),
        "Expected 'not a multicast address' error, got: {err:?}",
    );

    Ok(())
}

#[test]
fn test_double_subscribe() -> Result<()> {
    // Verify that subscribing to the same group twice is idempotent and does
    // not duplicate packet delivery.

    let topol = xde_tests::two_node_topology()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 101]);
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    let underlay = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 101,
    ]))
    .unwrap();

    let mcast = MulticastGroup::new(mcast_group.into(), underlay)?;

    // Use node B's underlay address as the switch unicast address for routing.
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    mcast.set_forwarding(vec![McastForwardingNextHop {
        next_hop: NextHopV6::new(fake_switch_addr, vni),
        replication: Replication::External,
        source_filter: SourceFilter::default(),
    }])?;

    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    for node in &topol.nodes {
        node.port.add_multicast_router_entry(mcast_cidr)?;
    }

    topol.nodes[1]
        .port
        .subscribe_multicast(mcast_group.into())
        .expect("first subscribe should succeed");

    let res = topol.nodes[1].port.subscribe_multicast(mcast_group.into());

    assert!(
        res.is_ok(),
        "Double subscribe should be idempotent, got error: {res:?}"
    );

    let subs = OpteHdl::open()?.dump_mcast_subs()?;
    let entry = subs
        .entries
        .iter()
        .find(|e| e.underlay == underlay)
        .expect("missing multicast subscription entry for group");
    let p1 = topol.nodes[1].port.name().to_string();
    assert!(
        entry.has_port(&p1),
        "expected {p1} to be subscribed; got {:?}",
        entry.subscribers
    );

    let filter =
        format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");
    let mut snoop = SnoopGuard::start(topol.nodes[1].port.name(), &filter)?;

    let sender_v4 = topol.nodes[0].port.ip();
    topol.nodes[0].zone.send_udp_v4(
        sender_v4,
        mcast_group,
        MCAST_TEST_PORT,
        "test",
    )?;

    let output = snoop.assert_packet("after double subscribe");

    let stdout = String::from_utf8_lossy(&output.stdout);

    let count = stdout.matches("UDP").count();
    assert!(
        count == 1,
        "Packet should be delivered once, not duplicated. Found {count} deliveries"
    );

    Ok(())
}

#[test]
fn test_unsubscribe_never_subscribed() -> Result<()> {
    let topol = xde_tests::two_node_topology()?;
    let hdl = OpteHdl::open()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 102]);

    let res = hdl.mcast_unsubscribe(&McastUnsubscribeReq {
        port_name: topol.nodes[0].port.name().to_string(),
        group: mcast_group.into(),
    });

    assert!(res.is_ok(), "Unsubscribe should be a no-op (Ok), got: {res:?}");

    Ok(())
}

#[test]
fn test_subscribe_then_clear_m2p() -> Result<()> {
    // Verify that clearing M2P mapping after subscribing stops both local
    // delivery and underlay forwarding for the group.

    let topol = xde_tests::two_node_topology()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 103]);
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    let underlay = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 103,
    ]))
    .unwrap();

    let mcast = MulticastGroup::new(mcast_group.into(), underlay)?;

    // Use node B's underlay address as the switch unicast address for routing.
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    mcast.set_forwarding(vec![McastForwardingNextHop {
        next_hop: NextHopV6::new(fake_switch_addr, vni),
        replication: Replication::External,
        source_filter: SourceFilter::default(),
    }])?;

    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    for node in &topol.nodes {
        node.port.add_multicast_router_entry(mcast_cidr)?;
    }

    topol.nodes[1]
        .port
        .subscribe_multicast(mcast_group.into())
        .expect("subscribe should succeed");

    let hdl = OpteHdl::open()?;
    hdl.clear_m2p(&ClearMcast2PhysReq { group: mcast_group.into(), underlay })
        .expect("clear_m2p should succeed");

    let dev_name_b = topol.nodes[1].port.name().to_string();
    let filter_local =
        format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");
    let mut snoop_local = SnoopGuard::start(&dev_name_b, &filter_local)?;

    let mut snoop_underlay =
        SnoopGuard::start(UNDERLAY_TEST_DEVICE, GENEVE_UNDERLAY_FILTER)?;

    let sender_v4 = topol.nodes[0].port.ip();
    let res = topol.nodes[0].zone.send_udp_v4(
        sender_v4,
        mcast_group,
        MCAST_TEST_PORT,
        "test",
    );

    assert!(res.is_ok(), "Send after M2P clear should succeed: {res:?}");

    snoop_local.assert_no_packet("after M2P clear (local delivery)");
    snoop_underlay.assert_no_packet("after M2P clear (underlay forwarding)");

    Ok(())
}

#[test]
fn test_set_mcast_fwd_rejects_non_default_vni() -> Result<()> {
    let topol = xde_tests::two_node_topology()?;
    let hdl = OpteHdl::open()?;

    let mcast_group = Ipv4Addr::from([224, 1, 2, 200]);
    let underlay = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 200,
    ]))
    .unwrap();

    let _mcast = MulticastGroup::new(mcast_group.into(), underlay)?;

    // Use a non-default VNI and multicast next hop address checks separately
    let bad_vni = Vni::new(DEFAULT_MULTICAST_VNI + 1)?;
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    let res = hdl.set_mcast_fwd(&oxide_vpc::api::SetMcastForwardingReq {
        underlay,
        next_hops: vec![oxide_vpc::api::McastForwardingNextHop {
            next_hop: NextHopV6::new(fake_switch_addr, bad_vni),
            replication: Replication::External,
            source_filter: SourceFilter::default(),
        }],
    });

    assert!(res.is_err(), "set_mcast_fwd should reject non-default VNI");
    Ok(())
}

#[test]
fn test_set_mcast_fwd_rejects_multicast_next_hop() -> Result<()> {
    let _topol = xde_tests::two_node_topology()?;
    let hdl = OpteHdl::open()?;

    let mcast_group = Ipv4Addr::from([224, 1, 2, 201]);
    let underlay = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 201,
    ]))
    .unwrap();

    let _mcast = MulticastGroup::new(mcast_group.into(), underlay)?;

    // Use a multicast address for next hop (invalid)
    let bad_next_hop: Ipv6Addr = "ff04::1".parse().unwrap();
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    let res = hdl.set_mcast_fwd(&oxide_vpc::api::SetMcastForwardingReq {
        underlay,
        next_hops: vec![oxide_vpc::api::McastForwardingNextHop {
            next_hop: NextHopV6::new(bad_next_hop, vni),
            replication: Replication::External,
            source_filter: SourceFilter::default(),
        }],
    });

    assert!(res.is_err(), "set_mcast_fwd should reject multicast next hop");
    Ok(())
}

#[test]
fn test_unsubscribe_ipv6_non_underlay_scopes() -> Result<()> {
    // This test only needs an OPTE port to exist, not IPv6 data plane.
    let topol = xde_tests::two_node_topology()?;
    let hdl = OpteHdl::open()?;

    // ff02::/16 (link-local) and ff0e::/16 (global) are rejected by set_m2p,
    // so no M2P mapping can exist for these scopes. Unsubscribe should be
    // idempotent and return Ok.

    let link_local: Ipv6Addr = "ff02::1:3".parse().unwrap();
    let global: Ipv6Addr = "ff0e::1:3".parse().unwrap();

    let res_ff02 = hdl.mcast_unsubscribe(&McastUnsubscribeReq {
        port_name: topol.nodes[0].port.name().to_string(),
        group: link_local.into(),
    });

    assert!(
        res_ff02.is_ok(),
        "Unsubscribe ff02:: should be idempotent (Ok), got: {res_ff02:?}"
    );

    let res_ff0e = hdl.mcast_unsubscribe(&McastUnsubscribeReq {
        port_name: topol.nodes[0].port.name().to_string(),
        group: global.into(),
    });

    assert!(
        res_ff0e.is_ok(),
        "Unsubscribe ff0e:: should be idempotent (Ok), got: {res_ff0e:?}"
    );

    Ok(())
}

#[test]
fn test_multiple_nexthops_accumulate() -> Result<()> {
    // Test that set_forwarding accumulates next hops like `swadm route add`:
    // - Same underlay + different next hop → add
    // - Same underlay + same next hop → replace replication mode
    let topol = xde_tests::two_node_topology()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 104]);
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    let underlay = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 104,
    ]))
    .unwrap();

    let mcast = MulticastGroup::new(mcast_group.into(), underlay)?;

    let switch_a = topol.nodes[0].port.underlay_ip().into();
    let switch_b = topol.nodes[1].port.underlay_ip().into();

    mcast.set_forwarding(vec![McastForwardingNextHop {
        next_hop: NextHopV6::new(switch_a, vni),
        replication: Replication::External,
        source_filter: SourceFilter::default(),
    }])?;

    let hdl = OpteHdl::open()?;
    let fwd = hdl.dump_mcast_fwd()?;
    let entry = fwd
        .entries
        .iter()
        .find(|e| e.underlay == underlay)
        .expect("missing forwarding entry");
    assert_eq!(entry.next_hops.len(), 1, "Expected 1 next hop after first set");
    assert_eq!(entry.next_hops[0].next_hop.addr, switch_a);
    assert_eq!(entry.next_hops[0].replication, Replication::External);

    mcast.set_forwarding(vec![McastForwardingNextHop {
        next_hop: NextHopV6::new(switch_b, vni),
        replication: Replication::Underlay,
        source_filter: SourceFilter::default(),
    }])?;

    let fwd = hdl.dump_mcast_fwd()?;
    let entry = fwd
        .entries
        .iter()
        .find(|e| e.underlay == underlay)
        .expect("missing forwarding entry");
    assert_eq!(
        entry.next_hops.len(),
        2,
        "Expected 2 next hops after second set"
    );

    let nexthop_a = entry
        .next_hops
        .iter()
        .find(|hop| hop.next_hop.addr == switch_a)
        .expect("switch_a not found");
    let nexthop_b = entry
        .next_hops
        .iter()
        .find(|hop| hop.next_hop.addr == switch_b)
        .expect("switch_b not found");

    assert_eq!(
        nexthop_a.replication,
        Replication::External,
        "switch_a should have External"
    );
    assert_eq!(
        nexthop_b.replication,
        Replication::Underlay,
        "switch_b should have Underlay"
    );

    mcast.set_forwarding(vec![McastForwardingNextHop {
        next_hop: NextHopV6::new(switch_a, vni),
        replication: Replication::Both,
        source_filter: SourceFilter::default(),
    }])?;

    let fwd = hdl.dump_mcast_fwd()?;
    let entry = fwd
        .entries
        .iter()
        .find(|e| e.underlay == underlay)
        .expect("missing forwarding entry");
    assert_eq!(
        entry.next_hops.len(),
        2,
        "Expected 2 next hops after updating switch_a"
    );

    let nexthop_a = entry
        .next_hops
        .iter()
        .find(|hop| hop.next_hop.addr == switch_a)
        .expect("switch_a not found");
    let nexthop_b = entry
        .next_hops
        .iter()
        .find(|hop| hop.next_hop.addr == switch_b)
        .expect("switch_b not found");

    assert_eq!(
        nexthop_a.replication,
        Replication::Both,
        "switch_a should now have Both (updated)"
    );
    assert_eq!(
        nexthop_b.replication,
        Replication::Underlay,
        "switch_b should still have Underlay"
    );

    Ok(())
}

#[test]
fn test_unsubscribe_all() -> Result<()> {
    // Verify that unsubscribe_all removes all port subscriptions for a group
    // and is idempotent when called multiple times.

    let topol = xde_tests::two_node_topology()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 105]);

    let underlay = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 105,
    ]))
    .unwrap();

    let _mcast = MulticastGroup::new(mcast_group.into(), underlay)?;

    // Subscribe both ports
    topol.nodes[0]
        .port
        .subscribe_multicast(mcast_group.into())
        .expect("port 0 subscribe should succeed");

    topol.nodes[1]
        .port
        .subscribe_multicast(mcast_group.into())
        .expect("port 1 subscribe should succeed");

    // Verify both ports are subscribed
    let hdl = OpteHdl::open()?;
    let subs = hdl.dump_mcast_subs()?;
    let entry = subs
        .entries
        .iter()
        .find(|e| e.underlay == underlay)
        .expect("missing multicast subscription entry for group");

    let p0 = topol.nodes[0].port.name().to_string();
    let p1 = topol.nodes[1].port.name().to_string();
    assert_eq!(
        entry.subscribers.len(),
        2,
        "Expected 2 ports subscribed before unsubscribe_all"
    );
    assert!(
        entry.has_port(&p0),
        "expected {p0} to be subscribed; got {:?}",
        entry.subscribers
    );
    assert!(
        entry.has_port(&p1),
        "expected {p1} to be subscribed; got {:?}",
        entry.subscribers
    );

    // Unsubscribe all ports from the group
    let res = hdl.mcast_unsubscribe_all(&McastUnsubscribeAllReq {
        group: mcast_group.into(),
    });
    assert!(res.is_ok(), "mcast_unsubscribe_all should succeed, got: {res:?}");

    // Verify no ports are subscribed
    let subs = hdl.dump_mcast_subs()?;
    let entry = subs.entries.iter().find(|e| e.underlay == underlay);
    assert!(
        entry.is_none(),
        "Expected no subscription entry after unsubscribe_all, found: {entry:?}"
    );

    // Verify idempotence: calling again should succeed
    let res = hdl.mcast_unsubscribe_all(&McastUnsubscribeAllReq {
        group: mcast_group.into(),
    });
    assert!(
        res.is_ok(),
        "mcast_unsubscribe_all should be idempotent, got: {res:?}"
    );

    Ok(())
}

#[test]
fn test_unsubscribe_all_without_m2p() -> Result<()> {
    let _topol = xde_tests::two_node_topology()?;
    let hdl = OpteHdl::open()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 106]);

    // Without M2P mapping, unsubscribe_all should be idempotent and succeed
    let res = hdl.mcast_unsubscribe_all(&McastUnsubscribeAllReq {
        group: mcast_group.into(),
    });

    assert!(
        res.is_ok(),
        "mcast_unsubscribe_all without M2P should succeed (idempotent), got: {res:?}"
    );

    Ok(())
}

#[test]
fn test_clear_forwarding_stops_underlay_egress() -> Result<()> {
    // Clearing the multicast forwarding entry should stop underlay egress,
    // independent of subscription state.
    let topol = xde_tests::two_node_topology()?;

    let mcast_group = Ipv4Addr::from([224, 1, 2, 210]);
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    let underlay = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 210,
    ]))
    .unwrap();

    let mcast = MulticastGroup::new(mcast_group.into(), underlay)?;

    // Route via node B's underlay address to select the egress link.
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();
    mcast.set_forwarding(vec![McastForwardingNextHop {
        next_hop: NextHopV6::new(fake_switch_addr, vni),
        replication: Replication::Underlay,
        source_filter: SourceFilter::default(),
    }])?;

    // Allow IPv4 multicast traffic via Multicast target
    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    for node in &topol.nodes {
        node.port.add_multicast_router_entry(mcast_cidr)?;
    }

    // Subscribe sender port to enable multicast Tx processing
    topol.nodes[0]
        .port
        .subscribe_multicast(mcast_group.into())
        .expect("subscribe node 0 should succeed");

    // Verify forwarding table contains the expected entry
    let hdl = OpteHdl::open()?;
    let fwd = hdl.dump_mcast_fwd()?;
    let entry = fwd
        .entries
        .iter()
        .find(|e| e.underlay == underlay)
        .expect("missing forwarding entry before send");
    assert_eq!(
        entry.next_hops.len(),
        1,
        "Expected 1 next hop in forwarding table"
    );
    assert_eq!(
        entry.next_hops[0].replication,
        Replication::Underlay,
        "Expected Underlay replication mode"
    );

    // First send should produce an underlay Geneve packet
    let mut snoop_underlay =
        SnoopGuard::start(UNDERLAY_TEST_DEVICE, GENEVE_UNDERLAY_FILTER)?;
    let sender_v4 = topol.nodes[0].port.ip();
    topol.nodes[0].zone.send_udp_v4(
        sender_v4,
        mcast_group,
        MCAST_TEST_PORT,
        "first",
    )?;
    snoop_underlay.assert_packet("before clearing forwarding");

    // Clear forwarding entry
    hdl.clear_mcast_fwd(&ClearMcastForwardingReq { underlay })?;

    // Verify forwarding entry was removed from table
    let fwd_after = hdl.dump_mcast_fwd()?;
    assert!(
        fwd_after.entries.iter().all(|e| e.underlay != underlay),
        "Expected no forwarding entry after clear_mcast_fwd"
    );

    // Subsequent sends should not egress to underlay (forwarding cleared)
    let mut snoop_underlay2 =
        SnoopGuard::start(UNDERLAY_TEST_DEVICE, GENEVE_UNDERLAY_FILTER)?;
    topol.nodes[0].zone.send_udp_v4(
        sender_v4,
        mcast_group,
        MCAST_TEST_PORT,
        "second",
    )?;
    if let Ok(out2) =
        snoop_underlay2.wait_with_timeout(SNOOP_TIMEOUT_EXPECT_NONE)
    {
        let stdout2 = String::from_utf8_lossy(&out2.stdout);
        panic!(
            "No underlay egress expected after clearing forwarding; got:\n{stdout2}"
        );
    }

    // Verify idempotence: clearing again should succeed
    let res = hdl.clear_mcast_fwd(&ClearMcastForwardingReq { underlay });
    assert!(res.is_ok(), "clear_mcast_fwd should be idempotent, got: {res:?}");

    Ok(())
}

#[test]
fn test_multiple_simultaneous_groups() -> Result<()> {
    // Tests that multiple multicast groups can be configured and operate
    // independently without interference.
    //
    // This validates:
    // - Two groups can have separate M2P mappings
    // - Subscriptions to one group don't affect another
    // - Packets sent to group A are only delivered to group A subscribers
    // - Packets sent to group B are only delivered to group B subscribers

    let topol = xde_tests::two_node_topology()?;

    // Configure two distinct multicast groups
    let group_a = Ipv4Addr::from([224, 1, 2, 10]);
    let group_b = Ipv4Addr::from([224, 1, 2, 11]);

    let underlay_a =
        MulticastUnderlay::new("ff04::e001:20a".parse().unwrap()).unwrap();
    let underlay_b =
        MulticastUnderlay::new("ff04::e001:20b".parse().unwrap()).unwrap();

    let mcast_a = MulticastGroup::new(group_a.into(), underlay_a)?;
    let mcast_b = MulticastGroup::new(group_b.into(), underlay_b)?;

    // Allow multicast traffic
    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr)?;

    // Subscribe node 0 to group A only, node 1 to group B only
    topol.nodes[0]
        .port
        .subscribe_multicast(group_a.into())
        .expect("subscribe node 0 to group A");
    topol.nodes[1]
        .port
        .subscribe_multicast(group_b.into())
        .expect("subscribe node 1 to group B");

    // Verify subscription state
    let hdl = OpteHdl::open()?;
    let subs = hdl.dump_mcast_subs()?;

    let p0 = topol.nodes[0].port.name().to_string();
    let p1 = topol.nodes[1].port.name().to_string();

    // Group A should have only node 0
    let entry_a = subs
        .entries
        .iter()
        .find(|e| e.underlay == underlay_a)
        .expect("missing subscription entry for group A");
    assert!(
        entry_a.has_port(&p0) && !entry_a.has_port(&p1),
        "group A should have only node 0; got {:?}",
        entry_a.subscribers
    );

    // Group B should have only node 1
    let entry_b = subs
        .entries
        .iter()
        .find(|e| e.underlay == underlay_b)
        .expect("missing subscription entry for group B");
    assert!(
        entry_b.has_port(&p1) && !entry_b.has_port(&p0),
        "group B should have only node 1; got {:?}",
        entry_b.subscribers
    );

    // Set up forwarding for both groups (needed for Tx path)
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;
    let fake_switch = topol.nodes[1].port.underlay_ip().into();
    mcast_a.set_forwarding(vec![McastForwardingNextHop {
        next_hop: NextHopV6::new(fake_switch, vni),
        replication: Replication::Underlay,
        source_filter: SourceFilter::default(),
    }])?;
    mcast_b.set_forwarding(vec![McastForwardingNextHop {
        next_hop: NextHopV6::new(fake_switch, vni),
        replication: Replication::Underlay,
        source_filter: SourceFilter::default(),
    }])?;

    // Start snoops on node B (we send from node 0, so we snoop on node 1)
    let dev_b = topol.nodes[1].port.name().to_string();
    let filter_a =
        format!("udp and ip dst {group_a} and port {MCAST_TEST_PORT}");
    let filter_b =
        format!("udp and ip dst {group_b} and port {MCAST_TEST_PORT}");

    // Test 1: Send to group A - only node 0 should potentially receive
    // (but node 0 is sender, so self-exclusion applies; node 1 not subscribed)
    let mut snoop_b_for_a = SnoopGuard::start(&dev_b, &filter_a)?;

    topol.nodes[0].zone.send_udp_v4(
        topol.nodes[0].port.ip(),
        group_a,
        MCAST_TEST_PORT,
        "group A packet",
    )?;

    // Node 1 should NOT receive group A packet (not subscribed to A)
    snoop_b_for_a.assert_no_packet("node 1 for group A (not subscribed)");

    // Test 2: Send to group B from node 0 - node 1 should receive (subscribed to B)
    // Node 0 is not subscribed to B, so it won't receive via same-sled
    let mut snoop_b_for_b = SnoopGuard::start(&dev_b, &filter_b)?;

    topol.nodes[0].zone.send_udp_v4(
        topol.nodes[0].port.ip(),
        group_b,
        MCAST_TEST_PORT,
        "group B packet",
    )?;

    // Node 1 SHOULD receive group B packet (subscribed to B, receives via Rx path)
    snoop_b_for_b.assert_packet("node 1 for group B (subscribed)");

    Ok(())
}

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
use oxide_vpc::api::IpCidr;
use oxide_vpc::api::Ipv4Addr;
use oxide_vpc::api::Ipv6Addr;
use oxide_vpc::api::McastSubscribeReq;
use oxide_vpc::api::McastUnsubscribeReq;
use oxide_vpc::api::NextHopV6;
use oxide_vpc::api::Replication;
use oxide_vpc::api::Vni;
use std::time::Duration;
use xde_tests::MulticastGroup;
use xde_tests::SnoopGuard;

#[test]
fn test_subscribe_without_m2p_mapping() -> Result<()> {
    let topol =
        xde_tests::two_node_topology_named("omicron1", "nm2pa", "nm2pb")?;
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
    let topol =
        xde_tests::two_node_topology_named("omicron1", "ff04a", "ff04b")?;

    // IPv6 admin-scoped multicast (ff04::/16) - already an underlay address
    let underlay_mcast = Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 99,
    ]);

    let res = topol.nodes[0].port.subscribe_multicast(underlay_mcast.into());

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
        entry.ports.contains(&p0),
        "expected {p0} to be subscribed; got {:?}",
        entry.ports
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
    });

    assert!(
        res.is_err(),
        "Expected error when subscribing non-existent port, got Ok"
    );

    Ok(())
}

#[test]
fn test_subscribe_unicast_ip_as_group() -> Result<()> {
    let topol = xde_tests::two_node_topology_named("omicron1", "unia", "unib")?;
    let hdl = OpteHdl::open()?;

    let unicast_ip = Ipv4Addr::from([10, 0, 0, 1]);
    let res = hdl.mcast_subscribe(&McastSubscribeReq {
        port_name: topol.nodes[0].port.name().to_string(),
        group: unicast_ip.into(),
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
    let topol = xde_tests::two_node_topology_named("omicron1", "dsa", "dsb")?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 101]);
    const MCAST_PORT: u16 = 9999; // Avoid mDNS port 5353
    let vni = Vni::new(oxide_vpc::api::DEFAULT_MULTICAST_VNI)?;

    let underlay = Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 101,
    ]);

    let mcast = MulticastGroup::new(mcast_group.into(), underlay)?;

    // Use node B's underlay address as the switch unicast address for routing.
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::External,
    )])?;

    let mcast_cidr = IpCidr::Ip4("224.0.0.0/4".parse().unwrap());
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
        entry.ports.contains(&p1),
        "expected {p1} to be subscribed; got {:?}",
        entry.ports
    );

    let filter = format!("udp and ip dst {mcast_group} and port {MCAST_PORT}");
    let mut snoop = SnoopGuard::start(topol.nodes[1].port.name(), &filter)?;

    let sender_v4 = topol.nodes[0].port.ip();
    topol.nodes[0].zone.send_udp_v4(
        &sender_v4,
        &mcast_group.to_string(),
        MCAST_PORT,
        "test",
    )?;

    let output = snoop.wait_with_timeout(Duration::from_secs(5))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success() && stdout.contains("UDP"),
        "Should receive multicast after double subscribe:\n{stdout}"
    );

    let count = stdout.matches("UDP").count();
    assert!(
        count == 1,
        "Packet should be delivered once, not duplicated. Found {count} deliveries"
    );

    Ok(())
}

#[test]
fn test_unsubscribe_never_subscribed() -> Result<()> {
    let topol = xde_tests::two_node_topology_named("omicron1", "usa", "usb")?;
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
    let topol = xde_tests::two_node_topology_named("omicron1", "sca", "scb")?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 103]);
    const MCAST_PORT: u16 = 9999; // Avoid mDNS port 5353
    let vni = Vni::new(oxide_vpc::api::DEFAULT_MULTICAST_VNI)?;

    let underlay = Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 103,
    ]);

    let mcast = MulticastGroup::new(mcast_group.into(), underlay)?;

    // Use node B's underlay address as the switch unicast address for routing.
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::External,
    )])?;

    let mcast_cidr = IpCidr::Ip4("224.0.0.0/4".parse().unwrap());
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
        format!("udp and ip dst {mcast_group} and port {MCAST_PORT}");
    let mut snoop_local = SnoopGuard::start(&dev_name_b, &filter_local)?;

    let underlay_dev = "xde_test_sim1";
    let mut snoop_underlay =
        SnoopGuard::start(underlay_dev, "ip6 and udp port 6081")?;

    let sender_v4 = topol.nodes[0].port.ip();
    let res = topol.nodes[0].zone.send_udp_v4(
        &sender_v4,
        &mcast_group.to_string(),
        MCAST_PORT,
        "test",
    );

    assert!(res.is_ok(), "Send after M2P clear should succeed: {res:?}");

    if let Ok(out) = snoop_local.wait_with_timeout(Duration::from_secs(2)) {
        let stdout = String::from_utf8_lossy(&out.stdout);
        panic!("No local delivery expected; got:\n{stdout}");
    }

    if let Ok(out) = snoop_underlay.wait_with_timeout(Duration::from_secs(2)) {
        let stdout = String::from_utf8_lossy(&out.stdout);
        panic!(
            "No underlay forwarding expected after M2P clear; got:\n{stdout}"
        );
    }

    Ok(())
}

#[test]
fn test_set_mcast_fwd_rejects_non_default_vni() -> Result<()> {
    let topol = xde_tests::two_node_topology_named("omicron1", "vnix", "vniy")?;
    let hdl = OpteHdl::open()?;

    let mcast_group = Ipv4Addr::from([224, 1, 2, 200]);
    let underlay = Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 200,
    ]);

    let _mcast = MulticastGroup::new(mcast_group.into(), underlay)?;

    // Use a non-default VNI and multicast next-hop address checks separately
    let bad_vni = Vni::new(oxide_vpc::api::DEFAULT_MULTICAST_VNI + 1)?;
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    let res = hdl.set_mcast_fwd(&oxide_vpc::api::SetMcastForwardingReq {
        underlay,
        next_hops: vec![(
            NextHopV6::new(fake_switch_addr, bad_vni),
            Replication::External,
        )],
    });

    assert!(res.is_err(), "set_mcast_fwd should reject non-default VNI");
    Ok(())
}

#[test]
fn test_set_mcast_fwd_rejects_multicast_next_hop() -> Result<()> {
    let _topol =
        xde_tests::two_node_topology_named("omicron1", "mnhx", "mnhy")?;
    let hdl = OpteHdl::open()?;

    let mcast_group = Ipv4Addr::from([224, 1, 2, 201]);
    let underlay = Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 201,
    ]);

    let _mcast = MulticastGroup::new(mcast_group.into(), underlay)?;

    // Use a multicast address for next-hop (invalid)
    let bad_next_hop: Ipv6Addr = "ff04::1".parse().unwrap();
    let vni = Vni::new(oxide_vpc::api::DEFAULT_MULTICAST_VNI)?;

    let res = hdl.set_mcast_fwd(&oxide_vpc::api::SetMcastForwardingReq {
        underlay,
        next_hops: vec![(
            NextHopV6::new(bad_next_hop, vni),
            Replication::External,
        )],
    });

    assert!(res.is_err(), "set_mcast_fwd should reject multicast next-hop");
    Ok(())
}

#[test]
fn test_unsubscribe_ipv6_non_underlay_scopes() -> Result<()> {
    let topol = xde_tests::two_node_topology_dualstack_named(
        "omicron1", "unsv6a", "unsv6b",
    )?;
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
    // Test that set_forwarding accumulates next-hops like `swadm route add`:
    // - Same underlay + different next-hop → add
    // - Same underlay + same next-hop → replace replication mode
    let topol = xde_tests::two_node_topology_named("omicron1", "mnha", "mnhb")?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 104]);
    let vni = Vni::new(oxide_vpc::api::DEFAULT_MULTICAST_VNI)?;

    let underlay = Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 104,
    ]);

    let mcast = MulticastGroup::new(mcast_group.into(), underlay)?;

    let switch_a = topol.nodes[0].port.underlay_ip().into();
    let switch_b = topol.nodes[1].port.underlay_ip().into();

    mcast.set_forwarding(vec![(
        NextHopV6::new(switch_a, vni),
        Replication::External,
    )])?;

    let hdl = OpteHdl::open()?;
    let fwd = hdl.dump_mcast_fwd()?;
    let entry = fwd
        .entries
        .iter()
        .find(|e| e.underlay == underlay)
        .expect("missing forwarding entry");
    assert_eq!(entry.next_hops.len(), 1, "Expected 1 next-hop after first set");
    assert_eq!(entry.next_hops[0].0.addr, switch_a);
    assert_eq!(entry.next_hops[0].1, Replication::External);

    mcast.set_forwarding(vec![(
        NextHopV6::new(switch_b, vni),
        Replication::Underlay,
    )])?;

    let fwd = hdl.dump_mcast_fwd()?;
    let entry = fwd
        .entries
        .iter()
        .find(|e| e.underlay == underlay)
        .expect("missing forwarding entry");
    assert_eq!(
        entry.next_hops.len(),
        2,
        "Expected 2 next-hops after second set"
    );

    let nexthop_a = entry
        .next_hops
        .iter()
        .find(|(nexthop, _)| nexthop.addr == switch_a)
        .expect("switch_a not found");
    let nexthop_b = entry
        .next_hops
        .iter()
        .find(|(nexthop, _)| nexthop.addr == switch_b)
        .expect("switch_b not found");

    assert_eq!(
        nexthop_a.1,
        Replication::External,
        "switch_a should have External"
    );
    assert_eq!(
        nexthop_b.1,
        Replication::Underlay,
        "switch_b should have Underlay"
    );

    mcast.set_forwarding(vec![(
        NextHopV6::new(switch_a, vni),
        Replication::Both,
    )])?;

    let fwd = hdl.dump_mcast_fwd()?;
    let entry = fwd
        .entries
        .iter()
        .find(|e| e.underlay == underlay)
        .expect("missing forwarding entry");
    assert_eq!(
        entry.next_hops.len(),
        2,
        "Expected 2 next-hops after updating switch_a"
    );

    let nexthop_a = entry
        .next_hops
        .iter()
        .find(|(nexthop, _)| nexthop.addr == switch_a)
        .expect("switch_a not found");
    let nexthop_b = entry
        .next_hops
        .iter()
        .find(|(nexthop, _)| nexthop.addr == switch_b)
        .expect("switch_b not found");

    assert_eq!(
        nexthop_a.1,
        Replication::Both,
        "switch_a should now have Both (updated)"
    );
    assert_eq!(
        nexthop_b.1,
        Replication::Underlay,
        "switch_b should still have Underlay"
    );

    Ok(())
}

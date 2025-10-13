// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Validation tests covering multicast operations.

use anyhow::Context;
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
fn test_subscribe_nonexistent_port() -> Result<()> {
    let hdl = OpteHdl::open()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 100]);

    // Try to subscribe non-existent port
    let result = hdl.mcast_subscribe(&McastSubscribeReq {
        port_name: "this_port_does_not_exist_anywhere".to_string(),
        group: mcast_group.into(),
    });

    // Should return error, not panic or succeed
    assert!(
        result.is_err(),
        "Expected error when subscribing non-existent port, got Ok"
    );

    Ok(())
}

#[test]
fn test_subscribe_unicast_ip_as_group() -> Result<()> {
    let topol = xde_tests::two_node_topology_named("omicron1", "unia", "unib")?;
    let hdl = OpteHdl::open()?;

    // Try to subscribe to unicast IP (not multicast) - should be rejected
    let unicast_ip = Ipv4Addr::from([10, 0, 0, 1]);
    let result = hdl.mcast_subscribe(&McastSubscribeReq {
        port_name: topol.nodes[0].port.name().to_string(),
        group: unicast_ip.into(),
    });

    // Should reject non-multicast addresses
    match result {
        Ok(_) => {
            panic!("Expected error when subscribing to unicast IP, got Ok")
        }
        Err(e) => {
            assert!(
                format!("{e:?}").contains("not a multicast address"),
                "Expected 'not a multicast address' error, got: {e:?}",
            );
        }
    }

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

    let mcast = MulticastGroup::new(mcast_group.into(), underlay, vni)?;

    let node_b_underlay = Ipv6Addr::from([
        0xfd, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
    ]);

    mcast.set_forwarding(vec![(
        NextHopV6::new(node_b_underlay, vni),
        Replication::External,
    )])?;

    let mcast_cidr = IpCidr::Ip4("224.0.0.0/4".parse().unwrap());
    for node in &topol.nodes {
        node.port.add_multicast_router_entry(mcast_cidr)?;
    }

    // Subscribe once
    topol.nodes[1].port.subscribe_multicast(mcast_group.into())?;

    // Subscribe again (should be idempotent)
    let result = topol.nodes[1].port.subscribe_multicast(mcast_group.into());

    // Should succeed (idempotent operation)
    assert!(
        result.is_ok(),
        "Double subscribe should be idempotent, got error: {:?}",
        result
    );

    // Verify delivery works and packet is NOT duplicated
    let filter = format!("udp and ip dst {mcast_group} and port {MCAST_PORT}");
    let mut snoop = SnoopGuard::start(topol.nodes[1].port.name(), &filter)?;

    topol.nodes[0].zone.zone.zexec(&format!(
        "echo 'test' | nc -u -w1 {mcast_group} {MCAST_PORT}"
    ))?;

    let output = snoop
        .wait_with_timeout(Duration::from_secs(5))
        .context("Timeout waiting for multicast delivery")?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify packet received
    assert!(
        output.status.success() && stdout.contains("UDP"),
        "Should receive multicast after double subscribe:\n{stdout}"
    );

    // Count occurrences - should be 1, not 2 (no duplication)
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

    // Try to unsubscribe without ever subscribing
    let result = hdl.mcast_unsubscribe(&McastUnsubscribeReq {
        port_name: topol.nodes[0].port.name().to_string(),
        group: mcast_group.into(),
    });

    // Expected: Ok (no-op). Unsubscribe is idempotent for existing ports.
    assert!(
        result.is_ok(),
        "Unsubscribe should be a no-op (Ok), got: {result:?}"
    );

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

    let mcast = MulticastGroup::new(mcast_group.into(), underlay, vni)?;

    let node_b_underlay = Ipv6Addr::from([
        0xfd, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
    ]);

    mcast.set_forwarding(vec![(
        NextHopV6::new(node_b_underlay, vni),
        Replication::External,
    )])?;

    let mcast_cidr = IpCidr::Ip4("224.0.0.0/4".parse().unwrap());
    for node in &topol.nodes {
        node.port.add_multicast_router_entry(mcast_cidr)?;
    }

    topol.nodes[1].port.subscribe_multicast(mcast_group.into())?;

    // Clear M2P while subscription active
    let hdl = OpteHdl::open()?;
    hdl.clear_m2p(&ClearMcast2PhysReq {
        group: mcast_group.into(),
        underlay,
        vni,
    })?;

    // Start snoops to verify NO delivery occurs after M2P clear
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let filter_local =
        format!("udp and ip dst {mcast_group} and port {MCAST_PORT}");
    let mut snoop_local = SnoopGuard::start(&dev_name_b, &filter_local)?;

    let underlay_dev = "xde_test_sim1";
    let mut snoop_underlay =
        SnoopGuard::start(underlay_dev, "ip6 and udp port 6081")?;

    // Send packet - command should execute successfully regardless of delivery
    let result = topol.nodes[0]
        .zone
        .zone
        .zexec(&format!("echo 'test' | nc -u -w1 {mcast_group} {MCAST_PORT}"));

    // Expected: Ok (command executed). Delivery should NOT occur.
    assert!(result.is_ok(), "Send after M2P clear should succeed: {result:?}");

    // Verify no local delivery
    if let Ok(out) = snoop_local.wait_with_timeout(Duration::from_secs(2)) {
        let stdout = String::from_utf8_lossy(&out.stdout);
        panic!("No local delivery expected; got:\n{stdout}");
    }

    // Verify no underlay forwarding (encap denied without M2P)
    if let Ok(out) = snoop_underlay.wait_with_timeout(Duration::from_secs(2)) {
        let stdout = String::from_utf8_lossy(&out.stdout);
        panic!(
            "No underlay forwarding expected after M2P clear; got:\n{stdout}"
        );
    }

    Ok(())
}

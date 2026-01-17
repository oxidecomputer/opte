// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Source filtering tests for multicast subscriptions.
//!
//! These validate IGMPv3/MLDv2 source filtering semantics per RFC 3376/3810:
//! - INCLUDE(sources) only accepts packets from listed sources.
//! - INCLUDE() (empty) blocks all sources.
//! - EXCLUDE(sources) blocks listed sources but accepts others.
//! - EXCLUDE() (empty) accepts all sources (*, G) - default ASM behavior.
//! - Filter changes via re-subscribe take effect immediately.
//!
//! See <https://www.rfc-editor.org/rfc/rfc3376> (IGMPv3) and
//! <https://www.rfc-editor.org/rfc/rfc3810> (MLDv2).

use anyhow::Result;
use oxide_vpc::api::DEFAULT_MULTICAST_VNI;
use oxide_vpc::api::FilterMode;
use oxide_vpc::api::IpAddr;
use oxide_vpc::api::IpCidr;
use oxide_vpc::api::Ipv4Addr;
use oxide_vpc::api::MulticastUnderlay;
use oxide_vpc::api::NextHopV6;
use oxide_vpc::api::Replication;
use oxide_vpc::api::SourceFilter;
use oxide_vpc::api::Vni;
use xde_tests::IPV4_MULTICAST_CIDR;
use xde_tests::MCAST_TEST_PORT;
use xde_tests::MulticastGroup;
use xde_tests::SnoopGuard;

/// Create an INCLUDE filter with specified sources.
fn include_filter(sources: impl IntoIterator<Item = IpAddr>) -> SourceFilter {
    SourceFilter {
        mode: FilterMode::Include,
        sources: sources.into_iter().collect(),
    }
}

/// Helper to create an EXCLUDE filter with specified sources.
fn exclude_filter(sources: impl IntoIterator<Item = IpAddr>) -> SourceFilter {
    SourceFilter {
        mode: FilterMode::Exclude,
        sources: sources.into_iter().collect(),
    }
}

#[test]
fn test_include_filter_allows_listed_source() -> Result<()> {
    // When subscribed with INCLUDE(sender_ip), packets from sender should
    // be delivered.
    let topol = xde_tests::two_node_topology()?;
    let mcast_group = Ipv4Addr::from([224, 0, 0, 252]);
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    let mcast_underlay =
        MulticastUnderlay::new("ff04::e000:fc".parse().unwrap()).unwrap();
    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();
    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::Underlay,
    )])?;

    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr)?;

    // Sender's IP
    let sender_ip: IpAddr = topol.nodes[0].port.ip().into();

    // Subscribe receiver with INCLUDE(sender_ip) - should allow sender
    topol.nodes[1].port.subscribe_multicast_filtered(
        mcast_group.into(),
        include_filter([sender_ip]),
    )?;

    // Start snoop on receiver
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let filter =
        format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");
    let mut snoop = SnoopGuard::start(&dev_name_b, &filter)?;

    // Send from allowed source
    let payload = "allowed source test";
    topol.nodes[0].zone.send_udp_v4(
        topol.nodes[0].port.ip(),
        mcast_group,
        MCAST_TEST_PORT,
        payload,
    )?;

    // Should receive the packet
    let output = snoop.assert_packet("from allowed source");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("224.0.0.252"),
        "expected multicast destination in output: {stdout}"
    );

    Ok(())
}

#[test]
fn test_include_filter_blocks_unlisted_source() -> Result<()> {
    // When subscribed with INCLUDE(other_ip), packets from sender should
    // be blocked because sender is not in the include list.
    let topol = xde_tests::two_node_topology()?;
    let mcast_group = Ipv4Addr::from([224, 0, 0, 253]);
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    let mcast_underlay =
        MulticastUnderlay::new("ff04::e000:fd".parse().unwrap()).unwrap();
    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();
    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::Underlay,
    )])?;

    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr)?;

    // Some other IP that's not the sender
    let other_ip: IpAddr = Ipv4Addr::from([10, 99, 99, 99]).into();

    // Subscribe receiver with INCLUDE(other_ip) - should block sender
    topol.nodes[1].port.subscribe_multicast_filtered(
        mcast_group.into(),
        include_filter([other_ip]),
    )?;

    // Start snoop on receiver
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let filter =
        format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");
    let mut snoop = SnoopGuard::start(&dev_name_b, &filter)?;

    // Send from source not in include list
    let payload = "blocked source test";
    topol.nodes[0].zone.send_udp_v4(
        topol.nodes[0].port.ip(),
        mcast_group,
        MCAST_TEST_PORT,
        payload,
    )?;

    // Should not receive the packet
    snoop.assert_no_packet("from unlisted source with INCLUDE filter");

    Ok(())
}

#[test]
fn test_include_empty_blocks_all() -> Result<()> {
    // INCLUDE() means accept nothing - all packets should be blocked.
    let topol = xde_tests::two_node_topology()?;
    let mcast_group = Ipv4Addr::from([224, 0, 0, 254]);
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    let mcast_underlay =
        MulticastUnderlay::new("ff04::e000:fe".parse().unwrap()).unwrap();
    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();
    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::Underlay,
    )])?;

    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr)?;

    // Subscribe receiver with INCLUDE() (empty) - blocks all
    topol.nodes[1].port.subscribe_multicast_filtered(
        mcast_group.into(),
        include_filter(std::iter::empty::<IpAddr>()),
    )?;

    // Start snoop on receiver
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let filter =
        format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");
    let mut snoop = SnoopGuard::start(&dev_name_b, &filter)?;

    // Send packet
    let payload = "should be blocked";
    topol.nodes[0].zone.send_udp_v4(
        topol.nodes[0].port.ip(),
        mcast_group,
        MCAST_TEST_PORT,
        payload,
    )?;

    // Should not receive - INCLUDE() blocks everything
    snoop.assert_no_packet("with INCLUDE() (empty) filter");

    Ok(())
}

#[test]
fn test_exclude_empty_allows_all() -> Result<()> {
    // EXCLUDE() means accept any source - this is the default ASM behavior.
    let topol = xde_tests::two_node_topology()?;
    let mcast_group = Ipv4Addr::from([224, 0, 1, 1]);
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    let mcast_underlay =
        MulticastUnderlay::new("ff04::e000:101".parse().unwrap()).unwrap();
    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();
    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::Underlay,
    )])?;

    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr)?;

    // Subscribe receiver with EXCLUDE() (empty) - allows all
    // This is the default filter, so equivalent to subscribe_multicast()
    topol.nodes[1].port.subscribe_multicast_filtered(
        mcast_group.into(),
        exclude_filter(std::iter::empty::<IpAddr>()),
    )?;

    // Start snoop on receiver
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let filter =
        format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");
    let mut snoop = SnoopGuard::start(&dev_name_b, &filter)?;

    // Send packet
    let payload = "should be allowed";
    topol.nodes[0].zone.send_udp_v4(
        topol.nodes[0].port.ip(),
        mcast_group,
        MCAST_TEST_PORT,
        payload,
    )?;

    // Should receive - EXCLUDE() allows all
    let output = snoop.assert_packet("with EXCLUDE() (any source) filter");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("224.0.1.1"),
        "expected multicast destination in output: {stdout}"
    );

    Ok(())
}

#[test]
fn test_exclude_filter_blocks_listed_source() -> Result<()> {
    // EXCLUDE(sender_ip) should block packets from sender.
    let topol = xde_tests::two_node_topology()?;
    let mcast_group = Ipv4Addr::from([224, 0, 1, 2]);
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    let mcast_underlay =
        MulticastUnderlay::new("ff04::e000:102".parse().unwrap()).unwrap();
    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();
    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::Underlay,
    )])?;

    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr)?;

    // Sender's IP
    let sender_ip: IpAddr = topol.nodes[0].port.ip().into();

    // Subscribe receiver with EXCLUDE(sender_ip) - should block sender
    topol.nodes[1].port.subscribe_multicast_filtered(
        mcast_group.into(),
        exclude_filter([sender_ip]),
    )?;

    // Start snoop on receiver
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let filter =
        format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");
    let mut snoop = SnoopGuard::start(&dev_name_b, &filter)?;

    // Send from excluded source
    let payload = "excluded source test";
    topol.nodes[0].zone.send_udp_v4(
        topol.nodes[0].port.ip(),
        mcast_group,
        MCAST_TEST_PORT,
        payload,
    )?;

    // Should not receive - sender is in exclude list
    snoop.assert_no_packet("from excluded source");

    Ok(())
}

#[test]
fn test_filter_update_via_resubscribe() -> Result<()> {
    // Re-subscribing with a different filter should update the filter
    // and take effect immediately.
    let topol = xde_tests::two_node_topology()?;
    let mcast_group = Ipv4Addr::from([224, 0, 1, 3]);
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    let mcast_underlay =
        MulticastUnderlay::new("ff04::e000:103".parse().unwrap()).unwrap();
    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();
    mcast.set_forwarding(vec![(
        NextHopV6::new(fake_switch_addr, vni),
        Replication::Underlay,
    )])?;

    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr)?;

    let sender_ip: IpAddr = topol.nodes[0].port.ip().into();
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let filter =
        format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");

    // First: subscribe with INCLUDE(sender_ip) - should allow
    topol.nodes[1].port.subscribe_multicast_filtered(
        mcast_group.into(),
        include_filter([sender_ip]),
    )?;

    let mut snoop1 = SnoopGuard::start(&dev_name_b, &filter)?;
    topol.nodes[0].zone.send_udp_v4(
        topol.nodes[0].port.ip(),
        mcast_group,
        MCAST_TEST_PORT,
        "first test",
    )?;
    snoop1.assert_packet("initially with INCLUDE(sender}");

    // Second: re-subscribe with EXCLUDE(sender_ip) - should block
    topol.nodes[1].port.subscribe_multicast_filtered(
        mcast_group.into(),
        exclude_filter([sender_ip]),
    )?;

    let mut snoop2 = SnoopGuard::start(&dev_name_b, &filter)?;
    topol.nodes[0].zone.send_udp_v4(
        topol.nodes[0].port.ip(),
        mcast_group,
        MCAST_TEST_PORT,
        "second test",
    )?;
    snoop2.assert_no_packet("after filter update to EXCLUDE(sender}");

    // Third: re-subscribe with EXCLUDE() (empty) - should allow again
    topol.nodes[1].port.subscribe_multicast_filtered(
        mcast_group.into(),
        exclude_filter(std::iter::empty::<IpAddr>()),
    )?;

    let mut snoop3 = SnoopGuard::start(&dev_name_b, &filter)?;
    topol.nodes[0].zone.send_udp_v4(
        topol.nodes[0].port.ip(),
        mcast_group,
        MCAST_TEST_PORT,
        "third test",
    )?;
    snoop3.assert_packet("after filter update to EXCLUDE() (any)");

    Ok(())
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Source filtering tests for multicast subscriptions.
//!
//! These validate source filtering with semantics based on IGMPv3/MLDv2:
//! - INCLUDE(sources) only accepts packets from listed sources.
//! - INCLUDE() (empty) blocks all sources.
//! - EXCLUDE(sources) blocks listed sources but accepts others.
//! - EXCLUDE() (empty) accepts all sources (*, G) -> default ASM behavior.
//! - Filter changes via resubscribe take effect immediately.
//!
//! See RFC 3376 (IGMPv3) and RFC 3810 (MLDv2) for the original protocol
//! definitions that inspired this design.

use anyhow::Result;
use oxide_vpc::api::DEFAULT_MULTICAST_VNI;
use oxide_vpc::api::FilterMode;
use oxide_vpc::api::IpAddr;
use oxide_vpc::api::IpCidr;
use oxide_vpc::api::Ipv4Addr;
use oxide_vpc::api::Ipv6Addr;
use oxide_vpc::api::McastForwardingNextHop;
use oxide_vpc::api::MulticastUnderlay;
use oxide_vpc::api::NextHopV6;
use oxide_vpc::api::Replication;
use oxide_vpc::api::SourceFilter;
use oxide_vpc::api::Vni;
use xde_tests::GENEVE_UNDERLAY_FILTER;
use xde_tests::IPV4_MULTICAST_CIDR;
use xde_tests::IPV6_ADMIN_LOCAL_MULTICAST_CIDR;
use xde_tests::MCAST_TEST_PORT;
use xde_tests::MulticastGroup;
use xde_tests::SnoopGuard;
use xde_tests::UNDERLAY_TEST_DEVICE;

/// Create an INCLUDE filter with specified sources.
fn include_filter(sources: impl IntoIterator<Item = IpAddr>) -> SourceFilter {
    SourceFilter {
        mode: FilterMode::Include,
        sources: sources.into_iter().collect(),
    }
}

/// Create an EXCLUDE filter with specified sources.
fn exclude_filter(sources: impl IntoIterator<Item = IpAddr>) -> SourceFilter {
    SourceFilter {
        mode: FilterMode::Exclude,
        sources: sources.into_iter().collect(),
    }
}

#[test]
fn test_include_filter_allows_listed_source() -> Result<()> {
    // When subscribed with INCLUDE(sender_ip, other_ip), packets from sender
    // should be delivered.

    let topol = xde_tests::two_node_topology_dualstack()?;
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();
    let dev_name_b = topol.nodes[1].port.name().to_string();

    // Add router entries for both families
    let mcast_cidr_v4 = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    let mcast_cidr_v6 =
        IpCidr::Ip6(IPV6_ADMIN_LOCAL_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr_v4)?;
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr_v6)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr_v4)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr_v6)?;

    // IPv4
    {
        let mcast_group = Ipv4Addr::from([224, 0, 0, 252]);
        let mcast_underlay =
            MulticastUnderlay::new("ff04::e000:fc".parse().unwrap()).unwrap();
        let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;
        mcast.set_forwarding(vec![McastForwardingNextHop {
            next_hop: NextHopV6::new(fake_switch_addr, vni),
            replication: Replication::Underlay,
            source_filter: SourceFilter::default(),
        }])?;

        let sender_ip: IpAddr = topol.nodes[0].port.ip().into();
        let other_allowed: IpAddr = Ipv4Addr::from([10, 88, 88, 88]).into();

        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            include_filter([sender_ip, other_allowed]),
        )?;

        let filter =
            format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");
        let mut snoop = SnoopGuard::start(&dev_name_b, &filter)?;

        topol.nodes[0].zone.send_udp_v4(
            topol.nodes[0].port.ip(),
            mcast_group,
            MCAST_TEST_PORT,
            "allowed source test",
        )?;

        let output = snoop.assert_packet("IPv4: from allowed source");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("224.0.0.252"),
            "expected multicast dest: {stdout}"
        );
    }

    // IPv6
    {
        let mcast_group: Ipv6Addr = "ff04::e000:200".parse().unwrap();
        let mcast_underlay =
            MulticastUnderlay::new("ff04::e000:200".parse().unwrap()).unwrap();
        let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;
        mcast.set_forwarding(vec![McastForwardingNextHop {
            next_hop: NextHopV6::new(fake_switch_addr, vni),
            replication: Replication::Underlay,
            source_filter: SourceFilter::default(),
        }])?;

        let sender_ip: IpAddr = topol.nodes[0]
            .port
            .ipv6()
            .expect("dualstack port must have IPv6")
            .into();

        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            include_filter([sender_ip]),
        )?;

        let filter =
            format!("udp and ip6 dst {mcast_group} and port {MCAST_TEST_PORT}");
        let mut snoop = SnoopGuard::start(&dev_name_b, &filter)?;

        topol.nodes[0].zone.send_udp_v6(
            topol.nodes[0].port.ipv6().unwrap(),
            mcast_group,
            MCAST_TEST_PORT,
            "allowed v6 source",
        )?;

        let output = snoop.assert_packet("IPv6: from allowed source");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("ff04::e000:200"),
            "expected multicast dest: {stdout}"
        );
    }

    Ok(())
}

#[test]
fn test_include_filter_blocks_unlisted_source() -> Result<()> {
    // When subscribed with INCLUDE(other_ip), packets from sender should
    // be blocked because sender is not in the include list.

    let topol = xde_tests::two_node_topology_dualstack()?;
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();
    let dev_name_b = topol.nodes[1].port.name().to_string();

    let mcast_cidr_v4 = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    let mcast_cidr_v6 =
        IpCidr::Ip6(IPV6_ADMIN_LOCAL_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr_v4)?;
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr_v6)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr_v4)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr_v6)?;

    // IPv4
    {
        let mcast_group = Ipv4Addr::from([224, 0, 0, 253]);
        let mcast_underlay =
            MulticastUnderlay::new("ff04::e000:fd".parse().unwrap()).unwrap();
        let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;
        mcast.set_forwarding(vec![McastForwardingNextHop {
            next_hop: NextHopV6::new(fake_switch_addr, vni),
            replication: Replication::Underlay,
            source_filter: SourceFilter::default(),
        }])?;

        let other_ip: IpAddr = Ipv4Addr::from([10, 99, 99, 99]).into();
        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            include_filter([other_ip]),
        )?;

        let filter =
            format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");
        let mut snoop = SnoopGuard::start(&dev_name_b, &filter)?;

        topol.nodes[0].zone.send_udp_v4(
            topol.nodes[0].port.ip(),
            mcast_group,
            MCAST_TEST_PORT,
            "blocked source test",
        )?;

        snoop
            .assert_no_packet("IPv4: from unlisted source with INCLUDE filter");
    }

    // IPv6
    {
        let mcast_group: Ipv6Addr = "ff04::e000:201".parse().unwrap();
        let mcast_underlay =
            MulticastUnderlay::new("ff04::e000:201".parse().unwrap()).unwrap();
        let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;
        mcast.set_forwarding(vec![McastForwardingNextHop {
            next_hop: NextHopV6::new(fake_switch_addr, vni),
            replication: Replication::Underlay,
            source_filter: SourceFilter::default(),
        }])?;

        let other_ip: IpAddr =
            "fd00:9999::1".parse::<Ipv6Addr>().unwrap().into();
        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            include_filter([other_ip]),
        )?;

        let filter =
            format!("udp and ip6 dst {mcast_group} and port {MCAST_TEST_PORT}");
        let mut snoop = SnoopGuard::start(&dev_name_b, &filter)?;

        topol.nodes[0].zone.send_udp_v6(
            topol.nodes[0].port.ipv6().unwrap(),
            mcast_group,
            MCAST_TEST_PORT,
            "blocked v6 source",
        )?;

        snoop
            .assert_no_packet("IPv6: from unlisted source with INCLUDE filter");
    }

    Ok(())
}

#[test]
fn test_include_empty_blocks_all() -> Result<()> {
    // INCLUDE() means accept nothing, so all packets should be blocked.

    let topol = xde_tests::two_node_topology_dualstack()?;
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();
    let dev_name_b = topol.nodes[1].port.name().to_string();

    let mcast_cidr_v4 = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    let mcast_cidr_v6 =
        IpCidr::Ip6(IPV6_ADMIN_LOCAL_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr_v4)?;
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr_v6)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr_v4)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr_v6)?;

    // IPv4
    {
        let mcast_group = Ipv4Addr::from([224, 0, 0, 254]);
        let mcast_underlay =
            MulticastUnderlay::new("ff04::e000:fe".parse().unwrap()).unwrap();
        let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;
        mcast.set_forwarding(vec![McastForwardingNextHop {
            next_hop: NextHopV6::new(fake_switch_addr, vni),
            replication: Replication::Underlay,
            source_filter: SourceFilter::default(),
        }])?;

        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            include_filter(std::iter::empty::<IpAddr>()),
        )?;

        let filter =
            format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");
        let mut snoop = SnoopGuard::start(&dev_name_b, &filter)?;

        topol.nodes[0].zone.send_udp_v4(
            topol.nodes[0].port.ip(),
            mcast_group,
            MCAST_TEST_PORT,
            "should be blocked",
        )?;

        snoop.assert_no_packet("IPv4: with INCLUDE() (empty) filter");
    }

    // IPv6
    {
        let mcast_group: Ipv6Addr = "ff04::e000:203".parse().unwrap();
        let mcast_underlay =
            MulticastUnderlay::new("ff04::e000:203".parse().unwrap()).unwrap();
        let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;
        mcast.set_forwarding(vec![McastForwardingNextHop {
            next_hop: NextHopV6::new(fake_switch_addr, vni),
            replication: Replication::Underlay,
            source_filter: SourceFilter::default(),
        }])?;

        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            include_filter(std::iter::empty::<IpAddr>()),
        )?;

        let filter =
            format!("udp and ip6 dst {mcast_group} and port {MCAST_TEST_PORT}");
        let mut snoop = SnoopGuard::start(&dev_name_b, &filter)?;

        topol.nodes[0].zone.send_udp_v6(
            topol.nodes[0].port.ipv6().unwrap(),
            mcast_group,
            MCAST_TEST_PORT,
            "should be blocked v6",
        )?;

        snoop.assert_no_packet("IPv6: with INCLUDE() (empty) filter");
    }

    Ok(())
}

#[test]
fn test_exclude_empty_allows_all() -> Result<()> {
    // EXCLUDE() means accept any source, which is the default ASM behavior.

    let topol = xde_tests::two_node_topology_dualstack()?;
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();
    let dev_name_b = topol.nodes[1].port.name().to_string();

    let mcast_cidr_v4 = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    let mcast_cidr_v6 =
        IpCidr::Ip6(IPV6_ADMIN_LOCAL_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr_v4)?;
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr_v6)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr_v4)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr_v6)?;

    // IPv4
    {
        let mcast_group = Ipv4Addr::from([224, 0, 1, 1]);
        let mcast_underlay =
            MulticastUnderlay::new("ff04::e000:101".parse().unwrap()).unwrap();
        let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;
        mcast.set_forwarding(vec![McastForwardingNextHop {
            next_hop: NextHopV6::new(fake_switch_addr, vni),
            replication: Replication::Underlay,
            source_filter: SourceFilter::default(),
        }])?;

        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            exclude_filter(std::iter::empty::<IpAddr>()),
        )?;

        let filter =
            format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");
        let mut snoop = SnoopGuard::start(&dev_name_b, &filter)?;

        topol.nodes[0].zone.send_udp_v4(
            topol.nodes[0].port.ip(),
            mcast_group,
            MCAST_TEST_PORT,
            "should be allowed",
        )?;

        let output =
            snoop.assert_packet("IPv4: with EXCLUDE() (any source) filter");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("224.0.1.1"),
            "expected multicast dest: {stdout}"
        );
    }

    // IPv6
    {
        let mcast_group: Ipv6Addr = "ff04::e000:204".parse().unwrap();
        let mcast_underlay =
            MulticastUnderlay::new("ff04::e000:204".parse().unwrap()).unwrap();
        let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;
        mcast.set_forwarding(vec![McastForwardingNextHop {
            next_hop: NextHopV6::new(fake_switch_addr, vni),
            replication: Replication::Underlay,
            source_filter: SourceFilter::default(),
        }])?;

        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            exclude_filter(std::iter::empty::<IpAddr>()),
        )?;

        let filter =
            format!("udp and ip6 dst {mcast_group} and port {MCAST_TEST_PORT}");
        let mut snoop = SnoopGuard::start(&dev_name_b, &filter)?;

        topol.nodes[0].zone.send_udp_v6(
            topol.nodes[0].port.ipv6().unwrap(),
            mcast_group,
            MCAST_TEST_PORT,
            "should be allowed v6",
        )?;

        let output =
            snoop.assert_packet("IPv6: with EXCLUDE() (any source) filter");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("ff04::e000:204"),
            "expected multicast dest: {stdout}"
        );
    }

    Ok(())
}

#[test]
fn test_exclude_filter_blocks_listed_source() -> Result<()> {
    // EXCLUDE(sender_ip, other_ip) should block packets from sender.

    let topol = xde_tests::two_node_topology_dualstack()?;
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();
    let dev_name_b = topol.nodes[1].port.name().to_string();

    let mcast_cidr_v4 = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    let mcast_cidr_v6 =
        IpCidr::Ip6(IPV6_ADMIN_LOCAL_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr_v4)?;
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr_v6)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr_v4)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr_v6)?;

    // IPv4
    {
        let mcast_group = Ipv4Addr::from([224, 0, 1, 2]);
        let mcast_underlay =
            MulticastUnderlay::new("ff04::e000:102".parse().unwrap()).unwrap();
        let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;
        mcast.set_forwarding(vec![McastForwardingNextHop {
            next_hop: NextHopV6::new(fake_switch_addr, vni),
            replication: Replication::Underlay,
            source_filter: SourceFilter::default(),
        }])?;

        let sender_ip: IpAddr = topol.nodes[0].port.ip().into();
        let other_blocked: IpAddr = Ipv4Addr::from([10, 77, 77, 77]).into();

        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            exclude_filter([sender_ip, other_blocked]),
        )?;

        let filter =
            format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");
        let mut snoop = SnoopGuard::start(&dev_name_b, &filter)?;

        topol.nodes[0].zone.send_udp_v4(
            topol.nodes[0].port.ip(),
            mcast_group,
            MCAST_TEST_PORT,
            "excluded source test",
        )?;

        snoop.assert_no_packet("IPv4: from excluded source");
    }

    // IPv6
    {
        let mcast_group: Ipv6Addr = "ff04::e000:202".parse().unwrap();
        let mcast_underlay =
            MulticastUnderlay::new("ff04::e000:202".parse().unwrap()).unwrap();
        let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;
        mcast.set_forwarding(vec![McastForwardingNextHop {
            next_hop: NextHopV6::new(fake_switch_addr, vni),
            replication: Replication::Underlay,
            source_filter: SourceFilter::default(),
        }])?;

        let sender_ip: IpAddr = topol.nodes[0]
            .port
            .ipv6()
            .expect("dualstack port must have IPv6")
            .into();

        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            exclude_filter([sender_ip]),
        )?;

        let filter =
            format!("udp and ip6 dst {mcast_group} and port {MCAST_TEST_PORT}");
        let mut snoop = SnoopGuard::start(&dev_name_b, &filter)?;

        topol.nodes[0].zone.send_udp_v6(
            topol.nodes[0].port.ipv6().unwrap(),
            mcast_group,
            MCAST_TEST_PORT,
            "excluded v6 source",
        )?;

        snoop.assert_no_packet("IPv6: from excluded source");
    }

    Ok(())
}

#[test]
fn test_exclude_filter_allows_unlisted_source() -> Result<()> {
    // EXCLUDE(other_ip) should allow packets from sender (not in exclude list).

    let topol = xde_tests::two_node_topology_dualstack()?;
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();
    let dev_name_b = topol.nodes[1].port.name().to_string();

    let mcast_cidr_v4 = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    let mcast_cidr_v6 =
        IpCidr::Ip6(IPV6_ADMIN_LOCAL_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr_v4)?;
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr_v6)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr_v4)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr_v6)?;

    // IPv4
    {
        let mcast_group = Ipv4Addr::from([224, 0, 1, 4]);
        let mcast_underlay =
            MulticastUnderlay::new("ff04::e000:104".parse().unwrap()).unwrap();
        let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;
        mcast.set_forwarding(vec![McastForwardingNextHop {
            next_hop: NextHopV6::new(fake_switch_addr, vni),
            replication: Replication::Underlay,
            source_filter: SourceFilter::default(),
        }])?;

        let other_ip: IpAddr = Ipv4Addr::from([10, 99, 99, 99]).into();
        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            exclude_filter([other_ip]),
        )?;

        let filter =
            format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");
        let mut snoop = SnoopGuard::start(&dev_name_b, &filter)?;

        topol.nodes[0].zone.send_udp_v4(
            topol.nodes[0].port.ip(),
            mcast_group,
            MCAST_TEST_PORT,
            "allowed by exclude filter",
        )?;

        let output = snoop
            .assert_packet("IPv4: from unlisted source with EXCLUDE filter");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("224.0.1.4"),
            "expected multicast dest: {stdout}"
        );
    }

    // IPv6
    {
        let mcast_group: Ipv6Addr = "ff04::e000:207".parse().unwrap();
        let mcast_underlay =
            MulticastUnderlay::new("ff04::e000:207".parse().unwrap()).unwrap();
        let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;
        mcast.set_forwarding(vec![McastForwardingNextHop {
            next_hop: NextHopV6::new(fake_switch_addr, vni),
            replication: Replication::Underlay,
            source_filter: SourceFilter::default(),
        }])?;

        let other_ip: IpAddr =
            "fd00:9999::1".parse::<Ipv6Addr>().unwrap().into();
        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            exclude_filter([other_ip]),
        )?;

        let filter =
            format!("udp and ip6 dst {mcast_group} and port {MCAST_TEST_PORT}");
        let mut snoop = SnoopGuard::start(&dev_name_b, &filter)?;

        topol.nodes[0].zone.send_udp_v6(
            topol.nodes[0].port.ipv6().unwrap(),
            mcast_group,
            MCAST_TEST_PORT,
            "allowed by exclude filter v6",
        )?;

        let output = snoop
            .assert_packet("IPv6: from unlisted source with EXCLUDE filter");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("ff04::e000:207"),
            "expected multicast dest: {stdout}"
        );
    }

    Ok(())
}

#[test]
fn test_filter_update_via_resubscribe() -> Result<()> {
    // Resubscribing with a different filter should update the filter
    // and take effect immediately.

    let topol = xde_tests::two_node_topology_dualstack()?;
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();
    let dev_name_b = topol.nodes[1].port.name().to_string();

    let mcast_cidr_v4 = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    let mcast_cidr_v6 =
        IpCidr::Ip6(IPV6_ADMIN_LOCAL_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr_v4)?;
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr_v6)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr_v4)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr_v6)?;

    // IPv4
    {
        let mcast_group = Ipv4Addr::from([224, 0, 1, 3]);
        let mcast_underlay =
            MulticastUnderlay::new("ff04::e000:103".parse().unwrap()).unwrap();
        let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;
        mcast.set_forwarding(vec![McastForwardingNextHop {
            next_hop: NextHopV6::new(fake_switch_addr, vni),
            replication: Replication::Underlay,
            source_filter: SourceFilter::default(),
        }])?;

        let sender_ip: IpAddr = topol.nodes[0].port.ip().into();
        let filter =
            format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");

        // Case: INCLUDE(sender) allows delivery
        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            include_filter([sender_ip]),
        )?;

        let mut snoop1 = SnoopGuard::start(&dev_name_b, &filter)?;
        topol.nodes[0].zone.send_udp_v4(
            topol.nodes[0].port.ip(),
            mcast_group,
            MCAST_TEST_PORT,
            "case 1",
        )?;
        snoop1.assert_packet("IPv4: INCLUDE(sender) allows");

        // Case: resubscribe with EXCLUDE(sender) blocks delivery
        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            exclude_filter([sender_ip]),
        )?;

        let mut snoop2 = SnoopGuard::start(&dev_name_b, &filter)?;
        topol.nodes[0].zone.send_udp_v4(
            topol.nodes[0].port.ip(),
            mcast_group,
            MCAST_TEST_PORT,
            "case 2",
        )?;
        snoop2.assert_no_packet("IPv4: EXCLUDE(sender) blocks");

        // Case: resubscribe with EXCLUDE() allows delivery again
        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            exclude_filter(std::iter::empty::<IpAddr>()),
        )?;

        let mut snoop3 = SnoopGuard::start(&dev_name_b, &filter)?;
        topol.nodes[0].zone.send_udp_v4(
            topol.nodes[0].port.ip(),
            mcast_group,
            MCAST_TEST_PORT,
            "case 3",
        )?;
        snoop3.assert_packet("IPv4: EXCLUDE() allows");
    }

    // IPv6
    {
        let mcast_group: Ipv6Addr = "ff04::e000:205".parse().unwrap();
        let mcast_underlay =
            MulticastUnderlay::new("ff04::e000:205".parse().unwrap()).unwrap();
        let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;
        mcast.set_forwarding(vec![McastForwardingNextHop {
            next_hop: NextHopV6::new(fake_switch_addr, vni),
            replication: Replication::Underlay,
            source_filter: SourceFilter::default(),
        }])?;

        let sender_ip: IpAddr = topol.nodes[0]
            .port
            .ipv6()
            .expect("dualstack port must have IPv6")
            .into();
        let filter =
            format!("udp and ip6 dst {mcast_group} and port {MCAST_TEST_PORT}");

        // Case: INCLUDE(sender) allows delivery
        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            include_filter([sender_ip]),
        )?;

        let mut snoop1 = SnoopGuard::start(&dev_name_b, &filter)?;
        topol.nodes[0].zone.send_udp_v6(
            topol.nodes[0].port.ipv6().unwrap(),
            mcast_group,
            MCAST_TEST_PORT,
            "case 1 v6",
        )?;
        snoop1.assert_packet("IPv6: INCLUDE(sender) allows");

        // Case: resubscribe with EXCLUDE(sender) blocks delivery
        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            exclude_filter([sender_ip]),
        )?;

        let mut snoop2 = SnoopGuard::start(&dev_name_b, &filter)?;
        topol.nodes[0].zone.send_udp_v6(
            topol.nodes[0].port.ipv6().unwrap(),
            mcast_group,
            MCAST_TEST_PORT,
            "case 2 v6",
        )?;
        snoop2.assert_no_packet("IPv6: EXCLUDE(sender) blocks");

        // Case: resubscribe with EXCLUDE() allows delivery again
        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            exclude_filter(std::iter::empty::<IpAddr>()),
        )?;

        let mut snoop3 = SnoopGuard::start(&dev_name_b, &filter)?;
        topol.nodes[0].zone.send_udp_v6(
            topol.nodes[0].port.ipv6().unwrap(),
            mcast_group,
            MCAST_TEST_PORT,
            "case 3 v6",
        )?;
        snoop3.assert_packet("IPv6: EXCLUDE() allows");
    }

    Ok(())
}

#[test]
fn test_tx_same_sled_source_filtering() -> Result<()> {
    // This tests source filtering on Tx same-sled delivery path.
    //
    // This exercises the mcast_tx_source_filtered code path by verifying
    // per-member filtering where one subscriber receives and another is blocked.
    //
    // Setup: Three nodes (A sender, B and C receivers) on the same sled.
    // - Node B subscribes with INCLUDE(sender_ip) -> should be received
    // - Node C subscribes with INCLUDE(other_ip) -> should be blocked
    // - No forwarding configured, so only Tx same-sled delivery is tested

    let topol = xde_tests::three_node_topology_dualstack()?;

    let mcast_cidr_v4 = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    let mcast_cidr_v6 =
        IpCidr::Ip6(IPV6_ADMIN_LOCAL_MULTICAST_CIDR.parse().unwrap());
    for node in &topol.nodes {
        node.port.add_multicast_router_entry(mcast_cidr_v4)?;
        node.port.add_multicast_router_entry(mcast_cidr_v6)?;
    }

    let dev_name_b = topol.nodes[1].port.name().to_string();
    let dev_name_c = topol.nodes[2].port.name().to_string();

    // IPv4
    {
        let mcast_group = Ipv4Addr::from([224, 0, 1, 5]);
        let mcast_underlay =
            MulticastUnderlay::new("ff04::e000:105".parse().unwrap()).unwrap();
        let _mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

        let sender_ip: IpAddr = topol.nodes[0].port.ip().into();
        let other_ip: IpAddr = Ipv4Addr::from([10, 99, 99, 99]).into();

        topol.nodes[0].port.subscribe_multicast(mcast_group.into())?;
        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            include_filter([sender_ip]),
        )?;
        topol.nodes[2].port.subscribe_multicast_filtered(
            mcast_group.into(),
            include_filter([other_ip]),
        )?;

        let filter =
            format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");
        let mut snoop_b = SnoopGuard::start(&dev_name_b, &filter)?;
        let mut snoop_c = SnoopGuard::start(&dev_name_c, &filter)?;

        topol.nodes[0].zone.send_udp_v4(
            topol.nodes[0].port.ip(),
            mcast_group,
            MCAST_TEST_PORT,
            "tx same-sled filter test",
        )?;

        let output_b =
            snoop_b.assert_packet("IPv4: node B with INCLUDE(sender)");
        let stdout_b = String::from_utf8_lossy(&output_b.stdout);
        assert!(
            stdout_b.contains("224.0.1.5"),
            "expected multicast dest: {stdout_b}"
        );

        snoop_c
            .assert_no_packet("IPv4: node C with INCLUDE(other) blocks sender");
    }

    // IPv6
    {
        let mcast_group: Ipv6Addr = "ff04::e000:206".parse().unwrap();
        let mcast_underlay =
            MulticastUnderlay::new("ff04::e000:206".parse().unwrap()).unwrap();
        let _mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

        let sender_ip: IpAddr = topol.nodes[0]
            .port
            .ipv6()
            .expect("dualstack port must have IPv6")
            .into();
        let other_ip: IpAddr =
            "fd00:9999::1".parse::<Ipv6Addr>().unwrap().into();

        topol.nodes[0].port.subscribe_multicast(mcast_group.into())?;
        topol.nodes[1].port.subscribe_multicast_filtered(
            mcast_group.into(),
            include_filter([sender_ip]),
        )?;
        topol.nodes[2].port.subscribe_multicast_filtered(
            mcast_group.into(),
            include_filter([other_ip]),
        )?;

        let filter =
            format!("udp and ip6 dst {mcast_group} and port {MCAST_TEST_PORT}");
        let mut snoop_b = SnoopGuard::start(&dev_name_b, &filter)?;
        let mut snoop_c = SnoopGuard::start(&dev_name_c, &filter)?;

        topol.nodes[0].zone.send_udp_v6(
            topol.nodes[0].port.ipv6().unwrap(),
            mcast_group,
            MCAST_TEST_PORT,
            "tx same-sled v6 filter test",
        )?;

        let output_b =
            snoop_b.assert_packet("IPv6: node B with INCLUDE(sender)");
        let stdout_b = String::from_utf8_lossy(&output_b.stdout);
        assert!(
            stdout_b.contains("ff04::e000:206"),
            "expected multicast dest: {stdout_b}"
        );

        snoop_c
            .assert_no_packet("IPv6: node C with INCLUDE(other) blocks sender");
    }

    Ok(())
}

#[test]
fn test_forwarding_source_filter() -> Result<()> {
    // Test forwarding-level source filtering. Packets are blocked from being
    // forwarded to remote sleds when the aggregated source filter for that
    // next hop rejects the source.
    //
    // This exercises mcast_tx_fwd_source_filtered.

    let topol = xde_tests::two_node_topology_dualstack()?;
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    let mcast_group = Ipv4Addr::from([224, 1, 2, 240]);
    let mcast_underlay = MulticastUnderlay::new(Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 240,
    ]))
    .unwrap();

    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();
    let sender_ip: IpAddr = topol.nodes[0].port.ip().into();

    // Set up forwarding with INCLUDE filter that blocks the sender.
    // The aggregated filter for this next hop only accepts packets from
    // 10.99.99.99 (an address that doesn't exist), so packets from the
    // actual sender should be filtered.
    let other_ip: IpAddr = Ipv4Addr::from([10, 99, 99, 99]).into();
    mcast.set_forwarding(vec![McastForwardingNextHop {
        next_hop: NextHopV6::new(fake_switch_addr, vni),
        replication: Replication::Underlay,
        source_filter: include_filter([other_ip]),
    }])?;

    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr)?;

    // Subscribe sender to enable Tx processing
    topol.nodes[0]
        .port
        .subscribe_multicast(mcast_group.into())
        .expect("subscribe should succeed");

    // Snoop underlay for Geneve packets
    let mut snoop_underlay =
        SnoopGuard::start(UNDERLAY_TEST_DEVICE, GENEVE_UNDERLAY_FILTER)?;

    // Send multicast packet -> tihs should be filtered at forwarding level
    topol.nodes[0].zone.send_udp_v4(
        topol.nodes[0].port.ip(),
        mcast_group,
        MCAST_TEST_PORT,
        "filtered at forwarding",
    )?;

    // No packet should appear on underlay because forwarding filter blocked it
    snoop_underlay.assert_no_packet(
        "forwarding INCLUDE(other) should block sender from underlay",
    );

    // Now update forwarding to allow the sender
    mcast.set_forwarding(vec![McastForwardingNextHop {
        next_hop: NextHopV6::new(fake_switch_addr, vni),
        replication: Replication::Underlay,
        source_filter: include_filter([sender_ip]),
    }])?;

    let mut snoop_underlay2 =
        SnoopGuard::start(UNDERLAY_TEST_DEVICE, GENEVE_UNDERLAY_FILTER)?;

    topol.nodes[0].zone.send_udp_v4(
        topol.nodes[0].port.ip(),
        mcast_group,
        MCAST_TEST_PORT,
        "allowed at forwarding",
    )?;

    // Packet should now appear on underlay
    snoop_underlay2
        .assert_packet("forwarding INCLUDE(sender) should allow to underlay");

    // Test EXCLUDE mode: EXCLUDE(sender) should block
    mcast.set_forwarding(vec![McastForwardingNextHop {
        next_hop: NextHopV6::new(fake_switch_addr, vni),
        replication: Replication::Underlay,
        source_filter: exclude_filter([sender_ip]),
    }])?;

    let mut snoop_underlay3 =
        SnoopGuard::start(UNDERLAY_TEST_DEVICE, GENEVE_UNDERLAY_FILTER)?;

    topol.nodes[0].zone.send_udp_v4(
        topol.nodes[0].port.ip(),
        mcast_group,
        MCAST_TEST_PORT,
        "excluded at forwarding",
    )?;

    snoop_underlay3.assert_no_packet(
        "forwarding EXCLUDE(sender) should block sender from underlay",
    );

    // EXCLUDE() (empty) should allow any source
    mcast.set_forwarding(vec![McastForwardingNextHop {
        next_hop: NextHopV6::new(fake_switch_addr, vni),
        replication: Replication::Underlay,
        source_filter: SourceFilter::default(), // EXCLUDE() = any
    }])?;

    let mut snoop_underlay4 =
        SnoopGuard::start(UNDERLAY_TEST_DEVICE, GENEVE_UNDERLAY_FILTER)?;

    topol.nodes[0].zone.send_udp_v4(
        topol.nodes[0].port.ip(),
        mcast_group,
        MCAST_TEST_PORT,
        "default filter allows",
    )?;

    snoop_underlay4.assert_packet(
        "forwarding EXCLUDE() (default) should allow any source",
    );

    // IPv6
    {
        let mcast_group_v6: Ipv6Addr = "ff04::e000:2f0".parse().unwrap();
        let mcast_underlay_v6 =
            MulticastUnderlay::new("ff04::e000:2f0".parse().unwrap()).unwrap();
        let mcast_v6 =
            MulticastGroup::new(mcast_group_v6.into(), mcast_underlay_v6)?;

        let sender_ip_v6: IpAddr = topol.nodes[0]
            .port
            .ipv6()
            .expect("dualstack port must have IPv6")
            .into();

        // INCLUDE(other) should block
        let other_ip_v6: IpAddr = "fd00::99:99:99:99".parse().unwrap();
        mcast_v6.set_forwarding(vec![McastForwardingNextHop {
            next_hop: NextHopV6::new(fake_switch_addr, vni),
            replication: Replication::Underlay,
            source_filter: include_filter([other_ip_v6]),
        }])?;

        let mcast_cidr_v6 =
            IpCidr::Ip6(IPV6_ADMIN_LOCAL_MULTICAST_CIDR.parse().unwrap());
        topol.nodes[0].port.add_multicast_router_entry(mcast_cidr_v6)?;

        topol.nodes[0]
            .port
            .subscribe_multicast(mcast_group_v6.into())
            .expect("subscribe should succeed");

        let mut snoop_v6_1 =
            SnoopGuard::start(UNDERLAY_TEST_DEVICE, GENEVE_UNDERLAY_FILTER)?;

        topol.nodes[0].zone.send_udp_v6(
            topol.nodes[0].port.ipv6().unwrap(),
            mcast_group_v6,
            MCAST_TEST_PORT,
            "v6 filtered",
        )?;

        snoop_v6_1.assert_no_packet(
            "IPv6: forwarding INCLUDE(other) should block sender",
        );

        // INCLUDE(sender) should allow
        mcast_v6.set_forwarding(vec![McastForwardingNextHop {
            next_hop: NextHopV6::new(fake_switch_addr, vni),
            replication: Replication::Underlay,
            source_filter: include_filter([sender_ip_v6]),
        }])?;

        let mut snoop_v6_2 =
            SnoopGuard::start(UNDERLAY_TEST_DEVICE, GENEVE_UNDERLAY_FILTER)?;

        topol.nodes[0].zone.send_udp_v6(
            topol.nodes[0].port.ipv6().unwrap(),
            mcast_group_v6,
            MCAST_TEST_PORT,
            "v6 allowed",
        )?;

        snoop_v6_2
            .assert_packet("IPv6: forwarding INCLUDE(sender) should allow");
    }

    Ok(())
}

#[test]
fn test_forwarding_multi_nexthop_different_filters() -> Result<()> {
    // Test multi-next-hop forwarding with different source filters per hop.
    // Verifies that filtering is applied independently per next hop. When two
    // next hops have different filters, packets only forward to allowed hops.

    let topol = xde_tests::two_node_topology_dualstack()?;
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    // IPv4
    {
        let mcast_group = Ipv4Addr::from([224, 1, 2, 241]);
        let mcast_underlay = MulticastUnderlay::new(Ipv6Addr::from([
            0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 224, 1, 2, 241,
        ]))
        .unwrap();

        let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

        // Two synthetic next hop addresses
        let nexthop_allowed: Ipv6Addr = "fd77::1".parse().unwrap();
        let nexthop_blocked: Ipv6Addr = "fd77::2".parse().unwrap();

        let sender_ip: IpAddr = topol.nodes[0].port.ip().into();
        let other_ip: IpAddr = Ipv4Addr::from([10, 99, 99, 99]).into();

        // Set up two next hops with different filters:
        // - nexthop_allowed: INCLUDE(sender) -> should forward
        // - nexthop_blocked: INCLUDE(other) -> should NOT forward
        mcast.set_forwarding(vec![
            McastForwardingNextHop {
                next_hop: NextHopV6::new(nexthop_allowed, vni),
                replication: Replication::Underlay,
                source_filter: include_filter([sender_ip]),
            },
            McastForwardingNextHop {
                next_hop: NextHopV6::new(nexthop_blocked, vni),
                replication: Replication::External,
                source_filter: include_filter([other_ip]),
            },
        ])?;

        let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
        topol.nodes[0].port.add_multicast_router_entry(mcast_cidr)?;

        topol.nodes[0]
            .port
            .subscribe_multicast(mcast_group.into())
            .expect("subscribe should succeed");

        // Snoop underlay, where we should see exactly 1 packet
        // (to nexthop_allowed) and not 2 (which would happen if both next hops
        // received the packet)
        let mut snoop =
            SnoopGuard::start(UNDERLAY_TEST_DEVICE, GENEVE_UNDERLAY_FILTER)?;

        topol.nodes[0].zone.send_udp_v4(
            topol.nodes[0].port.ip(),
            mcast_group,
            MCAST_TEST_PORT,
            "multi-hop filter test",
        )?;

        // Packet should reach allowed hop, while the blocked hop is filtered out.
        snoop.assert_packet("IPv4: should forward to allowed next hop");
    }

    // IPv6
    {
        let mcast_group_v6: Ipv6Addr = "ff04::e000:2f1".parse().unwrap();
        let mcast_underlay_v6 =
            MulticastUnderlay::new("ff04::e000:2f1".parse().unwrap()).unwrap();
        let mcast_v6 =
            MulticastGroup::new(mcast_group_v6.into(), mcast_underlay_v6)?;

        let nexthop_allowed: Ipv6Addr = "fd77::3".parse().unwrap();
        let nexthop_blocked: Ipv6Addr = "fd77::4".parse().unwrap();

        let sender_ip_v6: IpAddr = topol.nodes[0]
            .port
            .ipv6()
            .expect("dualstack port must have IPv6")
            .into();
        let other_ip_v6: IpAddr = "fd00::99:99:99:99".parse().unwrap();

        mcast_v6.set_forwarding(vec![
            McastForwardingNextHop {
                next_hop: NextHopV6::new(nexthop_allowed, vni),
                replication: Replication::Underlay,
                source_filter: include_filter([sender_ip_v6]),
            },
            McastForwardingNextHop {
                next_hop: NextHopV6::new(nexthop_blocked, vni),
                replication: Replication::External,
                source_filter: include_filter([other_ip_v6]),
            },
        ])?;

        let mcast_cidr_v6 =
            IpCidr::Ip6(IPV6_ADMIN_LOCAL_MULTICAST_CIDR.parse().unwrap());
        topol.nodes[0].port.add_multicast_router_entry(mcast_cidr_v6)?;

        topol.nodes[0]
            .port
            .subscribe_multicast(mcast_group_v6.into())
            .expect("subscribe should succeed");

        let mut snoop_v6 =
            SnoopGuard::start(UNDERLAY_TEST_DEVICE, GENEVE_UNDERLAY_FILTER)?;

        topol.nodes[0].zone.send_udp_v6(
            topol.nodes[0].port.ipv6().unwrap(),
            mcast_group_v6,
            MCAST_TEST_PORT,
            "multi-hop filter test v6",
        )?;

        snoop_v6.assert_packet("IPv6: should forward to allowed next hop");
    }

    Ok(())
}

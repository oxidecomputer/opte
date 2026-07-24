// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! XDE multicast replication-target fanout and redundant-next-hop collapse
//! tests.
//!
//! Distinct replication targets represent distinct multicast delivery sets, so
//! XDE emits one packet per target carrying the correct Geneve flag. Redundant
//! next hops sharing a target are alternate switch paths to the same delivery
//! set, so they collapse to a single per-flow copy via ECMP select-one rather
//! than fanning out a duplicate.

use anyhow::Result;
use opte_ioctl::OpteHdl;
use opte_test_utils::geneve_verify;
use oxide_vpc::api::DEFAULT_MULTICAST_VNI;
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
use xde_tests::MCAST_TEST_PORT;
use xde_tests::MulticastGroup;
use xde_tests::SNOOP_TIMEOUT_EXPECT_NONE;
use xde_tests::SnoopGuard;
use xde_tests::UNDERLAY_TEST_DEVICE;

#[test]
fn test_multicast_multi_nexthop_fanout() -> Result<()> {
    let topol = xde_tests::two_node_topology()?;
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    // Disjoint {External, Underlay} programming always splits.
    assert_splits_into_two_copies(
        &topol,
        Ipv4Addr::from([224, 1, 2, 100]),
        MulticastUnderlay::new("ff04::e001:264".parse().unwrap()).unwrap(),
        vec![
            McastForwardingNextHop {
                next_hop: NextHopV6::new("fd77::1".parse().unwrap(), vni),
                replication: Replication::External,
                source_filter: SourceFilter::default(),
            },
            McastForwardingNextHop {
                next_hop: NextHopV6::new("fd77::2".parse().unwrap(), vni),
                replication: Replication::Underlay,
                source_filter: SourceFilter::default(),
            },
        ],
    )?;

    // A `Both` replication hop coalesces only when its source filter admits the
    // sender. This one `Include`s a different source, so selection falls back
    // to the admitting External and Underlay hops.
    let other_ip: IpAddr = topol.nodes[1].port.ip().into();
    assert_splits_into_two_copies(
        &topol,
        Ipv4Addr::from([224, 1, 2, 109]),
        MulticastUnderlay::new("ff04::e001:273".parse().unwrap()).unwrap(),
        vec![
            McastForwardingNextHop {
                next_hop: NextHopV6::new("fd77::9".parse().unwrap(), vni),
                replication: Replication::Both,
                source_filter: SourceFilter::Include(
                    [other_ip].into_iter().collect(),
                ),
            },
            McastForwardingNextHop {
                next_hop: NextHopV6::new("fd77::a".parse().unwrap(), vni),
                replication: Replication::External,
                source_filter: SourceFilter::default(),
            },
            McastForwardingNextHop {
                next_hop: NextHopV6::new("fd77::b".parse().unwrap(), vni),
                replication: Replication::Underlay,
                source_filter: SourceFilter::default(),
            },
        ],
    )?;

    Ok(())
}

#[test]
fn test_multicast_dual_external_select_one() -> Result<()> {
    // Two External next hops are redundant switch paths to the same external
    // multicast network, so the flow must yield a single egress copy. Exercised
    // for both any-source (ASM) and source-specific (SSM) entries, since
    // selection is filter-aware.

    let topol = xde_tests::two_node_topology()?;
    let sender_ip: IpAddr = topol.nodes[0].port.ip().into();

    // ASM: both hops accept any source via the default `Exclude(empty)` filter.
    assert_dual_select_one(
        &topol,
        Ipv4Addr::from([224, 1, 2, 101]),
        MulticastUnderlay::new("ff04::e001:265".parse().unwrap()).unwrap(),
        SourceFilter::default(),
        [Replication::External, Replication::External],
        Replication::External,
        ["fd77::1", "fd77::2"],
    )?;

    // SSM: both hops `Include` the sender, so both admit this flow's source and
    // remain ECMP candidates.
    assert_dual_select_one(
        &topol,
        Ipv4Addr::from([224, 1, 2, 102]),
        MulticastUnderlay::new("ff04::e001:266".parse().unwrap()).unwrap(),
        SourceFilter::Include([sender_ip].into_iter().collect()),
        [Replication::External, Replication::External],
        Replication::External,
        ["fd77::1", "fd77::2"],
    )?;

    Ok(())
}

#[test]
fn test_multicast_dual_underlay_select_one() -> Result<()> {
    // Two Underlay next hops are redundant switch paths to the same sled
    // subscribers, so the flow must leave this sled as a single underlay copy
    // rather than a duplicate the Rx path could not dedup. Exercised for both
    // ASM and SSM entries.

    let topol = xde_tests::two_node_topology()?;
    let sender_ip: IpAddr = topol.nodes[0].port.ip().into();

    assert_dual_select_one(
        &topol,
        Ipv4Addr::from([224, 1, 2, 105]),
        MulticastUnderlay::new("ff04::e001:269".parse().unwrap()).unwrap(),
        SourceFilter::default(),
        [Replication::Underlay, Replication::Underlay],
        Replication::Underlay,
        ["fd77::5", "fd77::6"],
    )?;

    assert_dual_select_one(
        &topol,
        Ipv4Addr::from([224, 1, 2, 106]),
        MulticastUnderlay::new("ff04::e001:270".parse().unwrap()).unwrap(),
        SourceFilter::Include([sender_ip].into_iter().collect()),
        [Replication::Underlay, Replication::Underlay],
        Replication::Underlay,
        ["fd77::5", "fd77::6"],
    )?;

    Ok(())
}

#[test]
fn test_multicast_dual_both_select_one() -> Result<()> {
    // Two Both next hops are redundant switch paths to the same external network
    // and the same sled subscribers. Since both targets see the same candidate
    // set, the egress and underlay selections land on the same switch. The flow
    // leaves as a single copy carrying the Both flag while the peer is fully
    // suppressed. Exercised for both ASM and SSM entries.

    let topol = xde_tests::two_node_topology()?;
    let sender_ip: IpAddr = topol.nodes[0].port.ip().into();

    assert_dual_select_one(
        &topol,
        Ipv4Addr::from([224, 1, 2, 103]),
        MulticastUnderlay::new("ff04::e001:267".parse().unwrap()).unwrap(),
        SourceFilter::default(),
        [Replication::Both, Replication::Both],
        Replication::Both,
        ["fd77::3", "fd77::4"],
    )?;

    assert_dual_select_one(
        &topol,
        Ipv4Addr::from([224, 1, 2, 104]),
        MulticastUnderlay::new("ff04::e001:268".parse().unwrap()).unwrap(),
        SourceFilter::Include([sender_ip].into_iter().collect()),
        [Replication::Both, Replication::Both],
        Replication::Both,
        ["fd77::3", "fd77::4"],
    )?;

    Ok(())
}

#[test]
fn test_multicast_mixed_underlay_both_coalesce() -> Result<()> {
    // A heterogeneous hop set (one Underlay hop, one Both hop) must not split
    // the flow across switches: the Both hop covers both replication targets,
    // so selection coalesces onto it and a single copy leaves carrying the
    // Both flag rather than one Underlay copy plus one External copy.
    // Exercised for both ASM and SSM entries.

    let topol = xde_tests::two_node_topology()?;
    let sender_ip: IpAddr = topol.nodes[0].port.ip().into();

    assert_dual_select_one(
        &topol,
        Ipv4Addr::from([224, 1, 2, 107]),
        MulticastUnderlay::new("ff04::e001:271".parse().unwrap()).unwrap(),
        SourceFilter::default(),
        [Replication::Underlay, Replication::Both],
        Replication::Both,
        ["fd77::7", "fd77::8"],
    )?;

    assert_dual_select_one(
        &topol,
        Ipv4Addr::from([224, 1, 2, 108]),
        MulticastUnderlay::new("ff04::e001:272".parse().unwrap()).unwrap(),
        SourceFilter::Include([sender_ip].into_iter().collect()),
        [Replication::Underlay, Replication::Both],
        Replication::Both,
        ["fd77::7", "fd77::8"],
    )?;

    Ok(())
}

/// Program the given next hops, send one packet, and assert the flow splits
/// into exactly two copies, one External and one Underlay.
///
/// A second send with a three-packet snoop must time out, proving the split
/// costs exactly one copy per target and nothing more.
fn assert_splits_into_two_copies(
    topol: &xde_tests::Topology,
    mcast_group: Ipv4Addr,
    mcast_underlay: MulticastUnderlay,
    next_hops: Vec<McastForwardingNextHop>,
) -> Result<()> {
    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;
    mcast.set_forwarding(next_hops.clone())?;

    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr)?;

    topol.nodes[0]
        .port
        .subscribe_multicast(mcast_group.into())
        .expect("subscribe port 0 should succeed");

    // Confirm every hop is programmed.
    let hdl = OpteHdl::open()?;
    let mfwd = hdl.dump_mcast_fwd()?;
    let entry = mfwd
        .entries
        .iter()
        .find(|e| e.underlay == mcast_underlay)
        .expect("missing multicast forwarding entry for underlay group");
    assert_eq!(
        entry.next_hops.len(),
        next_hops.len(),
        "expected {} next hops in forwarding table; got: {:?}",
        next_hops.len(),
        entry.next_hops
    );

    for hop in &next_hops {
        assert!(
            entry.next_hops.contains(hop),
            "expected {hop:?} in forwarding table; got: {:?}",
            entry.next_hops
        );
    }

    let sender_v4 = topol.nodes[0].port.ip();
    let payload = "split two copies";

    // 1st send: exactly one External copy and one Underlay copy.
    {
        let mut snoop = SnoopGuard::start_with_count(
            UNDERLAY_TEST_DEVICE,
            GENEVE_UNDERLAY_FILTER,
            2,
        )?;

        topol.nodes[0].zone.send_udp_v4(
            sender_v4,
            mcast_group,
            MCAST_TEST_PORT,
            payload,
        )?;

        let out = snoop.assert_packet("two split Geneve copies on underlay");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let packets = geneve_verify::extract_snoop_hex(&stdout)
            .expect("snoop output should contain hex dumps");
        assert_eq!(
            packets.len(),
            2,
            "expected 2 packets; got {}",
            packets.len()
        );

        let mut replications = Vec::new();
        for (i, hex) in packets.iter().enumerate() {
            let bytes =
                geneve_verify::parse_snoop_hex(hex).unwrap_or_else(|e| {
                    panic!("packet {i}: failed to parse hex: {e}")
                });
            let info = geneve_verify::parse_geneve_packet(&bytes)
                .unwrap_or_else(|e| panic!("packet {i}: not Geneve: {e}"));
            replications.push(info.replication);
        }

        assert!(
            replications.contains(&Some(Replication::External)),
            "expected an External copy; got: {replications:?}"
        );
        assert!(
            replications.contains(&Some(Replication::Underlay)),
            "expected an Underlay copy; got: {replications:?}"
        );
    }

    // 2nd send: a snoop waiting for three packets must time out, proving no
    // hop emitted a copy beyond the one per target.
    {
        let mut snoop = SnoopGuard::start_with_count(
            UNDERLAY_TEST_DEVICE,
            GENEVE_UNDERLAY_FILTER,
            3,
        )?;

        topol.nodes[0].zone.send_udp_v4(
            sender_v4,
            mcast_group,
            MCAST_TEST_PORT,
            payload,
        )?;

        if let Ok(out) = snoop.wait_with_timeout(SNOOP_TIMEOUT_EXPECT_NONE) {
            let stdout = String::from_utf8_lossy(&out.stdout);
            panic!(
                "expected two copies, but snoop captured a third:\n{stdout}"
            );
        }
    }

    Ok(())
}

/// Program two next hops sharing at least one replication target, send one
/// packet, and assert that exactly one copy leaves carrying the expected
/// replication flag.
///
/// Switches sharing a target reach the same multicast delivery set, so a flow
/// needs a single copy per target. For a homogeneous pair, the egress and
/// underlay selections index the same candidate set with the same flow hash
/// and pick the same hop. For a mixed pair containing a `Both` replication hop,
/// selection coalesces onto a `Both` hop rather than splitting the flow across
/// switches.
///
/// Either way, one copy leaves with the expected flag and the peer is
/// suppressed.
fn assert_dual_select_one(
    topol: &xde_tests::Topology,
    mcast_group: Ipv4Addr,
    mcast_underlay: MulticastUnderlay,
    source_filter: SourceFilter,
    replications: [Replication; 2],
    expected: Replication,
    nexthops: [&str; 2],
) -> Result<()> {
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;
    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    let nexthop1: Ipv6Addr = nexthops[0].parse().unwrap();
    let nexthop2: Ipv6Addr = nexthops[1].parse().unwrap();

    mcast.set_forwarding(vec![
        McastForwardingNextHop {
            next_hop: NextHopV6::new(nexthop1, vni),
            replication: replications[0],
            source_filter: source_filter.clone(),
        },
        McastForwardingNextHop {
            next_hop: NextHopV6::new(nexthop2, vni),
            replication: replications[1],
            source_filter,
        },
    ])?;

    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr)?;

    topol.nodes[0]
        .port
        .subscribe_multicast(mcast_group.into())
        .expect("subscribe port 0 should succeed");

    // Confirm both next hops are available for failover.
    let hdl = OpteHdl::open()?;
    let mfwd = hdl.dump_mcast_fwd()?;
    let entry = mfwd
        .entries
        .iter()
        .find(|e| e.underlay == mcast_underlay)
        .expect("missing multicast forwarding entry for underlay group");

    for (addr, replication) in
        [(nexthop1, replications[0]), (nexthop2, replications[1])]
    {
        assert!(
            entry.next_hops.iter().any(|hop| {
                hop.next_hop.addr == addr && hop.replication == replication
            }),
            "expected next hop {addr:?} programmed with {replication:?}; got: {:?}",
            entry.next_hops
        );
    }

    let sender_v4 = topol.nodes[0].port.ip();
    let payload = "dual select-one";

    // 1st send: exactly one copy carrying the configured replication flag.
    {
        let mut snoop =
            SnoopGuard::start(UNDERLAY_TEST_DEVICE, GENEVE_UNDERLAY_FILTER)?;

        topol.nodes[0].zone.send_udp_v4(
            sender_v4,
            mcast_group,
            MCAST_TEST_PORT,
            payload,
        )?;

        let out = snoop.assert_packet("single underlay copy");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let packets = geneve_verify::extract_snoop_hex(&stdout)
            .expect("snoop output should contain a hex dump");
        let bytes = geneve_verify::parse_snoop_hex(&packets[0])
            .expect("captured packet should parse as hex");
        let info = geneve_verify::parse_geneve_packet(&bytes)
            .expect("captured packet should parse as Geneve");
        assert_eq!(
            info.replication,
            Some(expected),
            "selected copy must carry {expected:?} replication"
        );
    }

    // 2nd send: a snoop waiting for two packets must time out, proving the
    // redundant switch path for the same target emitted no duplicate copy.
    {
        let mut snoop = SnoopGuard::start_with_count(
            UNDERLAY_TEST_DEVICE,
            GENEVE_UNDERLAY_FILTER,
            2,
        )?;

        topol.nodes[0].zone.send_udp_v4(
            sender_v4,
            mcast_group,
            MCAST_TEST_PORT,
            payload,
        )?;

        if let Ok(out) = snoop.wait_with_timeout(SNOOP_TIMEOUT_EXPECT_NONE) {
            let stdout = String::from_utf8_lossy(&out.stdout);
            panic!(
                "expected a single copy, but snoop captured a duplicate:\n{stdout}"
            );
        }
    }

    Ok(())
}

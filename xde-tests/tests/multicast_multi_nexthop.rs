// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

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
    // Test that multicast forwarding with multiple replication targets sends one
    // packet per target, each with the correct replication flag.
    //
    // This test configures two next hops with different replication modes:
    // - NextHop 1: External replication (to boundary switch)
    // - NextHop 2: Underlay replication (sled-to-sled)
    //
    // After sending one multicast packet, we verify that the External and
    // Underlay targets each produce a Geneve packet with the correct flag.

    let topol = xde_tests::two_node_topology()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 100]);
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    let mcast_underlay =
        MulticastUnderlay::new("ff04::e001:264".parse().unwrap()).unwrap();

    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    // Configure two next hops with different replication modes.
    // Use different addresses since NextHopV6 is the key in the forwarding table.
    // In production, these would be different switch addresses.
    // For single-sled testing, we use two synthetic addresses.
    let nexthop1: Ipv6Addr = "fd77::1".parse().unwrap();
    let nexthop2: Ipv6Addr = "fd77::2".parse().unwrap();

    mcast.set_forwarding(vec![
        McastForwardingNextHop {
            next_hop: NextHopV6::new(nexthop1, vni),
            replication: Replication::External,
            source_filter: SourceFilter::default(),
        },
        McastForwardingNextHop {
            next_hop: NextHopV6::new(nexthop2, vni),
            replication: Replication::Underlay,
            source_filter: SourceFilter::default(),
        },
    ])?;

    // Allow IPv4 multicast traffic (224.0.0.0/4) via Multicast target
    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr)?;

    // Subscribe sender to enable Tx processing (though sender is self-excluded)
    topol.nodes[0]
        .port
        .subscribe_multicast(mcast_group.into())
        .expect("subscribe port 0 should succeed");

    // Assert forwarding table contains both next hops with correct replication modes
    let hdl = OpteHdl::open()?;
    let mfwd = hdl.dump_mcast_fwd()?;
    let entry = mfwd
        .entries
        .iter()
        .find(|e| e.underlay == mcast_underlay)
        .expect("missing multicast forwarding entry for underlay group");

    assert_eq!(
        entry.next_hops.len(),
        2,
        "expected 2 next hops in forwarding table; got: {:?}",
        entry.next_hops
    );

    // Verify External replication next hop is present
    assert!(
        entry.next_hops.iter().any(|hop| {
            hop.replication == Replication::External
                && hop.next_hop.addr == nexthop1
                && hop.next_hop.vni == vni
        }),
        "expected External replication to {nexthop1:?} in forwarding table; got: {:?}",
        entry.next_hops
    );

    // Verify Underlay replication next hop is present
    assert!(
        entry.next_hops.iter().any(|hop| {
            hop.replication == Replication::Underlay
                && hop.next_hop.addr == nexthop2
                && hop.next_hop.vni == vni
        }),
        "expected Underlay replication to {nexthop2:?} in forwarding table; got: {:?}",
        entry.next_hops
    );

    // Start snoop on underlay to capture both Geneve packets
    // Use -c 2 to capture exactly two packets, then exit
    let mut snoop_underlay = SnoopGuard::start_with_count(
        UNDERLAY_TEST_DEVICE,
        GENEVE_UNDERLAY_FILTER,
        2,
    )?;

    // Send one multicast packet from zone A
    let payload = "fanout test";
    let sender_v4 = topol.nodes[0].port.ip();
    topol.nodes[0].zone.send_udp_v4(
        sender_v4,
        mcast_group,
        MCAST_TEST_PORT,
        payload,
    )?;

    // Wait for snoop to capture two packets
    let snoop_output =
        snoop_underlay.assert_packet("two Geneve packets on underlay");

    let stdout = String::from_utf8_lossy(&snoop_output.stdout);

    // Parse both packets and verify replication modes using geneve_verify helpers.
    // snoop with -c 2 captures two packets. extract_snoop_hex splits them
    // automatically by detecting offset 0 boundaries.
    let packets = geneve_verify::extract_snoop_hex(&stdout).unwrap_or_else(|e| {
        panic!("Expected snoop output to contain hex dump: {}\n\nSnoop output was:\n{}", e, stdout);
    });

    assert_eq!(
        packets.len(),
        2,
        "Expected to capture 2 packets, found {}",
        packets.len()
    );

    // Parse each packet and extract replication mode
    let mut replications = Vec::new();
    for (i, hex) in packets.iter().enumerate() {
        let bytes = geneve_verify::parse_snoop_hex(hex).unwrap_or_else(|e| {
            panic!("Packet {}: failed to parse hex: {}", i, e)
        });

        match geneve_verify::parse_geneve_packet(&bytes) {
            Ok(geneve_info) => {
                replications.push(geneve_info.replication);
            }
            Err(e) => {
                panic!("Packet {}: failed to parse as Geneve: {}", i, e);
            }
        }
    }

    assert_eq!(
        replications.len(),
        2,
        "Expected to parse 2 Geneve packets with replication info; got: {:?}",
        replications
    );

    // Verify we have one External and one Underlay packet
    assert!(
        replications.contains(&Some(Replication::External)),
        "Expected one packet with External replication; got: {:?}",
        replications
    );
    assert!(
        replications.contains(&Some(Replication::Underlay)),
        "Expected one packet with Underlay replication; got: {:?}",
        replications
    );

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
        Replication::Underlay,
        ["fd77::5", "fd77::6"],
    )?;

    assert_dual_select_one(
        &topol,
        Ipv4Addr::from([224, 1, 2, 106]),
        MulticastUnderlay::new("ff04::e001:270".parse().unwrap()).unwrap(),
        SourceFilter::Include([sender_ip].into_iter().collect()),
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
        Replication::Both,
        ["fd77::3", "fd77::4"],
    )?;

    assert_dual_select_one(
        &topol,
        Ipv4Addr::from([224, 1, 2, 104]),
        MulticastUnderlay::new("ff04::e001:268".parse().unwrap()).unwrap(),
        SourceFilter::Include([sender_ip].into_iter().collect()),
        Replication::Both,
        ["fd77::3", "fd77::4"],
    )?;

    Ok(())
}

/// Program two redundant next hops sharing a replication target, send one
/// packet, and assert that exactly one copy leaves carrying the requested
/// replication flag.
///
/// Switches sharing a target reach the same multicast delivery set, so a flow
/// needs a single copy per target. For a homogeneous pair, the egress and
/// underlay selections index the same candidate set with the same flow hash
/// and pick the same hop, so the result is one copy with the configured flag and
/// the peer is suppressed.
fn assert_dual_select_one(
    topol: &xde_tests::Topology,
    mcast_group: Ipv4Addr,
    mcast_underlay: MulticastUnderlay,
    source_filter: SourceFilter,
    replication: Replication,
    nexthops: [&str; 2],
) -> Result<()> {
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;
    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    let nexthop1: Ipv6Addr = nexthops[0].parse().unwrap();
    let nexthop2: Ipv6Addr = nexthops[1].parse().unwrap();

    mcast.set_forwarding(vec![
        McastForwardingNextHop {
            next_hop: NextHopV6::new(nexthop1, vni),
            replication,
            source_filter: source_filter.clone(),
        },
        McastForwardingNextHop {
            next_hop: NextHopV6::new(nexthop2, vni),
            replication,
            source_filter,
        },
    ])?;

    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr)?;

    topol.nodes[0]
        .port
        .subscribe_multicast(mcast_group.into())
        .expect("subscribe port 0 should succeed");

    // Confirm both next hops are programmed for failover.
    let hdl = OpteHdl::open()?;
    let mfwd = hdl.dump_mcast_fwd()?;
    let entry = mfwd
        .entries
        .iter()
        .find(|e| e.underlay == mcast_underlay)
        .expect("missing multicast forwarding entry for underlay group");

    assert_eq!(
        entry
            .next_hops
            .iter()
            .filter(|hop| hop.replication == replication)
            .count(),
        2,
        "expected both next hops programmed with {replication:?}; got: {:?}",
        entry.next_hops
    );

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
            Some(replication),
            "selected copy must carry {replication:?} replication"
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

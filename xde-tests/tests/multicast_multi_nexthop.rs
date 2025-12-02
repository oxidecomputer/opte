// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! XDE multicast multi-next-hop fanout tests.
//!
//! These tests validate that when multiple next hops are configured with
//! different replication modes, OPTE sends a separate packet to each next hop
//! with the correct replication flag in the Geneve header.

use anyhow::Result;
use opte_ioctl::OpteHdl;
use opte_test_utils::geneve_verify;
use oxide_vpc::api::DEFAULT_MULTICAST_VNI;
use oxide_vpc::api::IpCidr;
use oxide_vpc::api::Ipv4Addr;
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
fn test_multicast_multi_nexthop_fanout() -> Result<()> {
    // Test that multicast forwarding with multiple next hops sends packets to
    // all configured destinations, each with the correct replication flag.
    //
    // This test configures two next hops with different replication modes:
    // - NextHop 1: External replication (to boundary switch)
    // - NextHop 2: Underlay replication (sled-to-sled)
    //
    // After sending one multicast packet, we verify that two distinct Geneve
    // packets appear on the underlay, each with the correct replication flag.

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
    let nexthop1: oxide_vpc::api::Ipv6Addr = "fd77::1".parse().unwrap();
    let nexthop2: oxide_vpc::api::Ipv6Addr = "fd77::2".parse().unwrap();

    mcast.set_forwarding(vec![
        (NextHopV6::new(nexthop1, vni), Replication::External),
        (NextHopV6::new(nexthop2, vni), Replication::Underlay),
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
        entry.next_hops.iter().any(|(nexthop, rep)| {
            *rep == Replication::External
                && nexthop.addr == nexthop1
                && nexthop.vni == vni
        }),
        "expected External replication to {nexthop1:?} in forwarding table; got: {:?}",
        entry.next_hops
    );

    // Verify Underlay replication next hop is present
    assert!(
        entry.next_hops.iter().any(|(nexthop, rep)| {
            *rep == Replication::Underlay
                && nexthop.addr == nexthop2
                && nexthop.vni == vni
        }),
        "expected Underlay replication to {nexthop2:?} in forwarding table; got: {:?}",
        entry.next_hops
    );

    // Start snoop on underlay to capture both Geneve packets
    // Use -c 2 to capture exactly two packets, then exit
    let underlay_dev = UNDERLAY_TEST_DEVICE;
    let filter = GENEVE_UNDERLAY_FILTER;
    let mut snoop_underlay =
        SnoopGuard::start_with_count(underlay_dev, filter, 2)?;

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

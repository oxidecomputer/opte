// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! XDE multicast Rx-path tests.
//!
//! These validate that:
//! - Control-plane config (M2P map + forwarding) drives Tx encapsulation only.
//! - Same-sled delivery is based purely on subscriptions and is independent of
//!   the Replication mode set for Tx.
//! - Underlay multicast uses admin-local IPv6 (ff04::/16) and routes via the
//!   host underlay interface.
//! - Packets received from the underlay are delivered to subscribed ports and
//!   include the expected protocol and payload characteristics.

use anyhow::Result;
use opte_ioctl::OpteHdl;
use oxide_vpc::api::DEFAULT_MULTICAST_VNI;
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
use xde_tests::SNOOP_TIMEOUT_EXPECT_NONE;
use xde_tests::SnoopGuard;
use xde_tests::UNDERLAY_TEST_DEVICE;

#[test]
fn test_xde_multicast_rx_dual_family() -> Result<()> {
    // Dual-family Rx test: validates both IPv4 and IPv6 multicast Rx delivery
    // in a single test. Both address families follow identical packet processing
    // paths, so testing both in one test is justified.
    //
    // This test consolidates test_xde_multicast_rx_ipv4 and test_xde_multicast_rx_ipv6
    // to eliminate redundancy while maintaining coverage.

    // Create 2-node dual-stack topology (IPv4 + IPv6 overlay)
    let topol = xde_tests::two_node_topology_dualstack()?;

    // IPv4 multicast group: 224.0.0.251
    let mcast_group = Ipv4Addr::from([224, 0, 0, 251]);
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    // M2P mapping: overlay layer needs IPv6 multicast underlay address
    // Use admin-scoped IPv6 multicast per Omicron's map_external_to_underlay_ip()
    // Maps IPv4 multicast to ff04::/16 (admin-local scope) + IPv4 address
    let mcast_underlay =
        MulticastUnderlay::new("ff04::e000:fb".parse().unwrap()).unwrap();

    // Set up multicast group with automatic cleanup on drop
    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    // Use node B's underlay address as the switch unicast address for routing.
    // OPTE uses this address to determine the underlay port (via DDM routing),
    // but the actual packet destination is the multicast underlay address.
    // Note: This is a single-sled test; all nodes share one underlay network.
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    // Set up Tx forwarding with Underlay replication to test underlay Rx path.
    //
    // In this single-sled test (shared L2 underlay), packets receive both Tx
    // same-sled delivery (guest_loopback during Tx processing) and Rx delivery
    // (when packet loops back via u1→u2 from the underlay). This double-delivery
    // is a test artifact. In production multi-sled, only Rx delivery occurs when
    // receiving from other sleds.
    mcast.set_forwarding(vec![McastForwardingNextHop {
        next_hop: NextHopV6::new(fake_switch_addr, vni),
        replication: Replication::Underlay,
        source_filter: SourceFilter::default(),
    }])?;

    // Allow IPv4 multicast traffic (224.0.0.0/4) via Multicast target.
    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());

    // Add router entries for multicast (allows both In and Out directions)
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr)?;

    // Subscribe both ports to the multicast group
    topol.nodes[0]
        .port
        .subscribe_multicast(mcast_group.into())
        .expect("subscribe port 0 should succeed");
    topol.nodes[1]
        .port
        .subscribe_multicast(mcast_group.into())
        .expect("subscribe port 1 should succeed");

    // Assert subscription state via ioctl dump before sending
    let hdl = OpteHdl::open()?;
    let subs = hdl.dump_mcast_subs()?;
    let s_entry = subs
        .entries
        .iter()
        .find(|e| e.underlay == mcast_underlay)
        .expect("missing multicast subscription entry for underlay group");
    let p0 = topol.nodes[0].port.name().to_string();
    let p1 = topol.nodes[1].port.name().to_string();
    assert!(
        s_entry.has_port(&p0) && s_entry.has_port(&p1),
        "expected both {p0} and {p1} to be subscribed; got {:?}",
        s_entry.subscribers
    );

    // Assert forwarding table contains expected next hop + replication
    let mfwd = hdl.dump_mcast_fwd()?;
    let entry = mfwd
        .entries
        .iter()
        .find(|e| e.underlay == mcast_underlay)
        .expect("missing multicast forwarding entry for underlay group");
    assert!(
        entry.next_hops.iter().any(|hop| {
            hop.replication == Replication::Underlay
                && hop.next_hop.addr == fake_switch_addr
                && hop.next_hop.vni == vni
        }),
        "expected Underlay replication to {fake_switch_addr:?} in forwarding table; got: {:?}",
        entry.next_hops
    );

    // Start snoop on Rx side (matches IPv6 test pattern)
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let filter =
        format!("udp and ip dst {mcast_group} and port {MCAST_TEST_PORT}");
    let mut snoop_rx = SnoopGuard::start(&dev_name_b, &filter)?;

    // Send UDP packet from zone A using helper (pins source for deterministic egress)
    let payload = "multicast test";
    let sender_v4 = topol.nodes[0].port.ip();
    topol.nodes[0].zone.send_udp_v4(
        sender_v4,
        mcast_group,
        MCAST_TEST_PORT,
        payload,
    )?;

    // Wait for Rx snoop to capture the packet (or timeout)
    let snoop_rx_output = snoop_rx.assert_packet(&format!("on {dev_name_b}"));

    let stdout = String::from_utf8_lossy(&snoop_rx_output.stdout);
    // Verify destination address appears in snoop output
    // SnoopGuard uses -r flag, so we always get numeric addresses
    assert!(
        stdout.contains("224.0.0.251"),
        "expected destination 224.0.0.251 in snoop output:\n{stdout}"
    );
    // Payload present - check for substring in ASCII representation
    assert!(
        stdout.contains("test"),
        "expected payload substring 'test' in ASCII portion of snoop output:\n{stdout}"
    );
    // L2 dest: Verify proper IPv4 multicast MAC per RFC 1112.
    // For 224.0.0.251, the multicast MAC should be 01:00:5e:00:00:fb
    // (01:00:5e + lower 23 bits of IP address).
    // snoop shows MAC addresses in 16-bit grouped hex format.
    assert!(
        stdout.to_ascii_lowercase().contains("0100 5e00 00fb"),
        "expected IPv4 multicast MAC '0100 5e00 00fb' (01:00:5e:00:00:fb) in snoop output; got:\n{stdout}"
    );

    // Unsubscribe receiver and verify no further same-sled delivery
    topol.nodes[1]
        .port
        .unsubscribe_multicast(mcast_group.into())
        .expect("unsubscribe should succeed");

    // Assert subscription table reflects unsubscribe
    let subs2 = hdl.dump_mcast_subs()?;
    let s_entry2 = subs2
        .entries
        .iter()
        .find(|e| e.underlay == mcast_underlay)
        .expect("missing multicast subscription entry after unsubscribe");
    assert!(
        !s_entry2.has_port(&p1),
        "expected {p1} to be unsubscribed; got {:?}",
        s_entry2.subscribers
    );

    let mut snoop2 = SnoopGuard::start(&dev_name_b, &filter)?;
    topol.nodes[0].zone.send_udp_v4(
        sender_v4,
        mcast_group,
        MCAST_TEST_PORT,
        payload,
    )?;
    snoop2.assert_no_packet("after unsubscribe (IPv4)");

    // ========== IPv6 Test Section ==========
    // Now test IPv6 multicast using the same dual-stack topology

    // IPv6 multicast group: ff04::1:3 (admin-local scope)
    let mcast_group_v6: Ipv6Addr = "ff04::1:3".parse().unwrap();
    let mcast_underlay_v6 =
        MulticastUnderlay::new("ff04::1:3".parse().unwrap()).unwrap();

    let mcast_v6 =
        MulticastGroup::new(mcast_group_v6.into(), mcast_underlay_v6)?;

    // Reuse same forwarding config
    mcast_v6.set_forwarding(vec![McastForwardingNextHop {
        next_hop: NextHopV6::new(fake_switch_addr, vni),
        replication: Replication::Underlay,
        source_filter: SourceFilter::default(),
    }])?;

    // Allow IPv6 multicast traffic (ff04::/16 admin-local) via Multicast target
    let mcast_cidr_v6 =
        IpCidr::Ip6(IPV6_ADMIN_LOCAL_MULTICAST_CIDR.parse().unwrap());
    topol.nodes[0].port.add_multicast_router_entry(mcast_cidr_v6)?;
    topol.nodes[1].port.add_multicast_router_entry(mcast_cidr_v6)?;

    // Subscribe both ports to the IPv6 multicast group
    topol.nodes[0]
        .port
        .subscribe_multicast(mcast_group_v6.into())
        .expect("subscribe port 0 to IPv6 group should succeed");
    topol.nodes[1]
        .port
        .subscribe_multicast(mcast_group_v6.into())
        .expect("subscribe port 1 to IPv6 group should succeed");

    // Start snoop for IPv6 multicast
    let filter_v6 =
        format!("udp and ip6 dst {mcast_group_v6} and port {MCAST_TEST_PORT}");
    let mut snoop_v6 = SnoopGuard::start(&dev_name_b, &filter_v6)?;

    // Send UDP packet to the IPv6 multicast address from zone A
    let payload_v6 = "multicast test v6";
    let sender_v6 = topol.nodes[0]
        .port
        .ipv6()
        .expect("dualstack port must have IPv6 address");
    topol.nodes[0].zone.send_udp_v6(
        sender_v6,
        mcast_group_v6,
        MCAST_TEST_PORT,
        payload_v6,
    )?;

    // Wait for snoop to capture the IPv6 packet
    let snoop_output_v6 =
        snoop_v6.assert_packet(&format!("IPv6 on {dev_name_b}"));

    let stdout_v6 = String::from_utf8_lossy(&snoop_output_v6.stdout);
    // L2 dest: Verify proper IPv6 multicast MAC per RFC 2464 §7.
    // For ff04::1:3, the multicast MAC should be 33:33:00:01:00:03
    // (33:33 + last 4 bytes of IPv6 address).
    // snoop shows MAC addresses in 16-bit grouped hex format.
    assert!(
        stdout_v6.to_ascii_lowercase().contains("3333 0001 0003"),
        "expected IPv6 multicast MAC '3333 0001 0003' (33:33:00:01:00:03) in snoop output; got:\n{stdout_v6}"
    );

    Ok(())
}

#[test]
fn test_reject_link_local_underlay_ff02() -> Result<()> {
    let hdl = OpteHdl::open()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 99]);

    let link_local_underlay: Ipv6Addr = "ff02::e001:263".parse().unwrap();
    let underlay = MulticastUnderlay::new_unchecked(link_local_underlay);
    let result = hdl.set_m2p(&oxide_vpc::api::SetMcast2PhysReq {
        group: mcast_group.into(),
        underlay,
    });
    assert!(
        result.is_err(),
        "Expected link-local underlay (ff02::) to be rejected"
    );

    Ok(())
}

#[test]
fn test_reject_global_underlay_ff0e() -> Result<()> {
    let hdl = OpteHdl::open()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 99]);

    let global_underlay: Ipv6Addr = "ff0e::e001:263".parse().unwrap();
    let underlay = MulticastUnderlay::new_unchecked(global_underlay);
    let result = hdl.set_m2p(&oxide_vpc::api::SetMcast2PhysReq {
        group: mcast_group.into(),
        underlay,
    });
    assert!(
        result.is_err(),
        "Expected global underlay (ff0e::) to be rejected"
    );

    Ok(())
}

#[test]
fn test_accept_admin_local_underlay_ff04() -> Result<()> {
    let mcast_group = Ipv4Addr::from([224, 1, 2, 99]);
    let admin_local =
        MulticastUnderlay::new("ff04::e001:263".parse().unwrap()).unwrap();

    // MulticastGroup::new calls set_m2p internally and cleans up on drop.
    // This test verifies that admin-local (ff04::/16) addresses are accepted,
    // in contrast to link-local (ff02::) and global (ff0e::) which are rejected.
    let result = MulticastGroup::new(mcast_group.into(), admin_local);
    assert!(
        result.is_ok(),
        "Expected admin-local (ff04::) underlay to be accepted"
    );

    Ok(())
}

#[test]
fn test_multicast_config_no_spurious_traffic() -> Result<()> {
    // Test that multicast configuration (subscriptions + forwarding entries)
    // doesn't spontaneously generate traffic on the underlay when no packets
    // are actually being sent.

    let topol = xde_tests::two_node_topology()?;
    let mcast_group = Ipv4Addr::from([224, 1, 2, 200]);
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    let mcast_underlay =
        MulticastUnderlay::new("ff04::e001:2c8".parse().unwrap()).unwrap();

    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay)?;

    // Use node B's underlay address as the switch unicast address for routing.
    let fake_switch_addr = topol.nodes[1].port.underlay_ip().into();

    // Set up forwarding with Underlay replication
    mcast.set_forwarding(vec![McastForwardingNextHop {
        next_hop: NextHopV6::new(fake_switch_addr, vni),
        replication: Replication::Underlay,
        source_filter: SourceFilter::default(),
    }])?;

    let mcast_cidr = IpCidr::Ip4(IPV4_MULTICAST_CIDR.parse().unwrap());
    for node in &topol.nodes {
        node.port.add_multicast_router_entry(mcast_cidr)?;
        node.port
            .subscribe_multicast(mcast_group.into())
            .expect("subscribe should succeed");
    }

    // Snoop the underlay to verify no spurious traffic without sending
    let mut snoop_underlay =
        SnoopGuard::start(UNDERLAY_TEST_DEVICE, GENEVE_UNDERLAY_FILTER)?;

    // Verify no spurious underlay traffic (we're not sending any packets)
    let snoop_result =
        snoop_underlay.wait_with_timeout(SNOOP_TIMEOUT_EXPECT_NONE);

    match snoop_result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.is_empty(),
                "No multicast traffic should appear on underlay without a sender:\n{stdout}"
            );
        }
        Err(_) => {
            // Timeout is expected - no packets should appear
        }
    }

    Ok(())
}

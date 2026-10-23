// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Tests for IPv6 multicast: Geneve encapsulation and the rejection of
//! protocols which are incompatible with multicast.

use super::*;

// Test that IPv6 multicast packets get encapsulated with Geneve
#[test]
fn test_ipv6_multicast_encapsulation() {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);

    // Create an IPv6 multicast packet (ff04::1:3 - admin-local multicast)
    let mcast_dst = Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x03,
    ]);

    // Create a multicast underlay address (must be multicast for forwarding)
    let mcast_underlay = Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0xff, 0xff,
    ]);

    // Add multicast forwarding entry BEFORE starting the port
    g1.m2p.set(
        mcast_dst.into(),
        opte::api::MulticastUnderlay::new(mcast_underlay)
            .expect("ff04::/16 is admin-scoped multicast"),
    );

    g1.port.start();
    set!(g1, "port_state=running");

    // Multicast traffic is detected automatically by the gateway layer
    // (checking if the destination IP is multicast). Outbound multicast is
    // allowed by the router's built-in multicast rule and the gateway's
    // no-spoof rules; so, no explicit router entry or firewall rule is needed.

    // Build a UDP packet to the multicast address
    let eth = Ethernet {
        destination: MacAddr::from([0x33, 0x33, 0x00, 0x01, 0x00, 0x03]),
        source: g1_cfg.guest_mac,
        ethertype: Ethertype::IPV6,
    };
    let ip = Ipv6 {
        source: g1_cfg.ipv6().private_ip,
        destination: mcast_dst,
        next_header: IpProtocol::UDP,
        payload_len: (Udp::MINIMUM_LENGTH) as u16,
        hop_limit: 64,
        ..Default::default()
    };
    let udp = Udp {
        source: 12345,
        destination: 5353, // mDNS port as an example multicast UDP service
        length: Udp::MINIMUM_LENGTH as u16,
        ..Default::default()
    };
    let mut pkt_m = ulp_pkt(eth, ip, udp, &[]);

    let pkt = parse_outbound(&mut pkt_m, GenericUlp {}).unwrap();
    let res = g1.port.process(Out, pkt).expect("process should succeed");

    // Verify packet was encapsulated
    let Modified(spec) = res else {
        panic!("Expected Modified result, got {res:?}");
    };
    let mut pkt_m = spec.apply(pkt_m);

    // Parse the encapsulated packet as inbound (it's now on the wire with Geneve)
    let parsed = Packet::parse_inbound(pkt_m.iter_mut(), VpcParser {}).unwrap();
    let meta = parsed.meta();

    // Verify the outer IPv6 destination is the multicast underlay address
    assert_eq!(
        meta.outer_v6.destination(),
        mcast_underlay,
        "Outer IPv6 destination should be multicast underlay address"
    );

    // Verify the outer IPv6 source is the physical IP of the guest
    assert_eq!(
        meta.outer_v6.source(),
        g1_cfg.phys_ip,
        "Outer IPv6 source should be the physical IP"
    );

    // Verify the outer Ethernet destination MAC is the IPv6 multicast MAC
    // For IPv6 multicast, MAC is 33:33:xx:xx:xx:xx where xx:xx:xx:xx are the
    // last 4 bytes of the IPv6 address
    let expected_outer_mac = mcast_underlay.multicast_mac().unwrap();
    assert_eq!(
        meta.outer_eth.destination(),
        expected_outer_mac,
        "Outer Ethernet MAC should be IPv6 multicast MAC"
    );

    // Verify we have Geneve encapsulation with the correct VNI (fleet multicast VNI)
    assert_eq!(
        meta.outer_encap.vni(),
        Vni::new(oxide_vpc::api::DEFAULT_MULTICAST_VNI).unwrap(),
        "Geneve VNI should match DEFAULT_MULTICAST_VNI"
    );

    // Verify the Geneve multicast option is present with External replication
    let replication = geneve::extract_multicast_replication(&meta.outer_encap)
        .expect("Geneve packet should have multicast option");
    assert_eq!(
        replication,
        oxide_vpc::api::Replication::External,
        "Multicast option should have External replication"
    );
}

// Test that TCP + multicast packets are denied (TCP is incompatible with multicast)
#[test]
fn test_tcp_multicast_denied() {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);

    // Create an IPv6 multicast address
    let mcast_dst = Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x03,
    ]);

    let mcast_underlay = Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0xff, 0xff,
    ]);

    g1.m2p.set(
        mcast_dst.into(),
        opte::api::MulticastUnderlay::new(mcast_underlay)
            .expect("ff04::/16 is admin-scoped multicast"),
    );

    g1.port.start();
    set!(g1, "port_state=running");

    // Build a TCP packet to the multicast address (should be denied)
    let mut pkt_m = http_syn3(
        g1_cfg.guest_mac,
        g1_cfg.ipv6().private_ip,
        MacAddr::from([0x33, 0x33, 0x00, 0x01, 0x00, 0x03]),
        mcast_dst,
        12345,
        80,
    );

    let pkt = parse_outbound(&mut pkt_m, GenericUlp {}).unwrap();
    let res = g1.port.process(Out, pkt);

    // Verify packet was denied (TCP + multicast is incompatible)
    assert!(
        matches!(
            res,
            Ok(ProcessResult::Drop { reason: DropReason::Layer { .. } })
        ),
        "Expected Drop with Layer reason, got: {res:?}"
    );
}

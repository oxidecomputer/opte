//! Integration tests.
//!
//! The idea behind these tests is to use actual packet captures to
//! regression test known good captures. This is done by taking a
//! packet capture in the guest as well as on the host -- one for each
//! side of OPTE. These captures are then used to regression test an
//! OPTE pipeline by single-stepping the packets in each capture and
//! verifying that OPTE processing produces the expected bytes.
//!
//! TODO: We should also write tests which programmatically build
//! packets in order to better test more interesting scenarios. For
//! example, attempt an inbound connect to the guest's HTTP server,
//! verify it's blocked by firewall, add a new rule to allow incoming
//! on 80/443, verify the next request passes, remove the rules,
//! verify it once again is denied, etc.
use std::fs;
use std::ops::Range;
use std::prelude::v1::*;
use std::time::{Duration, Instant};

extern crate pcap_parser;
use pcap_parser::pcap::{self, LegacyPcapBlock, PcapHeader};

use zerocopy::AsBytes;

use crate::arp::{ArpEth4Payload, ArpEth4PayloadRaw, ArpHdrRaw, ARP_HDR_SZ};
use crate::ether::{EtherAddr, EtherHdrRaw, ETHER_HDR_SZ, ETHER_TYPE_ARP};
use crate::firewallng::Firewall;
use crate::flow_table::FLOW_DEF_EXPIRE_SECS;
use crate::ip4::Protocol;
use crate::layer::Layer;
use crate::nat::{DynNat4, NatPool};
use crate::packet::{
    mock_allocb, Initialized, Packet, PacketRead, PacketReader, PacketSeg,
    WritePos,
};
use crate::port::{Port, Pos, ProcessResult};
use crate::rule::{
    Action, EtherTypeMatch, Identity, IpProtoMatch, Ipv4AddrMatch, Predicate,
    Rule, RuleAction,
};
use crate::Direction::{self, *};

use ProcessResult::*;

fn get_header(offset: &[u8]) -> (&[u8], PcapHeader) {
    match pcap::parse_pcap_header(offset) {
        Ok((new_offset, header)) => (new_offset, header),
        Err(e) => panic!("failed to get header: {:?}", e),
    }
}

fn next_block(offset: &[u8]) -> (&[u8], LegacyPcapBlock) {
    match pcap::parse_pcap_frame(offset) {
        Ok((new_offset, block)) => {
            // We always want access to the entire packet.
            assert_eq!(block.origlen, block.caplen);
            (new_offset, block)
        }

        Err(e) => panic!("failed to get next block: {:?}", e),
    }
}

/// Verify that any early ARP traffic is dropped.
#[test]
fn early_arp() {
    use crate::packet::PacketWriter;

    let host_mac = EtherAddr::from([0x80, 0xe8, 0x2c, 0xf5, 0x10, 0x35]);
    let host_ip = "10.0.0.206".parse().unwrap();
    let gw_mac = EtherAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d]);
    let gw_ip = "10.0.0.1".parse().unwrap();
    let guest_mac = EtherAddr::from([0x02, 0x08, 0x20, 0xd8, 0x35, 0xcf]);
    let guest_ip = "10.0.0.210".parse().unwrap();
    let pub_ip = "10.0.0.99".parse().unwrap();
    let port = Port::new("int_test".to_string(), guest_mac);

    // Setup firewall.
    let fw_layer = Firewall::create_layer();
    port.add_layer(fw_layer, Pos::First);

    // We drop all outbound ARP until the the IP/gateway information
    // is set via opetadm set-ip-config, at which point we remove this
    // layer and put a new ARP layer in its place.
    let arp_drop = Identity::new("arp-drop".to_string());
    let arp = Layer::new("arp-drop", vec![Action::Static(Box::new(arp_drop))]);
    let mut rule = Rule::new(1, RuleAction::Deny);
    rule.add_predicate(Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(
        ETHER_TYPE_ARP,
    )]));
    arp.add_rule(Direction::Out, rule.clone());
    arp.add_rule(Direction::In, rule);
    port.add_layer(arp, Pos::First);

    let mut mp_head = mock_allocb(14);
    let mut mp2 = mock_allocb(28);

    // Use PacketSeg for the sole purpose of writing some bytes to these
    // segments before they are collected into the `Pkt` type.
    //
    // The first packet is a GARP Request from the host, split across
    // two segments (inbound).
    let eth_hdr = EtherHdrRaw {
        dst: host_mac.to_bytes(),
        src: host_mac.to_bytes(),
        ether_type: [0x08, 0x06],
    };
    let mut seg = unsafe { PacketSeg::wrap(mp_head) };
    seg.write(eth_hdr.as_bytes(), WritePos::Append).unwrap();
    mp_head = seg.unwrap();

    let arp_hdr = ArpHdrRaw {
        htype: [0x00, 0x01],
        ptype: [0x08, 0x00],
        hlen: 0x06,
        plen: 0x04,
        op: [0x00, 0x01],
    };
    seg = unsafe { PacketSeg::wrap(mp2) };
    seg.write(arp_hdr.as_bytes(), WritePos::Append).unwrap();
    let arp = ArpEth4Payload {
        sha: host_mac,
        spa: host_ip,
        tha: EtherAddr::from([0xFF; 6]),
        tpa: host_ip,
    };
    seg.write(ArpEth4PayloadRaw::from(arp).as_bytes(), WritePos::Append)
        .unwrap();
    mp2 = seg.unwrap();

    unsafe {
        (*mp_head).b_cont = mp2;
    }

    let mut pkt =
        unsafe { Packet::<Initialized>::wrap(mp_head).parse().unwrap() };
    assert_eq!(pkt.num_segs(), 2);
    assert_eq!(pkt.len(), 42);

    let res = port.process(In, &mut pkt, 0);
    match res {
        Drop => (),
        res => panic!("expected a Drop, got {:?}", res),
    }

    // The second ARP request is the gateway asking for the mac
    // address of the guest's public IP (inbound).
    let pkt = Packet::alloc(42);
    let eth_hdr = EtherHdrRaw {
        dst: [0xff; 6],
        src: gw_mac.to_bytes(),
        ether_type: [0x08, 0x06],
    };

    let arp_hdr = ArpHdrRaw {
        htype: [0x00, 0x01],
        ptype: [0x08, 0x00],
        hlen: 0x06,
        plen: 0x04,
        op: [0x00, 0x01],
    };

    let arp = ArpEth4Payload {
        sha: gw_mac,
        spa: gw_ip,
        tha: EtherAddr::from([0x00; 6]),
        tpa: pub_ip,
    };

    let mut wtr = PacketWriter::new(pkt, None);
    let _ = wtr.write(eth_hdr.as_bytes()).unwrap();
    let _ = wtr.write(arp_hdr.as_bytes()).unwrap();
    let _ = wtr.write(ArpEth4PayloadRaw::from(arp).as_bytes()).unwrap();
    let mut pkt = wtr.finish().parse().unwrap();

    let res = port.process(In, &mut pkt, 0);
    match res {
        Drop => (),
        res => panic!("expected a Drop, got {:?}", res),
    }

    // The third ARP request is the guest asking for the gateway's mac
    // address (outbound).
    let pkt = Packet::alloc(42);
    let eth_hdr = EtherHdrRaw {
        dst: [0xff; 6],
        src: guest_mac.to_bytes(),
        ether_type: [0x08, 0x06],
    };

    let arp_hdr = ArpHdrRaw {
        htype: [0x00, 0x01],
        ptype: [0x08, 0x00],
        hlen: 0x06,
        plen: 0x04,
        op: [0x00, 0x01],
    };

    let arp = ArpEth4Payload {
        sha: guest_mac,
        spa: guest_ip,
        tha: EtherAddr::from([0x00; 6]),
        tpa: gw_ip,
    };

    let mut wtr = PacketWriter::new(pkt, None);
    let _ = wtr.write(eth_hdr.as_bytes()).unwrap();
    let _ = wtr.write(arp_hdr.as_bytes()).unwrap();
    let _ = wtr.write(ArpEth4PayloadRaw::from(arp).as_bytes()).unwrap();
    let mut pkt = wtr.finish().parse().unwrap();

    let res = port.process(Out, &mut pkt, 0);
    match res {
        Drop => (),
        res => panic!("expected a Drop, got {:?}", res),
    }
}

// Verify the various parts of ARP hairpinning work and that any other
// ARP traffic is dropped.
#[test]
fn arp_hairpin() {
    use crate::arp::{ArpOp, ArpReply};
    use crate::ether::ETHER_TYPE_IPV4;
    use crate::ip4::Ipv4Addr;
    use crate::packet::PacketWriter;
    use crate::rule::{
        ArpHtypeMatch, ArpOpMatch, ArpPtypeMatch, DataPredicate, EtherAddrMatch,
    };

    let host_mac = EtherAddr::from([0x80, 0xe8, 0x2c, 0xf5, 0x10, 0x35]);
    let host_ip = "10.0.0.206".parse().unwrap();
    let gw_mac = EtherAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d]);
    let gw_ip = "10.0.0.1".parse().unwrap();
    let guest_mac = EtherAddr::from([0x02, 0x08, 0x20, 0xd8, 0x35, 0xcf]);
    let guest_ip = "10.0.0.210".parse().unwrap();
    let pub_ip = "10.0.0.99".parse::<Ipv4Addr>().unwrap();
    let pub_ip_bytes = pub_ip.to_be_bytes();
    let pub_mac = EtherAddr::from([
        0xa8,
        0x40,
        0x25,
        pub_ip_bytes[1],
        pub_ip_bytes[2],
        pub_ip_bytes[3],
    ]);
    let port = Port::new("int_test".to_string(), guest_mac);

    // Setup firewall layer.
    let fw_layer = Firewall::create_layer();
    port.add_layer(fw_layer, Pos::First);

    // Setup ARP layer.
    let arp = Layer::new(
        "arp",
        vec![
            // ARP Reply for gateway's IP.
            Action::Hairpin(Box::new(ArpReply::new(gw_ip, gw_mac))),
            // ARP Reply for guest's private IP.
            Action::Hairpin(Box::new(ArpReply::new(guest_ip, guest_mac))),
            // ARP Reply for guest's public IP.
            Action::Hairpin(Box::new(ArpReply::new(pub_ip, pub_mac))),
        ],
    );

    // ================================================================
    // Outbound ARP Request for Gateway, from Guest
    // ================================================================
    let mut rule = Rule::new(1, RuleAction::Allow(0));
    rule.add_predicate(Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(
        ETHER_TYPE_ARP,
    )]));
    rule.add_predicate(Predicate::InnerEtherDst(vec![EtherAddrMatch::Exact(
        EtherAddr::from([0xFF; 6]),
    )]));
    rule.add_predicate(Predicate::InnerArpHtype(ArpHtypeMatch::Exact(1)));
    rule.add_predicate(Predicate::InnerArpPtype(ArpPtypeMatch::Exact(
        ETHER_TYPE_IPV4,
    )));
    rule.add_predicate(Predicate::InnerArpOp(ArpOpMatch::Exact(
        ArpOp::Request,
    )));
    rule.add_data_predicate(DataPredicate::InnerArpTpa(vec![
        Ipv4AddrMatch::Exact(gw_ip),
    ]));
    arp.add_rule(Direction::Out, rule);

    // ================================================================
    // Drop all other outbound ARP Requests from Guest
    // ================================================================
    let mut rule = Rule::new(2, RuleAction::Deny);
    rule.add_predicate(Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(
        ETHER_TYPE_ARP,
    )]));
    arp.add_rule(Direction::Out, rule);

    // ================================================================
    // Inbound ARP Request from Gateway, for Guest Private IP
    // ================================================================
    let mut rule = Rule::new(1, RuleAction::Allow(1));
    rule.add_predicate(Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(
        ETHER_TYPE_ARP,
    )]));
    rule.add_predicate(Predicate::InnerEtherDst(vec![EtherAddrMatch::Exact(
        EtherAddr::from([0xFF; 6]),
    )]));
    rule.add_predicate(Predicate::InnerArpHtype(ArpHtypeMatch::Exact(1)));
    rule.add_predicate(Predicate::InnerArpPtype(ArpPtypeMatch::Exact(
        ETHER_TYPE_IPV4,
    )));
    rule.add_predicate(Predicate::InnerArpOp(ArpOpMatch::Exact(
        ArpOp::Request,
    )));
    rule.add_data_predicate(DataPredicate::InnerArpTpa(vec![
        Ipv4AddrMatch::Exact(guest_ip),
    ]));
    arp.add_rule(Direction::In, rule);

    // ================================================================
    // Inbound ARP Request from Gateway, for Guest Public IP
    // ================================================================
    let mut rule = Rule::new(1, RuleAction::Allow(2));
    rule.add_predicate(Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(
        ETHER_TYPE_ARP,
    )]));
    rule.add_predicate(Predicate::InnerEtherDst(vec![EtherAddrMatch::Exact(
        EtherAddr::from([0xFF; 6]),
    )]));
    rule.add_predicate(Predicate::InnerArpHtype(ArpHtypeMatch::Exact(1)));
    rule.add_predicate(Predicate::InnerArpPtype(ArpPtypeMatch::Exact(
        ETHER_TYPE_IPV4,
    )));
    rule.add_predicate(Predicate::InnerArpOp(ArpOpMatch::Exact(
        ArpOp::Request,
    )));
    rule.add_data_predicate(DataPredicate::InnerArpTpa(vec![
        Ipv4AddrMatch::Exact(pub_ip),
    ]));
    arp.add_rule(Direction::In, rule);

    // ================================================================
    // Drop all other inbound ARP Requests
    // ================================================================
    let mut rule = Rule::new(2, RuleAction::Deny);
    rule.add_predicate(Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(
        ETHER_TYPE_ARP,
    )]));
    arp.add_rule(Direction::In, rule);

    port.add_layer(arp, Pos::Before("firewall"));

    let reply_hdr_sz = ETHER_HDR_SZ + ARP_HDR_SZ;

    // ================================================================
    // GARP from the host. This should be dropped.
    // ================================================================
    let mut mp_head = mock_allocb(14);
    let mut mp2 = mock_allocb(28);

    // Use PacketSeg for the sole purpose of writing some bytes to these
    // segments before they are collected into the `Pkt` type.
    let eth_hdr = EtherHdrRaw {
        dst: host_mac.to_bytes(),
        src: host_mac.to_bytes(),
        ether_type: [0x08, 0x06],
    };
    let mut seg = unsafe { PacketSeg::wrap(mp_head) };
    seg.write(eth_hdr.as_bytes(), WritePos::Append).unwrap();
    mp_head = seg.unwrap();

    let arp_hdr = ArpHdrRaw {
        htype: [0x00, 0x01],
        ptype: [0x08, 0x00],
        hlen: 0x06,
        plen: 0x04,
        op: [0x00, 0x01],
    };
    seg = unsafe { PacketSeg::wrap(mp2) };
    seg.write(arp_hdr.as_bytes(), WritePos::Append).unwrap();
    let arp = ArpEth4Payload {
        sha: host_mac,
        spa: host_ip,
        tha: EtherAddr::from([0xFF; 6]),
        tpa: host_ip,
    };
    seg.write(ArpEth4PayloadRaw::from(arp).as_bytes(), WritePos::Append)
        .unwrap();
    mp2 = seg.unwrap();

    unsafe {
        (*mp_head).b_cont = mp2;
    }

    let mut pkt =
        unsafe { Packet::<Initialized>::wrap(mp_head).parse().unwrap() };
    assert_eq!(pkt.num_segs(), 2);
    assert_eq!(pkt.len(), 42);

    let res = port.process(In, &mut pkt, 0);
    match res {
        Drop => (),
        res => panic!("expected a Drop, got {:?}", res),
    }

    // ================================================================
    // ARP Request from guest for gateway. This should generate a
    // hairpin result.
    // ================================================================
    let pkt = Packet::alloc(42);
    let eth_hdr = EtherHdrRaw {
        dst: [0xff; 6],
        src: guest_mac.to_bytes(),
        ether_type: [0x08, 0x06],
    };

    let arp_hdr = ArpHdrRaw {
        htype: [0x00, 0x01],
        ptype: [0x08, 0x00],
        hlen: 0x06,
        plen: 0x04,
        op: [0x00, 0x01],
    };

    let arp = ArpEth4Payload {
        sha: guest_mac,
        spa: guest_ip,
        tha: EtherAddr::from([0x00; 6]),
        tpa: gw_ip,
    };

    let mut wtr = PacketWriter::new(pkt, None);
    let _ = wtr.write(eth_hdr.as_bytes()).unwrap();
    let _ = wtr.write(arp_hdr.as_bytes()).unwrap();
    let _ = wtr.write(ArpEth4PayloadRaw::from(arp).as_bytes()).unwrap();
    let mut pkt = wtr.finish().parse().unwrap();

    let res = port.process(Out, &mut pkt, 0);
    match res {
        Hairpin(hppkt) => {
            let hppkt = hppkt.parse().unwrap();
            let meta = hppkt.clone_meta();
            let ethm = meta.inner_ether.as_ref().unwrap();
            let arpm = meta.inner_arp.as_ref().unwrap();
            assert_eq!(ethm.dst, guest_mac);
            assert_eq!(ethm.src, gw_mac);
            assert_eq!(ethm.ether_type, ETHER_TYPE_ARP);
            assert_eq!(arpm.op, ArpOp::Reply);
            assert_eq!(arpm.ptype, ETHER_TYPE_IPV4);

            let mut rdr = PacketReader::new(&hppkt, ());
            assert!(rdr.seek(reply_hdr_sz).is_ok());
            let arp = ArpEth4Payload::from(
                &ArpEth4PayloadRaw::parse(&mut rdr).unwrap(),
            );

            assert_eq!(arp.sha, gw_mac);
            assert_eq!(arp.spa, gw_ip);
            assert_eq!(arp.tha, guest_mac);
            assert_eq!(arp.tpa, guest_ip);
        }

        res => panic!("expected a Hairpin, got {:?}", res),
    }

    // ================================================================
    // ARP Request from gateway for guest private IP. This should
    // generate a hairpin result.
    // ================================================================
    let pkt = Packet::alloc(42);
    let eth_hdr = EtherHdrRaw {
        dst: [0xff; 6],
        src: gw_mac.to_bytes(),
        ether_type: [0x08, 0x06],
    };

    let arp_hdr = ArpHdrRaw {
        htype: [0x00, 0x01],
        ptype: [0x08, 0x00],
        hlen: 0x06,
        plen: 0x04,
        op: [0x00, 0x01],
    };

    let arp = ArpEth4Payload {
        sha: gw_mac,
        spa: gw_ip,
        tha: EtherAddr::from([0x00; 6]),
        tpa: guest_ip,
    };

    let mut wtr = PacketWriter::new(pkt, None);
    let _ = wtr.write(eth_hdr.as_bytes()).unwrap();
    let _ = wtr.write(arp_hdr.as_bytes()).unwrap();
    let _ = wtr.write(ArpEth4PayloadRaw::from(arp).as_bytes()).unwrap();
    let mut pkt = wtr.finish().parse().unwrap();

    let res = port.process(In, &mut pkt, 0);
    match res {
        Hairpin(hppkt) => {
            let hppkt = hppkt.parse().unwrap();
            let meta = hppkt.clone_meta();
            let ethm = meta.inner_ether.as_ref().unwrap();
            let arpm = meta.inner_arp.as_ref().unwrap();
            assert_eq!(ethm.dst, gw_mac);
            assert_eq!(ethm.src, guest_mac);
            assert_eq!(ethm.ether_type, ETHER_TYPE_ARP);
            assert_eq!(arpm.op, ArpOp::Reply);
            assert_eq!(arpm.ptype, ETHER_TYPE_IPV4);

            let mut rdr = PacketReader::new(&hppkt, ());
            assert!(rdr.seek(reply_hdr_sz).is_ok());
            let arp = ArpEth4Payload::from(
                &ArpEth4PayloadRaw::parse(&mut rdr).unwrap(),
            );

            assert_eq!(arp.sha, guest_mac);
            assert_eq!(arp.spa, guest_ip);
            assert_eq!(arp.tha, gw_mac);
            assert_eq!(arp.tpa, gw_ip);
        }

        res => panic!("expected a Hairpin, got {:?}", res),
    }

    // ================================================================
    // ARP Request from gateway for guest public IP. This should
    // generate a hairpin result.
    // ================================================================
    let pkt = Packet::alloc(42);
    let eth_hdr = EtherHdrRaw {
        dst: [0xff; 6],
        src: gw_mac.to_bytes(),
        ether_type: [0x08, 0x06],
    };

    let arp_hdr = ArpHdrRaw {
        htype: [0x00, 0x01],
        ptype: [0x08, 0x00],
        hlen: 0x06,
        plen: 0x04,
        op: [0x00, 0x01],
    };

    let arp = ArpEth4Payload {
        sha: gw_mac,
        spa: gw_ip,
        tha: EtherAddr::from([0x00; 6]),
        tpa: pub_ip,
    };

    let mut wtr = PacketWriter::new(pkt, None);
    let _ = wtr.write(eth_hdr.as_bytes()).unwrap();
    let _ = wtr.write(arp_hdr.as_bytes()).unwrap();
    let _ = wtr.write(ArpEth4PayloadRaw::from(arp).as_bytes()).unwrap();
    let mut pkt = wtr.finish().parse().unwrap();

    let res = port.process(In, &mut pkt, 0);
    match res {
        Hairpin(hppkt) => {
            let hppkt = hppkt.parse().unwrap();
            let meta = hppkt.clone_meta();
            let ethm = meta.inner_ether.as_ref().unwrap();
            let arpm = meta.inner_arp.as_ref().unwrap();
            assert_eq!(ethm.dst, gw_mac);
            assert_eq!(ethm.src, pub_mac);
            assert_eq!(ethm.ether_type, ETHER_TYPE_ARP);
            assert_eq!(arpm.op, ArpOp::Reply);
            assert_eq!(arpm.ptype, ETHER_TYPE_IPV4);

            let mut rdr = PacketReader::new(&hppkt, ());
            assert!(rdr.seek(reply_hdr_sz).is_ok());
            let arp = ArpEth4Payload::from(
                &ArpEth4PayloadRaw::parse(&mut rdr).unwrap(),
            );

            assert_eq!(arp.sha, pub_mac);
            assert_eq!(arp.spa, pub_ip);
            assert_eq!(arp.tha, gw_mac);
            assert_eq!(arp.tpa, gw_ip);
        }

        res => panic!("expected a Hairpin, got {:?}", res),
    }
}

/// Test a DNS lookup from guest to internet.
///
/// TODO Would be nice to verify if packet hits a layer rule or flow
/// or hits the UFT.
///
/// TODO Would also be nice to verify the number of hits against LFTs
/// and UFT.
#[test]
fn outgoing_dns_lookup() {
    let sub = "10.0.0.0/24".parse().unwrap();
    let guest_mac = EtherAddr::from([0x02, 0x08, 0x20, 0xd8, 0x35, 0xcf]);
    let guest_ip = "10.0.0.210".parse().unwrap();
    let pub_mac = EtherAddr::from([0xa8, 0x40, 0x25, 0x0, 0x0, 0x63]);
    let pub_ip = "10.0.0.99".parse().unwrap();
    let port = Port::new("int_test".to_string(), guest_mac);

    // Setup firewall.
    let fw_layer = Firewall::create_layer();
    port.add_layer(fw_layer, Pos::First);

    // Setup Dynamic NAT
    let mut nat_pool = NatPool::new();
    nat_pool.add(guest_ip, pub_ip, Range { start: 1025, end: 4096 });
    port.set_nat_pool(nat_pool);
    let nat =
        DynNat4::new("dyn-nat4".to_string(), guest_ip, guest_mac, pub_mac);
    let nat_layer =
        Layer::new("dyn-nat4", vec![Action::Stateful(Box::new(nat))]);
    let mut rule = Rule::new(1, RuleAction::Allow(0));
    rule.add_predicate(Predicate::InnerIpProto(vec![
        IpProtoMatch::Exact(Protocol::TCP),
        IpProtoMatch::Exact(Protocol::UDP),
    ]));
    rule.add_predicate(Predicate::Not(Box::new(Predicate::InnerDstIp4(vec![
        Ipv4AddrMatch::Prefix(sub),
    ]))));
    nat_layer.add_rule(Direction::Out, rule);
    port.add_layer(nat_layer, Pos::After("firewall"));

    let gpath = "dns-lookup-guest.pcap";
    let gbytes = fs::read(gpath).unwrap();
    let hpath = "dns-lookup-host.pcap";
    let hbytes = fs::read(hpath).unwrap();

    assert_eq!(port.num_flows("dyn-nat4", In), 0);
    assert_eq!(port.num_flows("dyn-nat4", Out), 0);
    assert_eq!(port.num_flows("firewall", In), 0);
    assert_eq!(port.num_flows("firewall", Out), 0);
    let now = Instant::now();

    // ================================================================
    // Packet 1 (DNS query)
    // ================================================================
    let (gbytes, _) = get_header(&gbytes[..]);
    let (gbytes, gblock) = next_block(&gbytes);
    let mut pkt = Packet::copy(gblock.data).parse().unwrap();
    let res = port.process(Out, &mut pkt, 0);
    let meta = match res {
        Modify(m) => m,
        res => panic!("expected a Modify, got {:?}", res),
    };

    assert_eq!(port.num_flows("dyn-nat4", In), 0);
    assert_eq!(port.num_flows("dyn-nat4", Out), 0);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let _ = pkt.set_headers(&meta).unwrap();

    // TODO While it's easy to compare straight bytes right now this
    // is not how we want to do it moving forward. Instead, we'll want
    // to compare each individual header so we can give detailed error
    // reports on test failure. Furthermore, as more layers are added
    // to the stack it will be rare that a packet goes through
    // processing untouched (at least in the case of the Oxide Network
    // it should never happen for guest traffic). But, for now, this
    // works.
    let (hbytes, _hdr) = get_header(&hbytes[..]);
    let (hbytes, hblock) = next_block(&hbytes);
    assert_eq!(pkt.seg_bytes(0), hblock.data);

    // ================================================================
    // Packet 2 (DNS query response)
    // ================================================================
    let (_hbytes, hblock) = next_block(&hbytes);
    let mut pkt = Packet::copy(hblock.data).parse().unwrap();
    let res = port.process(In, &mut pkt, 0);
    let meta = match res {
        Modify(m) => m,
        res => panic!("expected a Modify, got {:?}", res),
    };

    assert_eq!(port.num_flows("dyn-nat4", In), 0);
    assert_eq!(port.num_flows("dyn-nat4", Out), 0);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let _ = pkt.set_headers(&meta).unwrap();
    let (_gbytes, gblock) = next_block(&gbytes);
    assert_eq!(pkt.seg_bytes(0), gblock.data);

    // ================================================================
    // Expiration
    // ================================================================

    // Verify that the flow is still valid when it should be.
    port.expire_flows(now + Duration::new(FLOW_DEF_EXPIRE_SECS as u64, 0));
    assert_eq!(port.num_flows("dyn-nat4", In), 0);
    assert_eq!(port.num_flows("dyn-nat4", Out), 0);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    // Verify the flow is expired when it should be.
    port.expire_flows(now + Duration::new(FLOW_DEF_EXPIRE_SECS as u64 + 1, 0));
    assert_eq!(port.num_flows("dyn-nat4", In), 0);
    assert_eq!(port.num_flows("dyn-nat4", Out), 0);
    assert_eq!(port.num_flows("firewall", In), 0);
    assert_eq!(port.num_flows("firewall", Out), 0);
}

// Test an outgoing HTTP request/connection. I happened upon a small
// connectivity check that Ubuntu makes which is good for this
// smaller-scale test (Ubuntu uses this to check for captive portals).
#[test]
fn outgoing_http_req() {
    let sub = "10.0.0.0/24".parse().unwrap();
    let guest_mac = EtherAddr::from([0x02, 0x08, 0x20, 0xd8, 0x35, 0xcf]);
    let guest_ip = "10.0.0.210".parse().unwrap();
    let pub_mac = EtherAddr::from([0xa8, 0x40, 0x25, 0x0, 0x0, 0x63]);
    let pub_ip = "10.0.0.99".parse().unwrap();
    let port = Port::new("int_test".to_string(), guest_mac);

    // Setup firewall.
    let fw_layer = Firewall::create_layer();
    port.add_layer(fw_layer, Pos::First);

    // Setup Dynamic NAT
    let mut nat_pool = NatPool::new();
    // We have to specify exactly one port to match up with the actual
    // port from the pcap.
    nat_pool.add(guest_ip, pub_ip, Range { start: 3839, end: 3840 });
    port.set_nat_pool(nat_pool);
    let nat =
        DynNat4::new("dyn-nat4".to_string(), guest_ip, guest_mac, pub_mac);
    let nat_layer =
        Layer::new("dyn-nat4", vec![Action::Stateful(Box::new(nat))]);
    let mut rule = Rule::new(1, RuleAction::Allow(0));
    rule.add_predicate(Predicate::InnerIpProto(vec![
        IpProtoMatch::Exact(Protocol::TCP),
        IpProtoMatch::Exact(Protocol::UDP),
    ]));
    rule.add_predicate(Predicate::Not(Box::new(Predicate::InnerDstIp4(vec![
        Ipv4AddrMatch::Prefix(sub),
    ]))));
    nat_layer.add_rule(Direction::Out, rule);
    port.add_layer(nat_layer, Pos::After("firewall"));

    let gpath = "http-out-guest.pcap";
    let gbytes = fs::read(gpath).unwrap();
    let hpath = "http-out-host.pcap";
    let hbytes = fs::read(hpath).unwrap();

    // Assert the baseline before any packet processing occurs.
    assert_eq!(port.num_flows("dyn-nat4", In), 0);
    assert_eq!(port.num_flows("dyn-nat4", Out), 0);
    assert_eq!(port.num_flows("firewall", In), 0);
    assert_eq!(port.num_flows("firewall", Out), 0);
    let now = Instant::now();

    // ================================================================
    // Packet 1 (SYN)
    // ================================================================
    let (gbytes, _) = get_header(&gbytes[..]);
    let (gbytes, gblock) = next_block(gbytes);
    let mut pkt = Packet::copy(gblock.data).parse().unwrap();
    let res = port.process(Out, &mut pkt, 0);
    let meta = match res {
        Modify(m) => m,
        res => panic!("expected a Modify, got {:?}", res),
    };

    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let _ = pkt.set_headers(&meta).unwrap();
    let (hbytes, _) = get_header(&hbytes[..]);
    let (hbytes, hblock) = next_block(hbytes);
    assert_eq!(pkt.seg_bytes(0), hblock.data);
    drop(pkt);

    // ================================================================
    // Packet 2 (SYN+ACK)
    // ================================================================
    let (hbytes, hblock) = next_block(hbytes);
    let mut pkt = Packet::copy(hblock.data).parse().unwrap();
    let res = port.process(In, &mut pkt, 0);
    let meta = match res {
        Modify(m) => m,
        res => panic!("expected a Modify, got {:?}", res),
    };

    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let _ = pkt.set_headers(&meta).unwrap();
    let (gbytes, gblock) = next_block(gbytes);
    assert_eq!(pkt.seg_bytes(0), gblock.data);
    drop(pkt);

    // ================================================================
    // Packet 3 (ACK)
    // ================================================================
    let (gbytes, gblock) = next_block(gbytes);
    let mut pkt = Packet::copy(gblock.data).parse().unwrap();
    let res = port.process(Out, &mut pkt, 0);
    let meta = match res {
        Modify(m) => m,
        res => panic!("expected a Modify, got {:?}", res),
    };

    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let _ = pkt.set_headers(&meta).unwrap();
    let (hbytes, hblock) = next_block(hbytes);
    assert_eq!(pkt.seg_bytes(0), hblock.data);
    drop(pkt);

    // ================================================================
    // Packet 4 (HTTP GET)
    // ================================================================
    let (gbytes, gblock) = next_block(gbytes);
    let mut pkt = Packet::copy(gblock.data).parse().unwrap();
    let res = port.process(Out, &mut pkt, 0);
    let meta = match res {
        Modify(m) => m,
        res => panic!("expected a Modify, got {:?}", res),
    };

    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let _ = pkt.set_headers(&meta).unwrap();
    let (hbytes, hblock) = next_block(hbytes);
    assert_eq!(pkt.seg_bytes(0), hblock.data);
    drop(pkt);

    // ================================================================
    // Packet 5 (ACK #4)
    // ================================================================
    let (hbytes, hblock) = next_block(hbytes);
    let mut pkt = Packet::copy(hblock.data).parse().unwrap();
    let res = port.process(In, &mut pkt, 0);
    let meta = match res {
        Modify(m) => m,
        res => panic!("expected a Modify, got {:?}", res),
    };

    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let _ = pkt.set_headers(&meta).unwrap();
    let (gbytes, gblock) = next_block(gbytes);
    assert_eq!(pkt.seg_bytes(0), gblock.data);
    drop(pkt);

    // ================================================================
    // Packet 6 (HTTP 301)
    // ================================================================
    let (hbytes, hblock) = next_block(hbytes);
    let mut pkt = Packet::copy(hblock.data).parse().unwrap();
    let res = port.process(In, &mut pkt, 0);
    let meta = match res {
        Modify(m) => m,
        res => panic!("expected a Modify, got {:?}", res),
    };

    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let _ = pkt.set_headers(&meta).unwrap();
    let (gbytes, gblock) = next_block(gbytes);
    assert_eq!(pkt.seg_bytes(0), gblock.data);
    drop(pkt);

    // ================================================================
    // Packet 7 (ACK #6)
    // ================================================================
    let (gbytes, gblock) = next_block(gbytes);
    let mut pkt = Packet::copy(gblock.data).parse().unwrap();
    let res = port.process(Out, &mut pkt, 0);
    let meta = match res {
        Modify(m) => m,
        res => panic!("expected a Modify, got {:?}", res),
    };

    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let _ = pkt.set_headers(&meta).unwrap();
    let (hbytes, hblock) = next_block(hbytes);
    assert_eq!(pkt.seg_bytes(0), hblock.data);
    drop(pkt);

    // ================================================================
    // Packet 8 (Guest FIN ACK)
    // ================================================================
    let (gbytes, gblock) = next_block(gbytes);
    let mut pkt = Packet::copy(gblock.data).parse().unwrap();
    let res = port.process(Out, &mut pkt, 0);
    let meta = match res {
        Modify(m) => m,
        res => panic!("expected a Modify, got {:?}", res),
    };

    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let _ = pkt.set_headers(&meta).unwrap();
    let (hbytes, hblock) = next_block(hbytes);
    assert_eq!(pkt.seg_bytes(0), hblock.data);
    drop(pkt);

    // ================================================================
    // Packet 9 (ACK #8)
    // ================================================================
    let (hbytes, hblock) = next_block(hbytes);
    let mut pkt = Packet::copy(hblock.data).parse().unwrap();
    let res = port.process(In, &mut pkt, 0);
    let meta = match res {
        Modify(m) => m,
        res => panic!("expected a Modify, got {:?}", res),
    };

    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let _ = pkt.set_headers(&meta).unwrap();
    let (gbytes, gblock) = next_block(gbytes);
    assert_eq!(pkt.seg_bytes(0), gblock.data);
    drop(pkt);

    // ================================================================
    // Packet 10 (Remote FIN ACK)
    // ================================================================
    let (hbytes, hblock) = next_block(hbytes);
    let mut pkt = Packet::copy(hblock.data).parse().unwrap();
    let res = port.process(In, &mut pkt, 0);
    let meta = match res {
        Modify(m) => m,
        res => panic!("expected a Modify, got {:?}", res),
    };

    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let _ = pkt.set_headers(&meta).unwrap();
    let (gbytes, gblock) = next_block(gbytes);
    assert_eq!(pkt.seg_bytes(0), gblock.data);
    drop(pkt);

    // ================================================================
    // Packet 11 (ACK #10)
    // ================================================================
    let (_gbytes, gblock) = next_block(gbytes);
    let mut pkt = Packet::copy(gblock.data).parse().unwrap();
    let res = port.process(Out, &mut pkt, 0);
    let meta = match res {
        Modify(m) => m,
        res => panic!("expected a Modify, got {:?}", res),
    };

    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let _ = pkt.set_headers(&meta).unwrap();
    let (_hbytes, hblock) = next_block(hbytes);
    assert_eq!(pkt.seg_bytes(0), hblock.data);
    drop(pkt);

    // ================================================================
    // Expiration
    // ================================================================

    // TODO: TCP flow table needs to hook into expiry, in which case
    // the flows would all expire at the moment of connection
    // teardown.

    // Verify that the flow is still valid when it should be.
    port.expire_flows(now + Duration::new(FLOW_DEF_EXPIRE_SECS as u64, 0));
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    // Verify the flow is expired when it should be.
    port.expire_flows(now + Duration::new(FLOW_DEF_EXPIRE_SECS as u64 + 1, 0));
    assert_eq!(port.num_flows("dyn-nat4", In), 0);
    assert_eq!(port.num_flows("dyn-nat4", Out), 0);
    assert_eq!(port.num_flows("firewall", In), 0);
    assert_eq!(port.num_flows("firewall", Out), 0);
}

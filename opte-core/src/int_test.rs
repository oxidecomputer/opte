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
use crate::ether::{
    self, EtherAddr, EtherHdrRaw, EtherMeta, ETHER_HDR_SZ, ETHER_TYPE_ARP,
    ETHER_TYPE_IPV4
};
use crate::flow_table::FLOW_DEF_EXPIRE_SECS;
use crate::headers::{Ipv4Meta, IpMeta, UdpMeta};
use crate::ip4::{self, Ipv4HdrRaw, Protocol};
use crate::layer::Layer;
use crate::oxide_net;
use crate::packet::{
    mock_allocb, Initialized, Packet, PacketRead, PacketReader, PacketSeg,
    PacketWriter, WritePos,
};
use crate::port::{Port, Pos, ProcessResult};
use crate::rule::{
    Action, EtherTypeMatch, Identity, Predicate, Rule, RuleAction,
};
use crate::udp::UdpHdrRaw;
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

fn home_cfg() -> oxide_net::PortConfig {
    oxide_net::PortConfig {
        private_ip: "10.0.0.210".parse().unwrap(),
        private_mac: EtherAddr::from([0x02, 0x08, 0x20, 0xd8, 0x35, 0xcf]),
        vpc_subnet: "10.0.0.0/24".parse().unwrap(),
        dyn_nat: oxide_net::DynNat4Config {
            public_mac: EtherAddr::from([0xA8, 0x40, 0x25, 0x00, 0x00, 0x63]),
            public_ip: "10.0.0.99".parse().unwrap(),
            ports: Range { start: 1025, end: 4096 },
        },
        gw_mac: EtherAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d]),
        gw_ip: "10.0.0.1".parse().unwrap(),
    }
}

fn lab_cfg() -> oxide_net::PortConfig {
    oxide_net::PortConfig {
        private_ip: "172.20.14.16".parse().unwrap(),
        private_mac: EtherAddr::from([0xAA, 0x00, 0x04, 0x00, 0xFF, 0x10]),
        vpc_subnet: "172.20.14.0/24".parse().unwrap(),
        dyn_nat: oxide_net::DynNat4Config {
            public_mac: EtherAddr::from([0xA8, 0x40, 0x25, 0x00, 0x01, 0xEE]),
            public_ip: "76.76.21.21".parse().unwrap(),
            ports: Range { start: 1025, end: 4096 },
        },
        gw_mac: EtherAddr::from([0xAA, 0x00, 0x04, 0x00, 0xFF, 0x01]),
        gw_ip: "172.20.14.1".parse().unwrap(),
    }
}

fn oxide_net_setup(port: &mut Port, cfg: &oxide_net::PortConfig) {
    // ================================================================
    // Firewall layer
    // ================================================================
    oxide_net::firewall::setup(port);

    // ================================================================
    // Dynamic NAT Layer (IPv4)
    // ================================================================
    oxide_net::dyn_nat4::setup(port, cfg);

    // ================================================================
    // ARP layer
    // ================================================================
    oxide_net::arp::setup(port, cfg);
}

#[test]
fn dhcp_req() {
    let cfg = lab_cfg();
    let mut port = Port::new("dhcp_req".to_string(), cfg.private_mac);
    oxide_net_setup(&mut port, &cfg);

    let pkt = Packet::alloc(42);

    let ether = EtherMeta {
        src: cfg.private_mac,
        dst: ether::ETHER_BROADCAST,
        ether_type: ETHER_TYPE_IPV4
    };

    let ip = Ipv4Meta {
        src: "0.0.0.0".parse().unwrap(),
        dst: ip4::LOCAL_BROADCAST,
        proto: Protocol::UDP,
    };

    let udp = UdpMeta { src: 68, dst: 67 };

    let mut wtr = PacketWriter::new(pkt, None);
    let _ = wtr.write(EtherHdrRaw::from(&ether).as_bytes()).unwrap();
    let _ = wtr.write(Ipv4HdrRaw::from(&ip).as_bytes()).unwrap();
    let _ = wtr.write(UdpHdrRaw::from(&udp).as_bytes()).unwrap();

    let mut pkt = wtr.finish().parse().unwrap();

    let res = port.process(Out, &mut pkt, 0);
    match res {
        Modify(meta) => {
            // TODO This packet wasn't actually moidfied (that's the
            // point of this test), but `Modify()` is what processing
            // returns since it technically did pass through the
            // firewall action (which is just Identity). It would be
            // nice if we only returned `Modify()` when the metadata
            // actually changes.
            let ethm = meta.inner_ether.as_ref().unwrap();
            assert_eq!(ethm.src, cfg.private_mac);
            assert_eq!(ethm.dst, ether::ETHER_BROADCAST);

            let ip4m = match meta.inner_ip.as_ref().unwrap() {
                IpMeta::Ip4(v) => v,
                _ => panic!("expect Ipv4Meta"),
            };

            assert_eq!(ip4m.src, "0.0.0.0".parse().unwrap());
            assert_eq!(ip4m.dst, ip4::LOCAL_BROADCAST);
            assert_eq!(ip4m.proto, Protocol::UDP);
        }

        res => panic!("expected Modify result, got {:?}", res),
    }
}

/// Verify that any early ARP traffic is dropped.
#[test]
fn early_arp() {
    let host_mac = EtherAddr::from([0x80, 0xe8, 0x2c, 0xf5, 0x10, 0x35]);
    let host_ip = "10.0.0.206".parse().unwrap();

    let cfg = home_cfg();
    let mut port = Port::new("int_test".to_string(), cfg.private_mac);

    oxide_net::firewall::setup(&mut port);

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
        src: cfg.gw_mac.to_bytes(),
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
        sha: cfg.gw_mac,
        spa: cfg.gw_ip,
        tha: EtherAddr::from([0x00; 6]),
        tpa: cfg.dyn_nat.public_ip,
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
        src: cfg.private_mac.to_bytes(),
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
        sha: cfg.private_mac,
        spa: cfg.private_ip,
        tha: EtherAddr::from([0x00; 6]),
        tpa: cfg.gw_ip,
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
    use crate::arp::ArpOp;
    use crate::ether::ETHER_TYPE_IPV4;

    let cfg = home_cfg();
    let host_mac = EtherAddr::from([0x80, 0xe8, 0x2c, 0xf5, 0x10, 0x35]);
    let host_ip = "10.0.0.206".parse().unwrap();
    let mut port = Port::new("int_test".to_string(), cfg.private_mac);
    oxide_net_setup(&mut port, &cfg);
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
        src: cfg.private_mac.to_bytes(),
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
        sha: cfg.private_mac,
        spa: cfg.private_ip,
        tha: EtherAddr::from([0x00; 6]),
        tpa: cfg.gw_ip,
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
            assert_eq!(ethm.dst, cfg.private_mac);
            assert_eq!(ethm.src, cfg.gw_mac);
            assert_eq!(ethm.ether_type, ETHER_TYPE_ARP);
            assert_eq!(arpm.op, ArpOp::Reply);
            assert_eq!(arpm.ptype, ETHER_TYPE_IPV4);

            let mut rdr = PacketReader::new(&hppkt, ());
            assert!(rdr.seek(reply_hdr_sz).is_ok());
            let arp = ArpEth4Payload::from(
                &ArpEth4PayloadRaw::parse(&mut rdr).unwrap(),
            );

            assert_eq!(arp.sha, cfg.gw_mac);
            assert_eq!(arp.spa, cfg.gw_ip);
            assert_eq!(arp.tha, cfg.private_mac);
            assert_eq!(arp.tpa, cfg.private_ip);
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
        src: cfg.gw_mac.to_bytes(),
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
        sha: cfg.gw_mac,
        spa: cfg.gw_ip,
        tha: EtherAddr::from([0x00; 6]),
        tpa: cfg.private_ip,
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
            assert_eq!(ethm.dst, cfg.gw_mac);
            assert_eq!(ethm.src, cfg.private_mac);
            assert_eq!(ethm.ether_type, ETHER_TYPE_ARP);
            assert_eq!(arpm.op, ArpOp::Reply);
            assert_eq!(arpm.ptype, ETHER_TYPE_IPV4);

            let mut rdr = PacketReader::new(&hppkt, ());
            assert!(rdr.seek(reply_hdr_sz).is_ok());
            let arp = ArpEth4Payload::from(
                &ArpEth4PayloadRaw::parse(&mut rdr).unwrap(),
            );

            assert_eq!(arp.sha, cfg.private_mac);
            assert_eq!(arp.spa, cfg.private_ip);
            assert_eq!(arp.tha, cfg.gw_mac);
            assert_eq!(arp.tpa, cfg.gw_ip);
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
        src: cfg.gw_mac.to_bytes(),
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
        sha: cfg.gw_mac,
        spa: cfg.gw_ip,
        tha: EtherAddr::from([0x00; 6]),
        tpa: cfg.dyn_nat.public_ip,
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
            assert_eq!(ethm.dst, cfg.gw_mac);
            assert_eq!(ethm.src, cfg.dyn_nat.public_mac);
            assert_eq!(ethm.ether_type, ETHER_TYPE_ARP);
            assert_eq!(arpm.op, ArpOp::Reply);
            assert_eq!(arpm.ptype, ETHER_TYPE_IPV4);

            let mut rdr = PacketReader::new(&hppkt, ());
            assert!(rdr.seek(reply_hdr_sz).is_ok());
            let arp = ArpEth4Payload::from(
                &ArpEth4PayloadRaw::parse(&mut rdr).unwrap(),
            );

            assert_eq!(arp.sha, cfg.dyn_nat.public_mac);
            assert_eq!(arp.spa, cfg.dyn_nat.public_ip);
            assert_eq!(arp.tha, cfg.gw_mac);
            assert_eq!(arp.tpa, cfg.gw_ip);
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
    let cfg = home_cfg();
    let mut port = Port::new("int_test".to_string(), cfg.private_mac);
    oxide_net_setup(&mut port, &cfg);
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
    let mut cfg = home_cfg();
    // We have to specify exactly one port to match up with the actual
    // port from the pcap.
    cfg.dyn_nat.ports.start = 3839;
    cfg.dyn_nat.ports.end = 3840;
    let mut port = Port::new("int_test".to_string(), cfg.private_mac);
    oxide_net_setup(&mut port, &cfg);
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

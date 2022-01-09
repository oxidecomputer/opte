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
    self, EtherAddr, EtherHdr, EtherHdrRaw, EtherMeta, ETHER_HDR_SZ,
    ETHER_TYPE_ARP, ETHER_TYPE_IPV4
};
use crate::flow_table::FLOW_DEF_EXPIRE_SECS;
use crate::geneve::Vni;
use crate::headers::{IpMeta, UlpMeta};
use crate::ip4::{self, Ipv4Hdr, Ipv4HdrRaw, Ipv4Meta, Protocol};
use crate::ip6::Ipv6Addr;
use crate::oxide_net;
use crate::packet::{
    mock_allocb, Initialized, Packet, PacketRead, PacketReader, PacketSeg,
    PacketWriter, ParseError, WritePos,
};
use crate::port::{Inactive, Port, ProcessResult};
use crate::udp::{UdpHdr, UdpHdrRaw, UdpMeta};
use crate::Direction::*;

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
        overlay: None,
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
        overlay: None,
    }
}

fn oxide_net_setup(port: &mut Port<Inactive>, cfg: &oxide_net::PortConfig) {
    // ================================================================
    // Firewall layer
    // ================================================================
    oxide_net::firewall::setup(port).expect("failed to add firewall layer");

    // ================================================================
    // Dynamic NAT Layer (IPv4)
    // ================================================================
    oxide_net::dyn_nat4::setup(port, cfg)
        .expect("failed to add dyn-nat4 layer");

    // ================================================================
    // ARP layer
    // ================================================================
    oxide_net::arp::setup(port, cfg).expect("failed to add ARP layer");
}

// Verify that basic encap/decap works.
//
// XXX This test is a bit of a hack in that it repurposes the
// http-out-guest.pcap to act as a base for a mock encap/decap
// scenario. This test takes the first (outgoing) packet, and makes
// sure it is encapsulated. It then takes the second (ingoing) packet,
// prepends an outer header, and then verifies the packet is
// decapsulated. IMO this test would be better if it just generated
// mock packets from scratch, wether we do that by writing some macros
// around the various header types or just using some exsiting crate.
// We're also going to want to this ability to test all sorts of
// invalid and malformed packets.
//
// TODO This test sucks. Replace it with a test that generates the
// packet data in the test itself and split it into two different
// tests: one for BS, and one for guest-to-guest.
#[test]
fn encap_decap() {
    use std::sync::Arc;
    use crate::ether::ETHER_TYPE_IPV6;
    use crate::geneve::{GeneveHdr, GeneveMeta, GENEVE_PORT};
    use crate::headers::IpAddr;
    use crate::ip6::{Ipv6Hdr, Ipv6Meta};
    use crate::tcp::TcpFlags;
    use crate::udp::UdpHdr;
    use crate::oxide_net::overlay::{PhysNet, Virt2Phys};

    let mut cfg = home_cfg();
    // We have to specify exactly one port to match up with the actual
    // port from the pcap.
    cfg.dyn_nat.ports.start = 3839;
    cfg.dyn_nat.ports.end = 3840;
    let mut port = Port::new("encap_decap".to_string(), cfg.private_mac);
    oxide_net_setup(&mut port, &cfg);

    let inner_eth_dst = EtherAddr::from([0x78, 0x23, 0xAE, 0x5D, 0x4F, 0x0D]);
    let inner_ip_dst = "52.10.128.69".parse().unwrap();

    let phys_ip6_src = Ipv6Addr::from([0; 16]);
    let v2p = Arc::new(Virt2Phys::new());
    cfg.overlay = Some(oxide_net::OverlayConfig {
        boundary_services: PhysNet {
            ether: EtherAddr::from([0xA8, 0x40, 0x25, 0x77, 0x77, 0x77]),
            ip: Ipv6Addr::from([
                0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x01, 0xFF,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x77, 0x77
            ]),
            vni: Vni::new(7777u32).unwrap(),
        },
        vni: Vni::new(99u32).unwrap(),
        phys_mac_src: EtherAddr::from([0x02, 0x33, 0x33, 0x33, 0x33, 0x33]),
        phys_mac_dst: EtherAddr::from([0x02, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),
        phys_ip_src: phys_ip6_src,
    });
    oxide_net::overlay::setup(&mut port, &cfg, v2p.clone())
        .expect("failed to add overlay layer");
    let port = port.activate();

    // Here we setup the virtual-to-physical mapping for the
    // destination: 52.10.128.69.
    let mut phys_ip6_bytes = [0u8; 16];
    phys_ip6_bytes[15] = 0xA1;
    let dst_eth = EtherAddr::from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    let dst_ip6 = Ipv6Addr::from(phys_ip6_bytes);
    let phys = PhysNet {
        ether: dst_eth,
        ip: dst_ip6,
        vni: Vni::new(99u32).unwrap(),
    };
    v2p.set(IpAddr::Ip4("52.10.128.69".parse().unwrap()), phys);

    // ================================================================
    // Borrowing the first packet from http-out-guest.pcap to test
    // encap.
    // ================================================================
    let gpath = "http-out-guest.pcap";
    let gbytes = fs::read(gpath).unwrap();
    let hpath = "http-out-host.pcap";
    let hbytes = fs::read(hpath).unwrap();

    // Assert the baseline before any packet processing occurs.
    assert_eq!(port.num_flows("dyn-nat4", In), 0);
    assert_eq!(port.num_flows("dyn-nat4", Out), 0);
    assert_eq!(port.num_flows("firewall", In), 0);
    assert_eq!(port.num_flows("firewall", Out), 0);

    // ================================================================
    // Packet 1 (SYN)
    // ================================================================
    let (gbytes, _) = get_header(&gbytes[..]);
    let (_gbytes, gblock) = next_block(gbytes);
    let mut pkt = Packet::copy(gblock.data).parse().unwrap();
    let res = port.process(Out, &mut pkt, 0);
    assert!(matches!(res, Ok(Modified)));
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    // The body should start in the second segment.
    //
    // Ether + IPv6 + UDP + Geneve + Ether + IPv4 + TCP
    let body_off = 14 + 40 + 8 + 8 + 14 + 20 + 40;
    assert_eq!(pkt.body_offset(), body_off);
    assert_eq!(pkt.body_seg(), 1);

    // By unwrapping and reparsing the packet we verify that the
    // underlying data in the mblk is correct.
    let newmp = pkt.unwrap();
    let new_pkt = unsafe { Packet::<Initialized>::wrap(newmp) };
    let new_pkt_parsed = new_pkt.parse().unwrap();
    let meta = new_pkt_parsed.meta();

    assert_eq!(new_pkt_parsed.body_offset(), body_off);
    assert_eq!(new_pkt_parsed.body_seg(), 1);

    match meta.outer.ether.as_ref() {
        Some(eth) => {
	    assert_eq!(eth.src, cfg.overlay.as_ref().unwrap().phys_mac_src);
            assert_eq!(eth.dst, cfg.overlay.as_ref().unwrap().phys_mac_dst);
        },

        None => panic!("no outer ether header"),
    }

    match meta.outer.ip.as_ref().unwrap() {
        IpMeta::Ip6(ip6) => {
	    assert_eq!(ip6.src, phys_ip6_src);
            assert_eq!(ip6.dst, dst_ip6);
        }

        val => panic!("expected outer IPv6, got: {:?}", val),
    }

    match meta.outer.ulp.as_ref().unwrap() {
	UlpMeta::Udp(udp) => {
	    assert_eq!(udp.src, 7777);
	    assert_eq!(udp.dst, GENEVE_PORT);
	}

	ulp => panic!("expected outer UDP metadata, got: {:?}", ulp),
    }

    match meta.outer.encap.as_ref() {
	Some(geneve) => {
	    assert_eq!(geneve.vni, Vni::new(99u32).unwrap());
	}

	None => panic!("expected outer Geneve metadata"),
    }

    match meta.inner.ether.as_ref() {
	Some(eth) => {
	    assert_eq!(eth.src, cfg.dyn_nat.public_mac);
	    assert_eq!(eth.dst, dst_eth);
	    assert_eq!(eth.ether_type, ETHER_TYPE_IPV4);
	}

	None => panic!("expected inner Ether header"),
    }

    match meta.inner.ip.as_ref().unwrap() {
	IpMeta::Ip4(ip4) => {
	    assert_eq!(ip4.src, cfg.dyn_nat.public_ip);
	    assert_eq!(ip4.dst, inner_ip_dst);
	    assert_eq!(ip4.proto, Protocol::TCP);
	}

	ip6 => panic!("execpted inner IPv4 metadata, got IPv6: {:?}", ip6),
    }

    match meta.inner.ulp.as_ref().unwrap() {
        UlpMeta::Tcp(tcp) => {
            assert_eq!(tcp.src, 3839);
            assert_eq!(tcp.dst, 80);
        },

        ulp => panic!("expected inner TCP metadata, got: {:?}", ulp),
    }

    drop(meta);
    drop(new_pkt_parsed);

    // ================================================================
    // Packet 2 (SYN+ACK)
    // ================================================================

    // First, skip over outgoing Packet 1.
    let (hbytes, _hdr) = get_header(&hbytes[..]);
    let (hbytes, _hblock) = next_block(&hbytes);

    let mut incoming_bytes = Vec::new();

    // Mock out the encap.
    let phys_ether = EtherHdrRaw::from(&EtherMeta {
	dst: cfg.overlay.as_ref().unwrap().phys_mac_src,
	src: cfg.overlay.as_ref().unwrap().phys_mac_dst,
	ether_type: ETHER_TYPE_IPV6,
    });
    incoming_bytes.extend_from_slice(phys_ether.as_bytes());

    let mut phys_ip6 = Ipv6Hdr::from(&Ipv6Meta {
	src: dst_ip6,
	dst: cfg.overlay.as_ref().unwrap().phys_ip_src,
	proto: Protocol::UDP,
    });
    // IPv6 header + UDP + Geneve + original packet
    phys_ip6.set_total_len((phys_ip6.hdr_len() + 8 + 8 + 74) as u16);
    incoming_bytes.extend_from_slice(&phys_ip6.as_bytes());

    let mut phys_udp = UdpHdr::from(&UdpMeta {
	src: 9999,
	dst: GENEVE_PORT,
    });
    // Geneve + original packet
    phys_udp.set_pay_len(8 + 74);
    incoming_bytes.extend_from_slice(&phys_udp.as_bytes());

    let phys_geneve = GeneveHdr::from(&GeneveMeta {
	vni: cfg.overlay.as_ref().unwrap().vni,
    });
    incoming_bytes.extend_from_slice(&phys_geneve.as_bytes());

    let (_hbytes, hblock) = next_block(hbytes);
    incoming_bytes.extend_from_slice(hblock.data);

    let mut pkt = Packet::copy(&incoming_bytes).parse().unwrap();
    let res = port.process(In, &mut pkt, 0);
    assert!(matches!(res, Ok(Modified)));

    // The body should start in the second segment, but there should
    // be no encap headers.
    //
    // Ether + IPv4 + TCP w/ options
    let body_off = 14 + 20 + 40;
    assert_eq!(pkt.meta().outer.ether, None);
    assert_eq!(pkt.meta().outer.arp, None);
    assert_eq!(pkt.meta().outer.ip, None);
    assert_eq!(pkt.meta().outer.ulp, None);
    assert_eq!(pkt.meta().outer.encap, None);
    assert!(pkt.hdr_offsets().outer.is_none());

    match pkt.meta().inner.ether.as_ref() {
	Some(eth) => {
	    assert_eq!(eth.dst, cfg.private_mac);
	    assert_eq!(eth.src, inner_eth_dst);
	    assert_eq!(eth.ether_type, ETHER_TYPE_IPV4);
	}

	None => panic!("expected inner Ether header"),
    }

    match pkt.meta().inner.ip.as_ref().unwrap() {
	IpMeta::Ip4(ip4) => {
	    assert_eq!(ip4.dst, cfg.private_ip);
	    assert_eq!(ip4.src, inner_ip_dst);
	    assert_eq!(ip4.proto, Protocol::TCP);
	}

	ip6 => panic!("execpted inner IPv4 metadata, got IPv6: {:?}", ip6),
    }

    match pkt.meta().inner.ulp.as_ref().unwrap() {
        UlpMeta::Tcp(tcp) => {
            assert_eq!(tcp.dst, 35986);
            assert_eq!(tcp.src, 80);
	    assert!((tcp.flags & TcpFlags::SYN) != 0);
	    assert!((tcp.flags & TcpFlags::ACK) != 0);
        },

        ulp => panic!("expected inner TCP metadata, got: {:?}", ulp),
    }

    // There body is zero bytes as this is a SYN/ACK packet, but there
    // is still a body start position to verify.
    assert_eq!(pkt.body_offset(), body_off);
    assert_eq!(pkt.body_seg(), 1);
}

#[test]
fn bad_ip_len() {
    let cfg = lab_cfg();
    let mut setup_port = Port::new("bad_ip_len".to_string(), cfg.private_mac);
    oxide_net_setup(&mut setup_port, &cfg);
    let _port = setup_port.activate();

    let pkt = Packet::alloc(42);

    let ether = EtherHdr::from(&EtherMeta {
        src: cfg.private_mac,
        dst: ether::ETHER_BROADCAST,
        ether_type: ETHER_TYPE_IPV4,
    });

    let mut ip = Ipv4Hdr::from(&Ipv4Meta {
        src: "0.0.0.0".parse().unwrap(),
        dst: ip4::LOCAL_BROADCAST,
        proto: Protocol::UDP,
    });

    // We write a total legnth of 4 bytes, which is completely bogus
    // for an IP header and should return an error during processing.
    ip.set_total_len(4);

    let udp = UdpHdr::from(&UdpMeta { src: 68, dst: 67 });

    let mut wtr = PacketWriter::new(pkt, None);
    let _ = wtr.write(&ether.as_bytes()).unwrap();
    let _ = wtr.write(&ip.as_bytes()).unwrap();
    let _ = wtr.write(&udp.as_bytes()).unwrap();
    let res = wtr.finish().parse();
    assert_eq!(
        res.err().unwrap(),
        ParseError::BadHeader("IPv4: BadTotalLen { total_len: 4 }".to_string())
    );

    let pkt = Packet::alloc(42);

    let ether = EtherHdr::from(&EtherMeta {
        src: cfg.private_mac,
        dst: ether::ETHER_BROADCAST,
        ether_type: ETHER_TYPE_IPV4,
    });

    let mut ip = Ipv4Hdr::from(&Ipv4Meta {
        src: "0.0.0.0".parse().unwrap(),
        dst: ip4::LOCAL_BROADCAST,
        proto: Protocol::UDP,
    });

    // We write an incorrect total legnth of 40 bytes, but the real
    // total length should only be 28 bytes.
    ip.set_total_len(40);

    let udp = UdpHdr::from(&UdpMeta { src: 68, dst: 67 });

    let mut wtr = PacketWriter::new(pkt, None);
    let _ = wtr.write(&ether.as_bytes()).unwrap();
    let _ = wtr.write(&ip.as_bytes()).unwrap();
    let _ = wtr.write(&udp.as_bytes()).unwrap();
    let res = wtr.finish().parse();
    assert_eq!(
        res.err().unwrap(),
        ParseError::BadInnerIpLen { expected: 8, actual: 20 }
    );
}

// This test was added to verify that the DHCP request in the Oxide
// lab would not be re-written by the SNAT layer.
//
// XXX: At some point this test should go away as it tests an issue
// that only applies to the Oxide lab network demos when using the
// native IPv4 network as the "overlay" (with no underlay) and letting
// the lab gateway perform DHCP. Moving forward, both of these go
// away: 1) the Oxide Network uses an IPv6 underlay and 2) DHCP for
// the guest is mocked-out by OPTE itself.
#[test]
fn dhcp_req() {
    let cfg = lab_cfg();
    let mut port = Port::new("dhcp_req".to_string(), cfg.private_mac);
    oxide_net_setup(&mut port, &cfg);
    let port = port.activate();
    let pkt = Packet::alloc(42);

    let ether = EtherHdr::from(&EtherMeta {
        src: cfg.private_mac,
        dst: ether::ETHER_BROADCAST,
        ether_type: ETHER_TYPE_IPV4,
    });

    let ip = Ipv4Hdr::from(&Ipv4Meta {
        src: "0.0.0.0".parse().unwrap(),
        dst: ip4::LOCAL_BROADCAST,
        proto: Protocol::UDP,
    });

    let udp = UdpHdr::from(&UdpMeta { src: 68, dst: 67 });

    let mut wtr = PacketWriter::new(pkt, None);
    let _ = wtr.write(EtherHdrRaw::from(&ether).as_bytes()).unwrap();
    let mut ipraw = Ipv4HdrRaw::from(&ip);
    ipraw.total_len = 28u16.to_be_bytes();
    let _ = wtr.write(ipraw.as_bytes()).unwrap();
    let _ = wtr.write(UdpHdrRaw::from(&udp).as_bytes()).unwrap();
    let mut pkt = wtr.finish().parse().unwrap();

    let res = port.process(Out, &mut pkt, 0);

    match res {
        Ok(Modified) => {
	    let meta = pkt.meta();
            // XXX Modified is what processing returns since it
            // technically did pass through the firewall action (which
            // is just Identity). It would be nice if we only returned
            // Modified when the metadata actually changes.
            let ethm = meta.inner.ether.as_ref().unwrap();
            assert_eq!(ethm.src, cfg.private_mac);
            assert_eq!(ethm.dst, ether::ETHER_BROADCAST);

            let ip4m = match meta.inner.ip.as_ref().unwrap() {
                IpMeta::Ip4(v) => v,
                _ => panic!("expect Ipv4Meta"),
            };

            assert_eq!(ip4m.src, "0.0.0.0".parse().unwrap());
            assert_eq!(ip4m.dst, ip4::LOCAL_BROADCAST);
            assert_eq!(ip4m.proto, Protocol::UDP);
        }

        res => panic!("expected Modified result, got {:?}", res),
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
    let port = port.activate();
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
    assert!(matches!(res, Ok(Drop)));

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
        Ok(Hairpin(hppkt)) => {
            let hppkt = hppkt.parse().unwrap();
            let meta = hppkt.meta();
            let ethm = meta.inner.ether.as_ref().unwrap();
            let arpm = meta.inner.arp.as_ref().unwrap();
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
        Ok(Hairpin(hppkt)) => {
            let hppkt = hppkt.parse().unwrap();
            let meta = hppkt.meta();
            let ethm = meta.inner.ether.as_ref().unwrap();
            let arpm = meta.inner.arp.as_ref().unwrap();
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
        Ok(Hairpin(hppkt)) => {
            let hppkt = hppkt.parse().unwrap();
            let meta = hppkt.meta();
            let ethm = meta.inner.ether.as_ref().unwrap();
            let arpm = meta.inner.arp.as_ref().unwrap();
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
/// or hits the UFT. Two ideas here:
///
/// 1. The `ProcessResult` could include a receipt of how the packet
/// was processed. If this is only useful for testing I'm not sure
/// it's worth it. However, if it could also be useful for production
/// debugging, then it's definitely worth doing; sleep on it.
///
/// 2. Add stats for rule hits, layer hits, Layer Flow Table hits,
/// Unified Flow Table hits, etc. These stats can be used by tests for
/// verifying a given packet was processed in a certain way. They are
/// also useful for production as a way to track if packets are being
/// handled in the way we expect: e.g. that most packets hit the UFT.
#[test]
fn outgoing_dns_lookup() {
    let cfg = home_cfg();
    let mut port = Port::new("int_test".to_string(), cfg.private_mac);
    oxide_net_setup(&mut port, &cfg);
    let port = port.activate();
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
    assert!(matches!(res, Ok(Modified)));
    assert_eq!(port.num_flows("dyn-nat4", In), 0);
    assert_eq!(port.num_flows("dyn-nat4", Out), 0);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let (hbytes, _hdr) = get_header(&hbytes[..]);
    let (hbytes, hblock) = next_block(&hbytes);
    let pcap_pkt = Packet::copy(hblock.data).parse().unwrap();
    assert_hg!(pkt.headers().inner, pcap_pkt.headers().inner);
    assert_eq!(pkt.all_bytes(), hblock.data);

    // ================================================================
    // Packet 2 (DNS query response)
    // ================================================================
    let (_hbytes, hblock) = next_block(&hbytes);
    let mut pkt = Packet::copy(hblock.data).parse().unwrap();
    let res = port.process(In, &mut pkt, 0);
    assert!(matches!(res, Ok(Modified)));
    assert_eq!(port.num_flows("dyn-nat4", In), 0);
    assert_eq!(port.num_flows("dyn-nat4", Out), 0);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let (_gbytes, gblock) = next_block(&gbytes);
    let pcap_pkt = Packet::copy(gblock.data).parse().unwrap();
    assert_hg!(pkt.headers().inner, pcap_pkt.headers().inner);
    assert_eq!(pkt.all_bytes(), gblock.data);

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
    let port = port.activate();
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
    assert!(matches!(res, Ok(Modified)));
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let (hbytes, _) = get_header(&hbytes[..]);
    let (hbytes, hblock) = next_block(hbytes);
    let pcap_pkt = Packet::copy(hblock.data).parse().unwrap();
    assert_hg!(pkt.headers().inner, pcap_pkt.headers().inner);
    assert_eq!(pkt.all_bytes(), hblock.data);
    drop(pkt);

    // ================================================================
    // Packet 2 (SYN+ACK)
    // ================================================================
    let (hbytes, hblock) = next_block(hbytes);
    let mut pkt = Packet::copy(hblock.data).parse().unwrap();
    let res = port.process(In, &mut pkt, 0);
    assert!(matches!(res, Ok(Modified)));
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let (gbytes, gblock) = next_block(gbytes);
    let pcap_pkt = Packet::copy(gblock.data).parse().unwrap();
    assert_hg!(pkt.headers().inner, pcap_pkt.headers().inner);
    assert_eq!(pkt.all_bytes(), gblock.data);
    drop(pkt);

    // ================================================================
    // Packet 3 (ACK)
    // ================================================================
    let (gbytes, gblock) = next_block(gbytes);
    let mut pkt = Packet::copy(gblock.data).parse().unwrap();
    let res = port.process(Out, &mut pkt, 0);
    assert!(matches!(res, Ok(Modified)));
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let (hbytes, hblock) = next_block(hbytes);
    let pcap_pkt = Packet::copy(hblock.data).parse().unwrap();
    assert_hg!(pkt.headers().inner, pcap_pkt.headers().inner);
    assert_eq!(pkt.all_bytes(), hblock.data);
    drop(pkt);

    // ================================================================
    // Packet 4 (HTTP GET)
    // ================================================================
    let (gbytes, gblock) = next_block(gbytes);
    let mut pkt = Packet::copy(gblock.data).parse().unwrap();
    let res = port.process(Out, &mut pkt, 0);
    assert!(matches!(res, Ok(Modified)));
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let (hbytes, hblock) = next_block(hbytes);
    let pcap_pkt = Packet::copy(hblock.data).parse().unwrap();
    assert_hg!(pkt.headers().inner, pcap_pkt.headers().inner);
    assert_eq!(pkt.all_bytes(), hblock.data);
    drop(pkt);

    // ================================================================
    // Packet 5 (ACK #4)
    // ================================================================
    let (hbytes, hblock) = next_block(hbytes);
    let mut pkt = Packet::copy(hblock.data).parse().unwrap();
    let res = port.process(In, &mut pkt, 0);
    assert!(matches!(res, Ok(Modified)));
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let (gbytes, gblock) = next_block(gbytes);
    let pcap_pkt = Packet::copy(gblock.data).parse().unwrap();
    assert_hg!(pkt.headers().inner, pcap_pkt.headers().inner);
    assert_eq!(pkt.all_bytes(), gblock.data);
    drop(pkt);

    // ================================================================
    // Packet 6 (HTTP 301)
    // ================================================================
    let (hbytes, hblock) = next_block(hbytes);
    let mut pkt = Packet::copy(hblock.data).parse().unwrap();
    let res = port.process(In, &mut pkt, 0);
    assert!(matches!(res, Ok(Modified)));
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let (gbytes, gblock) = next_block(gbytes);
    let pcap_pkt = Packet::copy(gblock.data).parse().unwrap();
    assert_hg!(pkt.headers().inner, pcap_pkt.headers().inner);
    assert_eq!(pkt.all_bytes(), gblock.data);
    drop(pkt);

    // ================================================================
    // Packet 7 (ACK #6)
    // ================================================================
    let (gbytes, gblock) = next_block(gbytes);
    let mut pkt = Packet::copy(gblock.data).parse().unwrap();
    let res = port.process(Out, &mut pkt, 0);
    assert!(matches!(res, Ok(Modified)));
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let (hbytes, hblock) = next_block(hbytes);
    let pcap_pkt = Packet::copy(hblock.data).parse().unwrap();
    assert_hg!(pkt.headers().inner, pcap_pkt.headers().inner);
    assert_eq!(pkt.all_bytes(), hblock.data);
    drop(pkt);

    // ================================================================
    // Packet 8 (Guest FIN ACK)
    // ================================================================
    let (gbytes, gblock) = next_block(gbytes);
    let mut pkt = Packet::copy(gblock.data).parse().unwrap();
    let res = port.process(Out, &mut pkt, 0);
    assert!(matches!(res, Ok(Modified)));
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let (hbytes, hblock) = next_block(hbytes);
    let pcap_pkt = Packet::copy(hblock.data).parse().unwrap();
    assert_hg!(pkt.headers().inner, pcap_pkt.headers().inner);
    assert_eq!(pkt.all_bytes(), hblock.data);
    drop(pkt);

    // ================================================================
    // Packet 9 (ACK #8)
    // ================================================================
    let (hbytes, hblock) = next_block(hbytes);
    let mut pkt = Packet::copy(hblock.data).parse().unwrap();
    let res = port.process(In, &mut pkt, 0);
    assert!(matches!(res, Ok(Modified)));
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let (gbytes, gblock) = next_block(gbytes);
    let pcap_pkt = Packet::copy(gblock.data).parse().unwrap();
    assert_hg!(pkt.headers().inner, pcap_pkt.headers().inner);
    assert_eq!(pkt.all_bytes(), gblock.data);
    drop(pkt);

    // ================================================================
    // Packet 10 (Remote FIN ACK)
    // ================================================================
    let (hbytes, hblock) = next_block(hbytes);
    let mut pkt = Packet::copy(hblock.data).parse().unwrap();
    let res = port.process(In, &mut pkt, 0);
    assert!(matches!(res, Ok(Modified)));
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let (gbytes, gblock) = next_block(gbytes);
    let pcap_pkt = Packet::copy(gblock.data).parse().unwrap();
    assert_hg!(pkt.headers().inner, pcap_pkt.headers().inner);
    assert_eq!(pkt.all_bytes(), gblock.data);
    drop(pkt);

    // ================================================================
    // Packet 11 (ACK #10)
    // ================================================================
    let (_gbytes, gblock) = next_block(gbytes);
    let mut pkt = Packet::copy(gblock.data).parse().unwrap();
    let res = port.process(Out, &mut pkt, 0);
    assert!(matches!(res, Ok(Modified)));
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    let (_hbytes, hblock) = next_block(hbytes);
    let pcap_pkt = Packet::copy(hblock.data).parse().unwrap();
    assert_hg!(pkt.headers().inner, pcap_pkt.headers().inner);
    assert_eq!(pkt.all_bytes(), hblock.data);
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

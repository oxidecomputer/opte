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
use std::boxed::Box;
use std::fs;
use std::ops::Range;
use std::prelude::v1::*;
use std::sync::Arc;
use std::time::{Duration, Instant};

extern crate pcap_parser;
use pcap_parser::pcap::{self, LegacyPcapBlock, PcapHeader};

use zerocopy::AsBytes;

use crate::arp::{ArpEth4Payload, ArpEth4PayloadRaw, ArpHdrRaw, ARP_HDR_SZ};
use crate::ether::{
    self, EtherAddr, EtherHdr, EtherHdrRaw, EtherMeta, EtherType, ETHER_HDR_SZ,
    ETHER_TYPE_ARP, ETHER_TYPE_IPV4,
};
use crate::flow_table::FLOW_DEF_EXPIRE_SECS;
use crate::geneve::Vni;
use crate::headers::{IpMeta, UlpMeta};
use crate::ip4::{self, Ipv4Hdr, Ipv4HdrRaw, Ipv4Meta, Protocol};
use crate::ip6::Ipv6Addr;
use crate::oxide_net::{self, arp, dyn_nat4, firewall, overlay, router};
use crate::packet::{
    mock_allocb, Initialized, Packet, PacketRead, PacketReader, PacketSeg,
    PacketWriter, ParseError, WritePos,
};
use crate::port::{DropReason, Inactive, Port, ProcessResult};
use crate::tcp::TcpHdr;
use crate::udp::{UdpHdr, UdpHdrRaw, UdpMeta};
use crate::{Direction::*, ExecCtx};

use ProcessResult::*;

// I'm not sure if we've defined the MAC address OPTE uses to
// masqurade as the guests gateway.
pub const GW_MAC_ADDR: [u8; 6] = [0xA8, 0x40, 0x25, 0xFF, 0xFF, 0xFF];

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

fn home_cfg() -> oxide_net::PortCfg {
    oxide_net::PortCfg {
        private_ip: "10.0.0.210".parse().unwrap(),
        private_mac: EtherAddr::from([0x02, 0x08, 0x20, 0xd8, 0x35, 0xcf]),
        vpc_subnet: "10.0.0.0/24".parse().unwrap(),
        dyn_nat: oxide_net::DynNat4Cfg {
            public_mac: EtherAddr::from([0xA8, 0x40, 0x25, 0x00, 0x00, 0x63]),
            public_ip: "10.0.0.99".parse().unwrap(),
            ports: Range { start: 1025, end: 4096 },
        },
        gw_mac: EtherAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d]),
        gw_ip: "10.0.0.1".parse().unwrap(),
        overlay: None,
    }
}

fn lab_cfg() -> oxide_net::PortCfg {
    oxide_net::PortCfg {
        private_ip: "172.20.14.16".parse().unwrap(),
        private_mac: EtherAddr::from([0xAA, 0x00, 0x04, 0x00, 0xFF, 0x10]),
        vpc_subnet: "172.20.14.0/24".parse().unwrap(),
        dyn_nat: oxide_net::DynNat4Cfg {
            public_mac: EtherAddr::from([0xA8, 0x40, 0x25, 0x00, 0x01, 0xEE]),
            public_ip: "76.76.21.21".parse().unwrap(),
            ports: Range { start: 1025, end: 4096 },
        },
        gw_mac: EtherAddr::from([0xAA, 0x00, 0x04, 0x00, 0xFF, 0x01]),
        gw_ip: "172.20.14.1".parse().unwrap(),
        overlay: None,
    }
}

fn oxide_net_setup(name: &str, cfg: &oxide_net::PortCfg) -> Port<Inactive> {
    let ectx = Arc::new(ExecCtx {
        log: Box::new(crate::PrintlnLog {})
    });
    let mut port = Port::new(name, cfg.private_mac, ectx.clone());

    // ================================================================
    // Firewall layer
    // ================================================================
    firewall::setup(&mut port).expect("failed to add firewall layer");

    // ================================================================
    // Dynamic NAT Layer (IPv4)
    // ================================================================
    dyn_nat4::setup(&mut port, cfg).expect("failed to add dyn-nat4 layer");

    // ================================================================
    // ARP layer
    // ================================================================
    arp::setup(&mut port, cfg).expect("failed to add ARP layer");

    port
}

fn g1_cfg() -> oxide_net::PortCfg {
    oxide_net::PortCfg {
        private_ip: "192.168.77.101".parse().unwrap(),
        private_mac: EtherAddr::from([0xA8, 0x40, 0x25, 0xF7, 0x00, 0x65]),
        vpc_subnet: "192.168.77.0/24".parse().unwrap(),
        dyn_nat: oxide_net::DynNat4Cfg {
            // NOTE: This member is used for home routers that might
            // balk at multiple IPs sharing a MAC address. As these
            // tests are meant to mimic the Oxide Rack Network we just
            // keep this the same.
            public_mac: EtherAddr::from([0xA8, 0x40, 0x25, 0xF7, 0x00, 0x65]),
            // NOTE: This is not a routable IP, but remember that a
            // "public IP" for an Oxide guest could either be a
            // public, routable IP or simply an IP on their wider LAN
            // which the oxide Rack is simply a part of.
            public_ip: "10.77.77.13".parse().unwrap(),
            ports: Range { start: 1025, end: 4096 },
        },
        gw_mac: EtherAddr::from([0xA8, 0x40, 0x25, 0xF7, 0x00, 0x1]),
        gw_ip: "192.168.77.1".parse().unwrap(),
        // We set the overlay in the test because some tests use it
        // and some don't.
        overlay: None,
    }
}

fn g2_cfg() -> oxide_net::PortCfg {
    oxide_net::PortCfg {
        private_ip: "192.168.77.102".parse().unwrap(),
        private_mac: EtherAddr::from([0xA8, 0x40, 0x25, 0xF7, 0x00, 0x66]),
        vpc_subnet: "192.168.77.0/24".parse().unwrap(),
        dyn_nat: oxide_net::DynNat4Cfg {
            // NOTE: This member is used for home routers that might
            // balk at multiple IPs sharing a MAC address. As these
            // tests are meant to mimic the Oxide Rack Network we just
            // keep this the same.
            public_mac: EtherAddr::from([0xA8, 0x40, 0x25, 0xF7, 0x00, 0x66]),
            // NOTE: This is not a routable IP, but remember that a
            // "public IP" for an Oxide guest could either be a
            // public, routable IP or simply an IP on their wider LAN
            // which the oxide Rack is simply a part of.
            public_ip: "10.77.77.23".parse().unwrap(),
            ports: Range { start: 4097, end: 8192 },
        },
        gw_mac: EtherAddr::from([0xA8, 0x40, 0x25, 0xF7, 0x00, 0x1]),
        gw_ip: "192.168.77.1".parse().unwrap(),
        // We set the overlay in the test because some tests use it
        // and some don't.
        overlay: None,
    }
}

// Verify that two guests on the same VPC can communicate via overlay.
// I.e., test routing + encap/decap.
#[test]
fn overlay_guest_to_guest() {
    use crate::checksum::HeaderChecksum;
    use crate::geneve;
    use crate::headers::{IpAddr, IpCidr};
    use crate::ip4::UlpCsumOpt;
    use crate::oxide_net::overlay::{OverlayCfg, PhysNet, Virt2Phys};
    use crate::oxide_net::router::RouterTarget;
    use crate::tcp::TcpFlags;

    // ================================================================
    // Configure ports for g1 and g2.
    // ================================================================
    let mut g1_cfg = g1_cfg();
    let mut g2_cfg = g2_cfg();

    // NOTE: We're not testing Boundary Services in this test, so the
    // values are irrelevant here.
    let bs = PhysNet {
        ether: EtherAddr::from([0xA8, 0x40, 0x25, 0x77, 0x77, 0x77]),
        ip: Ipv6Addr::from([
            0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x01, 0xFF,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x77, 0x77
        ]),
        vni: Vni::new(7777u32).unwrap(),
    };

    g1_cfg.overlay = Some(OverlayCfg {
        boundary_services: bs.clone(),
        vni: Vni::new(99u32).unwrap(),
        phys_ip_src: Ipv6Addr::from([
            0xFD00, 0x0000, 0x00F7, 0x0101, 0x0000, 0x0000, 0x0000, 0x0001,
        ]),
    });

    g2_cfg.overlay = Some(OverlayCfg {
        boundary_services: bs.clone(),
        vni: Vni::new(99u32).unwrap(),
        // Site 0xF7, Rack 1, Sled 22, Interface 1
        phys_ip_src: Ipv6Addr::from([
            0xFD00, 0x0000, 0x00F7, 0x0116, 0x0000, 0x0000, 0x0000, 0x0001,
        ]),
    });
    let g2_phys = PhysNet {
        ether: g2_cfg.private_mac,
        ip: g2_cfg.overlay.as_ref().unwrap().phys_ip_src,
        vni: g2_cfg.overlay.as_ref().unwrap().vni,
    };

    // Add V2P mappings that allow guests to resolve each others
    // physical addresses.
    let v2p = Arc::new(Virt2Phys::new());
    v2p.set(IpAddr::Ip4(g2_cfg.private_ip), g2_phys);

    let mut g1_port = oxide_net_setup("g1_port", &g1_cfg);
    router::setup(&mut g1_port).unwrap();
    overlay::setup(&mut g1_port, g1_cfg.overlay.as_ref().unwrap(), v2p.clone());
    let g1_port = g1_port.activate();

    // Add router entry that allows Guest 1 to send to Guest 2.
    router::add_entry_active(
        &g1_port,
        IpCidr::Ip4(g2_cfg.vpc_subnet.cidr()),
        RouterTarget::VpcSubnet(IpCidr::Ip4(g2_cfg.vpc_subnet.cidr())),
    )
    .unwrap();

    let mut g2_port = oxide_net_setup("g2_port", &g2_cfg);
    router::setup(&mut g2_port).unwrap();
    overlay::setup(&mut g2_port, g2_cfg.overlay.as_ref().unwrap(), v2p.clone());
    let g2_port = g2_port.activate();

    // Add router entry that allows Guest 2 to send to Guest 1.
    //
    // XXX I just realized that it might make sense to move the router
    // tables up to a global level like the Virt2Phys mappings. This
    // way a new router entry that applies to many guests can placed
    // once instead of on each port individually.
    router::add_entry_active(
        &g2_port,
        IpCidr::Ip4(g1_cfg.vpc_subnet.cidr()),
        RouterTarget::VpcSubnet(IpCidr::Ip4(g1_cfg.vpc_subnet.cidr())),
    )
    .unwrap();

    // Allow incoming TCP connection from anyone.
    let rule = "dir=in action=allow priority=10 protocol=TCP";
    crate::ioctl::add_fw_rule(
        &g2_port,
        &firewall::FwAddRuleReq {
            port_name: g2_port.name().to_string(),
            rule: rule.parse().unwrap(),
        },
    )
    .unwrap();

    // ================================================================
    // Generate a telnet SYN packet from g1 to g2.
    // ================================================================
    let body = vec![];
    let mut tcp = TcpHdr::new(7865, 23);
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_seq(4224936861);
    let mut ip4 =
        Ipv4Hdr::new_tcp(&mut tcp, &body, g1_cfg.private_ip, g2_cfg.private_ip);
    ip4.compute_hdr_csum();
    let tcp_csum = ip4.compute_ulp_csum(UlpCsumOpt::Full, &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    let eth = EtherHdr::new(
        EtherType::Ipv4,
        g1_cfg.private_mac,
        // TODO This dest mac is wrong, it would be using the mac of
        // the gateway.
        g2_cfg.private_mac,
    );

    let mut bytes = vec![];
    bytes.extend_from_slice(&eth.as_bytes());
    bytes.extend_from_slice(&ip4.as_bytes());
    bytes.extend_from_slice(&tcp.as_bytes());
    bytes.extend_from_slice(&body);
    let mut g1_pkt = Packet::copy(&bytes).parse().unwrap();

    // ================================================================
    // Run the telnet SYN packet through g1's port in the outbound
    // direction and verify the resulting packet meets expectations.
    // ================================================================
    let res = g1_port.process(Out, &mut g1_pkt);
    assert!(matches!(res, Ok(Modified)));

    // Ether + IPv6 + UDP + Geneve + Ether + IPv4 + TCP
    assert_eq!(g1_pkt.body_offset(), 14 + 40 + 8 + 8 + 14 + 20 + 20);
    assert_eq!(g1_pkt.body_seg(), 1);

    let meta = g1_pkt.meta();
    match meta.outer.ether.as_ref() {
        Some(eth) => {
            assert_eq!(eth.src, Default::default());
            assert_eq!(eth.dst, Default::default());
        }

        None => panic!("no outer ether header"),
    }

    match meta.outer.ip.as_ref().unwrap() {
        IpMeta::Ip6(ip6) => {
            assert_eq!(ip6.src, g1_cfg.overlay.as_ref().unwrap().phys_ip_src);
            assert_eq!(ip6.dst, g2_cfg.overlay.as_ref().unwrap().phys_ip_src);
        }

        val => panic!("expected outer IPv6, got: {:?}", val),
    }

    match meta.outer.ulp.as_ref().unwrap() {
        UlpMeta::Udp(udp) => {
            assert_eq!(udp.src, 7777);
            assert_eq!(udp.dst, geneve::GENEVE_PORT);
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
            assert_eq!(eth.src, g1_cfg.private_mac);
            assert_eq!(eth.dst, g2_cfg.private_mac);
            assert_eq!(eth.ether_type, ETHER_TYPE_IPV4);
        }

        None => panic!("expected inner Ether header"),
    }

    match meta.inner.ip.as_ref().unwrap() {
        IpMeta::Ip4(ip4) => {
            assert_eq!(ip4.src, g1_cfg.private_ip);
            assert_eq!(ip4.dst, g2_cfg.private_ip);
            assert_eq!(ip4.proto, Protocol::TCP);
        }

        ip6 => panic!("execpted inner IPv4 metadata, got IPv6: {:?}", ip6),
    }

    match meta.inner.ulp.as_ref().unwrap() {
        UlpMeta::Tcp(tcp) => {
            assert_eq!(tcp.src, 7865);
            assert_eq!(tcp.dst, 23);
        }

        ulp => panic!("expected inner TCP metadata, got: {:?}", ulp),
    }

    // ================================================================
    // Now that the packet has been encap'd let's play the role of
    // router and send this inbound to g2's port. For maximum fidelity
    // of the real process we first dump the raw bytes of g1's
    // outgoing packet and then reparse it.
    // ================================================================
    let mblk = g1_pkt.unwrap();
    let mut g2_pkt =
        unsafe { Packet::<Initialized>::wrap(mblk).parse().unwrap() };

    let res = g2_port.process(In, &mut g2_pkt);
    assert!(matches!(res, Ok(Modified)));

    // Ether + IPv4 + TCP
    assert_eq!(g2_pkt.body_offset(), 14 + 20 + 20);
    assert_eq!(g2_pkt.body_seg(), 1);

    let g2_meta = g2_pkt.meta();
    assert!(g2_meta.outer.ether.is_none());
    assert!(g2_meta.outer.ip.is_none());
    assert!(g2_meta.outer.ulp.is_none());
    assert!(g2_meta.outer.encap.is_none());

    match g2_meta.inner.ether.as_ref() {
        Some(eth) => {
            assert_eq!(eth.src, g1_cfg.private_mac);
            assert_eq!(eth.dst, g2_cfg.private_mac);
            assert_eq!(eth.ether_type, ETHER_TYPE_IPV4);
        }

        None => panic!("expected inner Ether header"),
    }

    match g2_meta.inner.ip.as_ref().unwrap() {
        IpMeta::Ip4(ip4) => {
            assert_eq!(ip4.src, g1_cfg.private_ip);
            assert_eq!(ip4.dst, g2_cfg.private_ip);
            assert_eq!(ip4.proto, Protocol::TCP);
        }

        ip6 => panic!("execpted inner IPv4 metadata, got IPv6: {:?}", ip6),
    }

    match g2_meta.inner.ulp.as_ref().unwrap() {
        UlpMeta::Tcp(tcp) => {
            assert_eq!(tcp.src, 7865);
            assert_eq!(tcp.dst, 23);
        }

        ulp => panic!("expected inner TCP metadata, got: {:?}", ulp),
    }
}

// Verify that a guest can communicate with the internet.
#[test]
fn overlay_guest_to_internet() {
    use crate::checksum::HeaderChecksum;
    use crate::geneve;
    use crate::headers::{IpAddr, IpCidr};
    use crate::ip4::UlpCsumOpt;
    use crate::oxide_net::overlay::{OverlayCfg, PhysNet, Virt2Phys};
    use crate::oxide_net::router::RouterTarget;
    use crate::tcp::TcpFlags;

    // ================================================================
    // Configure ports for g1 and g2.
    // ================================================================
    let mut g1_cfg = g1_cfg();

    let bs = PhysNet {
        ether: EtherAddr::from([0xA8, 0x40, 0x25, 0x77, 0x77, 0x77]),
        ip: Ipv6Addr::from([
            0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x01, 0xFF, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x77, 0x77,
        ]),
        vni: Vni::new(7777u32).unwrap(),
    };

    g1_cfg.overlay = Some(OverlayCfg {
        boundary_services: bs.clone(),
        vni: Vni::new(99u32).unwrap(),
        // Site 0xF7, Rack 1, Sled 1, Interface 1
        phys_ip_src: Ipv6Addr::from([
            0xFD00, 0x0000, 0x00F7, 0x0101, 0x0000, 0x0000, 0x0000, 0x0001,
        ]),
    });

    let v2p = Arc::new(Virt2Phys::new());
    let mut g1_port = oxide_net_setup("g1_port", &g1_cfg);
    router::setup(&mut g1_port).unwrap();
    overlay::setup(&mut g1_port, g1_cfg.overlay.as_ref().unwrap(), v2p.clone());
    let g1_port = g1_port.activate();

    // Add router entry that allows Guest 1 to send to Guest 2.
    router::add_entry_active(
        &g1_port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway,
    )
    .unwrap();

    let dst_ip = "52.10.128.69".parse().unwrap();

    // ================================================================
    // Generate a TCP SYN packet from g1 to zinascii.com
    // ================================================================
    let body = vec![];
    let mut tcp = TcpHdr::new(54854, 443);
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_seq(1741469041);
    let mut ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, g1_cfg.private_ip, dst_ip);
    ip4.compute_hdr_csum();
    let tcp_csum = ip4.compute_ulp_csum(UlpCsumOpt::Full, &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    let eth = EtherHdr::new(
        EtherType::Ipv4,
        g1_cfg.private_mac,
        EtherAddr::from(GW_MAC_ADDR),
    );

    let mut bytes = vec![];
    bytes.extend_from_slice(&eth.as_bytes());
    bytes.extend_from_slice(&ip4.as_bytes());
    bytes.extend_from_slice(&tcp.as_bytes());
    bytes.extend_from_slice(&body);
    let mut g1_pkt = Packet::copy(&bytes).parse().unwrap();

    // ================================================================
    // Run the telnet SYN packet through g1's port in the outbound
    // direction and verify the resulting packet meets expectations.
    // ================================================================
    let res = g1_port.process(Out, &mut g1_pkt);
    assert!(matches!(res, Ok(Modified)), "bad result: {:?}", res);

    // Ether + IPv6 + UDP + Geneve + Ether + IPv4 + TCP
    assert_eq!(g1_pkt.body_offset(), 14 + 40 + 8 + 8 + 14 + 20 + 20);
    assert_eq!(g1_pkt.body_seg(), 1);

    let meta = g1_pkt.meta();
    match meta.outer.ether.as_ref() {
        Some(eth) => {
            assert_eq!(eth.src, Default::default());
            assert_eq!(eth.dst, Default::default());
        }

        None => panic!("no outer ether header"),
    }

    match meta.outer.ip.as_ref().unwrap() {
        IpMeta::Ip6(ip6) => {
            assert_eq!(ip6.src, g1_cfg.overlay.as_ref().unwrap().phys_ip_src);
            assert_eq!(ip6.dst, bs.ip);
        }

        val => panic!("expected outer IPv6, got: {:?}", val),
    }

    match meta.outer.ulp.as_ref().unwrap() {
        UlpMeta::Udp(udp) => {
            assert_eq!(udp.src, 7777);
            assert_eq!(udp.dst, geneve::GENEVE_PORT);
        }

        ulp => panic!("expected outer UDP metadata, got: {:?}", ulp),
    }

    match meta.outer.encap.as_ref() {
        Some(geneve) => {
            assert_eq!(geneve.vni, bs.vni);
        }

        None => panic!("expected outer Geneve metadata"),
    }

    match meta.inner.ether.as_ref() {
        Some(eth) => {
            assert_eq!(eth.src, g1_cfg.private_mac);
            assert_eq!(eth.dst, bs.ether);
            assert_eq!(eth.ether_type, ETHER_TYPE_IPV4);
        }

        None => panic!("expected inner Ether header"),
    }

    match meta.inner.ip.as_ref().unwrap() {
        IpMeta::Ip4(ip4) => {
            assert_eq!(ip4.src, g1_cfg.dyn_nat.public_ip);
            assert_eq!(ip4.dst, dst_ip);
            assert_eq!(ip4.proto, Protocol::TCP);
        }

        ip6 => panic!("execpted inner IPv4 metadata, got IPv6: {:?}", ip6),
    }

    match meta.inner.ulp.as_ref().unwrap() {
        UlpMeta::Tcp(tcp) => {
            assert_eq!(tcp.src, g1_cfg.dyn_nat.ports.rev().next().unwrap());
            assert_eq!(tcp.dst, 443);
        }

        ulp => panic!("expected inner TCP metadata, got: {:?}", ulp),
    }
}

#[test]
fn bad_ip_len() {
    let cfg = lab_cfg();
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
    let port = oxide_net_setup("dhcp_req", &cfg).activate();
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

    let res = port.process(Out, &mut pkt);

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
    let port = oxide_net_setup("arp_hairpin", &cfg).activate();
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

    let res = port.process(In, &mut pkt);
    assert!(res.is_ok(), "bad result: {:?}", res);
    let val = res.unwrap();
    assert!(matches!(val, ProcessResult::Drop { .. }), "bad val: {:?}", val);
    if let ProcessResult::Drop { reason: DropReason::Layer { name } } = val {
        assert_eq!(name, "arp")
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

    let res = port.process(Out, &mut pkt);
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

    let res = port.process(In, &mut pkt);
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

    let res = port.process(In, &mut pkt);
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
    let port = oxide_net_setup("outdoing_dns_lookup", &cfg).activate();
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
    let res = port.process(Out, &mut pkt);
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
    let res = port.process(In, &mut pkt);
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
    let port = oxide_net_setup("outgoing_http_req", &cfg).activate();
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
    let res = port.process(Out, &mut pkt);
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
    let res = port.process(In, &mut pkt);
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
    let res = port.process(Out, &mut pkt);
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
    let res = port.process(Out, &mut pkt);
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
    let res = port.process(In, &mut pkt);
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
    let res = port.process(In, &mut pkt);
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
    let res = port.process(Out, &mut pkt);
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
    let res = port.process(Out, &mut pkt);
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
    let res = port.process(In, &mut pkt);
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
    let res = port.process(In, &mut pkt);
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
    let res = port.process(Out, &mut pkt);
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

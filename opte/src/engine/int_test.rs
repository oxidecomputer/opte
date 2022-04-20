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
//!
//! TODO This module belongs in oxide_vpc as it's testing VPC-specific
//! configuration.
use std::boxed::Box;
use std::fs;
use std::ops::Range;
use std::prelude::v1::*;
use std::sync::Arc;
use std::time::Duration;

use pcap_parser::pcap::{self, LegacyPcapBlock, PcapHeader};

use smoltcp::phy::ChecksumCapabilities as CsumCapab;

use zerocopy::AsBytes;

use super::arp::{ArpEth4Payload, ArpEth4PayloadRaw, ArpHdrRaw, ARP_HDR_SZ};
use super::ether::{
    self, EtherAddr, EtherHdr, EtherHdrRaw, EtherMeta, EtherType, ETHER_HDR_SZ,
    ETHER_TYPE_ARP, ETHER_TYPE_IPV4,
};
use super::flow_table::FLOW_DEF_EXPIRE_SECS;
use super::geneve::{self, Vni};
use super::headers::{IpAddr, IpCidr, IpMeta, UlpMeta};
use super::ip4::{Ipv4Addr, Ipv4Hdr, Ipv4HdrRaw, Ipv4Meta, Protocol};
use super::ip6::Ipv6Addr;
use super::packet::{
    Initialized, Packet, PacketRead, PacketReader, PacketWriter, ParseError,
};
use super::port::{Inactive, Port, ProcessResult};
use super::port::meta::Meta;
use super::tcp::TcpHdr;
use super::time::Moment;
use super::udp::{UdpHdr, UdpHdrRaw, UdpMeta};
use crate::api::{Direction::*, MacAddr};
use crate::oxide_vpc::api::{
    AddFwRuleReq, GuestPhysAddr, PhysNet, RouterTarget
};
use crate::oxide_vpc::engine::overlay::{self, Virt2Phys};
use crate::oxide_vpc::engine::{arp, dyn_nat4, firewall, icmp, router};
use crate::oxide_vpc::{DynNat4Cfg, PortCfg};
use crate::ExecCtx;

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

fn home_cfg() -> PortCfg {
    PortCfg {
        private_ip: "10.0.0.210".parse().unwrap(),
        private_mac: EtherAddr::from([0x02, 0x08, 0x20, 0xd8, 0x35, 0xcf]),
        vpc_subnet: "10.0.0.0/24".parse().unwrap(),
        dyn_nat: DynNat4Cfg {
            public_ip: "10.0.0.99".parse().unwrap(),
            ports: Range { start: 1025, end: 4096 },
        },
        gw_mac: EtherAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d]),
        gw_ip: "10.0.0.1".parse().unwrap(),

        // XXX These values don't really mean anything in this
        // context. This "home cfg" was created during the early days
        // of OPTE dev when the VPC implementation was just part of an
        // existing IPv4 network. Any tests relying on this cfg need
        // to be rewritten or deleted.
        vni: Vni::new(99u32).unwrap(),
        // Site 0xF7, Rack 1, Sled 1, Interface 1
        phys_ip: Ipv6Addr::from([
            0xFD00, 0x0000, 0x00F7, 0x0101, 0x0000, 0x0000, 0x0000, 0x0001,
        ]),
        bsvc_addr: PhysNet {
            ether: MacAddr::from([0xA8, 0x40, 0x25, 0x77, 0x77, 0x77]),
            ip: Ipv6Addr::from([
                0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x01, 0xFF, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x77, 0x77,
            ]),
            vni: Vni::new(7777u32).unwrap(),
        },
    }
}

fn lab_cfg() -> PortCfg {
    PortCfg {
        private_ip: "172.20.14.16".parse().unwrap(),
        private_mac: EtherAddr::from([0xAA, 0x00, 0x04, 0x00, 0xFF, 0x10]),
        vpc_subnet: "172.20.14.0/24".parse().unwrap(),
        dyn_nat: DynNat4Cfg {
            public_ip: "76.76.21.21".parse().unwrap(),
            ports: Range { start: 1025, end: 4096 },
        },
        gw_mac: EtherAddr::from([0xAA, 0x00, 0x04, 0x00, 0xFF, 0x01]),
        gw_ip: "172.20.14.1".parse().unwrap(),

        // XXX These values don't really mean anything in this
        // context. This "lab cfg" was created during the early days
        // of OPTE dev when the VPC implementation was just part of an
        // existing IPv4 network. Any tests relying on this cfg need
        // to be rewritten or deleted.
        vni: Vni::new(99u32).unwrap(),
        // Site 0xF7, Rack 1, Sled 1, Interface 1
        phys_ip: Ipv6Addr::from([
            0xFD00, 0x0000, 0x00F7, 0x0101, 0x0000, 0x0000, 0x0000, 0x0001,
        ]),
        bsvc_addr: PhysNet {
            ether: MacAddr::from([0xA8, 0x40, 0x25, 0x77, 0x77, 0x77]),
            ip: Ipv6Addr::from([
                0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x01, 0xFF, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x77, 0x77,
            ]),
            vni: Vni::new(7777u32).unwrap(),
        },
    }
}

fn oxide_net_setup(name: &str, cfg: &PortCfg) -> Port<Inactive> {
    let ectx = Arc::new(ExecCtx { log: Box::new(crate::PrintlnLog {}) });
    let name_cstr = crate::CString::new(name).unwrap();
    let mut port = Port::new(name, name_cstr, cfg.private_mac, ectx.clone());

    // ================================================================
    // Firewall layer
    // ================================================================
    firewall::setup(&mut port).expect("failed to add firewall layer");

    // ================================================================
    // ICMP layer
    //
    // For intercepting ICMP Echo Requests to the virtual gateway.
    // ================================================================
    icmp::setup(&mut port, cfg).expect("failed to add icmp layer");

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

fn g1_cfg() -> PortCfg {
    PortCfg {
        private_ip: "192.168.77.101".parse().unwrap(),
        private_mac: EtherAddr::from([0xA8, 0x40, 0x25, 0xF7, 0x00, 0x65]),
        vpc_subnet: "192.168.77.0/24".parse().unwrap(),
        dyn_nat: DynNat4Cfg {
            // NOTE: This is not a routable IP, but remember that a
            // "public IP" for an Oxide guest could either be a
            // public, routable IP or simply an IP on their wider LAN
            // which the oxide Rack is simply a part of.
            public_ip: "10.77.77.13".parse().unwrap(),
            ports: Range { start: 1025, end: 4096 },
        },
        gw_mac: EtherAddr::from([0xA8, 0x40, 0x25, 0xF7, 0x00, 0x1]),
        gw_ip: "192.168.77.1".parse().unwrap(),
        vni: Vni::new(99u32).unwrap(),
        // Site 0xF7, Rack 1, Sled 1, Interface 1
        phys_ip: Ipv6Addr::from([
            0xFD00, 0x0000, 0x00F7, 0x0101, 0x0000, 0x0000, 0x0000, 0x0001,
        ]),
        bsvc_addr: PhysNet {
            ether: MacAddr::from([0xA8, 0x40, 0x25, 0x77, 0x77, 0x77]),
            ip: Ipv6Addr::from([
                0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x01, 0xFF, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x77, 0x77,
            ]),
            vni: Vni::new(7777u32).unwrap(),
        },
    }
}

fn g2_cfg() -> PortCfg {
    PortCfg {
        private_ip: "192.168.77.102".parse().unwrap(),
        private_mac: EtherAddr::from([0xA8, 0x40, 0x25, 0xF7, 0x00, 0x66]),
        vpc_subnet: "192.168.77.0/24".parse().unwrap(),
        dyn_nat: DynNat4Cfg {
            // NOTE: This is not a routable IP, but remember that a
            // "public IP" for an Oxide guest could either be a
            // public, routable IP or simply an IP on their wider LAN
            // which the oxide Rack is simply a part of.
            public_ip: "10.77.77.23".parse().unwrap(),
            ports: Range { start: 4097, end: 8192 },
        },
        gw_mac: EtherAddr::from([0xA8, 0x40, 0x25, 0xF7, 0x00, 0x1]),
        gw_ip: "192.168.77.1".parse().unwrap(),
        vni: Vni::new(99u32).unwrap(),
        // Site 0xF7, Rack 1, Sled 22, Interface 1
        phys_ip: Ipv6Addr::from([
            0xFD00, 0x0000, 0x00F7, 0x0116, 0x0000, 0x0000, 0x0000, 0x0001,
        ]),
        bsvc_addr: PhysNet {
            ether: MacAddr::from([0xA8, 0x40, 0x25, 0x77, 0x77, 0x77]),
            ip: Ipv6Addr::from([
                0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x01, 0xFF, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x77, 0x77,
            ]),
            vni: Vni::new(7777u32).unwrap(),
        },
    }
}

// Verify that the guest can ping the virtual gateway.
#[test]
fn gateway_icmp4_ping() {
    use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr};

    #[cfg(feature = "usdt")]
    usdt::register_probes().unwrap();

    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let g2_phys = GuestPhysAddr {
        ether: g2_cfg.private_mac.into(),
        ip: g2_cfg.phys_ip,
    };

    // Add V2P mappings that allow guests to resolve each others
    // physical addresses.
    let v2p = Arc::new(Virt2Phys::new());
    v2p.set(IpAddr::Ip4(g2_cfg.private_ip), g2_phys);
    let mut port_meta = Meta::new();
    port_meta.add(v2p).unwrap();

    let mut g1_port = oxide_net_setup("g1_port", &g1_cfg);
    router::setup(&mut g1_port, &g1_cfg).unwrap();
    overlay::setup(&mut g1_port, &g1_cfg).unwrap();
    let g1_port = g1_port.activate();

    let mut pcap = crate::test::PcapBuilder::new("gateway_icmpv4_ping.pcap");

    // ================================================================
    // Generate an ICMP Echo Request from G1 to Virtual GW
    // ================================================================
    let ident = 7;
    let seq_no = 777;
    let data = b"reunion\0";

    let req = Icmpv4Repr::EchoRequest { ident, seq_no, data: &data[..] };

    let mut body_bytes = vec![0u8; req.buffer_len()];
    let mut req_pkt = Icmpv4Packet::new_unchecked(&mut body_bytes);
    let _ = req.emit(&mut req_pkt, &Default::default());

    let mut ip4 = Ipv4Hdr::from(&Ipv4Meta {
        src: g1_cfg.private_ip,
        dst: g1_cfg.gw_ip,
        proto: Protocol::ICMP,
    });
    ip4.set_total_len(ip4.hdr_len() as u16 + req.buffer_len() as u16);
    ip4.compute_hdr_csum();

    let eth = EtherHdr::from(&EtherMeta {
        dst: g1_cfg.gw_mac,
        src: g1_cfg.private_mac,
        ether_type: ETHER_TYPE_IPV4,
    });

    let mut pkt_bytes =
        Vec::with_capacity(ETHER_HDR_SZ + ip4.hdr_len() + req.buffer_len());
    pkt_bytes.extend_from_slice(&eth.as_bytes());
    pkt_bytes.extend_from_slice(&ip4.as_bytes());
    pkt_bytes.extend_from_slice(&body_bytes);
    let mut g1_pkt = Packet::copy(&pkt_bytes).parse().unwrap();
    pcap.add_pkt(&g1_pkt);

    // ================================================================
    // Run the Echo Request through g1's port in the outbound
    // direction and verify it results in an Echo Reply Hairpin packet
    // back to guest.
    // ================================================================
    let res = g1_port.process(Out, &mut g1_pkt, &mut port_meta);
    let hp = match res {
        Ok(Hairpin(hp)) => hp,
        _ => panic!("expected Hairpin, got {:?}", res),
    };

    let reply = hp.parse().unwrap();
    pcap.add_pkt(&reply);

    // Ether + IPv4
    assert_eq!(reply.body_offset(), 14 + 20);
    assert_eq!(reply.body_seg(), 0);

    let meta = reply.meta();
    assert!(meta.outer.ether.is_none());
    assert!(meta.outer.ip.is_none());
    assert!(meta.outer.ulp.is_none());

    match meta.inner.ether.as_ref() {
        Some(eth) => {
            assert_eq!(eth.src, g1_cfg.gw_mac);
            assert_eq!(eth.dst, g1_cfg.private_mac);
        }

        None => panic!("no inner ether header"),
    }

    match meta.inner.ip.as_ref().unwrap() {
        IpMeta::Ip4(ip4) => {
            assert_eq!(ip4.src, g1_cfg.gw_ip);
            assert_eq!(ip4.dst, g1_cfg.private_ip);
            assert_eq!(ip4.proto, Protocol::ICMP);
        }

        ip6 => panic!("execpted inner IPv4 metadata, got IPv6: {:?}", ip6),
    }

    let mut rdr = PacketReader::new(&reply, ());
    // Need to seek to body.
    rdr.seek(14 + 20).unwrap();
    let reply_body = rdr.copy_remaining();
    let reply_pkt = Icmpv4Packet::new_checked(&reply_body).unwrap();
    // TODO The 2nd arguemnt is the checksum capab, while the default
    // value should verify the checksums better to make this explicit
    // so it's clear what is happening.
    let mut csum = CsumCapab::ignored();
    csum.ipv4 = smoltcp::phy::Checksum::Rx;
    csum.icmpv4 = smoltcp::phy::Checksum::Rx;
    let reply_icmp = Icmpv4Repr::parse(&reply_pkt, &csum).unwrap();
    match reply_icmp {
        Icmpv4Repr::EchoReply {
            ident: r_ident,
            seq_no: r_seq_no,
            data: r_data,
        } => {
            assert_eq!(r_ident, ident);
            assert_eq!(r_seq_no, seq_no);
            assert_eq!(r_data, data);
        }

        _ => panic!("expected Echo Reply, got {:?}", reply_icmp),
    }
}

// Try to send a TCP packet from one guest to another; but in this
// case the guest has not route to the other guest, resulting in the
// packet being dropped.
#[test]
fn overlay_guest_to_guest_no_route() {
    use crate::engine::checksum::HeaderChecksum;
    use crate::engine::ip4::UlpCsumOpt;
    use crate::engine::tcp::TcpFlags;

    // ================================================================
    // Configure ports for g1 and g2.
    // ================================================================
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let g2_phys = GuestPhysAddr {
        ether: g2_cfg.private_mac.into(),
        ip: g2_cfg.phys_ip,
    };

    // Add V2P mappings that allow guests to resolve each others
    // physical addresses.
    let v2p = Arc::new(Virt2Phys::new());
    v2p.set(IpAddr::Ip4(g2_cfg.private_ip), g2_phys);
    let mut port_meta = Meta::new();
    port_meta.add(v2p).unwrap();

    let mut g1_port = oxide_net_setup("g1_port", &g1_cfg);
    router::setup(&mut g1_port, &g1_cfg).unwrap();
    overlay::setup(&mut g1_port, &g1_cfg).unwrap();
    let g1_port = g1_port.activate();

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
    let tcp_csum =
        ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    let eth = EtherHdr::new(EtherType::Ipv4, g1_cfg.private_mac, g1_cfg.gw_mac);

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
    let res = g1_port.process(Out, &mut g1_pkt, &mut port_meta);
    assert!(matches!(res, Ok(ProcessResult::Drop { .. })));
}

// Verify that two guests on the same VPC can communicate via overlay.
// I.e., test routing + encap/decap.
#[test]
fn overlay_guest_to_guest() {
    use super::checksum::HeaderChecksum;
    use super::ip4::UlpCsumOpt;
    use super::tcp::TcpFlags;

    // ================================================================
    // Configure ports for g1 and g2.
    // ================================================================
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let g2_phys = GuestPhysAddr {
        ether: g2_cfg.private_mac.into(),
        ip: g2_cfg.phys_ip,
    };

    // Add V2P mappings that allow guests to resolve each others
    // physical addresses.
    let v2p = Arc::new(Virt2Phys::new());
    v2p.set(IpAddr::Ip4(g2_cfg.private_ip), g2_phys);
    let mut port_meta = Meta::new();
    port_meta.add(v2p).unwrap();

    let mut g1_port = oxide_net_setup("g1_port", &g1_cfg);
    router::setup(&mut g1_port, &g1_cfg).unwrap();
    overlay::setup(&mut g1_port, &g1_cfg).unwrap();
    let g1_port = g1_port.activate();

    // Add router entry that allows Guest 1 to send to Guest 2.
    router::add_entry_active(
        &g1_port,
        IpCidr::Ip4(g2_cfg.vpc_subnet.cidr()),
        RouterTarget::VpcSubnet(IpCidr::Ip4(g2_cfg.vpc_subnet.cidr())),
    )
    .unwrap();

    let mut g2_port = oxide_net_setup("g2_port", &g2_cfg);
    router::setup(&mut g2_port, &g2_cfg).unwrap();
    overlay::setup(&mut g2_port, &g2_cfg).unwrap();
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
    firewall::add_fw_rule(
        &g2_port,
        &AddFwRuleReq {
            port_name: g2_port.name().to_string(),
            rule: rule.parse().unwrap(),
        },
    )
    .unwrap();

    let mut pcap_guest1 =
        crate::test::PcapBuilder::new("overlay_guest_to_guest-guest-1.pcap");
    let mut pcap_phys1 =
        crate::test::PcapBuilder::new("overlay_guest_to_guest-phys-1.pcap");

    let mut pcap_guest2 =
        crate::test::PcapBuilder::new("overlay_guest_to_guest-guest-2.pcap");
    let mut pcap_phys2 =
        crate::test::PcapBuilder::new("overlay_guest_to_guest-phys-2.pcap");

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
    let tcp_csum =
        ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    let eth = EtherHdr::new(EtherType::Ipv4, g1_cfg.private_mac, g1_cfg.gw_mac);

    let mut bytes = vec![];
    bytes.extend_from_slice(&eth.as_bytes());
    bytes.extend_from_slice(&ip4.as_bytes());
    bytes.extend_from_slice(&tcp.as_bytes());
    bytes.extend_from_slice(&body);
    let mut g1_pkt = Packet::copy(&bytes).parse().unwrap();
    pcap_guest1.add_pkt(&g1_pkt);

    // ================================================================
    // Run the telnet SYN packet through g1's port in the outbound
    // direction and verify the resulting packet meets expectations.
    // ================================================================
    let res = g1_port.process(Out, &mut g1_pkt, &mut port_meta);
    pcap_phys1.add_pkt(&g1_pkt);
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
            assert_eq!(ip6.src, g1_cfg.phys_ip);
            assert_eq!(ip6.dst, g2_cfg.phys_ip);
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
    pcap_phys2.add_pkt(&g2_pkt);

    let res = g2_port.process(In, &mut g2_pkt, &mut port_meta);
    pcap_guest2.add_pkt(&g2_pkt);
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

// Two guests on different, non-peered VPCs should not be able to
// communicate.
#[test]
fn guest_to_guest_diff_vpc_no_peer() {
    use super::checksum::HeaderChecksum;
    use super::ip4::UlpCsumOpt;
    use super::tcp::TcpFlags;

    // ================================================================
    // Configure ports for g1 and g2. Place g1 on VNI 99 and g2 on VNI
    // 100.
    // ================================================================
    let g1_cfg = g1_cfg();
    let mut g2_cfg = g2_cfg();
    g2_cfg.vni = Vni::new(100u32).unwrap();

    let g1_phys = GuestPhysAddr {
        ether: g1_cfg.private_mac.into(),
        ip: g1_cfg.phys_ip,
    };

    // Add V2P mappings that allow guests to resolve each others
    // physical addresses. In this case the only guest in VNI 99 is
    // g1.
    let v2p = Arc::new(Virt2Phys::new());
    v2p.set(IpAddr::Ip4(g1_cfg.private_ip), g1_phys);
    let mut port_meta = Meta::new();
    port_meta.add(v2p.clone()).unwrap();

    let mut g1_port = oxide_net_setup("g1_port", &g1_cfg);
    router::setup(&mut g1_port, &g1_cfg).unwrap();
    overlay::setup(&mut g1_port, &g1_cfg).unwrap();
    let g1_port = g1_port.activate();

    // Add router entry that allows g1 to talk to any other guest on
    // its VPC subnet.
    //
    // In this case both g1 and g2 have the same subnet. However, g1
    // is part of VNI 99, and g2 is part of VNI 100. Without a VPC
    // Peering Gateway they have no way to reach each other.
    router::add_entry_active(
        &g1_port,
        IpCidr::Ip4(g1_cfg.vpc_subnet.cidr()),
        RouterTarget::VpcSubnet(IpCidr::Ip4(g1_cfg.vpc_subnet.cidr())),
    )
    .unwrap();

    let mut g2_port = oxide_net_setup("g2_port", &g2_cfg);
    router::setup(&mut g2_port, &g2_cfg).unwrap();
    overlay::setup(&mut g2_port, &g2_cfg).unwrap();
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
    firewall::add_fw_rule(
        &g2_port,
        &AddFwRuleReq {
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
    let tcp_csum =
        ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    let eth = EtherHdr::new(EtherType::Ipv4, g1_cfg.private_mac, g1_cfg.gw_mac);

    let mut bytes = vec![];
    bytes.extend_from_slice(&eth.as_bytes());
    bytes.extend_from_slice(&ip4.as_bytes());
    bytes.extend_from_slice(&tcp.as_bytes());
    bytes.extend_from_slice(&body);
    let mut g1_pkt = Packet::copy(&bytes).parse().unwrap();

    // ================================================================
    // Run the telnet SYN packet through g1's port in the outbound
    // direction and verify the packet is dropped.
    // ================================================================
    let res = g1_port.process(Out, &mut g1_pkt, &mut port_meta);
    println!("=== res: {:?}", res);
    assert!(matches!(res, Ok(ProcessResult::Drop { .. })));
}

// Verify that a guest can communicate with the internet.
#[test]
fn overlay_guest_to_internet() {
    use super::checksum::HeaderChecksum;
    use super::ip4::UlpCsumOpt;
    use super::tcp::TcpFlags;

    // ================================================================
    // Configure g1 port.
    // ================================================================
    let g1_cfg = g1_cfg();
    let v2p = Arc::new(Virt2Phys::new());
    let mut port_meta = Meta::new();
    port_meta.add(v2p).unwrap();

    let mut g1_port = oxide_net_setup("g1_port", &g1_cfg);
    router::setup(&mut g1_port, &g1_cfg).unwrap();
    overlay::setup(&mut g1_port, &g1_cfg).unwrap();
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
    let tcp_csum =
        ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
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
    let res = g1_port.process(Out, &mut g1_pkt, &mut port_meta);
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
            assert_eq!(ip6.src, g1_cfg.phys_ip);
            assert_eq!(ip6.dst, g1_cfg.bsvc_addr.ip);
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
            assert_eq!(geneve.vni, g1_cfg.bsvc_addr.vni);
        }

        None => panic!("expected outer Geneve metadata"),
    }

    match meta.inner.ether.as_ref() {
        Some(eth) => {
            assert_eq!(eth.src, g1_cfg.private_mac);
            assert_eq!(eth.dst, g1_cfg.bsvc_addr.ether.into());
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
        dst: Ipv4Addr::LOCAL_BCAST,
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
        dst: Ipv4Addr::LOCAL_BCAST,
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
    let mut port_meta = Meta::new();
    let port = oxide_net_setup("dhcp_req", &cfg).activate();
    let pkt = Packet::alloc(42);

    let ether = EtherHdr::from(&EtherMeta {
        src: cfg.private_mac,
        dst: ether::ETHER_BROADCAST,
        ether_type: ETHER_TYPE_IPV4,
    });

    let ip = Ipv4Hdr::from(&Ipv4Meta {
        src: "0.0.0.0".parse().unwrap(),
        dst: Ipv4Addr::LOCAL_BCAST,
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

    let res = port.process(Out, &mut pkt, &mut port_meta);

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
            assert_eq!(ip4m.dst, Ipv4Addr::LOCAL_BCAST);
            assert_eq!(ip4m.proto, Protocol::UDP);
        }

        res => panic!("expected Modified result, got {:?}", res),
    }
}

// Verify that OPTE generates a hairpin ARP reply when the guest
// queries for the gateway.
#[test]
fn arp_gateway() {
    use super::arp::ArpOp;
    use super::ether::ETHER_TYPE_IPV4;

    let cfg = g1_cfg();
    let mut port_meta = Meta::new();
    let port = oxide_net_setup("arp_hairpin", &cfg).activate();
    let reply_hdr_sz = ETHER_HDR_SZ + ARP_HDR_SZ;

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

    let res = port.process(Out, &mut pkt, &mut port_meta);
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
    let mut port_meta = Meta::new();
    let port = oxide_net_setup("outdoing_dns_lookup", &cfg).activate();
    let gpath = "dns-lookup-guest.pcap";
    let gbytes = fs::read(gpath).unwrap();
    let hpath = "dns-lookup-host.pcap";
    let hbytes = fs::read(hpath).unwrap();

    assert_eq!(port.num_flows("dyn-nat4", In), 0);
    assert_eq!(port.num_flows("dyn-nat4", Out), 0);
    assert_eq!(port.num_flows("firewall", In), 0);
    assert_eq!(port.num_flows("firewall", Out), 0);
    let now = Moment::now();

    // ================================================================
    // Packet 1 (DNS query)
    // ================================================================
    let (gbytes, _) = get_header(&gbytes[..]);
    let (gbytes, gblock) = next_block(&gbytes);
    let mut pkt = Packet::copy(gblock.data).parse().unwrap();
    let res = port.process(Out, &mut pkt, &mut port_meta);
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
    let res = port.process(In, &mut pkt, &mut port_meta);
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

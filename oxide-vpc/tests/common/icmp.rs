// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Routines for ICMP testing.

use opte::api::*;
use opte::engine::ether::*;
use opte::engine::ip4::*;
use opte::engine::ip6::*;
use opte::engine::packet::*;
use smoltcp::wire::Icmpv4Packet;
use smoltcp::wire::Icmpv4Repr;
use smoltcp::wire::Icmpv6Packet;
use smoltcp::wire::Icmpv6Repr;
use smoltcp::wire::Ipv6Address;

pub enum IcmpEchoType {
    Req,
    Reply,
}

pub fn gen_icmp_echo_req(
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: IpAddr,
    ip_dst: IpAddr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
) -> Packet<Parsed> {
    match (ip_src, ip_dst) {
        (IpAddr::Ip4(src), IpAddr::Ip4(dst)) => {
            gen_icmpv4_echo_req(eth_src, eth_dst, src, dst, ident, seq_no, data)
        }
        (IpAddr::Ip6(src), IpAddr::Ip6(dst)) => {
            gen_icmpv6_echo_req(eth_src, eth_dst, src, dst, ident, seq_no, data)
        }
        (_, _) => panic!("IP src and dst versions must match"),
    }
}

pub fn gen_icmpv4_echo_req(
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: Ipv4Addr,
    ip_dst: Ipv4Addr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
) -> Packet<Parsed> {
    let etype = IcmpEchoType::Req;
    gen_icmp_echo(etype, eth_src, eth_dst, ip_src, ip_dst, ident, seq_no, data)
}

pub fn gen_icmp_echo_reply(
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: Ipv4Addr,
    ip_dst: Ipv4Addr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
) -> Packet<Parsed> {
    let etype = IcmpEchoType::Reply;
    gen_icmp_echo(etype, eth_src, eth_dst, ip_src, ip_dst, ident, seq_no, data)
}

pub fn gen_icmp_echo(
    etype: IcmpEchoType,
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: Ipv4Addr,
    ip_dst: Ipv4Addr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
) -> Packet<Parsed> {
    let icmp = match etype {
        IcmpEchoType::Req => Icmpv4Repr::EchoRequest { ident, seq_no, data },
        IcmpEchoType::Reply => Icmpv4Repr::EchoReply { ident, seq_no, data },
    };
    let mut icmp_bytes = vec![0u8; icmp.buffer_len()];
    let mut icmp_pkt = Icmpv4Packet::new_unchecked(&mut icmp_bytes);
    let _ = icmp.emit(&mut icmp_pkt, &Default::default());

    let mut ip4 = Ipv4Hdr::from(&Ipv4Meta {
        src: ip_src,
        dst: ip_dst,
        proto: Protocol::ICMP,
    });
    ip4.set_total_len(ip4.hdr_len() as u16 + icmp.buffer_len() as u16);
    ip4.compute_hdr_csum();
    let eth = EtherHdr::from(&EtherMeta {
        dst: eth_dst,
        src: eth_src,
        ether_type: ETHER_TYPE_IPV4,
    });

    let mut pkt_bytes =
        Vec::with_capacity(EtherHdr::SIZE + ip4.hdr_len() + icmp.buffer_len());
    pkt_bytes.extend_from_slice(&eth.as_bytes());
    pkt_bytes.extend_from_slice(&ip4.as_bytes());
    pkt_bytes.extend_from_slice(&icmp_bytes);
    Packet::copy(&pkt_bytes).parse().unwrap()
}

pub fn gen_icmpv6_echo_req(
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: Ipv6Addr,
    ip_dst: Ipv6Addr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
) -> Packet<Parsed> {
    let req = Icmpv6Repr::EchoRequest { ident, seq_no, data };
    let mut body_bytes = vec![0u8; req.buffer_len()];
    let mut req_pkt = Icmpv6Packet::new_unchecked(&mut body_bytes);
    let _ = req.emit(
        &Ipv6Address::from_bytes(&ip_src).into(),
        &Ipv6Address::from_bytes(&ip_dst).into(),
        &mut req_pkt,
        &Default::default(),
    );
    let mut ip6 = Ipv6Hdr::from(&Ipv6Meta {
        src: ip_src,
        dst: ip_dst,
        proto: Protocol::ICMPv6,
    });
    ip6.set_total_len(ip6.hdr_len() as u16 + req.buffer_len() as u16);
    let eth = EtherHdr::from(&EtherMeta {
        dst: eth_dst,
        src: eth_src,
        ether_type: ETHER_TYPE_IPV6,
    });

    let mut pkt_bytes =
        Vec::with_capacity(EtherHdr::SIZE + ip6.hdr_len() + req.buffer_len());
    pkt_bytes.extend_from_slice(&eth.as_bytes());
    pkt_bytes.extend_from_slice(&ip6.as_bytes());
    pkt_bytes.extend_from_slice(&body_bytes);
    Packet::copy(&pkt_bytes).parse().unwrap()
}

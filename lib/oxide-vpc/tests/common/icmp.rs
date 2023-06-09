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
use opte::engine::Direction::*;
use oxide_vpc::engine::VpcParser;
use smoltcp::wire::Icmpv4Packet;
use smoltcp::wire::Icmpv4Repr;
use smoltcp::wire::Icmpv6Packet;
use smoltcp::wire::Icmpv6Repr;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv6Address;

pub enum IcmpEchoType {
    Req,
    Reply,
}

#[allow(clippy::too_many_arguments)]
pub fn gen_icmp_echo_req(
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: IpAddr,
    ip_dst: IpAddr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
    segments: usize,
) -> Packet<Parsed> {
    match (ip_src, ip_dst) {
        (IpAddr::Ip4(src), IpAddr::Ip4(dst)) => gen_icmpv4_echo_req(
            eth_src, eth_dst, src, dst, ident, seq_no, data, segments,
        ),
        (IpAddr::Ip6(src), IpAddr::Ip6(dst)) => gen_icmpv6_echo_req(
            eth_src, eth_dst, src, dst, ident, seq_no, data, segments,
        ),
        (_, _) => panic!("IP src and dst versions must match"),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn gen_icmpv4_echo_req(
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: Ipv4Addr,
    ip_dst: Ipv4Addr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
    segments: usize,
) -> Packet<Parsed> {
    let etype = IcmpEchoType::Req;
    gen_icmp_echo(
        etype, eth_src, eth_dst, ip_src, ip_dst, ident, seq_no, data, segments,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn gen_icmp_echo_reply(
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: Ipv4Addr,
    ip_dst: Ipv4Addr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
    segments: usize,
) -> Packet<Parsed> {
    let etype = IcmpEchoType::Reply;
    gen_icmp_echo(
        etype, eth_src, eth_dst, ip_src, ip_dst, ident, seq_no, data, segments,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn gen_icmp_echo(
    etype: IcmpEchoType,
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: Ipv4Addr,
    ip_dst: Ipv4Addr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
    segments: usize,
) -> Packet<Parsed> {
    let icmp = match etype {
        IcmpEchoType::Req => Icmpv4Repr::EchoRequest { ident, seq_no, data },
        IcmpEchoType::Reply => Icmpv4Repr::EchoReply { ident, seq_no, data },
    };
    let mut icmp_bytes = vec![0u8; icmp.buffer_len()];
    let mut icmp_pkt = Icmpv4Packet::new_unchecked(&mut icmp_bytes);
    icmp.emit(&mut icmp_pkt, &Default::default());

    let mut ip4 = Ipv4Meta {
        src: ip_src,
        dst: ip_dst,
        proto: Protocol::ICMP,
        total_len: (Ipv4Hdr::BASE_SIZE + icmp.buffer_len()) as u16,
        ..Default::default()
    };
    ip4.compute_hdr_csum();
    let eth =
        &EtherMeta { dst: eth_dst, src: eth_src, ether_type: EtherType::Ipv4 };

    let total_len = EtherHdr::SIZE + ip4.hdr_len() + icmp.buffer_len();

    match segments {
        1 => {
            let mut pkt = Packet::alloc_and_expand(total_len);
            let mut wtr = pkt.seg0_wtr();
            eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
            ip4.emit(wtr.slice_mut(ip4.hdr_len()).unwrap());
            wtr.write(&icmp_bytes).unwrap();
            pkt.parse(Out, VpcParser::new()).unwrap()
        }
        2 => {
            let mut pkt = Packet::alloc_and_expand(EtherHdr::SIZE);
            let mut wtr = pkt.seg_wtr(0);
            eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
            let i = pkt.add_seg(ip4.hdr_len() + icmp_bytes.len()).unwrap();
            let mut wtr = pkt.seg_wtr(i);
            ip4.emit(wtr.slice_mut(ip4.hdr_len()).unwrap());
            wtr.write(&icmp_bytes).unwrap();
            pkt.parse(Out, VpcParser::new()).unwrap()
        }
        3 => {
            let mut pkt = Packet::alloc_and_expand(EtherHdr::SIZE);
            let mut wtr = pkt.seg_wtr(0);
            eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
            let i = pkt.add_seg(ip4.hdr_len()).unwrap();
            let mut wtr = pkt.seg_wtr(i);
            ip4.emit(wtr.slice_mut(ip4.hdr_len()).unwrap());
            let i = pkt.add_seg(icmp_bytes.len()).unwrap();
            let mut wtr = pkt.seg_wtr(i);
            wtr.write(&icmp_bytes).unwrap();
            pkt.parse(Out, VpcParser::new()).unwrap()
        }
        _ => {
            panic!("only 1 2 or 3 segments allowed")
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn gen_icmpv6_echo_req(
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: Ipv6Addr,
    ip_dst: Ipv6Addr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
    segments: usize,
) -> Packet<Parsed> {
    let req = Icmpv6Repr::EchoRequest { ident, seq_no, data };
    let mut body_bytes = vec![0u8; req.buffer_len()];
    let mut req_pkt = Icmpv6Packet::new_unchecked(&mut body_bytes);
    req.emit(
        &Ipv6Address::from_bytes(&ip_src).into(),
        &Ipv6Address::from_bytes(&ip_dst).into(),
        &mut req_pkt,
        &Default::default(),
    );
    let ip6 = Ipv6Meta {
        src: ip_src,
        dst: ip_dst,
        proto: Protocol::ICMPv6,
        next_hdr: IpProtocol::Icmpv6,
        hop_limit: 64,
        pay_len: req.buffer_len() as u16,
        ..Default::default()
    };
    let eth =
        &EtherMeta { dst: eth_dst, src: eth_src, ether_type: EtherType::Ipv6 };

    let total_len = EtherHdr::SIZE + ip6.hdr_len() + req.buffer_len();

    match segments {
        1 => {
            let mut pkt = Packet::alloc_and_expand(total_len);
            let mut wtr = pkt.seg0_wtr();
            eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
            ip6.emit(wtr.slice_mut(ip6.hdr_len()).unwrap());
            wtr.write(&body_bytes).unwrap();
            pkt.parse(Out, VpcParser::new()).unwrap()
        }
        2 => {
            let mut pkt = Packet::alloc_and_expand(EtherHdr::SIZE);
            let mut wtr = pkt.seg_wtr(0);
            eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
            let i = pkt.add_seg(ip6.hdr_len() + body_bytes.len()).unwrap();
            let mut wtr = pkt.seg_wtr(i);
            ip6.emit(wtr.slice_mut(ip6.hdr_len()).unwrap());
            wtr.write(&body_bytes).unwrap();
            pkt.parse(Out, VpcParser::new()).unwrap()
        }
        3 => {
            let mut pkt = Packet::alloc_and_expand(EtherHdr::SIZE);
            let mut wtr = pkt.seg_wtr(0);
            eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
            let i = pkt.add_seg(ip6.hdr_len()).unwrap();
            let mut wtr = pkt.seg_wtr(i);
            ip6.emit(wtr.slice_mut(ip6.hdr_len()).unwrap());
            let i = pkt.add_seg(body_bytes.len()).unwrap();
            let mut wtr = pkt.seg_wtr(i);
            wtr.write(&body_bytes).unwrap();
            pkt.parse(Out, VpcParser::new()).unwrap()
        }
        _ => {
            panic!("only 1 2 or 3 segments allowed")
        }
    }
}

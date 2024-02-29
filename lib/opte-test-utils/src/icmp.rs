// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Routines for ICMP testing.

use opte::api::*;
use opte::engine::ether::*;
use opte::engine::ip4::*;
use opte::engine::ip6::*;
use opte::engine::packet::*;
use opte::engine::Direction::*;
use oxide_vpc::engine::VpcParser;
use smoltcp::phy::ChecksumCapabilities as CsumCapab;
use smoltcp::wire::Icmpv4Packet;
use smoltcp::wire::Icmpv4Repr;
use smoltcp::wire::Icmpv6Packet;
use smoltcp::wire::Icmpv6Repr;
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv6Address;
use smoltcp::wire::NdiscNeighborFlags;
pub use smoltcp::wire::NdiscRepr;
pub use smoltcp::wire::RawHardwareAddress;

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
    ip_src: IpAddr,
    ip_dst: IpAddr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
    segments: usize,
) -> Packet<Parsed> {
    match (ip_src, ip_dst) {
        (IpAddr::Ip4(src), IpAddr::Ip4(dst)) => gen_icmpv4_echo_reply(
            eth_src, eth_dst, src, dst, ident, seq_no, data, segments,
        ),
        (IpAddr::Ip6(src), IpAddr::Ip6(dst)) => gen_icmpv6_echo_reply(
            eth_src, eth_dst, src, dst, ident, seq_no, data, segments,
        ),
        (_, _) => panic!("IP src and dst versions must match"),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn gen_icmpv4_echo_reply(
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
            let mut wtr =
                pkt.add_seg(ip4.hdr_len() + icmp_bytes.len()).unwrap();
            ip4.emit(wtr.slice_mut(ip4.hdr_len()).unwrap());
            wtr.write(&icmp_bytes).unwrap();
            pkt.parse(Out, VpcParser::new()).unwrap()
        }
        3 => {
            let mut pkt = Packet::alloc_and_expand(EtherHdr::SIZE);
            let mut wtr = pkt.seg_wtr(0);
            eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
            let mut wtr = pkt.add_seg(ip4.hdr_len()).unwrap();
            ip4.emit(wtr.slice_mut(ip4.hdr_len()).unwrap());
            let mut wtr = pkt.add_seg(icmp_bytes.len()).unwrap();
            wtr.write(&icmp_bytes).unwrap();
            pkt.parse(Out, VpcParser::new()).unwrap()
        }
        _ => {
            panic!("only 1 2 or 3 segments allowed")
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn gen_icmp_echo_unparsed(
    etype: IcmpEchoType,
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: Ipv4Addr,
    ip_dst: Ipv4Addr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
    segments: usize,
) -> Packet<Initialized> {
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

            pkt
        }
        2 => {
            let mut pkt = Packet::alloc_and_expand(EtherHdr::SIZE);
            let mut wtr = pkt.seg_wtr(0);
            eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
            let mut wtr =
                pkt.add_seg(ip4.hdr_len() + icmp_bytes.len()).unwrap();
            ip4.emit(wtr.slice_mut(ip4.hdr_len()).unwrap());
            wtr.write(&icmp_bytes).unwrap();

            pkt
        }
        3 => {
            let mut pkt = Packet::alloc_and_expand(EtherHdr::SIZE);
            let mut wtr = pkt.seg_wtr(0);
            eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
            let mut wtr = pkt.add_seg(ip4.hdr_len()).unwrap();
            ip4.emit(wtr.slice_mut(ip4.hdr_len()).unwrap());
            let mut wtr = pkt.add_seg(icmp_bytes.len()).unwrap();
            wtr.write(&icmp_bytes).unwrap();

            pkt
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
    let etype = IcmpEchoType::Req;
    gen_icmpv6_echo(
        etype, eth_src, eth_dst, ip_src, ip_dst, ident, seq_no, data, segments,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn gen_icmpv6_echo_reply(
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: Ipv6Addr,
    ip_dst: Ipv6Addr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
    segments: usize,
) -> Packet<Parsed> {
    let etype = IcmpEchoType::Reply;
    gen_icmpv6_echo(
        etype, eth_src, eth_dst, ip_src, ip_dst, ident, seq_no, data, segments,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn gen_icmpv6_echo(
    etype: IcmpEchoType,
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: Ipv6Addr,
    ip_dst: Ipv6Addr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
    segments: usize,
) -> Packet<Parsed> {
    gen_icmpv6_echo_unparsed(
        etype, eth_src, eth_dst, ip_src, ip_dst, ident, seq_no, data, segments,
    )
    .parse(Out, VpcParser::new())
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
pub fn gen_icmpv6_echo_unparsed(
    etype: IcmpEchoType,
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: Ipv6Addr,
    ip_dst: Ipv6Addr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
    segments: usize,
) -> Packet<Initialized> {
    let icmp = match etype {
        IcmpEchoType::Req => Icmpv6Repr::EchoRequest { ident, seq_no, data },
        IcmpEchoType::Reply => Icmpv6Repr::EchoReply { ident, seq_no, data },
    };

    let mut body_bytes = vec![0u8; icmp.buffer_len()];
    let mut req_pkt = Icmpv6Packet::new_unchecked(&mut body_bytes);
    icmp.emit(
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
        pay_len: icmp.buffer_len() as u16,
        ..Default::default()
    };
    let eth =
        &EtherMeta { dst: eth_dst, src: eth_src, ether_type: EtherType::Ipv6 };

    let total_len = EtherHdr::SIZE + ip6.hdr_len() + icmp.buffer_len();

    match segments {
        1 => {
            let mut pkt = Packet::alloc_and_expand(total_len);
            let mut wtr = pkt.seg0_wtr();
            eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
            ip6.emit(wtr.slice_mut(ip6.hdr_len()).unwrap());
            wtr.write(&body_bytes).unwrap();
            pkt
        }
        2 => {
            let mut pkt = Packet::alloc_and_expand(EtherHdr::SIZE);
            let mut wtr = pkt.seg_wtr(0);
            eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
            let mut wtr =
                pkt.add_seg(ip6.hdr_len() + body_bytes.len()).unwrap();
            ip6.emit(wtr.slice_mut(ip6.hdr_len()).unwrap());
            wtr.write(&body_bytes).unwrap();
            pkt
        }
        3 => {
            let mut pkt = Packet::alloc_and_expand(EtherHdr::SIZE);
            let mut wtr = pkt.seg_wtr(0);
            eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
            let mut wtr = pkt.add_seg(ip6.hdr_len()).unwrap();
            ip6.emit(wtr.slice_mut(ip6.hdr_len()).unwrap());
            let mut wtr = pkt.add_seg(body_bytes.len()).unwrap();
            wtr.write(&body_bytes).unwrap();
            pkt
        }
        _ => {
            panic!("only 1 2 or 3 segments allowed")
        }
    }
}

/// Generate an NDP packet given an inner `repr`.
pub fn generate_ndisc(
    repr: NdiscRepr,
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    with_checksum: bool,
) -> Packet<Parsed> {
    generate_ndisc_unparsed(
        repr,
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        with_checksum,
    )
    .parse(Out, VpcParser::new())
    .unwrap()
}

/// Generate an NDP packet given an inner `repr`.
pub fn generate_ndisc_unparsed(
    repr: NdiscRepr,
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    with_checksum: bool,
) -> Packet<Initialized> {
    let req = Icmpv6Repr::Ndisc(repr);
    let mut body = vec![0u8; req.buffer_len()];
    let mut req_pkt = Icmpv6Packet::new_unchecked(&mut body);
    let mut csum = CsumCapab::ignored();
    if with_checksum {
        csum.icmpv6 = smoltcp::phy::Checksum::Tx;
    }
    req.emit(
        &IpAddress::Ipv6(src_ip.into()),
        &IpAddress::Ipv6(dst_ip.into()),
        &mut req_pkt,
        &csum,
    );
    let ip6 = Ipv6Meta {
        src: src_ip,
        dst: dst_ip,
        proto: Protocol::ICMPv6,
        next_hdr: IpProtocol::Icmpv6,
        hop_limit: 255,
        pay_len: req.buffer_len() as u16,
        ..Default::default()
    };
    let eth =
        EtherMeta { dst: dst_mac, src: src_mac, ether_type: EtherType::Ipv6 };

    let total_len = EtherHdr::SIZE + ip6.hdr_len() + req.buffer_len();
    let mut pkt = Packet::alloc_and_expand(total_len);
    let mut wtr = pkt.seg0_wtr();
    eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
    ip6.emit(wtr.slice_mut(ip6.hdr_len()).unwrap());
    wtr.write(&body).unwrap();
    pkt
}

// Generate a packet containing an NDP Router Solicitation.
//
// The source MAC is used to generate the source IPv6 address, using the EUI-64
// transform. The resulting packet has a multicast MAC address, and the
// All-Routers destination IPv6 address.
pub fn gen_router_solicitation(src_mac: &MacAddr) -> Packet<Parsed> {
    let solicit = NdiscRepr::RouterSolicit {
        lladdr: Some(RawHardwareAddress::from_bytes(src_mac)),
    };
    let dst_ip = Ipv6Addr::ALL_ROUTERS;

    generate_ndisc(
        solicit,
        *src_mac,
        // Must be destined for the All-Routers IPv6 address, and the corresponding
        // multicast Ethernet address.
        dst_ip.multicast_mac().unwrap(),
        // The source IPv6 address is the EUI-64 transform of the source MAC.
        Ipv6Addr::from_eui64(src_mac),
        dst_ip,
        true,
    )
}

// Create a Neighbor Solicitation.
pub fn generate_neighbor_solicitation(
    info: &SolicitInfo,
    with_checksum: bool,
) -> Packet<Parsed> {
    let solicit = NdiscRepr::NeighborSolicit {
        target_addr: Ipv6Address::from(info.target_addr),
        lladdr: info.lladdr.map(|x| RawHardwareAddress::from_bytes(&x)),
    };
    generate_ndisc(
        solicit,
        info.src_mac,
        info.dst_mac,
        info.src_ip,
        info.dst_ip,
        with_checksum,
    )
}

// Helper type describing a Neighbor Solicitation
#[derive(Clone, Copy, Debug)]
pub struct SolicitInfo {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub target_addr: Ipv6Addr,
    pub lladdr: Option<MacAddr>,
}

impl std::fmt::Display for SolicitInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let lladdr = match self.lladdr {
            None => "None".to_string(),
            Some(x) => x.to_string(),
        };
        f.debug_struct("SolicitInfo")
            .field("src_mac", &self.src_mac.to_string())
            .field("dst_mac", &self.dst_mac.to_string())
            .field("src_ip", &self.src_ip.to_string())
            .field("dst_ip", &self.dst_ip.to_string())
            .field("target_addr", &self.target_addr.to_string())
            .field("lladdr", &lladdr)
            .finish()
    }
}

// Create a Neighbor Advertisement.
pub fn generate_neighbor_advertisement(
    info: &AdvertInfo,
    with_checksum: bool,
) -> Packet<Parsed> {
    let advert = NdiscRepr::NeighborAdvert {
        flags: info.flags,
        target_addr: info.target_addr.into(),
        lladdr: info.lladdr.map(|x| RawHardwareAddress::from_bytes(&x)),
    };

    generate_ndisc(
        advert,
        info.src_mac,
        info.dst_mac,
        info.src_ip,
        info.dst_ip,
        with_checksum,
    )
}

// Helper type describing a Neighbor Advertisement
#[derive(Clone, Copy, Debug)]
pub struct AdvertInfo {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub target_addr: Ipv6Addr,
    pub lladdr: Option<MacAddr>,
    pub flags: NdiscNeighborFlags,
}

impl std::fmt::Display for AdvertInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let lladdr = match self.lladdr {
            None => "None".to_string(),
            Some(x) => x.to_string(),
        };
        f.debug_struct("AdvertInfo")
            .field("src_mac", &self.src_mac.to_string())
            .field("dst_mac", &self.dst_mac.to_string())
            .field("src_ip", &self.src_ip.to_string())
            .field("dst_ip", &self.dst_ip.to_string())
            .field("target_addr", &self.target_addr.to_string())
            .field("lladdr", &lladdr)
            .field("flags", &self.flags)
            .finish()
    }
}

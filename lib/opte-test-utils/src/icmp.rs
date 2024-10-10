// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Routines for ICMP testing.

use opte::api::*;
use opte::engine::ether::*;
use opte::engine::ingot_base::Ethernet;
use opte::engine::ingot_base::Ipv4;
use opte::engine::ingot_base::Ipv6;
use opte::engine::ingot_packet::MsgBlk;
use opte::engine::ip4::*;
use opte::engine::ip6::*;
use opte::engine::packet::*;
use opte::engine::Direction::*;
use opte::ingot::ethernet::Ethertype;
use opte::ingot::ip::IpProtocol as IngotIpProto;
use opte::ingot::types::HeaderLen;
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
) -> MsgBlk {
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
) -> MsgBlk {
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
) -> MsgBlk {
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
) -> MsgBlk {
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
    n_segments: usize,
) -> MsgBlk {
    let icmp = match etype {
        IcmpEchoType::Req => Icmpv4Repr::EchoRequest { ident, seq_no, data },
        IcmpEchoType::Reply => Icmpv4Repr::EchoReply { ident, seq_no, data },
    };
    let mut icmp_bytes = vec![0u8; icmp.buffer_len()];
    let mut icmp_pkt = Icmpv4Packet::new_unchecked(&mut icmp_bytes);
    icmp.emit(&mut icmp_pkt, &Default::default());

    let eth = Ethernet {
        destination: eth_dst,
        source: eth_src,
        ethertype: Ethertype::IPV4,
    };

    let mut ip = Ipv4 {
        source: ip_src,
        destination: ip_dst,
        protocol: IngotIpProto::ICMP,
        total_len: (icmp.buffer_len() + Ipv4::MINIMUM_LENGTH) as u16,
        ..Default::default()
    };
    ip.fill_checksum();

    let total_len =
        eth.packet_length() + ip.packet_length() + icmp.buffer_len();
    let mut segments = vec![];

    match n_segments {
        1 => {
            let mut pkt = MsgBlk::new_ethernet(total_len);
            pkt.emit_back(&(eth, ip));
            pkt.resize(total_len);
            pkt.write_bytes_back(&icmp_bytes).unwrap();

            return pkt;
        }
        2 => {
            let mut pkt = MsgBlk::new_ethernet(eth.packet_length());
            pkt.emit_back(eth).unwrap();
            segments.push(pkt);

            let t_len = ip.packet_length() + icmp.buffer_len();
            let mut pkt = MsgBlk::new(t_len);
            pkt.emit_back(ip).unwrap();
            pkt.resize(t_len).unwrap();
            pkt.write_bytes_back(&icmp_bytes).unwrap();
            segments.push(pkt);
        }
        3 => {
            let mut pkt = MsgBlk::new_ethernet(eth.packet_length());
            pkt.emit_back(eth).unwrap();
            segments.push(pkt);

            let mut pkt = MsgBlk::new(ip.packet_length());
            pkt.emit_back(eth).unwrap();
            segments.push(pkt);

            let mut pkt = MsgBlk::new(icmp.buffer_len());
            pkt.write_bytes_back(&icmp_bytes).unwrap();
            segments.push(pkt);
        }
        _ => {
            panic!("only 1 2 or 3 segments allowed")
        }
    }

    while segments.len() > 1 {
        let chain = segments.pop().unwrap();
        let mut new_el = segments.last_mut().unwrap();

        new_el.extend_if_one(chain);
    }

    segments.pop().unwrap()
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
) -> MsgBlk {
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
) -> MsgBlk {
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
    n_segments: usize,
) -> MsgBlk {
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

    let eth = Ethernet {
        destination: eth_dst,
        source: eth_src,
        ethertype: Ethertype::IPV4,
    };

    let ip = Ipv6 {
        source: ip_src,
        destination: ip_dst,
        next_header: IngotIpProto::ICMP_V6,
        payload_len: icmp.buffer_len() as u16,
        hop_limit: 64,
        ..Default::default()
    };

    let total_len =
        eth.packet_length() + ip.packet_length() + icmp.buffer_len();
    let mut segments = vec![];

    match n_segments {
        1 => {
            let mut pkt = MsgBlk::new_ethernet(total_len);
            pkt.emit_back(&(eth, ip));
            pkt.resize(total_len);
            pkt.write_bytes_back(&body_bytes).unwrap();

            return pkt;
        }
        2 => {
            let mut pkt = MsgBlk::new_ethernet(eth.packet_length());
            pkt.emit_back(eth).unwrap();
            segments.push(pkt);

            let t_len = ip.packet_length() + icmp.buffer_len();
            let mut pkt = MsgBlk::new(t_len);
            pkt.emit_back(ip).unwrap();
            pkt.resize(t_len).unwrap();
            pkt.write_bytes_back(&body_bytes).unwrap();
            segments.push(pkt);
        }
        3 => {
            let mut pkt = MsgBlk::new_ethernet(eth.packet_length());
            pkt.emit_back(eth).unwrap();
            segments.push(pkt);

            let mut pkt = MsgBlk::new(ip.packet_length());
            pkt.emit_back(eth).unwrap();
            segments.push(pkt);

            let mut pkt = MsgBlk::new(icmp.buffer_len());
            pkt.write_bytes_back(&body_bytes).unwrap();
            segments.push(pkt);
        }
        _ => {
            panic!("only 1 2 or 3 segments allowed")
        }
    }

    while segments.len() > 1 {
        let chain = segments.pop().unwrap();
        let mut new_el = segments.last_mut().unwrap();

        new_el.extend_if_one(chain);
    }

    segments.pop().unwrap()
}

/// Generate an NDP packet given an inner `repr`.
pub fn generate_ndisc(
    repr: NdiscRepr,
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    with_checksum: bool,
) -> MsgBlk {
    let req = Icmpv6Repr::Ndisc(repr);
    let eth = Ethernet {
        destination: dst_mac,
        source: src_mac,
        ethertype: Ethertype::IPV6,
    };

    let ip = Ipv6 {
        source: src_ip,
        destination: dst_ip,
        next_header: IngotIpProto::ICMP_V6,
        payload_len: req.buffer_len() as u16,
        hop_limit: 255,
        ..Default::default()
    };

    let headers = (eth, ip);
    let total_len = req.buffer_len() + headers.packet_length();
    let mut pkt = MsgBlk::new_ethernet(total_len);
    pkt.emit_back(&headers).unwrap();
    let ndisc_off = pkt.len();
    pkt.resize(total_len);

    let mut req_pkt = Icmpv6Packet::new_unchecked(&mut pkt[ndisc_off..]);
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

    pkt
}

// Generate a packet containing an NDP Router Solicitation.
//
// The source MAC is used to generate the source IPv6 address, using the EUI-64
// transform. The resulting packet has a multicast MAC address, and the
// All-Routers destination IPv6 address.
pub fn gen_router_solicitation(src_mac: &MacAddr) -> MsgBlk {
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
) -> MsgBlk {
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
) -> MsgBlk {
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

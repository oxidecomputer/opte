// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Common routines for integration tests.

pub mod icmp;
pub mod pcap;
pub mod port_state;

use opte::api::MacAddr;
use opte::engine::checksum::HeaderChecksum;
use opte::engine::ether::EtherHdr;
use opte::engine::ether::EtherType;
use opte::engine::headers::IpHdr;
use opte::engine::headers::UlpHdr;
use opte::engine::ip4::Ipv4Addr;
use opte::engine::ip4::Ipv4Hdr;
use opte::engine::ip4::UlpCsumOpt;
use opte::engine::packet::Packet;
use opte::engine::packet::Parsed;
use opte::engine::tcp::TcpFlags;
use opte::engine::tcp::TcpHdr;
use oxide_vpc::api::VpcCfg;

// This is the MAC address that OPTE uses to act as the virtual gateway.
pub const GW_MAC_ADDR: MacAddr =
    MacAddr::from_const([0xA8, 0x40, 0x25, 0xFF, 0x77, 0x77]);

pub fn ulp_pkt<I: Into<IpHdr>, U: Into<UlpHdr>>(
    eth: EtherHdr,
    ip: I,
    ulp: U,
    body: &[u8],
) -> Packet<Parsed> {
    let mut bytes = vec![];
    bytes.extend_from_slice(&eth.as_bytes());
    bytes.extend_from_slice(&ip.into().as_bytes());
    bytes.extend_from_slice(&ulp.into().as_bytes());
    bytes.extend_from_slice(&body);
    Packet::copy(&bytes).parse().unwrap()
}

// Generate a packet representing the start of a TCP handshake for a
// telnet session from src to dst.
pub fn tcp_telnet_syn(src: &VpcCfg, dst: &VpcCfg) -> Packet<Parsed> {
    let body = vec![];
    let mut tcp = TcpHdr::new(7865, 23);
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_seq(4224936861);
    let mut ip4 = Ipv4Hdr::new_tcp(
        &mut tcp,
        &body,
        src.ipv4_cfg().unwrap().private_ip,
        dst.ipv4_cfg().unwrap().private_ip,
    );
    ip4.compute_hdr_csum();
    let tcp_csum =
        ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    let eth = EtherHdr::new(EtherType::Ipv4, src.private_mac, src.gateway_mac);
    ulp_pkt(eth, ip4, tcp, &body)
}

// Generate a packet representing the start of a TCP handshake for an
// HTTP request from src to dst.
pub fn http_tcp_syn(src: &VpcCfg, dst: &VpcCfg) -> Packet<Parsed> {
    http_tcp_syn2(
        src.private_mac,
        src.ipv4_cfg().unwrap().private_ip,
        dst.ipv4_cfg().unwrap().private_ip,
    )
}

// Generate a packet representing the start of a TCP handshake for an
// HTTP request from src to dst.
pub fn http_tcp_syn2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    ip_dst: Ipv4Addr,
) -> Packet<Parsed> {
    let body = vec![];
    let mut tcp = TcpHdr::new(44490, 80);
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_seq(2382112979);
    let mut ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, ip_src, ip_dst);
    ip4.compute_hdr_csum();
    let tcp_csum =
        ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    // Any packet from the guest is always addressed to the gateway.
    let eth = EtherHdr::new(EtherType::Ipv4, eth_src, GW_MAC_ADDR);
    ulp_pkt(eth, ip4, tcp, &body)
}

// Generate a packet representing the SYN+ACK reply to `http_tcp_syn()`,
// from g1 to g2.
pub fn http_tcp_syn_ack(src: &VpcCfg, dst: &VpcCfg) -> Packet<Parsed> {
    let body = vec![];
    let mut tcp = TcpHdr::new(80, 44490);
    tcp.set_flags(TcpFlags::SYN | TcpFlags::ACK);
    tcp.set_seq(44161351);
    tcp.set_ack(2382112980);
    let mut ip4 = Ipv4Hdr::new_tcp(
        &mut tcp,
        &body,
        src.ipv4_cfg().unwrap().private_ip,
        dst.ipv4_cfg().unwrap().private_ip,
    );
    ip4.compute_hdr_csum();
    let tcp_csum =
        ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    let eth = EtherHdr::new(EtherType::Ipv4, src.private_mac, src.gateway_mac);
    ulp_pkt(eth, ip4, tcp, &body)
}

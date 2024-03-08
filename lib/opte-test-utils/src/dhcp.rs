// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Routines for DHCP testing.

use super::*;
use dhcpv6::protocol::MessageType;
use opte::engine::dhcpv6;
pub use smoltcp::wire::DhcpMessageType;
pub use smoltcp::wire::DhcpPacket;
pub use smoltcp::wire::DhcpRepr;

// Build a packet from a DHCPv4 message, from a client to server.
pub fn packet_from_client_dhcpv4_message_unparsed(
    cfg: &VpcCfg,
    msg: &DhcpRepr,
) -> Packet<Initialized> {
    let eth = EtherMeta {
        dst: MacAddr::BROADCAST,
        src: cfg.guest_mac,
        ether_type: EtherType::Ipv4,
    };

    let ip = Ipv4Meta {
        src: Ipv4Addr::ANY_ADDR,
        dst: Ipv4Addr::LOCAL_BCAST,
        proto: Protocol::UDP,
        total_len: (msg.buffer_len() + UdpHdr::SIZE + Ipv4Hdr::BASE_SIZE)
            as u16,

        ..Default::default()
    };

    let udp = UdpMeta {
        src: 68,
        dst: 67,
        len: (UdpHdr::SIZE + msg.buffer_len()) as u16,
        ..Default::default()
    };

    let reply_len =
        msg.buffer_len() + UdpHdr::SIZE + Ipv6Hdr::BASE_SIZE + EtherHdr::SIZE;
    let mut pkt = Packet::alloc_and_expand(reply_len);
    let mut wtr = pkt.seg0_wtr();
    eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
    ip.emit(wtr.slice_mut(ip.hdr_len()).unwrap());
    udp.emit(wtr.slice_mut(udp.hdr_len()).unwrap());

    let mut msg_buf = vec![0; msg.buffer_len()];
    let mut dhcp_pkt = DhcpPacket::new_checked(&mut msg_buf).unwrap();
    msg.emit(&mut dhcp_pkt).unwrap();
    wtr.write(&msg_buf).unwrap();
    pkt
}

// Build a packet from a DHCPv6 message, from a client to server.
pub fn packet_from_client_dhcpv6_message_unparsed(
    cfg: &VpcCfg,
    msg: &dhcpv6::protocol::Message<'_>,
) -> Packet<Initialized> {
    let eth = EtherMeta {
        dst: dhcpv6::ALL_RELAYS_AND_SERVERS.multicast_mac().unwrap(),
        src: cfg.guest_mac,
        ether_type: EtherType::Ipv6,
    };

    let ip = Ipv6Meta {
        src: Ipv6Addr::from_eui64(&cfg.guest_mac),
        dst: dhcpv6::ALL_RELAYS_AND_SERVERS,
        proto: Protocol::UDP,
        next_hdr: IpProtocol::Udp,
        pay_len: (msg.buffer_len() + UdpHdr::SIZE) as u16,
        ..Default::default()
    };

    let udp = UdpMeta {
        src: dhcpv6::CLIENT_PORT,
        dst: dhcpv6::SERVER_PORT,
        len: (UdpHdr::SIZE + msg.buffer_len()) as u16,
        ..Default::default()
    };

    write_dhcpv6_packet_unparsed(eth, ip, udp, msg)
}

pub fn packet_from_client_dhcpv6_message(
    cfg: &VpcCfg,
    msg: &dhcpv6::protocol::Message<'_>,
) -> Packet<Parsed> {
    packet_from_client_dhcpv6_message_unparsed(cfg, msg)
        .parse(Out, GenericUlp {})
        .unwrap()
}

pub fn write_dhcpv6_packet_unparsed(
    eth: EtherMeta,
    ip: Ipv6Meta,
    udp: UdpMeta,
    msg: &dhcpv6::protocol::Message<'_>,
) -> Packet<Initialized> {
    let reply_len =
        msg.buffer_len() + UdpHdr::SIZE + Ipv6Hdr::BASE_SIZE + EtherHdr::SIZE;
    let mut pkt = Packet::alloc_and_expand(reply_len);
    let mut wtr = pkt.seg0_wtr();
    eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
    ip.emit(wtr.slice_mut(ip.hdr_len()).unwrap());
    udp.emit(wtr.slice_mut(udp.hdr_len()).unwrap());
    let mut msg_buf = vec![0; msg.buffer_len()];
    msg.copy_into(&mut msg_buf).unwrap();
    wtr.write(&msg_buf).unwrap();
    pkt
}

pub fn write_dhcpv6_packet(
    eth: EtherMeta,
    ip: Ipv6Meta,
    udp: UdpMeta,
    msg: &dhcpv6::protocol::Message<'_>,
) -> Packet<Parsed> {
    write_dhcpv6_packet_unparsed(eth, ip, udp, msg)
        .parse(Out, GenericUlp {})
        .unwrap()
}

pub fn dhcpv6_with_reasonable_defaults(
    typ: MessageType,
    rapid_commit: bool,
    cfg: &VpcCfg,
) -> dhcpv6::protocol::Message<'_> {
    let requested_iana = dhcpv6::options::IaNa {
        id: dhcpv6::options::IaId(0xff7),
        t1: dhcpv6::Lifetime(3600),
        t2: dhcpv6::Lifetime(6200),
        options: vec![],
    };

    let extra_options =
        &[dhcpv6::options::Code::DnsServers, dhcpv6::options::Code::DomainList];
    let oro = dhcpv6::options::OptionRequest(extra_options.as_slice().into());
    let base_options = vec![
        dhcpv6::options::Option::ClientId(dhcpv6::Duid::from(&cfg.guest_mac)),
        dhcpv6::options::Option::ElapsedTime(dhcpv6::options::ElapsedTime(10)),
        dhcpv6::options::Option::IaNa(requested_iana.clone()),
        dhcpv6::options::Option::OptionRequest(oro),
    ];

    let mut options = base_options.clone();
    if rapid_commit {
        options.push(dhcpv6::options::Option::RapidCommit);
    }
    if typ == dhcpv6::protocol::MessageType::Request {
        options.push(dhcpv6::options::Option::ServerId(dhcpv6::Duid::from(
            &cfg.gateway_mac,
        )));
    }

    dhcpv6::protocol::Message {
        typ,
        xid: dhcpv6::TransactionId::from(&[0u8, 1, 2]),
        options,
    }
}

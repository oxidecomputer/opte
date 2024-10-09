// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Routines for DHCP testing.

use super::*;
use dhcpv6::protocol::MessageType;
use opte::engine::dhcp::DHCP_CLIENT_PORT;
use opte::engine::dhcp::DHCP_SERVER_PORT;
use opte::engine::dhcpv6;
use opte::engine::ingot_base::Ethernet;
use opte::engine::ingot_base::Ipv4;
use opte::engine::ingot_base::Ipv6;
use opte::engine::ingot_packet::MsgBlk;
use opte::ingot::ethernet::Ethertype;
use opte::ingot::ip::IpProtocol;
use opte::ingot::types::Header;
use opte::ingot::udp::Udp;
pub use smoltcp::wire::DhcpMessageType;
pub use smoltcp::wire::DhcpPacket;
pub use smoltcp::wire::DhcpRepr;

// Build a packet from a DHCPv4 message, from a client to server.
pub fn packet_from_client_dhcpv4_message(
    cfg: &VpcCfg,
    msg: &DhcpRepr,
) -> MsgBlk {
    let eth = Ethernet {
        destination: MacAddr::BROADCAST,
        source: cfg.guest_mac,
        ethertype: Ethertype::IPV4,
    };

    let ip = Ipv4 {
        source: Ipv4Addr::ANY_ADDR,
        destination: Ipv4Addr::LOCAL_BCAST,
        protocol: IpProtocol::UDP,
        total_len: (msg.buffer_len()
            + Udp::MINIMUM_LENGTH
            + Ipv4::MINIMUM_LENGTH) as u16,
        ..Default::default()
    };

    let udp = Udp {
        source: DHCP_CLIENT_PORT,
        destination: DHCP_SERVER_PORT,
        length: (Udp::MINIMUM_LENGTH + msg.buffer_len()) as u16,
        ..Default::default()
    };

    let headers = (eth, ip, udp);
    let total_len = msg.buffer_len() + headers.packet_length();

    let mut pkt = MsgBlk::new_ethernet(total_len);
    pkt.emit_back(&headers).unwrap();
    let dhcp_off = pkt.len();
    pkt.resize(total_len);
    let mut dhcp_pkt = DhcpPacket::new_checked(&mut pkt[dhcp_off..]).unwrap();
    msg.emit(&mut dhcp_pkt).unwrap();

    pkt
}

// Build a packet from a DHCPv6 message, from a client to server.
pub fn packet_from_client_dhcpv6_message(
    cfg: &VpcCfg,
    msg: &dhcpv6::protocol::Message<'_>,
) -> MsgBlk {
    let eth = Ethernet {
        destination: dhcpv6::ALL_RELAYS_AND_SERVERS.multicast_mac().unwrap(),
        source: cfg.guest_mac,
        ethertype: Ethertype::IPV6,
    };

    let ip = Ipv6 {
        source: Ipv6Addr::from_eui64(&cfg.guest_mac),
        destination: dhcpv6::ALL_RELAYS_AND_SERVERS,
        next_header: IpProtocol::UDP,
        payload_len: (msg.buffer_len() + Udp::MINIMUM_LENGTH) as u16,
        ..Default::default()
    };

    let udp = Udp {
        source: dhcpv6::CLIENT_PORT,
        destination: dhcpv6::SERVER_PORT,
        length: (UdpHdr::SIZE + msg.buffer_len()) as u16,
        ..Default::default()
    };

    write_dhcpv6_packet(eth, ip, udp, msg)
}

pub fn write_dhcpv6_packet(
    eth: Ethernet,
    ip: Ipv6,
    udp: Udp,
    msg: &dhcpv6::protocol::Message<'_>,
) -> MsgBlk {
    let headers = (eth, ip, udp);
    let total_len = msg.buffer_len() + headers.packet_length();

    let mut pkt = MsgBlk::new_ethernet(total_len);
    pkt.emit_back(&headers).unwrap();
    let dhcp_off = pkt.len();
    pkt.resize(total_len);
    msg.copy_into(&mut pkt[dhcp_off..]).unwrap();

    pkt
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

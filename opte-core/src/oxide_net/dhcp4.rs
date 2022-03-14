//! Oxide Network DHCPv4
//!
//! This implements DHCPv4 support allowing OPTE act as the gateway
//! for the guest without the need for static configuration.
//!
//! XXX rename layer to "gateway" for Virtual Gateway and move ARP and
//! ICMP code in here too. Then add high-value priority rule to drop
//! all traffic destined for gateway that doesn't match lower-value
//! priority rule; keeping gateway-bound packets from ending up on the
//! underlay.
use core::fmt::{self, Display};
use core::result::Result;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::sync::Arc;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::vec::Vec;

#[cfg(any(feature = "std", test))]
use std::sync::Arc;
#[cfg(any(feature = "std", test))]
use std::vec::Vec;

use smoltcp::wire::{DhcpPacket, DhcpRepr, EthernetAddress, Ipv4Address};

use crate::dhcp::{
    ClasslessStaticRouteOpt, MessageType as DhcpMessageType, SubnetRouterPair,
};
use crate::ether::{self, EtherAddr, EtherHdr, EtherMeta, ETHER_HDR_SZ};
use crate::ip4::{
    self, Ipv4Addr, Ipv4Cidr, Ipv4Hdr, Ipv4Meta, Protocol, IPV4_HDR_SZ,
};
use crate::layer::Layer;
use crate::packet::{
    Initialized, Packet, PacketMeta, PacketRead, PacketReader, Parsed,
};
use crate::port::{self, Port, Pos};
use crate::rule::{
    Action, DataPredicate, EtherAddrMatch, GenResult, HairpinAction,
    IpProtoMatch, Ipv4AddrMatch, PortMatch, Predicate, Rule,
};
use crate::udp::{UdpHdr, UdpMeta, UDP_HDR_SZ};
use crate::Direction;

pub fn setup(
    port: &mut Port<port::Inactive>,
    cfg: &super::PortCfg,
) -> Result<(), port::AddLayerError> {
    use smoltcp::wire::DhcpMessageType as SmolDMT;

    let offer = Action::Hairpin(Arc::new(Dhcp4Action {
        guest_mac: cfg.private_mac,
        guest_ip4: cfg.private_ip,
        gw_mac: cfg.gw_mac,
        gw_ip4: cfg.gw_ip,
        reply_type: Dhcp4ReplyType::Offer,
    }));
    let offer_idx = 0;

    let ack = Action::Hairpin(Arc::new(Dhcp4Action {
        guest_mac: cfg.private_mac,
        guest_ip4: cfg.private_ip,
        gw_mac: cfg.gw_mac,
        gw_ip4: cfg.gw_ip,
        reply_type: Dhcp4ReplyType::Ack,
    }));
    let ack_idx = 1;

    let dhcp = Layer::new("dhcp4", port.name(), vec![offer, ack]);

    let common = vec![
        Predicate::InnerEtherDst(vec![EtherAddrMatch::Exact(
            ether::ETHER_BROADCAST,
        )]),
        Predicate::InnerEtherSrc(vec![EtherAddrMatch::Exact(cfg.private_mac)]),
        Predicate::InnerSrcIp4(vec![Ipv4AddrMatch::Exact(ip4::ANY_ADDR)]),
        // XXX I believe DHCP can also come via subnet broadcast. Add
        // additional match for that.
        Predicate::InnerDstIp4(vec![Ipv4AddrMatch::Exact(
            ip4::LOCAL_BROADCAST,
        )]),
        Predicate::InnerIpProto(vec![IpProtoMatch::Exact(Protocol::UDP)]),
        Predicate::InnerDstPort(vec![PortMatch::Exact(67)]),
        Predicate::InnerSrcPort(vec![PortMatch::Exact(68)]),
    ];
    let dp_discover =
        DataPredicate::Dhcp4MsgType(DhcpMessageType::from(SmolDMT::Discover));
    let discover_rule = Rule::new(1, dhcp.action(offer_idx).unwrap().clone());
    let mut discover_rule = discover_rule.add_predicates(common.clone());
    discover_rule.add_data_predicate(dp_discover);
    dhcp.add_rule(Direction::Out, discover_rule.finalize());

    let dp_request =
        DataPredicate::Dhcp4MsgType(DhcpMessageType::from(SmolDMT::Request));
    let request_rule = Rule::new(1, dhcp.action(ack_idx).unwrap().clone());
    let mut request_rule = request_rule.add_predicates(common);
    request_rule.add_data_predicate(dp_request);
    dhcp.add_rule(Direction::Out, request_rule.finalize());

    port.add_layer(dhcp, Pos::Before("firewall"))
}

/// Respond to guest DHCPDISCOVER and DHCPREQUEST messages.
///
/// XXX Currently we return the same options no matter what the client
/// specifies in the parameter request list. This has worked thus far,
/// but we should come back to this and comb over RFC 2131 more
/// carefully -- particularly §4.3.1 and §4.3.2.
pub struct Dhcp4Action {
    guest_mac: EtherAddr,
    guest_ip4: Ipv4Addr,
    gw_mac: EtherAddr,
    gw_ip4: Ipv4Addr,
    reply_type: Dhcp4ReplyType,
}

#[derive(Clone, Copy, Debug)]
pub enum Dhcp4ReplyType {
    Offer,
    Ack,
}

impl Display for Dhcp4ReplyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Offer => write!(f, "OFFER"),
            Self::Ack => write!(f, "ACK"),
        }
    }
}

impl From<Dhcp4ReplyType> for DhcpMessageType {
    fn from(rt: Dhcp4ReplyType) -> Self {
        use smoltcp::wire::DhcpMessageType as SmolDMT;

        match rt {
            Dhcp4ReplyType::Offer => Self::from(SmolDMT::Offer),
            Dhcp4ReplyType::Ack => Self::from(SmolDMT::Ack),
        }
    }
}

impl Display for Dhcp4Action {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DHCPv4 {}: {}", self.reply_type, self.guest_ip4)
    }
}

impl HairpinAction for Dhcp4Action {
    fn gen_packet(
        &self,
        _meta: &PacketMeta,
        rdr: &mut PacketReader<Parsed, ()>,
    ) -> GenResult<Packet<Initialized>> {
        let body = rdr.copy_remaining();
        let guest_pkt = DhcpPacket::new_checked(&body)?;
        let guest_dhcp = DhcpRepr::parse(&guest_pkt)?;
        let mt = DhcpMessageType::from(self.reply_type);

        let reply = DhcpRepr {
            message_type: mt.into(),
            transaction_id: guest_dhcp.transaction_id,
            client_hardware_address: EthernetAddress::from(self.guest_mac),
            client_ip: Ipv4Address::UNSPECIFIED,
            your_ip: Ipv4Address::from(self.guest_ip4),
            server_ip: Ipv4Address::from(self.gw_ip4),
            router: Some(Ipv4Address::from(self.gw_ip4)),
            // Everything lives on its own /32-island in our VPC. You
            // wanna get somewhere? You better go talk to the gateway
            // aka OPTE.
            subnet_mask: Some(Ipv4Address::new(255, 255, 255, 255)),
            relay_agent_ip: Ipv4Address::UNSPECIFIED,
            broadcast: false,
            requested_ip: None,
            // The client identifier is an opaque token used by the
            // server, in combination with the chaddr, to uniquely
            // identify a client on the network in order to track its
            // lease status. Our world is much simpler: we are hooked
            // up directly to a guest's virtual interface, and we know
            // this IP is theirs until the port is torn down. There is
            // no tracking to do.
            client_identifier: None,
            server_identifier: Some(Ipv4Address::from(self.gw_ip4)),
            parameter_request_list: None,
            // XXX For now we at least resolve the internet.
            dns_servers: Some([Some(Ipv4Address::new(8, 8, 8, 8)), None, None]),
            max_size: None,
            lease_duration: Some(86400),
        };

        let reply_len = reply.buffer_len();

        let island_net = Ipv4Cidr::new(self.guest_ip4, 32).unwrap();
        let def_route = Ipv4Cidr::new(ip4::ANY_ADDR, 0).unwrap();
        let csr_opt = ClasslessStaticRouteOpt::new(
            SubnetRouterPair::new(island_net, ip4::ANY_ADDR),
            Some(SubnetRouterPair::new(def_route, self.gw_ip4)),
            None,
        );

        // XXX This is temporary until I can add interface to Packet
        // to initialize a zero'd mblk of N bytes and then get a
        // direct mutable reference to the PacketSeg.
        //
        // We provide exactly the number of bytes needed guaranteeing
        // that emit() should not fail.
        let mut tmp = vec![0u8; reply_len];
        let mut dhcp = DhcpPacket::new_unchecked(&mut tmp);
        let _ = reply.emit(&mut dhcp).unwrap();

        // Need to overwrite the End Option with Classless Static
        // Route Option and then write new End Option marker.
        assert_eq!(tmp.pop(), Some(255));
        tmp.extend_from_slice(&csr_opt.encode());
        tmp.push(255);
        assert_eq!(tmp.len(), reply_len + csr_opt.encode_len() as usize);

        let mut udp = UdpHdr::from(&UdpMeta { src: 67, dst: 68 });
        udp.set_pay_len(tmp.len() as u16);

        let mut ip4 = Ipv4Hdr::from(&Ipv4Meta {
            src: self.gw_ip4,
            dst: ip4::LOCAL_BROADCAST,
            proto: Protocol::UDP,
        });
        ip4.set_total_len(ip4.hdr_len() as u16 + udp.total_len());
        ip4.compute_hdr_csum();

        let eth = EtherHdr::from(&EtherMeta {
            dst: ether::ETHER_BROADCAST,
            src: self.gw_mac,
            ether_type: ether::ETHER_TYPE_IPV4,
        });

        let mut pkt_bytes = Vec::with_capacity(
            ETHER_HDR_SZ + IPV4_HDR_SZ + UDP_HDR_SZ + tmp.len(),
        );
        pkt_bytes.extend_from_slice(&eth.as_bytes());
        pkt_bytes.extend_from_slice(&ip4.as_bytes());
        pkt_bytes.extend_from_slice(&udp.as_bytes());
        pkt_bytes.extend_from_slice(&tmp);
        Ok(Packet::copy(&pkt_bytes))
    }
}

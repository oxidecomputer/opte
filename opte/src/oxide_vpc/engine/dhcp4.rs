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
use core::result::Result;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::sync::Arc;
    } else {
        use std::sync::Arc;
    }
}

use crate::api::{
    Dhcp4Action, Dhcp4ReplyType, Direction, Ipv4Addr, Ipv4PrefixLen, OpteError,
    SubnetRouterPair,
};
use crate::engine::dhcp::{MessageType as DhcpMessageType};
use crate::engine::ip4::Ipv4Cidr;
use crate::engine::layer::Layer;
use crate::engine::port::{self, Port, Pos};
use crate::engine::rule::{Action, Rule};
use crate::oxide_vpc::PortCfg;

pub fn setup(
    port: &mut Port<port::Inactive>,
    cfg: &PortCfg,
) -> Result<(), OpteError> {
    // All guest interfaces live on a `/32`-network in the Oxide VPC;
    // restricting the L2 domain to two links: the guest NIC and the
    // OPTE Port. This allows OPTE to act as the gateway for which all
    // guest traffic must cross, no matter the destination.
    let guest_cidr = Ipv4Cidr::new(cfg.private_ip, Ipv4PrefixLen::NETMASK_ALL);
    let re1 = SubnetRouterPair::new(guest_cidr, Ipv4Addr::ANY_ADDR);
    let re2 = SubnetRouterPair::new(
        Ipv4Cidr::new(Ipv4Addr::ANY_ADDR, Ipv4PrefixLen::NETMASK_NONE),
        cfg.gw_ip
    );

    let offer = Action::Hairpin(Arc::new(Dhcp4Action {
        client_mac: cfg.private_mac.into(),
        client_ip: cfg.private_ip,
        subnet_prefix_len: Ipv4PrefixLen::NETMASK_ALL,
        gw_mac: cfg.gw_mac.into(),
        gw_ip: cfg.gw_ip,
        reply_type: Dhcp4ReplyType::Offer,
        re1,
        re2: Some(re2),
        re3: None,
    }));
    let offer_idx = 0;

    let ack = Action::Hairpin(Arc::new(Dhcp4Action {
        client_mac: cfg.private_mac.into(),
        client_ip: cfg.private_ip,
        subnet_prefix_len: Ipv4PrefixLen::NETMASK_ALL,
        gw_mac: cfg.gw_mac.into(),
        gw_ip: cfg.gw_ip,
        reply_type: Dhcp4ReplyType::Ack,
        re1,
        re2: Some(re2),
        re3: None,
    }));
    let ack_idx = 1;

    let dhcp = Layer::new("dhcp4", port.name(), vec![offer, ack]);

    let discover_rule = Rule::new_implicit(
        1,
        dhcp.action(offer_idx).unwrap().clone()
    );
    dhcp.add_rule(Direction::Out, discover_rule.finalize());

    let request_rule = Rule::new_implicit(
        1,
        dhcp.action(ack_idx).unwrap().clone()
    );
    dhcp.add_rule(Direction::Out, request_rule.finalize());

    port.add_layer(dhcp, Pos::Before("firewall"))
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

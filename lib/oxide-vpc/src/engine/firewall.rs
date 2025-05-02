// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! The Oxide VPC firewall.
//!
//! This layer is responsible for implementing the VPC firewall as
//! described in RFD 21 §2.8.

use super::VpcNetwork;
use crate::api::AddFwRuleReq;
use crate::api::Address;
use crate::api::FirewallAction;
use crate::api::FirewallRule;
use crate::api::Ports;
pub use crate::api::ProtoFilter;
use crate::api::RemFwRuleReq;
use crate::api::SetFwRulesReq;
use crate::api::stat::*;
use crate::engine::overlay::ACTION_META_VNI;
use alloc::string::ToString;
use core::num::NonZeroU32;
use opte::api::Direction;
use opte::api::IpAddr;
use opte::api::IpCidr;
use opte::api::OpteError;
use opte::engine::ether::ETHER_TYPE_ARP;
use opte::engine::layer::DefaultAction;
use opte::engine::layer::Layer;
use opte::engine::layer::LayerActions;
use opte::engine::port::Port;
use opte::engine::port::PortBuilder;
use opte::engine::port::Pos;
use opte::engine::predicate::EtherTypeMatch;
use opte::engine::predicate::IpProtoMatch;
use opte::engine::predicate::Ipv4AddrMatch;
use opte::engine::predicate::Ipv6AddrMatch;
use opte::engine::predicate::PortMatch;
use opte::engine::predicate::Predicate;
use opte::engine::rule::Action;
use opte::engine::rule::Finalized;
use opte::engine::rule::Rule;

pub const FW_LAYER_NAME: &str = "firewall";

pub fn setup(
    pb: &mut PortBuilder,
    ft_limit: NonZeroU32,
) -> Result<(), OpteError> {
    // The inbound side of the firewall is a filtering layer, only
    // traffic explicitly allowed should pass. By setting the
    // default inbound action to deny we effectively implement the
    // implied "implied deny inbound" rule as speficied in RFD 63
    // §2.8.1.
    //
    // RFD 63 §2.8.1 also states that all outbond traffic should
    // be allowed by default, aka the "implied allow outbound"
    // rule. Therefore, we set the default outbound action to
    // allow.
    let actions = LayerActions {
        default_in: DefaultAction::Deny,
        default_in_stat_id: Some(FW_DEFAULT_IN),
        default_out: DefaultAction::StatefulAllow,
        default_out_stat_id: Some(FW_DEFAULT_OUT),
        ..Default::default()
    };

    let fw_layer = Layer::new(FW_LAYER_NAME, pb, actions, ft_limit);
    pb.add_layer(fw_layer, Pos::First)
}

pub fn add_fw_rule(
    port: &Port<VpcNetwork>,
    req: &AddFwRuleReq,
) -> Result<(), OpteError> {
    let action = match req.rule.action {
        FirewallAction::Allow => Action::StatefulAllow,
        FirewallAction::Deny => Action::Deny,
    };

    let rule = from_fw_rule(req.rule.clone(), action);
    port.add_rule(FW_LAYER_NAME, req.rule.direction, rule)
}

pub fn rem_fw_rule(
    port: &Port<VpcNetwork>,
    req: &RemFwRuleReq,
) -> Result<(), OpteError> {
    port.remove_rule(FW_LAYER_NAME, req.dir, req.id)
}

pub fn set_fw_rules(
    port: &Port<VpcNetwork>,
    req: &SetFwRulesReq,
) -> Result<(), OpteError> {
    let mut in_rules = vec![];
    let mut out_rules = vec![];

    for fwr in &req.rules {
        let action = match fwr.action {
            FirewallAction::Allow => Action::StatefulAllow,
            FirewallAction::Deny => Action::Deny,
        };

        let rule = from_fw_rule(fwr.clone(), action);
        if fwr.direction == Direction::In {
            in_rules.push(rule);
        } else {
            out_rules.push(rule);
        }
    }

    port.set_rules(FW_LAYER_NAME, in_rules, out_rules)
}

pub struct Firewall {}

pub fn from_fw_rule(fw_rule: FirewallRule, action: Action) -> Rule<Finalized> {
    let addr_pred = fw_rule.filters.hosts().into_predicate(fw_rule.direction);
    let proto_pred = fw_rule.filters.protocol().into_predicate();
    let port_pred = fw_rule.filters.ports().into_predicate();

    if addr_pred.is_none() && proto_pred.is_none() && port_pred.is_none() {
        return Rule::match_any(fw_rule.priority, action);
    }

    let mut rule = Rule::new(fw_rule.priority, action);

    if let Some(proto_pred) = proto_pred {
        rule.add_predicate(proto_pred);
    }

    if let Some(port_pred) = port_pred {
        rule.add_predicate(port_pred);
    }

    if let Some(addr_pred) = addr_pred {
        rule.add_predicate(addr_pred);
    }

    rule.finalize()
}

impl ProtoFilter {
    pub fn into_predicate(self) -> Option<Predicate> {
        match self {
            ProtoFilter::Any => None,

            ProtoFilter::Arp => {
                Some(Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(
                    ETHER_TYPE_ARP,
                )]))
            }

            ProtoFilter::Proto(p) => {
                Some(Predicate::InnerIpProto(vec![IpProtoMatch::Exact(p)]))
            }
        }
    }
}

impl Address {
    pub fn into_predicate(self, dir: Direction) -> Option<Predicate> {
        match (dir, self) {
            (_, Address::Any) => None,

            (Direction::Out, Address::Ip(IpAddr::Ip4(ip4))) => {
                Some(Predicate::InnerDstIp4(vec![Ipv4AddrMatch::Exact(ip4)]))
            }

            (Direction::Out, Address::Ip(IpAddr::Ip6(ip6))) => {
                Some(Predicate::InnerDstIp6(vec![Ipv6AddrMatch::Exact(ip6)]))
            }

            (Direction::In, Address::Ip(IpAddr::Ip4(ip4))) => {
                Some(Predicate::InnerSrcIp4(vec![Ipv4AddrMatch::Exact(ip4)]))
            }

            (Direction::In, Address::Ip(IpAddr::Ip6(ip6))) => {
                Some(Predicate::InnerSrcIp6(vec![Ipv6AddrMatch::Exact(ip6)]))
            }

            (Direction::Out, Address::Subnet(IpCidr::Ip4(ip4_sub))) => Some(
                Predicate::InnerDstIp4(vec![Ipv4AddrMatch::Prefix(ip4_sub)]),
            ),

            (Direction::Out, Address::Subnet(IpCidr::Ip6(ip6_sub))) => Some(
                Predicate::InnerDstIp6(vec![Ipv6AddrMatch::Prefix(ip6_sub)]),
            ),

            (Direction::In, Address::Subnet(IpCidr::Ip4(ip4_sub))) => Some(
                Predicate::InnerSrcIp4(vec![Ipv4AddrMatch::Prefix(ip4_sub)]),
            ),

            (Direction::In, Address::Subnet(IpCidr::Ip6(ip6_sub))) => Some(
                Predicate::InnerSrcIp6(vec![Ipv6AddrMatch::Prefix(ip6_sub)]),
            ),

            (_, Address::Vni(vni)) => Some(Predicate::Meta(
                ACTION_META_VNI.to_string(),
                vni.to_string(),
            )),
        }
    }
}

impl Ports {
    pub fn into_predicate(&self) -> Option<Predicate> {
        match self {
            Ports::Any => None,

            Ports::PortList(ports) => {
                let mlist =
                    ports.iter().map(|p| PortMatch::Exact(*p)).collect();
                Some(Predicate::InnerDstPort(mlist))
            }
        }
    }
}

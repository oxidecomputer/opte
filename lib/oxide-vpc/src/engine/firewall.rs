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
use crate::api::IcmpFilter;
use crate::api::Ports;
pub use crate::api::ProtoFilter;
use crate::api::RemFwRuleReq;
use crate::api::SetFwRulesReq;
use crate::engine::overlay::ACTION_META_VNI;
use alloc::collections::BTreeSet;
use alloc::string::ToString;
use alloc::vec::Vec;
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
use opte::engine::predicate::Match;
use opte::engine::predicate::Predicate;
use opte::engine::rule::Action;
use opte::engine::rule::Finalized;
use opte::engine::rule::Rule;

pub const FW_LAYER_NAME: &str = "firewall";

pub fn setup(
    pb: &mut PortBuilder,
    ft_limit: NonZeroU32,
) -> Result<(), OpteError> {
    let fw_layer = Firewall::create_layer(pb.name(), ft_limit);
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
    let proto_preds = fw_rule.filters.protocol().into_predicates();
    let port_pred = fw_rule.filters.ports().into_predicate();

    if addr_pred.is_none() && proto_preds.is_empty() && port_pred.is_none() {
        return Rule::match_any(fw_rule.priority, action);
    }

    let mut rule = Rule::new(fw_rule.priority, action);

    rule.add_predicates(proto_preds);

    if let Some(port_pred) = port_pred {
        rule.add_predicate(port_pred);
    }

    if let Some(addr_pred) = addr_pred {
        rule.add_predicate(addr_pred);
    }

    rule.finalize()
}

impl Firewall {
    pub fn create_layer(port_name: &str, ft_limit: NonZeroU32) -> Layer {
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
            actions: vec![],
            default_in: DefaultAction::Deny,
            default_out: DefaultAction::StatefulAllow,
        };

        Layer::new(FW_LAYER_NAME, port_name, actions, ft_limit)
    }
}

impl ProtoFilter {
    pub fn into_predicates(self) -> Vec<Predicate> {
        match self {
            // Non-L4 cases.
            ProtoFilter::Any => vec![],

            ProtoFilter::Arp => {
                vec![Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(
                    ETHER_TYPE_ARP,
                )])]
            }

            // L4 cases.
            ProtoFilter::Icmp(Some(filter)) => {
                let mut out = vec![
                    // Match::Exact(Protocol::ICMP) is validated in msg type/code.
                    Predicate::IcmpMsgType(vec![Match::Exact(
                        filter.ty.into(),
                    )]),
                ];

                if let Some(codes) = filter.codes {
                    out.push(Predicate::IcmpMsgCode(vec![codes.into()]));
                }

                out
            }

            ProtoFilter::Icmpv6(Some(filter)) => {
                let mut out = vec![
                    // Match::Exact(Protocol::ICMP) is validated in msg type/code.
                    Predicate::Icmpv6MsgType(vec![Match::Exact(
                        filter.ty.into(),
                    )]),
                ];

                if let Some(codes) = filter.codes {
                    out.push(Predicate::Icmpv6MsgCode(vec![codes.into()]));
                }

                out
            }

            other => {
                let proto = other
                    .l4_protocol()
                    .expect("handled all non-l4 cases above");
                vec![Predicate::InnerIpProto(vec![IpProtoMatch::Exact(proto)])]
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
                // TODO: We may want to reshape the controlplane API to make
                // this more direct. We'd probably still want to optimise what
                // they tell us at this stage, though.
                let ports: BTreeSet<_> = ports.iter().copied().collect();

                let mut mlist = vec![];
                let mut curr_range = None;
                for port in ports {
                    let range = curr_range.get_or_insert_with(|| port..=port);
                    let end = *range.end();
                    if port <= end {
                        // Created new.
                    } else if port == end + 1 {
                        // Extend range
                        *range = *range.start()..=port;
                    } else {
                        // Finalise.
                        let mut temp = port..=port;
                        core::mem::swap(&mut temp, range);
                        mlist.push(temp.into());
                    }
                }
                if let Some(range) = curr_range.take() {
                    mlist.push(range.into());
                }
                Some(Predicate::InnerDstPort(mlist))
            }
        }
    }
}

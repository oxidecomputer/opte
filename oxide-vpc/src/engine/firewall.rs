// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use core::fmt;
use core::num::NonZeroU32;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::{String, ToString};
        use alloc::sync::Arc;
        use alloc::vec::Vec;
    } else {
        use std::string::{String, ToString};
        use std::sync::Arc;
        use std::vec::Vec;
    }
}

use crate::api::Action;
use crate::api::AddFwRuleReq;
use crate::api::Address;
use crate::api::FirewallRule;
use crate::api::Ports;
pub use crate::api::ProtoFilter;
use crate::api::RemFwRuleReq;
use crate::api::SetFwRulesReq;
use opte::api::Direction;
use opte::api::OpteError;
use opte::engine::layer::DefaultAction;
use opte::engine::layer::Layer;
use opte::engine::layer::LayerActions;
use opte::engine::packet::InnerFlowId;
use opte::engine::packet::Packet;
use opte::engine::packet::Parsed;
use opte::engine::port::meta::ActionMeta;
use opte::engine::port::Port;
use opte::engine::port::PortBuilder;
use opte::engine::port::Pos;
use opte::engine::rule;
use opte::engine::rule::AllowOrDeny;
use opte::engine::rule::DataPredicate;
use opte::engine::rule::IdentityDesc;
use opte::engine::rule::IpProtoMatch;
use opte::engine::rule::Ipv4AddrMatch;
use opte::engine::rule::PortMatch;
use opte::engine::rule::Predicate;
use opte::engine::rule::Rule;
use opte::engine::rule::StatefulAction;

pub const FW_LAYER_NAME: &'static str = "firewall";

pub fn setup(
    pb: &mut PortBuilder,
    ft_limit: NonZeroU32,
) -> Result<(), OpteError> {
    let fw_layer = Firewall::create_layer(pb.name(), ft_limit);
    pb.add_layer(fw_layer, Pos::First)
}

pub fn add_fw_rule(port: &Port, req: &AddFwRuleReq) -> Result<(), OpteError> {
    let action = match req.rule.action {
        Action::Allow => port.layer_action(FW_LAYER_NAME, 0).unwrap().clone(),

        Action::Deny => rule::Action::Deny,
    };

    let rule = from_fw_rule(req.rule.clone(), action);
    port.add_rule(FW_LAYER_NAME, req.rule.direction, rule)
}

pub fn rem_fw_rule(port: &Port, req: &RemFwRuleReq) -> Result<(), OpteError> {
    port.remove_rule(FW_LAYER_NAME, req.dir, req.id)
}

pub fn set_fw_rules(port: &Port, req: &SetFwRulesReq) -> Result<(), OpteError> {
    let mut in_rules = vec![];
    let mut out_rules = vec![];

    for fwr in &req.rules {
        let action = match fwr.action {
            Action::Allow => {
                port.layer_action(FW_LAYER_NAME, 0).unwrap().clone()
            }

            Action::Deny => rule::Action::Deny,
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

pub fn from_fw_rule(
    fw_rule: FirewallRule,
    action: rule::Action,
) -> Rule<rule::Finalized> {
    let addr_pred = fw_rule.filters.hosts().into_predicate(fw_rule.direction);
    let proto_pred = fw_rule.filters.protocol().into_predicate();
    let port_pred = fw_rule.filters.ports().into_predicate();

    if addr_pred.is_none() && proto_pred.is_none() && port_pred.is_none() {
        return Rule::match_any(fw_rule.priority, action);
    }

    let mut rule = Rule::new(fw_rule.priority, action);

    if proto_pred.is_some() {
        rule.add_predicate(proto_pred.unwrap());
    }

    if port_pred.is_some() {
        rule.add_predicate(port_pred.unwrap());
    }

    if addr_pred.is_some() {
        rule.add_predicate(addr_pred.unwrap());
    }

    rule.finalize()
}

pub struct FwStatefulAction {
    name: String,
}

impl FwStatefulAction {
    fn new(name: String) -> Self {
        FwStatefulAction { name }
    }
}

impl fmt::Display for FwStatefulAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Firewall")
    }
}

impl StatefulAction for FwStatefulAction {
    fn gen_desc(
        &self,
        _flow_id: &InnerFlowId,
        _pkt: &Packet<Parsed>,
        _meta: &mut ActionMeta,
    ) -> rule::GenDescResult {
        Ok(AllowOrDeny::Allow(Arc::new(IdentityDesc::new(self.name.clone()))))
    }

    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        (vec![], vec![])
    }
}

impl Firewall {
    pub fn create_layer(port_name: &str, ft_limit: NonZeroU32) -> Layer {
        // The allow action is currently stateful, causing an entry to
        // be created in the flow table for each flow allowed by the
        // firewall.
        let allow = rule::Action::Stateful(Arc::new(FwStatefulAction::new(
            "fw".to_string(),
        )));

        // The firewall layer is meant as a filtering layer, and thus
        // denies all traffic by default.
        let actions = LayerActions {
            actions: vec![allow],
            default_in: DefaultAction::Deny,
            default_out: DefaultAction::Deny,
        };

        Layer::new(FW_LAYER_NAME, port_name, actions, ft_limit)
    }
}

impl ProtoFilter {
    pub fn into_predicate(self) -> Option<Predicate> {
        match self {
            ProtoFilter::Any => None,

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

            (Direction::Out, Address::Ip(ip4)) => {
                Some(Predicate::InnerDstIp4(vec![Ipv4AddrMatch::Exact(ip4)]))
            }

            (Direction::In, Address::Ip(ip4)) => {
                Some(Predicate::InnerSrcIp4(vec![Ipv4AddrMatch::Exact(ip4)]))
            }

            (Direction::Out, Address::Subnet(ip4_sub)) => Some(
                Predicate::InnerDstIp4(vec![Ipv4AddrMatch::Prefix(ip4_sub)]),
            ),

            (Direction::In, Address::Subnet(ip4_sub)) => Some(
                Predicate::InnerSrcIp4(vec![Ipv4AddrMatch::Prefix(ip4_sub)]),
            ),
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

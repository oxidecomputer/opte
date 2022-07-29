// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! The Oxide Network VPC Router.
//!
//! This implements both the Oxide Network VPC "System Router" and
//! "Custom Router" abstractions, as described in RFD 21 §2.3.
use core::fmt;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::ToString;
        use alloc::sync::Arc;
        use alloc::vec::Vec;
    } else {
        use std::string::ToString;
        use std::sync::Arc;
        use std::vec::Vec;
    }
}

use super::firewall as fw;
use crate::api::{Direction, NoResp, OpteError};
use crate::engine::headers::{IpAddr, IpCidr};
use crate::engine::layer::{InnerFlowId, Layer};
use crate::engine::port::{meta::Meta, Port, PortBuilder, Pos};
use crate::engine::rule::{
    self, Action, AllowOrDeny, Finalized, MetaAction, ModMetaResult, Predicate,
    Rule,
};
use crate::oxide_vpc::api::{DelRouterEntryIpv4Resp, RouterTarget};
use crate::oxide_vpc::VpcCfg;

pub const ROUTER_LAYER_NAME: &'static str = "router";

// The control plane wants to define "no destination" as a router
// target. This routing layer implementation converts said target to a
// `Rule` paired with `Action::Deny`. The MetaAction wants an internal
// version of the router target without the "drop" target to match the
// remaining possible targets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouterTargetInternal {
    InternetGateway,
    Ip(IpAddr),
    VpcSubnet(IpCidr),
}

impl crate::engine::rule::MetaPredicate for RouterTargetInternal {
    fn is_match(&self, meta: &Meta) -> bool {
        if let Some(tgt) = meta.get::<Self>() {
            if self == tgt {
                return true;
            }
        }

        false
    }
}

impl fmt::Display for RouterTargetInternal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Self::InternetGateway => "IG".to_string(),
            Self::Ip(addr) => format!("IP: {}", addr),
            Self::VpcSubnet(sub) => format!("Subnet: {}", sub),
        };
        write!(f, "{}", s)
    }
}

// The array index represents the subnet prefix length (thus the need
// for 33 entries). The value represents the Rule priority.
fn build_ip4_len_to_pri() -> [u16; 33] {
    let mut v = [0; 33];
    for (i, pri) in (0..33).rev().enumerate() {
        v[i] = pri + 10;
    }
    v
}

pub fn setup(
    pb: &PortBuilder,
    _cfg: &VpcCfg,
    ft_limit: core::num::NonZeroU32,
) -> Result<(), OpteError> {
    let ig = Action::Meta(Arc::new(RouterAction::new(
        RouterTargetInternal::InternetGateway,
    )));

    // Indexes:
    //
    // * 0: InternetGateway
    let layer = Layer::new(ROUTER_LAYER_NAME, pb.name(), vec![ig], ft_limit);

    // If there is no matching router entry we drop the packet.
    let drop_rule = Rule::match_any(65535, rule::Action::Deny);
    layer.add_rule(Direction::Out, drop_rule);
    pb.add_layer(layer, Pos::After(fw::FW_LAYER_NAME))
}

fn make_rule(
    dest: IpCidr,
    target: RouterTarget,
) -> Result<Rule<Finalized>, OpteError> {
    let pri_map4 = build_ip4_len_to_pri();

    match target {
        RouterTarget::Drop => match dest {
            IpCidr::Ip4(ip4) => {
                let mut rule = Rule::new(
                    pri_map4[ip4.prefix_len() as usize],
                    Action::Deny,
                );
                rule.add_predicate(Predicate::InnerDstIp4(vec![
                    rule::Ipv4AddrMatch::Prefix(ip4),
                ]));
                Ok(rule.finalize())
            }

            IpCidr::Ip6(_) => todo!("IPv6 drop"),
        },

        RouterTarget::InternetGateway => {
            if !dest.is_default() {
                return Err(OpteError::InvalidRouteDest(dest.to_string()));
            }

            match dest {
                IpCidr::Ip4(ip4) => {
                    let mut rule = Rule::new(
                        pri_map4[dest.prefix_len()],
                        Action::Meta(Arc::new(RouterAction::new(
                            RouterTargetInternal::InternetGateway,
                        ))),
                    );
                    rule.add_predicate(Predicate::InnerDstIp4(vec![
                        rule::Ipv4AddrMatch::Prefix(ip4),
                    ]));
                    Ok(rule.finalize())
                }

                IpCidr::Ip6(_) => todo!("IPv6 IG"),
            }
        }

        RouterTarget::Ip(ip) => match dest {
            IpCidr::Ip4(ip4) => {
                let mut rule = Rule::new(
                    pri_map4[ip4.prefix_len() as usize],
                    Action::Meta(Arc::new(RouterAction::new(
                        RouterTargetInternal::Ip(ip),
                    ))),
                );
                rule.add_predicate(Predicate::InnerDstIp4(vec![
                    rule::Ipv4AddrMatch::Prefix(ip4),
                ]));
                Ok(rule.finalize())
            }

            IpCidr::Ip6(_) => todo!("IPv6 IP"),
        },

        RouterTarget::VpcSubnet(vpc) => match dest {
            IpCidr::Ip4(ip4) => {
                let mut rule = Rule::new(
                    pri_map4[ip4.prefix_len() as usize],
                    Action::Meta(Arc::new(RouterAction::new(
                        RouterTargetInternal::VpcSubnet(vpc),
                    ))),
                );
                rule.add_predicate(Predicate::InnerDstIp4(vec![
                    rule::Ipv4AddrMatch::Prefix(ip4),
                ]));
                Ok(rule.finalize())
            }

            IpCidr::Ip6(_) => todo!("IPv6 router entry"),
        },
    }
}

pub fn del_entry(
    port: &Port,
    dest: IpCidr,
    target: RouterTarget,
) -> Result<DelRouterEntryIpv4Resp, OpteError> {
    let rule = make_rule(dest, target)?;
    let maybe_id = port.find_rule(ROUTER_LAYER_NAME, Direction::Out, &rule)?;
    match maybe_id {
        Some(id) => {
            port.remove_rule(ROUTER_LAYER_NAME, Direction::Out, id)?;
            Ok(DelRouterEntryIpv4Resp::Ok)
        }

        None => Ok(DelRouterEntryIpv4Resp::NotFound),
    }
}

pub fn add_entry(
    port: &Port,
    dest: IpCidr,
    target: RouterTarget,
) -> Result<NoResp, OpteError> {
    let rule = make_rule(dest, target)?;
    port.add_rule(ROUTER_LAYER_NAME, Direction::Out, rule)?;
    Ok(NoResp::default())
}

// TODO For each router table entry we should mark whether it came
// from system or custom.
//
// TODO I may want to have different types of rule/flow tables a layer
// can have. Up to this point the tables consist of `Rule` entires;
// matching arbitrary header predicates to a `RuleAction`. I may want
// to also have more switch-like MATs which match one specific header
// field to an action. For example a table which matches
// longest-prefix-match of the packet's IP destination.
//
// VFP §5.4 ("Groups") talks about using longest prefix match for
// Layer Groups (I still haven't implemented groups).
//
// VFP §6.5 ("Packet Classification"), talks about the ability for
// each condition type to use 1 of 4 different types of classifiers.
pub struct RouterAction {
    // system_table: RouterTable,
    // subnet_table: Option<RouterTable>,
    target: RouterTargetInternal,
}

impl RouterAction {
    fn new(target: RouterTargetInternal) -> Self {
        Self { target }
    }
}

impl fmt::Display for RouterAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Target = {}", self.target)
    }
}

impl MetaAction for RouterAction {
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<rule::DataPredicate>) {
        (vec![], vec![])
    }

    fn mod_meta(
        &self,
        _flow_id: &InnerFlowId,
        meta: &mut Meta,
    ) -> ModMetaResult {
        // No target entry should currently exist in the metadata; it
        // would be a bug. However, because of the dynamic nature of
        // metadata we don't have an easy way to enforce this
        // constraint in the type system. Rather than use the
        // `Meta::add()` method and pollute the code with unwrap, we
        // instead choose to use the `Meta::replace()` API.
        meta.replace(self.target);
        Ok(AllowOrDeny::Allow(()))
    }
}

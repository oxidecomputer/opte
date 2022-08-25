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
        use alloc::string::{String, ToString};
        use alloc::sync::Arc;
        use alloc::vec::Vec;
    } else {
        use std::string::{String, ToString};
        use std::sync::Arc;
        use std::vec::Vec;
    }
}

use super::firewall as fw;
use crate::api::{DelRouterEntryResp, RouterTarget, VpcCfg};
use opte::api::{
    Direction, Ipv4Addr, Ipv4Cidr, Ipv6Addr, Ipv6Cidr, NoResp, OpteError,
};
use opte::engine::headers::{IpAddr, IpCidr};
use opte::engine::layer::{InnerFlowId, Layer};
use opte::engine::port::meta::{ActionMeta, ActionMetaValue};
use opte::engine::port::{Port, PortBuilder, Pos};
use opte::engine::rule::{
    self, Action, AllowOrDeny, Finalized, MetaAction, ModMetaResult, Predicate,
    Rule,
};

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

impl ActionMetaValue for RouterTargetInternal {
    const KEY: &'static str = "router-target";

    fn from_meta(s: &str) -> Result<Self, String> {
        match s {
            "ig" => Ok(Self::InternetGateway),

            _ => match s.split_once("=") {
                Some(("ip4", ip4_s)) => {
                    let ip4 = ip4_s.parse::<Ipv4Addr>()?;
                    Ok(Self::Ip(IpAddr::Ip4(ip4)))
                }

                Some(("ip6", ip6_s)) => {
                    let ip6 = ip6_s.parse::<Ipv6Addr>()?;
                    Ok(Self::Ip(IpAddr::Ip6(ip6)))
                }

                Some(("sub4", cidr4_s)) => {
                    let cidr4 = cidr4_s.parse::<Ipv4Cidr>()?;
                    Ok(Self::VpcSubnet(IpCidr::Ip4(cidr4)))
                }

                Some(("sub6", cidr6_s)) => {
                    let cidr6 = cidr6_s.parse::<Ipv6Cidr>()?;
                    Ok(Self::VpcSubnet(IpCidr::Ip6(cidr6)))
                }

                _ => Err(format!("bad router target: {}", s)),
            },
        }
    }

    fn as_meta(&self) -> String {
        match self {
            Self::InternetGateway => "ig".to_string(),
            Self::Ip(IpAddr::Ip4(ip4)) => format!("ip4={}", ip4),
            Self::Ip(IpAddr::Ip6(ip6)) => format!("ip6={}", ip6),
            Self::VpcSubnet(IpCidr::Ip4(cidr4)) => format!("sub4={}", cidr4),
            Self::VpcSubnet(IpCidr::Ip6(cidr6)) => format!("sub6={}", cidr6),
        }
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

// Return a priority for an IP subnet, depending on its prefix length.
//
// The priority is computed as `max_prefix_len - prefix_len + 10`, where
// `max_prefix_len` is the maximum prefix length for the CIDR block of each IP
// version.
fn prefix_len_to_priority(cidr: &IpCidr) -> u16 {
    use opte::api::ip::IpCidr::*;
    use opte::api::ip::Ipv4PrefixLen;
    use opte::api::ip::Ipv6PrefixLen;
    let (max_prefix_len, prefix_len) = match cidr {
        Ip4(ipv4) => (Ipv4PrefixLen::NETMASK_ALL.val(), ipv4.prefix_len()),
        Ip6(ipv6) => (Ipv6PrefixLen::NETMASK_ALL.val(), ipv6.prefix_len()),
    };
    (max_prefix_len - prefix_len) as u16 + 10
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
    let mut layer =
        Layer::new(ROUTER_LAYER_NAME, pb.name(), vec![ig], ft_limit);

    // If there is no matching router entry we drop the packet.
    let drop_rule = Rule::match_any(65535, rule::Action::Deny);
    layer.add_rule(Direction::Out, drop_rule);
    pb.add_layer(layer, Pos::After(fw::FW_LAYER_NAME))
}

fn valid_router_dest_target_pair(dest: &IpCidr, target: &RouterTarget) -> bool {
    matches!(
        (&dest, &target),
        // Anything can go to the gateway or be dropped
        (_, RouterTarget::Drop) |
        (_, RouterTarget::InternetGateway) |
        // IPv4 destination, IPv4 address
        (IpCidr::Ip4(_), RouterTarget::Ip(IpAddr::Ip4(_))) |
        // IPv4 destination, IPv4 subnet
        (IpCidr::Ip4(_), RouterTarget::VpcSubnet(IpCidr::Ip4(_))) |
        // IPv6 destination, IPv6 address
        (IpCidr::Ip6(_), RouterTarget::Ip(IpAddr::Ip6(_))) |
        // IPv6 destination, IPv6 subnet
        (IpCidr::Ip6(_), RouterTarget::VpcSubnet(IpCidr::Ip6(_)))
    )
}

fn make_rule(
    dest: IpCidr,
    target: RouterTarget,
) -> Result<Rule<Finalized>, OpteError> {
    if !valid_router_dest_target_pair(&dest, &target) {
        return Err(OpteError::InvalidRouteDest(String::from(
            "Invalid destination/target pair for router. \
            Routes must match in their IP protocol versions.",
        )));
    }

    let priority = prefix_len_to_priority(&dest);
    match target {
        RouterTarget::Drop => {
            let predicate =
                match dest {
                    IpCidr::Ip4(ip4) => Predicate::InnerDstIp4(vec![
                        rule::Ipv4AddrMatch::Prefix(ip4),
                    ]),

                    IpCidr::Ip6(ip6) => Predicate::InnerDstIp6(vec![
                        rule::Ipv6AddrMatch::Prefix(ip6),
                    ]),
                };
            let mut rule = Rule::new(priority, Action::Deny);
            rule.add_predicate(predicate);
            Ok(rule.finalize())
        }

        RouterTarget::InternetGateway => {
            if !dest.is_default() {
                return Err(OpteError::InvalidRouteDest(dest.to_string()));
            }
            let predicate =
                match dest {
                    IpCidr::Ip4(ip4) => Predicate::InnerDstIp4(vec![
                        rule::Ipv4AddrMatch::Prefix(ip4),
                    ]),

                    IpCidr::Ip6(ip6) => Predicate::InnerDstIp6(vec![
                        rule::Ipv6AddrMatch::Prefix(ip6),
                    ]),
                };
            let mut rule = Rule::new(
                priority,
                Action::Meta(Arc::new(RouterAction::new(
                    RouterTargetInternal::InternetGateway,
                ))),
            );
            rule.add_predicate(predicate);
            Ok(rule.finalize())
        }

        RouterTarget::Ip(ip) => {
            let predicate =
                match dest {
                    IpCidr::Ip4(ip4) => Predicate::InnerDstIp4(vec![
                        rule::Ipv4AddrMatch::Prefix(ip4),
                    ]),

                    IpCidr::Ip6(ip6) => Predicate::InnerDstIp6(vec![
                        rule::Ipv6AddrMatch::Prefix(ip6),
                    ]),
                };
            let mut rule = Rule::new(
                priority,
                Action::Meta(Arc::new(RouterAction::new(
                    RouterTargetInternal::Ip(ip),
                ))),
            );
            rule.add_predicate(predicate);
            Ok(rule.finalize())
        }

        RouterTarget::VpcSubnet(vpc) => {
            let predicate =
                match dest {
                    IpCidr::Ip4(ip4) => Predicate::InnerDstIp4(vec![
                        rule::Ipv4AddrMatch::Prefix(ip4),
                    ]),

                    IpCidr::Ip6(ip6) => Predicate::InnerDstIp6(vec![
                        rule::Ipv6AddrMatch::Prefix(ip6),
                    ]),
                };
            let mut rule = Rule::new(
                priority,
                Action::Meta(Arc::new(RouterAction::new(
                    RouterTargetInternal::VpcSubnet(vpc),
                ))),
            );
            rule.add_predicate(predicate);
            Ok(rule.finalize())
        }
    }
}

pub fn del_entry(
    port: &Port,
    dest: IpCidr,
    target: RouterTarget,
) -> Result<DelRouterEntryResp, OpteError> {
    let rule = make_rule(dest, target)?;
    let maybe_id = port.find_rule(ROUTER_LAYER_NAME, Direction::Out, &rule)?;
    match maybe_id {
        Some(id) => {
            port.remove_rule(ROUTER_LAYER_NAME, Direction::Out, id)?;
            Ok(DelRouterEntryResp::Ok)
        }

        None => Ok(DelRouterEntryResp::NotFound),
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
        meta: &mut ActionMeta,
    ) -> ModMetaResult {
        // No target entry should currently exist in the metadata; it
        // would be a bug. However, because of the dynamic nature of
        // metadata we don't have an easy way to enforce this
        // constraint in the type system.
        meta.insert(self.target.key(), self.target.as_meta());
        Ok(AllowOrDeny::Allow(()))
    }
}

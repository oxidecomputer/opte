// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! The Oxide Network VPC Router.
//!
//! This implements both the Oxide Network VPC "System Router" and
//! "Custom Router" abstractions, as described in RFD 21 §2.3.
use super::VpcNetwork;
use super::firewall as fw;
use crate::api::DelRouterEntryResp;
use crate::api::RouterClass;
use crate::api::RouterTarget;
use crate::cfg::VpcCfg;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use opte::api::Direction;
use opte::api::Ipv4Addr;
use opte::api::Ipv4Cidr;
use opte::api::Ipv6Addr;
use opte::api::Ipv6Cidr;
use opte::api::NoResp;
use opte::api::OpteError;
use opte::engine::headers::IpAddr;
use opte::engine::headers::IpCidr;
use opte::engine::layer::DefaultAction;
use opte::engine::layer::Layer;
use opte::engine::layer::LayerActions;
use opte::engine::packet::InnerFlowId;
use opte::engine::port::Port;
use opte::engine::port::PortBuilder;
use opte::engine::port::Pos;
use opte::engine::port::meta::ActionMeta;
use opte::engine::port::meta::ActionMetaValue;
use opte::engine::predicate::DataPredicate;
use opte::engine::predicate::Ipv4AddrMatch;
use opte::engine::predicate::Ipv6AddrMatch;
use opte::engine::predicate::Predicate;
use opte::engine::rule::Action;
use opte::engine::rule::AllowOrDeny;
use opte::engine::rule::Finalized;
use opte::engine::rule::MetaAction;
use opte::engine::rule::ModMetaResult;
use opte::engine::rule::Rule;
use uuid::Uuid;

pub const ROUTER_LAYER_NAME: &str = "router";

// The control plane wants to define "no destination" as a router
// target. This routing layer implementation converts said target to a
// `Rule` paired with `Action::Deny`. The MetaAction wants an internal
// version of the router target without the "drop" target to match the
// remaining possible targets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouterTargetInternal {
    // The selected internet gateway determines a packet's chosen source
    // address during NAT. We don't necessarily *know* the ID of this
    // gateway.
    InternetGateway(Option<Uuid>),
    Ip(IpAddr),
    VpcSubnet(IpCidr),
}

impl RouterTargetInternal {
    pub const IP_KEY: &'static str = "router-target-ip";
    pub const GENERIC_META: &'static str = "ig";

    pub fn generic_meta(&self) -> String {
        Self::GENERIC_META.to_string()
    }

    pub fn ip_key(&self) -> String {
        Self::IP_KEY.to_string()
    }

    pub fn class(&self) -> RouterTargetClass {
        match self {
            RouterTargetInternal::InternetGateway(_) => {
                RouterTargetClass::InternetGateway
            }
            RouterTargetInternal::Ip(_) => RouterTargetClass::Ip,
            RouterTargetInternal::VpcSubnet(_) => RouterTargetClass::VpcSubnet,
        }
    }
}

impl ActionMetaValue for RouterTargetInternal {
    const KEY: &'static str = "router-target";

    fn from_meta(s: &str) -> Result<Self, String> {
        match s {
            "ig" => Ok(Self::InternetGateway(None)),
            _ => match s.split_once('=') {
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

                Some(("ig", ig)) => {
                    let ig = ig.parse::<Uuid>().map_err(|e| e.to_string())?;
                    Ok(Self::InternetGateway(Some(ig)))
                }

                _ => Err(format!("bad router target: {}", s)),
            },
        }
    }

    fn as_meta(&self) -> String {
        match self {
            Self::InternetGateway(ip) => match ip {
                Some(ip) => format!("ig={}", ip),
                None => String::from("ig"),
            },
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
            Self::InternetGateway(addr) => format!("IG({:?})", addr),
            Self::Ip(addr) => format!("IP: {}", addr),
            Self::VpcSubnet(sub) => format!("Subnet: {}", sub),
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouterTargetClass {
    InternetGateway,
    Ip,
    VpcSubnet,
}

impl ActionMetaValue for RouterTargetClass {
    const KEY: &'static str = "router-target-class";

    fn from_meta(s: &str) -> Result<Self, String> {
        match s {
            "ig" => Ok(Self::InternetGateway),
            "ip" => Ok(Self::Ip),
            "subnet" => Ok(Self::VpcSubnet),
            _ => Err(format!("bad router target class: {}", s)),
        }
    }

    fn as_meta(&self) -> String {
        match self {
            Self::InternetGateway => "ig".into(),
            Self::Ip => "ip".into(),
            Self::VpcSubnet => "subnet".into(),
        }
    }
}

impl fmt::Display for RouterTargetClass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InternetGateway => write!(f, "IG"),
            Self::Ip => write!(f, "IP"),
            Self::VpcSubnet => write!(f, "Subnet"),
        }
    }
}

// Return the priority for a given IP subnet. The priority is based on
// the subnet's prefix length and the type of router the rule belongs to.
// Specifically, it is given the following value:
//
// ```
// priority = (((max_prefix_len - prefix len) << 1) | is_system) + 10
// ```
//
// `max_prefix_len` is the maximum prefix length for a given IP
// CIDR type: `32` for IPv4, `128` for IPv6.
//
// `prefix_len` comes from the passed in `cidr` argument.
//
// One bit is used to ensure that 'custom' router rules take precedence
// over 'system' rules when all other factors are equal.
//
// The constant `10` displaces these rules so they start at a priority
// of `10`. This allows placing higher priority rules (lower number)
// to override them, if needed.
//
// # IPv4
//
// ```
// |Prefix Len |System?|Priority                       |
// |-----------|-------|-------------------------------|
// |32         |0      |10 = ((32 - 32) << 1 | 0) + 10 |
// |32         |1      |11 = ((32 - 32) << 1 | 1) + 10 |
// |31         |0      |12 = ((32 - 31) << 1 | 0) + 10 |
// |30         |0      |14 = ((32 - 30) << 1 | 0) + 10 |
// |...        |...    |...                            |
// |0          |0      |74 = ((32 - 0) << 1 | 0) + 10  |
// |0          |1      |75 = ((32 - 0) << 1 | 1) + 10  |
// ```
//
// # IPv6
//
// ```
// |Prefix Len |System?|Priority                         |
// |-----------|-------|---------------------------------|
// |128        |0      |10 = ((128 - 128) << 1 | 0) + 10 |
// |128        |1      |11 = ((128 - 128) << 1 | 1) + 10 |
// |127        |0      |12 = ((128 - 127) << 1 | 0) + 10 |
// |126        |0      |14 = ((128 - 126) << 1 | 0) + 10 |
// |...        |...    |...                              |
// |0          |0      |266 = ((128 - 0) << 1 | 0) + 10  |
// |0          |1      |267 = ((128 - 0) << 1 | 1) + 10  |
// ```
fn compute_rule_priority(cidr: &IpCidr, class: RouterClass) -> u16 {
    let max_prefix_len = cidr.max_prefix_len();
    let prefix_len = cidr.prefix_len();
    let class_prio = match class {
        RouterClass::Custom => 0,
        RouterClass::System => 1,
    };
    ((((max_prefix_len - prefix_len) as u16) << 1) | class_prio) + 10
}

pub fn setup(
    pb: &PortBuilder,
    _cfg: &VpcCfg,
    ft_limit: core::num::NonZeroU32,
) -> Result<(), OpteError> {
    // Inbound: The router assumes that if the packet made it here,
    // then it had a route to get here.
    //
    // Outbound: If there is no matching route, then the packet should
    // make it no further.
    let actions = LayerActions {
        actions: vec![],
        default_in: DefaultAction::Allow,
        default_out: DefaultAction::Deny,
    };

    let layer = Layer::new(ROUTER_LAYER_NAME, pb.name(), actions, ft_limit);
    pb.add_layer(layer, Pos::After(fw::FW_LAYER_NAME))
}

fn valid_router_dest_target_pair(dest: &IpCidr, target: &RouterTarget) -> bool {
    matches!(
        (&dest, &target),
        // Anything can be dropped
        (_, RouterTarget::Drop) |
        // Internet gateways are valid for any IP family.
        (_, RouterTarget::InternetGateway(_)) |
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
    class: RouterClass,
) -> Result<Rule<Finalized>, OpteError> {
    if !valid_router_dest_target_pair(&dest, &target) {
        return Err(OpteError::InvalidRouterEntry {
            dest,
            target: target.to_string(),
        });
    }

    let (predicate, action) = match target {
        RouterTarget::Drop => {
            let predicate = match dest {
                IpCidr::Ip4(ip4) => {
                    Predicate::InnerDstIp4(vec![Ipv4AddrMatch::Prefix(ip4)])
                }

                IpCidr::Ip6(ip6) => {
                    Predicate::InnerDstIp6(vec![Ipv6AddrMatch::Prefix(ip6)])
                }
            };
            (predicate, Action::Deny)
        }

        RouterTarget::InternetGateway(id) => {
            let predicate = match dest {
                IpCidr::Ip4(ip4) => {
                    Predicate::InnerDstIp4(vec![Ipv4AddrMatch::Prefix(ip4)])
                }

                IpCidr::Ip6(ip6) => {
                    Predicate::InnerDstIp6(vec![Ipv6AddrMatch::Prefix(ip6)])
                }
            };
            let action = Action::Meta(Arc::new(RouterAction::new(
                RouterTargetInternal::InternetGateway(id),
            )));
            (predicate, action)
        }

        RouterTarget::Ip(ip) => {
            let predicate = match dest {
                IpCidr::Ip4(ip4) => {
                    Predicate::InnerDstIp4(vec![Ipv4AddrMatch::Prefix(ip4)])
                }

                IpCidr::Ip6(ip6) => {
                    Predicate::InnerDstIp6(vec![Ipv6AddrMatch::Prefix(ip6)])
                }
            };
            let action = Action::Meta(Arc::new(RouterAction::new(
                RouterTargetInternal::Ip(ip),
            )));
            (predicate, action)
        }

        RouterTarget::VpcSubnet(vpc) => {
            let predicate = match dest {
                IpCidr::Ip4(ip4) => {
                    Predicate::InnerDstIp4(vec![Ipv4AddrMatch::Prefix(ip4)])
                }

                IpCidr::Ip6(ip6) => {
                    Predicate::InnerDstIp6(vec![Ipv6AddrMatch::Prefix(ip6)])
                }
            };
            let action = Action::Meta(Arc::new(RouterAction::new(
                RouterTargetInternal::VpcSubnet(vpc),
            )));
            (predicate, action)
        }
    };

    let priority = compute_rule_priority(&dest, class);
    let mut rule = Rule::new(priority, action);
    rule.add_predicate(predicate);

    Ok(rule.finalize())
}

/// Delete a router entry.
///
/// For the entry to be deleted it must match exactly for the
/// destination [`IpCidr`] as well as its paired [`RouterTarget`].
pub fn del_entry(
    port: &Port<VpcNetwork>,
    dest: IpCidr,
    target: RouterTarget,
    class: RouterClass,
) -> Result<DelRouterEntryResp, OpteError> {
    let rule = make_rule(dest, target, class)?;
    let maybe_id = port.find_rule(ROUTER_LAYER_NAME, Direction::Out, &rule)?;
    match maybe_id {
        Some(id) => {
            port.remove_rule(ROUTER_LAYER_NAME, Direction::Out, id)?;
            Ok(DelRouterEntryResp::Ok)
        }

        None => Ok(DelRouterEntryResp::NotFound),
    }
}

/// Add a router entry.
///
/// Route the [`IpCidr`] to the specified [`RouterTarget`].
pub fn add_entry(
    port: &Port<VpcNetwork>,
    dest: IpCidr,
    target: RouterTarget,
    class: RouterClass,
) -> Result<NoResp, OpteError> {
    let rule = make_rule(dest, target, class)?;
    port.add_rule(ROUTER_LAYER_NAME, Direction::Out, rule)?;
    Ok(NoResp::default())
}

/// Replace the current set of router entries with the set passed in.
pub fn replace(
    port: &Port<VpcNetwork>,
    entries: Vec<(IpCidr, RouterTarget, RouterClass)>,
) -> Result<NoResp, OpteError> {
    let mut out_rules = Vec::with_capacity(entries.len());
    for (cidr, target, class) in entries {
        out_rules.push(make_rule(cidr, target, class)?);
    }

    port.set_rules(ROUTER_LAYER_NAME, vec![], out_rules)?;
    Ok(NoResp::default())
}

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
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        (vec![], vec![])
    }

    fn mod_meta(
        &self,
        _flow_id: &InnerFlowId,
        meta: &mut ActionMeta,
    ) -> ModMetaResult {
        // TODO: I don't think we need IP_KEY.
        if let RouterTargetInternal::InternetGateway(_) = self.target {
            meta.insert(self.target.key(), self.target.as_meta());
        }
        meta.insert(self.target.ip_key(), self.target.as_meta());
        let rt_class = self.target.class();
        meta.insert(rt_class.key(), rt_class.as_meta());
        Ok(AllowOrDeny::Allow(()))
    }
}

//! The Oxide Network VPC Router.
//!
//! This implements both the Oxide Network VPC "System Router" and
//! "Custom Router" abstractions, as described in RFD 21 §2.3.
use core::fmt;
use core::str::FromStr;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::{String, ToString};
        use alloc::sync::Arc;
    } else {
        use std::string::{String, ToString};
        use std::sync::Arc;
    }
}

use serde::{Deserialize, Serialize};

use crate::headers::{IpAddr, IpCidr};
use crate::ioctl::NoResp;
use crate::ip4::Ipv4Cidr;
use crate::layer::{InnerFlowId, Layer};
use crate::oxide_net::firewall as fw;
use crate::port::{self, meta::Meta, Port};
use crate::rule::{self, Action, MetaAction, Predicate, Rule};
use crate::{Direction, OpteError};

pub const ROUTER_LAYER_NAME: &'static str = "router";

/// The target for a given router entry.
///
/// * Drop: Packets matching this entry are dropped.
///
/// * InternetGateway: Packets matching this entry are forwarded to
/// the internet. In the case of the Oxide Network the IG is not an
/// actual destination, but rather a configuration that determines how
/// we should NAT the flow.
///
/// * Ip: Packets matching this entry are forwarded to the specified IP.
///
/// XXX Make sure that if a router's target is an IP address that it
/// matches the destination IP type.
///
/// * VpcSubnet: Packets matching this entry are forwarded to the
/// specified VPC Subnet. In the Oxide Network this is just an
/// abstraction, it's simply allowing one subnet to talk to another.
/// There is no separate VPC router process, the real routing is done
/// by the underlay.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RouterTarget {
    Drop,
    InternetGateway,
    Ip(IpAddr),
    VpcSubnet(crate::headers::IpCidr),
}

impl FromStr for RouterTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "drop" => Ok(Self::Drop),
            "ig" => Ok(Self::InternetGateway),
            lower => match lower.split_once("=") {
                Some(("ip4", ip4s)) => {
                    let ip4 = ip4s.parse()?;
                    Ok(Self::Ip(IpAddr::Ip4(ip4)))
                }

                Some(("sub4", cidr4s)) => {
                    let cidr4 = cidr4s.parse()?;
                    Ok(Self::VpcSubnet(IpCidr::Ip4(cidr4)))
                }

                _ => Err(format!("malformed router target: {}", lower)),
            },
        }
    }
}

impl fmt::Display for RouterTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Self::Drop => "drop".to_string(),
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

pub fn setup(port: &Port<port::Inactive>) -> Result<(), OpteError> {
    let ig = Action::Meta(Arc::new(RouterAction::new(
        RouterTarget::InternetGateway,
    )));

    // Indexes:
    //
    // * 0: InternetGateway
    let layer = Layer::new(ROUTER_LAYER_NAME, port.name(), vec![ig]);

    // If there is no matching router entry we drop the packet.
    let drop_rule = Rule::new(65535, rule::Action::Deny).match_any();
    layer.add_rule(Direction::Out, drop_rule);

    port.add_layer(layer, port::Pos::After(fw::FW_LAYER_NAME))
}

pub fn add_entry_inactive(
    port: &Port<port::Inactive>,
    dest: IpCidr,
    target: RouterTarget,
) -> Result<(), OpteError> {
    let pri_map4 = build_ip4_len_to_pri();

    match &target {
        RouterTarget::Drop => todo!("drop entry"),

        RouterTarget::InternetGateway => {
            if !dest.is_default() {
                return Err(OpteError::InvalidRouteDest(dest));
            }

            match dest {
                IpCidr::Ip4(ip4) => {
                    let rule = Rule::new(
                        pri_map4[dest.prefix()],
                        Action::Meta(Arc::new(RouterAction::new(
                            target.clone(),
                        ))),
                    );
                    let rule = rule
                        .add_predicate(Predicate::InnerDstIp4(vec![
                            rule::Ipv4AddrMatch::Prefix(ip4),
                        ]))
                        .finalize();
                    Ok(port.add_rule(
                        ROUTER_LAYER_NAME,
                        Direction::Out,
                        rule,
                    )?)
                }

                IpCidr::Ip6(_) => todo!("IPv6 IG"),
            }
        }

        RouterTarget::Ip(_) => todo!("add IP entry"),

        RouterTarget::VpcSubnet(_) => match dest {
            IpCidr::Ip4(ip4) => {
                let rule = Rule::new(
                    pri_map4[dest.prefix()],
                    Action::Meta(Arc::new(RouterAction::new(target.clone()))),
                );
                let rule = rule
                    .add_predicate(Predicate::InnerDstIp4(vec![
                        rule::Ipv4AddrMatch::Prefix(ip4),
                    ]))
                    .finalize();
                Ok(port.add_rule(ROUTER_LAYER_NAME, Direction::Out, rule)?)
            }

            IpCidr::Ip6(_) => todo!("IPv6 VpcSubnet"),
        },
    }
}

pub fn add_entry_active(
    port: &Port<port::Active>,
    dest: IpCidr,
    target: RouterTarget,
) -> Result<NoResp, OpteError> {
    let pri_map4 = build_ip4_len_to_pri();

    match &target {
        RouterTarget::Drop => todo!("drop entry"),

        RouterTarget::InternetGateway => {
            if !dest.is_default() {
                return Err(OpteError::InvalidRouteDest(dest));
            }

            match dest {
                IpCidr::Ip4(ip4) => {
                    let rule = Rule::new(
                        pri_map4[dest.prefix()],
                        Action::Meta(Arc::new(RouterAction::new(
                            target.clone(),
                        ))),
                    );
                    let rule = rule
                        .add_predicate(Predicate::InnerDstIp4(vec![
                            rule::Ipv4AddrMatch::Prefix(ip4),
                        ]))
                        .finalize();
                    port.add_rule(ROUTER_LAYER_NAME, Direction::Out, rule)?;
                    Ok(NoResp::default())
                }

                IpCidr::Ip6(_) => todo!("IPv6 IG"),
            }
        }

        RouterTarget::Ip(_) => match dest {
            IpCidr::Ip4(ip4) => {
                let rule = Rule::new(
                    pri_map4[dest.prefix()],
                    Action::Meta(Arc::new(RouterAction::new(target.clone()))),
                );
                let rule = rule
                    .add_predicate(Predicate::InnerDstIp4(vec![
                        rule::Ipv4AddrMatch::Prefix(ip4),
                    ]))
                    .finalize();
                port.add_rule(ROUTER_LAYER_NAME, Direction::Out, rule)?;
                Ok(NoResp::default())
            }
            IpCidr::Ip6(_) => todo!("IPv6 IP"),
        },

        RouterTarget::VpcSubnet(_) => match dest {
            IpCidr::Ip4(ip4) => {
                let rule = Rule::new(
                    pri_map4[dest.prefix()],
                    Action::Meta(Arc::new(RouterAction::new(target.clone()))),
                );
                let rule = rule
                    .add_predicate(Predicate::InnerDstIp4(vec![
                        rule::Ipv4AddrMatch::Prefix(ip4),
                    ]))
                    .finalize();
                port.add_rule(ROUTER_LAYER_NAME, Direction::Out, rule)?;
                Ok(NoResp::default())
            }

            IpCidr::Ip6(_) => todo!("IPv6 router entry"),
        },
    }
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
    target: RouterTarget,
}

impl RouterAction {
    pub fn new(target: RouterTarget) -> Self {
        Self { target }
    }
}

impl fmt::Display for RouterAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RouterTarget = {}", self.target)
    }
}

impl MetaAction for RouterAction {
    fn mod_meta(&self, _flow_id: &InnerFlowId, meta: &mut Meta) {
        // TODO Eiter mod_meta() needs to be able to return an error,
        // setting metadata needs to be a different callback, or we
        // should handle failure here and overwrite any existing
        // entry.
        meta.add::<RouterTarget>(self.target.clone()).unwrap();
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AddRouterEntryIpv4Req {
    pub port_name: String,
    pub dest: Ipv4Cidr,
    pub target: RouterTarget,
}

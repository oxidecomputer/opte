//! The Oxide Network VPC Router.
//!
//! This implements both the Oxide Network VPC "System Router" and
//! "Custom Router" abstractions, as described in RFD 21 §2.3.
use core::fmt;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::ToString;
        use alloc::sync::Arc;
    } else {
        use std::string::ToString;
        use std::sync::Arc;
    }
}

use super::firewall as fw;
use crate::api::{Direction, NoResp, OpteError};
use crate::engine::headers::IpCidr;
use crate::engine::layer::{InnerFlowId, Layer};
use crate::engine::port::{self, meta::Meta, Port};
use crate::engine::rule::{self, Action, MetaAction, Predicate, Rule};
use crate::oxide_vpc::api::RouterTarget;

pub const ROUTER_LAYER_NAME: &'static str = "router";

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
                return Err(OpteError::InvalidRouteDest(dest.to_string()));
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
                return Err(OpteError::InvalidRouteDest(dest.to_string()));
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

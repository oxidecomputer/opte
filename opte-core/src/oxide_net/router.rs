//! The Oxide Network VPC Router.
//!
//! This implements both the Oxide Network VPC "System Router" and
//! "Custom Router" abstractions, as described in RFD 21 §2.3.
use core::fmt;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::boxed::Box;
#[cfg(any(feature = "std", test))]
use std::boxed::Box;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::string::ToString;
#[cfg(any(feature = "std", test))]
use std::string::ToString;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::sync::Arc;
#[cfg(any(feature = "std", test))]
use std::sync::Arc;

use crate::headers::IpAddr;
use crate::layer::{InnerFlowId, Layer};
use crate::port::{self, meta::Meta, Port};
use crate::rule::{
    self, Action, ActionDesc, HT, GenDescResult, Predicate, Rule, StatefulAction
};
use crate::Direction;

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
#[derive(Clone, Debug)]
pub enum RouterTarget {
    Drop,
    InternetGateway,
    Ip(IpAddr),
    VpcSubnet(crate::headers::IpCidr),
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

// TODO Implement stateful action to map destination IP to RourterTarget.
#[derive(Clone, Debug)]
struct RouterDesc {
    target: RouterTarget,
}

impl ActionDesc for RouterDesc {
    fn fini(&self) {}

    fn gen_ht(&self, _dir: Direction, meta: &mut Meta) -> HT {
        // TODO Eiter gen_ht() needs to be able to return an error;
        // setting metadata needs to be a different callback; or we
        // should handle failure here and overwrite any existing
        // entry.
        meta.add::<RouterTarget>(self.target.clone()).unwrap();
        HT::identity(ROUTER_LAYER_NAME)
    }

    fn name(&self) -> &str {
        ROUTER_LAYER_NAME
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

pub fn setup(port: &Port<port::Inactive>) {
    let pri_map = build_ip4_len_to_pri();

    // let router = Action::Stateful(
    //     Box::new(RouterAction::new(ROUTER_ACTION_NAME))
    // );

    let ig = Action::Stateful(
        Arc::new(RouterAction::new(RouterTarget::InternetGateway))
    );

    // Indexes:
    //
    // * 0: InternetGateway
    let layer = Layer::new(ROUTER_LAYER_NAME, vec![ig]);
    let ig_idx = 0;

    // TODO These hard-coded rules will actually come dynamically from
    // Nexus. Just keeping them here for now.
    let ig4 = Rule::new(pri_map[0], layer.action(0).unwrap().clone());
    ig4.add_predicate(
        Predicate::InnerDstIp4(vec![
            rule::Ipv4AddrMatch::Prefix("0.0.0.0/0".parse().unwrap())
        ])
    );
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

impl StatefulAction for RouterAction {
    fn gen_desc(
        &self,
        _flow_id: InnerFlowId,
        _meta: &mut Meta
    ) -> GenDescResult {
        Ok(Arc::new(RouterDesc {
            target: RouterTarget::Drop,
        }))
    }
}

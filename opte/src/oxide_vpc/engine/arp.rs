// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::sync::Arc;
    } else {
        use std::sync::Arc;
    }
}

use crate::api::{Direction, MacAddr, OpteError};
use crate::engine::arp::ArpReply;
use crate::engine::ether::ETHER_TYPE_ARP;
use crate::engine::layer::Layer;
use crate::engine::port::{PortBuilder, Pos};
use crate::engine::rule::{
    Action, EtherAddrMatch, EtherTypeMatch, Predicate, Rule,
};
use crate::oxide_vpc::PortCfg;

pub fn setup(
    pb: &mut PortBuilder,
    cfg: &PortCfg,
) -> core::result::Result<(), OpteError> {
    let arp = Layer::new(
        "arp",
        pb.name(),
        vec![
            // ARP Reply for gateway's IP.
            Action::Hairpin(Arc::new(ArpReply::new(cfg.gw_ip, cfg.gw_mac))),
        ],
    );

    // ================================================================
    // Outbound ARP Request for Gateway, from Guest
    // ================================================================
    let mut rule = Rule::new(1, arp.action(0).unwrap().clone());
    rule.add_predicate(Predicate::InnerEtherSrc(vec![EtherAddrMatch::Exact(
        MacAddr::from(cfg.private_mac),
    )]));
    arp.add_rule(Direction::Out, rule.finalize());

    // ================================================================
    // Drop all other outbound ARP Requests from Guest
    // ================================================================
    let mut rule = Rule::new(2, Action::Deny);
    rule.add_predicate(Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(
        ETHER_TYPE_ARP,
    )]));
    arp.add_rule(Direction::Out, rule.finalize());

    // ================================================================
    // Drop all inbound ARP Requests
    // ================================================================
    let mut rule = Rule::new(2, Action::Deny);
    rule.add_predicate(Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(
        ETHER_TYPE_ARP,
    )]));
    arp.add_rule(Direction::In, rule.finalize());

    pb.add_layer(arp, Pos::Before("firewall"))
}

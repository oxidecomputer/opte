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
use crate::oxide_vpc::VpcCfg;

pub fn setup(
    pb: &mut PortBuilder,
    cfg: &VpcCfg,
    ft_limit: core::num::NonZeroU32,
) -> core::result::Result<(), OpteError> {
    let mut actions = vec![
        // ARP Reply for gateway's IP.
        Action::Hairpin(Arc::new(ArpReply::new(cfg.gw_ip, cfg.gw_mac))),
    ];

    if let Some(ip) = cfg.external_ips_v4.as_ref() {
        if cfg.proxy_arp_enable {
            // XXX-EXT-IP Hack to get remote access to guest instance
            // via Proxy ARP.
            //
            // Reuse the same MAC address for both IPs. This should be
            // fine as the VIP is contained solely to the guest
            // instance.
            actions.push(Action::Hairpin(Arc::new(ArpReply::new(
                *ip,
                cfg.private_mac,
            ))));
        }
    }

    let arp = Layer::new(
        "arp",
        pb.name(),
        // vec![
        //     // ARP Reply for gateway's IP.
        //     Action::Hairpin(Arc::new(ArpReply::new(cfg.gw_ip, cfg.gw_mac))),
        // ],
        actions,
        ft_limit,
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
    // Proxy ARP for any incoming requests for guest's external IP.
    //
    // XXX-EXT-IP This is a hack to get guest access working until we
    // have boundary services integrated.
    // ================================================================
    if cfg.external_ips_v4.is_some() && cfg.proxy_arp_enable {
        let rule = Rule::new(1, arp.action(1).unwrap().clone());
        arp.add_rule(Direction::In, rule.finalize());
    }

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

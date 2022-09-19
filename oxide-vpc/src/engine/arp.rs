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

use crate::api::VpcCfg;
use opte::api::{Direction, MacAddr, OpteError};
use opte::engine::arp::ArpReply;
use opte::engine::ether::ETHER_TYPE_ARP;
use opte::engine::layer::Layer;
use opte::engine::port::{PortBuilder, Pos};
use opte::engine::rule::{
    Action, EtherAddrMatch, EtherTypeMatch, Predicate, Rule,
};

pub fn setup(
    pb: &mut PortBuilder,
    cfg: &VpcCfg,
    ft_limit: core::num::NonZeroU32,
) -> core::result::Result<(), OpteError> {
    // If the guest is configured to use IPv4, we need to respond to its ARP
    // requests to resolve the gateway (OPTE) IP address. While the external IP
    // hack is still in place, we also need to Proxy ARP external requests for
    // the guest's IP address.
    //
    // Regardless of which IP version the guest is configured to use, we need to
    // drop any other ARP request, inbound or outbound.
    let mut arp = if let Some(ip_cfg) = cfg.ipv4_cfg() {
        let mut actions = vec![
            // ARP Reply for gateway's IPv4 address.
            Action::Hairpin(Arc::new(ArpReply::new(
                ip_cfg.gateway_ip,
                cfg.gateway_mac,
            ))),
        ];

        if let Some(ip) = ip_cfg.external_ips.as_ref() {
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
        let mut arp = Layer::new(
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
        rule.add_predicate(Predicate::InnerEtherSrc(vec![
            EtherAddrMatch::Exact(MacAddr::from(cfg.private_mac)),
        ]));
        arp.add_rule(Direction::Out, rule.finalize());

        // ================================================================
        // Proxy ARP for any incoming requests for guest's external IP.
        //
        // XXX-EXT-IP This is a hack to get guest access working until we
        // have boundary services integrated.
        // ================================================================
        if ip_cfg.external_ips.is_some() && cfg.proxy_arp_enable {
            let rule = Rule::new(1, arp.action(1).unwrap().clone());
            arp.add_rule(Direction::In, rule.finalize());
        }

        arp
    } else {
        Layer::new("arp", pb.name(), vec![], ft_limit)
    };

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

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! The ARP implementation of the Virtual Gateway.

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::sync::Arc;
    } else {
        use std::sync::Arc;
    }
}

use crate::api::Ipv4Cfg;
use crate::api::VpcCfg;
use core::result::Result;
use opte::api::Direction;
use opte::api::MacAddr;
use opte::api::OpteError;
use opte::engine::arp::ArpReply;
use opte::engine::layer::Layer;
use opte::engine::predicate::EtherAddrMatch;
use opte::engine::predicate::Predicate;
use opte::engine::rule::Action;
use opte::engine::rule::Rule;

pub fn setup(
    layer: &mut Layer,
    cfg: &VpcCfg,
    ip_cfg: &Ipv4Cfg,
) -> Result<(), OpteError> {
    // We need to respond to its ARP requests to resolve the gateway
    // (OPTE) IP address. While the external IP hack is still in
    // place, we also need to Proxy ARP external requests for the
    // guest's IP address.

    // ================================================================
    // Outbound ARP Request for Gateway, from Guest
    // ================================================================
    let reply = Action::Hairpin(Arc::new(ArpReply::new(
        ip_cfg.gateway_ip,
        cfg.gateway_mac,
    )));
    let mut rule = Rule::new(1, reply);
    rule.add_predicate(Predicate::InnerEtherSrc(vec![EtherAddrMatch::Exact(
        MacAddr::from(cfg.guest_mac),
    )]));
    layer.add_rule(Direction::Out, rule.finalize());

    // ================================================================
    // Proxy ARP for any incoming requests for guest's external IP.
    //
    // XXX-EXT-IP This is a hack to get guest access working until we
    // have boundary services integrated.
    // ================================================================
    if let Some(ip) = ip_cfg.external_ips.as_ref() {
        if cfg.proxy_arp_enable {
            let action =
                Action::Hairpin(Arc::new(ArpReply::new(*ip, cfg.guest_mac)));
            let rule = Rule::new(1, action);
            layer.add_rule(Direction::In, rule.finalize());
        }
    }

    // ================================================================
    // Proxy ARP for any incoming requests for guest's SNAT IP.
    //
    // This is not great because once you have more than one guest it
    // means there is an ARP battle for the same SNAT IP. One more
    // rason why this hack needs to go away.
    //
    // XXX-EXT-IP This is a hack to get guest access working until we
    // have boundary services integrated.
    // ================================================================
    if let Some(snat) = ip_cfg.snat.as_ref() {
        if cfg.proxy_arp_enable {
            let action = Action::Hairpin(Arc::new(ArpReply::new(
                snat.external_ip,
                cfg.guest_mac,
            )));
            let rule = Rule::new(1, action);
            layer.add_rule(Direction::In, rule.finalize());
        }
    }

    Ok(())
}

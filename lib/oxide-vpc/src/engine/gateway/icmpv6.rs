// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! The ICMPv6 implementation of the Virtual Gateway.

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::sync::Arc;
        use alloc::vec::Vec;
    } else {
        use std::sync::Arc;
        use std::vec::Vec;
    }
}

use crate::api::Ipv6Cfg;
use crate::api::VpcCfg;
use core::result::Result;
use opte::api::Direction;
use opte::api::Ipv6Addr;
use opte::api::OpteError;
use opte::engine::icmpv6::Icmpv6EchoReply;
use opte::engine::icmpv6::NeighborAdvertisement;
use opte::engine::icmpv6::RouterAdvertisement;
use opte::engine::layer::Layer;
use opte::engine::rule::Action;
use opte::engine::rule::Rule;

// Add support for ICMPv6:
//
// - Respond to echo requests from the guest to the gateway. The source address
// may be either any link-local address in guest (since we can't know how they
// generate that) or its assigned VPC-private address. The destination address
// must be the link-local address we derive for OPTE, from the EUI-64 transform
// on its MAC address.
//
// - Respond to NDP Router Solicitations from the guest to the gateway.
//
// - Respond to NDP Neighbor Solicitations from the guest to the gateway. This
// includes solicitations unicast to the gateway, and also delivered to the
// solicited-node multicast group.
pub fn setup(
    layer: &mut Layer,
    cfg: &VpcCfg,
    ip_cfg: &Ipv6Cfg,
) -> Result<(), OpteError> {
    // We need to hairpin echo requests from either the VPC-private or
    // link-local address of the guest, to OPTE's link-local.
    let src_ips = [ip_cfg.private_ip, Ipv6Addr::from_eui64(&cfg.guest_mac)];
    let dst_ip = Ipv6Addr::from_eui64(&cfg.gateway_mac);
    let n_pings = src_ips.len();
    let mut rule_actions = Vec::with_capacity(n_pings + 2);
    for src_ip in src_ips.iter().copied() {
        let echo = Action::Hairpin(Arc::new(Icmpv6EchoReply {
            src_mac: cfg.guest_mac,
            src_ip,
            dst_mac: cfg.gateway_mac,
            dst_ip,
        }));
        rule_actions.push(echo);
    }

    // Map an NDP Router Solicitation from the guest to a Router Advertisement
    // from the OPTE virtual gateway's link-local IPv6 address.
    let router_advert = Action::Hairpin(Arc::new(RouterAdvertisement::new(
        // From the guest's VPC MAC.
        cfg.guest_mac,
        // The MAC from which we respond, i.e., OPTE's MAC.
        cfg.gateway_mac,
        // "Managed Configuration", indicating the guest needs to use DHCPv6 to
        // acquire an IPv6 address.
        true,
    )));
    rule_actions.push(router_advert);

    // Map an NDP Neighbor Solicitation from the guest to a neighbor
    // advertisement from the OPTE virtual gateway. Note that this is required
    // per RFC 4861 so that the guest does not mark the neighbor failed.
    let neighbor_advert =
        Action::Hairpin(Arc::new(NeighborAdvertisement::new(
            // From the guest's VPC MAC.
            cfg.guest_mac,
            // To OPTE's MAC.
            cfg.gateway_mac,
            // Set the ROUTER flag to true.
            true,
            // Respond to solicitations from `::`
            true,
        )));
    rule_actions.push(neighbor_advert);

    let n_rule_actions = rule_actions.len();

    // Add rules for the above actions.
    for i in 0..n_rule_actions {
        let priority = u16::try_from(i + 1).unwrap();
        let rule = Rule::new(priority, rule_actions.remove(0));
        layer.add_rule(Direction::Out, rule.finalize());
    }

    Ok(())
}

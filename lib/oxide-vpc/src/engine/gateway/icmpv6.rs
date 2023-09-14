// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! The ICMPv6 implementation of the Virtual Gateway.

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::sync::Arc;
    } else {
        use std::sync::Arc;
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
use opte::engine::predicate::DataPredicate;
use opte::engine::rule::Action;
use opte::engine::rule::Rule;
use smoltcp::wire::Icmpv6Message;

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
    let dst_ip = Ipv6Addr::from_eui64(&cfg.gateway_mac);
    let hairpins = [
        // We need to hairpin echo requests from either the VPC-private or
        // link-local address of the guest, to OPTE's link-local.
        Action::Hairpin(Arc::new(Icmpv6EchoReply {
            src_mac: cfg.guest_mac,
            src_ip: ip_cfg.private_ip,
            dst_mac: cfg.gateway_mac,
            dst_ip,
        })),
        Action::Hairpin(Arc::new(Icmpv6EchoReply {
            src_mac: cfg.guest_mac,
            src_ip: Ipv6Addr::from_eui64(&cfg.guest_mac),
            dst_mac: cfg.gateway_mac,
            dst_ip,
        })),
        // Map an NDP Router Solicitation from the guest to a Router Advertisement
        // from the OPTE virtual gateway's link-local IPv6 address.
        Action::Hairpin(Arc::new(RouterAdvertisement::new(
            // From the guest's VPC MAC.
            cfg.guest_mac,
            // The MAC from which we respond, i.e., OPTE's MAC.
            cfg.gateway_mac,
            // "Managed Configuration", indicating the guest needs to use DHCPv6 to
            // acquire an IPv6 address.
            true,
        ))),
        // Map an NDP Neighbor Solicitation from the guest to a neighbor
        // advertisement from the OPTE virtual gateway. Note that this is required
        // per RFC 4861 so that the guest does not mark the neighbor failed.
        Action::Hairpin(Arc::new(NeighborAdvertisement::new(
            // From the guest's VPC MAC.
            cfg.guest_mac,
            // To OPTE's MAC.
            cfg.gateway_mac,
            // Set the ROUTER flag to true.
            true,
            // Respond to solicitations from `::`
            true,
        ))),
    ];

    // UNWRAP SAFETY: There are far fewer than 65535 rules inserted here.
    let next_out_prio = u16::try_from(hairpins.len() + 1).unwrap();
    // Add rules for the above actions.
    hairpins.into_iter().enumerate().for_each(|(i, action)| {
        let priority = u16::try_from(i + 1).unwrap();
        let rule = Rule::new(priority, action);
        layer.add_rule(Direction::Out, rule.finalize());
    });

    // Filter any uncaught in/out-bound NDP traffic.
    let pred = DataPredicate::Icmpv6MsgType(
        (Icmpv6Message::RouterSolicit.into()..=Icmpv6Message::Redirect.into())
            .into(),
    );
    let in_pred = pred.clone();

    let mut ndp_filter = Rule::new(next_out_prio, Action::Deny);
    ndp_filter.add_data_predicate(pred);
    layer.add_rule(Direction::Out, ndp_filter.finalize());

    let mut ndp_filter = Rule::new(1, Action::Deny);
    ndp_filter.add_data_predicate(in_pred);
    layer.add_rule(Direction::In, ndp_filter.finalize());

    Ok(())
}

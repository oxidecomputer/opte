// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! The ICMPv6 implementation of the Virtual Gateway.

use super::BuildCtx;
use crate::cfg::Ipv6Cfg;
use alloc::sync::Arc;
use opte::api::Ipv6Addr;
use opte::api::OpteError;
use opte::engine::icmp::v6::Icmpv6EchoReply;
use opte::engine::icmp::v6::NeighborAdvertisement;
use opte::engine::icmp::v6::RouterAdvertisement;
use opte::engine::predicate::Predicate;
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
pub(crate) fn setup(
    ctx: &mut BuildCtx,
    ip_cfg: &Ipv6Cfg,
) -> Result<(), OpteError> {
    let dst_ip = Ipv6Addr::from_eui64(&ctx.cfg.gateway_mac);
    let hairpins = [
        // We need to hairpin echo requests from either the VPC-private or
        // link-local address of the guest, to OPTE's link-local.
        Action::Hairpin(Arc::new(Icmpv6EchoReply {
            src_mac: ctx.cfg.guest_mac,
            src_ip: ip_cfg.private_ip,
            dst_mac: ctx.cfg.gateway_mac,
            dst_ip,
        })),
        Action::Hairpin(Arc::new(Icmpv6EchoReply {
            src_mac: ctx.cfg.guest_mac,
            src_ip: Ipv6Addr::from_eui64(&ctx.cfg.guest_mac),
            dst_mac: ctx.cfg.gateway_mac,
            dst_ip,
        })),
        // Map an NDP Router Solicitation from the guest to a Router Advertisement
        // from the OPTE virtual gateway's link-local IPv6 address.
        Action::Hairpin(Arc::new(RouterAdvertisement::new(
            // From the guest's VPC MAC.
            ctx.cfg.guest_mac,
            // The MAC from which we respond, i.e., OPTE's MAC.
            ctx.cfg.gateway_mac,
            // "Managed Configuration", indicating the guest needs to use DHCPv6 to
            // acquire an IPv6 address.
            true,
        ))),
        // Map an NDP Neighbor Solicitation from the guest to a neighbor
        // advertisement from the OPTE virtual gateway. Note that this is required
        // per RFC 4861 so that the guest does not mark the neighbor failed.
        Action::Hairpin(Arc::new(NeighborAdvertisement::new(
            // From the guest's VPC MAC.
            ctx.cfg.guest_mac,
            // To OPTE's MAC.
            ctx.cfg.gateway_mac,
            // Set the ROUTER flag to true.
            true,
            // Respond to solicitations from `::`
            true,
        ))),
    ];

    // UNWRAP SAFETY: There are far fewer than 65535 rules inserted here.
    let next_out_prio = u16::try_from(hairpins.len() + 1).unwrap();
    // Add rules for the above actions.
    ctx.out_rules.extend(hairpins.into_iter().enumerate().map(
        |(i, action)| {
            let priority = u16::try_from(i + 1).unwrap();
            Rule::new(priority, action).finalize()
        },
    ));

    // Filter any uncaught in/out-bound NDP traffic.
    let pred = Predicate::Icmpv6MsgType(vec![
        (Icmpv6Message::RouterSolicit.into()..=Icmpv6Message::Redirect.into())
            .into(),
    ]);
    let in_pred = pred.clone();

    let mut ndp_filter = Rule::new(next_out_prio, Action::Deny);
    ndp_filter.add_predicate(pred);
    ctx.out_rules.push(ndp_filter.finalize());

    let mut ndp_filter = Rule::new(1, Action::Deny);
    ndp_filter.add_predicate(in_pred);
    ctx.in_rules.push(ndp_filter.finalize());

    Ok(())
}

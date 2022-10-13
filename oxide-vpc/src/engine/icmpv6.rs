// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Layer handling ICMPv6 messages

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
use core::num::NonZeroU32;
use core::result::Result;
use opte::api::Direction;
use opte::api::Ipv6Addr;
use opte::api::OpteError;
use opte::api::Protocol;
use opte::engine::ether::ETHER_TYPE_IPV6;
use opte::engine::icmpv6::Icmpv6EchoReply;
use opte::engine::icmpv6::MessageType;
use opte::engine::icmpv6::NeighborAdvertisement;
use opte::engine::icmpv6::RouterAdvertisement;
use opte::engine::layer::DefaultAction;
use opte::engine::layer::Layer;
use opte::engine::layer::LayerActions;
use opte::engine::port::PortBuilder;
use opte::engine::port::Pos;
use opte::engine::rule::Action;
use opte::engine::rule::DataPredicate;
use opte::engine::rule::EtherAddrMatch;
use opte::engine::rule::EtherTypeMatch;
use opte::engine::rule::Identity;
use opte::engine::rule::IpProtoMatch;
use opte::engine::rule::Ipv6AddrMatch;
use opte::engine::rule::Predicate;
use opte::engine::rule::Rule;
use smoltcp::wire::Icmpv6Message;

pub fn setup(
    pb: &mut PortBuilder,
    cfg: &VpcCfg,
    ft_limit: NonZeroU32,
) -> Result<(), OpteError> {
    match cfg.ipv6_cfg() {
        None => drop_all_icmpv6(pb, ft_limit),
        Some(ip_cfg) => add_icmpv6_rules(pb, cfg, ip_cfg, ft_limit),
    }
}

// Explicitly drop any ICMPv6 traffic if the guest is not configured with an
// IPv6 address.
fn drop_all_icmpv6(
    pb: &mut PortBuilder,
    ft_limit: NonZeroU32,
) -> Result<(), OpteError> {
    let mut rule = Rule::new(1, Action::Deny);
    rule.add_predicate(Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(
        ETHER_TYPE_IPV6,
    )]));
    rule.add_predicate(Predicate::InnerIpProto(vec![IpProtoMatch::Exact(
        Protocol::ICMPv6,
    )]));
    let rule = rule.finalize();

    // We use an explicit rule to drop ICMPv6 traffic, and let the
    // rest pass through.
    //
    // XXX This is going away fairly soon when we move to a "gateway"
    // layer that brings all these gateway-related rules together in
    // one place and will allow us to more easily enforce an allowed
    // list of traffic based on the VpcCfg.
    let actions = LayerActions {
        actions: vec![],
        default_in: DefaultAction::Allow,
        default_out: DefaultAction::Allow,
    };

    let mut icmp = Layer::new("icmpv6", pb.name(), actions, ft_limit);
    icmp.add_rule(Direction::In, rule.clone());
    icmp.add_rule(Direction::Out, rule.clone());
    pb.add_layer(icmp, Pos::Before("firewall"))
}

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
//
// - Drop any other NDP traffic, inbound or outbound.
//
// - Pass through any other ICMPv6 traffic.
fn add_icmpv6_rules(
    pb: &mut PortBuilder,
    cfg: &VpcCfg,
    ip_cfg: &Ipv6Cfg,
    ft_limit: NonZeroU32,
) -> Result<(), OpteError> {
    // We need to hairpin echo requests from either the VPC-private or
    // link-local address of the guest, to OPTE's link-local.
    let src_ips = [ip_cfg.private_ip, Ipv6Addr::from_eui64(&cfg.private_mac)];
    let dst_ip = Ipv6Addr::from_eui64(&cfg.gateway_mac);
    let n_pings = src_ips.len();
    let mut rule_actions = Vec::with_capacity(n_pings + 2);
    for src_ip in src_ips.iter().copied() {
        let echo = Action::Hairpin(Arc::new(Icmpv6EchoReply {
            src_mac: cfg.private_mac,
            src_ip,
            dst_mac: cfg.gateway_mac,
            dst_ip,
        }));
        rule_actions.push(echo);
    }

    // Map an NDP Router Solicitation from the guest to a Router Advertisement
    // from the OPTE virtual gateway's link-local IPv6 address.
    let router_advert = Action::Hairpin(Arc::new(RouterAdvertisement::new(
        // From the guest's private MAC.
        cfg.private_mac,
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
            // From the guest's private MAC.
            cfg.private_mac,
            // To OPTE's MAC.
            cfg.gateway_mac,
            // Set the ROUTER flag to true.
            true,
            // Respond to solicitations from `::`
            true,
        )));
    rule_actions.push(neighbor_advert);

    let n_rule_actions = rule_actions.len();

    // We use an explicit rule to drop ICMPv6 traffic, and let the
    // rest pass through.
    //
    // XXX This is going away fairly soon when we move to a "gateway"
    // layer that brings all these gateway-related rules together in
    // one place and will allow us to more easily enforce an allowed
    // list of traffic based on the VpcCfg.
    let actions = LayerActions {
        actions: rule_actions,
        default_in: DefaultAction::Allow,
        default_out: DefaultAction::Allow,
    };

    let mut icmp = Layer::new("icmpv6", pb.name(), actions, ft_limit);

    // Add rules for the above actions.
    for i in 0..n_rule_actions {
        let priority = u16::try_from(i + 1).unwrap();
        let rule = Rule::new(priority, icmp.action(i).unwrap().clone());
        icmp.add_rule(Direction::Out, rule.finalize());
    }

    // Add a high numeric priority rule to drop any ICMPv6 traffic.
    let mut rule = Rule::new(u16::MAX, Action::Deny);
    rule.add_predicate(Predicate::InnerIpProto(vec![IpProtoMatch::Exact(
        Protocol::ICMPv6,
    )]));
    icmp.add_rule(Direction::In, rule.clone().finalize());
    icmp.add_rule(Direction::Out, rule.finalize());

    // And then pass through unchanged any ICMPv6 Echo Request / Reply messages.
    // These will not be matched by the ping rules above, meaning they're
    // destined for somewhere else. We can add more exceptions to the Deny above
    // as needed.
    let priority = u16::try_from(n_rule_actions + 1).unwrap();

    // Outbound echo messages.
    let mut rule = Rule::new(
        priority,
        Action::Static(Arc::new(Identity::new("allow-outbound-icmpv6-echo"))),
    );
    // IPv6 only.
    rule.add_predicate(Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(
        ETHER_TYPE_IPV6,
    )]));
    // From client MAC.
    rule.add_predicate(Predicate::InnerEtherSrc(vec![EtherAddrMatch::Exact(
        cfg.private_mac,
    )]));
    // To OPTE MAC.
    rule.add_predicate(Predicate::InnerEtherDst(vec![EtherAddrMatch::Exact(
        cfg.gateway_mac,
    )]));
    // From client VPC-private IP, link-local cannot be used.
    rule.add_predicate(Predicate::InnerSrcIp6(vec![Ipv6AddrMatch::Exact(
        ip_cfg.private_ip,
    )]));
    // ICMPv6
    rule.add_predicate(Predicate::InnerIpProto(vec![IpProtoMatch::Exact(
        Protocol::ICMPv6,
    )]));
    // Supported message types.
    rule.add_data_predicate(DataPredicate::Icmpv6MsgType(MessageType::from(
        Icmpv6Message::EchoRequest,
    )));
    rule.add_data_predicate(DataPredicate::Icmpv6MsgType(MessageType::from(
        Icmpv6Message::EchoReply,
    )));
    icmp.add_rule(Direction::Out, rule.finalize());

    // Inbound echo mesages.
    let mut rule = Rule::new(
        priority,
        Action::Static(Arc::new(Identity::new("allow-inbound-icmpv6-echo"))),
    );
    // IPv6 only.
    rule.add_predicate(Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(
        ETHER_TYPE_IPV6,
    )]));
    // To client MAC. Note we don't have a predicate on the source MAC.
    rule.add_predicate(Predicate::InnerEtherDst(vec![EtherAddrMatch::Exact(
        cfg.private_mac,
    )]));
    // To client VPC-private IP, link-local cannot be used.
    rule.add_predicate(Predicate::InnerDstIp6(vec![Ipv6AddrMatch::Exact(
        ip_cfg.private_ip,
    )]));
    // ICMPv6
    rule.add_predicate(Predicate::InnerIpProto(vec![IpProtoMatch::Exact(
        Protocol::ICMPv6,
    )]));
    // Supported message types.
    rule.add_data_predicate(DataPredicate::Icmpv6MsgType(MessageType::from(
        Icmpv6Message::EchoRequest,
    )));
    rule.add_data_predicate(DataPredicate::Icmpv6MsgType(MessageType::from(
        Icmpv6Message::EchoReply,
    )));
    icmp.add_rule(Direction::In, rule.finalize());

    pb.add_layer(icmp, Pos::Before("firewall"))
}

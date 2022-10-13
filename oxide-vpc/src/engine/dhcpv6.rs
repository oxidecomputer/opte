// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Implements DHCPv6 as supported in the Oxide VPC environment.

use crate::api::Ipv6Cfg;
use crate::api::VpcCfg;
use core::num::NonZeroU32;
use opte::api::Direction;
use opte::api::Ipv6Addr;
use opte::api::OpteError;
use opte::api::Protocol;
use opte::engine::dhcpv6::AddressInfo;
use opte::engine::dhcpv6::Dhcpv6Action;
use opte::engine::dhcpv6::LeasedAddress;
use opte::engine::dhcpv6::ALL_RELAYS_AND_SERVERS;
use opte::engine::dhcpv6::ALL_SERVERS;
use opte::engine::dhcpv6::CLIENT_PORT;
use opte::engine::dhcpv6::SERVER_PORT;
use opte::engine::layer::DefaultAction;
use opte::engine::layer::Layer;
use opte::engine::layer::LayerActions;
use opte::engine::port::PortBuilder;
use opte::engine::port::Pos;
use opte::engine::rule::Action;
use opte::engine::rule::HairpinAction;
use opte::engine::rule::IpProtoMatch;
use opte::engine::rule::Ipv6AddrMatch;
use opte::engine::rule::PortMatch;
use opte::engine::rule::Predicate;
use opte::engine::rule::Rule;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::sync::Arc;
    } else {
        use std::sync::Arc;
    }
}

pub fn setup(
    pb: &mut PortBuilder,
    cfg: &VpcCfg,
    ft_limit: NonZeroU32,
) -> Result<(), OpteError> {
    match cfg.ipv6_cfg() {
        None => drop_all_dhcpv6(pb, ft_limit),
        Some(ip_cfg) => add_dhcpv6_rules(pb, cfg, ip_cfg, ft_limit),
    }
}

const LAYER_NAME: &'static str = "dhcpv6";

fn drop_all_dhcpv6(
    pb: &mut PortBuilder,
    ft_limit: NonZeroU32,
) -> Result<(), OpteError> {
    // Predicates identifying any traffic destined for a DHCPv6 server.
    let predicates = vec![
        // Destined for the server multicast IP address.
        Predicate::InnerDstIp6(vec![
            Ipv6AddrMatch::Exact(ALL_RELAYS_AND_SERVERS),
            Ipv6AddrMatch::Exact(ALL_SERVERS),
        ]),
        // DHCPv6 runs over UDP.
        Predicate::InnerIpProto(vec![IpProtoMatch::Exact(Protocol::UDP)]),
        // From the client source port.
        Predicate::InnerSrcPort(vec![PortMatch::Exact(CLIENT_PORT)]),
        // To the server destination port.
        Predicate::InnerDstPort(vec![PortMatch::Exact(SERVER_PORT)]),
    ];
    let mut rule = Rule::new(u16::MAX, Action::Deny);
    rule.add_predicates(predicates);

    // The DHCPv6 layer is only meant to intercept DHCPv6 traffic, and
    // therefore it allows all other traffic to pass by default.
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

    let mut layer = Layer::new(LAYER_NAME, pb.name(), actions, ft_limit);
    layer.add_rule(Direction::In, rule.clone().finalize());
    layer.add_rule(Direction::Out, rule.clone().finalize());
    pb.add_layer(layer, Pos::Before("firewall"))
}

fn add_dhcpv6_rules(
    pb: &mut PortBuilder,
    cfg: &VpcCfg,
    ip_cfg: &Ipv6Cfg,
    ft_limit: NonZeroU32,
) -> Result<(), OpteError> {
    // The main DHCPv6 server action, which currently just leases the
    // VPC-private IP addresses to the client.
    let addrs = AddressInfo {
        addrs: vec![LeasedAddress::infinite_lease(ip_cfg.private_ip)],
        renew: u32::MAX,
    };
    let action = Dhcpv6Action {
        client_mac: cfg.private_mac,
        server_mac: cfg.gateway_mac,
        addrs,
        dns_servers: vec![
            // CloudFlare
            Ipv6Addr::from_const([0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111]),
            Ipv6Addr::from_const([0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001]),
            // Google
            Ipv6Addr::from_const([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888]),
            Ipv6Addr::from_const([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844]),
        ],
        sntp_servers: vec![],
    };

    // Clone predicates, since they're used in the static rule below to drop all
    // inbound DHCPv6.
    let is_dhcp = action.implicit_preds().0.clone();

    let server = Action::Hairpin(Arc::new(action));

    // The DHCPv6 layer is only meant to intercept DHCPv6 traffic, and
    // therefore it allows all other traffic to pass by default.
    //
    // XXX This is going away fairly soon when we move to a "gateway"
    // layer that brings all these gateway-related rules together in
    // one place and will allow us to more easily enforce an allowed
    // list of traffic based on the VpcCfg.
    let actions = LayerActions {
        actions: vec![server],
        default_in: DefaultAction::Allow,
        default_out: DefaultAction::Allow,
    };

    let mut dhcp = Layer::new(LAYER_NAME, pb.name(), actions, ft_limit);
    let rule = Rule::new(1, dhcp.action(0).unwrap().clone());
    dhcp.add_rule(Direction::Out, rule.finalize());

    // Static rule to drop all inbound DHCPv6 traffic.
    let mut rule = Rule::new(1, Action::Deny);
    rule.add_predicates(is_dhcp);
    dhcp.add_rule(Direction::In, rule.finalize());

    pb.add_layer(dhcp, Pos::Before("firewall"))
}

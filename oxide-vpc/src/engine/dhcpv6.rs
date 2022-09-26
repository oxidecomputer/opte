// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Implements DHCPv6 as supported in the Oxide VPC environment.

use crate::api::VpcCfg;
use core::num::NonZeroU32;
use opte::api::Direction;
use opte::api::Ipv6Addr;
use opte::api::OpteError;
use opte::engine::dhcpv6::AddressInfo;
use opte::engine::dhcpv6::Dhcpv6Action;
use opte::engine::dhcpv6::LeasedAddress;
use opte::engine::layer::Layer;
use opte::engine::port::PortBuilder;
use opte::engine::port::Pos;
use opte::engine::rule::Action;
use opte::engine::rule::HairpinAction;
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
    // This layer contains no actions if the client has not been configured with
    // IPv6 support.
    let ip_cfg = match cfg.ipv6_cfg() {
        None => return Ok(()),
        Some(c) => c,
    };

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
    let mut dhcp = Layer::new("dhcpv6", pb.name(), vec![server], ft_limit);
    let rule = Rule::new(1, dhcp.action(0).unwrap().clone());
    dhcp.add_rule(Direction::Out, rule.finalize());

    // Static rule to drop all inbound DHCPv6 traffic.
    let mut rule = Rule::new(1, Action::Deny);
    rule.add_predicates(is_dhcp);
    dhcp.add_rule(Direction::In, rule.finalize());

    pb.add_layer(dhcp, Pos::Before("firewall"))
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! The DHCPv6 implementation of the Virtual Gateway.

use crate::api::VpcCfg;
use opte::api::Direction;
use opte::api::Ipv6Addr;
use opte::api::OpteError;
use opte::engine::dhcpv6::AddressInfo;
use opte::engine::dhcpv6::Dhcpv6Action;
use opte::engine::dhcpv6::LeasedAddress;
use opte::engine::layer::Layer;
use opte::engine::rule::Action;
use opte::engine::rule::Rule;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::sync::Arc;
    } else {
        use std::sync::Arc;
    }
}

pub fn setup(layer: &mut Layer, cfg: &VpcCfg) -> Result<(), OpteError> {
    let ip_cfg = match cfg.ipv6_cfg() {
        None => return Ok(()),
        Some(ip_cfg) => ip_cfg,
    };

    // The main DHCPv6 server action, which currently just leases the
    // VPC-private IP addresses to the client.
    let addrs = AddressInfo {
        addrs: vec![LeasedAddress::infinite_lease(ip_cfg.private_ip)],
        renew: u32::MAX,
    };
    let action = Dhcpv6Action {
        client_mac: cfg.guest_mac,
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
        domain_list: cfg.domain_list.clone(),
    };

    let server = Action::Hairpin(Arc::new(action));
    let rule = Rule::new(1, server);
    layer.add_rule(Direction::Out, rule.finalize());
    Ok(())
}

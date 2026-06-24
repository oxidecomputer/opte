// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! The DHCPv6 implementation of the Virtual Gateway.

use super::BuildCtx;
use alloc::sync::Arc;
use opte::api::OpteError;
use opte::engine::dhcpv6::AddressInfo;
use opte::engine::dhcpv6::Dhcpv6Action;
use opte::engine::dhcpv6::LeasedAddress;
use opte::engine::rule::Action;
use opte::engine::rule::Rule;

pub(super) fn setup(ctx: &mut BuildCtx) -> Result<(), OpteError> {
    let ip_cfg = match ctx.cfg.ipv6_cfg() {
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
        client_mac: ctx.cfg.guest_mac,
        server_mac: ctx.cfg.gateway_mac,
        addrs,
        sntp_servers: vec![],
        dhcp_cfg: ctx.cfg.dhcp.clone(),
    };

    let server = Action::Hairpin(Arc::new(action));
    ctx.out_rules.push(Rule::new(1, server).finalize());
    Ok(())
}

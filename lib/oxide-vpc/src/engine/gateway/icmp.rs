// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! The ICMP implementation of the Virtual Gateway.

use super::BuildCtx;
use crate::cfg::Ipv4Cfg;
use alloc::sync::Arc;
use opte::api::OpteError;
use opte::engine::icmp::v4::IcmpEchoReply;
use opte::engine::rule::Action;
use opte::engine::rule::Rule;

pub(crate) fn setup(
    ctx: &mut BuildCtx,
    ip_cfg: &Ipv4Cfg,
) -> Result<(), OpteError> {
    // ================================================================
    // ICMPv4 Echo Reply
    // ================================================================
    let reply = Action::Hairpin(Arc::new(IcmpEchoReply {
        // Map an Echo from guest (src) -> gateway (dst) to an Echo
        // Reply from gateway (dst) -> guest (src).
        echo_src_mac: ctx.cfg.guest_mac,
        echo_src_ip: ip_cfg.private_ip,
        echo_dst_mac: ctx.cfg.gateway_mac,
        echo_dst_ip: ip_cfg.gateway_ip,
    }));
    let rule = Rule::new(1, reply);
    ctx.out_rules.push(rule.finalize());
    Ok(())
}

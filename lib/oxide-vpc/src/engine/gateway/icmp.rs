// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! The ICMP implementation of the Virtual Gateway.

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
use opte::api::OpteError;
use opte::engine::icmp::IcmpEchoReply;
use opte::engine::layer::Layer;
use opte::engine::rule::Action;
use opte::engine::rule::Rule;

pub fn setup(
    layer: &mut Layer,
    cfg: &VpcCfg,
    ip_cfg: &Ipv4Cfg,
) -> Result<(), OpteError> {
    // ================================================================
    // ICMPv4 Echo Reply
    // ================================================================
    let reply = Action::Hairpin(Arc::new(IcmpEchoReply {
        // Map an Echo from guest (src) -> gateway (dst) to an Echo
        // Reply from gateway (dst) -> guest (src).
        echo_src_mac: cfg.guest_mac,
        echo_src_ip: ip_cfg.private_ip,
        echo_dst_mac: cfg.gateway_mac,
        echo_dst_ip: ip_cfg.gateway_ip,
    }));
    let rule = Rule::new(1, reply);
    layer.add_rule(Direction::Out, rule.finalize());
    Ok(())
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Layer handling ICMPv6 messages

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::sync::Arc;
    } else {
        use std::sync::Arc;
    }
}

use crate::api::VpcCfg;
use opte::api::{Direction, OpteError};
use opte::engine::icmpv6::Icmpv6EchoReply;
use opte::engine::layer::Layer;
use opte::engine::port::{PortBuilder, Pos};
use opte::engine::rule::{Action, Rule};

pub fn setup(
    pb: &mut PortBuilder,
    cfg: &VpcCfg,
    ft_limit: core::num::NonZeroU32,
) -> core::result::Result<(), OpteError> {
    // The ICMPv6 layer only contains meaningful actions if the port is
    // configured to support IPv6.
    let ip_cfg = match cfg.ipv6_cfg() {
        None => return Ok(()),
        Some(cfg) => cfg,
    };

    let reply = Action::Hairpin(Arc::new(Icmpv6EchoReply {
        // Map an Echo Request from guest (src) -> gateway (dst) to an Echo
        // Reply from gateway (dst) -> guest (src).
        src_mac: cfg.private_mac.into(),
        src_ip: ip_cfg.private_ip,
        dst_mac: cfg.gateway_mac.into(),
        dst_ip: ip_cfg.gateway_ip,
    }));
    let mut icmp = Layer::new("icmpv6", pb.name(), vec![reply], ft_limit);

    let rule = Rule::new(1, icmp.action(0).unwrap().clone());
    icmp.add_rule(Direction::Out, rule.finalize());
    pb.add_layer(icmp, Pos::Before("firewall"))
}

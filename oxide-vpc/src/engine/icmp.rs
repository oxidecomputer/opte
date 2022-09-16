// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::sync::Arc;
    } else {
        use std::sync::Arc;
    }
}

use crate::api::VpcCfg;
use opte::api::{Direction, OpteError};
use opte::engine::icmp::IcmpEchoReply;
use opte::engine::layer::Layer;
use opte::engine::port::{PortBuilder, Pos};
use opte::engine::rule::{Action, Rule};

pub fn setup(
    pb: &mut PortBuilder,
    cfg: &VpcCfg,
    ft_limit: core::num::NonZeroU32,
) -> core::result::Result<(), OpteError> {
    // The ICMP layer only contains meaningful actions if the port is configured
    // to support IPv4.
    let ip_cfg = match cfg.ipv4_cfg() {
        None => return Ok(()),
        Some(cfg) => cfg,
    };

    let reply = Action::Hairpin(Arc::new(IcmpEchoReply {
        // Map an Echo from guest (src) -> gateway (dst) to an Echo
        // Reply from gateway (dst) -> guest (src).
        echo_src_mac: cfg.private_mac.into(),
        echo_src_ip: ip_cfg.private_ip,
        echo_dst_mac: cfg.gateway_mac.into(),
        echo_dst_ip: ip_cfg.gateway_ip,
    }));
    let mut icmp = Layer::new("icmp", pb.name(), vec![reply], ft_limit);

    // ================================================================
    // ICMPv4 Echo Reply
    // ================================================================
    //
    // TODO At first I only predicated on ICMP protocol + Echo Request
    // message type, but in reality I need to predicate against all
    // the specifics like frame dst + src + type as well as IP src +
    // dst + proto, etc. Otherwise, the guest could ping the gateway
    // with an invalid packet but still get a response. Or even worse,
    // could ping for some other valid address but instead of getting
    // a response from that host end up getting a response from OPTE!
    // This makes me think I need to check all my other rules to make
    // sure I didn't short cut the predicates.
    //
    // XXX It would be nice to have a macro shortcut for header
    // predicate that allows you do something like:
    //
    // hdr_pred!(eth_dst: cfg.gw_mac, eth_src: cfg.guest_mac,
    // eth_type: EtherType::Ipv4, ip_src: cfg.guest_ip4, ip_dst: cfg.gw_ip4,
    // ip_proto: Protocol::ICMP)
    //
    // which would generate a Vec of the header predicates.
    let rule = Rule::new(1, icmp.action(0).unwrap().clone());
    icmp.add_rule(Direction::Out, rule.finalize());
    pb.add_layer(icmp, Pos::Before("firewall"))
}

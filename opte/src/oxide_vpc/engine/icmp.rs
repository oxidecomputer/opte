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

use crate::api::{Direction, OpteError};
use crate::engine::icmp::Icmp4EchoReply;
use crate::engine::layer::Layer;
use crate::engine::port::{PortBuilder, Pos};
use crate::engine::rule::{Action, Rule};
use crate::oxide_vpc::VpcCfg;

pub fn setup(
    pb: &mut PortBuilder,
    cfg: &VpcCfg,
    ft_limit: core::num::NonZeroU32,
) -> core::result::Result<(), OpteError> {
    let reply = Action::Hairpin(Arc::new(Icmp4EchoReply {
        // Map an Echo from guest (src) -> gateway (dst) to an Echo
        // Reply from gateway (dst) -> guest (src).
        echo_src_mac: cfg.private_mac.into(),
        echo_src_ip: cfg.private_ip,
        echo_dst_mac: cfg.gw_mac.into(),
        echo_dst_ip: cfg.gw_ip,
    }));
    let icmp = Layer::new("icmp", pb.name(), vec![reply], ft_limit);

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

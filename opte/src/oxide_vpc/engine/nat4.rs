// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::boxed::Box;
        use alloc::sync::Arc;
    } else {
        use std::boxed::Box;
        use std::sync::Arc;
    }
}

use super::router::{RouterTargetInternal, ROUTER_LAYER_NAME};
use crate::api::{Direction, OpteError};
use crate::engine::ether::ETHER_TYPE_IPV4;
use crate::engine::layer::Layer;
use crate::engine::nat::Nat4;
use crate::engine::port::{PortBuilder, Pos};
use crate::engine::rule::{
    Action, EtherTypeMatch, Ipv4AddrMatch, Predicate, Rule,
};
use crate::oxide_vpc::PortCfg;

pub const NAT4_LAYER_NAME: &'static str = "nat4";

pub fn setup(
    pb: &mut PortBuilder,
    cfg: &PortCfg,
    ft_limit: core::num::NonZeroU32,
) -> core::result::Result<(), OpteError> {
    // XXX-EXT-IP This config should not some from SNAT. This is
    // currently a hack assuming its use is in service of the
    // ext_ip_hack flag.
    let nat = Nat4::new(
        cfg.private_ip,
        cfg.snat.as_ref().unwrap().public_ip,
        cfg.snat.as_ref().unwrap().phys_gw_mac,
    );
    let layer = Layer::new(
        NAT4_LAYER_NAME,
        pb.name(),
        vec![Action::Stateful(Arc::new(nat))],
        ft_limit,
    );
    let mut rule = Rule::new(1, layer.action(0).unwrap().clone());
    rule.add_predicate(Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(
        ETHER_TYPE_IPV4,
    )]));
    rule.add_predicate(Predicate::Meta(Box::new(
        RouterTargetInternal::InternetGateway,
    )));
    layer.add_rule(Direction::Out, rule.finalize());

    let mut rule = Rule::new(1, layer.action(0).unwrap().clone());
    rule.add_predicate(Predicate::InnerDstIp4(vec![Ipv4AddrMatch::Exact(
        cfg.snat.as_ref().unwrap().public_ip,
    )]));
    layer.add_rule(Direction::In, rule.finalize());

    pb.add_layer(layer, Pos::After(ROUTER_LAYER_NAME))
}

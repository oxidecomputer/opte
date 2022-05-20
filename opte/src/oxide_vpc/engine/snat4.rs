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
use crate::engine::ip4::Protocol;
use crate::engine::layer::Layer;
use crate::engine::port::{PortBuilder, Pos};
use crate::engine::rule::{Action, IpProtoMatch, Predicate, Rule};
use crate::engine::snat::{NatPool, SNat4};
use crate::oxide_vpc::PortCfg;

pub const SNAT4_LAYER_NAME: &'static str = "snat4";

pub fn setup(
    pb: &mut PortBuilder,
    cfg: &PortCfg,
    ft_limit: core::num::NonZeroU32,
) -> core::result::Result<(), OpteError> {
    let pool = NatPool::new();
    pool.add(
        cfg.private_ip,
        cfg.snat.as_ref().unwrap().public_ip,
        cfg.snat.as_ref().unwrap().ports.clone(),
    );

    let nat = SNat4::new(cfg.private_ip, Arc::new(pool));
    let layer = Layer::new(
        SNAT4_LAYER_NAME,
        pb.name(),
        vec![Action::Stateful(Arc::new(nat))],
        ft_limit,
    );
    let mut rule = Rule::new(1, layer.action(0).unwrap().clone());

    rule.add_predicate(Predicate::InnerIpProto(vec![
        IpProtoMatch::Exact(Protocol::TCP),
        IpProtoMatch::Exact(Protocol::UDP),
    ]));
    rule.add_predicate(Predicate::Meta(Box::new(
        RouterTargetInternal::InternetGateway,
    )));
    layer.add_rule(Direction::Out, rule.finalize());
    pb.add_layer(layer, Pos::After(ROUTER_LAYER_NAME))
}

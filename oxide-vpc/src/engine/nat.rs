// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::ToString;
        use alloc::sync::Arc;
    } else {
        use std::string::ToString;
        use std::sync::Arc;
    }
}

use super::router::{RouterTargetInternal, ROUTER_LAYER_NAME};
use crate::VpcCfg;
use opte::api::{Direction, OpteError};
use opte::engine::ether::ETHER_TYPE_IPV4;
use opte::engine::layer::Layer;
use opte::engine::nat::Nat4;
use opte::engine::port::meta::ActionMetaValue;
use opte::engine::port::{PortBuilder, Pos};
use opte::engine::rule::{
    Action, EtherTypeMatch, Ipv4AddrMatch, Predicate, Rule,
};
use opte::engine::snat::{NatPool, SNat4};

pub const NAT_LAYER_NAME: &'static str = "nat";

pub fn setup(
    pb: &mut PortBuilder,
    cfg: &VpcCfg,
    ft_limit: core::num::NonZeroU32,
) -> core::result::Result<(), OpteError> {
    let mut layer = Layer::new(NAT_LAYER_NAME, pb.name(), vec![], ft_limit);

    // When it comes to NAT we always prefer using 1:1 NAT of external
    // IP to SNAT. To achieve this we place the NAT rules at a lower
    // priority than SNAT.
    if let Some(ip4) = cfg.external_ips_v4 {
        let nat = Arc::new(Nat4::new(cfg.private_ip, ip4, cfg.phys_gw_mac));

        // 1:1 NAT outbound packets destined for internet gateway.
        let mut out_nat = Rule::new(10, Action::Stateful(nat.clone()));
        out_nat.add_predicate(Predicate::InnerEtherType(vec![
            EtherTypeMatch::Exact(ETHER_TYPE_IPV4),
        ]));
        out_nat.add_predicate(Predicate::Meta(
            RouterTargetInternal::KEY.to_string(),
            RouterTargetInternal::InternetGateway.as_meta(),
        ));
        layer.add_rule(Direction::Out, out_nat.finalize());

        // 1:1 NAT inbound packets destined for external IP.
        let mut in_nat = Rule::new(10, Action::Stateful(nat));
        in_nat.add_predicate(Predicate::InnerDstIp4(vec![
            Ipv4AddrMatch::Exact(ip4),
        ]));
        layer.add_rule(Direction::In, in_nat.finalize());
    }

    if cfg.snat.is_some() {
        let pool = NatPool::new();
        pool.add(
            cfg.private_ip,
            cfg.snat.as_ref().unwrap().public_ip,
            cfg.snat.as_ref().unwrap().ports.clone(),
        );
        let snat = SNat4::new(cfg.private_ip, Arc::new(pool));
        let mut rule = Rule::new(100, Action::Stateful(Arc::new(snat)));

        rule.add_predicate(Predicate::InnerEtherType(vec![
            EtherTypeMatch::Exact(ETHER_TYPE_IPV4),
        ]));
        rule.add_predicate(Predicate::Meta(
            RouterTargetInternal::KEY.to_string(),
            RouterTargetInternal::InternetGateway.as_meta(),
        ));
        layer.add_rule(Direction::Out, rule.finalize());
    }

    pb.add_layer(layer, Pos::After(ROUTER_LAYER_NAME))
}

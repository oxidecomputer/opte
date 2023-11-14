// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

use super::router::RouterTargetInternal;
use super::router::ROUTER_LAYER_NAME;
use crate::api::Ipv4Cfg;
use crate::api::Ipv6Cfg;
use crate::api::VpcCfg;
use alloc::string::ToString;
use alloc::sync::Arc;
use core::num::NonZeroU32;
use core::result::Result;
use opte::api::Direction;
use opte::api::OpteError;
use opte::engine::ether::ETHER_TYPE_IPV4;
use opte::engine::ether::ETHER_TYPE_IPV6;
use opte::engine::layer::DefaultAction;
use opte::engine::layer::Layer;
use opte::engine::layer::LayerActions;
use opte::engine::nat::InboundNat;
use opte::engine::nat::OutboundNat;
use opte::engine::port::meta::ActionMetaValue;
use opte::engine::port::PortBuilder;
use opte::engine::port::Pos;
use opte::engine::predicate::EtherTypeMatch;
use opte::engine::predicate::Ipv4AddrMatch;
use opte::engine::predicate::Ipv6AddrMatch;
use opte::engine::predicate::Predicate;
use opte::engine::rule::Action;
use opte::engine::rule::Rule;
use opte::engine::snat::NatPool;
use opte::engine::snat::SNat;

pub const NAT_LAYER_NAME: &str = "nat";
const FLOATING_ONE_TO_ONE_NAT_PRIORITY: u16 = 5;
const EPHEMERAL_ONE_TO_ONE_NAT_PRIORITY: u16 = 10;
const SNAT_PRIORITY: u16 = 100;

pub fn setup(
    pb: &mut PortBuilder,
    cfg: &VpcCfg,
    ft_limit: NonZeroU32,
) -> Result<(), OpteError> {
    // The NAT layer is rewrite layer and not a filtering one. Any
    // packets that don't match should be allowed to pass through to
    // the next layer.
    let actions = LayerActions {
        actions: vec![],
        default_in: DefaultAction::Allow,
        default_out: DefaultAction::Allow,
    };
    let mut layer = Layer::new(NAT_LAYER_NAME, pb.name(), actions, ft_limit);
    if let Some(ipv4_cfg) = cfg.ipv4_cfg() {
        setup_ipv4_nat(&mut layer, ipv4_cfg)?;
    }
    if let Some(ipv6_cfg) = cfg.ipv6_cfg() {
        setup_ipv6_nat(&mut layer, ipv6_cfg)?;
    }
    pb.add_layer(layer, Pos::After(ROUTER_LAYER_NAME))
}

// TODO: modify this and below to work with `set_rules` or similar so that we can
//       call at runtime.
// TODO: remove this code duplication.
fn setup_ipv4_nat(
    layer: &mut Layer,
    ip_cfg: &Ipv4Cfg,
) -> Result<(), OpteError> {
    // When it comes to NAT we always prefer using 1:1 NAT of external
    // IP to SNAT, preferring floating IPs over ephemeral.
    // To achieve this we place the NAT rules at a lower
    // priority than SNAT.
    let in_nat = Arc::new(InboundNat::new(ip_cfg.private_ip));

    if !ip_cfg.floating_ips.is_empty() {
        let mut out_nat = Rule::new(
            FLOATING_ONE_TO_ONE_NAT_PRIORITY,
            Action::Stateful(Arc::new(OutboundNat::new(
                ip_cfg.private_ip,
                &ip_cfg.floating_ips,
            ))),
        );
        out_nat.add_predicate(Predicate::InnerEtherType(vec![
            EtherTypeMatch::Exact(ETHER_TYPE_IPV4),
        ]));
        out_nat.add_predicate(Predicate::Meta(
            RouterTargetInternal::KEY.to_string(),
            RouterTargetInternal::InternetGateway.as_meta(),
        ));
        layer.add_rule(Direction::Out, out_nat.finalize());

        // 1:1 NAT inbound packets destined for external IP.
        let mut in_nat = Rule::new(
            FLOATING_ONE_TO_ONE_NAT_PRIORITY,
            Action::Stateful(in_nat.clone()),
        );
        let matches = ip_cfg
            .floating_ips
            .iter()
            .copied()
            .map(Ipv4AddrMatch::Exact)
            .collect();
        in_nat.add_predicate(Predicate::InnerDstIp4(matches));
        layer.add_rule(Direction::In, in_nat.finalize());
    }

    if let Some(ip4) = ip_cfg.ephemeral_ip {
        // 1:1 NAT outbound packets destined for internet gateway.
        let mut out_nat = Rule::new(
            EPHEMERAL_ONE_TO_ONE_NAT_PRIORITY,
            Action::Stateful(Arc::new(OutboundNat::new(
                ip_cfg.private_ip,
                &[ip4],
            ))),
        );
        out_nat.add_predicate(Predicate::InnerEtherType(vec![
            EtherTypeMatch::Exact(ETHER_TYPE_IPV4),
        ]));
        out_nat.add_predicate(Predicate::Meta(
            RouterTargetInternal::KEY.to_string(),
            RouterTargetInternal::InternetGateway.as_meta(),
        ));
        layer.add_rule(Direction::Out, out_nat.finalize());

        // 1:1 NAT inbound packets destined for external IP.
        let mut in_nat = Rule::new(
            EPHEMERAL_ONE_TO_ONE_NAT_PRIORITY,
            Action::Stateful(in_nat),
        );
        in_nat.add_predicate(Predicate::InnerDstIp4(vec![
            Ipv4AddrMatch::Exact(ip4),
        ]));
        layer.add_rule(Direction::In, in_nat.finalize());
    }

    if let Some(snat_cfg) = &ip_cfg.snat {
        let pool = NatPool::new();
        pool.add(
            ip_cfg.private_ip,
            snat_cfg.external_ip,
            snat_cfg.ports.clone(),
        );
        let snat = SNat::new(ip_cfg.private_ip, Arc::new(pool));
        let mut rule =
            Rule::new(SNAT_PRIORITY, Action::Stateful(Arc::new(snat)));

        rule.add_predicate(Predicate::InnerEtherType(vec![
            EtherTypeMatch::Exact(ETHER_TYPE_IPV4),
        ]));
        rule.add_predicate(Predicate::Meta(
            RouterTargetInternal::KEY.to_string(),
            RouterTargetInternal::InternetGateway.as_meta(),
        ));
        layer.add_rule(Direction::Out, rule.finalize());
    }
    Ok(())
}

fn setup_ipv6_nat(
    layer: &mut Layer,
    ip_cfg: &Ipv6Cfg,
) -> Result<(), OpteError> {
    // When it comes to NAT we always prefer using 1:1 NAT of external
    // IP to SNAT, preferring floating IPs over ephemeral.
    // To achieve this we place the NAT rules at a lower
    // priority than SNAT.
    let in_nat = Arc::new(InboundNat::new(ip_cfg.private_ip));

    if !ip_cfg.floating_ips.is_empty() {
        let mut out_nat = Rule::new(
            FLOATING_ONE_TO_ONE_NAT_PRIORITY,
            Action::Stateful(Arc::new(OutboundNat::new(
                ip_cfg.private_ip,
                &ip_cfg.floating_ips,
            ))),
        );
        out_nat.add_predicate(Predicate::InnerEtherType(vec![
            EtherTypeMatch::Exact(ETHER_TYPE_IPV4),
        ]));
        out_nat.add_predicate(Predicate::Meta(
            RouterTargetInternal::KEY.to_string(),
            RouterTargetInternal::InternetGateway.as_meta(),
        ));
        layer.add_rule(Direction::Out, out_nat.finalize());

        // 1:1 NAT inbound packets destined for external IP.
        let mut in_nat = Rule::new(
            FLOATING_ONE_TO_ONE_NAT_PRIORITY,
            Action::Stateful(in_nat.clone()),
        );
        let matches = ip_cfg
            .floating_ips
            .iter()
            .copied()
            .map(Ipv6AddrMatch::Exact)
            .collect();
        in_nat.add_predicate(Predicate::InnerDstIp6(matches));
        layer.add_rule(Direction::In, in_nat.finalize());
    }

    if let Some(ip6) = ip_cfg.ephemeral_ip {
        // 1:1 NAT outbound packets destined for internet gateway.
        let mut out_nat = Rule::new(
            EPHEMERAL_ONE_TO_ONE_NAT_PRIORITY,
            Action::Stateful(Arc::new(OutboundNat::new(
                ip_cfg.private_ip,
                &[ip6],
            ))),
        );
        out_nat.add_predicate(Predicate::InnerEtherType(vec![
            EtherTypeMatch::Exact(ETHER_TYPE_IPV6),
        ]));
        out_nat.add_predicate(Predicate::Meta(
            RouterTargetInternal::KEY.to_string(),
            RouterTargetInternal::InternetGateway.as_meta(),
        ));
        layer.add_rule(Direction::Out, out_nat.finalize());

        // 1:1 NAT inbound packets destined for external IP.
        let mut in_nat = Rule::new(
            EPHEMERAL_ONE_TO_ONE_NAT_PRIORITY,
            Action::Stateful(in_nat),
        );
        in_nat.add_predicate(Predicate::InnerDstIp6(vec![
            Ipv6AddrMatch::Exact(ip6),
        ]));
        layer.add_rule(Direction::In, in_nat.finalize());
    }

    if let Some(ref snat_cfg) = ip_cfg.snat {
        let pool = NatPool::new();
        pool.add(
            ip_cfg.private_ip,
            snat_cfg.external_ip,
            snat_cfg.ports.clone(),
        );
        let snat = SNat::new(ip_cfg.private_ip, Arc::new(pool));
        let mut rule =
            Rule::new(SNAT_PRIORITY, Action::Stateful(Arc::new(snat)));

        rule.add_predicate(Predicate::InnerEtherType(vec![
            EtherTypeMatch::Exact(ETHER_TYPE_IPV6),
        ]));
        rule.add_predicate(Predicate::Meta(
            RouterTargetInternal::KEY.to_string(),
            RouterTargetInternal::InternetGateway.as_meta(),
        ));
        layer.add_rule(Direction::Out, rule.finalize());
    }
    Ok(())
}

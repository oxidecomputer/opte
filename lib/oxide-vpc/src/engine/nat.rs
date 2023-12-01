// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

use super::router::RouterTargetInternal;
use super::router::ROUTER_LAYER_NAME;
use super::VpcNetwork;
use crate::api::ExternalIpCfg;
use crate::api::SetExternalIpsReq;
use crate::cfg::IpCfg;
use crate::cfg::Ipv4Cfg;
use crate::cfg::Ipv6Cfg;
use crate::cfg::VpcCfg;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::num::NonZeroU32;
use core::result::Result;
use opte::api::IpAddr;
use opte::api::Ipv4Addr;
use opte::api::Ipv6Addr;
use opte::api::OpteError;
use opte::dynamic::Dynamic;
use opte::engine::ether::ETHER_TYPE_IPV4;
use opte::engine::ether::ETHER_TYPE_IPV6;
use opte::engine::layer::DefaultAction;
use opte::engine::layer::Layer;
use opte::engine::layer::LayerActions;
use opte::engine::nat::InboundNat;
use opte::engine::nat::OutboundNat;
use opte::engine::nat::VerifyAddr;
use opte::engine::port::meta::ActionMetaValue;
use opte::engine::port::Port;
use opte::engine::port::PortBuilder;
use opte::engine::port::Pos;
use opte::engine::predicate::EtherTypeMatch;
use opte::engine::predicate::Ipv4AddrMatch;
use opte::engine::predicate::Ipv6AddrMatch;
use opte::engine::predicate::Predicate;
use opte::engine::rule::Action;
use opte::engine::rule::Finalized;
use opte::engine::rule::Rule;
use opte::engine::snat::ConcreteIpAddr;
use opte::engine::snat::SNat;

pub const NAT_LAYER_NAME: &str = "nat";
const FLOATING_ONE_TO_ONE_NAT_PRIORITY: u16 = 5;
const EPHEMERAL_ONE_TO_ONE_NAT_PRIORITY: u16 = 10;
const SNAT_PRIORITY: u16 = 100;

// A note on concurrency correctness of accessing the `Dynamic`:
// * Validation will not be triggered until table is marked dirty
//   after config is rebuilt.
// * A packet may see a future `ExternalIpCfg` during `is_addr_valid`:
//   in the worst case, this will pre-emptively remove a flow.
// * If a flow is marked clean but followed by a new config insert,
//   the flow will be re-marked as dirty once the ioctl thread acquires
//   the table lock.
#[derive(Debug)]
struct ExtIps<T: ConcreteIpAddr>(Dynamic<ExternalIpCfg<T>>);

impl VerifyAddr for ExtIps<Ipv4Addr> {
    fn is_addr_valid(&self, addr: &IpAddr) -> bool {
        let IpAddr::Ip4(ip) = addr else {
            return false;
        };

        let snap = self.0.load();
        snap.ephemeral_ip == Some(*ip) || snap.floating_ips.contains(ip)
    }
}

impl VerifyAddr for ExtIps<Ipv6Addr> {
    fn is_addr_valid(&self, addr: &IpAddr) -> bool {
        let IpAddr::Ip6(ip) = addr else {
            return false;
        };

        let snap = self.0.load();
        snap.ephemeral_ip == Some(*ip) || snap.floating_ips.contains(ip)
    }
}

/// Create the NAT layer for a new port, returning the number of flowtable layers
/// required.
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
    let (in_rules, out_rules) = create_nat_rules(cfg)?;
    layer.set_rules(in_rules, out_rules);
    pb.add_layer(layer, Pos::After(ROUTER_LAYER_NAME))
}

#[allow(clippy::type_complexity)]
fn create_nat_rules(
    cfg: &VpcCfg,
) -> Result<(Vec<Rule<Finalized>>, Vec<Rule<Finalized>>), OpteError> {
    let mut in_rules = vec![];
    let mut out_rules = vec![];
    if let Some(ipv4_cfg) = cfg.ipv4_cfg() {
        setup_ipv4_nat(ipv4_cfg, &mut in_rules, &mut out_rules)?;
    }
    if let Some(ipv6_cfg) = cfg.ipv6_cfg() {
        setup_ipv6_nat(ipv6_cfg, &mut in_rules, &mut out_rules)?;
    }
    Ok((in_rules, out_rules))
}

// TODO: remove this code duplication.
fn setup_ipv4_nat(
    ip_cfg: &Ipv4Cfg,
    in_rules: &mut Vec<Rule<Finalized>>,
    out_rules: &mut Vec<Rule<Finalized>>,
) -> Result<(), OpteError> {
    // When it comes to NAT we always prefer using 1:1 NAT of external
    // IP to SNAT, preferring floating IPs over ephemeral.
    // To achieve this we place the NAT rules at a lower
    // priority than SNAT.
    let verifier = Arc::new(ExtIps(ip_cfg.external_ips.clone()));
    let in_nat = Arc::new(InboundNat::new(ip_cfg.private_ip, verifier.clone()));
    let external_cfg = ip_cfg.external_ips.load();

    if !external_cfg.floating_ips.is_empty() {
        let mut out_nat = Rule::new(
            FLOATING_ONE_TO_ONE_NAT_PRIORITY,
            Action::Stateful(Arc::new(OutboundNat::new(
                ip_cfg.private_ip,
                &external_cfg.floating_ips,
                verifier.clone(),
            ))),
        );
        out_nat.add_predicate(Predicate::InnerEtherType(vec![
            EtherTypeMatch::Exact(ETHER_TYPE_IPV4),
        ]));
        out_nat.add_predicate(Predicate::Meta(
            RouterTargetInternal::KEY.to_string(),
            RouterTargetInternal::InternetGateway.as_meta(),
        ));
        out_rules.push(out_nat.finalize());

        // 1:1 NAT inbound packets destined for external IP.
        let mut in_nat = Rule::new(
            FLOATING_ONE_TO_ONE_NAT_PRIORITY,
            Action::Stateful(in_nat.clone()),
        );
        let matches = external_cfg
            .floating_ips
            .iter()
            .copied()
            .map(Ipv4AddrMatch::Exact)
            .collect();
        in_nat.add_predicate(Predicate::InnerDstIp4(matches));
        in_rules.push(in_nat.finalize());
    }

    if let Some(ip4) = external_cfg.ephemeral_ip {
        // 1:1 NAT outbound packets destined for internet gateway.
        let mut out_nat = Rule::new(
            EPHEMERAL_ONE_TO_ONE_NAT_PRIORITY,
            Action::Stateful(Arc::new(OutboundNat::new(
                ip_cfg.private_ip,
                &[ip4],
                verifier,
            ))),
        );
        out_nat.add_predicate(Predicate::InnerEtherType(vec![
            EtherTypeMatch::Exact(ETHER_TYPE_IPV4),
        ]));
        out_nat.add_predicate(Predicate::Meta(
            RouterTargetInternal::KEY.to_string(),
            RouterTargetInternal::InternetGateway.as_meta(),
        ));
        out_rules.push(out_nat.finalize());

        // 1:1 NAT inbound packets destined for external IP.
        let mut in_nat = Rule::new(
            EPHEMERAL_ONE_TO_ONE_NAT_PRIORITY,
            Action::Stateful(in_nat),
        );
        in_nat.add_predicate(Predicate::InnerDstIp4(vec![
            Ipv4AddrMatch::Exact(ip4),
        ]));
        in_rules.push(in_nat.finalize());
    }

    if let Some(snat_cfg) = &external_cfg.snat {
        let snat = SNat::new(ip_cfg.private_ip);
        snat.add(
            ip_cfg.private_ip,
            snat_cfg.external_ip,
            snat_cfg.ports.clone(),
        );
        let mut rule =
            Rule::new(SNAT_PRIORITY, Action::Stateful(Arc::new(snat)));

        rule.add_predicate(Predicate::InnerEtherType(vec![
            EtherTypeMatch::Exact(ETHER_TYPE_IPV4),
        ]));
        rule.add_predicate(Predicate::Meta(
            RouterTargetInternal::KEY.to_string(),
            RouterTargetInternal::InternetGateway.as_meta(),
        ));
        out_rules.push(rule.finalize());
    }
    Ok(())
}

fn setup_ipv6_nat(
    ip_cfg: &Ipv6Cfg,
    in_rules: &mut Vec<Rule<Finalized>>,
    out_rules: &mut Vec<Rule<Finalized>>,
) -> Result<(), OpteError> {
    // When it comes to NAT we always prefer using 1:1 NAT of external
    // IP to SNAT, preferring floating IPs over ephemeral.
    // To achieve this we place the NAT rules at a lower
    // priority than SNAT.
    let verifier = Arc::new(ExtIps(ip_cfg.external_ips.clone()));
    let in_nat = Arc::new(InboundNat::new(ip_cfg.private_ip, verifier.clone()));
    let external_cfg = ip_cfg.external_ips.load();

    if !external_cfg.floating_ips.is_empty() {
        let mut out_nat = Rule::new(
            FLOATING_ONE_TO_ONE_NAT_PRIORITY,
            Action::Stateful(Arc::new(OutboundNat::new(
                ip_cfg.private_ip,
                &external_cfg.floating_ips,
                verifier.clone(),
            ))),
        );
        out_nat.add_predicate(Predicate::InnerEtherType(vec![
            EtherTypeMatch::Exact(ETHER_TYPE_IPV6),
        ]));
        out_nat.add_predicate(Predicate::Meta(
            RouterTargetInternal::KEY.to_string(),
            RouterTargetInternal::InternetGateway.as_meta(),
        ));
        out_rules.push(out_nat.finalize());

        // 1:1 NAT inbound packets destined for external IP.
        let mut in_nat = Rule::new(
            FLOATING_ONE_TO_ONE_NAT_PRIORITY,
            Action::Stateful(in_nat.clone()),
        );
        let matches = external_cfg
            .floating_ips
            .iter()
            .copied()
            .map(Ipv6AddrMatch::Exact)
            .collect();
        in_nat.add_predicate(Predicate::InnerDstIp6(matches));
        in_rules.push(in_nat.finalize());
    }

    if let Some(ip6) = external_cfg.ephemeral_ip {
        // 1:1 NAT outbound packets destined for internet gateway.
        let mut out_nat = Rule::new(
            EPHEMERAL_ONE_TO_ONE_NAT_PRIORITY,
            Action::Stateful(Arc::new(OutboundNat::new(
                ip_cfg.private_ip,
                &[ip6],
                verifier,
            ))),
        );
        out_nat.add_predicate(Predicate::InnerEtherType(vec![
            EtherTypeMatch::Exact(ETHER_TYPE_IPV6),
        ]));
        out_nat.add_predicate(Predicate::Meta(
            RouterTargetInternal::KEY.to_string(),
            RouterTargetInternal::InternetGateway.as_meta(),
        ));
        out_rules.push(out_nat.finalize());

        // 1:1 NAT inbound packets destined for external IP.
        let mut in_nat = Rule::new(
            EPHEMERAL_ONE_TO_ONE_NAT_PRIORITY,
            Action::Stateful(in_nat),
        );
        in_nat.add_predicate(Predicate::InnerDstIp6(vec![
            Ipv6AddrMatch::Exact(ip6),
        ]));
        in_rules.push(in_nat.finalize());
    }

    if let Some(ref snat_cfg) = external_cfg.snat {
        let snat = SNat::new(ip_cfg.private_ip);
        snat.add(
            ip_cfg.private_ip,
            snat_cfg.external_ip,
            snat_cfg.ports.clone(),
        );
        let mut rule =
            Rule::new(SNAT_PRIORITY, Action::Stateful(Arc::new(snat)));

        rule.add_predicate(Predicate::InnerEtherType(vec![
            EtherTypeMatch::Exact(ETHER_TYPE_IPV6),
        ]));
        rule.add_predicate(Predicate::Meta(
            RouterTargetInternal::KEY.to_string(),
            RouterTargetInternal::InternetGateway.as_meta(),
        ));
        out_rules.push(rule.finalize());
    }
    Ok(())
}

pub fn set_nat_rules(
    cfg: &VpcCfg,
    port: &Port<VpcNetwork>,
    req: SetExternalIpsReq,
) -> Result<(), OpteError> {
    // This procedure only holds one lock at a time: a `Dynamic`'s shared
    // space writelock, *or* the table lock via set_rules_soft.
    // The datapath will hold the table lock for processing, *and* the `Dynamic`'s
    // readlock when validating dirty match entries.
    // As such, the two should not deadlock.
    match (&cfg.ip_cfg, req.external_ips_v4, req.external_ips_v6) {
        (IpCfg::DualStack { ipv4, ipv6 }, Some(new_v4), Some(new_v6)) => {
            ipv4.external_ips.store(new_v4);
            ipv6.external_ips.store(new_v6);
        }
        (
            IpCfg::Ipv4(ipv4) | IpCfg::DualStack { ipv4, .. },
            Some(new_v4),
            None,
        ) => {
            ipv4.external_ips.store(new_v4);
        }
        (
            IpCfg::Ipv6(ipv6) | IpCfg::DualStack { ipv6, .. },
            None,
            Some(new_v6),
        ) => {
            ipv6.external_ips.store(new_v6);
        }
        _ => return Err(OpteError::InvalidIpCfg),
    }

    let (in_rules, out_rules) = create_nat_rules(cfg)?;
    port.set_rules_soft(NAT_LAYER_NAME, in_rules, out_rules)
}

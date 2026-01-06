// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use super::VpcNetwork;
use super::gateway;
use super::overlay::VpcMappings;
use super::router::ROUTER_LAYER_NAME;
use super::router::RouterTargetClass;
use super::router::RouterTargetInternal;
use crate::api::AttachSubnetReq;
use crate::api::DetachSubnetReq;
use crate::api::DetachSubnetResp;
use crate::api::ExternalIpCfg;
use crate::api::InternetGatewayMap;
use crate::api::SetExternalIpsReq;
use crate::cfg::IpCfg;
use crate::cfg::Ipv4Cfg;
use crate::cfg::Ipv6Cfg;
use crate::cfg::VpcCfg;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::num::NonZeroU32;
use opte::api::IpAddr;
use opte::api::IpCidr;
use opte::api::Ipv4Addr;
use opte::api::Ipv6Addr;
use opte::api::OpteError;
use opte::dynamic::Dynamic;
use opte::engine::ether::ETHER_TYPE_IPV4;
use opte::engine::ether::ETHER_TYPE_IPV6;
use opte::engine::layer::DefaultAction;
use opte::engine::layer::Layer;
use opte::engine::layer::LayerActions;
use opte::engine::nat::ExternalIpTagger;
use opte::engine::nat::InboundNat;
use opte::engine::nat::OutboundNat;
use opte::engine::nat::VerifyAddr;
use opte::engine::port::Port;
use opte::engine::port::PortBuilder;
use opte::engine::port::Pos;
use opte::engine::port::meta::ActionMetaValue;
use opte::engine::predicate::EtherTypeMatch;
use opte::engine::predicate::Ipv4AddrMatch;
use opte::engine::predicate::Ipv6AddrMatch;
use opte::engine::predicate::Predicate;
use opte::engine::rule::Action;
use opte::engine::rule::Finalized;
use opte::engine::rule::Rule;
use opte::engine::snat::ConcreteIpAddr;
use opte::engine::snat::SNat;
use uuid::Uuid;

pub const NAT_LAYER_NAME: &str = "nat";
const EXTERNAL_ATTACHED_SUBNET_PRIORITY: u16 = 4;
const FLOATING_ONE_TO_ONE_NAT_PRIORITY: u16 = 5;
const EPHEMERAL_ONE_TO_ONE_NAT_PRIORITY: u16 = 10;
const SNAT_PRIORITY: u16 = 100;
const NO_EIP_PRIORITY: u16 = 255;

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
    // The NAT layer is generally rewrite layer and not a filtering one.
    // Any packets that don't match should be allowed to pass through to
    // the next layer.
    // There is one exception: a packet with an InternetGateway target
    // but no valid replacement source IP must be dropped, otherwise it will
    // be forwarded to boundary services.
    let actions = LayerActions {
        actions: vec![],
        default_in: DefaultAction::Allow,
        default_out: DefaultAction::Allow,
    };

    let mut layer = Layer::new(NAT_LAYER_NAME, pb.name(), actions, ft_limit);
    let (in_rules, out_rules) = create_nat_rules(cfg, None)?;
    layer.set_rules(in_rules, out_rules);
    pb.add_layer(layer, Pos::After(ROUTER_LAYER_NAME))
}

#[allow(clippy::type_complexity)]
fn create_nat_rules(
    cfg: &VpcCfg,
    inet_gw_map: Option<&InternetGatewayMap>,
) -> Result<(Vec<Rule<Finalized>>, Vec<Rule<Finalized>>), OpteError> {
    let mut in_rules = vec![];
    let mut out_rules = vec![];
    if let Some(ipv4_cfg) = cfg.ipv4_cfg() {
        setup_ipv4_nat(ipv4_cfg, &mut in_rules, &mut out_rules, inet_gw_map)?;
    }
    if let Some(ipv6_cfg) = cfg.ipv6_cfg() {
        setup_ipv6_nat(ipv6_cfg, &mut in_rules, &mut out_rules, inet_gw_map)?;
    }

    // Append an additional rule to drop any InternetGateway packets
    // which *did not* match an existing source IP address. This is
    // expected to occur in cases where we have assigned multiple
    // internet gateways but have no valid source address on a selected
    // IGW.
    let mut out_igw_nat_miss = Rule::new(NO_EIP_PRIORITY, Action::Deny);
    out_igw_nat_miss.add_predicate(Predicate::from_action_meta(
        RouterTargetClass::InternetGateway,
    ));
    out_rules.push(out_igw_nat_miss.finalize());

    Ok((in_rules, out_rules))
}

// TODO: remove this code duplication.
fn setup_ipv4_nat(
    ip_cfg: &Ipv4Cfg,
    in_rules: &mut Vec<Rule<Finalized>>,
    out_rules: &mut Vec<Rule<Finalized>>,
    inet_gw_map: Option<&BTreeMap<IpAddr, BTreeSet<Uuid>>>,
) -> Result<(), OpteError> {
    // When it comes to NAT we always prefer using 1:1 NAT of external
    // IP to SNAT, preferring floating IPs over ephemeral.
    // To achieve this we place the NAT rules at a lower
    // priority than SNAT.
    let verifier = Arc::new(ExtIps(ip_cfg.external_ips.clone()));
    let in_nat = Arc::new(InboundNat::new(ip_cfg.private_ip, verifier.clone()));
    let external_cfg = ip_cfg.external_ips.load();

    let attached_subnets: Vec<_> = ip_cfg
        .attached_subnets
        .load()
        .iter()
        .filter_map(|(k, v)| v.is_external.then_some(Ipv4AddrMatch::Prefix(*k)))
        .collect();

    if !attached_subnets.is_empty() {
        // Use of this rule implicitly requires that we have selected *an*
        // InternetGateway routing target by the time we reach the overlay layer.
        // Don't match on the RouterTargetClass as a predicate here, as we need
        // to record that a known EIP was used as a source.
        let mut out_subnet = Rule::new(
            EXTERNAL_ATTACHED_SUBNET_PRIORITY,
            Action::Meta(Arc::new(ExternalIpTagger)),
        );
        out_subnet
            .add_predicate(Predicate::InnerSrcIp4(attached_subnets.clone()));
        out_rules.push(out_subnet.finalize());

        // Inbound rules here aren't *strictly* necessary, as the control plane
        // should not be assigning us EIPs which overlap with these subnets.
        // We would then fall through to the default `Allow`.
        //
        // Install these as belts and braces, regardless.
        let mut in_subnet =
            Rule::new(EXTERNAL_ATTACHED_SUBNET_PRIORITY, Action::Allow);
        in_subnet.add_predicate(Predicate::InnerDstIp4(attached_subnets));
        in_rules.push(in_subnet.finalize());
    }

    // Outbound IP selection needs to be gated upon which internet gateway was
    // chosen during routing.
    // We need to partition FIPs into separate lists based on which internet gateway
    // each belongs to. This may in future extend to further SNATs from each
    // attached Internet Gateway, but not today.
    if !external_cfg.floating_ips.is_empty() {
        let mut fips_by_gw: BTreeMap<Option<Uuid>, Vec<Ipv4Addr>> =
            BTreeMap::new();
        for ip in &external_cfg.floating_ips {
            let gw_mappings =
                inet_gw_map.and_then(|map| map.get(&(*ip).into())).cloned();
            if let Some(igw_list) = gw_mappings {
                for igw in igw_list {
                    let entry = fips_by_gw.entry(Some(igw));
                    let ips = entry.or_default();
                    ips.push(*ip);
                }
            } else {
                let entry = fips_by_gw.entry(None);
                let ips = entry.or_default();
                ips.push(*ip);
            };
        }

        for (gw, fips) in fips_by_gw {
            let mut out_nat = Rule::new(
                FLOATING_ONE_TO_ONE_NAT_PRIORITY,
                Action::Stateful(Arc::new(OutboundNat::new(
                    ip_cfg.private_ip,
                    &fips[..],
                    verifier.clone(),
                ))),
            );
            out_nat.add_predicate(Predicate::InnerEtherType(vec![
                EtherTypeMatch::Exact(ETHER_TYPE_IPV4),
            ]));
            out_nat.add_predicate(Predicate::Meta(
                RouterTargetInternal::KEY.to_string(),
                RouterTargetInternal::InternetGateway(gw)
                    .as_meta()
                    .into_owned(),
            ));
            out_rules.push(out_nat.finalize());
        }

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
        let igw_matches = match inet_gw_map {
            Some(inet_gw_map) => match inet_gw_map.get(&(ip4.into())) {
                Some(igw_set) => {
                    igw_set.iter().copied().map(Option::Some).collect()
                }
                None => vec![None],
            },
            None => vec![None],
        };

        for igw_id in igw_matches {
            let mut out_nat = Rule::new(
                EPHEMERAL_ONE_TO_ONE_NAT_PRIORITY,
                Action::Stateful(Arc::new(OutboundNat::new(
                    ip_cfg.private_ip,
                    &[ip4],
                    verifier.clone(),
                ))),
            );
            out_nat.add_predicate(Predicate::InnerEtherType(vec![
                EtherTypeMatch::Exact(ETHER_TYPE_IPV4),
            ]));
            out_nat.add_predicate(Predicate::Meta(
                RouterTargetInternal::KEY.to_string(),
                RouterTargetInternal::InternetGateway(igw_id)
                    .as_meta()
                    .into_owned(),
            ));
            out_rules.push(out_nat.finalize());
        }

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
        let igw_matches = match inet_gw_map {
            Some(inet_gw_map) => {
                match inet_gw_map.get(&(snat_cfg.external_ip.into())) {
                    Some(igw_set) => {
                        igw_set.iter().copied().map(Option::Some).collect()
                    }
                    None => vec![None],
                }
            }
            None => vec![None],
        };

        let snat = SNat::new(ip_cfg.private_ip);
        snat.add(
            ip_cfg.private_ip,
            snat_cfg.external_ip,
            snat_cfg.ports.clone(),
        );
        let snat = Arc::new(snat);

        for igw_id in igw_matches {
            let mut rule =
                Rule::new(SNAT_PRIORITY, Action::Stateful(snat.clone()));

            rule.add_predicate(Predicate::InnerEtherType(vec![
                EtherTypeMatch::Exact(ETHER_TYPE_IPV4),
            ]));
            rule.add_predicate(Predicate::Meta(
                RouterTargetInternal::KEY.to_string(),
                RouterTargetInternal::InternetGateway(igw_id)
                    .as_meta()
                    .into_owned(),
            ));
            out_rules.push(rule.finalize());
        }
    }
    Ok(())
}

fn setup_ipv6_nat(
    ip_cfg: &Ipv6Cfg,
    in_rules: &mut Vec<Rule<Finalized>>,
    out_rules: &mut Vec<Rule<Finalized>>,
    inet_gw_map: Option<&BTreeMap<IpAddr, BTreeSet<Uuid>>>,
) -> Result<(), OpteError> {
    // When it comes to NAT we always prefer using 1:1 NAT of external
    // IP to SNAT, preferring floating IPs over ephemeral.
    // To achieve this we place the NAT rules at a lower
    // priority than SNAT.
    let verifier = Arc::new(ExtIps(ip_cfg.external_ips.clone()));
    let in_nat = Arc::new(InboundNat::new(ip_cfg.private_ip, verifier.clone()));
    let external_cfg = ip_cfg.external_ips.load();

    let attached_subnets: Vec<_> = ip_cfg
        .attached_subnets
        .load()
        .iter()
        .filter_map(|(k, v)| v.is_external.then_some(Ipv6AddrMatch::Prefix(*k)))
        .collect();

    if !attached_subnets.is_empty() {
        // Use of this rule implicitly requires that we have selected *an*
        // InternetGateway routing target by the time we reach the overlay layer.
        // Don't match on the RouterTargetClass as a predicate here, as we need
        // to record that a known EIP was used as a source.
        let mut out_subnet = Rule::new(
            EXTERNAL_ATTACHED_SUBNET_PRIORITY,
            Action::Meta(Arc::new(ExternalIpTagger)),
        );
        out_subnet
            .add_predicate(Predicate::InnerSrcIp6(attached_subnets.clone()));
        out_rules.push(out_subnet.finalize());

        // Inbound rules here aren't *strictly* necessary, as the control plane
        // should not be assigning us EIPs which overlap with these subnets.
        // We would then fall through to the default `Allow`.
        //
        // Install these as belts and braces, regardless.
        let mut in_subnet =
            Rule::new(EXTERNAL_ATTACHED_SUBNET_PRIORITY, Action::Allow);
        in_subnet.add_predicate(Predicate::InnerDstIp6(attached_subnets));
        in_rules.push(in_subnet.finalize());
    }

    // See `setup_ipv4_nat` for an explanation on partitioning FIPs
    // by internet gateway ID.
    if !external_cfg.floating_ips.is_empty() {
        let mut fips_by_gw: BTreeMap<Option<Uuid>, Vec<Ipv6Addr>> =
            BTreeMap::new();
        for ip in &external_cfg.floating_ips {
            let gw_mappings =
                inet_gw_map.and_then(|map| map.get(&(*ip).into())).cloned();
            if let Some(igw_list) = gw_mappings {
                for igw in igw_list {
                    let entry = fips_by_gw.entry(Some(igw));
                    let ips = entry.or_default();
                    ips.push(*ip);
                }
            } else {
                let entry = fips_by_gw.entry(None);
                let ips = entry.or_default();
                ips.push(*ip);
            };
        }

        for (gw, fips) in fips_by_gw {
            let mut out_nat = Rule::new(
                FLOATING_ONE_TO_ONE_NAT_PRIORITY,
                Action::Stateful(Arc::new(OutboundNat::new(
                    ip_cfg.private_ip,
                    &fips[..],
                    verifier.clone(),
                ))),
            );
            out_nat.add_predicate(Predicate::InnerEtherType(vec![
                EtherTypeMatch::Exact(ETHER_TYPE_IPV6),
            ]));
            out_nat.add_predicate(Predicate::Meta(
                RouterTargetInternal::KEY.to_string(),
                RouterTargetInternal::InternetGateway(gw)
                    .as_meta()
                    .into_owned(),
            ));
            out_rules.push(out_nat.finalize());
        }

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
        let igw_matches = match inet_gw_map {
            Some(inet_gw_map) => match inet_gw_map.get(&(ip6.into())) {
                Some(igw_set) => {
                    igw_set.iter().copied().map(Option::Some).collect()
                }
                None => vec![None],
            },
            None => vec![None],
        };

        for igw_id in igw_matches {
            let mut out_nat = Rule::new(
                EPHEMERAL_ONE_TO_ONE_NAT_PRIORITY,
                Action::Stateful(Arc::new(OutboundNat::new(
                    ip_cfg.private_ip,
                    &[ip6],
                    verifier.clone(),
                ))),
            );
            out_nat.add_predicate(Predicate::InnerEtherType(vec![
                EtherTypeMatch::Exact(ETHER_TYPE_IPV6),
            ]));
            out_nat.add_predicate(Predicate::Meta(
                RouterTargetInternal::KEY.to_string(),
                RouterTargetInternal::InternetGateway(igw_id)
                    .as_meta()
                    .into_owned(),
            ));
            out_rules.push(out_nat.finalize());
        }

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
        let igw_matches = match inet_gw_map {
            Some(inet_gw_map) => {
                match inet_gw_map.get(&(snat_cfg.external_ip.into())) {
                    Some(igw_set) => {
                        igw_set.iter().copied().map(Option::Some).collect()
                    }
                    None => vec![None],
                }
            }
            None => vec![None],
        };

        let snat = SNat::new(ip_cfg.private_ip);
        snat.add(
            ip_cfg.private_ip,
            snat_cfg.external_ip,
            snat_cfg.ports.clone(),
        );
        let snat = Arc::new(snat);

        for igw_id in igw_matches {
            let mut rule =
                Rule::new(SNAT_PRIORITY, Action::Stateful(snat.clone()));

            rule.add_predicate(Predicate::InnerEtherType(vec![
                EtherTypeMatch::Exact(ETHER_TYPE_IPV6),
            ]));
            rule.add_predicate(Predicate::Meta(
                RouterTargetInternal::KEY.to_string(),
                RouterTargetInternal::InternetGateway(igw_id)
                    .as_meta()
                    .into_owned(),
            ));
            out_rules.push(rule.finalize());
        }
    }
    Ok(())
}

pub fn set_external_ips(
    port: &Port<VpcNetwork>,
    req: SetExternalIpsReq,
) -> Result<(), OpteError> {
    let cfg = &port.network().cfg;
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

    refresh_nat_rules(port, req.inet_gw_map.as_ref())
}

pub fn attach_subnet(
    port: &Port<VpcNetwork>,
    inet_gw_map: Option<&InternetGatewayMap>,
    vpc_mappings: &Arc<VpcMappings>,
    req: AttachSubnetReq,
) -> Result<(), OpteError> {
    let cfg = &port.network().cfg;
    let changed = match (req.cidr, &cfg.ip_cfg) {
        (IpCidr::Ip4(v4), IpCfg::Ipv4(v4_cfg))
        | (IpCidr::Ip4(v4), IpCfg::DualStack { ipv4: v4_cfg, .. }) => {
            v4_cfg.attached_subnets.update(|map| {
                let install = if let Some(val) = map.get(&v4) {
                    val != &req.cfg
                } else {
                    true
                };
                install.then(|| {
                    let mut out = map.clone();
                    out.insert(v4, req.cfg);
                    out
                })
            })
        }
        (IpCidr::Ip6(v6), IpCfg::Ipv6(v6_cfg))
        | (IpCidr::Ip6(v6), IpCfg::DualStack { ipv6: v6_cfg, .. }) => {
            v6_cfg.attached_subnets.update(|map| {
                let install = if let Some(val) = map.get(&v6) {
                    val != &req.cfg
                } else {
                    true
                };
                install.then(|| {
                    let mut out = map.clone();
                    out.insert(v6, req.cfg);
                    out
                })
            })
        }
        // Trying to attach a CIDR class which this port cannot use.
        _ => return Err(OpteError::InvalidIpCfg),
    };

    if changed {
        refresh_nat_rules(port, inet_gw_map)?;
        gateway::set_gateway_rules(port, vpc_mappings.clone())?;
    }

    Ok(())
}

pub fn detach_subnet(
    port: &Port<VpcNetwork>,
    inet_gw_map: Option<&InternetGatewayMap>,
    vpc_mappings: &Arc<VpcMappings>,
    req: DetachSubnetReq,
) -> Result<DetachSubnetResp, OpteError> {
    let cfg = &port.network().cfg;
    let changed = match (req.cidr, &cfg.ip_cfg) {
        (IpCidr::Ip4(v4), IpCfg::Ipv4(v4_cfg))
        | (IpCidr::Ip4(v4), IpCfg::DualStack { ipv4: v4_cfg, .. }) => {
            v4_cfg.attached_subnets.update(|map| {
                map.contains_key(&v4).then(|| {
                    let mut out = map.clone();
                    out.remove(&v4);
                    out
                })
            })
        }
        (IpCidr::Ip6(v6), IpCfg::Ipv6(v6_cfg))
        | (IpCidr::Ip6(v6), IpCfg::DualStack { ipv6: v6_cfg, .. }) => {
            v6_cfg.attached_subnets.update(|map| {
                map.contains_key(&v6).then(|| {
                    let mut out = map.clone();
                    out.remove(&v6);
                    out
                })
            })
        }
        // Trying to attach a CIDR class which this port cannot use.
        _ => return Err(OpteError::InvalidIpCfg),
    };

    if changed {
        refresh_nat_rules(port, inet_gw_map)?;
        gateway::set_gateway_rules(port, vpc_mappings.clone())?;
    }

    Ok(if !changed {
        DetachSubnetResp::NotFound
    } else {
        DetachSubnetResp::Ok(req.cidr)
    })
}

fn refresh_nat_rules(
    port: &Port<VpcNetwork>,
    inet_gw_map: Option<&InternetGatewayMap>,
) -> Result<(), OpteError> {
    let cfg = &port.network().cfg;
    let (in_rules, out_rules) = create_nat_rules(cfg, inet_gw_map)?;
    port.set_rules_soft(NAT_LAYER_NAME, in_rules, out_rules)
}

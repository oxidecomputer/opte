// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! The Oxide VPC Virtual Gateway.
//!
//! This layer is responsible for emulating a physical gateway to the
//! guest.
//!
//! # No Spoof Outbound
//!
//! One of the rules we set directly in this layer is the no spoof
//! rule as described in RFD 21 §2.8.2. The no spoof rule dictates
//! that we only allow outbound traffic from the guest's VPC IP and
//! MAC address; all other traffic should be denied. This prevents any
//! given guest interface from spoofing an IP it does not own.
//!
//! # Add VNI to Action Meta
//!
//! We use the outbound no spoof check as a convenient place to insert
//! the VNI of the destination into the action metadata. This can be
//! used by the firewall to filter traffic by VNI (VPC).
//!
//! # L3 Unicast Inbound
//!
//! We limit all inbound traffic to that destined for the guest's VPC
//! IP and MAC address. If the VPC network as a whole is operating
//! correctly, we should never deliver traffic destined for one guest
//! to some other guest's interface. However, should such an event
//! occur, this offers a final filter preventing it from reaching the
//! guest. The only traffic a guest can see is the traffic between
//! itself and the gateway or any unicast L3 traffic addressed to it.
//! Importantly, a guest can't place their NIC in promiscuous mode and
//! see traffic for other guests -- it has no visibility past the
//! gateway.
//!
//! # Link-Local IPv6
//!
//! No IPv6 link-local traffic should ever make it past this layer.
//!
//! # Multicast Traffic
//!
//! The gateway layer allows both unicast and multicast traffic through
//! the no-spoof rules (outbound) and separate inbound rules:
//!
//! - Outbound: The no-spoof rule matches on source IP/MAC but has no
//!   destination IP predicate, so it permits multicast destinations. This
//!   allows guests to send to any multicast group address at the gateway
//!   layer. However, the overlay layer enforces M2P (Multicast-to-Physical)
//!   mappings, denying packets for unconfigured multicast groups.
//!
//! - Inbound: Separate rules (IPv4 224.0.0.0/4 and IPv6 ff00::/8)
//!   allow multicast packets to reach guests and rewrite the source MAC
//!   to the gateway MAC, similar to unicast traffic.

use crate::api::AttachedSubnetConfig;
use crate::api::MacAddr;
use crate::api::TransitIpConfig;
use crate::cfg::Ipv4Cfg;
use crate::cfg::Ipv6Cfg;
use crate::cfg::VpcCfg;
use crate::engine::overlay::VniTag;
use crate::engine::overlay::VpcMappings;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Display;
use opte::api::Direction;
use opte::api::NoResp;
use opte::api::OpteError;
use opte::engine::ether::EtherMod;
use opte::engine::headers::HeaderAction;
use opte::engine::ip::v4::Ipv4Cidr;
use opte::engine::ip::v6::Ipv6Cidr;
use opte::engine::layer::DefaultAction;
use opte::engine::layer::Layer;
use opte::engine::layer::LayerActions;
use opte::engine::packet::InnerFlowId;
use opte::engine::packet::MblkPacketData;
use opte::engine::port::Port;
use opte::engine::port::PortBuilder;
use opte::engine::port::Pos;
use opte::engine::port::meta::ActionMeta;
use opte::engine::predicate::DataPredicate;
use opte::engine::predicate::EtherAddrMatch;
use opte::engine::predicate::Ipv4AddrMatch;
use opte::engine::predicate::Ipv6AddrMatch;
use opte::engine::predicate::Predicate;
use opte::engine::rule::Action;
use opte::engine::rule::AllowOrDeny;
use opte::engine::rule::Finalized;
use opte::engine::rule::GenHtResult;
use opte::engine::rule::HdrTransform;
use opte::engine::rule::MetaAction;
use opte::engine::rule::ModMetaResult;
use opte::engine::rule::Rule;
use opte::engine::rule::StaticAction;

pub mod arp;
pub mod dhcp;
pub mod dhcpv6;
pub mod icmp;
pub mod icmpv6;
mod transit;
pub use transit::*;

use super::VpcNetwork;

pub const NAME: &str = "gateway";

pub(crate) struct BuildCtx<'a> {
    in_rules: Vec<Rule<Finalized>>,
    out_rules: Vec<Rule<Finalized>>,
    cfg: &'a VpcCfg,
    vpc_meta: Arc<VpcMeta>,
}

pub fn setup(
    pb: &PortBuilder,
    cfg: &VpcCfg,
    vpc_mappings: Arc<VpcMappings>,
    ft_limit: core::num::NonZeroU32,
) -> Result<(), OpteError> {
    // We implement the gateway as a filtering layer in order to
    // enforce that any traffic that makes it past this layer is
    // traffic meant for the guest interface. Remember, there could
    // also be some process in the guest trying to spoof traffic for a
    // different IP than it was assigned.
    //
    // Since we are acting as a gateway we also rewrite the source MAC address
    // for inbound traffic to be that of the gateway.
    let actions = LayerActions {
        actions: vec![],
        default_in: DefaultAction::Deny,
        default_out: DefaultAction::Deny,
    };

    let mut layer = Layer::new(NAME, pb.name(), actions, ft_limit);

    let mut ctx = BuildCtx {
        in_rules: vec![],
        out_rules: vec![],
        cfg,
        vpc_meta: Arc::new(VpcMeta::new(vpc_mappings)),
    };

    if let Some(ipv4_cfg) = cfg.ipv4_cfg() {
        setup_ipv4(&mut ctx, ipv4_cfg)?;
    }

    if let Some(ipv6_cfg) = cfg.ipv6_cfg() {
        setup_ipv6(&mut ctx, ipv6_cfg)?;
    }

    layer.set_rules(ctx.in_rules, ctx.out_rules);

    pb.add_layer(layer, Pos::Before("firewall"))
}

// Recreates the full set of gateway rules on a given port in response to a
// change to the set of transit IPs or overall `IpCfg`.
pub fn set_gateway_rules(
    port: &Port<VpcNetwork>,
    vpc_mappings: Arc<VpcMappings>,
) -> Result<NoResp, OpteError> {
    let mut ctx = BuildCtx {
        in_rules: vec![],
        out_rules: vec![],
        cfg: &port.network().cfg,
        vpc_meta: Arc::new(VpcMeta::new(vpc_mappings)),
    };

    if let Some(ipv4_cfg) = ctx.cfg.ipv4_cfg() {
        setup_ipv4(&mut ctx, ipv4_cfg)?;
    }

    if let Some(ipv6_cfg) = ctx.cfg.ipv6_cfg() {
        setup_ipv6(&mut ctx, ipv6_cfg)?;
    }

    port.set_rules(NAME, ctx.in_rules, ctx.out_rules).map(|_| NoResp::default())
}

struct RewriteSrcMac {
    gateway_mac: MacAddr,
}

impl fmt::Display for RewriteSrcMac {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ether.src={}", self.gateway_mac)
    }
}

impl StaticAction for RewriteSrcMac {
    fn gen_ht(
        &self,
        _dir: Direction,
        _flow_id: &InnerFlowId,
        _packet_meta: &MblkPacketData,
        _action_meta: &mut ActionMeta,
    ) -> GenHtResult {
        Ok(AllowOrDeny::Allow(HdrTransform {
            inner_ether: HeaderAction::Modify(EtherMod {
                src: Some(self.gateway_mac),
                ..Default::default()
            }),
            ..Default::default()
        }))
    }

    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        (vec![], vec![])
    }
}

struct Exceptions<'a, T> {
    allow_in: BTreeSet<&'a T>,
    allow_out: BTreeSet<&'a T>,
}

fn compute_exceptions<'a, T: Ord>(
    attached: &'a BTreeMap<T, AttachedSubnetConfig>,
    transit: &'a BTreeMap<T, TransitIpConfig>,
) -> Exceptions<'a, T> {
    let allow_in: BTreeSet<_> = attached
        .keys()
        .chain(transit.iter().filter_map(|(k, v)| v.allow_in.then_some(k)))
        .collect();
    let allow_out: BTreeSet<_> = attached
        .keys()
        .chain(transit.iter().filter_map(|(k, v)| v.allow_out.then_some(k)))
        .collect();

    Exceptions { allow_in, allow_out }
}

fn setup_ipv4(ctx: &mut BuildCtx, ip_cfg: &Ipv4Cfg) -> Result<(), OpteError> {
    arp::setup(ctx)?;
    dhcp::setup(ctx, ip_cfg)?;
    icmp::setup(ctx, ip_cfg)?;

    // Outbound no-spoof rule: only allow traffic from the guest's IP and MAC.
    // This rule has no destination IP predicate, so it matches both unicast
    // and multicast destinations, enforcing no-spoof for all outbound traffic.
    //
    // NOTE: Because this gateway rule is unconditional on destination IP, guests
    // can send to any multicast group address. The overlay layer enforces M2P
    // mappings and underlay address validation, so guests cannot send multicast
    // unless the group is configured. In the future, we may want to explicitly
    // filter outbound multicast to only the groups configured via M2P to further
    // tighten spoof prevention at the gateway layer.
    let mut nospoof_out = Rule::new(1000, Action::Meta(ctx.vpc_meta.clone()));
    nospoof_out.add_predicate(Predicate::InnerSrcIp4(vec![
        Ipv4AddrMatch::Exact(ip_cfg.private_ip),
    ]));
    nospoof_out.add_predicate(Predicate::InnerEtherSrc(vec![
        EtherAddrMatch::Exact(ctx.cfg.guest_mac),
    ]));
    ctx.out_rules.push(nospoof_out.finalize());

    let mut unicast_in = Rule::new(
        1000,
        Action::Static(Arc::new(RewriteSrcMac {
            gateway_mac: ctx.cfg.gateway_mac,
        })),
    );
    unicast_in.add_predicate(Predicate::InnerDstIp4(vec![
        Ipv4AddrMatch::Exact(ip_cfg.private_ip),
    ]));
    unicast_in.add_predicate(Predicate::InnerEtherDst(vec![
        EtherAddrMatch::Exact(ctx.cfg.guest_mac),
    ]));
    ctx.in_rules.push(unicast_in.finalize());

    // Inbound IPv4 multicast - rewrite source MAC to gateway and allow
    let ipv4_mcast = vec![Ipv4AddrMatch::Prefix(Ipv4Cidr::MCAST)];
    // This mirrors the IPv6 multicast inbound rule to ensure multicast
    // delivery to guests is permitted by the gateway layer.
    let mut mcast_in_v4 = Rule::new(
        1001,
        Action::Static(Arc::new(RewriteSrcMac {
            gateway_mac: ctx.cfg.gateway_mac,
        })),
    );
    mcast_in_v4.add_predicate(Predicate::InnerDstIp4(ipv4_mcast));
    mcast_in_v4.add_predicate(Predicate::InnerEtherDst(vec![
        EtherAddrMatch::Multicast,
    ]));
    ctx.in_rules.push(mcast_in_v4.finalize());

    // Plumb in any required exceptions to spoof prevention/filtering.
    let transit = ip_cfg.transit_ips.load();
    let attached = ip_cfg.attached_subnets.load();

    let Exceptions { allow_in, allow_out } =
        compute_exceptions(&attached, &transit);

    for (place, dir, from) in [
        (&mut ctx.in_rules, Direction::In, allow_in),
        (&mut ctx.out_rules, Direction::Out, allow_out),
    ] {
        place.extend(from.into_iter().map(|cidr| {
            make_holepunch_rule(
                ctx.cfg.guest_mac,
                ctx.cfg.gateway_mac,
                (*cidr).into(),
                dir,
                &ctx.vpc_meta,
            )
        }));
    }

    Ok(())
}

fn setup_ipv6(ctx: &mut BuildCtx, ip_cfg: &Ipv6Cfg) -> Result<(), OpteError> {
    icmpv6::setup(ctx, ip_cfg)?;
    dhcpv6::setup(ctx)?;

    // Outbound no-spoof rule: only allow traffic from the guest's IP and MAC.
    // This rule has no destination IP predicate, so it matches both unicast
    // and multicast destinations, enforcing no-spoof for all outbound traffic.
    //
    // NOTE: Because this gateway rule is unconditional on destination IP, guests
    // can send to any multicast group address. The overlay layer enforces M2P
    // mappings and underlay address validation, so guests cannot send multicast
    // unless the group is configured. In the future, we may want to explicitly
    // filter outbound multicast to only the groups configured via M2P to further
    // tighten spoof prevention at the gateway layer.
    let mut nospoof_out = Rule::new(1000, Action::Meta(ctx.vpc_meta.clone()));
    nospoof_out.add_predicate(Predicate::InnerSrcIp6(vec![
        Ipv6AddrMatch::Exact(ip_cfg.private_ip),
    ]));
    nospoof_out.add_predicate(Predicate::InnerEtherSrc(vec![
        EtherAddrMatch::Exact(ctx.cfg.guest_mac),
    ]));
    ctx.out_rules.push(nospoof_out.finalize());

    let mut unicast_in = Rule::new(
        1000,
        Action::Static(Arc::new(RewriteSrcMac {
            gateway_mac: ctx.cfg.gateway_mac,
        })),
    );
    unicast_in.add_predicate(Predicate::InnerDstIp6(vec![
        Ipv6AddrMatch::Exact(ip_cfg.private_ip),
    ]));
    unicast_in.add_predicate(Predicate::InnerEtherDst(vec![
        EtherAddrMatch::Exact(ctx.cfg.guest_mac),
    ]));
    ctx.in_rules.push(unicast_in.finalize());

    // Inbound IPv6 multicast - rewrite source MAC to gateway and allow
    let ipv6_mcast = vec![Ipv6AddrMatch::Prefix(Ipv6Cidr::MCAST)];
    let mut mcast_in = Rule::new(
        1001,
        Action::Static(Arc::new(RewriteSrcMac {
            gateway_mac: ctx.cfg.gateway_mac,
        })),
    );
    mcast_in.add_predicate(Predicate::InnerDstIp6(ipv6_mcast));
    mcast_in.add_predicate(Predicate::InnerEtherDst(vec![
        EtherAddrMatch::Multicast,
    ]));
    ctx.in_rules.push(mcast_in.finalize());

    // Plumb in any required exceptions to spoof prevention/filtering.
    let transit = ip_cfg.transit_ips.load();
    let attached = ip_cfg.attached_subnets.load();

    let Exceptions { allow_in, allow_out } =
        compute_exceptions(&attached, &transit);

    for (place, dir, from) in [
        (&mut ctx.in_rules, Direction::In, allow_in),
        (&mut ctx.out_rules, Direction::Out, allow_out),
    ] {
        place.extend(from.into_iter().map(|cidr| {
            make_holepunch_rule(
                ctx.cfg.guest_mac,
                ctx.cfg.gateway_mac,
                (*cidr).into(),
                dir,
                &ctx.vpc_meta,
            )
        }));
    }

    Ok(())
}

/// Insert the VNI into the action metadata based on the VPC mappings.
///
/// This allows the outbound side of firewall layer to filter based on
/// VPC.
pub(crate) struct VpcMeta {
    vpc_mappings: Arc<VpcMappings>,
}

impl VpcMeta {
    fn new(vpc_mappings: Arc<VpcMappings>) -> Self {
        Self { vpc_mappings }
    }
}

impl MetaAction for VpcMeta {
    fn mod_meta(
        &self,
        flow: &InnerFlowId,
        action_meta: &mut ActionMeta,
    ) -> ModMetaResult {
        match self.vpc_mappings.ip_to_vni(&flow.dst_ip()) {
            Some(vni) => {
                action_meta.insert_typed(&VniTag(vni));
                Ok(AllowOrDeny::Allow(()))
            }

            None => Ok(AllowOrDeny::Allow(())),
        }
    }

    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        (vec![], vec![])
    }
}

impl Display for VpcMeta {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "vpc-meta")
    }
}

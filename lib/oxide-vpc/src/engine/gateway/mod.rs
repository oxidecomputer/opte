// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

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

use crate::api::DhcpCfg;
use crate::api::MacAddr;
use crate::cfg::Ipv4Cfg;
use crate::cfg::Ipv6Cfg;
use crate::cfg::VpcCfg;
use crate::engine::overlay::VpcMappings;
use crate::engine::overlay::ACTION_META_VNI;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Display;
use core::marker::PhantomData;
use opte::api::Direction;
use opte::api::OpteError;
use opte::engine::ether::EtherMod;
use opte::engine::headers::HeaderAction;
use opte::engine::layer::DefaultAction;
use opte::engine::layer::Layer;
use opte::engine::layer::LayerActions;
use opte::engine::packet::InnerFlowId;
use opte::engine::packet::PacketMeta;
use opte::engine::port::meta::ActionMeta;
use opte::engine::port::PortBuilder;
use opte::engine::port::Pos;
use opte::engine::predicate::DataPredicate;
use opte::engine::predicate::EtherAddrMatch;
use opte::engine::predicate::Ipv4AddrMatch;
use opte::engine::predicate::Ipv6AddrMatch;
use opte::engine::predicate::Predicate;
use opte::engine::rule::Action;
use opte::engine::rule::AllowOrDeny;
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

pub const NAME: &str = "gateway";

pub fn setup(
    pb: &PortBuilder,
    cfg: &VpcCfg,
    vpc_mappings: Arc<VpcMappings>,
    ft_limit: core::num::NonZeroU32,
    dhcp_cfg: &DhcpCfg,
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

    if let Some(ipv4_cfg) = cfg.ipv4_cfg() {
        setup_ipv4(
            &mut layer,
            cfg,
            ipv4_cfg,
            vpc_mappings.clone(),
            dhcp_cfg.clone(),
        )?;
    }

    if let Some(ipv6_cfg) = cfg.ipv6_cfg() {
        setup_ipv6(&mut layer, cfg, ipv6_cfg, vpc_mappings, dhcp_cfg.clone())?;
    }

    pb.add_layer(layer, Pos::Before("firewall"))
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
        _packet_meta: &PacketMeta,
        _action_meta: &mut ActionMeta,
    ) -> GenHtResult {
        Ok(AllowOrDeny::Allow(HdrTransform {
            inner_ether: HeaderAction::Modify(
                EtherMod { src: Some(self.gateway_mac), ..Default::default() },
                PhantomData,
            ),
            ..Default::default()
        }))
    }

    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        (vec![], vec![])
    }
}

fn setup_ipv4(
    layer: &mut Layer,
    cfg: &VpcCfg,
    ip_cfg: &Ipv4Cfg,
    vpc_mappings: Arc<VpcMappings>,
    dhcp_cfg: DhcpCfg,
) -> Result<(), OpteError> {
    arp::setup(layer, cfg)?;
    dhcp::setup(layer, cfg, ip_cfg, dhcp_cfg)?;
    icmp::setup(layer, cfg, ip_cfg)?;

    let vpc_meta = Arc::new(VpcMeta::new(vpc_mappings));

    let mut nospoof_out = Rule::new(1000, Action::Meta(vpc_meta));
    nospoof_out.add_predicate(Predicate::InnerSrcIp4(vec![
        Ipv4AddrMatch::Exact(ip_cfg.private_ip),
    ]));
    nospoof_out.add_predicate(Predicate::InnerEtherSrc(vec![
        EtherAddrMatch::Exact(cfg.guest_mac),
    ]));
    layer.add_rule(Direction::Out, nospoof_out.finalize());

    let mut unicast_in = Rule::new(
        1000,
        Action::Static(Arc::new(RewriteSrcMac {
            gateway_mac: cfg.gateway_mac,
        })),
    );
    unicast_in.add_predicate(Predicate::InnerDstIp4(vec![
        Ipv4AddrMatch::Exact(ip_cfg.private_ip),
    ]));
    unicast_in.add_predicate(Predicate::InnerEtherDst(vec![
        EtherAddrMatch::Exact(cfg.guest_mac),
    ]));
    layer.add_rule(Direction::In, unicast_in.finalize());

    Ok(())
}

fn setup_ipv6(
    layer: &mut Layer,
    cfg: &VpcCfg,
    ip_cfg: &Ipv6Cfg,
    vpc_mappings: Arc<VpcMappings>,
    dhcp_cfg: DhcpCfg,
) -> Result<(), OpteError> {
    icmpv6::setup(layer, cfg, ip_cfg)?;
    dhcpv6::setup(layer, cfg, dhcp_cfg)?;
    let vpc_meta = Arc::new(VpcMeta::new(vpc_mappings));
    let mut nospoof_out = Rule::new(1000, Action::Meta(vpc_meta));
    nospoof_out.add_predicate(Predicate::InnerSrcIp6(vec![
        Ipv6AddrMatch::Exact(ip_cfg.private_ip),
    ]));
    nospoof_out.add_predicate(Predicate::InnerEtherSrc(vec![
        EtherAddrMatch::Exact(cfg.guest_mac),
    ]));
    layer.add_rule(Direction::Out, nospoof_out.finalize());

    let mut unicast_in = Rule::new(
        1000,
        Action::Static(Arc::new(RewriteSrcMac {
            gateway_mac: cfg.gateway_mac,
        })),
    );
    unicast_in.add_predicate(Predicate::InnerDstIp6(vec![
        Ipv6AddrMatch::Exact(ip_cfg.private_ip),
    ]));
    unicast_in.add_predicate(Predicate::InnerEtherDst(vec![
        EtherAddrMatch::Exact(cfg.guest_mac),
    ]));
    layer.add_rule(Direction::In, unicast_in.finalize());

    Ok(())
}

/// Insert the VNI into the action metadata based on the VPC mappings.
///
/// This allows the outbound side of firewall layer to filter based on
/// VPC.
struct VpcMeta {
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
                action_meta
                    .insert(ACTION_META_VNI.to_string(), vni.to_string());
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

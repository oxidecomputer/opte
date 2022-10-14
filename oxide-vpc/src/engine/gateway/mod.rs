// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! The Oxide VPC Virtual Gateway.
//!
//! This layer is responsible for emulating a physical gateway to the
//! guest.

use crate::api::Ipv4Cfg;
use crate::api::Ipv6Cfg;
use crate::api::VpcCfg;
use opte::api::Direction;
use opte::api::OpteError;
use opte::engine::layer::DefaultAction;
use opte::engine::layer::Layer;
use opte::engine::layer::LayerActions;
use opte::engine::port::PortBuilder;
use opte::engine::port::Pos;
use opte::engine::rule::Action;
use opte::engine::rule::EtherAddrMatch;
use opte::engine::rule::Ipv4AddrMatch;
use opte::engine::rule::Ipv6AddrMatch;
use opte::engine::rule::Predicate;
use opte::engine::rule::Rule;

pub mod arp;
pub mod dhcp;
pub mod dhcpv6;
pub mod icmp;
pub mod icmpv6;

pub const NAME: &str = "gateway";

pub fn setup(
    pb: &PortBuilder,
    cfg: &VpcCfg,
    ft_limit: core::num::NonZeroU32,
) -> Result<(), OpteError> {
    // We implement the gateway as a filtering layer in order to
    // enforce that any traffic that makes it past this layer is
    // traffic meant for the guest interface. Remember, there could
    // also be some process in the guest trying to spoof traffic for a
    // different IP than it was assigned.
    let actions = LayerActions {
        actions: vec![],
        default_in: DefaultAction::Deny,
        default_out: DefaultAction::Deny,
    };

    let mut layer = Layer::new(NAME, pb.name(), actions, ft_limit);

    if let Some(ipv4_cfg) = cfg.ipv4_cfg() {
        setup_ipv4(&mut layer, cfg, ipv4_cfg)?;
    }

    if let Some(ipv6_cfg) = cfg.ipv6_cfg() {
        setup_ipv6(&mut layer, cfg, ipv6_cfg)?;
    }

    pb.add_layer(layer, Pos::Before("firewall"))
}

fn setup_ipv4(
    layer: &mut Layer,
    cfg: &VpcCfg,
    ip_cfg: &Ipv4Cfg,
) -> Result<(), OpteError> {
    arp::setup(layer, cfg, ip_cfg)?;
    dhcp::setup(layer, cfg, ip_cfg)?;
    icmp::setup(layer, cfg, ip_cfg)?;

    let mut nospoof_out = Rule::new(1000, Action::Allow);
    nospoof_out.add_predicate(Predicate::InnerSrcIp4(vec![
        Ipv4AddrMatch::Exact(ip_cfg.private_ip),
    ]));
    nospoof_out.add_predicate(Predicate::InnerEtherSrc(vec![
        EtherAddrMatch::Exact(cfg.private_mac),
    ]));
    layer.add_rule(Direction::Out, nospoof_out.finalize());

    let mut nospoof_in = Rule::new(1000, Action::Allow);
    nospoof_in.add_predicate(Predicate::InnerDstIp4(vec![
        Ipv4AddrMatch::Exact(ip_cfg.private_ip),
    ]));
    nospoof_in.add_predicate(Predicate::InnerEtherDst(vec![
        EtherAddrMatch::Exact(cfg.private_mac),
    ]));
    layer.add_rule(Direction::In, nospoof_in.finalize());

    Ok(())
}

fn setup_ipv6(
    layer: &mut Layer,
    cfg: &VpcCfg,
    ip_cfg: &Ipv6Cfg,
) -> Result<(), OpteError> {
    icmpv6::setup(layer, cfg, ip_cfg)?;
    dhcpv6::setup(layer, cfg)?;

    // Allow outbound IPv6 traffic from the guest's VPC IP and MAC
    // address to make it past the gateway. Any other IPv6 traffic
    // trying to make it out is denied, ensuring the guest cannot
    // spoof IPs it does not own.
    //
    // Allow inbound IPv6 traffic destined for the guest. In general,
    // our physical network should only deliver traffic truly destined
    // for us, but this final check makes sure the guest only sees
    // what it should.
    //
    // Any traffic coming from the guest's link-local traffic should
    // NOT pass the gateway. It's important that the various ICMPv6
    // and DHCPv6 rules related to implementing the virtual gateway
    // have a lower priority value than this rule, so that they are
    // checked first.
    let mut nospoof_out = Rule::new(1000, Action::Allow);
    nospoof_out.add_predicate(Predicate::InnerSrcIp6(vec![
        Ipv6AddrMatch::Exact(ip_cfg.private_ip),
    ]));
    nospoof_out.add_predicate(Predicate::InnerEtherSrc(vec![
        EtherAddrMatch::Exact(cfg.private_mac),
    ]));
    layer.add_rule(Direction::Out, nospoof_out.finalize());

    let mut nospoof_in = Rule::new(1000, Action::Allow);
    nospoof_in.add_predicate(Predicate::InnerDstIp6(vec![
        Ipv6AddrMatch::Exact(ip_cfg.private_ip),
    ]));
    nospoof_in.add_predicate(Predicate::InnerEtherDst(vec![
        EtherAddrMatch::Exact(cfg.private_mac),
    ]));
    layer.add_rule(Direction::In, nospoof_in.finalize());

    Ok(())
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! The DHCP implementation of the Virtual Gateway.

use crate::cfg::Ipv4Cfg;
use crate::cfg::VpcCfg;
use alloc::sync::Arc;
use opte::api::DhcpCfg;
use opte::api::DhcpReplyType;
use opte::api::Direction;
use opte::api::Ipv4Addr;
use opte::api::Ipv4PrefixLen;
use opte::api::OpteError;
use opte::api::SubnetRouterPair;
use opte::engine::dhcp::DhcpAction;
use opte::engine::ip4::Ipv4Cidr;
use opte::engine::layer::Layer;
use opte::engine::rule::Action;
use opte::engine::rule::Rule;

pub fn setup(
    layer: &mut Layer,
    cfg: &VpcCfg,
    ip_cfg: &Ipv4Cfg,
    dhcp_cfg: DhcpCfg,
) -> Result<(), OpteError> {
    // All guest interfaces live on a `/32`-network in the Oxide VPC;
    // restricting the L2 domain to two nodes: the guest NIC and the
    // OPTE Port. This allows OPTE to act as the gateway for which all
    // guest traffic must cross, no matter the destination. In order
    // to achieve this we use something called a "local subnet route".
    // This is a router entry that maps a "local subnet" to the router
    // `0.0.0.0`. If you read RFC 3442, you'll see the original
    // intention for this type of route is to allow different subnets
    // on the same link (L2 segment) to communicate with each other.
    // In our case we place the guest in a network of 1, meaning the
    // router itself must be on a different subnet. However, since the
    // router, in this case OPTE, is on the same link, we can use the local
    // subnet route feature to deliver packets to the router.
    //
    // * `re1`: The local subnet router entry; mapping the gateway
    // subnet to `0.0.0.0.`.
    //
    // * `re2`: The default router entry; mapping all packets to the
    // gateway.
    //
    // You might wonder why the `re2` entry is needed when we have the
    // `Router Option (code 3)`. RFC 3442 specifies the following:
    //
    // > If the DHCP server returns both a Classless Static Routes
    // > option and a Router option, the DHCP client MUST ignore the
    // > Router option.
    //
    // Furthermore, RFC 3442 goes on to say that a DHCP server
    // administrator should always set both to be on the safe side.
    let gw_cidr = Ipv4Cidr::new(ip_cfg.gateway_ip, Ipv4PrefixLen::NETMASK_ALL);
    let re1 = SubnetRouterPair::new(gw_cidr, Ipv4Addr::ANY_ADDR);
    let re2 = SubnetRouterPair::new(
        Ipv4Cidr::new(Ipv4Addr::ANY_ADDR, Ipv4PrefixLen::NETMASK_NONE),
        ip_cfg.gateway_ip,
    );

    let offer = Action::Hairpin(Arc::new(DhcpAction {
        client_mac: cfg.guest_mac,
        client_ip: ip_cfg.private_ip,
        subnet_prefix_len: Ipv4PrefixLen::NETMASK_ALL,
        gw_mac: cfg.gateway_mac,
        gw_ip: ip_cfg.gateway_ip,
        reply_type: DhcpReplyType::Offer,
        re1,
        re2: Some(re2),
        re3: None,
        dhcp_cfg: dhcp_cfg.clone(),
    }));

    let ack = Action::Hairpin(Arc::new(DhcpAction {
        client_mac: cfg.guest_mac,
        client_ip: ip_cfg.private_ip,
        subnet_prefix_len: Ipv4PrefixLen::NETMASK_ALL,
        gw_mac: cfg.gateway_mac,
        gw_ip: ip_cfg.gateway_ip,
        reply_type: DhcpReplyType::Ack,
        re1,
        re2: Some(re2),
        re3: None,
        dhcp_cfg,
    }));

    let discover_rule = Rule::new(1, offer);
    layer.add_rule(Direction::Out, discover_rule.finalize());

    let request_rule = Rule::new(1, ack);
    layer.add_rule(Direction::Out, request_rule.finalize());
    Ok(())
}

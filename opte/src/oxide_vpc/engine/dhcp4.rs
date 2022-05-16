// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Oxide Network DHCPv4
//!
//! This implements DHCPv4 support allowing OPTE act as the gateway
//! for the guest without the need for static configuration.
//!
//! XXX rename layer to "gateway" for Virtual Gateway and move ARP and
//! ICMP code in here too. Then add high-value priority rule to drop
//! all traffic destined for gateway that doesn't match lower-value
//! priority rule; keeping gateway-bound packets from ending up on the
//! underlay.
use core::result::Result;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::sync::Arc;
    } else {
        use std::sync::Arc;
    }
}

use crate::api::{
    Dhcp4Action, Dhcp4ReplyType, Direction, Ipv4Addr, Ipv4PrefixLen, OpteError,
    SubnetRouterPair,
};
use crate::engine::ip4::Ipv4Cidr;
use crate::engine::layer::Layer;
use crate::engine::port::{PortBuilder, Pos};
use crate::engine::rule::{Action, Rule};
use crate::oxide_vpc::PortCfg;

pub fn setup(
    pb: &mut PortBuilder,
    cfg: &PortCfg,
    ft_limit: core::num::NonZeroU32,
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
    // router, in this OPTE, is on the same link, we can use the local
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
    let gw_cidr = Ipv4Cidr::new(cfg.gw_ip, Ipv4PrefixLen::NETMASK_ALL);
    let re1 = SubnetRouterPair::new(gw_cidr, Ipv4Addr::ANY_ADDR);
    let re2 = SubnetRouterPair::new(
        Ipv4Cidr::new(Ipv4Addr::ANY_ADDR, Ipv4PrefixLen::NETMASK_NONE),
        cfg.gw_ip,
    );

    let offer = Action::Hairpin(Arc::new(Dhcp4Action {
        client_mac: cfg.private_mac.into(),
        client_ip: cfg.private_ip,
        subnet_prefix_len: Ipv4PrefixLen::NETMASK_ALL,
        gw_mac: cfg.gw_mac.into(),
        gw_ip: cfg.gw_ip,
        reply_type: Dhcp4ReplyType::Offer,
        re1,
        re2: Some(re2),
        re3: None,
        // XXX For now at least resolve the internet.
        dns_servers: Some([
            Some(Ipv4Addr::from([8, 8, 8, 8]).into()),
            None,
            None,
        ]),
    }));
    let offer_idx = 0;

    let ack = Action::Hairpin(Arc::new(Dhcp4Action {
        client_mac: cfg.private_mac.into(),
        client_ip: cfg.private_ip,
        subnet_prefix_len: Ipv4PrefixLen::NETMASK_ALL,
        gw_mac: cfg.gw_mac.into(),
        gw_ip: cfg.gw_ip,
        reply_type: Dhcp4ReplyType::Ack,
        re1,
        re2: Some(re2),
        re3: None,
        // XXX For now at least resolve the internet.
        dns_servers: Some([
            Some(Ipv4Addr::from([8, 8, 8, 8]).into()),
            None,
            None,
        ]),
    }));
    let ack_idx = 1;

    let dhcp = Layer::new("dhcp4", pb.name(), vec![offer, ack], ft_limit);

    let discover_rule = Rule::new(1, dhcp.action(offer_idx).unwrap().clone());
    dhcp.add_rule(Direction::Out, discover_rule.finalize());

    let request_rule = Rule::new(1, dhcp.action(ack_idx).unwrap().clone());
    dhcp.add_rule(Direction::Out, request_rule.finalize());

    pb.add_layer(dhcp, Pos::Before("firewall"))
}

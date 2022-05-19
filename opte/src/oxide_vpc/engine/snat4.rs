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

use crate::api::{Direction, OpteError};
use crate::engine::ip4::{Ipv4Addr, Protocol};
use crate::engine::layer::Layer;
use crate::engine::port::{PortBuilder, Pos};
use crate::engine::rule::{
    Action, IpProtoMatch, Ipv4AddrMatch, Predicate, Rule,
};
use crate::engine::snat::{NatPool, SNat4};
use crate::oxide_vpc::PortCfg;

pub fn setup(
    pb: &mut PortBuilder,
    cfg: &PortCfg,
    ft_limit: core::num::NonZeroU32,
) -> core::result::Result<(), OpteError> {
    let pool = NatPool::new();
    pool.add(cfg.private_ip, cfg.snat.public_ip, cfg.snat.ports.clone());

    let nat = SNat4::new(cfg.private_ip, Arc::new(pool));
    let layer = Layer::new(
        "dyn-nat4",
        pb.name(),
        vec![Action::Stateful(Arc::new(nat))],
        ft_limit,
    );
    let mut rule = Rule::new(1, layer.action(0).unwrap().clone());

    rule.add_predicate(Predicate::InnerIpProto(vec![
        IpProtoMatch::Exact(Protocol::TCP),
        IpProtoMatch::Exact(Protocol::UDP),
    ]));

    // RFD 21 §2.10.4 (Primary and Multiple Interfaces) dictates that
    // there may be more than one interface, but one is primary.
    //
    //  * A given guest may only ever be a part of one VPC, i.e. every
    //    interface in a guest sits in the same VPC.
    //
    //  * However, each interface may be on a different subnet within
    //    the VPC.
    //
    //  * Only the primary interface participates in DNS, ephemeral &
    //    floating public IP, and is specified as the default route to
    //    the guest via DHCP
    //
    // Therefore, we can determine if an address needs NAT by checking
    // to see if the destination IP belongs to the interface's subnet.
    rule.add_predicate(Predicate::Not(Box::new(Predicate::InnerDstIp4(vec![
        Ipv4AddrMatch::Prefix(cfg.vpc_subnet.cidr()),
        Ipv4AddrMatch::Exact(Ipv4Addr::LOCAL_BCAST),
    ]))));
    layer.add_rule(Direction::Out, rule.finalize());
    pb.add_layer(layer, Pos::After("firewall"))
}

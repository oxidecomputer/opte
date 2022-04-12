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
use crate::engine::nat::{DynNat4, NatPool};
use crate::engine::port::{self, Port, Pos};
use crate::engine::rule::{
    Action, IpProtoMatch, Ipv4AddrMatch, Predicate, Rule,
};
use crate::oxide_vpc::PortCfg;

pub fn setup(
    port: &mut Port<port::Inactive>,
    cfg: &PortCfg,
) -> core::result::Result<(), OpteError> {
    let mut pool = NatPool::new();
    pool.add(cfg.private_ip, cfg.dyn_nat.public_ip, cfg.dyn_nat.ports.clone());

    let nat = DynNat4::new(cfg.private_ip, Arc::new(pool));

    let layer = Layer::new(
        "dyn-nat4",
        port.name(),
        vec![Action::Stateful(Arc::new(nat))],
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
    port.add_layer(layer, Pos::After("firewall"))
}

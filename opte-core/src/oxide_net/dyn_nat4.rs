#[cfg(all(not(feature = "std"), not(test)))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::sync::Arc;
#[cfg(any(feature = "std", test))]
use std::boxed::Box;
#[cfg(any(feature = "std", test))]
use std::sync::Arc;

use crate::ip4::{self, Protocol};
use crate::layer::Layer;
use crate::nat::{DynNat4, NatPool};
use crate::port::{self, Port, Pos};
use crate::rule::{Action, IpProtoMatch, Ipv4AddrMatch, Predicate, Rule};
use crate::Direction;

pub fn setup(
    port: &mut Port<port::Inactive>,
    cfg: &super::PortCfg,
) -> core::result::Result<(), port::AddLayerError> {
    let mut pool = NatPool::new();
    pool.add(cfg.private_ip, cfg.dyn_nat.public_ip, cfg.dyn_nat.ports.clone());

    let nat = DynNat4::new(
        cfg.private_ip,
        cfg.private_mac,
        cfg.dyn_nat.public_mac,
        Arc::new(pool),
    );

    let layer = Layer::new(
        "dyn-nat4",
        port.name(),
        vec![Action::Stateful(Arc::new(nat))],
    );

    let rule = Rule::new(1, layer.action(0).unwrap().clone());
    let mut rule = rule.add_predicate(Predicate::InnerIpProto(vec![
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
        Ipv4AddrMatch::Exact(ip4::LOCAL_BROADCAST),
    ]))));
    layer.add_rule(Direction::Out, rule.finalize());
    port.add_layer(layer, Pos::After("firewall"))
}

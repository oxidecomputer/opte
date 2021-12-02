#[cfg(all(not(feature = "std"), not(test)))]
use alloc::boxed::Box;
#[cfg(any(feature = "std", test))]
use std::boxed::Box;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::string::ToString;
#[cfg(any(feature = "std", test))]
use std::string::ToString;

use crate::ip4::{self, Protocol};
use crate::layer::Layer;
use crate::nat::{DynNat4, NatPool};
use crate::port::{Port, Pos};
use crate::rule::{
    Action, Ipv4AddrMatch, IpProtoMatch, Predicate, Rule, RuleAction
};
use crate::Direction;

pub fn setup(port: &mut Port, cfg: &super::PortConfig) {
    let mut pool = NatPool::new();
    pool.add(cfg.private_ip, cfg.dyn_nat.public_ip, cfg.dyn_nat.ports.clone());
    port.set_nat_pool(pool);

    let nat = DynNat4::new(
        "dyn-nat4".to_string(),
        cfg.private_ip,
        cfg.private_mac,
        cfg.dyn_nat.public_mac,
    );

    let layer = Layer::new("dyn-nat4", vec![Action::Stateful(Box::new(nat))]);

    let mut rule = Rule::new(1, RuleAction::Allow(0));
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
        Ipv4AddrMatch::Prefix(cfg.vpc_subnet.get_cidr()),
        Ipv4AddrMatch::Exact(ip4::LOCAL_BROADCAST),
    ]))));
    layer.add_rule(Direction::Out, rule);
    port.add_layer(layer, Pos::After("firewall"));
}

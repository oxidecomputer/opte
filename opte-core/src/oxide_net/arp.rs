cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::sync::Arc;
    } else {
        use std::sync::Arc;
    }
}

use opte_core_api::OpteError;

use crate::arp::{ArpOp, ArpReply};
use crate::ether::{EtherAddr, ETHER_TYPE_ARP, ETHER_TYPE_IPV4};
use crate::layer::Layer;
use crate::port::{self, Port, Pos};
use crate::rule::{
    Action, ArpHtypeMatch, ArpOpMatch, ArpPtypeMatch, DataPredicate,
    EtherAddrMatch, EtherTypeMatch, Ipv4AddrMatch, Predicate, Rule,
};
use crate::Direction;

pub fn setup(
    port: &mut Port<port::Inactive>,
    cfg: &super::PortCfg,
) -> core::result::Result<(), OpteError> {
    let arp = Layer::new(
        "arp",
        port.name(),
        vec![
            // ARP Reply for gateway's IP.
            Action::Hairpin(Arc::new(ArpReply::new(cfg.gw_ip, cfg.gw_mac))),
        ],
    );

    // ================================================================
    // Outbound ARP Request for Gateway, from Guest
    // ================================================================
    let rule = Rule::new(1, arp.action(0).unwrap().clone());
    let mut rule = rule.add_predicate(Predicate::InnerEtherType(vec![
        EtherTypeMatch::Exact(ETHER_TYPE_ARP),
    ]));
    rule.add_predicate(Predicate::InnerEtherDst(vec![EtherAddrMatch::Exact(
        EtherAddr::from([0xFF; 6]),
    )]));
    rule.add_predicate(Predicate::InnerArpHtype(ArpHtypeMatch::Exact(1)));
    rule.add_predicate(Predicate::InnerArpPtype(ArpPtypeMatch::Exact(
        ETHER_TYPE_IPV4,
    )));
    rule.add_predicate(Predicate::InnerArpOp(ArpOpMatch::Exact(
        ArpOp::Request,
    )));
    rule.add_data_predicate(DataPredicate::InnerArpTpa(vec![
        Ipv4AddrMatch::Exact(cfg.gw_ip),
    ]));
    arp.add_rule(Direction::Out, rule.finalize());

    // ================================================================
    // Drop all other outbound ARP Requests from Guest
    // ================================================================
    let rule = Rule::new(2, Action::Deny);
    let rule = rule.add_predicate(Predicate::InnerEtherType(vec![
        EtherTypeMatch::Exact(ETHER_TYPE_ARP),
    ]));
    arp.add_rule(Direction::Out, rule.finalize());

    // ================================================================
    // Drop all inbound ARP Requests
    // ================================================================
    let rule = Rule::new(2, Action::Deny);
    let rule = rule.add_predicate(Predicate::InnerEtherType(vec![
        EtherTypeMatch::Exact(ETHER_TYPE_ARP),
    ]));
    arp.add_rule(Direction::In, rule.finalize());

    port.add_layer(arp, Pos::Before("firewall"))
}

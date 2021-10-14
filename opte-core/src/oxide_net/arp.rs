#[cfg(all(not(feature = "std"), not(test)))]
use alloc::boxed::Box;
#[cfg(any(feature = "std", test))]
use std::boxed::Box;

use crate::arp::{ArpOp, ArpReply};
use crate::ether::{EtherAddr, ETHER_TYPE_ARP, ETHER_TYPE_IPV4};
use crate::layer::{Layer};
use crate::port::{self, Inactive, Port, Pos};
use crate::rule::{
    Action, ArpHtypeMatch, ArpOpMatch, ArpPtypeMatch, DataPredicate,
    EtherAddrMatch, EtherTypeMatch, Ipv4AddrMatch, Predicate, Rule, RuleAction,
};
use crate::Direction;

pub fn setup(
    port: &mut Port<Inactive>,
    cfg: &super::PortConfig
) -> port::Result<()> {
    let arp = Layer::new(
        "arp",
        vec![
            // ARP Reply for gateway's IP.
            Action::Hairpin(Box::new(ArpReply::new(cfg.gw_ip, cfg.gw_mac))),

            // ARP Reply for guest's private IP.
            Action::Hairpin(Box::new(ArpReply::new(
                cfg.private_ip,
                cfg.private_mac
            ))),

            // ARP Reply for guest's public IP.
            Action::Hairpin(Box::new(ArpReply::new(
                cfg.dyn_nat.public_ip,
                cfg.dyn_nat.public_mac,
            ))),
        ],
    );

    // ================================================================
    // Outbound ARP Request for Gateway, from Guest
    // ================================================================
    let rule = Rule::new(1, RuleAction::Allow(0));
    let mut rule = rule.add_predicate(
        Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(ETHER_TYPE_ARP)])
    );
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
    let rule = Rule::new(2, RuleAction::Deny);
    let rule = rule.add_predicate(
        Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(ETHER_TYPE_ARP)])
    );
    arp.add_rule(Direction::Out, rule.finalize());

    // ================================================================
    // Inbound ARP Request from Gateway, for Guest Private IP
    // ================================================================
    let rule = Rule::new(1, RuleAction::Allow(1));
    let mut rule = rule.add_predicate(
        Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(ETHER_TYPE_ARP)])
    );
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
        Ipv4AddrMatch::Exact(cfg.private_ip),
    ]));
    arp.add_rule(Direction::In, rule.finalize());

    // ================================================================
    // Inbound ARP Request from Gateway, for Guest Public IP
    // ================================================================
    let rule = Rule::new(1, RuleAction::Allow(2));
    let mut rule = rule.add_predicate(
        Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(ETHER_TYPE_ARP)])
    );
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
        Ipv4AddrMatch::Exact(cfg.dyn_nat.public_ip),
    ]));
    arp.add_rule(Direction::In, rule.finalize());

    // ================================================================
    // Drop all other inbound ARP Requests
    // ================================================================
    let rule = Rule::new(2, RuleAction::Deny);
    let rule = rule.add_predicate(
        Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(ETHER_TYPE_ARP)])
    );
    arp.add_rule(Direction::In, rule.finalize());

    port.add_layer(arp, Pos::Before("firewall"))
}

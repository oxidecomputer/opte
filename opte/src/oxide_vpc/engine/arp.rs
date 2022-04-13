cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::sync::Arc;
    } else {
        use std::sync::Arc;
    }
}

use crate::api::{Direction, OpteError};
use crate::engine::arp::ArpReply;
use crate::engine::ether::ETHER_TYPE_ARP;
use crate::engine::layer::Layer;
use crate::engine::port::{self, Port, Pos};
use crate::engine::rule::{Action, EtherTypeMatch, Predicate, Rule};
use crate::oxide_vpc::PortCfg;

pub fn setup(
    port: &mut Port<port::Inactive>,
    cfg: &PortCfg,
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
    // TODO add predicate for SHA/SPA
    let rule = Rule::new(1, arp.action(0).unwrap().clone());
    arp.add_rule(Direction::Out, rule.finalize());

    // ================================================================
    // Drop all other outbound ARP Requests from Guest
    // ================================================================
    let mut rule = Rule::new(2, Action::Deny);
    rule.add_predicate(Predicate::InnerEtherType(vec![
        EtherTypeMatch::Exact(ETHER_TYPE_ARP),
    ]));
    arp.add_rule(Direction::Out, rule.finalize());

    // ================================================================
    // Drop all inbound ARP Requests
    // ================================================================
    let mut rule = Rule::new(2, Action::Deny);
    rule.add_predicate(Predicate::InnerEtherType(vec![
        EtherTypeMatch::Exact(ETHER_TYPE_ARP),
    ]));
    arp.add_rule(Direction::In, rule.finalize());

    port.add_layer(arp, Pos::Before("firewall"))
}

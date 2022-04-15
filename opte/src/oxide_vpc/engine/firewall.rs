use core::fmt;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::{String, ToString};
        use alloc::sync::Arc;
        use alloc::vec::Vec;
    } else {
        use std::string::{String, ToString};
        use std::sync::Arc;
        use std::vec::Vec;
    }
}

use crate::api::{Direction, OpteError};
use crate::engine::ether::ETHER_TYPE_ARP;
use crate::engine::ip4::Protocol;
use crate::engine::layer::{InnerFlowId, Layer};
use crate::engine::port::meta::Meta;
use crate::engine::port::{self, Port, Pos};
use crate::engine::rule::{
    self, AllowOrDeny, DataPredicate, EtherTypeMatch, Identity, IdentityDesc,
    IpProtoMatch, Ipv4AddrMatch, PortMatch, Predicate, Rule, StatefulAction,
};
use crate::engine::tcp::{TCP_PORT_RDP, TCP_PORT_SSH};
pub use crate::oxide_vpc::api::ProtoFilter;
use crate::oxide_vpc::api::{
    Action, AddFwRuleReq, Address, FirewallRule, Ports, RemFwRuleReq,
};

pub const FW_LAYER_NAME: &'static str = "firewall";

pub fn setup(
    port: &mut Port<port::Inactive>,
) -> core::result::Result<(), OpteError> {
    let fw_layer = Firewall::create_layer(port.name());
    port.add_layer(fw_layer, Pos::First)
}

pub fn add_fw_rule(
    port: &port::Port<port::Active>,
    req: &AddFwRuleReq,
) -> Result<(), OpteError> {
    let action = match req.rule.action {
        Action::Allow => port.layer_action(FW_LAYER_NAME, 0).unwrap().clone(),

        Action::Deny => rule::Action::Deny,
    };

    let rule = from_fw_rule(req.rule.clone(), action);
    port.add_rule(FW_LAYER_NAME, req.rule.direction, rule)
}

pub fn rem_fw_rule(
    port: &port::Port<port::Active>,
    req: &RemFwRuleReq,
) -> Result<(), OpteError> {
    port.remove_rule(FW_LAYER_NAME, req.dir, req.id)
}

pub struct Firewall {}

// Default rules are defined in RFD 21 §2.8.1. These default rules are
// technically part of the definition of the Oxide Network, and should
// probably not live in opte-core itself. That is, there is a
// difference between the engine itself and the specification of the
// Oxide Network (to program the engine), for now it's okay to mix
// them, but in the future it would be nice to cleanly separate them.
fn add_default_inbound_rules(layer: &mut Layer) {
    // Block all inbound traffic.
    //
    // By default, if there are no predicates, then a rule matches.
    // Thus, to match all incoming traffic, we add no predicates.
    layer.add_rule(Direction::In, Rule::match_any(65535, rule::Action::Deny));

    // This rule is not listed in the RFDs, nor does the Oxide VPC
    // Firewall have any features for matching L2 data. The underlying
    // firewall mechanism in OPTE is stronger than the model offered
    // by RFD 21. We use this to our advantage here to allow ARP
    // traffic to pass, which will be dealt with by the ARP layer in
    // the Oxide Network configuration.
    let mut arp = Rule::new(1, layer.action(1).unwrap().clone());
    arp.add_predicate(Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(
        ETHER_TYPE_ARP,
    )]));
    layer.add_rule(Direction::In, arp.finalize());

    // Allow SSH traffic from anywhere.
    let mut ssh = Rule::new(65534, layer.action(0).unwrap().clone());
    ssh.add_predicate(Predicate::InnerIpProto(vec![IpProtoMatch::Exact(
        Protocol::TCP,
    )]));
    ssh.add_predicate(Predicate::InnerDstPort(vec![PortMatch::Exact(
        TCP_PORT_SSH,
    )]));
    layer.add_rule(Direction::In, ssh.finalize());

    // Allow ICMP traffic from anywhere. This allows useful messages
    // like Destination Unreachable to make it back to the guest.
    //
    // XXX It might be nice to add ICMP Type & Code predicates. While
    // we don't expose these things in the Oxide Virtual Firewall, it
    // would allow us to perform finer-grained ICMP filtering in the
    // event that is useful.
    let mut icmp = Rule::new(65534, layer.action(0).unwrap().clone());
    icmp.add_predicate(Predicate::InnerIpProto(vec![IpProtoMatch::Exact(
        Protocol::ICMP,
    )]));
    layer.add_rule(Direction::In, icmp.finalize());

    // Allow RDP from anywhere.
    let mut rdp = Rule::new(65534, layer.action(0).unwrap().clone());
    rdp.add_predicate(Predicate::InnerIpProto(vec![IpProtoMatch::Exact(
        Protocol::TCP,
    )]));
    rdp.add_predicate(Predicate::InnerDstPort(vec![PortMatch::Exact(
        TCP_PORT_RDP,
    )]));
    layer.add_rule(Direction::In, rdp.finalize());
}

fn add_default_outbound_rules(layer: &mut Layer) {
    let act = layer.action(0).unwrap().clone();
    layer.add_rule(Direction::Out, Rule::match_any(65535, act));
}

pub fn from_fw_rule(
    fw_rule: FirewallRule,
    action: rule::Action,
) -> Rule<rule::Finalized> {
    let addr_pred = fw_rule.filters.hosts().into_predicate(fw_rule.direction);
    let proto_pred = fw_rule.filters.protocol().into_predicate();
    let port_pred = fw_rule.filters.ports().into_predicate();

    if addr_pred.is_none() && proto_pred.is_none() && port_pred.is_none() {
        return Rule::match_any(fw_rule.priority, action);
    }

    let mut rule = Rule::new(fw_rule.priority, action);

    if proto_pred.is_some() {
        rule.add_predicate(proto_pred.unwrap());
    }

    if port_pred.is_some() {
        rule.add_predicate(port_pred.unwrap());
    }

    if addr_pred.is_some() {
        rule.add_predicate(addr_pred.unwrap());
    }

    rule.finalize()
}

pub struct FwStatefulAction {
    name: String,
}

impl FwStatefulAction {
    fn new(name: String) -> Self {
        FwStatefulAction { name }
    }
}

impl fmt::Display for FwStatefulAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Firewall")
    }
}

impl StatefulAction for FwStatefulAction {
    fn gen_desc(
        &self,
        _flow_id: &InnerFlowId,
        _meta: &mut Meta,
    ) -> rule::GenDescResult {
        Ok(AllowOrDeny::Allow(Arc::new(IdentityDesc::new(self.name.clone()))))
    }

    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        (vec![], vec![])
    }
}

impl Firewall {
    pub fn create_layer(port_name: &str) -> Layer {
        // A stateful action creates a FlowTable entry.
        let stateful_action = rule::Action::Stateful(Arc::new(
            FwStatefulAction::new("fw".to_string()),
        ));

        // A static action does not create an entry in the FlowTable.
        // For the moment this is only used to allow ARP to bypass the
        // firewall layer, but it may be useful to expose this more
        // generally in the future.
        let static_action =
            rule::Action::Static(Arc::new(Identity::new("fw_arp")));

        let mut layer = Layer::new(
            FW_LAYER_NAME,
            port_name,
            vec![stateful_action, static_action],
        );
        add_default_inbound_rules(&mut layer);
        add_default_outbound_rules(&mut layer);
        layer
    }
}

impl ProtoFilter {
    pub fn into_predicate(self) -> Option<Predicate> {
        match self {
            ProtoFilter::Any => None,

            ProtoFilter::Proto(p) => {
                Some(Predicate::InnerIpProto(vec![IpProtoMatch::Exact(p)]))
            }
        }
    }
}

impl Address {
    pub fn into_predicate(self, dir: Direction) -> Option<Predicate> {
        match (dir, self) {
            (_, Address::Any) => None,

            (Direction::Out, Address::Ip(ip4)) => {
                Some(Predicate::InnerDstIp4(vec![Ipv4AddrMatch::Exact(ip4)]))
            }

            (Direction::In, Address::Ip(ip4)) => {
                Some(Predicate::InnerSrcIp4(vec![Ipv4AddrMatch::Exact(ip4)]))
            }

            (Direction::Out, Address::Subnet(ip4_sub)) => Some(
                Predicate::InnerDstIp4(vec![Ipv4AddrMatch::Prefix(ip4_sub)]),
            ),

            (Direction::In, Address::Subnet(ip4_sub)) => Some(
                Predicate::InnerSrcIp4(vec![Ipv4AddrMatch::Prefix(ip4_sub)]),
            ),
        }
    }
}

impl Ports {
    pub fn into_predicate(&self) -> Option<Predicate> {
        match self {
            Ports::Any => None,

            Ports::PortList(ports) => {
                let mlist =
                    ports.iter().map(|p| PortMatch::Exact(*p)).collect();
                Some(Predicate::InnerDstPort(mlist))
            }
        }
    }
}

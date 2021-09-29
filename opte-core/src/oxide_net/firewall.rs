#[cfg(all(not(feature = "std"), not(test)))]
use alloc::prelude::v1::*;
#[cfg(any(feature = "std", test))]
use std::prelude::v1::*;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::sync::Arc;
#[cfg(any(feature = "std", test))]
use std::sync::Arc;

use std::fmt::{self, Display};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ether::ETHER_TYPE_ARP;
use crate::headers::DYNAMIC_PORT;
use crate::ip4::{Ipv4Addr, Ipv4Cidr, Protocol};
use crate::layer::{InnerFlowId, Layer};
use crate::port::{Port, Pos};
use crate::rule::{
    Action as LayerAction, ActionDesc, EtherTypeMatch, Identity, IdentityDesc,
    IpProtoMatch, Ipv4AddrMatch, PortMatch, Predicate, Resources, Rule,
    RuleAction, StatefulAction,
};
use crate::tcp::{TCP_PORT_RDP, TCP_PORT_SSH};
use crate::{Direction, ParseErr, ParseResult};

pub fn setup(port: &mut Port) {
    let fw_layer = Firewall::create_layer();
    port.add_layer(fw_layer, Pos::First);
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
    layer.add_rule(Direction::In, Rule::new(65535, RuleAction::Deny));

    // This rule is not listed in the RFDs, nor does the Oxide VPC
    // Firewall have any features for matching L2 data. The underlying
    // firewall mechanism in OPTE is stronger than the model offered
    // by RFD 21. We use this to our advantage here to allow ARP
    // traffic to pass, which will be dealt with by the ARP layer in
    // the Oxide Network configuration.
    let mut arp = Rule::new(1, RuleAction::Allow(1));
    arp.add_predicate(Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(
        ETHER_TYPE_ARP,
    )]));
    layer.add_rule(Direction::In, arp);

    // Allow SSH traffic from anywhere.
    let mut ssh = Rule::new(65534, RuleAction::Allow(0));
    ssh.add_predicate(Predicate::InnerIpProto(vec![IpProtoMatch::Exact(
        Protocol::TCP,
    )]));
    ssh.add_predicate(Predicate::InnerDstPort(vec![PortMatch::Exact(
        TCP_PORT_SSH,
    )]));
    layer.add_rule(Direction::In, ssh);

    // Allow ICMP traffic from anywhere.
    let mut icmp = Rule::new(65534, RuleAction::Allow(0));
    icmp.add_predicate(Predicate::InnerIpProto(vec![IpProtoMatch::Exact(
        Protocol::ICMP,
    )]));
    layer.add_rule(Direction::In, icmp);

    // Allow RDP from anywhere.
    let mut rdp = Rule::new(65534, RuleAction::Allow(0));
    rdp.add_predicate(Predicate::InnerIpProto(vec![IpProtoMatch::Exact(
        Protocol::TCP,
    )]));
    rdp.add_predicate(Predicate::InnerDstPort(vec![PortMatch::Exact(
        TCP_PORT_RDP,
    )]));
    layer.add_rule(Direction::In, rdp);
}

fn add_default_outbound_rules(layer: &mut Layer) {
    layer.add_rule(Direction::Out, Rule::new(65535, RuleAction::Allow(0)));
}

impl From<FirewallRule> for Rule {
    fn from(fw_rule: FirewallRule) -> Self {
        let action = match fw_rule.action {
            Action::Allow => RuleAction::Allow(0),
            Action::Deny => RuleAction::Deny,
        };

        let mut rule = Rule::new(fw_rule.priority, action);

        match (fw_rule.direction, fw_rule.filters.hosts) {
            (_, Address::Any) => (),

            (Direction::Out, Address::Ip(ip4)) => {
                rule.add_predicate(Predicate::InnerDstIp4(vec![
                    Ipv4AddrMatch::Exact(ip4),
                ]));
            }

            (Direction::In, Address::Ip(ip4)) => {
                rule.add_predicate(Predicate::InnerSrcIp4(vec![
                    Ipv4AddrMatch::Exact(ip4),
                ]));
            }

            (Direction::Out, Address::Subnet(ip4_sub)) => {
                rule.add_predicate(Predicate::InnerDstIp4(vec![
                    Ipv4AddrMatch::Prefix(ip4_sub),
                ]));
            }

            (Direction::In, Address::Subnet(ip4_sub)) => {
                rule.add_predicate(Predicate::InnerSrcIp4(vec![
                    Ipv4AddrMatch::Prefix(ip4_sub),
                ]));
            }
        }

        match fw_rule.filters.protocol {
            ProtoFilter::Any => (),

            ProtoFilter::Proto(p) => {
                rule.add_predicate(Predicate::InnerIpProto(vec![
                    IpProtoMatch::Exact(p),
                ]));
            }
        }

        match (fw_rule.direction, fw_rule.filters.ports) {
            (_, Ports::Any) => (),

            (Direction::Out, Ports::PortList(ports)) => {
                let mlist =
                    ports.iter().map(|p| PortMatch::Exact(*p)).collect();
                rule.add_predicate(Predicate::InnerDstPort(mlist));
            }

            (Direction::In, Ports::PortList(ports)) => {
                let mlist =
                    ports.iter().map(|p| PortMatch::Exact(*p)).collect();
                rule.add_predicate(Predicate::InnerDstPort(mlist));
            }
        }

        rule
    }
}

pub struct FwStatefulAction {
    name: String,
}

impl FwStatefulAction {
    fn new(name: String) -> Self {
        FwStatefulAction { name }
    }
}

impl StatefulAction for FwStatefulAction {
    fn gen_desc(
        &self,
        _flow_id: InnerFlowId,
        _resources: &Resources,
    ) -> Arc<dyn ActionDesc> {
        Arc::new(IdentityDesc::new(self.name.clone()))
    }
}

impl Firewall {
    pub fn create_layer() -> Layer {
        // A stateful action creates a FlowTable entry.
        let stateful_action = LayerAction::Stateful(
            Box::new(FwStatefulAction::new("fw".to_string()))
        );

        // A static action does not create an entry in the FlowTable.
        // For the moment this is only used to allow ARP to bypass the
        // firewall layer, but it may be useful to expose this more
        // generally in the future.
        let static_action = LayerAction::Static(Box::new(Identity::new(
            "fw_arp".to_string(),
        )));

        let mut layer = Layer::new(
            "firewall",
            vec![stateful_action, static_action]
        );
        add_default_inbound_rules(&mut layer);
        add_default_outbound_rules(&mut layer);
        layer
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FwRemRuleReq {
    pub dir: Direction,
    pub id: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FwAddRuleReq {
    pub rule: FirewallRule,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FirewallRule {
    pub direction: Direction,
    // pub target: Target,
    pub filters: Filters,
    pub action: Action,
    pub priority: u16,
}

impl FromStr for FirewallRule {
    type Err = ParseErr;

    fn from_str(s: &str) -> ParseResult<Self> {
        let mut action = None;
        let mut direction = None;
        let mut priority = None;
        // let mut target = None;
        let mut hosts = None;
        let mut protocol = None;
        let mut ports = None;

        for token in s.to_ascii_lowercase().split(" ") {
            match token.split_once("=") {
                None => {
                    return Err(ParseErr::BadToken(token.to_string()));
                }

                Some(("dir", val)) => {
                    direction = Some(val.parse::<Direction>()?);
                }

                // Some(("target", val)) => {
                //     target = Some(val.parse::<Target>()?);
                // }
                Some(("action", val)) => {
                    action = Some(val.parse::<Action>()?);
                }

                Some(("priority", val)) => {
                    priority = Some(val.parse::<u16>()?);
                }

                // Parse the filters.
                Some(("ip", _)) => {
                    hosts = Some(token.parse::<Address>()?);
                }

                Some(("protocol", val)) => {
                    protocol = Some(val.parse::<ProtoFilter>()?);
                }

                // TODO For now just allow single port.
                Some(("port", val)) => {
                    ports = Some(val.parse::<Ports>()?);
                }

                Some((_, _)) => {
                    return Err(ParseErr::UnknownToken(token.to_string()));
                }
            }
        }

        if action.is_none() || direction.is_none() || priority.is_none()
        // || target.is_none()
        {
            return Err(ParseErr::MissingField);
        }

        let mut filters = Filters::new();
        filters
            .set_hosts(hosts.unwrap_or(Address::Any))
            .protocol(protocol.unwrap_or(ProtoFilter::Any))
            .ports(ports.unwrap_or(Ports::Any));

        Ok(FirewallRule {
            direction: direction.unwrap(),
            // target.unwrap(),
            filters,
            action: action.unwrap(),
            priority: priority.unwrap(),
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Action {
    Allow,
    Deny,
}

impl FromStr for Action {
    type Err = ParseErr;

    fn from_str(s: &str) -> ParseResult<Self> {
        match s.to_ascii_lowercase().as_str() {
            "allow" => Ok(Action::Allow),
            "deny" => Ok(Action::Deny),
            _ => Err(ParseErr::BadAction),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Filters {
    hosts: Address,
    protocol: ProtoFilter,
    ports: Ports,
}

impl Display for Filters {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "proto={} ports={} hosts={}",
            self.protocol, self.ports, self.hosts
        )
    }
}

impl Filters {
    pub fn new() -> Self {
        Filters {
            hosts: Address::Any,
            protocol: ProtoFilter::Any,
            ports: Ports::Any,
        }
    }

    pub fn new_hosts(hosts: Address) -> Self {
        Filters { hosts, protocol: ProtoFilter::Any, ports: Ports::Any }
    }

    pub fn set_hosts<H: Into<Address>>(&mut self, hosts: H) -> &mut Self {
        self.hosts = hosts.into();
        self
    }

    pub fn protocol<P: Into<ProtoFilter>>(&mut self, proto: P) -> &mut Self {
        self.protocol = proto.into();
        self
    }

    pub fn ports<P: Into<Ports>>(&mut self, ports: P) -> &mut Self {
        self.ports = ports.into();
        self
    }

    pub fn port(&mut self, port: u16) -> &mut Self {
        self.ports = Ports::PortList(vec![port]);
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Address {
    Any,
    Subnet(Ipv4Cidr),
    Ip(Ipv4Addr),
}

impl FromStr for Address {
    type Err = ParseErr;

    fn from_str(s: &str) -> ParseResult<Self> {
        match s.to_ascii_lowercase().as_str() {
            "any" => Ok(Address::Any),

            addrstr => match addrstr.split_once("=") {
                None => Err(ParseErr::Malformed),
                Some(("ip", val)) => Ok(Address::Ip(val.parse()?)),
                Some(("subnet", val)) => Ok(Address::Subnet(val.parse()?)),
                Some((_, _)) => Err(ParseErr::Malformed),
            },
        }
    }
}

#[test]
fn parse_good_address() {
    assert_eq!("any".parse::<Address>(), Ok(Address::Any));
    assert_eq!(
        "ip=192.168.2.1".parse::<Address>(),
        Ok(Address::Ip("192.168.2.1".parse().unwrap()))
    );
}

#[test]
fn parse_bad_address() {
    use crate::ip4::IpError;

    assert_eq!("ip:192.168.2.1".parse::<Address>(), Err(ParseErr::Malformed));
    assert_eq!(
        "ip=192.168.2".parse::<Address>(),
        Err(ParseErr::IpError(IpError::MalformedIp("192.168.2".to_string())))
    );
    assert_eq!(
        "ip=192.168.O.1".parse::<Address>(),
        Err(ParseErr::IpError(IpError::MalformedInt))
    );
    assert_eq!("addr=192.168.2.1".parse::<Address>(), Err(ParseErr::Malformed));
}

impl Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Address::Any => write!(f, "ANY"),

            Address::Ip(val) => {
                write!(f, "{},", val)
            }

            Address::Subnet(val) => {
                write!(f, "{},", val)
            }
        }
    }
}

impl Address {
    pub fn new_ip(ip: Ipv4Addr) -> Address {
        Address::Ip(ip)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProtoFilter {
    Any,
    Proto(Protocol),
}

impl FromStr for ProtoFilter {
    type Err = ParseErr;

    fn from_str(s: &str) -> ParseResult<Self> {
        match s.to_ascii_lowercase().as_str() {
            "any" => Ok(ProtoFilter::Any),
            "tcp" => Ok(ProtoFilter::Proto(Protocol::TCP)),
            _ => Err(ParseErr::BadProtoError),
        }
    }
}

#[test]
fn parse_good_proto_filter() {
    assert_eq!("aNy".parse::<ProtoFilter>().unwrap(), ProtoFilter::Any);
    assert_eq!(
        "TCp".parse::<ProtoFilter>().unwrap(),
        ProtoFilter::Proto(Protocol::TCP)
    );
}

#[test]
fn parse_bad_proto_filter() {
    assert_eq!(
        "foo".parse::<ProtoFilter>().err(),
        Some(ParseErr::BadProtoError)
    );
    assert_eq!(
        "TCP,".parse::<ProtoFilter>().err(),
        Some(ParseErr::BadProtoError)
    );
    assert_eq!("6".parse::<ProtoFilter>().err(), Some(ParseErr::BadProtoError));
}

impl Display for ProtoFilter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProtoFilter::Any => write!(f, "ANY"),
            ProtoFilter::Proto(proto) => write!(f, "{},", proto),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Ports {
    Any,
    PortList(Vec<u16>),
}

impl FromStr for Ports {
    type Err = ParseErr;

    fn from_str(s: &str) -> ParseResult<Self> {
        match s.to_ascii_lowercase().as_str() {
            "any" => Ok(Ports::Any),
            "any," => Ok(Ports::Any),

            _ => {
                let ports: Vec<u16> =
                    s.split(",")
                        .map(|s| s.parse())
                        .collect::<std::result::Result<Vec<u16>, _>>()?;

                if ports.len() == 0 {
                    return Err(ParseErr::MalformedPort);
                }

                // TODO Move this into code above, it's only a
                // separate check because I was in a hurry to refactor
                // the ioctl code.
                for p in ports.iter() {
                    if *p == DYNAMIC_PORT {
                        return Err(ParseErr::InvalidPort);
                    }
                }
                Ok(Ports::PortList(ports))
            }
        }
    }
}

#[test]
fn ports_from_str_good() {
    assert_eq!("AnY".parse::<Ports>(), Ok(Ports::Any));
    assert_eq!("any,".parse::<Ports>(), Ok(Ports::Any));
    assert_eq!("22".parse::<Ports>().unwrap(), Ports::PortList(vec![22]));
    assert_eq!(
        "22,443".parse::<Ports>().unwrap(),
        Ports::PortList(vec![22, 443])
    );
}

#[test]
fn ports_from_str_bad() {
    assert_eq!("".parse::<Ports>(), Err(ParseErr::MalformedInt));
    assert_eq!("0".parse::<Ports>(), Err(ParseErr::InvalidPort));
    assert_eq!("rpz".parse::<Ports>(), Err(ParseErr::MalformedInt));
    assert_eq!("rpz,0".parse::<Ports>(), Err(ParseErr::MalformedInt));
    assert_eq!("rpz,22".parse::<Ports>(), Err(ParseErr::MalformedInt));
    assert_eq!("22,rpz".parse::<Ports>(), Err(ParseErr::MalformedInt));
    assert_eq!("any,rpz".parse::<Ports>(), Err(ParseErr::MalformedInt));
}

impl Display for Ports {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Ports::Any => write!(f, "ANY"),
            Ports::PortList(plist) => {
                // TODO For now we just assume one port.
                write!(f, "{}", plist[0])
            }
        }
    }
}

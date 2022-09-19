// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use core::fmt::{self, Display};
use core::result;
use core::str::FromStr;
use illumos_sys_hdrs::datalink_id_t;
pub use opte::api::*;
use serde::{Deserialize, Serialize};

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::{String, ToString};
        use alloc::vec::Vec;
    } else {
        use std::string::{String, ToString};
        use std::vec::Vec;
    }
}

/// Description of Boundary Services, the endpoint used to route traffic
/// to external networks.
//
// NOTE: This is identical to the `PhysNet` type below, but serves a different
// purpose, to identify Boundary Services itself, not a generic physical network
// endpoint in an Oxide rack.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BoundaryServices {
    /// IPv6 address of the switch running Boundary Services.
    pub ip: Ipv6Addr,
    /// Dedicated Geneve VNI for Boundary Services traffic.
    pub vni: Vni,
    /// A MAC address identifying Boundary Services as a logical next
    /// hop.
    // This value is effectively arbitrary. It's never used to filter or
    // direct traffic by the Oxide VPC. It is used to rewrite the
    // destination MAC address of the _inner_ guest Ethernet frame, from
    // the OPTE virtual gateway MAC, to this one. This serves two
    // purposes: OPTE acts "correctly" as a gateway, rewriting the
    // destination MAC to the logical next hop; and as an observability
    // tool, allowing us to snoop traffic with this MAC. We already have
    // the VNI of Boundary Services for that, but it might be useful
    // nonetheless.
    pub mac: MacAddr,
}

/// The IPv4 configuration for an OPTE port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Cfg {
    /// The private IP subnet of the VPC Subnet.
    pub vpc_subnet: Ipv4Cidr,

    /// The guest's private IP address in the VPC Subnet.
    pub private_ip: Ipv4Addr,

    /// The IPv4 address for the virtual gateway.
    ///
    /// The virtual gateway is what the guest sees as its gateway to all other
    /// networks, including other VPC guests as well as external networks and
    /// the internet. Essentially, this is the IPv4 address of OPTE itself,
    /// which is acting as the gateway to the guest.
    pub gateway_ip: Ipv4Addr,

    /// The source NAT configuration for making outbound connections
    /// from the private network.
    ///
    /// This allows a guest to make outbound connections to hosts on an external
    /// network when there is no external IP address assigned to the guest
    /// itself.
    //
    // XXX Keep this optional for now until NAT'ing is more thoroughly
    // implemented in Omicron.
    pub snat_cfg: Option<SNat4Cfg>,

    /// Optional external IP addresses for this port.
    ///
    /// This allows hosts on the external network to make inbound connections to
    /// the guest. When present, it is also used as 1:1 NAT for outbound
    /// connections from the guest to an external network.
    //
    // XXX For now we only allow one external IP.
    pub external_ips: Option<Ipv4Addr>,
}

/// The IPv6 configuration for an OPTE port
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6Cfg {
    /// The private IP subnet of the VPC Subnet.
    pub vpc_subnet: Ipv6Cidr,

    /// The guest's private IP address in the VPC Subnet.
    pub private_ip: Ipv6Addr,

    /// The IPv6 address for the virtual gateway.
    ///
    /// The virtual gateway is what the guest sees as its gateway to all other
    /// networks, including other VPC guests as well as external networks and
    /// the internet. Essentially, this is the IPv6 address of OPTE itself,
    /// which is acting as the gateway to the guest.
    pub gateway_ip: Ipv6Addr,

    /// The source NAT configuration for making outbound connections
    /// from the private network.
    ///
    /// This allows a guest to make outbound connections to hosts on an external
    /// network when there is no external IP address assigned to the guest
    /// itself.
    //
    // XXX Keep this optional for now until NAT'ing is more thoroughly
    // implemented in Omicron.
    pub snat_cfg: Option<SNat6Cfg>,

    /// Optional external IP addresses for this port.
    ///
    /// This allows hosts on the external network to make inbound connections to
    /// the guest. When present, it is also used as 1:1 NAT for outbound
    /// connections from the guest to an external network.
    //
    // XXX For now we only allow one external IP.
    pub external_ips: Option<Ipv6Addr>,
}

/// The IP configuration for a port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpCfg {
    Ipv4(Ipv4Cfg),
    Ipv6(Ipv6Cfg),
    DualStack { ipv4: Ipv4Cfg, ipv6: Ipv6Cfg },
}

/// The overall configuration for an OPTE port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpcCfg {
    /// IP address configuration.
    pub ip_cfg: IpCfg,

    /// The VPC-private MAC address of the guest.
    pub private_mac: MacAddr,

    /// The MAC address for the virtual gateway.
    ///
    /// The virtual gateway is what the guest sees as its gateway to all other
    /// networks, including other VPC guests as well as external networks and
    /// the internet. Essentially, this is the MAC address of OPTE itself,
    /// which is acting as the gateway to the guest.
    pub gateway_mac: MacAddr,

    /// The Geneve Virtual Network Identifier for this VPC in which the guest
    /// resides.
    pub vni: Vni,

    /// The host (sled) IPv6 address. All guests on the same sled are
    /// sourced to a single IPv6 address.
    pub phys_ip: Ipv6Addr,

    /// Information for reaching Boundary Services, for traffic destined
    /// for external networks.
    pub boundary_services: BoundaryServices,

    // XXX-EXT-IP the following two fields are for the external IP hack.
    pub proxy_arp_enable: bool,
    pub phys_gw_mac: Option<MacAddr>,
}

impl VpcCfg {
    /// Return the IPv4 configuration, if it exists, or None.
    pub fn ipv4_cfg(&self) -> Option<&Ipv4Cfg> {
        match self.ip_cfg {
            IpCfg::Ipv4(ref ipv4) | IpCfg::DualStack { ref ipv4, .. } => {
                Some(ipv4)
            }
            _ => None,
        }
    }

    /// Return the IPv6 configuration, if it exists, or None.
    pub fn ipv6_cfg(&self) -> Option<&Ipv6Cfg> {
        match self.ip_cfg {
            IpCfg::Ipv6(ref ipv6) | IpCfg::DualStack { ref ipv6, .. } => {
                Some(ipv6)
            }
            _ => None,
        }
    }
}

/// A network destination on the Oxide Rack's physical network.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct PhysNet {
    pub ether: MacAddr,
    pub ip: Ipv6Addr,
    pub vni: Vni,
}

/// The physical address for a guest.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct GuestPhysAddr {
    pub ether: MacAddr,
    pub ip: Ipv6Addr,
}

/// The target for a given router entry.
///
/// * Drop: Packets matching this entry are dropped.
///
/// * InternetGateway: Packets matching this entry are forwarded to
/// the internet. In the case of the Oxide Network the IG is not an
/// actual destination, but rather a configuration that determines how
/// we should NAT the flow.
///
/// * Ip: Packets matching this entry are forwarded to the specified IP.
///
/// XXX Make sure that if a router's target is an IP address that it
/// matches the destination IP type.
///
/// * VpcSubnet: Packets matching this entry are forwarded to the
/// specified VPC Subnet. In the Oxide Network this is just an
/// abstraction, it's simply allowing one subnet to talk to another.
/// There is no separate VPC router process, the real routing is done
/// by the underlay.
#[derive(Clone, Debug, Copy, Deserialize, Serialize)]
pub enum RouterTarget {
    Drop,
    InternetGateway,
    Ip(IpAddr),
    VpcSubnet(IpCidr),
}

#[cfg(any(feature = "std", test))]
impl FromStr for RouterTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "drop" => Ok(Self::Drop),
            "ig" => Ok(Self::InternetGateway),
            lower => match lower.split_once("=") {
                Some(("ip4", ip4s)) => {
                    let ip4 = ip4s
                        .parse::<std::net::Ipv4Addr>()
                        .map_err(|e| format!("bad IP: {}", e))?;
                    Ok(Self::Ip(IpAddr::Ip4(ip4.into())))
                }

                Some(("sub4", cidr4s)) => {
                    let cidr4 = cidr4s.parse()?;
                    Ok(Self::VpcSubnet(IpCidr::Ip4(cidr4)))
                }

                Some(("ip6", ip6s)) => {
                    ip6s.parse().map(|x| Self::Ip(IpAddr::Ip6(x)))
                }

                Some(("sub6", cidr6s)) => {
                    cidr6s.parse().map(|x| Self::VpcSubnet(IpCidr::Ip6(x)))
                }

                _ => Err(format!("malformed router target: {}", lower)),
            },
        }
    }
}

impl Display for RouterTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Drop => write!(f, "Drop"),
            Self::InternetGateway => write!(f, "IG"),
            Self::Ip(IpAddr::Ip4(ip4)) => write!(f, "ip4={}", ip4),
            Self::Ip(IpAddr::Ip6(ip6)) => write!(f, "ip6={}", ip6),
            Self::VpcSubnet(IpCidr::Ip4(sub4)) => write!(f, "sub4={}", sub4),
            Self::VpcSubnet(IpCidr::Ip6(sub6)) => write!(f, "sub6={}", sub6),
        }
    }
}

/// Xde create ioctl parameter data.
///
/// The bulk of the information is provided via [`VpcCfg`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateXdeReq {
    /// The link identifier of the guest, as provided by dlmgmtd.
    pub linkid: datalink_id_t,

    /// The name of the data link, as it appears to `dlmgmtd`.
    pub xde_devname: String,

    /// Configuration information describing the device. See [`VpcCfg`] for more
    /// details.
    pub cfg: VpcCfg,

    /// This is a development tool for completely bypassing OPTE processing.
    ///
    /// XXX Pretty sure we aren't making much use of this anymore, and
    /// should go away before v1.
    pub passthrough: bool,
}

/// Configuration of source NAT for a port, describing how a private IP
/// address is mapped to an external IP and port range for outbound connections.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SNat4Cfg {
    pub external_ip: Ipv4Addr,
    pub ports: core::ops::RangeInclusive<u16>,
}

/// Configuration of source NAT for a port, describing how a private IP
/// address is mapped to an external IP and port range for outbound connections.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SNat6Cfg {
    pub external_ip: Ipv6Addr,
    pub ports: core::ops::RangeInclusive<u16>,
}

/// Xde delete ioctl parameter data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeleteXdeReq {
    pub xde_devname: String,
}

/// List existing xde ports.
#[derive(Debug, Deserialize, Serialize)]
pub struct ListPortsReq {
    pub unused: (),
}

/// Information about a single existing xde port
#[derive(Debug, Deserialize, Serialize)]
pub struct PortInfo {
    pub name: String,
    pub mac_addr: MacAddr,
    pub ip4_addr: Option<Ipv4Addr>,
    pub external_ip4_addr: Option<Ipv4Addr>,
    pub ip6_addr: Option<Ipv6Addr>,
    pub external_ip6_addr: Option<Ipv6Addr>,
    pub state: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListPortsResp {
    pub ports: Vec<PortInfo>,
}

impl opte::api::cmd::CmdOk for ListPortsResp {}

/// Set mapping from VPC IP to physical network destination.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SetVirt2PhysReq {
    pub vip: IpAddr,
    pub phys: PhysNet,
}

/// Add an entry to the router. Addresses may be either IPv4 or IPv6, though the
/// destination and target must match in protocol version.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AddRouterEntryReq {
    pub port_name: String,
    pub dest: IpCidr,
    pub target: RouterTarget,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DelRouterEntryReq {
    pub port_name: String,
    pub dest: IpCidr,
    pub target: RouterTarget,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum DelRouterEntryResp {
    Ok,
    NotFound,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AddFwRuleReq {
    pub port_name: String,
    pub rule: FirewallRule,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SetFwRulesReq {
    pub port_name: String,
    pub rules: Vec<FirewallRule>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RemFwRuleReq {
    pub port_name: String,
    pub dir: Direction,
    pub id: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FirewallRule {
    pub direction: Direction,
    pub filters: Filters,
    pub action: Action,
    pub priority: u16,
}

impl FromStr for FirewallRule {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut action = None;
        let mut direction = None;
        let mut priority = None;
        let mut hosts = None;
        let mut protocol = None;
        let mut ports = None;

        for token in s.to_ascii_lowercase().split(" ") {
            match token.split_once("=") {
                None => {
                    return Err(format!("bad token: {}", token));
                }

                Some(("dir", val)) => {
                    direction = Some(val.parse::<Direction>()?);
                }

                Some(("action", val)) => {
                    action = Some(val.parse::<Action>()?);
                }

                Some(("priority", val)) => {
                    priority = Some(val.parse::<u16>().map_err(|e| {
                        format!("bad priroity: '{}' {}", val, e.to_string())
                    })?);
                }

                // Parse the filters.
                Some(("hosts", val)) => {
                    hosts = Some(val.parse::<Address>()?);
                }

                Some(("protocol", val)) => {
                    protocol = Some(val.parse::<ProtoFilter>()?);
                }

                // TODO For now just allow single port.
                Some(("port", val)) => {
                    ports = Some(val.parse::<Ports>()?);
                }

                Some((_, _)) => {
                    return Err(format!("invalid key: {}", token));
                }
            }
        }

        if action.is_none() {
            return Err(format!("missing 'action' key"));
        }

        if direction.is_none() {
            return Err(format!("missing direction ('dir') key"));
        }

        if priority.is_none() {
            return Err(format!("missing 'priority' key"));
        }

        let mut filters = Filters::new();
        filters
            .set_hosts(hosts.unwrap_or(Address::Any))
            .set_protocol(protocol.unwrap_or(ProtoFilter::Any))
            .set_ports(ports.unwrap_or(Ports::Any));

        Ok(FirewallRule {
            direction: direction.unwrap(),
            // target.unwrap(),
            filters,
            action: action.unwrap(),
            priority: priority.unwrap(),
        })
    }
}

// TODO rename FirewallAction
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Action {
    Allow,
    Deny,
}

impl FromStr for Action {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "allow" => Ok(Action::Allow),
            "deny" => Ok(Action::Deny),
            _ => Err(format!("invalid action: {} ('allow' or 'deny')", s)),
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

    pub fn hosts(&self) -> Address {
        self.hosts
    }

    pub fn new_hosts(hosts: Address) -> Self {
        Filters { hosts, protocol: ProtoFilter::Any, ports: Ports::Any }
    }

    pub fn ports(&self) -> &Ports {
        &self.ports
    }

    pub fn protocol(&self) -> ProtoFilter {
        self.protocol
    }

    pub fn set_hosts<H: Into<Address>>(&mut self, hosts: H) -> &mut Self {
        self.hosts = hosts.into();
        self
    }

    pub fn set_protocol<P: Into<ProtoFilter>>(
        &mut self,
        proto: P,
    ) -> &mut Self {
        self.protocol = proto.into();
        self
    }

    pub fn set_ports<P: Into<Ports>>(&mut self, ports: P) -> &mut Self {
        self.ports = ports.into();
        self
    }

    pub fn set_port(&mut self, port: u16) -> &mut Self {
        self.ports = Ports::PortList(vec![port]);
        self
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Address {
    Any,
    Subnet(Ipv4Cidr),
    Ip(Ipv4Addr),
}

impl FromStr for Address {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "any" => Ok(Address::Any),

            addrstr => match addrstr.split_once("=") {
                None => Err(format!(
                    "malformed address specification: {}",
                    addrstr,
                )),
                Some(("ip", val)) => Ok(Address::Ip(val.parse()?)),
                Some(("subnet", val)) => Ok(Address::Subnet(val.parse()?)),
                Some((key, _)) => Err(format!("invalid address type: {}", key)),
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
    assert!("ip:192.168.2.1".parse::<Address>().is_err());
    assert!("ip=192.168.2".parse::<Address>().is_err());
    assert!("ip=192.168.O.1".parse::<Address>().is_err());
    assert!("addr=192.168.2.1".parse::<Address>().is_err());
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProtoFilter {
    Any,
    Proto(Protocol),
}

impl FromStr for ProtoFilter {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "any" => Ok(ProtoFilter::Any),
            "icmp" => Ok(ProtoFilter::Proto(Protocol::ICMP)),
            "tcp" => Ok(ProtoFilter::Proto(Protocol::TCP)),
            "udp" => Ok(ProtoFilter::Proto(Protocol::UDP)),
            _ => Err(format!("unknown protocol: {}", s)),
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
    assert!("foo".parse::<ProtoFilter>().is_err());
    assert!("TCP,".parse::<ProtoFilter>().is_err());
    assert!("6".parse::<ProtoFilter>().is_err());
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
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "any" => Ok(Ports::Any),
            "any," => Ok(Ports::Any),

            _ => {
                let ports: Vec<u16> = s
                    .split(",")
                    .map(|ps| ps.parse::<u16>().map_err(|e| e.to_string()))
                    .collect::<result::Result<Vec<u16>, _>>()?;

                if ports.len() == 0 {
                    return Err(format!("malformed ports spec: {}", s));
                }

                for p in ports.iter() {
                    if *p == DYNAMIC_PORT {
                        return Err(format!("invalid port: {}", p));
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
    assert!("".parse::<Ports>().is_err());
    assert!("0".parse::<Ports>().is_err());
    assert!("rpz".parse::<Ports>().is_err());
    assert!("rpz,0".parse::<Ports>().is_err());
    assert!("rpz,22".parse::<Ports>().is_err());
    assert!("22,rpz".parse::<Ports>().is_err());
    assert!("any,rpz".parse::<Ports>().is_err());
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

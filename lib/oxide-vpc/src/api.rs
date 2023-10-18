// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

use core::fmt;
use core::fmt::Display;
use core::result;
use core::str::FromStr;
use illumos_sys_hdrs::datalink_id_t;
pub use opte::api::*;
use serde::Deserialize;
use serde::Serialize;

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

/// The IPv4 configuration of a VPC guest.
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
    pub snat: Option<SNat4Cfg>,

    /// Optional external IP addresses for this port.
    ///
    /// This allows hosts on the external network to make inbound connections to
    /// the guest. When present, it is also used as 1:1 NAT for outbound
    /// connections from the guest to an external network.
    //
    // XXX For now we only allow one external IP.
    pub external_ips: Option<Ipv4Addr>,
}

/// The IPv6 configuration of a VPC guest.
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
    //
    // TODO-remove: The current plan is to use only the link-local address for
    // OPTE as the virtual gateway, populated by NDP. Assuming we move forward
    // with that, this should be removed.
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
    pub snat: Option<SNat6Cfg>,

    /// Optional external IP addresses for this port.
    ///
    /// This allows hosts on the external network to make inbound connections to
    /// the guest. When present, it is also used as 1:1 NAT for outbound
    /// connections from the guest to an external network.
    //
    // XXX For now we only allow one external IP.
    pub external_ips: Option<Ipv6Addr>,
}

/// The IP configuration of a VPC guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpCfg {
    Ipv4(Ipv4Cfg),
    Ipv6(Ipv6Cfg),
    DualStack { ipv4: Ipv4Cfg, ipv6: Ipv6Cfg },
}

impl IpCfg {
    #[cfg(any(feature = "test-help", test))]
    pub fn ext_ipv4(&self) -> Ipv4Addr {
        match self {
            Self::Ipv4(ipv4) | Self::DualStack { ipv4, .. } => {
                ipv4.external_ips.unwrap()
            }

            _ => panic!("set IPv4 external IP on IPv6-only config"),
        }
    }

    #[cfg(any(feature = "test-help", test))]
    pub fn set_ext_ipv4(&mut self, ip: Ipv4Addr) {
        match self {
            Self::Ipv4(ipv4) | Self::DualStack { ipv4, .. } => {
                if let Some(snat) = &ipv4.snat {
                    assert_ne!(snat.external_ip, ip);
                }
                ipv4.external_ips = Some(ip);
            }

            _ => panic!("set IPv4 external IP on IPv6-only config"),
        }
    }
}

/// The overall configuration for an OPTE port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpcCfg {
    /// IP address configuration.
    pub ip_cfg: IpCfg,

    /// The VPC MAC address of the guest.
    pub guest_mac: MacAddr,

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

    /// Return an exclusive reference to the IPv4 configuration, if it exists,
    /// or None.
    pub fn ipv4_cfg_mut(&mut self) -> Option<&mut Ipv4Cfg> {
        match self.ip_cfg {
            IpCfg::Ipv4(ref mut ipv4)
            | IpCfg::DualStack { ref mut ipv4, .. } => Some(ipv4),
            _ => None,
        }
    }

    #[cfg(any(feature = "test-help", test))]
    pub fn ipv4(&self) -> &Ipv4Cfg {
        match &self.ip_cfg {
            IpCfg::Ipv4(ipv4) | IpCfg::DualStack { ipv4, .. } => ipv4,

            _ => panic!("expected an IPv4 configuration"),
        }
    }

    #[cfg(any(feature = "test-help", test))]
    pub fn ext_ipv4(&self) -> Ipv4Addr {
        self.ip_cfg.ext_ipv4()
    }

    #[cfg(any(feature = "test-help", test))]
    pub fn set_ext_ipv4(&mut self, ip: Ipv4Addr) {
        self.ip_cfg.set_ext_ipv4(ip);
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

    /// Return an exclusive reference to the IPv6 configuration, if it exists,
    /// or None.
    pub fn ipv6_cfg_mut(&mut self) -> Option<&mut Ipv6Cfg> {
        match self.ip_cfg {
            IpCfg::Ipv6(ref mut ipv6)
            | IpCfg::DualStack { ref mut ipv6, .. } => Some(ipv6),
            _ => None,
        }
    }

    #[cfg(any(feature = "test-help", test))]
    /// Return the physical address of the guest.
    pub fn phys_addr(&self) -> PhysNet {
        PhysNet { ether: self.guest_mac, ip: self.phys_ip, vni: self.vni }
    }

    #[cfg(not(any(feature = "test-help", test)))]
    /// Return the IPv4 SNAT config, if it exists.
    pub fn snat(&self) -> Option<&SNat4Cfg> {
        match &self.ip_cfg {
            IpCfg::Ipv4(ipv4) | IpCfg::DualStack { ipv4, .. } => {
                ipv4.snat.as_ref()
            }

            _ => None,
        }
    }

    #[cfg(any(feature = "test-help", test))]
    pub fn snat(&self) -> &SNat4Cfg {
        match &self.ip_cfg {
            IpCfg::Ipv4(ipv4) | IpCfg::DualStack { ipv4, .. } => {
                ipv4.snat.as_ref().unwrap()
            }

            _ => panic!("expected an IPv4 SNAT configuration"),
        }
    }

    #[cfg(any(feature = "test-help", test))]
    pub fn snat6(&self) -> &SNat6Cfg {
        match &self.ip_cfg {
            IpCfg::Ipv6(ipv6) | IpCfg::DualStack { ipv6, .. } => {
                ipv6.snat.as_ref().unwrap()
            }

            _ => panic!("expected an IPv6 SNAT configuration"),
        }
    }

    /// Return the total number of external ports in the IP configuration,
    /// across both IPv4 and IPv6. If there is no external address configured,
    /// of either family, `None` is returned. If there is such a configuration,
    /// then `Some` is returned, though the contained value may still be zero if
    /// the port range for the relevant address is empty
    ///
    /// Note that this uses the explicit 1-1 NAT external IP address over the
    /// SNAT address, if both are provided.
    //
    // # Notes
    //
    // This is mostly used for computing flow table limits in some situations,
    // such as for the NAT layer in OPTE.
    //
    // The NAT layer only applies to traffic that is destinted outside the VPC.
    // If the configuration supplies no external addresses at all, then we
    // return `NonZeroU32(1)`. The logic here is that we'd like to keep the NAT
    // layer itself, but it will have zero rules / predicates. I.e., no traffic
    // will ever match or be rewritten. We supply the minimum possible
    // flow-table size in that case, of one. See `oxide_vpc::engine::nat::setup`
    // for confirmation that the layer will be "empty" if we have no external
    // addresses.
    pub fn n_external_ports(&self) -> Option<u32> {
        let n_ipv4_ports = match &self.ip_cfg {
            IpCfg::Ipv4(ipv4) | IpCfg::DualStack { ipv4, .. } => {
                match (ipv4.external_ips, &ipv4.snat) {
                    (Some(_), _) => Some(u32::from(u16::MAX)),
                    (None, Some(snat)) => {
                        // Safety: This is an inclusive range of `u16`s, so the
                        // length is <= `u16::MAX` and fits in a `u32`.
                        let n_ports = u32::try_from(snat.ports.len()).unwrap();
                        Some(n_ports)
                    }
                    (None, None) => None,
                }
            }
            _ => None,
        };
        let n_ipv6_ports = match &self.ip_cfg {
            IpCfg::Ipv6(ipv6) | IpCfg::DualStack { ipv6, .. } => {
                match (ipv6.external_ips, &ipv6.snat) {
                    (Some(_), _) => Some(u32::from(u16::MAX)),
                    (None, Some(snat)) => {
                        // Safety: This is an inclusive range of `u16`s, so the
                        // length is <= `u16::MAX` and fits in a `u32`.
                        let n_ports = u32::try_from(snat.ports.len()).unwrap();
                        Some(n_ports)
                    }
                    (None, None) => None,
                }
            }
            _ => None,
        };
        match (n_ipv4_ports, n_ipv6_ports) {
            (None, None) => None,
            (v4, v6) => Some(v4.unwrap_or(0) + v6.unwrap_or(0)),
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

/// The physical address for a guest, minus the VNI.
///
/// We save space in the VPC mappings by grouping guest
/// Virtual-to-Physical mappings by VNI.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct GuestPhysAddr {
    pub ether: MacAddr,
    pub ip: Ipv6Addr,
}

impl From<PhysNet> for GuestPhysAddr {
    fn from(phys: PhysNet) -> Self {
        Self { ether: phys.ether, ip: phys.ip }
    }
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
            lower => match lower.split_once('=') {
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

    /// Configuration for DHCP responses created by OPTE
    pub dhcp: DhcpCfg,

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

#[derive(Debug, Deserialize, Serialize)]
pub struct SetDhcpParamsReq {
    pub port_name: String,
    pub data: DhcpCfg,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpDhcpParamsReq {
    pub port_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpDhcpParamsResp {
    pub data: DhcpCfg,
}

impl CmdOk for DumpDhcpParamsResp {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FirewallRule {
    pub direction: Direction,
    pub filters: Filters,
    pub action: FirewallAction,
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

        for token in s.to_ascii_lowercase().split(' ') {
            match token.split_once('=') {
                None => {
                    return Err(format!("bad token: {}", token));
                }

                Some(("dir", val)) => {
                    direction = Some(val.parse::<Direction>()?);
                }

                Some(("action", val)) => {
                    action = Some(val.parse::<FirewallAction>()?);
                }

                Some(("priority", val)) => {
                    priority = Some(val.parse::<u16>().map_err(|e| {
                        format!("bad priroity: '{}' {}", val, e)
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
            return Err("missing 'action' key".to_string());
        }

        if direction.is_none() {
            return Err("missing direction ('dir') key".to_string());
        }

        if priority.is_none() {
            return Err("missing 'priority' key".to_string());
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FirewallAction {
    Allow,
    Deny,
}

impl FromStr for FirewallAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "allow" => Ok(FirewallAction::Allow),
            "deny" => Ok(FirewallAction::Deny),
            _ => Err(format!("invalid action: {} ('allow' or 'deny')", s)),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
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

/// Filter traffic by address.
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize,
)]
pub enum Address {
    /// Match traffic from any address.
    #[default]
    Any,

    /// Match traffic from the given subnet CIDR.
    Subnet(IpCidr),

    /// Match traffic from the given IP address.
    Ip(IpAddr),

    /// Match traffic from the given VNI.
    Vni(Vni),
}

impl FromStr for Address {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "any" => Ok(Address::Any),

            addrstr => match addrstr.split_once('=') {
                None => Err(format!(
                    "malformed address specification: {}",
                    addrstr,
                )),
                Some(("ip", val)) => Ok(Address::Ip(val.parse()?)),
                Some(("subnet", val)) => Ok(Address::Subnet(val.parse()?)),
                Some(("vni", val)) => Ok(Address::Vni(val.parse()?)),
                Some((key, _)) => Err(format!("invalid address type: {}", key)),
            },
        }
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Address::Any => write!(f, "ANY"),
            Address::Ip(val) => write!(f, "{},", val),
            Address::Subnet(val) => write!(f, "{},", val),
            Address::Vni(val) => write!(f, "{}", val),
        }
    }
}

#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize,
)]
pub enum ProtoFilter {
    #[default]
    Any,
    Arp,
    Proto(Protocol),
}

impl FromStr for ProtoFilter {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "any" => Ok(ProtoFilter::Any),
            "arp" => Ok(ProtoFilter::Arp),
            "icmp" => Ok(ProtoFilter::Proto(Protocol::ICMP)),
            "icmp6" => Ok(ProtoFilter::Proto(Protocol::ICMPv6)),
            "tcp" => Ok(ProtoFilter::Proto(Protocol::TCP)),
            "udp" => Ok(ProtoFilter::Proto(Protocol::UDP)),
            _ => Err(format!("unknown protocol: {}", s)),
        }
    }
}

impl Display for ProtoFilter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProtoFilter::Any => write!(f, "ANY"),
            ProtoFilter::Arp => write!(f, "ARP"),
            ProtoFilter::Proto(proto) => write!(f, "{},", proto),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum Ports {
    #[default]
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
                    .split(',')
                    .map(|ps| ps.parse::<u16>().map_err(|e| e.to_string()))
                    .collect::<result::Result<Vec<u16>, _>>()?;

                if ports.is_empty() {
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

#[cfg(test)]
mod tests {
    use super::Address;
    use super::BoundaryServices;
    use super::IpAddr;
    use super::IpCfg;
    use super::IpCidr;
    use super::Ipv4Cfg;
    use super::Ipv6Cfg;
    use super::MacAddr;
    use super::Ports;
    use super::ProtoFilter;
    use super::Protocol;
    use super::SNat4Cfg;
    use super::SNat6Cfg;
    use super::Vni;
    use super::VpcCfg;

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

    #[test]
    fn parse_good_address() {
        assert_eq!("any".parse::<Address>(), Ok(Address::Any));
        assert_eq!(
            "ip=192.168.2.1".parse::<Address>(),
            Ok(Address::Ip("192.168.2.1".parse().unwrap()))
        );
        assert_eq!(
            "vni=7777".parse(),
            Ok(Address::Vni(Vni::new(7777u32).unwrap()))
        );
        assert_eq!(
            "ip=fd00::1".parse::<Address>().unwrap(),
            Address::Ip(IpAddr::Ip6("fd00::1".parse().unwrap()))
        );
        assert_eq!(
            "subnet=fd00::0/64".parse::<Address>().unwrap(),
            Address::Subnet(IpCidr::Ip6("fd00::0/64".parse().unwrap()))
        );
    }

    #[test]
    fn parse_bad_address() {
        assert!("ip:192.168.2.1".parse::<Address>().is_err());
        assert!("ip=192.168.2".parse::<Address>().is_err());
        assert!("ip=192.168.O.1".parse::<Address>().is_err());
        assert!("addr=192.168.2.1".parse::<Address>().is_err());
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

    fn test_vpc_cfg() -> VpcCfg {
        VpcCfg {
            boundary_services: BoundaryServices {
                ip: "fd00::99".parse().unwrap(),
                mac: MacAddr::from([0xa8, 0x40, 0x25, 0x00, 0x00, 0x99]),
                vni: Vni::new(99u32).unwrap(),
            },
            gateway_mac: MacAddr::from([0xa8, 0x40, 0x25, 0x00, 0x00, 0x01]),
            guest_mac: MacAddr::from([0xa8, 0x40, 0x25, 0xff, 0xff, 0x01]),
            phys_ip: "fd00::1".parse().unwrap(),
            ip_cfg: IpCfg::DualStack {
                ipv4: Ipv4Cfg {
                    private_ip: "10.0.0.5".parse().unwrap(),
                    external_ips: Some("10.1.0.5".parse().unwrap()),
                    gateway_ip: "10.0.0.1".parse().unwrap(),
                    snat: Some(SNat4Cfg {
                        external_ip: "10.1.0.6".parse().unwrap(),
                        ports: 0..=8095,
                    }),
                    vpc_subnet: "10.0.0.0/24".parse().unwrap(),
                },
                ipv6: Ipv6Cfg {
                    private_ip: "fd00::5".parse().unwrap(),
                    external_ips: Some("fd00:1::5".parse().unwrap()),
                    gateway_ip: "fd00::1".parse().unwrap(),
                    snat: Some(SNat6Cfg {
                        external_ip: "fd00:1::6".parse().unwrap(),
                        ports: 0..=8095,
                    }),
                    vpc_subnet: "fd00::/64".parse().unwrap(),
                },
            },
            vni: Vni::new(100u32).unwrap(),
        }
    }

    #[test]
    fn test_n_external_ports() {
        let cfg = test_vpc_cfg();
        // Each IPv4/v6 has the full port range.
        assert_eq!(cfg.n_external_ports(), Some(u32::from(u16::MAX) * 2));
    }

    // Check that without any external address configuration at all, we return
    // None for the number of external ports.
    #[test]
    fn test_n_external_ports_none() {
        let mut cfg = test_vpc_cfg();
        let ipv4 = cfg.ipv4_cfg_mut().unwrap();
        ipv4.snat.take();
        ipv4.external_ips.take();
        let ipv6 = cfg.ipv6_cfg_mut().unwrap();
        ipv6.snat.take();
        ipv6.external_ips.take();
        assert_eq!(cfg.n_external_ports(), None);
    }

    #[test]
    fn test_n_external_ports_only_ipv4() {
        let mut cfg = test_vpc_cfg();
        let ipv6 = cfg.ipv6_cfg_mut().unwrap();
        ipv6.snat.take();
        ipv6.external_ips.take();
        assert_eq!(cfg.n_external_ports(), Some(u32::from(u16::MAX)));
    }

    #[test]
    fn test_n_external_ports_only_ipv6() {
        let mut cfg = test_vpc_cfg();
        let ipv4 = cfg.ipv4_cfg_mut().unwrap();
        ipv4.snat.take();
        ipv4.external_ips.take();
        assert_eq!(cfg.n_external_ports(), Some(u32::from(u16::MAX)));
    }

    #[test]
    fn test_n_external_ports_only_snat4() {
        let mut cfg = test_vpc_cfg();
        let ipv6 = cfg.ipv6_cfg_mut().unwrap();
        ipv6.snat.take();
        ipv6.external_ips.take();
        let ipv4 = cfg.ipv4_cfg_mut().unwrap();
        ipv4.external_ips.take();
        assert_eq!(cfg.n_external_ports(), Some(8096));
    }

    #[test]
    fn test_n_external_ports_only_snat6() {
        let mut cfg = test_vpc_cfg();
        let ipv4 = cfg.ipv4_cfg_mut().unwrap();
        ipv4.snat.take();
        ipv4.external_ips.take();
        let ipv6 = cfg.ipv6_cfg_mut().unwrap();
        ipv6.external_ips.take();
        assert_eq!(cfg.n_external_ports(), Some(8096));
    }

    #[test]
    #[allow(clippy::reversed_empty_ranges)]
    fn test_n_external_ports_bad_snat_range() {
        let mut cfg = test_vpc_cfg();
        let ipv4 = cfg.ipv4_cfg_mut().unwrap();
        ipv4.external_ips.take();
        ipv4.snat.as_mut().unwrap().ports = 8096..=0;
        let ipv6 = cfg.ipv6_cfg_mut().unwrap();
        ipv6.snat.take();
        ipv6.external_ips.take();
        assert_eq!(cfg.n_external_ports(), Some(0));
    }
}

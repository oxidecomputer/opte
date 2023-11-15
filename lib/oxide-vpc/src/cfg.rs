// We need our own VpcCfg here which is separate from the
// api one to hide the things we do for perf/reconfig.

use crate::api;
use crate::api::BoundaryServices;
use crate::api::ExternalIpCfg;
#[cfg(any(feature = "test-help", test))]
use crate::api::PhysNet;
use opte::api::*;
use opte::resource::Resource;

#[derive(Debug, Clone)]
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

    /// (S)NAT assignments used for rack-external configuration.
    pub external_ips: Resource<ExternalIpCfg<Ipv4Addr>>,
}

/// The IPv6 configuration of a VPC guest.
#[derive(Debug, Clone)]
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

    /// (S)NAT assignments used for rack-external configuration.
    pub external_ips: Resource<ExternalIpCfg<Ipv6Addr>>,
}

/// The IP configuration of a VPC guest.
#[derive(Debug, Clone)]
pub enum IpCfg {
    Ipv4(Ipv4Cfg),
    Ipv6(Ipv6Cfg),
    DualStack { ipv4: Ipv4Cfg, ipv6: Ipv6Cfg },
}

/// The overall configuration for an OPTE port.
#[derive(Debug, Clone)]
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
    pub fn ipv6(&self) -> &Ipv6Cfg {
        self.ipv6_cfg().expect("expected an IPv6 configuration")
    }

    #[cfg(any(feature = "test-help", test))]
    /// Return the physical address of the guest.
    pub fn phys_addr(&self) -> PhysNet {
        PhysNet { ether: self.guest_mac, ip: self.phys_ip, vni: self.vni }
    }

    // #[cfg(not(any(feature = "test-help", test)))]
    // /// Return the IPv4 SNAT config, if it exists.
    // pub fn snat(&self) -> Option<&SNat4Cfg> {
    //     match &self.ip_cfg {
    //         IpCfg::Ipv4(ipv4) | IpCfg::DualStack { ipv4, .. } => {
    //             ipv4.snat.as_ref()
    //         }

    //         _ => None,
    //     }
    // }

    // #[cfg(any(feature = "test-help", test))]
    // pub fn snat(&self) -> &SNat4Cfg {
    //     match &self.ip_cfg {
    //         IpCfg::Ipv4(ipv4) | IpCfg::DualStack { ipv4, .. } => {
    //             ipv4.external_ips.snat.as_ref().unwrap()
    //         }

    //         _ => panic!("expected an IPv4 SNAT configuration"),
    //     }
    // }

    // #[cfg(any(feature = "test-help", test))]
    // pub fn snat6(&self) -> &SNat6Cfg {
    //     match &self.ip_cfg {
    //         IpCfg::Ipv6(ipv6) | IpCfg::DualStack { ipv6, .. } => {
    //             ipv6.external_ips.snat.as_ref().unwrap()
    //         }

    //         _ => panic!("expected an IPv6 SNAT configuration"),
    //     }
    // }

    // / Return the total number of external ports in the IP configuration,
    // / across both IPv4 and IPv6. If there is no external address configured,
    // / of either family, `None` is returned. If there is such a configuration,
    // / then `Some` is returned, though the contained value may still be zero if
    // / the port range for the relevant address is empty
    // /
    // / Note that this uses the explicit 1-1 NAT external IP address over the
    // / SNAT address, if both are provided.
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
    // pub fn n_external_ports(&self) -> Option<u32> {
    //     // TODO: factor in floating IPs here?
    //     let n_ipv4_ports = match &self.ip_cfg {
    //         IpCfg::Ipv4(ipv4) | IpCfg::DualStack { ipv4, .. } => {
    //             match (ipv4.external_ips.ephemeral_ip, &ipv4.external_ips.snat) {
    //                 (Some(_), _) => Some(u32::from(u16::MAX)),
    //                 (None, Some(snat)) => {
    //                     // Safety: This is an inclusive range of `u16`s, so the
    //                     // length is <= `u16::MAX` and fits in a `u32`.
    //                     let n_ports = u32::try_from(snat.ports.len()).unwrap();
    //                     Some(n_ports)
    //                 }
    //                 (None, None) => None,
    //             }
    //         }
    //         _ => None,
    //     };
    //     let n_ipv6_ports = match &self.ip_cfg {
    //         IpCfg::Ipv6(ipv6) | IpCfg::DualStack { ipv6, .. } => {
    //             match (ipv6.external_ips.ephemeral_ip, &ipv6.external_ips.snat) {
    //                 (Some(_), _) => Some(u32::from(u16::MAX)),
    //                 (None, Some(snat)) => {
    //                     // Safety: This is an inclusive range of `u16`s, so the
    //                     // length is <= `u16::MAX` and fits in a `u32`.
    //                     let n_ports = u32::try_from(snat.ports.len()).unwrap();
    //                     Some(n_ports)
    //                 }
    //                 (None, None) => None,
    //             }
    //         }
    //         _ => None,
    //     };
    //     match (n_ipv4_ports, n_ipv6_ports) {
    //         (None, None) => None,
    //         (v4, v6) => Some(v4.unwrap_or(0) + v6.unwrap_or(0)),
    //     }
    // }
}

impl From<api::VpcCfg> for VpcCfg {
    fn from(value: api::VpcCfg) -> Self {
        Self {
            ip_cfg: value.ip_cfg.into(),
            guest_mac: value.guest_mac,
            gateway_mac: value.gateway_mac,
            vni: value.vni,
            phys_ip: value.phys_ip,
            boundary_services: value.boundary_services,
        }
    }
}

impl From<api::IpCfg> for IpCfg {
    fn from(value: api::IpCfg) -> Self {
        match value {
            api::IpCfg::Ipv4(ipv4) => Self::Ipv4(ipv4.into()),
            api::IpCfg::Ipv6(ipv6) => Self::Ipv6(ipv6.into()),
            api::IpCfg::DualStack { ipv4, ipv6 } => {
                Self::DualStack { ipv4: ipv4.into(), ipv6: ipv6.into() }
            }
        }
    }
}

impl From<api::Ipv4Cfg> for Ipv4Cfg {
    fn from(value: api::Ipv4Cfg) -> Self {
        Self {
            vpc_subnet: value.vpc_subnet,
            private_ip: value.private_ip,
            gateway_ip: value.gateway_ip,
            external_ips: value.external_ips.into(),
        }
    }
}

impl From<api::Ipv6Cfg> for Ipv6Cfg {
    fn from(value: api::Ipv6Cfg) -> Self {
        Self {
            vpc_subnet: value.vpc_subnet,
            private_ip: value.private_ip,
            gateway_ip: value.gateway_ip,
            external_ips: value.external_ips.into(),
        }
    }
}

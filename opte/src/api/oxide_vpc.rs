use super::encap::Vni;
use super::ip::{IpAddr, IpCidr, Ipv4Addr, Ipv4Cidr, Ipv6Addr};
use super::mac::MacAddr;

use illumos_sys_hdrs::datalink_id_t;

use serde::{Deserialize, Serialize};

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::String;
    } else {
        use std::str::FromStr;
        use std::string::String;
    }
}

/// A network destination on the Oxide Rack's physical network (underlay)
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct PhysNet {
    pub ether: MacAddr,
    pub ip: Ipv6Addr,
    pub vni: Vni,
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
#[derive(Clone, Debug, Deserialize, Serialize)]
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

                _ => Err(format!("malformed router target: {}", lower)),
            },
        }
    }
}

/// Xde create ioctl parameter data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateXdeReq {
    pub linkid: datalink_id_t,
    pub xde_devname: String,

    pub private_ip: Ipv4Addr,
    pub private_mac: MacAddr,
    pub gw_mac: MacAddr,
    pub gw_ip: Ipv4Addr,

    pub bsvc_addr: Ipv6Addr,
    pub bsvc_vni: Vni,
    pub src_underlay_addr: Ipv6Addr,
    pub vpc_vni: Vni,

    pub passthrough: bool,
}

/// Xde delete ioctl parameter data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeleteXdeReq {
    pub xde_devname: String,
}

/// Set mapping from VPC IP to physical network destination.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SetVirt2PhysReq {
    pub vip: IpAddr,
    pub phys: PhysNet,
}

/// Add an entry to the IPv4 router.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AddRouterEntryIpv4Req {
    pub port_name: String,
    pub dest: Ipv4Cidr,
    pub target: RouterTarget,
}

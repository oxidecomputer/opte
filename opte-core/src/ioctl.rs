//! The ioctl interface.
use core::convert::TryFrom;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::string::String;
#[cfg(any(feature = "std", test))]
use std::string::String;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::vec::Vec;
#[cfg(any(feature = "std", test))]
use std::vec::Vec;

#[cfg(all(not(feature = "std"), not(test)))]
use illumos_ddi_dki::{c_int, size_t};
#[cfg(any(feature = "std", test))]
use libc::{c_int, size_t};

use serde::{Deserialize, Serialize};

use crate::ether::EtherAddr;
use crate::ip4::Ipv4Addr;
use crate::vpc::VpcSubnet4;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum IoctlCmd {
    ListPorts = 1,     // list all ports
    RegisterPort = 2,     // register new port
    UnregisterPort = 3,     // unregister port
    FwAddRule = 20,     // add firewall rule
    FwRemRule = 21,     // remove firewall rule
    TcpFlowsDump = 30,  // dump TCP flows
    LayerDump = 31,     // dump the specified Layer
    UftDump = 32,       // dump the Unified Flow Table
}

impl TryFrom<c_int> for IoctlCmd {
    type Error = ();

    fn try_from(num: c_int) -> Result<Self, Self::Error> {
        match num {
            1 => Ok(IoctlCmd::ListPorts),
            2 => Ok(IoctlCmd::RegisterPort),
            3 => Ok(IoctlCmd::UnregisterPort),
            20 => Ok(IoctlCmd::FwAddRule),
            21 => Ok(IoctlCmd::FwRemRule),
            30 => Ok(IoctlCmd::TcpFlowsDump),
            31 => Ok(IoctlCmd::LayerDump),
            32 => Ok(IoctlCmd::UftDump),
            _ => Err(()),
        }
    }
}

// We need repr(C) for a stable layout across compilations. This is a
// generic structure for all ioctls, the actual request/response data
// is serialized/deserialized by serde. In the future, if we need this
// to work with non-Rust programs in illumos, we could write an nvlist
// provider that works with serde.
#[derive(Debug)]
#[repr(C)]
pub struct Ioctl {
    pub req_bytes: *const u8,
    pub req_len: size_t,
    pub resp_bytes: *mut u8,
    pub resp_len: size_t,
    pub resp_len_needed: size_t,
}

pub type CmdResp<R> = Result<R, String>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SnatCfg {
    pub public_mac: EtherAddr,
    pub public_ip: Ipv4Addr,
    pub port_start: u16,
    pub port_end: u16,
    pub vpc_sub4: VpcSubnet4,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IpConfig {
    pub private_ip: Ipv4Addr,
    pub gw_mac: EtherAddr,
    pub gw_ip: Ipv4Addr,
    pub snat: Option<SnatCfg>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterPortReq {
    pub link_name: String,
    pub ip_cfg: IpConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UnregisterPortReq {
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListPortsReq {
    pub unused: (),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PortInfo {
    pub name: String,
    pub mac_addr: EtherAddr,
    pub ip4_addr: Ipv4Addr,
    pub in_use: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListPortsResp {
    pub ports: Vec<PortInfo>,
}

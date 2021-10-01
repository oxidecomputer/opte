//! The ioctl interface.
#[cfg(all(not(feature = "std"), not(test)))]
use illumos_ddi_dki::{c_int, size_t};
#[cfg(any(feature = "std", test))]
use libc::{c_int, size_t};

use serde::{Deserialize, Serialize};

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::prelude::v1::*;

#[cfg(any(feature = "std", test))]
use std::prelude::v1::*;

use std::convert::TryFrom;
use std::str::FromStr;

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
pub struct IpConfig {
    pub private_ip: Ipv4Addr,
    pub public_mac: EtherAddr,
    pub public_ip: Ipv4Addr,
    pub port_start: u16,
    pub port_end: u16,
    pub vpc_sub4: VpcSubnet4,
    pub gw_mac: EtherAddr,
    pub gw_ip: Ipv4Addr,
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

impl FromStr for IpConfig {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut private_ip = None;
        let mut public_mac = None;
        let mut public_ip = None;
        let mut port_start = None;
        let mut port_end = None;
        let mut vpc_sub4 = None;
        let mut gw_mac = None;
        let mut gw_ip = None;

        for token in s.split(" ") {
            match token.split_once("=") {
                Some(("private_ip", val)) => {
                    private_ip = Some(val.parse()?);
                }

                Some(("public_mac", val)) => {
                    public_mac = Some(val.parse()?);
                }

                Some(("public_ip", val)) => {
                    public_ip = Some(val.parse()?);
                }

                Some(("port_start", val)) => {
                    port_start = Some(
                        val.parse::<u16>().map_err(|e| e.to_string())?
                    );
                }

                Some(("port_end", val)) => {
                    port_end = Some(
                        val.parse::<u16>().map_err(|e| e.to_string())?
                    );
                }

                Some(("vpc_sub4", val)) => {
                    vpc_sub4 = Some(val.parse()?);
                }

                Some(("gw_mac", val)) => {
                    gw_mac = Some(val.parse()?);
                }

                Some(("gw_ip", val)) => {
                    gw_ip = Some(val.parse()?);
                }

                _ => {
                    return Err(format!("bad token: {}", token));
                }
            };
        }

        if private_ip == None {
            return Err(format!("missing private_ip"));
        }

        if public_mac == None {
            return Err(format!("missing public_mac"));
        }

        if public_ip == None {
            return Err(format!("missing public_ip"));
        }

        if port_start == None {
            return Err(format!("missing port_start"));
        }

        if port_end == None {
            return Err(format!("missing port_end"));
        }

        if vpc_sub4 == None {
            return Err(format!("missing vpc_sub4"));
        }

        if gw_mac == None {
            return Err(format!("missing gw_mac"));
        }

        if gw_ip == None {
            return Err(format!("missing gw_ip"));
        }

        Ok(IpConfig {
            private_ip: private_ip.unwrap(),
            public_mac: public_mac.unwrap(),
            public_ip: public_ip.unwrap(),
            port_start: port_start.unwrap(),
            port_end: port_end.unwrap(),
            vpc_sub4: vpc_sub4.unwrap(),
            gw_mac: gw_mac.unwrap(),
            gw_ip: gw_ip.unwrap(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListPortsReq {
    pub unused: (),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListPortsResp {
    pub ports: Vec<(String, crate::ether::EtherAddr)>,
}

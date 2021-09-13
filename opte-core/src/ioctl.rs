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
use std::result;
use std::str::FromStr;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum IoctlCmd {
    SetVpcSubnet4 = 1, // set the VPC subnet
    SetIpConfig = 2,   // set various IP config
    FwAddRule = 3,     // add firewall rule
    FwRemRule = 4,     // remove firewall rule
    TcpFlowsDump = 6,  // dump TCP flows
    LayerDump = 8,     // dump the specified Layer
    UftDump = 9,       // dump the Unified Flow Table
}

impl TryFrom<c_int> for IoctlCmd {
    type Error = ();

    fn try_from(num: c_int) -> Result<Self, Self::Error> {
        match num {
            1 => Ok(IoctlCmd::SetVpcSubnet4),
            2 => Ok(IoctlCmd::SetIpConfig),
            3 => Ok(IoctlCmd::FwAddRule),
            4 => Ok(IoctlCmd::FwRemRule),
            6 => Ok(IoctlCmd::TcpFlowsDump),
            8 => Ok(IoctlCmd::LayerDump),
            9 => Ok(IoctlCmd::UftDump),
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

// TODO These should really be String. A malicious client could craft
// a byte stream and deserializes to these structures, but doesn't
// conform to the checks make in their constructors.
#[derive(Debug, Deserialize, Serialize)]
pub struct SetIpConfigReq {
    pub private_ip: String,
    pub public_ip: String,
    pub port_start: String,
    pub port_end: String,
    pub vpc_sub4: String,
    pub gw_mac: String,
    pub gw_ip: String,
}

impl FromStr for SetIpConfigReq {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut private_ip = None;
        let mut public_ip = None;
        let mut port_start = None;
        let mut port_end = None;
        let mut vpc_sub4 = None;
        let mut gw_mac = None;
        let mut gw_ip = None;

        for token in s.split(" ") {
            match token.split_once("=") {
                Some(("private_ip", val)) => {
                    private_ip = Some(val.to_string());
                }

                Some(("public_ip", val)) => {
                    public_ip = Some(val.to_string());
                }

                Some(("port_start", val)) => {
                    port_start = Some(val.to_string());
                }

                Some(("port_end", val)) => {
                    port_end = Some(val.to_string());
                }

                Some(("vpc_sub4", val)) => {
                    vpc_sub4 = Some(val.to_string());
                }

                Some(("gw_mac", val)) => {
                    gw_mac = Some(val.to_string());
                }

                Some(("gw_ip", val)) => {
                    gw_ip = Some(val.to_string());
                }

                _ => {
                    return Err(format!("bad token: {}", token));
                }
            };
        }

        if private_ip == None {
            return Err(format!("missing private_ip"));
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

        Ok(SetIpConfigReq {
            private_ip: private_ip.unwrap(),
            public_ip: public_ip.unwrap(),
            port_start: port_start.unwrap(),
            port_end: port_end.unwrap(),
            vpc_sub4: vpc_sub4.unwrap(),
            gw_mac: gw_mac.unwrap(),
            gw_ip: gw_ip.unwrap(),
        })
    }
}

#[derive(Deserialize, Serialize)]
pub struct SetIpConfigResp {
    pub resp: result::Result<(), String>,
}

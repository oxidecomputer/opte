// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use super::encap::Vni;
use super::ip::IpCidr;
use super::mac::MacAddr;
use super::API_VERSION;
use illumos_sys_hdrs::c_int;
use illumos_sys_hdrs::size_t;
use serde::Deserialize;
use serde::Serialize;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::String;
    } else {
        use std::string::String;
    }
}

pub const XDE_IOC: u32 = 0xde777700;
pub const XDE_IOC_OPTE_CMD: i32 = XDE_IOC as i32 | 0x01;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum OpteCmd {
    ListPorts = 1,       // list all ports
    AddFwRule = 20,      // add firewall rule
    RemFwRule = 21,      // remove firewall rule
    SetFwRules = 22,     // set/replace all firewall rules at once
    DumpTcpFlows = 30,   // dump TCP flows
    DumpLayer = 31,      // dump the specified Layer
    DumpUft = 32,        // dump the Unified Flow Table
    ListLayers = 33,     // list the layers on a given port
    ClearUft = 40,       // clear the UFT
    ClearLft = 41,       // clear the given Layer's Flow Table
    SetVirt2Phys = 50,   // set a v2p mapping
    DumpVirt2Phys = 51,  // dump the v2p mappings
    AddRouterEntry = 60, // add a router entry for IP dest
    CreateXde = 70,      // create a new xde device
    DeleteXde = 71,      // delete an xde device
    SetXdeUnderlay = 72, // set xde underlay devices
}

impl TryFrom<c_int> for OpteCmd {
    type Error = ();

    fn try_from(num: c_int) -> Result<Self, Self::Error> {
        match num {
            1 => Ok(Self::ListPorts),
            20 => Ok(Self::AddFwRule),
            21 => Ok(Self::RemFwRule),
            22 => Ok(Self::SetFwRules),
            30 => Ok(Self::DumpTcpFlows),
            31 => Ok(Self::DumpLayer),
            32 => Ok(Self::DumpUft),
            33 => Ok(Self::ListLayers),
            40 => Ok(Self::ClearUft),
            41 => Ok(Self::ClearLft),
            50 => Ok(Self::SetVirt2Phys),
            51 => Ok(Self::DumpVirt2Phys),
            60 => Ok(Self::AddRouterEntry),
            70 => Ok(Self::CreateXde),
            71 => Ok(Self::DeleteXde),
            72 => Ok(Self::SetXdeUnderlay),
            _ => Err(()),
        }
    }
}

/// Indicates that a command response has been written to the response
/// buffer (`resp_bytes`).
pub const OPTE_CMD_RESP_COPY_OUT: u64 = 0x1;

/// The `ioctl(2)` argument passed when sending an `OpteCmd`.
///
/// We need `repr(C)` for a stable layout across compilations. This is
/// a generic structure used to carry the various commands; the
/// command's actual request/response data is serialized/deserialized
/// by serde into the user supplied pointers in
/// `req_bytes`/`resp_bytes`. In the future, if we need this to work
/// with non-Rust programs in illumos, we could write an nvlist
/// provider that works with serde.
#[derive(Debug)]
#[repr(C)]
pub struct OpteCmdIoctl {
    pub api_version: u64,
    pub cmd: OpteCmd,
    pub flags: u64,
    // Reserve some additional bytes in case we need them in the
    // future.
    pub reserved1: u64,
    pub req_bytes: *const u8,
    pub req_len: size_t,
    pub resp_bytes: *mut u8,
    pub resp_len: size_t,
    pub resp_len_actual: size_t,
}

impl OpteCmdIoctl {
    pub fn cmd_err_resp(&self) -> Option<OpteError> {
        if self.has_cmd_resp() {
            // Safety: We know the resp_bytes point to a Vec and that
            // resp_len_actual is within range.
            let resp = unsafe {
                core::slice::from_raw_parts(
                    self.resp_bytes,
                    self.resp_len_actual,
                )
            };

            match postcard::from_bytes(resp) {
                Ok(cmd_err) => Some(cmd_err),
                Err(deser_err) => {
                    Some(OpteError::DeserCmdErr(format!("{}", deser_err)))
                }
            }
        } else {
            None
        }
    }

    fn has_cmd_resp(&self) -> bool {
        (self.flags & OPTE_CMD_RESP_COPY_OUT) != 0
    }
}

impl OpteCmdIoctl {
    /// Is this the expected API version?
    ///
    /// NOTE: This function is compiled twice: once for the userland
    /// client, again for the kernel driver. As long as we remember to
    /// update the `API_VERSION` value when making API changes, this
    /// method will return `false` when user and kernel disagree.
    pub fn check_version(&self) -> bool {
        self.api_version == API_VERSION
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum OpteError {
    BadApiVersion {
        user: u64,
        kernel: u64,
    },
    BadLayerPos {
        layer: String,
        pos: String,
    },
    BadName,
    BadState(String),
    CopyinReq,
    CopyoutResp,
    DeserCmdErr(String),
    DeserCmdReq(String),
    FlowExists(String),
    InvalidRouterEntry {
        dest: IpCidr,
        target: String,
    },
    LayerNotFound(String),
    MacExists {
        port: String,
        vni: Vni,
        mac: MacAddr,
    },
    MaxCapacity(u64),

    /// The OpteCmdIoctl has `req_len == 0` but the specified `cmd`
    /// types expects a request body. This can happen either by
    /// developer error or a hand-rolled, negligent/malicious ioctl.
    NoRequestBody,

    PortCreate(String),
    PortExists(String),
    PortNotFound(String),
    RespTooLarge {
        needed: usize,
        given: usize,
    },
    RuleNotFound(u64),
    SerCmdErr(String),
    SerCmdResp(String),
    System {
        errno: c_int,
        msg: String,
    },
    /// The provided `IpCfg` is not valid, such as an empty port range.
    InvalidIpCfg,
}

impl OpteError {
    /// Convert to an errno value.
    ///
    /// NOTE: In order for `run_cmd_ioctl()` to function correctly
    /// only `RespTooLarge` may use `ENOBUFS`.
    ///
    /// XXX We should probably add the extra code necessary to enforce
    /// this constraint at compile time.
    pub fn to_errno(&self) -> c_int {
        use illumos_sys_hdrs::*;

        match self {
            Self::BadApiVersion { .. } => EPROTO,
            Self::BadLayerPos { .. } => EINVAL,
            Self::BadName => EINVAL,
            Self::BadState(_) => EINVAL,
            Self::CopyinReq => EFAULT,
            Self::CopyoutResp => EFAULT,
            Self::DeserCmdErr(_) => ENOMSG,
            Self::DeserCmdReq(_) => ENOMSG,
            Self::FlowExists(_) => EEXIST,
            Self::InvalidRouterEntry { .. } => EINVAL,
            Self::LayerNotFound(_) => ENOENT,
            Self::MacExists { .. } => EEXIST,
            Self::MaxCapacity(_) => ENFILE,
            Self::NoRequestBody => EINVAL,
            Self::PortCreate(_) => EINVAL,
            Self::PortExists(_) => EEXIST,
            Self::PortNotFound(_) => ENOENT,
            Self::RespTooLarge { .. } => ENOBUFS,
            Self::RuleNotFound(_) => ENOENT,
            Self::SerCmdErr(_) => ENOMSG,
            Self::SerCmdResp(_) => ENOMSG,
            Self::System { errno, .. } => *errno,
            Self::InvalidIpCfg => EINVAL,
        }
    }
}

/// A marker trait indicating a success response type that is returned
/// from a command and may be passed across the ioctl/API boundary.
pub trait CmdOk: core::fmt::Debug + Serialize {}

impl CmdOk for () {}

/// Indicates no meaningful response value on success.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct NoResp {
    pub unused: u64,
}

impl CmdOk for NoResp {}

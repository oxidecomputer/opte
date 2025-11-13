// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

use super::API_VERSION;
use super::RuleId;
use super::TcpState;
use super::encap::Vni;
use super::ip::IpCidr;
use super::mac::MacAddr;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt::Debug;
use illumos_sys_hdrs::c_int;
use illumos_sys_hdrs::size_t;
use serde::Deserialize;
use serde::Serialize;

pub const XDE_IOC: u32 = 0xde777700;
pub const XDE_IOC_OPTE_CMD: i32 = XDE_IOC as i32 | 0x01;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum OpteCmd {
    ListPorts = 1,                // list all ports
    AddFwRule = 20,               // add firewall rule
    RemFwRule = 21,               // remove firewall rule
    SetFwRules = 22,              // set/replace all firewall rules at once
    DumpTcpFlows = 30,            // dump TCP flows
    DumpLayer = 31,               // dump the specified Layer
    DumpUft = 32,                 // dump the Unified Flow Table
    ListLayers = 33,              // list the layers on a given port
    ClearUft = 40,                // clear the UFT
    ClearLft = 41,                // clear the given Layer's Flow Table
    SetVirt2Phys = 50,            // set a v2p mapping
    DumpVirt2Phys = 51,           // dump the v2p mappings
    SetVirt2Boundary = 52,        // set a v2b mapping
    ClearVirt2Boundary = 53,      // clear a v2b mapping
    DumpVirt2Boundary = 54,       // dump the v2b mappings
    ClearVirt2Phys = 55,          // clear a v2p mapping
    AddRouterEntry = 60,          // add a router entry for IP dest
    DelRouterEntry = 61,          // remove a router entry for IP dest
    CreateXde = 70,               // create a new xde device
    DeleteXde = 71,               // delete an xde device
    SetXdeUnderlay = 72,          // set xde underlay devices
    ClearXdeUnderlay = 73,        // clear xde underlay devices
    SetExternalIps = 80,          // set xde external IPs for a port
    AllowCidr = 90,               // allow ip block through gateway tx/rx
    RemoveCidr = 91,              // deny ip block through gateway tx/rx
    SetMcastForwarding = 100,     // set multicast forwarding entries
    ClearMcastForwarding = 101,   // clear multicast forwarding entries
    DumpMcastForwarding = 102,    // dump multicast forwarding table
    McastSubscribe = 103,         // subscribe a port to a multicast group
    McastUnsubscribe = 104,       // unsubscribe a port from a multicast group
    SetMcast2Phys = 105,          // set M2P mapping (group -> underlay mcast)
    ClearMcast2Phys = 106,        // clear M2P mapping
    DumpMcastSubscriptions = 107, // dump multicast subscription table
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
            52 => Ok(Self::SetVirt2Boundary),
            53 => Ok(Self::ClearVirt2Boundary),
            54 => Ok(Self::DumpVirt2Boundary),
            55 => Ok(Self::ClearVirt2Phys),
            60 => Ok(Self::AddRouterEntry),
            61 => Ok(Self::DelRouterEntry),
            70 => Ok(Self::CreateXde),
            71 => Ok(Self::DeleteXde),
            72 => Ok(Self::SetXdeUnderlay),
            73 => Ok(Self::ClearXdeUnderlay),
            80 => Ok(Self::SetExternalIps),
            90 => Ok(Self::AllowCidr),
            91 => Ok(Self::RemoveCidr),
            100 => Ok(Self::SetMcastForwarding),
            101 => Ok(Self::ClearMcastForwarding),
            102 => Ok(Self::DumpMcastForwarding),
            103 => Ok(Self::McastSubscribe),
            104 => Ok(Self::McastUnsubscribe),
            105 => Ok(Self::SetMcast2Phys),
            106 => Ok(Self::ClearMcast2Phys),
            107 => Ok(Self::DumpMcastSubscriptions),
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
                    Some(OpteError::DeserCmdErr(deser_err.to_string()))
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
    InvalidUnderlayMulticast(String),
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
            Self::InvalidUnderlayMulticast(_) => EINVAL,
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
pub trait CmdOk: Debug + Serialize {}

impl CmdOk for () {}

/// Indicates no meaningful response value on success.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct NoResp {
    pub unused: u64,
}

impl CmdOk for NoResp {}

/// Dump various information about a layer, for use in debugging or
/// administrative purposes.
#[derive(Debug, Deserialize, Serialize)]
pub struct DumpLayerReq {
    /// The name of the port whose layer you want to dump.
    pub port_name: String,
    /// The name of the layer to dump.
    pub name: String,
}

/// The response to a [`DumpLayerReq`].
#[derive(Debug, Deserialize, Serialize)]
pub struct DumpLayerResp<Flow> {
    /// The name of the layer.
    pub name: String,
    /// The inbound rules.
    pub rules_in: Vec<RuleTableEntryDump>,
    /// The outbound rules.
    pub rules_out: Vec<RuleTableEntryDump>,
    /// The default inbound action.
    pub default_in: String,
    /// The number of times the default inbound action was matched.
    pub default_in_hits: u64,
    /// The default outbound action.
    pub default_out: String,
    /// The number of times the default outbound action was matched.
    pub default_out_hits: u64,
    /// The inbound flow table.
    pub ft_in: Vec<(Flow, ActionDescEntryDump)>,
    /// The outbound flow table.
    pub ft_out: Vec<(Flow, ActionDescEntryDump)>,
}

impl<T: Debug + Serialize> CmdOk for DumpLayerResp<T> {}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListLayersReq {
    pub port_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LayerDesc {
    /// Name of the layer.
    pub name: String,
    /// Number of rules inbound.
    pub rules_in: usize,
    /// Number of rules outbound.
    pub rules_out: usize,
    /// Default action inbound.
    pub default_in: String,
    /// Default action outbound.
    pub default_out: String,
    /// Number of active flows.
    pub flows: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListLayersResp {
    pub layers: Vec<LayerDesc>,
}

impl CmdOk for ListLayersResp {}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClearUftReq {
    pub port_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClearLftReq {
    pub port_name: String,
    pub layer_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpUftReq {
    pub port_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpUftResp<Flow> {
    pub in_limit: u32,
    pub in_num_flows: u32,
    pub in_flows: Vec<(Flow, UftEntryDump)>,
    pub out_limit: u32,
    pub out_num_flows: u32,
    pub out_flows: Vec<(Flow, UftEntryDump)>,
}

impl<T: Debug + Serialize> CmdOk for DumpUftResp<T> {}

#[derive(Debug, Deserialize, Serialize)]
pub struct UftEntryDump {
    pub hits: u64,
    pub summary: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpTcpFlowsReq {
    pub port_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpTcpFlowsResp<Flow> {
    pub flows: Vec<(Flow, TcpFlowEntryDump<Flow>)>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TcpFlowEntryDump<Flow> {
    pub hits: u64,
    pub inbound_ufid: Option<Flow>,
    pub tcp_state: TcpFlowStateDump,
    pub segs_in: u64,
    pub segs_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TcpFlowStateDump {
    pub tcp_state: TcpState,
    pub guest_seq: Option<u32>,
    pub guest_ack: Option<u32>,
    pub remote_seq: Option<u32>,
    pub remote_ack: Option<u32>,
}

impl<T: Debug + Serialize> CmdOk for DumpTcpFlowsResp<T> {}

#[derive(Debug, Deserialize, Serialize)]
pub struct ActionDescEntryDump {
    pub hits: u64,
    pub summary: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RuleTableEntryDump {
    pub id: RuleId,
    pub hits: u64,
    pub rule: RuleDump,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RuleDump {
    pub priority: u16,
    pub predicates: Vec<String>,
    pub data_predicates: Vec<String>,
    pub action: String,
}

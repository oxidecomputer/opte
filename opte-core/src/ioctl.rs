//! The ioctl interface.
use core::convert::TryFrom;
use core::fmt::Debug;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::String;
        use alloc::vec::Vec;
    } else {
        use std::string::String;
        use std::vec::Vec;
    }
}

use illumos_ddi_dki::{c_int, datalink_id_t, size_t};
use serde::{Deserialize, Serialize};

use crate::ether::EtherAddr;
use crate::flow_table::FlowEntryDump;
use crate::geneve::Vni;
use crate::ip4::Ipv4Addr;
use crate::ip6::Ipv6Addr;
use crate::layer;
use crate::oxide_net::firewall as fw;
use crate::port;
use crate::rule;
use crate::vpc::VpcSubnet4;
use crate::OpteError;

/// The overall version of the API. Anytmie an API is added, removed,
/// or modified, this number should increment. Currently we attach no
/// semantic meaning to the number other than as a means to verify
/// that the user and kernel are compiled for the same API.
///
/// NOTE: Unfortunately this doesn't automatically catch changes to
/// the API and upate itself. We must be vigilant to increment this
/// number when modifying the API.
///
/// NOTE: A u64 is used to give future wiggle room to play bit games
/// if neeeded.
///
/// NOTE: XXX This method of catching version mismatches is currently
/// soft; better ideas are welcome.
pub const API_VERSION: u64 = 1;

pub const XDE_DLD_PREFIX: i32 = (0xde00u32 << 16) as i32;
pub const XDE_DLD_OPTE_CMD: i32 = XDE_DLD_PREFIX | 7777;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum OpteCmd {
    ListPorts = 1,           // list all ports
    AddFwRule = 20,          // add firewall rule
    RemFwRule = 21,          // remove firewall rule
    DumpTcpFlows = 30,       // dump TCP flows
    DumpLayer = 31,          // dump the specified Layer
    DumpUft = 32,            // dump the Unified Flow Table
    ListLayers = 33,         // list the layers on a given port
    SetVirt2Phys = 50,       // set a v2p mapping
    DumpVirt2Phys = 51,      // dump the v2p mappings
    AddRouterEntryIpv4 = 60, // add a router entry for IPv4 dest
    CreateXde = 70,          // create a new xde device
    DeleteXde = 71,          // delete an xde device
    SetXdeUnderlay = 72,     // set xde underlay devices
}

impl TryFrom<c_int> for OpteCmd {
    type Error = ();

    fn try_from(num: c_int) -> Result<Self, Self::Error> {
        match num {
            1 => Ok(Self::ListPorts),
            20 => Ok(Self::AddFwRule),
            21 => Ok(Self::RemFwRule),
            30 => Ok(Self::DumpTcpFlows),
            50 => Ok(Self::SetVirt2Phys),
            51 => Ok(Self::DumpVirt2Phys),
            60 => Ok(Self::AddRouterEntryIpv4),
            70 => Ok(Self::CreateXde),
            71 => Ok(Self::DeleteXde),
            72 => Ok(Self::SetXdeUnderlay),
            _ => Err(()),
        }
    }
}

/// A marker trait indicating a success response type that is returned
/// from a command and may be passed across the ioctl/API boundary.
pub trait CmdOk: core::fmt::Debug + Serialize {}

// Use the unit type to indicate no meaningful response value on success.
impl CmdOk for () {}

/// Dump various information about a `Layer` for use in debugging or
/// administrative purposes.
///
/// * The Layer name.
/// * The inbound and outbound rule tables.
/// * The inbound and outbound flow tables.
///
/// *port_name*: The name of the port.
/// *name*: The name of the [`Layer`] to dump.
#[derive(Debug, Deserialize, Serialize)]
pub struct DumpLayerReq {
    pub port_name: String,
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpLayerResp {
    pub name: String,
    pub rules_in: Vec<(layer::RuleId, rule::RuleDump)>,
    pub rules_out: Vec<(layer::RuleId, rule::RuleDump)>,
    pub ft_in: Vec<(layer::InnerFlowId, FlowEntryDump)>,
    pub ft_out: Vec<(layer::InnerFlowId, FlowEntryDump)>,
}

impl CmdOk for DumpLayerResp {}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListLayersReq {
    pub port_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LayerDesc {
    // Name of the layer.
    pub name: String,
    // Number of rules in/out.
    pub rules_in: usize,
    pub rules_out: usize,
    // Number of flows in/out.
    pub flows_in: u32,
    pub flows_out: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListLayersResp {
    pub layers: Vec<LayerDesc>,
}

impl CmdOk for ListLayersResp {}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpUftReq {
    pub port_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpUftResp {
    pub uft_in_limit: u32,
    pub uft_in_num_flows: u32,
    pub uft_in: Vec<(layer::InnerFlowId, FlowEntryDump)>,
    pub uft_out_limit: u32,
    pub uft_out_num_flows: u32,
    pub uft_out: Vec<(layer::InnerFlowId, FlowEntryDump)>,
}

impl CmdOk for DumpUftResp {}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpTcpFlowsReq {
    pub port_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpTcpFlowsResp {
    pub flows: Vec<(layer::InnerFlowId, FlowEntryDump)>,
}

impl CmdOk for DumpTcpFlowsResp {}

pub fn add_fw_rule(
    port: &port::Port<port::Active>,
    req: &fw::AddFwRuleReq,
) -> Result<(), OpteError> {
    let action = match req.rule.action {
        fw::Action::Allow => {
            port.layer_action(fw::FW_LAYER_NAME, 0).unwrap().clone()
        }

        fw::Action::Deny => rule::Action::Deny,
    };

    let rule = fw::from_fw_rule(req.rule.clone(), action);
    port.add_rule(fw::FW_LAYER_NAME, req.rule.direction, rule)
}

pub fn rem_fw_rule(
    port: &port::Port<port::Active>,
    req: &fw::RemFwRuleReq,
) -> Result<(), OpteError> {
    port.remove_rule(fw::FW_LAYER_NAME, req.dir, req.id)
}

pub fn dump_layer(
    port: &port::Port<port::Active>,
    req: &DumpLayerReq,
) -> Result<DumpLayerResp, OpteError> {
    port.dump_layer(&req.name)
}

pub fn dump_tcp_flows(
    port: &port::Port<port::Active>,
    _req: &DumpTcpFlowsReq,
) -> DumpTcpFlowsResp {
    port.dump_tcp_flows()
}

pub fn dump_uft(
    port: &port::Port<port::Active>,
    _req: &DumpUftReq,
) -> DumpUftResp {
    port.dump_uft()
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
pub struct SnatCfg {
    pub public_mac: EtherAddr,
    pub public_ip: Ipv4Addr,
    pub port_start: u16,
    pub port_end: u16,
    pub vpc_sub4: VpcSubnet4,
}

// XXX An OPTE Port is really both a virtual switch port as well as
// the implementation of a virtual interface; namely the VPC
// interface.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PortCfg {
    pub private_ip: Ipv4Addr,
    pub snat: Option<SnatCfg>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AddPortReq {
    pub link_name: String,
    pub port_cfg: PortCfg,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeletePortReq {
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
impl CmdOk for ListPortsResp {}

/// Xde create ioctl parameter data.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CreateXdeReq {
    pub linkid: datalink_id_t,
    pub xde_devname: String,

    pub private_ip: Ipv4Addr,
    pub private_mac: EtherAddr,
    pub gw_mac: EtherAddr,
    pub gw_ip: Ipv4Addr,

    pub boundary_services_addr: Ipv6Addr,
    pub boundary_services_vni: Vni,
    pub src_underlay_addr: Ipv6Addr,
    pub vpc_vni: Vni,

    pub passthrough: bool,
}

/// Xde delete ioctl parameter data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeleteXdeReq {
    pub xde_devname: String,
}

/// Set the underlay devices used by the xde kernel module
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetXdeUnderlayReq {
    pub u1: String,
    pub u2: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct NoResp {
    pub unused: u64,
}

impl CmdOk for NoResp {}

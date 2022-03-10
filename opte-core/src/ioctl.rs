//! The ioctl interface.
use core::convert::TryFrom;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::string::String;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::sync::Arc;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::vec::Vec;
#[cfg(any(feature = "std", test))]
use std::string::String;
#[cfg(any(feature = "std", test))]
use std::sync::Arc;
#[cfg(any(feature = "std", test))]
use std::vec::Vec;

#[cfg(all(not(feature = "std"), not(test)))]
use illumos_ddi_dki::{c_int, datalink_id_t, size_t};
#[cfg(any(feature = "std", test))]
use illumos_ddi_dki::{c_int, datalink_id_t, size_t};

use serde::{Deserialize, Serialize};

use crate::ether::EtherAddr;
use crate::flow_table::FlowEntryDump;
use crate::geneve::Vni;
use crate::ip4::Ipv4Addr;
use crate::ip6::Ipv6Addr;
use crate::layer;
use crate::oxide_net::{firewall as fw, overlay};
use crate::port;
use crate::rule;
use crate::vpc::VpcSubnet4;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum IoctlCmd {
    ListPorts = 1,           // list all ports
    AddPort = 2,             // add new port
    DeletePort = 3,          // delete a port
    FwAddRule = 20,          // add firewall rule
    FwRemRule = 21,          // remove firewall rule
    DumpTcpFlows = 30,       // dump TCP flows
    DumpLayer = 31,          // dump the specified Layer
    DumpUft = 32,            // dump the Unified Flow Table
    ListLayers = 33,         // list the layers on a given port
    SetOverlay = 40,         // set the overlay config
    XdeCreate = 47,          // create an xde device
    XdeDelete = 48,          // delete an xde device
    SetVirt2Phys = 50,       // set a v2p mapping
    GetVirt2Phys = 51,       // get v2p mapping
    AddRouterEntryIpv4 = 60, // add a router entry for IPv4 dest

    DLDSetVirt2Phys = ((0xde00u32<<16) | 50u32) as isize,
    DLDGetVirt2Phys = ((0xde00u32<<16) | 51u32) as isize,
}

impl TryFrom<c_int> for IoctlCmd {
    type Error = ();

    fn try_from(num: c_int) -> Result<Self, Self::Error> {
        match num {
            1 => Ok(IoctlCmd::ListPorts),
            2 => Ok(IoctlCmd::AddPort),
            3 => Ok(IoctlCmd::DeletePort),
            20 => Ok(IoctlCmd::FwAddRule),
            21 => Ok(IoctlCmd::FwRemRule),
            30 => Ok(IoctlCmd::DumpTcpFlows),
            31 => Ok(IoctlCmd::DumpLayer),
            32 => Ok(IoctlCmd::DumpUft),
            33 => Ok(IoctlCmd::ListLayers),
            40 => Ok(IoctlCmd::SetOverlay),
            47 => Ok(IoctlCmd::XdeCreate),
            48 => Ok(IoctlCmd::XdeDelete),
            50 => Ok(IoctlCmd::SetVirt2Phys),
            51 => Ok(IoctlCmd::GetVirt2Phys),
            60 => Ok(IoctlCmd::AddRouterEntryIpv4),
            _ => Err(()),
        }
    }
}

/// A marker trait indicating a success response type that is returned
/// from a command and may be passed across the ioctl/API boundary.
pub trait CmdOk: core::fmt::Debug + Serialize {}

// Use the unit type to indicate no meaningful response value on success.
impl CmdOk for () {}

/// A marker trait indicating an error response type that is returned
/// from a command and may be passed across the ioctl/API boundary.
pub trait CmdErr: Clone + core::fmt::Debug + Serialize {}

// Use the unit type to indicate that the command is infalliable.
impl CmdErr for () {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum PortError {
    Active,
    Exists,
    Inactive,
    MacOpenFailed(c_int),
    NotFound,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum AddPortError {
    Exists,
    MacOpenFailed(c_int),
}

impl CmdErr for AddPortError {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum DeletePortError {
    InUse,
    NotFound,
}

impl CmdErr for DeletePortError {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum AddFwRuleError {
    FirewallNotEnabled,
    PortError(PortError),
}

impl CmdErr for AddFwRuleError {}

impl From<PortError> for AddFwRuleError {
    fn from(e: PortError) -> Self {
        Self::PortError(e)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RemFwRuleError {
    FirewallNotEnabled,
    PortError(PortError),
    RuleNotFound,
}

impl CmdErr for RemFwRuleError {}

impl From<PortError> for RemFwRuleError {
    fn from(e: PortError) -> Self {
        Self::PortError(e)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum DumpLayerError {
    LayerNotFound,
    PortError(PortError),
}

impl CmdErr for DumpLayerError {}

impl From<PortError> for DumpLayerError {
    fn from(e: PortError) -> Self {
        Self::PortError(e)
    }
}

impl From<port::DumpLayerError> for DumpLayerError {
    fn from(e: port::DumpLayerError) -> Self {
        use port::DumpLayerError as Dle;

        match e {
            Dle::LayerNotFound => Self::LayerNotFound,
        }
    }
}

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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ListLayersError {
    PortError(PortError),
}

impl CmdErr for ListLayersError {}

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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum DumpUftError {
    PortError(PortError),
}

impl CmdErr for DumpUftError {}

impl From<PortError> for DumpUftError {
    fn from(e: PortError) -> Self {
        Self::PortError(e)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpTcpFlowsReq {
    pub port_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpTcpFlowsResp {
    pub flows: Vec<(layer::InnerFlowId, FlowEntryDump)>,
}

impl CmdOk for DumpTcpFlowsResp {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum DumpTcpFlowsError {
    PortError(PortError),
}

impl CmdErr for DumpTcpFlowsError {}

impl From<PortError> for DumpTcpFlowsError {
    fn from(e: PortError) -> Self {
        Self::PortError(e)
    }
}

pub fn add_fw_rule(
    port: &port::Port<port::Active>,
    req: &fw::FwAddRuleReq,
) -> Result<(), AddFwRuleError> {
    let action = match req.rule.action {
        fw::Action::Allow => {
            port.layer_action(fw::FW_LAYER_NAME, 0).unwrap().clone()
        }

        fw::Action::Deny => rule::Action::Deny,
    };

    let rule = fw::from_fw_rule(req.rule.clone(), action);

    let res = port.add_rule(fw::FW_LAYER_NAME, req.rule.direction, rule);

    match res {
        Ok(()) => Ok(()),
        Err(port::AddRuleError::LayerNotFound) => {
            Err(AddFwRuleError::FirewallNotEnabled)
        }
    }
}

pub fn rem_fw_rule(
    port: &port::Port<port::Active>,
    req: &fw::FwRemRuleReq,
) -> Result<(), RemFwRuleError> {
    let res = port.remove_rule(fw::FW_LAYER_NAME, req.dir, req.id);
    match res {
        Ok(()) => Ok(()),
        Err(port::RemoveRuleError::LayerNotFound) => {
            Err(RemFwRuleError::FirewallNotEnabled)
        }
        Err(port::RemoveRuleError::RuleNotFound) => {
            Err(RemFwRuleError::RuleNotFound)
        }
    }
}

pub fn dump_layer(
    port: &port::Port<port::Active>,
    req: &DumpLayerReq,
) -> Result<DumpLayerResp, DumpLayerError> {
    port.dump_layer(&req.name).map_err(DumpLayerError::from)
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

pub fn set_overlay(
    port: &port::Port<port::Inactive>,
    req: &overlay::SetOverlayReq,
    v2p: Arc<overlay::Virt2Phys>,
) {
    overlay::setup(port, &req.cfg, v2p);
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct XdeError {
    code: i32, // standard error code such as EINVAL
}
impl CmdErr for XdeError {}

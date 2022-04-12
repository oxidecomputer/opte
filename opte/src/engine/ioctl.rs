//! The ioctl interface.
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

use serde::{Deserialize, Serialize};

use super::ether::EtherAddr;
use super::flow_table::FlowEntryDump;
use super::layer;
use super::port;
use super::rule;
use super::vpc::VpcSubnet4;
use crate::api::{CmdOk, Ipv4Addr, OpteError};

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
pub struct ClearUftReq {
    pub port_name: String,
}

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

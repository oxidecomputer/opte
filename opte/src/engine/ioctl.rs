// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! The ioctl interface.
//!
//! XXX This stuff needs to be moved to oxide-api.
use super::flow_table::FlowEntryDump;
use super::layer;
use super::packet::InnerFlowId;
use super::port::Port;
use super::rule;
use core::fmt::Debug;
use opte_api::{CmdOk, OpteError};
use serde::{Deserialize, Serialize};

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::String;
        use alloc::vec::Vec;
    } else {
        use std::string::String;
        use std::vec::Vec;
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
    pub ft_in: Vec<(InnerFlowId, FlowEntryDump)>,
    pub ft_out: Vec<(InnerFlowId, FlowEntryDump)>,
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
    // Number of flows.
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
pub struct DumpUftReq {
    pub port_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpUftResp {
    pub uft_in_limit: u32,
    pub uft_in_num_flows: u32,
    pub uft_in: Vec<(InnerFlowId, FlowEntryDump)>,
    pub uft_out_limit: u32,
    pub uft_out_num_flows: u32,
    pub uft_out: Vec<(InnerFlowId, FlowEntryDump)>,
}

impl CmdOk for DumpUftResp {}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpTcpFlowsReq {
    pub port_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpTcpFlowsResp {
    pub flows: Vec<(InnerFlowId, FlowEntryDump)>,
}

impl CmdOk for DumpTcpFlowsResp {}

pub fn dump_layer(
    port: &Port,
    req: &DumpLayerReq,
) -> Result<DumpLayerResp, OpteError> {
    port.dump_layer(&req.name)
}

pub fn dump_tcp_flows(
    port: &Port,
    _req: &DumpTcpFlowsReq,
) -> Result<DumpTcpFlowsResp, OpteError> {
    port.dump_tcp_flows()
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! The ioctl interface.
//!
//! XXX This stuff needs to be moved to oxide-api.
use super::layer::RuleId;
use super::packet::InnerFlowId;
use super::port::Port;
use super::predicate::DataPredicate;
use super::tcp::TcpState;
use core::fmt::Debug;
use opte_api::CmdOk;
use opte_api::OpteError;
use serde::Deserialize;
use serde::Serialize;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::String;
        use alloc::vec::Vec;
    } else {
        use std::string::String;
        use std::vec::Vec;
    }
}

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
pub struct DumpLayerResp {
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
    pub ft_in: Vec<(InnerFlowId, ActionDescEntryDump)>,
    /// The outbound flow table.
    pub ft_out: Vec<(InnerFlowId, ActionDescEntryDump)>,
}

impl CmdOk for DumpLayerResp {}

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
pub struct DumpUftResp {
    pub in_limit: u32,
    pub in_num_flows: u32,
    pub in_flows: Vec<(InnerFlowId, UftEntryDump)>,
    pub out_limit: u32,
    pub out_num_flows: u32,
    pub out_flows: Vec<(InnerFlowId, UftEntryDump)>,
}

impl CmdOk for DumpUftResp {}

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
pub struct DumpTcpFlowsResp {
    pub flows: Vec<(InnerFlowId, TcpFlowEntryDump)>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TcpFlowEntryDump {
    pub hits: u64,
    pub inbound_ufid: Option<InnerFlowId>,
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

impl CmdOk for DumpTcpFlowsResp {}

#[derive(Debug, Deserialize, Serialize)]
pub struct ActionDescEntryDump {
    pub hits: u64,
    pub summary: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RuleTableEntryDump {
    pub id: RuleId,
    pub hits: u64,
    pub rule: super::ioctl::RuleDump,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RuleDump {
    pub priority: u16,
    pub predicates: Vec<String>,
    pub data_predicates: Vec<DataPredicate>,
    pub action: String,
}

pub fn dump_layer(
    port: &Port<impl crate::engine::NetworkImpl>,
    req: &DumpLayerReq,
) -> Result<DumpLayerResp, OpteError> {
    port.dump_layer(&req.name)
}

pub fn dump_tcp_flows(
    port: &Port<impl crate::engine::NetworkImpl>,
    _req: &DumpTcpFlowsReq,
) -> Result<DumpTcpFlowsResp, OpteError> {
    port.dump_tcp_flows()
}

pub fn dump_dhcp_params(
    port: &Port<impl crate::engine::NetworkImpl>,
    _req: &DumpTcpFlowsReq,
) -> Result<DumpTcpFlowsResp, OpteError> {
    port.dump_tcp_flows()
}

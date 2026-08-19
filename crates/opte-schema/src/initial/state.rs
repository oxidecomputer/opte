// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Types illustrating the 'soft state' for an OPTE port: current statistics,
//! active flow state, and fastpath entries.

use super::*;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use postcard_schema::Schema;
use serde::Deserialize;
use serde::Serialize;

/// Runtime state for an OPTE port.
#[derive(Deserialize, Serialize, Schema, Clone)]
pub struct PortState {
    // For compactness all FlowIDs are represented using the same version.
    pub flow_id_version: Version,

    pub current_time: u64,
    pub epoch: u64,
    pub uft_in: BTreeMap<FlowId, FlowEntry<UftEntry>>,
    pub uft_out: BTreeMap<FlowId, FlowEntry<UftEntry>>,
    pub tcp: BTreeMap<FlowId, FlowEntry<Elided>>,
    pub layers: Vec<LayerState>,

    // Flows within a table may share a lifetime, e.g. an LFT pair.
    // `FlowEntry`s hold indexes into this list.
    pub flow_entry_lifetimes: Vec<FlowEntryLifetime>,

    pub stats: Elided,
}

/// Runtime state of a layer within a port.
#[derive(Deserialize, Serialize, Schema, Clone)]
pub struct LayerState {
    pub name: LayerName,
    pub entries: Vec<FlowEntry<LftEntry>>,
    pub stats: Elided,
}

/// A reference from one floe entry to another which is resident in
/// a different layer or flowtable.
#[derive(Deserialize, Serialize, Schema, Clone)]
pub enum FlowEntryRef {
    Uft { idx: u64 },
    Tcp { idx: u64 },
    Lft { layer: LayerName, idx: u64 },
}

/// Tracking for the liveness of a given flow entry.
#[derive(Deserialize, Serialize, Schema, Clone)]
pub struct FlowEntryLifetime {
    pub last_hit_time: u64,
    pub entries: Vec<LftEntry>,
    pub parents: Vec<FlowEntryRef>,
    pub children: Vec<FlowEntryRef>,
}

/// State common to al flowtable entries.
#[derive(Deserialize, Serialize, Schema, Clone)]
pub struct FlowEntry<T> {
    pub flow_id: FlowId,
    pub hits: u64,
    pub lifetime_idx: u64,
    pub state: T,
    pub stats: Elided,
}

/// A fastpath entry for a given flow.
#[derive(Deserialize, Serialize, Schema, Clone)]
pub struct UftEntry {
    pub pair: Option<FlowId>,
    pub transforms: Transforms,
    pub l4_hash: u32,
    pub epoch: u64,
    pub tcp_flow_idx: Option<FlowId>,
}

/// The packet transforms requested by every layer encountered during a
/// slowpath walk, cached as part of a UFT entry.
#[derive(Deserialize, Serialize, Schema, Clone)]
pub struct Transforms {
    pub header: Vec<HdrTransform>,
    pub body: Vec<VersionedData>, // dyn BodyTransform

                                  // The compiled transform should be rebuilt by the recipient during
                                  // deserialisation.
}

/// The set of packet transforms requested by a single layer of a port.
#[derive(Deserialize, Serialize, Schema, Clone)]
pub struct HdrTransform {
    pub layer: LayerName,
    pub outer_ether: Elided,
    pub outer_ip: Elided,
    pub outer_encap: Elided,
    pub inner_ether: Elided,
    pub inner_ip: Elided,
    pub inner_ulp: Elided,
}

/// An in/out pair of packet transforms from a stateful allow action, sharing
/// a single lifetime.
#[derive(Deserialize, Serialize, Schema, Clone)]
pub struct LftEntry {
    pub state_in: FlowEntry<ActionDescEntry>,
    pub state_out: FlowEntry<ActionDescEntry>,
    // TODO XXX: link back to responsible rule? Flowstats RFD needs this.
}

/// How packets matching an `LftEntry` should be processed.
#[derive(Deserialize, Serialize, Schema, Clone)]
pub enum ActionDescEntry {
    NoOp,
    Desc(VersionedData), // dyn ActionDesc
}

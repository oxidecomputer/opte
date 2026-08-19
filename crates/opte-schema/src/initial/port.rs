// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Types illustrating the 'hard state' (port configuration)
//! for an OPTE port.

use super::*;
use alloc::string::String;
use alloc::vec::Vec;
use core::num::NonZeroU32;
use postcard_schema::Schema;
use serde::Deserialize;
use serde::Serialize;

#[derive(Deserialize, Serialize, Schema, Clone)]
pub struct Port {
    pub name: String,
    pub mac_address: [u8; 6],
    pub mtu: Option<NonZeroU32>,
    pub network: VersionedData, // NetworkImpl
    pub layers: Vec<Layer>,
    pub resources: Vec<Resource>,
}

/// Lookup tables and finite resources used during packet processing.
#[derive(Deserialize, Serialize, Schema, Clone)]
pub struct Resource {
    pub name: ResourceName,
    pub data: ResourceData,
}

#[derive(Deserialize, Serialize, Schema, Clone)]
pub enum ResourceData {
    Owned(VersionedData), // dyn Resource
    Global,
}

#[derive(Deserialize, Serialize, Schema, Clone)]
pub struct Layer {
    pub name: LayerName,
    pub rules_in: Vec<Rule>,
    pub rules_out: Vec<Rule>,
    pub default_action_in: DefaultAction,
    pub default_action_out: DefaultAction,
}

#[derive(Deserialize, Serialize, Schema, Clone)]
pub struct Rule {
    pub id: u64,
    pub predicates: Option<Predicates>,
    pub action: Action,
    pub priority: u16,
}

#[derive(Deserialize, Serialize, Schema, Clone)]
pub struct Predicates {
    pub header: Vec<Elided>,
    pub data: Vec<Elided>,
}

#[derive(Deserialize, Serialize, Schema, Clone)]
pub enum Action {
    Allow,
    HandlePacket,
    StatefulAllow,
    Deny,
    Meta(VersionedData),     // dyn MetaAction
    Static(VersionedData),   // dyn StaticAction
    Stateful(VersionedData), // dyn StatefulAction
    Hairpin(VersionedData),  // dyn HairpinAction
}

#[derive(Deserialize, Serialize, Schema, Clone)]
pub enum DefaultAction {
    Allow,
    StatefulAllow,
    Deny,
}

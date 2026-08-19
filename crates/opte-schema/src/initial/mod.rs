// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use alloc::string::String;
use alloc::vec::Vec;
use postcard_schema::Schema;
use serde::Deserialize;
use serde::Serialize;

pub mod port;
pub mod state;

/// Data which must be parsed by the `NetworkImpl` of a port.
///
/// The schema of a `N: NetworkImpl` corresponds to the serialised shape of the
/// types:
/// * `N` itself.
/// * `N::FlowId` (X).
/// * All `dyn Resource` which the port can own (X).
/// * All `dyn MetaAction`.
/// * All `dyn StaticAction`.
/// * All `dyn StatefulAction`.
/// * All `dyn HairpinAction`.
/// * All `dyn BodyTransform`.
/// * All `dyn ActionDesc`.
///
/// Entries marked `(X)` denote concepts not yet properly formalised in OPTE,
/// but which are necessary for state save/resumption.
///
/// The expected flow for parsing out these objects, aside from `N::FlowId` is that:
/// * The `NetworkImpl` parses out the serialised (but inert) form of the object.
/// * Converting this object to a useful action/descriptpr/transform uses this
///   inert state to read out any `ResourceName`s it cares about, take ownership
///   of any finite resources etc. This will be fallible!
#[derive(Deserialize, Serialize, Schema, Clone)]
pub struct VersionedData {
    pub version: Version,
    pub data: Vec<u8>,
}

/// A `(typename ⨉ version)` pair used by a `NetworkImpl` to identify the
/// intended type of a payload.
#[derive(Deserialize, Serialize, Schema, Clone, Hash, Eq, PartialEq)]
pub struct Version {
    pub ty: String,
    pub version: u64,
}

/// Header fields signifying the flow which packets belong to.
///
/// Flow IDs are controlled by the `NetworkImpl`. and must be
/// serialised/deserialised by it at a target version.
#[derive(
    Deserialize,
    Serialize,
    Schema,
    Clone,
    Default,
    Hash,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
)]
pub struct FlowId(pub Vec<u8>);

/// This represents a type without any `NetworkImpl`-controlled data
/// which is not yet sketched out.
#[derive(
    Deserialize,
    Serialize,
    Schema,
    Clone,
    Default,
    Hash,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
)]
pub struct Elided(u8);

#[derive(Deserialize, Serialize, Schema, Clone)]
pub struct ResourceName(pub String);

#[derive(Deserialize, Serialize, Schema, Clone)]
pub struct LayerName(pub String);

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Types for handling flow stats from the ioctl API.

use crate::Direction;
use alloc::vec::Vec;
use serde::Deserialize;
use serde::Serialize;
use uuid::Uuid;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct FlowStat<FlowId> {
    pub partner: FlowId,
    pub dir: Direction,
    pub bases: Vec<Uuid>,
    pub stats: PacketCounter,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
pub struct PacketCounter {
    pub pkts_in: u64,
    pub bytes_in: u64,
    pub pkts_out: u64,
    pub bytes_out: u64,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
pub struct FullCounter {
    pub allow: u64,
    pub deny: u64,
    pub hairpin: u64,
    pub packets: PacketCounter,
}

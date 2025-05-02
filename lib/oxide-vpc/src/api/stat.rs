// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Stat IDs for the Oxide VPC API.

use uuid::Uuid;

pub static FW_DEFAULT_IN: Uuid =
    Uuid::from_fields(0x01de_f00d, 0x7777, 0x0000, &0u64.to_be_bytes());
pub static FW_DEFAULT_OUT: Uuid =
    Uuid::from_fields(0x01de_f00d, 0x7777, 0x0000, &1u64.to_be_bytes());

pub static GATEWAY_NOSPOOF_IN: Uuid =
    Uuid::from_fields(0x01de_f00d, 0x7777, 0x0001, &0u64.to_be_bytes());
pub static GATEWAY_NOSPOOF_OUT: Uuid =
    Uuid::from_fields(0x01de_f00d, 0x7777, 0x0001, &1u64.to_be_bytes());

pub static ROUTER_NOROUTE: Uuid =
    Uuid::from_fields(0x01de_f00d, 0x7777, 0x0002, &0u64.to_be_bytes());

pub static NAT_SNAT_V4: Uuid =
    Uuid::from_fields(0x01de_f00d, 0x7777, 0x0003, &0u64.to_be_bytes());
pub static NAT_SNAT_V6: Uuid =
    Uuid::from_fields(0x01de_f00d, 0x7777, 0x0003, &1u64.to_be_bytes());
pub static NAT_VALID_IGW_V4: Uuid =
    Uuid::from_fields(0x01de_f00d, 0x7777, 0x0003, &2u64.to_be_bytes());
pub static NAT_VALID_IGW_V6: Uuid =
    Uuid::from_fields(0x01de_f00d, 0x7777, 0x0003, &3u64.to_be_bytes());
pub static NAT_NONE: Uuid =
    Uuid::from_fields(0x01de_f00d, 0x7777, 0x0003, &255u64.to_be_bytes());

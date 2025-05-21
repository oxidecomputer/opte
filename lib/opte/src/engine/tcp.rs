// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! TCP headers.

use super::flow_table::Ttl;
use serde::Deserialize;
use serde::Serialize;

pub const TCP_HDR_OFFSET_MASK: u8 = 0xF0;
pub const TCP_HDR_OFFSET_SHIFT: u8 = 4;

pub const TCP_PORT_RDP: u16 = 3389;
pub const TCP_PORT_SSH: u16 = 22;

/// The duration after which a connection in TIME-WAIT should be
/// considered free for either side to reuse.
///
/// This value is chosen by Windows and MacOS, which is larger
/// than Linux's default 60s. Allowances for tuned servers and/or
/// more aggressive reuse via RFCs 1323/7323 and/or 6191 are made in
/// `tcp_state`.
pub const TIME_WAIT_EXPIRE_SECS: u64 = 120;
/// The duration after which otherwise healthy TCP flows should be pruned.
///
/// Currently, this is tuned to be 2.5 hours: higher than the default behaviour
/// for SO_KEEPALIVE on linux/illumos. Each will wait 2 hours before sending a
/// keepalive, when interval + probe count will result in a timeout after
/// 8mins (illumos) / 11mins (linux).
pub const KEEPALIVE_EXPIRE_SECS: u64 = 8_000;
pub const TIME_WAIT_EXPIRE_TTL: Ttl = Ttl::new_seconds(TIME_WAIT_EXPIRE_SECS);
pub const KEEPALIVE_EXPIRE_TTL: Ttl = Ttl::new_seconds(KEEPALIVE_EXPIRE_SECS);

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct TcpPush {
    pub src: u16,
    pub dst: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TcpMod {
    src: Option<u16>,
    dst: Option<u16>,
}

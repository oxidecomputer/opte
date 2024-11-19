// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! UDP headers.

use serde::Deserialize;
use serde::Serialize;

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
pub struct UdpPush {
    pub src: u16,
    pub dst: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UdpMod {
    src: Option<u16>,
    dst: Option<u16>,
}

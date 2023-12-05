// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

#![no_std]
#![deny(unreachable_patterns)]
#![deny(unused_must_use)]

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[macro_use]
extern crate alloc;

use alloc::string::String;
use core::fmt;
use core::fmt::Display;
use serde::Deserialize;
use serde::Serialize;

pub mod cmd;
pub mod dhcpv6;
pub mod dns;
pub mod encap;
pub mod ip;
pub mod mac;
pub mod ndp;
pub mod ulp;

pub use cmd::*;
pub use dhcpv6::*;
pub use dns::*;
pub use encap::*;
pub use ip::*;
pub use mac::*;
pub use ndp::*;
pub use ulp::*;

/// The overall version of the API. Anytime an API is added, removed,
/// or modified, this number should increment. Currently we attach no
/// semantic meaning to the number other than as a means to verify
/// that the user and kernel are compiled for the same API. A u64 is
/// used to give future wiggle room to play bit games if neeeded.
///
/// We rely on CI and the check-api-version.sh script to verify that
/// this number is incremented anytime the oxide-api code changes.
pub const API_VERSION: u64 = 27;

/// Major version of the OPTE package.
pub const MAJOR_VERSION: u64 = 0;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Direction {
    In = 1,
    Out = 2,
}

impl core::str::FromStr for Direction {
    type Err = String;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "in" => Ok(Direction::In),
            "out" => Ok(Direction::Out),
            _ => Err(format!("invalid direction: {}", s)),
        }
    }
}

impl Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let dirstr = match self {
            Direction::In => "IN",
            Direction::Out => "OUT",
        };

        write!(f, "{}", dirstr)
    }
}

/// Set the underlay devices used by the xde kernel module
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetXdeUnderlayReq {
    pub u1: String,
    pub u2: String,
}

pub mod cmd;
pub mod encap;
pub mod ip;
pub mod mac;
pub mod ulp;

pub use cmd::*;
pub use encap::*;
pub use ip::*;
pub use mac::*;
pub use ulp::*;

/// The overall version of the API. Anytmie an API is added, removed,
/// or modified, this number should increment. Currently we attach no
/// semantic meaning to the number other than as a means to verify
/// that the user and kernel are compiled for the same API.
///
/// NOTE: Unfortunately this doesn't automatically catch changes to
/// the API and upate itself. We must be vigilant to increment this
/// number when modifying the API.
///
/// NOTE: A u64 is used to give future wiggle room to play bit games
/// if neeeded.
///
/// NOTE: XXX This method of catching version mismatches is currently
/// soft; better ideas are welcome.
pub const API_VERSION: u64 = 3;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::String;
    } else {
        use std::string::String;
    }
}

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Direction {
    In,
    Out,
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

/// Set the underlay devices used by the xde kernel module
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetXdeUnderlayReq {
    pub u1: String,
    pub u2: String,
}

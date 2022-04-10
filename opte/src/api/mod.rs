pub mod cmd;
pub mod encap;
pub mod ip;
pub mod mac;
pub mod oxide_vpc;

pub use cmd::*;
pub use encap::*;
pub use ip::*;
pub use mac::*;
pub use oxide_vpc::*;

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

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Direction {
    In,
    Out,
}

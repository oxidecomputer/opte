// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Types used to describe aspects common to all OPTE ports, regardless
//! of the inner `NetworkImpl` in use.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "initial/mod.rs"]
pub mod v1;

#[cfg(test)]
mod tests {
    use super::*;
    use postcard_schema::Schema;

    #[test]
    fn examine_schema() {
        eprintln!(
            "{}",
            serde_json::to_string_pretty(v1::port::Port::SCHEMA).unwrap()
        );
        eprintln!(
            "{}",
            serde_json::to_string_pretty(v1::state::PortState::SCHEMA).unwrap()
        );
    }
}

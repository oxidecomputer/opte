// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use alloc::string::String;
use alloc::string::ToString;
use core::fmt;
use core::fmt::Debug;
use core::fmt::Display;
use core::str::FromStr;
use serde::Deserialize;
use serde::Serialize;

pub use ingot::geneve::Vni;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn good_vni() {
        assert!(Vni::new(0u32).is_ok());
        assert!(Vni::new(11u8).is_ok());
        assert!(Vni::new((1u32 << 24) - 1).is_ok());
    }

    #[test]
    fn bad_vni() {
        assert!(Vni::new(2u32.pow(24)).is_err());
        assert!(Vni::new(2u32.pow(30)).is_err());
    }

    #[test]
    fn vni_round_trip() {
        let vni = Vni::new(7777u32).unwrap();
        assert_eq!([0x00, 0x1E, 0x61], vni.bytes());
        assert_eq!(7777, u32::from(vni));
    }
}

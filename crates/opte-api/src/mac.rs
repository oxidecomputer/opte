// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

use alloc::str::FromStr;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Debug;
use core::fmt::Display;
use core::ops::Deref;
use ingot::types::NetworkRepr;
use serde::Deserialize;
use serde::Serialize;

/// A MAC address.
#[derive(
    Clone,
    Copy,
    Default,
    Deserialize,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    Hash,
)]
pub struct MacAddr {
    inner: [u8; 6],
}

impl NetworkRepr<[u8; 6]> for MacAddr {
    fn to_network(self) -> [u8; 6] {
        self.inner
    }

    fn from_network(val: [u8; 6]) -> Self {
        Self { inner: val }
    }
}

impl MacAddr {
    pub const BROADCAST: Self = Self { inner: [0xFF; 6] };
    pub const ZERO: Self = Self { inner: [0x00; 6] };

    /// Return the bytes of the MAC address.
    #[inline]
    pub fn bytes(&self) -> [u8; 6] {
        self.inner
    }

    pub const fn from_const(bytes: [u8; 6]) -> Self {
        Self { inner: bytes }
    }
}

impl From<MacAddr> for smoltcp::wire::EthernetAddress {
    fn from(addr: MacAddr) -> Self {
        Self(addr.bytes())
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(bytes: [u8; 6]) -> Self {
        Self { inner: bytes }
    }
}

impl From<&[u8; 6]> for MacAddr {
    fn from(bytes: &[u8; 6]) -> Self {
        Self { inner: *bytes }
    }
}

impl AsRef<[u8]> for MacAddr {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl Deref for MacAddr {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl FromStr for MacAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let octets: Vec<u8> = s
            .split(':')
            .map(|s| {
                u8::from_str_radix(s, 16).map_err(|_| format!("bad octet: {s}"))
            })
            .collect::<Result<Vec<u8>, _>>()?;

        if octets.len() != 6 {
            return Err(format!("incorrect number of bytes: {}", octets.len()));
        }

        // At the time of writing there is no TryFrom impl for Vec to
        // array in the alloc create. Honestly this looks a bit
        // cleaner anyways.
        let bytes =
            [octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]];

        Ok(MacAddr { inner: bytes })
    }
}

impl Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.inner[0],
            self.inner[1],
            self.inner[2],
            self.inner[3],
            self.inner[4],
            self.inner[5]
        )
    }
}

// There's no reason to view the MAC address as its raw array, so just
// present it in a human-friendly manner.
impl Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MacAddr {{ inner: {self} }}")
    }
}

use core::fmt::{self, Display};
use serde::{Deserialize, Serialize};

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
    } else {
        use std::result;
        use std::str::FromStr;
        use std::string::String;
        use std::vec::Vec;
    }
}

/// A MAC address.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct MacAddr {
    inner: [u8; 6],
}

impl From<[u8; 6]> for MacAddr {
    fn from(bytes: [u8; 6]) -> Self {
        Self { inner: bytes }
    }
}

impl From<&[u8; 6]> for MacAddr {
    fn from(bytes: &[u8; 6]) -> Self {
        Self { inner: bytes.clone() }
    }
}

#[cfg(any(feature = "std", test))]
impl FromStr for MacAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let octets: Vec<u8> = s
            .split(":")
            .map(|s| {
                u8::from_str_radix(s, 16).or(Err(format!("bad octet: {}", s)))
            })
            .collect::<result::Result<Vec<u8>, _>>()?;

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

impl MacAddr {
    pub const BROADCAST: Self = Self { inner: [0xFF; 6] };
    pub const ZERO: Self = Self { inner: [0x00; 6] };

    /// Return the bytes of the MAC address.
    pub fn bytes(&self) -> [u8; 6] {
        self.inner
    }
}

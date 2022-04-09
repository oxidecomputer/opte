use core::fmt::{self, Display};

use serde::{Deserialize, Serialize};

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::String;
    } else {
        use std::str::FromStr;
        use std::string::{String, ToString};
    }
}

/// A Geneve Virtual Network Identifier (VNI).
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct Vni {
    // A VNI is 24-bit. By storing it this way we don't have to check
    // the value on the opte-core side to know if it's a valid VNI, we
    // just decode the bytes.
    //
    // The bytes are in network order.
    inner: [u8; 3],
}

impl From<Vni> for u32 {
    fn from(vni: Vni) -> u32 {
        let bytes = vni.inner;
        u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]])
    }
}

#[cfg(any(feature = "std", test))]
impl FromStr for Vni {
    type Err = String;

    fn from_str(val: &str) -> Result<Self, Self::Err> {
        let n = val.parse::<u32>().map_err(|e| e.to_string())?;
        Self::new(n)
    }
}

impl Display for Vni {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", u32::from(*self))
    }
}

const VNI_MAX: u32 = 0x00_FF_FF_FF;

impl Vni {
    /// Return the bytes that represent this VNI. The bytes are in
    /// network order.
    pub fn bytes(&self) -> [u8; 3] {
        return self.inner;
    }

    /// Attempt to create a new VNI from any value which can be
    /// converted to a `u32`.
    ///
    /// # Errors
    ///
    /// Returns an error when the value exceeds the 24-bit maximum.
    pub fn new<N: Into<u32>>(val: N) -> Result<Vni, String> {
        let val = val.into();
        if val > VNI_MAX {
            return Err(format!("VNI value exceeds maximum: {}", val));
        }

        let be_bytes = val.to_be_bytes();
        Ok(Vni { inner: [be_bytes[1], be_bytes[2], be_bytes[3]] })
    }
}

#[test]
fn vni_round_trip() {
    let vni = Vni::new(7777u32).unwrap();
    assert_eq!([0x00, 0x1E, 0x61], vni.inner);
    assert_eq!(7777, u32::from(vni));
}

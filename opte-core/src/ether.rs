#[cfg(all(not(feature = "std"), not(test)))]
use alloc::prelude::v1::*;

#[cfg(any(feature = "std", test))]
use std::prelude::v1::*;

use std::fmt::{self, Display};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

extern crate zerocopy;
use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

use crate::headers::{
    HeaderAction, HeaderActionModify, ModActionArg, PushActionArg,
};
use crate::packet::{PacketRead, ReadErr, WriteErr};

pub const ETHER_TYPE_IPV4: u16 = 0x0800;
pub const ETHER_TYPE_ARP: u16 = 0x0806;
pub const ETHER_TYPE_IPV6: u16 = 0x86DD;

pub const ETHER_ADDR_LEN: usize = 6;

pub const ETHER_HDR_SZ: usize = std::mem::size_of::<EtherHdrRaw>();

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct EtherAddr {
    bytes: [u8; ETHER_ADDR_LEN],
}

impl EtherAddr {
    pub fn to_bytes(self) -> [u8; ETHER_ADDR_LEN] {
        self.bytes
    }
}

impl From<[u8; ETHER_ADDR_LEN]> for EtherAddr {
    fn from(bytes: [u8; ETHER_ADDR_LEN]) -> Self {
        EtherAddr { bytes }
    }
}

impl FromStr for EtherAddr {
    type Err = String;

    fn from_str(val: &str) -> Result<Self, Self::Err> {
        let octets: Vec<u8> = val
            .split(":")
            .map(|s| {
                u8::from_str_radix(s, 16).or(Err(format!("bad octet: {}", s)))
            })
            .collect::<std::result::Result<Vec<u8>, _>>()?;

        if octets.len() != 6 {
            return Err(format!("incorrect number of bytes: {}", octets.len()));
        }

        // At the time of writing there is no TryFrom impl for Vec to
        // array in the alloc create. Honestly this looks a bit
        // cleaner anyways.
        let bytes =
            [octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]];

        Ok(EtherAddr::from(bytes))
    }
}

impl Display for EtherAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[3],
            self.bytes[4],
            self.bytes[5]
        )
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct EtherMeta {
    pub dst: EtherAddr,
    pub src: EtherAddr,
    pub ether_type: u16,
}

impl From<&LayoutVerified<&[u8], EtherHdrRaw>> for EtherMeta {
    fn from(raw: &LayoutVerified<&[u8], EtherHdrRaw>) -> Self {
        EtherMeta {
            src: EtherAddr::from(raw.src),
            dst: EtherAddr::from(raw.dst),
            ether_type: u16::from_be_bytes(raw.ether_type),
        }
    }
}

impl EtherMeta {
    pub fn modify(
        src: Option<EtherAddr>,
        dst: Option<EtherAddr>,
    ) -> HeaderAction<EtherMeta, EtherMetaOpt> {
        HeaderAction::Modify(EtherMetaOpt { src, dst })
    }
}

impl HeaderActionModify<EtherMetaOpt> for EtherMeta {
    fn run_modify(&mut self, spec: &EtherMetaOpt) {
        if spec.src.is_some() {
            self.src = spec.src.unwrap()
        }

        if spec.dst.is_some() {
            self.dst = spec.dst.unwrap()
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EtherMetaOpt {
    src: Option<EtherAddr>,
    dst: Option<EtherAddr>,
}

impl PushActionArg for EtherMeta {}
impl ModActionArg for EtherMetaOpt {}

/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, Debug, FromBytes, AsBytes, Unaligned)]
pub struct EtherHdrRaw {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ether_type: [u8; 2],
}

impl EtherHdrRaw {
    pub fn parse<R: PacketRead>(
        rdr: &mut R,
    ) -> Result<LayoutVerified<&[u8], Self>, ReadErr> {
        let slice = rdr.slice(std::mem::size_of::<Self>())?;
        let hdr = match LayoutVerified::new(slice) {
            Some(bytes) => bytes,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }

    pub fn parse_mut(
        dst: &mut [u8],
    ) -> Result<LayoutVerified<&mut [u8], Self>, WriteErr> {
        let hdr = match LayoutVerified::new(dst) {
            Some(bytes) => bytes,
            None => return Err(WriteErr::BadLayout),
        };
        Ok(hdr)
    }
}

impl From<&EtherMeta> for EtherHdrRaw {
    fn from(meta: &EtherMeta) -> Self {
        EtherHdrRaw {
            dst: meta.dst.to_bytes(),
            src: meta.src.to_bytes(),
            ether_type: meta.ether_type.to_be_bytes(),
        }
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Ethernet frames.

use super::headers::ModifyAction;
use super::headers::PushAction;
use super::headers::RawHeader;
use super::packet::PacketReadMut;
use super::packet::ReadErr;
use core::fmt;
use core::fmt::Debug;
use core::fmt::Display;
use core::result;
use core::str::FromStr;
use opte_api::MacAddr;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::LayoutVerified;
use zerocopy::Unaligned;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::String;
        use alloc::vec::Vec;
    } else {
        use std::string::String;
        use std::vec::Vec;
    }
}

pub const ETHER_TYPE_ETHER: u16 = 0x6558;
pub const ETHER_TYPE_IPV4: u16 = 0x0800;
pub const ETHER_TYPE_ARP: u16 = 0x0806;
pub const ETHER_TYPE_IPV6: u16 = 0x86DD;

pub const ETHER_ADDR_LEN: usize = 6;

#[repr(u16)]
#[derive(
    Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum EtherType {
    Ether,
    Ipv4,
    Arp,
    Ipv6,
    Unknown(u16),
}

impl From<u16> for EtherType {
    fn from(raw: u16) -> Self {
        match raw {
            ETHER_TYPE_ETHER => Self::Ether,
            ETHER_TYPE_ARP => Self::Arp,
            ETHER_TYPE_IPV4 => Self::Ipv4,
            ETHER_TYPE_IPV6 => Self::Ipv6,
            _ => Self::Unknown(raw),
        }
    }
}

impl From<EtherType> for u16 {
    fn from(et: EtherType) -> Self {
        use EtherType::*;

        match et {
            Ether => ETHER_TYPE_ETHER,
            Ipv4 => ETHER_TYPE_IPV4,
            Arp => ETHER_TYPE_ARP,
            Ipv6 => ETHER_TYPE_IPV6,
            Unknown(val) => val,
        }
    }
}

impl Default for EtherType {
    fn default() -> Self {
        EtherType::Unknown(0x7777)
    }
}

impl Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:04X}", u16::from(*self))
    }
}

/// We are never really interested in internal representation of
/// [`EtherType`].
impl Debug for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

#[derive(
    Clone, Copy, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct EtherAddr {
    bytes: [u8; ETHER_ADDR_LEN],
}

impl EtherAddr {
    pub fn to_bytes(self) -> [u8; ETHER_ADDR_LEN] {
        self.bytes
    }
    pub fn zero() -> Self {
        EtherAddr { bytes: [0u8; ETHER_ADDR_LEN] }
    }
    pub fn as_ptr(&self) -> *const u8 {
        &self.bytes as *const u8
    }
}

impl From<MacAddr> for EtherAddr {
    fn from(mac: MacAddr) -> Self {
        Self { bytes: mac.bytes() }
    }
}

impl From<EtherAddr> for MacAddr {
    fn from(ether: EtherAddr) -> Self {
        MacAddr::from(ether.bytes)
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
            .split(':')
            .map(|s| {
                u8::from_str_radix(s, 16)
                    .map_err(|_| format!("bad octet: {}", s))
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

        Ok(EtherAddr::from(bytes))
    }
}

impl From<EtherAddr> for smoltcp::wire::EthernetAddress {
    fn from(addr: EtherAddr) -> Self {
        Self(addr.bytes)
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

/// We are never really interested in internal representation of
/// EtherAddr.
impl Debug for EtherAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

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
pub struct EtherMeta {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ether_type: EtherType,
}

impl PushAction<EtherMeta> for EtherMeta {
    fn push(&self) -> EtherMeta {
        EtherMeta { dst: self.dst, src: self.src, ether_type: self.ether_type }
    }
}

impl<'a> From<&EtherHdr<'a>> for EtherMeta {
    fn from(eth: &EtherHdr) -> Self {
        EtherMeta {
            src: eth.src(),
            dst: eth.dst(),
            ether_type: eth.ether_type(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct EtherMod {
    pub src: Option<MacAddr>,
    pub dst: Option<MacAddr>,
}

impl ModifyAction<EtherMeta> for EtherMod {
    fn modify(&self, meta: &mut EtherMeta) {
        if let Some(src) = self.src {
            meta.src = src;
        }

        if let Some(dst) = self.dst {
            meta.dst = dst
        }
    }
}

impl EtherMeta {
    #[inline]
    pub fn emit(&self, dst: &mut [u8]) {
        debug_assert_eq!(dst.len(), EtherHdrRaw::SIZE);
        let mut raw = EtherHdrRaw::new_mut(dst).unwrap();
        raw.write(EtherHdrRaw::from(self));
    }

    #[inline]
    pub fn hdr_len(&self) -> usize {
        EtherHdr::SIZE
    }
}

#[derive(Debug)]
pub struct EtherHdr<'a> {
    bytes: LayoutVerified<&'a mut [u8], EtherHdrRaw>,
}

impl<'a> EtherHdr<'a> {
    // For the moment, this type is for non-VLAN ethernet headers
    // only.
    pub const SIZE: usize = EtherHdrRaw::SIZE;

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.bytes()
    }

    pub fn ether_type(&self) -> EtherType {
        EtherType::from(u16::from_be_bytes(self.bytes.ether_type))
    }

    pub fn hdr_len(&self) -> usize {
        Self::SIZE
    }

    pub fn src(&self) -> MacAddr {
        MacAddr::from(self.bytes.src)
    }

    pub fn dst(&self) -> MacAddr {
        MacAddr::from(self.bytes.dst)
    }

    pub fn set_dst(&mut self, dst: MacAddr) {
        self.bytes.dst = dst.bytes();
    }

    pub fn parse<'b, R>(rdr: &'b mut R) -> Result<Self, EtherHdrError>
    where
        R: PacketReadMut<'a>,
    {
        let src = rdr.slice_mut(EtherHdrRaw::SIZE)?;
        Ok(Self { bytes: EtherHdrRaw::new_mut(src)? })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum EtherHdrError {
    ReadError { error: ReadErr },
    UnsupportedEtherType { ether_type: u16 },
}

impl From<ReadErr> for EtherHdrError {
    fn from(error: ReadErr) -> Self {
        EtherHdrError::ReadError { error }
    }
}

impl Display for EtherHdrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::UnsupportedEtherType { ether_type } => {
                write!(f, "Unsupported Ether Type: 0x{:04X}", ether_type)
            }

            Self::ReadError { error } => {
                write!(f, "read error: {:?}", error)
            }
        }
    }
}

impl Debug for EtherHdrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl From<&EtherMeta> for EtherHdrRaw {
    fn from(meta: &EtherMeta) -> Self {
        Self {
            dst: meta.dst.bytes(),
            src: meta.src.bytes(),
            ether_type: u16::from(meta.ether_type).to_be_bytes(),
        }
    }
}

/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, Debug, Default, FromBytes, AsBytes, Unaligned)]
pub struct EtherHdrRaw {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ether_type: [u8; 2],
}

impl<'a> RawHeader<'a> for EtherHdrRaw {
    #[inline]
    fn new_mut(
        src: &mut [u8],
    ) -> Result<LayoutVerified<&mut [u8], Self>, ReadErr> {
        debug_assert_eq!(src.len(), Self::SIZE);
        let hdr = match LayoutVerified::new(src) {
            Some(hdr) => hdr,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::engine::packet::Packet;

    #[test]
    fn emit() {
        let eth = EtherMeta {
            dst: MacAddr::from([0xA8, 0x40, 0x25, 0xFF, 0x77, 0x77]),
            src: MacAddr::from([0xA8, 0x40, 0x25, 0xFA, 0xFA, 0x37]),
            ether_type: EtherType::Ipv4,
        };

        // Verify bytes are written and segment length is correct.
        let mut pkt = Packet::alloc_and_expand(14);
        let mut wtr = pkt.seg0_wtr();
        eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
        assert_eq!(pkt.len(), 14);
        #[rustfmt::skip]
        let expected_bytes = vec![
            // destination
            0xA8, 0x40, 0x25, 0xFF, 0x77, 0x77,
            // source
            0xA8, 0x40, 0x25, 0xFA, 0xFA, 0x37,
            // ether type
            0x08, 0x00,
        ];
        assert_eq!(&expected_bytes, pkt.seg_bytes(0));

        // Verify error when the mblk is not large enough.
        let mut pkt = Packet::alloc_and_expand(10);
        let mut wtr = pkt.seg0_wtr();
        assert!(wtr.slice_mut(EtherHdr::SIZE).is_err());
    }
}

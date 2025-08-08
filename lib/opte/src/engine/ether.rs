// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Ethernet frames.

use super::headers::HasInnerCksum;
use super::headers::HeaderActionError;
use super::headers::HeaderActionModify;
use super::headers::ModifyAction;
use super::headers::PushAction;
use super::headers::Valid;
use super::headers::Validate;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Debug;
use core::fmt::Display;
use core::result;
use core::str::FromStr;
use ingot::Ingot;
use ingot::ethernet::Ethertype;
use ingot::types::Header;
use ingot::types::HeaderLen;
use ingot::types::InlineHeader;
use opte_api::MacAddr;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::ByteSlice;
use zerocopy::ByteSliceMut;

pub const ETHER_TYPE_ETHER: u16 = 0x6558;
pub const ETHER_TYPE_IPV4: u16 = 0x0800;
pub const ETHER_TYPE_ARP: u16 = 0x0806;
pub const ETHER_TYPE_IPV6: u16 = 0x86DD;

pub const ETHER_ADDR_LEN: usize = 6;

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct Ethernet {
    #[ingot(is = "[u8; 6]")]
    pub destination: MacAddr,
    #[ingot(is = "[u8; 6]")]
    pub source: MacAddr,
    #[ingot(is = "u16be", next_layer)]
    pub ethertype: Ethertype,
}

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
        write!(f, "{self}")
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
                u8::from_str_radix(s, 16).map_err(|_| format!("bad octet: {s}"))
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
        write!(f, "{self}")
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
    fn push(value: &Valid<Self>) -> EtherMeta {
        **value
    }
}

impl Validate for EtherMeta {
    fn validate(&self) -> Result<(), super::headers::ValidateErr> {
        Ok(())
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
    pub fn hdr_len(&self) -> usize {
        Ethernet::MINIMUM_LENGTH
    }
}

impl<T: ByteSliceMut> HeaderActionModify<EtherMod> for EthernetPacket<T> {
    #[inline]
    fn run_modify(
        &mut self,
        mod_spec: &EtherMod,
    ) -> Result<(), HeaderActionError> {
        if let Some(src) = mod_spec.src {
            self.set_source(src);
        }
        if let Some(dst) = mod_spec.dst {
            self.set_destination(dst);
        }

        Ok(())
    }
}

impl<T: ByteSliceMut> HeaderActionModify<EtherMod>
    for InlineHeader<Ethernet, ValidEthernet<T>>
{
    #[inline]
    fn run_modify(
        &mut self,
        mod_spec: &EtherMod,
    ) -> Result<(), HeaderActionError> {
        match self {
            InlineHeader::Repr(a) => {
                if let Some(src) = mod_spec.src {
                    a.set_source(src);
                }
                if let Some(dst) = mod_spec.dst {
                    a.set_destination(dst);
                }
            }
            InlineHeader::Raw(a) => {
                if let Some(src) = mod_spec.src {
                    a.set_source(src);
                }
                if let Some(dst) = mod_spec.dst {
                    a.set_destination(dst);
                }
            }
        }

        Ok(())
    }
}

impl<T: ByteSlice> HasInnerCksum for InlineHeader<Ethernet, ValidEthernet<T>> {
    const HAS_CKSUM: bool = false;
}

impl<T: ByteSlice> HasInnerCksum for EthernetPacket<T> {
    const HAS_CKSUM: bool = false;
}

impl<T: ByteSlice> From<EtherMeta> for Header<Ethernet, ValidEthernet<T>> {
    #[inline]
    fn from(value: EtherMeta) -> Self {
        Header::Repr(
            Ethernet {
                destination: value.dst,
                source: value.src,
                ethertype: Ethertype(u16::from(value.ether_type)),
            }
            .into(),
        )
    }
}

impl<T: ByteSlice> From<EtherMeta>
    for InlineHeader<Ethernet, ValidEthernet<T>>
{
    #[inline]
    fn from(value: EtherMeta) -> Self {
        InlineHeader::Repr(Ethernet {
            destination: value.dst,
            source: value.src,
            ethertype: Ethertype(u16::from(value.ether_type)),
        })
    }
}

impl<T: ByteSlice> PushAction<InlineHeader<Ethernet, ValidEthernet<T>>>
    for EtherMeta
{
    #[inline]
    fn push(value: &Valid<Self>) -> InlineHeader<Ethernet, ValidEthernet<T>> {
        InlineHeader::Repr(Ethernet {
            destination: value.dst,
            source: value.src,
            ethertype: Ethertype(u16::from(value.ether_type)),
        })
    }
}

impl<T: ByteSlice> PushAction<EthernetPacket<T>> for EtherMeta {
    #[inline]
    fn push(value: &Valid<Self>) -> EthernetPacket<T> {
        Header::Repr(
            Ethernet {
                destination: value.dst,
                source: value.src,
                ethertype: Ethertype(u16::from(value.ether_type)),
            }
            .into(),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ingot::types::Emit;
    use ingot::types::HeaderParse;

    #[test]
    fn emit() {
        let eth = Ethernet {
            destination: MacAddr::from([0xA8, 0x40, 0x25, 0xFF, 0x77, 0x77]),
            source: MacAddr::from([0xA8, 0x40, 0x25, 0xFA, 0xFA, 0x37]),
            ethertype: Ethertype::IPV4,
        };

        // Verify bytes are written and segment length is correct.
        let out = eth.emit_vec();
        assert_eq!(out.len(), 14);
        #[rustfmt::skip]
        let expected_bytes = vec![
            // destination
            0xA8, 0x40, 0x25, 0xFF, 0x77, 0x77,
            // source
            0xA8, 0x40, 0x25, 0xFA, 0xFA, 0x37,
            // ether type
            0x08, 0x00,
        ];
        assert_eq!(expected_bytes, out);

        // Verify error when the mblk is not large enough.
        assert!(ValidEthernet::parse(&[0; 10][..]).is_err());
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Internet Control Message Protocol (ICMP) shared data structures.

pub mod v4;
pub mod v6;

pub use v4::Icmpv4Meta;
pub use v6::Icmpv6Meta;

use super::checksum::Checksum as OpteCsum;
use super::checksum::HeaderChecksum;
use super::headers::RawHeader;
use super::packet::PacketReadMut;
use super::packet::ReadErr;
use crate::engine::ether::EtherHdr;
use crate::engine::ether::EtherMeta;
use crate::engine::ether::EtherType;
use crate::engine::headers::HeaderActionModify;
use crate::engine::headers::UlpMetaModify;
use crate::engine::packet::Packet;
use crate::engine::packet::PacketMeta;
use crate::engine::packet::PacketRead;
use crate::engine::packet::PacketReader;
use crate::engine::predicate::DataPredicate;
use crate::engine::predicate::EtherAddrMatch;
use crate::engine::predicate::IpProtoMatch;
use crate::engine::predicate::Predicate;
use crate::engine::rule::AllowOrDeny;
use crate::engine::rule::GenErr;
use crate::engine::rule::GenPacketResult;
use crate::engine::rule::HairpinAction;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Display;
pub use opte_api::ip::Protocol;
use serde::Deserialize;
use serde::Serialize;
use smoltcp::phy::Checksum;
use smoltcp::phy::ChecksumCapabilities as Csum;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;
use zerocopy::Ref;
use zerocopy::Unaligned;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IcmpMeta<T> {
    pub msg_type: T,
    pub msg_code: u8,
    pub csum: [u8; 2],
    pub rest_of_header: [u8; 4],
}

impl<T: Into<u8> + Copy> IcmpMeta<T> {
    // This assumes the dst is large enough.
    #[inline]
    pub fn emit(&self, dst: &mut [u8]) {
        debug_assert!(dst.len() >= IcmpHdr::SIZE);
        dst[0] = self.msg_type.into();
        dst[1] = self.msg_code;
        dst[2..4].copy_from_slice(&self.csum);
        dst[4..8].copy_from_slice(&self.rest_of_header);
    }

    #[inline]
    pub fn hdr_len(&self) -> usize {
        IcmpHdr::SIZE
    }

    #[inline]
    pub fn body_echo(&self) -> Ref<&[u8], IcmpEchoRaw> {
        // Panic safety: Size *must* be 8B by construction.
        IcmpEchoRaw::new(&self.rest_of_header[..]).unwrap()
    }

    #[inline]
    pub fn body_echo_mut(&mut self) -> Ref<&mut [u8], IcmpEchoRaw> {
        // Panic safety: Size *must* be 8B by construction.
        IcmpEchoRaw::new_mut(&mut self.rest_of_header[..]).unwrap()
    }
}

impl<'a, T: From<u8>> From<&IcmpHdr<'a>> for IcmpMeta<T> {
    fn from(hdr: &IcmpHdr<'a>) -> Self {
        Self {
            msg_type: hdr.base.msg_type.into(),
            msg_code: hdr.base.msg_code,
            csum: hdr.base.csum,
            rest_of_header: hdr.base.rest_of_header,
        }
    }
}

/// Shared methods for handling ICMPv4/v6 Echo fields.
pub trait QueryEcho {
    /// Extract an ID from the body of an ICMP(v6) packet.
    ///
    /// This method should return `None` for any non-echo packets.
    fn echo_id(&self) -> Option<u16>;
}

// This covers both v4/v6 ICMP Echo rewriting for SNAT compatibility.
impl<T: Into<u8> + Copy> HeaderActionModify<UlpMetaModify> for IcmpMeta<T>
where
    IcmpMeta<T>: QueryEcho,
{
    fn run_modify(&mut self, spec: &UlpMetaModify) {
        let Some(new_id) = spec.icmp_id else {
            return;
        };

        if self.echo_id().is_none() {
            return;
        }

        let mut echo_data = self.body_echo_mut();
        echo_data.id = new_id.to_be_bytes();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IcmpHdrError {
    ReadError { error: ReadErr },
}

impl From<ReadErr> for IcmpHdrError {
    fn from(error: ReadErr) -> Self {
        IcmpHdrError::ReadError { error }
    }
}

#[derive(Debug)]
pub struct IcmpHdr<'a> {
    base: Ref<&'a mut [u8], IcmpHdrRaw>,
}

impl<'a> IcmpHdr<'a> {
    pub const SIZE: usize = IcmpHdrRaw::SIZE;

    /// Offset to the start of the ICMP(v6) checksum field.
    pub const CSUM_BEGIN_OFFSET: usize = 2;

    /// Offset to the end of the ICMP(v6) checksum field.
    pub const CSUM_END_OFFSET: usize = 4;

    pub fn csum_minus_hdr(&self) -> Option<OpteCsum> {
        if self.base.csum != [0; 2] {
            let mut csum = OpteCsum::from(HeaderChecksum::wrap(self.base.csum));
            let bytes = self.base.bytes();
            csum.sub_bytes(&bytes[..Self::CSUM_BEGIN_OFFSET]);
            csum.sub_bytes(&bytes[Self::CSUM_END_OFFSET..]);
            Some(csum)
        } else {
            None
        }
    }

    /// Return the header length, in bytes.
    pub fn hdr_len(&self) -> usize {
        Self::SIZE
    }

    pub fn parse<'b>(
        rdr: &'b mut impl PacketReadMut<'a>,
    ) -> Result<Self, IcmpHdrError> {
        let src = rdr.slice_mut(IcmpHdr::SIZE)?;
        Ok(Self { base: IcmpHdrRaw::new_mut(src)? })
    }
}

/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, Debug, FromBytes, AsBytes, FromZeroes, Unaligned)]
pub struct IcmpHdrRaw {
    pub msg_type: u8,
    pub msg_code: u8,
    pub csum: [u8; 2],
    pub rest_of_header: [u8; 4],
}

impl IcmpHdrRaw {
    /// An ICMP(v6) header is always 8 bytes.
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl<'a> RawHeader<'a> for IcmpHdrRaw {
    #[inline]
    fn new_mut(src: &mut [u8]) -> Result<Ref<&mut [u8], Self>, ReadErr> {
        debug_assert_eq!(src.len(), Self::SIZE);
        let hdr = match Ref::new(src) {
            Some(hdr) => hdr,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }
}

/// Internal structure of an ICMP(v6) Echo(Reply)'s rest_of_header.
#[repr(C)]
#[derive(Clone, Debug, FromBytes, AsBytes, FromZeroes, Unaligned)]
pub struct IcmpEchoRaw {
    pub id: [u8; 2],
    pub sequence: [u8; 2],
}

impl IcmpEchoRaw {
    /// Echo-specific fields are always 4 bytes.
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl<'a> RawHeader<'a> for IcmpEchoRaw {
    #[inline]
    fn new_mut(src: &mut [u8]) -> Result<Ref<&mut [u8], Self>, ReadErr> {
        debug_assert_eq!(src.len(), Self::SIZE);
        let hdr = match Ref::new(src) {
            Some(hdr) => hdr,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }

    #[inline]
    fn new(src: &[u8]) -> Result<Ref<&[u8], Self>, ReadErr> {
        debug_assert_eq!(src.len(), Self::SIZE);
        let hdr = match Ref::new(src) {
            Some(hdr) => hdr,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }
}

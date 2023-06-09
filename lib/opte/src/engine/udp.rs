// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! UDP headers.

use core::mem;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::LayoutVerified;
use zerocopy::Unaligned;

use crate::engine::checksum::Checksum;
use crate::engine::checksum::HeaderChecksum;
use crate::engine::headers::HeaderActionModify;
use crate::engine::headers::ModifyAction;
use crate::engine::headers::PushAction;
use crate::engine::headers::RawHeader;
use crate::engine::headers::UlpMetaModify;
use crate::engine::packet::PacketReadMut;
use crate::engine::packet::ReadErr;
use opte_api::DYNAMIC_PORT;

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct UdpMeta {
    pub src: u16,
    pub dst: u16,
    pub len: u16,
    pub csum: [u8; 2],
}

impl UdpMeta {
    // This assumes the dst is large enough.
    #[inline]
    pub fn emit(&self, dst: &mut [u8]) {
        debug_assert!(dst.len() >= UdpHdr::SIZE);
        dst[0..2].copy_from_slice(&self.src.to_be_bytes());
        dst[2..4].copy_from_slice(&self.dst.to_be_bytes());
        dst[4..6].copy_from_slice(&self.len.to_be_bytes());
        dst[6..8].copy_from_slice(&self.csum);
    }

    pub fn hdr_len(&self) -> usize {
        UdpHdr::SIZE
    }
}

impl<'a> From<&UdpHdr<'a>> for UdpMeta {
    fn from(udp: &UdpHdr) -> Self {
        UdpMeta {
            src: udp.src_port(),
            dst: udp.dst_port(),
            len: udp.len(),
            csum: udp.csum_bytes(),
        }
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
pub struct UdpPush {
    pub src: u16,
    pub dst: u16,
}

impl PushAction<UdpMeta> for UdpPush {
    fn push(&self) -> UdpMeta {
        let mut udp = UdpMeta::default();
        udp.src = self.src;
        udp.dst = self.dst;
        udp
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UdpMod {
    src: Option<u16>,
    dst: Option<u16>,
}

impl ModifyAction<UdpMeta> for UdpMod {
    fn modify(&self, meta: &mut UdpMeta) {
        if let Some(src) = self.src {
            meta.src = src;
        }

        if let Some(dst) = self.dst {
            meta.dst = dst;
        }
    }
}

impl HeaderActionModify<UlpMetaModify> for UdpMeta {
    fn run_modify(&mut self, spec: &UlpMetaModify) {
        if spec.generic.src_port.is_some() {
            self.src = spec.generic.src_port.unwrap()
        }

        if spec.generic.dst_port.is_some() {
            self.dst = spec.generic.dst_port.unwrap()
        }
    }
}

#[derive(Debug)]
pub struct UdpHdr<'a> {
    base: LayoutVerified<&'a mut [u8], UdpHdrRaw>,
}

impl<'a> UdpHdr<'a> {
    pub const SIZE: usize = UdpHdrRaw::SIZE;
    pub const CSUM_BEGIN_OFFSET: usize = 6;
    pub const CSUM_END_OFFSET: usize = 8;

    pub fn bytes(&self) -> &[u8] {
        self.base.bytes()
    }

    pub fn csum_bytes(&self) -> [u8; 2] {
        self.base.csum
    }

    pub fn csum_minus_hdr(&self) -> Option<Checksum> {
        if self.base.csum != [0; 2] {
            let mut csum = Checksum::from(HeaderChecksum::wrap(self.base.csum));
            csum.sub_bytes(&self.base.bytes()[0..Self::CSUM_BEGIN_OFFSET]);
            Some(csum)
        } else {
            None
        }
    }

    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes(self.base.dst_port)
    }

    /// Return the header length, in bytes.
    pub fn hdr_len(&self) -> usize {
        Self::SIZE
    }

    pub fn parse<'b>(
        rdr: &'b mut impl PacketReadMut<'a>,
    ) -> Result<Self, UdpHdrError> {
        let src = rdr.slice_mut(UdpHdrRaw::SIZE)?;
        let udp = Self { base: UdpHdrRaw::new_mut(src)? };

        let src_port = udp.src_port();
        if src_port == DYNAMIC_PORT {
            return Err(UdpHdrError::BadSrcPort { src_port });
        }

        let dst_port = udp.dst_port();
        if dst_port == DYNAMIC_PORT {
            return Err(UdpHdrError::BadDstPort { dst_port });
        }

        let length = udp.len();
        if length < Self::SIZE as u16 {
            return Err(UdpHdrError::BadLength { length });
        }

        Ok(udp)
    }

    pub fn set_csum(&mut self, csum: [u8; 2]) {
        self.base.csum = csum;
    }

    pub fn len(&self) -> u16 {
        u16::from_be_bytes(self.base.length)
    }

    /// Set the length, in bytes.
    ///
    /// The UDP length field includes both header and payload.
    pub fn set_len(&mut self, len: u16) {
        self.base.length = len.to_be_bytes();
    }

    pub fn set_pay_len(&mut self, len: u16) {
        self.base.length = (Self::SIZE as u16 + len).to_be_bytes();
    }

    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.base.src_port)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpHdrError {
    BadDstPort { dst_port: u16 },
    BadLength { length: u16 },
    BadSrcPort { src_port: u16 },
    ReadError { error: ReadErr },
}

impl From<ReadErr> for UdpHdrError {
    fn from(error: ReadErr) -> Self {
        UdpHdrError::ReadError { error }
    }
}

/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, Debug, FromBytes, AsBytes, Unaligned)]
pub struct UdpHdrRaw {
    pub src_port: [u8; 2],
    pub dst_port: [u8; 2],
    pub length: [u8; 2],
    pub csum: [u8; 2],
}

impl UdpHdrRaw {
    pub const SIZE: usize = mem::size_of::<Self>();
}

impl<'a> RawHeader<'a> for UdpHdrRaw {
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
        let udp = UdpMeta { src: 5353, dst: 5353, len: 142, csum: [0; 2] };
        let len = udp.hdr_len();
        let mut pkt = Packet::alloc_and_expand(len);
        let mut wtr = pkt.seg0_wtr();
        udp.emit(wtr.slice_mut(udp.hdr_len()).unwrap());
        assert_eq!(len, pkt.len());

        #[rustfmt::skip]
        let expected_bytes = [
            // source port + dest port
            0x14, 0xE9, 0x14, 0xE9,
            // length + checksum
            0x00, 0x8E, 0x00, 0x00,
        ];
        assert_eq!(&expected_bytes, pkt.seg_bytes(0));
    }
}

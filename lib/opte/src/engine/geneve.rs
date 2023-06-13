// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Geneve headers and their related actions.
//!
//! RFC 8926 Geneve: Generic Network Virtualization Encapsulation

use super::ether::ETHER_TYPE_ETHER;
use super::headers::ModifyAction;
use super::headers::PushAction;
use super::headers::RawHeader;
use super::packet::PacketReadMut;
use super::packet::ReadErr;
use core::mem;
pub use opte_api::Vni;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::LayoutVerified;
use zerocopy::Unaligned;

pub const GENEVE_VSN: u8 = 0;
pub const GENEVE_VER_MASK: u8 = 0xC0;
pub const GENEVE_VER_SHIFT: u8 = 6;
pub const GENEVE_OPT_LEN_MASK: u8 = 0x3F;
pub const GENEVE_PORT: u16 = 6081;

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct GeneveMeta {
    pub entropy: u16,
    pub vni: Vni,
    pub len: u16,
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
pub struct GenevePush {
    pub entropy: u16,
    pub vni: Vni,
}

impl PushAction<GeneveMeta> for GenevePush {
    fn push(&self) -> GeneveMeta {
        GeneveMeta {
            entropy: self.entropy,
            vni: self.vni,
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneveMod {
    vni: Option<Vni>,
}

impl ModifyAction<GeneveMeta> for GeneveMod {
    fn modify(&self, meta: &mut GeneveMeta) {
        if let Some(vni) = self.vni {
            meta.vni = vni;
        }
    }
}

impl GeneveMeta {
    #[inline]
    pub fn emit(&self, dst: &mut [u8]) {
        debug_assert_eq!(dst.len(), self.hdr_len());
        let base = &mut dst[0..GeneveHdrRaw::SIZE];
        let mut raw = GeneveHdrRaw::new_mut(base).unwrap();
        raw.write(GeneveHdrRaw::from(self));
    }

    pub fn hdr_len(&self) -> usize {
        GeneveHdr::BASE_SIZE
    }
}

impl<'a> From<&GeneveHdr<'a>> for GeneveMeta {
    fn from(geneve: &GeneveHdr<'a>) -> Self {
        Self {
            vni: geneve.vni(),
            entropy: geneve.entropy(),
            len: geneve.len() as u16,
        }
    }
}

pub struct GeneveHdr<'a> {
    bytes: LayoutVerified<&'a mut [u8], GeneveHdrRaw>,
}

impl<'a> GeneveHdr<'a> {
    pub const BASE_SIZE: usize = mem::size_of::<GeneveHdrRaw>();

    /// Return the header length, in bytes.
    pub fn hdr_len(&self) -> usize {
        usize::from(self.bytes.options_len() * 4) + Self::BASE_SIZE
    }

    pub fn entropy(&self) -> u16 {
        u16::from_be_bytes(self.bytes.src_port)
    }

    pub fn len(&self) -> usize {
        usize::from(u16::from_be_bytes(self.bytes.length))
    }

    pub fn parse<'b, R>(rdr: &'b mut R) -> Result<Self, GeneveHdrError>
    where
        R: PacketReadMut<'a>,
    {
        let src = rdr.slice_mut(GeneveHdrRaw::SIZE)?;
        Ok(Self { bytes: GeneveHdrRaw::new_mut(src)? })
    }

    /// Set the length, in bytes.
    ///
    /// The UDP length field includes both header and payload.
    pub fn set_len(&mut self, len: u16) {
        self.bytes.length = len.to_be_bytes();
    }

    pub fn unify(&mut self, meta: &GeneveMeta) {
        self.bytes.src_port = meta.entropy.to_be_bytes();
        self.bytes.dst_port = GENEVE_PORT.to_be_bytes();
        self.bytes.vni = meta.vni.bytes();
    }

    /// Return the VNI.
    pub fn vni(&self) -> Vni {
        // Unwrap: We know it's legit because we are making sure the
        // MSB is zero.
        Vni::new(u32::from_be_bytes([
            0,
            self.bytes.vni[0],
            self.bytes.vni[1],
            self.bytes.vni[2],
        ]))
        .unwrap()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneveHdrError {
    BadDstPort { dst_port: u16 },
    BadLength { len: u16 },
    BadVersion { vsn: u8 },
    BadVni { vni: u32 },
    ReadError { error: ReadErr },
    UnexpectedProtocol { protocol: u16 },
}

impl From<ReadErr> for GeneveHdrError {
    fn from(error: ReadErr) -> Self {
        GeneveHdrError::ReadError { error }
    }
}

/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, Debug, FromBytes, AsBytes, Unaligned)]
pub struct GeneveHdrRaw {
    src_port: [u8; 2],
    dst_port: [u8; 2],
    length: [u8; 2],
    csum: [u8; 2],
    ver_opt_len: u8,
    flags: u8,
    proto: [u8; 2],
    vni: [u8; 3],
    reserved: u8,
}

impl GeneveHdrRaw {
    // Return the length of the Geneve options.
    //
    // NOTE: The Geneve header specifies options length in 4-byte units.
    pub fn options_len(&self) -> u8 {
        self.ver_opt_len & GENEVE_OPT_LEN_MASK
    }

    pub fn version(&self) -> u8 {
        (self.ver_opt_len & GENEVE_VER_MASK) >> GENEVE_VER_SHIFT
    }
}

impl<'a> RawHeader<'a> for GeneveHdrRaw {
    #[inline]
    fn new_mut(
        src: &mut [u8],
    ) -> Result<LayoutVerified<&mut [u8], Self>, ReadErr> {
        debug_assert_eq!(src.len(), mem::size_of::<Self>());
        let hdr = match LayoutVerified::new(src) {
            Some(hdr) => hdr,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }
}

impl Default for GeneveHdrRaw {
    fn default() -> Self {
        Self {
            src_port: [0; 2],
            dst_port: [0; 2],
            length: [0; 2],
            csum: [0; 2],
            ver_opt_len: 0x0,
            flags: 0x0,
            proto: ETHER_TYPE_ETHER.to_be_bytes(),
            vni: [0x0; 3],
            reserved: 0,
        }
    }
}

impl From<&GeneveMeta> for GeneveHdrRaw {
    fn from(meta: &GeneveMeta) -> Self {
        Self {
            src_port: meta.entropy.to_be_bytes(),
            dst_port: GENEVE_PORT.to_be_bytes(),
            length: meta.len.to_be_bytes(),
            csum: [0; 2],
            ver_opt_len: 0x0,
            flags: 0x0,
            proto: ETHER_TYPE_ETHER.to_be_bytes(),
            vni: meta.vni.bytes(),
            reserved: 0,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::engine::packet::Packet;

    #[test]
    fn emit() {
        let geneve = GeneveMeta {
            entropy: 7777,
            vni: Vni::new(1234u32).unwrap(),
            len: GeneveHdr::BASE_SIZE as u16,
        };

        let len = geneve.hdr_len();
        let mut pkt = Packet::alloc_and_expand(len);
        let mut wtr = pkt.seg0_wtr();
        // geneve.emit(&mut wtr).unwrap();
        geneve.emit(wtr.slice_mut(len).unwrap());
        assert_eq!(len, pkt.len());
        #[rustfmt::skip]
        let expected_bytes = vec![
            // source
            0x1E, 0x61,
            // dest
            0x17, 0xC1,
            // length
            0x00, 0x10,
            // csum
            0x00, 0x00,
            // ver + opt len
            0x00,
            // flags
            0x00,
            // proto
            0x65, 0x58,
            // vni + reserved
            0x00, 0x04, 0xD2, 0x00
        ];
        assert_eq!(&expected_bytes, pkt.seg_bytes(0));
    }
}

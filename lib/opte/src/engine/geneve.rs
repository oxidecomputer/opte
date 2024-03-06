// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Geneve headers and their related actions.
//!
//! RFC 8926 Geneve: Generic Network Virtualization Encapsulation

use super::ether::ETHER_TYPE_ETHER;
use super::headers::ModifyAction;
use super::headers::PushAction;
use super::headers::RawHeader;
use super::packet::PacketReadMut;
use super::packet::ReadErr;
use crate::d_error::DError;
use super::udp::UdpHdr;
use super::udp::UdpMeta;
use core::mem;
pub use opte_api::Vni;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;
use zerocopy::Ref;
use zerocopy::Unaligned;

pub const GENEVE_VSN: u8 = 0;
pub const GENEVE_VER_MASK: u8 = 0xC0;
pub const GENEVE_VER_SHIFT: u8 = 6;
pub const GENEVE_OPT_LEN_MASK: u8 = 0x3F;
pub const GENEVE_OPT_LEN_SCALE_SHIFT: u8 = 2;
pub const GENEVE_PORT: u16 = 6081;

pub const GENEVE_OPT_CRIT_SHIFT: u8 = 7;
pub const GENEVE_OPT_TYPE_MASK: u8 = (1 << GENEVE_OPT_CRIT_SHIFT) - 1;
pub const GENEVE_OPT_RESERVED_SHIFT: u8 = 5;
pub const GENEVE_OPT_RESERVED_MASK: u8 = (1 << GENEVE_OPT_RESERVED_SHIFT) - 1;
pub const GENEVE_OPT_CLASS_OXIDE: u16 = 0x0129;

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct GeneveMeta {
    pub entropy: u16,
    pub vni: Vni,
    pub oxide_external_pkt: bool,
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
    /// Emit only the inner Geneve header.
    #[inline]
    pub fn emit_inner(&self, dst: &mut [u8]) {
        debug_assert_eq!(dst.len(), self.hdr_len_inner());
        let (base, remainder) = dst.split_at_mut(GeneveHdrRaw::SIZE);
        let mut raw = GeneveHdrRaw::new_mut(base).unwrap();
        raw.write(GeneveHdrRaw::from(self));

        raw.ver_opt_len = if self.oxide_external_pkt {
            GeneveOption::Oxide(OxideOption::External).emit(remainder) as u8
        } else {
            raw.ver_opt_len
        };
    }

    /// Emit a full Geneve encapsulation for an inner packet, including
    /// UDP.
    ///
    /// `total_len` should be precomputed as `self.hdr_len() + body.len()`.
    #[inline]
    pub fn emit(&self, total_len: u16, dst: &mut [u8]) {
        let (udp_buf, geneve_buf) = dst.split_at_mut(UdpHdr::SIZE);
        let udp = UdpMeta {
            src: self.entropy,
            dst: GENEVE_PORT,
            len: total_len,
            csum: [0; 2],
        };
        udp.emit(udp_buf);

        self.emit_inner(geneve_buf);
    }

    /// Return the length of headers needed to fully Geneve-encapsulate
    /// a packet, including UDP.
    #[inline]
    pub fn hdr_len(&self) -> usize {
        UdpHdr::SIZE + self.hdr_len_inner()
    }

    /// Return the length of only the Geneve header.
    #[inline]
    pub fn hdr_len_inner(&self) -> usize {
        GeneveHdr::BASE_SIZE + self.options_len()
    }

    /// Return the required length (in bytes) needed to store
    /// all Geneve options attached to this packet.
    pub fn options_len(&self) -> usize {
        // XXX: This is very special-cased just to enable testing.
        if self.oxide_external_pkt {
            GeneveOptHdrRaw::SIZE
        } else {
            0
        }
    }
}

impl<'a> From<(&UdpHdr<'a>, &GeneveHdr<'a>)> for GeneveMeta {
    fn from((udp, geneve): (&UdpHdr<'a>, &GeneveHdr<'a>)) -> Self {
        let mut out = Self::from(geneve);
        out.entropy = udp.src_port();
        out
    }
}

impl<'a> From<&GeneveHdr<'a>> for GeneveMeta {
    fn from(geneve: &GeneveHdr<'a>) -> Self {
        let mut out =
            Self { vni: geneve.vni(), entropy: 0, ..Default::default() };

        if let Some(ref opts) = geneve.opts {
            // XXX: Prevent duplication by making Meta generation fallible
            //      in same way as Parsing?
            // Unwrap safety: Invalid options will have been caught in
            // GeneveHdr::parse.
            GeneveOption::parse_all(opts, Some(&mut out)).unwrap();
        }

        out
    }
}

pub struct GeneveHdr<'a> {
    /// Main body of the Geneve Header.
    bytes: Ref<&'a mut [u8], GeneveHdrRaw>,
    /// Byte slice occupied by Geneve options.
    opts: Option<&'a mut [u8]>,
}

impl<'a> GeneveHdr<'a> {
    pub const BASE_SIZE: usize = mem::size_of::<GeneveHdrRaw>();

    /// Return the header length, in bytes.
    pub fn hdr_len(&self) -> usize {
        usize::from(self.bytes.options_len() * 4) + Self::BASE_SIZE
    }

    pub fn parse<'b, R>(rdr: &'b mut R) -> Result<Self, GeneveHdrError>
    where
        R: PacketReadMut<'a>,
    {
        let src = rdr.slice_mut(GeneveHdrRaw::SIZE)?;
        let bytes = GeneveHdrRaw::new_mut(src)?;
        let opt_len = bytes.options_len_bytes().into();
        let opts = if opt_len != 0 {
            let opts_body = rdr.slice_mut(opt_len)?;

            // Check for malformed options.
            // XXX: Can we use this to elide some checks when building GeneveMeta?
            //      Otherwise, currently repeated to filter packets at parse time.
            GeneveOption::parse_all(opts_body, None)?;

            Some(opts_body)
        } else {
            None
        };

        Ok(Self { bytes, opts })
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, DError)]
#[derror(leaf_data = GeneveHdrError::derror_data)]
pub enum GeneveHdrError {
    BadDstPort { dst_port: u16 },
    BadLength { len: u16 },
    BadVersion { vsn: u8 },
    BadVni { vni: u32 },
    ReadError(ReadErr),
    UnexpectedProtocol { protocol: u16 },
    UnknownCriticalOption { class: u16, opt_type: u8 },
}

impl From<ReadErr> for GeneveHdrError {
    fn from(error: ReadErr) -> Self {
        GeneveHdrError::ReadError(error)
    }
}

impl GeneveHdrError {
    fn derror_data(&self, data: &mut [u64]) {
        [data[0], data[1]] = match self {
            Self::BadDstPort { dst_port } => [*dst_port as u64, 0],
            Self::BadLength { len } => [*len as u64, 0],
            Self::BadVersion { vsn } => [*vsn as u64, 0],
            Self::BadVni { vni } => [*vni as u64, 0],
            Self::UnexpectedProtocol { protocol } => [*protocol as u64, 0],
            Self::UnknownCriticalOption { class, opt_type } => {
                [*class as u64, *opt_type as u64]
            }
            _ => [0, 0],
        }
    }
}

/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, Debug, FromBytes, AsBytes, FromZeroes, Unaligned)]
pub struct GeneveHdrRaw {
    ver_opt_len: u8,
    flags: u8,
    proto: [u8; 2],
    vni: [u8; 3],
    reserved: u8,
}

impl GeneveHdrRaw {
    /// Return the length of the Geneve options in 4-byte units.
    pub fn options_len(&self) -> u8 {
        self.ver_opt_len & GENEVE_OPT_LEN_MASK
    }

    /// Return the length of the Geneve options in bytes.
    pub fn options_len_bytes(&self) -> u8 {
        self.options_len() << GENEVE_OPT_LEN_SCALE_SHIFT
    }

    pub fn version(&self) -> u8 {
        (self.ver_opt_len & GENEVE_VER_MASK) >> GENEVE_VER_SHIFT
    }
}

impl<'a> RawHeader<'a> for GeneveHdrRaw {
    #[inline]
    fn new_mut(src: &mut [u8]) -> Result<Ref<&mut [u8], Self>, ReadErr> {
        debug_assert_eq!(src.len(), mem::size_of::<Self>());
        let hdr = match Ref::new(src) {
            Some(hdr) => hdr,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }
}

impl Default for GeneveHdrRaw {
    fn default() -> Self {
        Self {
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
            ver_opt_len: (meta.options_len() >> GENEVE_OPT_LEN_SCALE_SHIFT)
                as u8,
            flags: 0x0,
            proto: ETHER_TYPE_ETHER.to_be_bytes(),
            vni: meta.vni.bytes(),
            reserved: 0,
        }
    }
}

/// Parsed form of an individual Geneve option TLV.
///
/// These are grouped by the vendor `class`es understood by OPTE.
#[non_exhaustive]
pub enum GeneveOption {
    Oxide(OxideOption),
}

impl GeneveOption {
    /// Parse and check validity for all options attached to a Geneve
    /// header, recording known extensions in a [`GeneveMeta`] if
    /// given.
    pub fn parse_all(
        mut src: &[u8],
        mut meta: Option<&mut GeneveMeta>,
    ) -> Result<(), GeneveHdrError> {
        while !src.is_empty() {
            let option = GeneveOption::parse(&mut src)?;
            if let Some(ref mut meta) = meta {
                #[allow(clippy::single_match)]
                match option {
                    Some(GeneveOption::Oxide(OxideOption::External)) => {
                        meta.oxide_external_pkt = true
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    /// Parse an individual Geneve option from a byte slice, advancing the
    /// read location.
    pub fn parse(src: &mut &[u8]) -> Result<Option<Self>, GeneveHdrError> {
        let (head, tail) = src.split_at(GeneveOptHdrRaw::SIZE);
        let opt_header = GeneveOptHdrRaw::new(head)?;
        let needed_bytes = opt_header.options_len_bytes() as usize;
        if tail.len() < needed_bytes {
            return Err(GeneveHdrError::BadLength { len: needed_bytes as u16 });
        }

        let class = u16::from_be_bytes(opt_header.option_class);
        let opt_type = opt_header.option_type();

        // We don't yet have any options which need body parsing.
        // This will skip over them regardless.
        let (_body, tail) = tail.split_at(needed_bytes);
        *src = tail;

        // XXX: Break this out into a trait/impls to handle more cleanly.
        Ok(match (class, opt_header.option_type()) {
            (GENEVE_OPT_CLASS_OXIDE, 0) => {
                Some(GeneveOption::Oxide(OxideOption::External))
            }
            _ if opt_header.is_critical() => {
                return Err(GeneveHdrError::UnknownCriticalOption {
                    class,
                    opt_type,
                })
            }
            _ => None,
        })
    }

    /// Return the wire-length of this option in bytes, including headers.
    pub fn len(&self) -> usize {
        4 + match self {
            GeneveOption::Oxide(o) => o.len(),
        }
    }

    /// Emit an option, returning the number of 4-byte chunks written.
    pub fn emit(&self, dst: &mut [u8]) -> usize {
        let mut raw = GeneveOptHdrRaw::new_mut(dst).unwrap();

        let (class, opt_type, len) = match self {
            Self::Oxide(o) => (
                GENEVE_OPT_CLASS_OXIDE,
                o.opt_type(),
                o.len() >> GENEVE_OPT_LEN_SCALE_SHIFT,
            ),
        };
        raw.option_class = class.to_be_bytes();
        raw.crit_type = opt_type;
        raw.reserved_len = len as u8;

        len + 1
    }
}

/// Geneve options defined by Oxide, [`GENEVE_OPT_CLASS_OXIDE`].
#[non_exhaustive]
pub enum OxideOption {
    /// A tag indicating that this packet originated from outside the VPC.
    ///
    /// Option Type `0`. Currently includes no body.
    External,
}

impl OxideOption {
    /// Return the wire-length of this option's body in bytes, excluding headers.
    pub fn len(&self) -> usize {
        match self {
            OxideOption::External => 0,
        }
    }

    /// Return the option type number.
    pub fn opt_type(&self) -> u8 {
        match self {
            OxideOption::External => 0,
        }
    }
}

/// Field layout for a single Geneve option.
///
/// Note: Unaligned on the same rationale as [`GeneveHdrRaw`].
#[repr(C)]
#[derive(Clone, Debug, FromBytes, AsBytes, FromZeroes, Unaligned)]
pub struct GeneveOptHdrRaw {
    option_class: [u8; 2],
    crit_type: u8,
    reserved_len: u8,
}

impl GeneveOptHdrRaw {
    /// Indicates whether this option is critical, and MUST be dropped
    /// if not understood by a tunnel endpoint.
    pub fn is_critical(&self) -> bool {
        (self.crit_type >> GENEVE_OPT_CRIT_SHIFT) != 0
    }

    /// Return the type of this header.
    pub fn option_type(&self) -> u8 {
        self.crit_type & GENEVE_OPT_TYPE_MASK
    }

    /// Return the length of this Geneve option's body in 4-byte units.
    pub fn options_len(&self) -> u8 {
        self.reserved_len & GENEVE_OPT_RESERVED_MASK
    }

    /// Return the length of the Geneve options in bytes.
    pub fn options_len_bytes(&self) -> u8 {
        self.options_len() << GENEVE_OPT_LEN_SCALE_SHIFT
    }
}

impl<'a> RawHeader<'a> for GeneveOptHdrRaw {
    #[inline]
    fn new_mut(src: &mut [u8]) -> Result<Ref<&mut [u8], Self>, ReadErr> {
        debug_assert_eq!(src.len(), mem::size_of::<Self>());
        let hdr = match Ref::new(src) {
            Some(hdr) => hdr,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }

    #[inline]
    fn new(src: &[u8]) -> Result<Ref<&[u8], Self>, ReadErr> {
        debug_assert_eq!(src.len(), mem::size_of::<Self>());
        let hdr = match Ref::new(src) {
            Some(hdr) => hdr,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }
}

#[cfg(test)]
mod test {
    use core::matches;

    use super::*;
    use crate::engine::packet::Packet;

    #[test]
    fn emit_no_opts() {
        let geneve = GeneveMeta {
            entropy: 7777,
            vni: Vni::new(1234u32).unwrap(),

            ..Default::default()
        };

        let len = geneve.hdr_len();
        let mut pkt = Packet::alloc_and_expand(len);
        let mut wtr = pkt.seg0_wtr();
        geneve.emit(
            geneve.hdr_len().try_into().unwrap(),
            wtr.slice_mut(len).unwrap(),
        );
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

    #[test]
    fn emit_external_opt() {
        let geneve = GeneveMeta {
            entropy: 7777,
            vni: Vni::new(1234u32).unwrap(),
            oxide_external_pkt: true,
        };

        let len = geneve.hdr_len();
        let mut pkt = Packet::alloc_and_expand(len);
        let mut wtr = pkt.seg0_wtr();
        geneve.emit(
            geneve.hdr_len().try_into().unwrap(),
            wtr.slice_mut(len).unwrap(),
        );
        assert_eq!(len, pkt.len());
        #[rustfmt::skip]
        let expected_bytes = vec![
            // source
            0x1E, 0x61,
            // dest
            0x17, 0xC1,
            // length
            0x00, 0x14,
            // csum
            0x00, 0x00,
            // ver + opt len
            0x01,
            // flags
            0x00,
            // proto
            0x65, 0x58,
            // vni + reserved
            0x00, 0x04, 0xD2, 0x00,

            // option class
            0x01, 0x29,
            // crt + type
            0x00,
            // rsvd + len
            0x00,
        ];
        assert_eq!(&expected_bytes, pkt.seg_bytes(0));
    }

    #[test]
    fn parse_single_opt() {
        // Create a packet with one extension header.
        #[rustfmt::skip]
        let buf = vec![
            // source
            0x1E, 0x61,
            // dest
            0x17, 0xC1,
            // length
            0x00, 0x14,
            // csum
            0x00, 0x00,
            // ver + opt len
            0x01,
            // flags
            0x00,
            // proto
            0x65, 0x58,
            // vni + reserved
            0x00, 0x04, 0xD2, 0x00,

            // option class
            0x01, 0x29,
            // crt + type
            0x00,
            // rsvd + len
            0x00,
        ];
        let mut pkt = Packet::copy(&buf);
        let mut reader = pkt.get_rdr_mut();
        let udp = UdpHdr::parse(&mut reader).unwrap();
        let header = GeneveHdr::parse(&mut reader).unwrap();

        // Previously, the `Ipv6Meta::total_len` method double-counted the
        // extension header length. Assert we don't do that here.
        let meta = GeneveMeta::from((&udp, &header));
        assert_eq!(
            meta.entropy,
            u16::from_be_bytes(buf[0..2].try_into().unwrap())
        );
        assert!(meta.oxide_external_pkt);
    }

    #[test]
    fn bad_opt_len_fails() {
        // Create a packet with one extension header.
        #[rustfmt::skip]
        let buf = vec![
            // source
            0x1E, 0x61,
            // dest
            0x17, 0xC1,
            // length
            0x00, 0x14,
            // csum
            0x00, 0x00,
            // ver + BAD opt len
            0x01,
            // flags
            0x00,
            // proto
            0x65, 0x58,
            // vni + reserved
            0x00, 0x04, 0xD2, 0x00,

            // option class
            0x01, 0x29,
            // crt + type
            0x01,
            // rsvd + len
            0x01,
            // body
            0x00, 0x00, 0x00, 0x00
        ];
        let mut pkt = Packet::copy(&buf);
        let mut reader = pkt.get_rdr_mut();
        UdpHdr::parse(&mut reader).unwrap();
        assert!(matches!(
            GeneveHdr::parse(&mut reader),
            Err(GeneveHdrError::BadLength { .. }),
        ));
    }

    #[test]
    fn unknown_crit_option_fails() {
        // Create a packet with one extension header.
        #[rustfmt::skip]
        let buf = vec![
            // source
            0x1E, 0x61,
            // dest
            0x17, 0xC1,
            // length
            0x00, 0x14,
            // csum
            0x00, 0x00,
            // ver + opt len
            0x01,
            // flags
            0b0100_0000,
            // proto
            0x65, 0x58,
            // vni + reserved
            0x00, 0x04, 0xD2, 0x00,

            // experimenter option class
            0xff, 0xff,
            // crt + type
            0x80,
            // rsvd + len
            0x00,
        ];
        let mut pkt = Packet::copy(&buf);
        let mut reader = pkt.get_rdr_mut();
        UdpHdr::parse(&mut reader).unwrap();
        assert!(matches!(
            GeneveHdr::parse(&mut reader),
            Err(GeneveHdrError::UnknownCriticalOption {
                class: 0xff_ff,
                opt_type: 0
            }),
        ));
    }

    #[test]
    fn parse_multi_opt() {
        // Create a packet with one extension header.
        #[rustfmt::skip]
        let buf = vec![
            // source
            0x1E, 0x61,
            // dest
            0x17, 0xC1,
            // length
            0x00, 0x1c,
            // csum
            0x00, 0x00,
            // ver + opt len
            0x05,
            // flags
            0x00,
            // proto
            0x65, 0x58,
            // vni + reserved
            0x00, 0x04, 0xD2, 0x00,

            // option class
            0x01, 0x29,
            // crt + type
            0x00,
            // rsvd + len
            0x00,

            // experimenter option class
            0xff, 0xff,
            // crt + type
            0x05,
            // rsvd + len
            0x01,
            // body
            0x00, 0x00, 0x00, 0x00,

            // experimenter option class
            0xff, 0xff,
            // crt + type
            0x06,
            // rsvd + len
            0x01,
            // body
            0x00, 0x00, 0x00, 0x00,
        ];
        let mut pkt = Packet::copy(&buf);
        let mut reader = pkt.get_rdr_mut();
        let udp = UdpHdr::parse(&mut reader).unwrap();
        let header = GeneveHdr::parse(&mut reader).unwrap();

        // Previously, the `Ipv6Meta::total_len` method double-counted the
        // extension header length. Assert we don't do that here.
        let meta = GeneveMeta::from((&udp, &header));
        assert_eq!(
            meta.entropy,
            u16::from_be_bytes(buf[0..2].try_into().unwrap())
        );
        assert!(meta.oxide_external_pkt);
    }
}

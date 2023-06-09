// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! TCP headers.

use super::checksum::Checksum;
use super::checksum::HeaderChecksum;
use super::headers::HeaderActionModify;
use super::headers::ModifyAction;
use super::headers::PushAction;
use super::headers::RawHeader;
use super::headers::UlpMetaModify;
use super::packet::PacketReadMut;
use super::packet::ReadErr;
use core::fmt;
use core::fmt::Display;
use opte_api::DYNAMIC_PORT;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::LayoutVerified;
use zerocopy::Unaligned;

pub const TCP_HDR_OFFSET_MASK: u8 = 0xF0;
pub const TCP_HDR_OFFSET_SHIFT: u8 = 4;

pub const TCP_PORT_RDP: u16 = 3389;
pub const TCP_PORT_SSH: u16 = 22;

/// The standard TCP flags. We don't bother with the experimental NS
/// flag.
pub mod TcpFlags {
    pub const FIN: u8 = crate::bit_on(0);
    pub const SYN: u8 = crate::bit_on(1);
    pub const RST: u8 = crate::bit_on(2);
    pub const PSH: u8 = crate::bit_on(3);
    pub const ACK: u8 = crate::bit_on(4);
    pub const URG: u8 = crate::bit_on(5);
    pub const ECE: u8 = crate::bit_on(6);
    pub const CWR: u8 = crate::bit_on(7);
}

// The standard TCP states.
//
// See Figure 13-8 of TCP/IP Illustrated Vol. 1 Ed. 2
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynRcvd,
    Established,
    CloseWait,
    LastAck,
    FinWait1,
    FinWait2,
    TimeWait,
}

impl Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            TcpState::Closed => "CLOSED",
            TcpState::Listen => "LISTEN",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynRcvd => "SYN_RCVD",
            TcpState::Established => "ESTABLISHED",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::LastAck => "LAST_ACK",
            TcpState::FinWait1 => "FIN_WAIT_1",
            TcpState::FinWait2 => "FIN_WAIT_2",
            TcpState::TimeWait => "TIME_WAIT",
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct TcpMeta {
    pub src: u16,
    pub dst: u16,
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
    pub window_size: u16,
    pub csum: [u8; 2],
    // Fow now we keep options as raw bytes, allowing up to 40 bytes
    // of options.
    pub options_bytes: Option<[u8; TcpHdr::MAX_OPTION_SIZE]>,
    pub options_len: usize,
}

impl TcpMeta {
    // This assumes the slice is large enough to hold the header.
    #[inline]
    pub fn emit(&self, dst: &mut [u8]) {
        debug_assert_eq!(dst.len(), self.hdr_len());
        let base = &mut dst[0..TcpHdrRaw::SIZE];
        let mut raw = TcpHdrRaw::new_mut(base).unwrap();
        raw.write(TcpHdrRaw::from(self));
        if let Some(bytes) = self.options_bytes {
            dst[TcpHdr::BASE_SIZE..]
                .copy_from_slice(&bytes[0..self.options_len]);
        }
    }

    #[inline]
    pub fn has_flag(&self, flag: u8) -> bool {
        (self.flags & flag) != 0
    }

    #[inline]
    pub fn hdr_len(&self) -> usize {
        TcpHdr::BASE_SIZE + self.options_len
    }
}

impl<'a> From<&TcpHdr<'a>> for TcpMeta {
    fn from(tcp: &TcpHdr) -> Self {
        let (options_bytes, options_len) = match tcp.options_raw() {
            None => (None, 0),
            Some(src) => {
                let mut dst = [0; TcpHdr::MAX_OPTION_SIZE];
                dst[0..src.len()].copy_from_slice(src);
                (Some(dst), src.len())
            }
        };

        let raw = tcp.base.read();
        Self {
            src: u16::from_be_bytes(raw.src_port),
            dst: u16::from_be_bytes(raw.dst_port),
            flags: raw.flags,
            seq: u32::from_be_bytes(raw.seq),
            ack: u32::from_be_bytes(raw.ack),
            window_size: u16::from_be_bytes(raw.window_size),
            csum: raw.csum,
            options_bytes,
            options_len,
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
pub struct TcpPush {
    pub src: u16,
    pub dst: u16,
}

impl PushAction<TcpMeta> for TcpPush {
    fn push(&self) -> TcpMeta {
        TcpMeta { src: self.src, dst: self.dst, ..Default::default() }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TcpMod {
    src: Option<u16>,
    dst: Option<u16>,
}

impl ModifyAction<TcpMeta> for TcpMod {
    fn modify(&self, meta: &mut TcpMeta) {
        if let Some(src) = self.src {
            meta.src = src;
        }

        if let Some(dst) = self.dst {
            meta.dst = dst;
        }
    }
}

impl HeaderActionModify<UlpMetaModify> for TcpMeta {
    fn run_modify(&mut self, spec: &UlpMetaModify) {
        if spec.generic.src_port.is_some() {
            self.src = spec.generic.src_port.unwrap()
        }

        if spec.generic.dst_port.is_some() {
            self.dst = spec.generic.dst_port.unwrap()
        }

        if spec.tcp_flags.is_some() {
            self.flags = spec.tcp_flags.unwrap()
        }
    }
}

#[derive(Debug)]
pub struct TcpHdr<'a> {
    base: LayoutVerified<&'a mut [u8], TcpHdrRaw>,
    options: Option<&'a mut [u8]>,
}

impl<'a> TcpHdr<'a> {
    pub const BASE_SIZE: usize = TcpHdrRaw::SIZE;
    pub const CSUM_BEGIN_OFFSET: usize = 16;
    pub const CSUM_END_OFFSET: usize = 18;

    /// The maximum size of a TCP header.
    ///
    /// The header length is derived from the data offset field.
    /// Given it is a 4-bit field and specifies the size in 32-bit words,
    /// the maximum header size is therefore (2^4 - 1) * 4 = 60 bytes.
    pub const MAX_SIZE: usize = 60;

    /// The maximum size of any TCP options in a TCP header.
    pub const MAX_OPTION_SIZE: usize = Self::MAX_SIZE - Self::BASE_SIZE;

    /// Return the acknowledgement number.
    pub fn ack(&self) -> u32 {
        u32::from_be_bytes(self.base.ack)
    }

    pub fn csum(&self) -> [u8; 2] {
        self.base.csum
    }

    pub fn base_bytes(&self) -> &[u8] {
        self.base.bytes()
    }

    pub fn options_bytes(&self) -> Option<&[u8]> {
        match &self.options {
            None => None,
            Some(options) => Some(*options),
        }
    }

    /// Return the checksum value minus header TCP header bytes,
    /// producing the checksum value of the body.
    pub fn csum_minus_hdr(&self) -> Option<Checksum> {
        // There was no checksum to begin with.
        if self.base.csum == [0; 2] {
            return None;
        }

        let mut csum = Checksum::from(HeaderChecksum::wrap(self.base.csum));
        // When a checksum is calculated you treat the checksum field
        // bytes themselves as zero; therefore its imperative we do
        // not include the checksum field bytes when subtracting from
        // the checksum value.
        csum.sub_bytes(&self.base.bytes()[0..Self::CSUM_BEGIN_OFFSET]);
        csum.sub_bytes(&self.base.bytes()[Self::CSUM_END_OFFSET..]);

        if let Some(options) = self.options.as_ref() {
            csum.sub_bytes(options);
        }
        Some(csum)
    }

    /// Return destination port.
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes(self.base.dst_port)
    }

    /// Return the TCP flags.
    pub fn flags(&self) -> u8 {
        self.base.flags
    }

    /// Return the leangth of the TCP header, in bytes.
    ///
    /// This length includes the TCP options.
    pub fn hdr_len(&self) -> usize {
        usize::from(self.base.offset()) * 4
    }

    /// Return a reference to the options data.
    pub fn options_raw(&self) -> Option<&[u8]> {
        match &self.options {
            None => None,
            Some(options) => Some(*options),
        }
    }

    pub fn parse<'b>(
        rdr: &'b mut impl PacketReadMut<'a>,
    ) -> Result<Self, TcpHdrError> {
        let src = rdr.slice_mut(TcpHdrRaw::SIZE)?;
        let mut hdr = Self { base: TcpHdrRaw::new_mut(src)?, options: None };

        if hdr.src_port() == DYNAMIC_PORT {
            return Err(TcpHdrError::BadSrcPort { src_port: hdr.src_port() });
        }

        if hdr.dst_port() == DYNAMIC_PORT {
            return Err(TcpHdrError::BadDstPort { dst_port: hdr.dst_port() });
        }

        let hdr_len = hdr.hdr_len();

        if hdr_len < Self::BASE_SIZE {
            return Err(TcpHdrError::TruncatedHdr {
                hdr_len_bytes: hdr.hdr_len(),
            });
        }

        if hdr_len > Self::BASE_SIZE {
            let opts_len = hdr.hdr_len() - Self::BASE_SIZE;
            match rdr.slice_mut(opts_len) {
                Ok(opts) => hdr.options = Some(opts),
                Err(e) => {
                    return Err(TcpHdrError::TruncatedOptions { error: e });
                }
            }
        }

        Ok(hdr)
    }

    /// Return the sequence number.
    pub fn seq(&self) -> u32 {
        u32::from_be_bytes(self.base.seq)
    }

    /// Set the checksum value.
    pub fn set_csum(&mut self, csum: [u8; 2]) {
        self.base.csum = csum
    }

    /// Return the source port.
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.base.src_port)
    }

    /// Return the window size value.
    pub fn window_size(&self) -> u16 {
        u16::from_be_bytes(self.base.window_size)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpHdrError {
    BadDstPort { dst_port: u16 },
    BadOffset { offset: u8, len_in_bytes: u8 },
    BadSrcPort { src_port: u16 },
    ReadError { error: ReadErr },
    Straddled,
    TruncatedHdr { hdr_len_bytes: usize },
    TruncatedOptions { error: ReadErr },
}

impl From<ReadErr> for TcpHdrError {
    fn from(error: ReadErr) -> Self {
        TcpHdrError::ReadError { error }
    }
}

/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, Debug, FromBytes, AsBytes, Unaligned)]
pub struct TcpHdrRaw {
    pub src_port: [u8; 2],
    pub dst_port: [u8; 2],
    pub seq: [u8; 4],
    pub ack: [u8; 4],
    pub offset: u8,
    pub flags: u8,
    pub window_size: [u8; 2],
    pub csum: [u8; 2],
    pub urg: [u8; 2],
}

impl TcpHdrRaw {
    fn offset(&self) -> u8 {
        (self.offset & TCP_HDR_OFFSET_MASK) >> TCP_HDR_OFFSET_SHIFT
    }
}

impl<'a> RawHeader<'a> for TcpHdrRaw {
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

impl From<&TcpMeta> for TcpHdrRaw {
    #[inline]
    fn from(meta: &TcpMeta) -> Self {
        Self {
            src_port: meta.src.to_be_bytes(),
            dst_port: meta.dst.to_be_bytes(),
            seq: meta.seq.to_be_bytes(),
            ack: meta.ack.to_be_bytes(),
            offset: ((meta.hdr_len() as u8 / 4) & 0x0F) << 4,
            flags: meta.flags,
            window_size: meta.window_size.to_be_bytes(),
            csum: meta.csum,
            urg: [0; 2],
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::engine::packet::Packet;

    #[test]
    fn emit_no_opts() {
        let tcp = TcpMeta {
            src: 49154,
            dst: 80,
            seq: 2511121667,
            ack: 754208397,
            flags: TcpFlags::ACK,
            window_size: 64436,
            options_bytes: None,
            options_len: 0,
            csum: [0; 2],
        };

        let len = tcp.hdr_len();
        let mut pkt = Packet::alloc_and_expand(len);
        let mut wtr = pkt.seg0_wtr();
        tcp.emit(wtr.slice_mut(tcp.hdr_len()).unwrap());
        assert_eq!(len, pkt.len());
        #[rustfmt::skip]
        let expected_bytes = vec![
            // source
            0xC0, 0x02,
            // dest
            0x00, 0x50,
            // seq
            0x95, 0xAC, 0xAD, 0x03,
            // ack
            0x2C, 0xF4, 0x4E, 0x8D,
            // offset + flags
            0x50, 0x10,
            // window
            0xFB, 0xB4,
            // checksum
            0x00, 0x00,
            // URG pointer
            0x00, 0x00,
        ];
        assert_eq!(&expected_bytes, pkt.seg_bytes(0));
    }

    #[test]
    fn emit_opts() {
        let mut opts = [0x00; TcpHdr::MAX_OPTION_SIZE];
        let bytes = [
            0x02, 0x04, 0x05, 0xB4, 0x04, 0x02, 0x08, 0x0A, 0x09, 0xB4, 0x2A,
            0xA9, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x01,
        ];
        opts[0..bytes.len()].copy_from_slice(&bytes);

        let tcp = TcpMeta {
            src: 49154,
            dst: 80,
            seq: 2511121590,
            ack: 0,
            flags: TcpFlags::SYN,
            window_size: 64240,
            options_bytes: Some(opts),
            options_len: bytes.len(),
            csum: [0; 2],
        };

        let len = tcp.hdr_len();
        assert_eq!(40, len);
        let mut pkt = Packet::alloc_and_expand(len);
        let mut wtr = pkt.seg0_wtr();
        tcp.emit(wtr.slice_mut(tcp.hdr_len()).unwrap());
        assert_eq!(len, pkt.len());

        #[rustfmt::skip]
        let expected_bytes = vec![
            // source
            0xC0, 0x02,
            // dest
            0x00, 0x50,
            // seq
            0x95, 0xAC, 0xAC, 0xB6,
            // ack
            0x00, 0x00, 0x00, 0x00,
            // offset + flags
            0xA0, 0x02,
            // window
            0xFA, 0xF0,
            // checksum
            0x00, 0x00,
            // URG pointer
            0x00, 0x00,
            // MSS
            0x02, 0x04, 0x05, 0xB4,
            // SACK permitted
            0x04, 0x02,
            // Timestamps
            0x08, 0x0A, 0x09, 0xB4, 0x2A, 0xA9, 0x00, 0x00, 0x00, 0x00,
            // No-op
            0x01,
            // Window Scale
            0x03, 0x03, 0x01,

        ];
        assert_eq!(&expected_bytes, pkt.seg_bytes(0));
    }

    #[test]
    fn parse_no_opts() {
        let hdr_len = TcpHdr::BASE_SIZE;
        #[rustfmt::skip]
        let base_bytes = vec![
            // source
            0xC0, 0x02,
            // dest
            0x00, 0x50,
            // seq
            0x95, 0xAC, 0xAC, 0xB6,
            // ack
            0x00, 0x00, 0x00, 0x00,
            // offset
            ((hdr_len / 4) as u8) << TCP_HDR_OFFSET_SHIFT,
            // flags
            0x02,
            // window
            0xFA, 0xF0,
            // checksum
            0x00, 0x00,
            // URG pointer
            0x00, 0x00,
        ];
        assert_eq!(base_bytes.len(), TcpHdr::BASE_SIZE);

        let mut pkt = Packet::copy(&base_bytes);
        let mut rdr = pkt.get_rdr_mut();
        let tcp_hdr = TcpHdr::parse(&mut rdr).unwrap();

        assert_eq!(tcp_hdr.base_bytes(), &base_bytes);
        assert_eq!(tcp_hdr.options_bytes(), None);
    }

    #[test]
    fn parse_max_opts() {
        #[rustfmt::skip]
        let option_bytes = [
            // MSS
            0x02, 0x04, 0x05, 0xB4,
            // SACK permitted
            0x04, 0x02,
            // Timestamps
            0x08, 0x0A, 0x09, 0xB4, 0x2A, 0xA9, 0x00, 0x00, 0x00, 0x00,
            // No-op
            0x01,
            // Window Scale
            0x03, 0x03, 0x01,
            // No-ops
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        ];

        let hdr_len = TcpHdr::BASE_SIZE + option_bytes.len();
        #[rustfmt::skip]
        let base_bytes = [
            // source
            0xC0, 0x02,
            // dest
            0x00, 0x50,
            // seq
            0x95, 0xAC, 0xAC, 0xB6,
            // ack
            0x00, 0x00, 0x00, 0x00,
            // offset
            ((hdr_len / 4) as u8) << TCP_HDR_OFFSET_SHIFT,
            // flags
            0x02,
            // window
            0xFA, 0xF0,
            // checksum
            0x00, 0x00,
            // URG pointer
            0x00, 0x00,
        ];
        assert_eq!(base_bytes.len(), TcpHdr::BASE_SIZE);

        let pkt_bytes = base_bytes
            .iter()
            .copied()
            .chain(option_bytes.iter().copied())
            .collect::<Vec<_>>();

        let mut pkt = Packet::copy(&pkt_bytes);
        let mut rdr = pkt.get_rdr_mut();
        let tcp_hdr = TcpHdr::parse(&mut rdr).unwrap();

        assert_eq!(tcp_hdr.base_bytes(), &base_bytes);
        assert_eq!(tcp_hdr.options_bytes(), Some(&option_bytes[..]));
    }

    #[test]
    fn parse_opts_truncated() {
        #[rustfmt::skip]
        let option_bytes = [
            // MSS
            0x02, 0x04, 0x05, 0xB4,
            // SACK permitted
            0x04, 0x02,
            // Timestamps
            0x08, 0x0A, 0x09, 0xB4, 0x2A, 0xA9, 0x00, 0x00, 0x00, 0x00,
            // No-op
            0x01,
            // Window Scale
            0x03, 0x03, 0x01,
        ];

        let hdr_len = TcpHdr::BASE_SIZE
            + option_bytes.len()
            // Indicate there's an extra 32-bit word of options
            + 4;

        #[rustfmt::skip]
        let base_bytes = [
            // source
            0xC0, 0x02,
            // dest
            0x00, 0x50,
            // seq
            0x95, 0xAC, 0xAC, 0xB6,
            // ack
            0x00, 0x00, 0x00, 0x00,
            // offset
            ((hdr_len / 4) as u8) << TCP_HDR_OFFSET_SHIFT,
            // flags
            0x02,
            // window
            0xFA, 0xF0,
            // checksum
            0x00, 0x00,
            // URG pointer
            0x00, 0x00,
        ];
        assert_eq!(base_bytes.len(), TcpHdr::BASE_SIZE);

        let pkt_bytes = base_bytes
            .iter()
            .copied()
            .chain(option_bytes.iter().copied())
            .collect::<Vec<_>>();

        let mut pkt = Packet::copy(&pkt_bytes);
        let mut rdr = pkt.get_rdr_mut();
        let tcp_hdr_err = TcpHdr::parse(&mut rdr)
            .expect_err("expected to fail parsing malformed TCP header");

        assert_eq!(
            tcp_hdr_err,
            TcpHdrError::TruncatedOptions { error: ReadErr::NotEnoughBytes }
        );
    }
}

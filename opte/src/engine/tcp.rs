// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use core::convert::TryFrom;
use core::fmt::{self, Display};
use core::mem;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::vec::Vec;
    } else {
        use std::vec::Vec;
    }
}

use serde::{Deserialize, Serialize};
use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

use super::checksum::{Checksum, HeaderChecksum};
use super::headers::{
    Header, HeaderAction, HeaderActionModify, ModActionArg, PushActionArg,
    RawHeader, UlpHdr, UlpMetaModify,
};
use super::packet::{PacketRead, ReadErr, WriteError};
use crate::api::DYNAMIC_PORT;

pub const TCP_HDR_CSUM_OFF: usize = 16;
pub const TCP_HDR_OFFSET_MASK: u8 = 0xF0;
pub const TCP_HDR_OFFSET_SHIFT: u8 = 4;
pub const TCP_HDR_SZ: usize = mem::size_of::<TcpHdrRaw>();

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

#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct TcpMeta {
    pub src: u16,
    pub dst: u16,
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
}

impl TcpMeta {
    pub fn has_flag(&self, flag: u8) -> bool {
        (self.flags & flag) != 0
    }

    // XXX check that at least one field was specified.
    pub fn modify(
        src: Option<u16>,
        dst: Option<u16>,
        flags: Option<u8>,
    ) -> HeaderAction<TcpMeta, TcpMetaOpt> {
        HeaderAction::Modify(TcpMetaOpt { src, dst, flags }.into())
    }
}

impl PushActionArg for TcpMeta {}

impl From<&TcpHdr> for TcpMeta {
    fn from(tcp: &TcpHdr) -> Self {
        TcpMeta {
            src: tcp.src_port,
            dst: tcp.dst_port,
            flags: tcp.flags,
            seq: tcp.seq,
            ack: tcp.ack,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TcpMetaOpt {
    src: Option<u16>,
    dst: Option<u16>,
    flags: Option<u8>,
}

impl ModActionArg for TcpMetaOpt {}

impl HeaderActionModify<TcpMetaOpt> for TcpMeta {
    fn run_modify(&mut self, spec: &TcpMetaOpt) {
        if spec.src.is_some() {
            self.src = spec.src.unwrap()
        }

        if spec.dst.is_some() {
            self.dst = spec.dst.unwrap()
        }

        if spec.flags.is_some() {
            self.flags = spec.flags.unwrap()
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
pub struct TcpHdr {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    hdr_len_bytes: u8,
    flags: u8,
    win: u16,
    csum: [u8; 2],
    csum_minus_hdr: Checksum,
    urg: [u8; 2],
    options_raw: Vec<u8>,
}

#[macro_export]
macro_rules! assert_tcp {
    ($left:expr, $right:expr) => {
        assert!(
            $left.src_port() == $right.src_port(),
            "TCP src port mismatch: {} != {}",
            $left.src_port(),
            $right.src_port(),
        );

        assert!(
            $left.dst_port() == $right.dst_port(),
            "TCP dst port mismatch: {} != {}",
            $left.dst_port(),
            $right.dst_port(),
        );

        assert!(
            $left.seq() == $right.seq(),
            "TCP seq mismatch: {} != {}",
            $left.seq(),
            $right.seq(),
        );

        assert!(
            $left.ack() == $right.ack(),
            "TCP ack mismatch: {} != {}",
            $left.ack(),
            $right.ack(),
        );

        assert!(
            $left.hdr_len() == $right.hdr_len(),
            "TCP hdr len mismatch: {} != {}",
            $left.hdr_len(),
            $right.hdr_len(),
        );

        assert!(
            $left.flags() == $right.flags(),
            "TCP flags mismatch: 0x{:02X} != 0x{:02X}",
            $left.flags(),
            $right.flags(),
        );

        let lcsum = $left.csum();
        let rcsum = $right.csum();

        assert!(
            lcsum == rcsum,
            "TCP csum mismatch: 0x{:02X}{:02X} != 0x{:02X}{:02X}",
            lcsum[0],
            lcsum[1],
            rcsum[0],
            rcsum[1],
        );
    };
}

impl TcpHdr {
    pub fn ack(&self) -> u32 {
        self.ack
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.hdr_len());
        let base = TcpHdrRaw::from(self);
        bytes.extend_from_slice(base.as_bytes());
        bytes.extend_from_slice(&self.options_raw);
        bytes
    }

    pub fn csum(&self) -> [u8; 2] {
        self.csum
    }

    pub fn csum_minus_hdr(&self) -> Checksum {
        self.csum_minus_hdr
    }

    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }

    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Return the length of the header porition of the segment, in bytes.
    pub fn hdr_len(&self) -> usize {
        usize::from(self.hdr_len_bytes)
    }

    #[cfg(any(feature = "std", test))]
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port,
            dst_port,
            seq: 0,
            ack: 0,
            hdr_len_bytes: 20,
            flags: 0x02,
            win: 0,
            csum: [0; 2],
            csum_minus_hdr: Checksum::from(0),
            urg: [0; 2],
            options_raw: vec![],
        }
    }

    /// Return the length of the options portion of the header, in bytes.
    pub fn options_len(&self) -> usize {
        usize::from(self.hdr_len_bytes) - TCP_HDR_SZ
    }

    pub fn set_csum(&mut self, csum: [u8; 2]) {
        self.csum = csum;
    }

    pub fn set_flags(&mut self, flags: u8) {
        self.flags = flags;
    }

    pub fn set_seq(&mut self, seq: u32) {
        self.seq = seq;
    }

    pub fn seq(&self) -> u32 {
        self.seq
    }

    pub fn src_port(&self) -> u16 {
        self.src_port
    }

    pub fn unify(&mut self, meta: &TcpMeta) {
        self.src_port = meta.src;
        self.dst_port = meta.dst;
        self.flags = meta.flags;
    }
}

impl Header for TcpHdr {
    type Error = TcpHdrError;

    fn parse<'a, 'b, R>(rdr: &'b mut R) -> Result<Self, Self::Error>
    where
        R: PacketRead<'a>,
    {
        let raw = TcpHdrRaw::raw_zc(rdr)?;
        let mut tcp = TcpHdr::try_from(&raw)?;

        // Try to read all options as raw byte sequence in its network-order.
        let opts_len = tcp.options_len();
        if opts_len > 0 {
            match rdr.slice(opts_len) {
                Ok(opts) => tcp.options_raw.extend_from_slice(opts),
                Err(e) => {
                    return Err(TcpHdrError::TruncatedOptions { error: e });
                }
            }
        }

        let mut raw_clone = raw.clone();
        raw_clone.csum = [0; 2];
        let hc = HeaderChecksum::wrap(tcp.csum);
        let mut csum_mh = Checksum::from(hc);
        csum_mh.sub(&raw_clone.as_bytes());
        csum_mh.sub(&tcp.options_raw);
        tcp.csum_minus_hdr = csum_mh;
        Ok(tcp)
    }
}

impl From<&TcpMeta> for TcpHdr {
    fn from(meta: &TcpMeta) -> Self {
        TcpHdr {
            src_port: meta.src,
            dst_port: meta.dst,
            seq: 0,
            ack: 0,
            hdr_len_bytes: TCP_HDR_SZ as u8,
            flags: 0,
            win: 0,
            csum: [0; 2],
            csum_minus_hdr: Checksum::from(0),
            urg: [0; 2],
            // For now we simply store the raw options bytes.
            options_raw: vec![],
        }
    }
}

#[derive(Debug)]
pub enum TcpHdrError {
    BadDstPort { dst_port: u16 },
    BadOffset { offset: u8, len_in_bytes: u8 },
    BadSrcPort { src_port: u16 },
    ReadError { error: ReadErr },
    Straddled,
    TruncatedOptions { error: ReadErr },
}

impl From<ReadErr> for TcpHdrError {
    fn from(error: ReadErr) -> Self {
        TcpHdrError::ReadError { error }
    }
}

impl TryFrom<&LayoutVerified<&[u8], TcpHdrRaw>> for TcpHdr {
    type Error = TcpHdrError;

    fn try_from(
        raw: &LayoutVerified<&[u8], TcpHdrRaw>,
    ) -> Result<Self, Self::Error> {
        let src_port = u16::from_be_bytes(raw.src_port);

        if src_port == DYNAMIC_PORT {
            return Err(TcpHdrError::BadSrcPort { src_port });
        }

        let dst_port = u16::from_be_bytes(raw.dst_port);

        if dst_port == DYNAMIC_PORT {
            return Err(TcpHdrError::BadDstPort { dst_port });
        }

        let offset = raw.get_offset();
        let hdr_len_bytes = offset * 4;

        if hdr_len_bytes < 20 {
            return Err(TcpHdrError::BadOffset {
                offset,
                len_in_bytes: hdr_len_bytes,
            });
        }

        let options_len = hdr_len_bytes as usize - TCP_HDR_SZ;
        let options_raw = Vec::with_capacity(options_len);

        Ok(TcpHdr {
            src_port,
            dst_port,
            seq: u32::from_be_bytes(raw.seq),
            ack: u32::from_be_bytes(raw.ack),
            hdr_len_bytes,
            // XXX Could probably validate bad combos of flags and
            // convert to TcpFlags.
            flags: raw.flags,
            win: u16::from_be_bytes(raw.win),
            csum: raw.csum,
            csum_minus_hdr: Checksum::from(0),
            urg: raw.urg,
            options_raw,
        })
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
    pub win: [u8; 2],
    pub csum: [u8; 2],
    pub urg: [u8; 2],
}

impl<'a> TcpHdrRaw {
    fn get_offset(&self) -> u8 {
        (self.offset & TCP_HDR_OFFSET_MASK) >> TCP_HDR_OFFSET_SHIFT
    }
}

impl<'a> RawHeader<'a> for TcpHdrRaw {
    fn raw_zc<'b, R: PacketRead<'a>>(
        rdr: &'b mut R,
    ) -> Result<LayoutVerified<&'a [u8], Self>, ReadErr> {
        let slice = rdr.slice(mem::size_of::<Self>())?;
        let hdr = match LayoutVerified::new(slice) {
            Some(bytes) => bytes,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }

    fn raw_mut_zc(
        dst: &mut [u8],
    ) -> Result<LayoutVerified<&mut [u8], Self>, WriteError> {
        let hdr = match LayoutVerified::new(dst) {
            Some(bytes) => bytes,
            None => return Err(WriteError::BadLayout),
        };
        Ok(hdr)
    }
}

impl From<TcpHdr> for UlpHdr {
    fn from(tcp: TcpHdr) -> Self {
        UlpHdr::Tcp(tcp)
    }
}

impl From<&TcpHdr> for TcpHdrRaw {
    fn from(tcp: &TcpHdr) -> Self {
        TcpHdrRaw {
            src_port: tcp.src_port.to_be_bytes(),
            dst_port: tcp.dst_port.to_be_bytes(),
            seq: tcp.seq.to_be_bytes(),
            ack: tcp.ack.to_be_bytes(),
            offset: (tcp.hdr_len_bytes / 4) << TCP_HDR_OFFSET_SHIFT,
            flags: tcp.flags,
            win: tcp.win.to_be_bytes(),
            csum: tcp.csum,
            urg: tcp.urg,
        }
    }
}

impl From<&TcpMeta> for TcpHdrRaw {
    fn from(meta: &TcpMeta) -> Self {
        TcpHdrRaw {
            src_port: meta.src.to_be_bytes(),
            dst_port: meta.dst.to_be_bytes(),
            seq: meta.seq.to_be_bytes(),
            ack: meta.ack.to_be_bytes(),
            offset: 0,
            flags: meta.flags,
            win: [0; 2],
            csum: [0; 2],
            urg: [0; 2],
        }
    }
}

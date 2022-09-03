// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use core::convert::TryFrom;
use core::mem;
use serde::{Deserialize, Serialize};
use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

use crate::engine::checksum::{Checksum, HeaderChecksum};
use crate::engine::headers::{
    Header, HeaderAction, HeaderActionModify, ModifyActionArg, PushActionArg,
    RawHeader, UlpHdr, UlpMeta, UlpMetaModify, UlpMetaOpt,
};
use crate::engine::packet::{PacketRead, ReadErr, WriteError};
use opte_api::DYNAMIC_PORT;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::vec::Vec;
    } else {
        use std::vec::Vec;
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct UdpMeta {
    pub src: u16,
    pub dst: u16,
}

impl UdpMeta {
    pub fn modify(
        src: Option<u16>,
        dst: Option<u16>,
    ) -> HeaderAction<UdpMeta, UdpMetaOpt> {
        HeaderAction::Modify(UdpMetaOpt { src, dst }.into())
    }

    pub fn push(src: u16, dst: u16) -> HeaderAction<UlpMeta, UlpMetaOpt> {
        HeaderAction::Push(UlpMeta::from(UdpMeta { src, dst }))
    }
}

impl PushActionArg for UdpMeta {}

impl From<&UdpHdr> for UdpMeta {
    fn from(udp: &UdpHdr) -> Self {
        UdpMeta { src: udp.src_port, dst: udp.dst_port }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UdpMetaOpt {
    src: Option<u16>,
    dst: Option<u16>,
}

impl ModifyActionArg for UdpMetaOpt {}

impl HeaderActionModify<UdpMetaOpt> for UdpMeta {
    fn run_modify(&mut self, spec: &UdpMetaOpt) {
        if spec.src.is_some() {
            self.src = spec.src.unwrap()
        }

        if spec.dst.is_some() {
            self.dst = spec.dst.unwrap()
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
pub struct UdpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub csum: [u8; 2],
    pub csum_minus_hdr: Checksum,
}

#[macro_export]
macro_rules! assert_udp {
    ($left:expr, $right:expr) => {
        let lcsum = $left.csum();
        let rcsum = $right.csum();

        assert!(
            $left.src_port() == $right.src_port(),
            "UDP src port mismatch: {} != {}",
            $left.src_port(),
            $right.src_port(),
        );

        assert!(
            $left.dst_port() == $right.dst_port(),
            "UDP dst port mismatch: {} != {}",
            $left.dst_port(),
            $right.dst_port(),
        );

        assert!(
            $left.total_len() == $right.total_len(),
            "UDP length mismatch: {} != {}",
            $left.total_len(),
            $right.total_len(),
        );

        assert!(
            lcsum == rcsum,
            "UDP csum mismatch: 0x{:02X}{:02X} != 0x{:02X}{:02X}",
            lcsum[0],
            lcsum[1],
            rcsum[0],
            rcsum[1],
        );
    };
}

impl UdpHdr {
    pub const CSUM_OFFSET: usize = 6;
    pub const SIZE: usize = mem::size_of::<UdpHdrRaw>();

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.hdr_len());
        let raw = UdpHdrRaw::from(self);
        bytes.extend_from_slice(raw.as_bytes());
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

    pub fn hdr_len(&self) -> usize {
        Self::SIZE
    }

    /// Return the payload length, in bytes.
    pub fn pay_len(&self) -> usize {
        usize::from(self.length) - Self::SIZE
    }

    pub fn set_csum(&mut self, csum: [u8; 2]) {
        self.csum = csum;
    }

    pub fn set_pay_len(&mut self, len: u16) {
        self.length = Self::SIZE as u16 + len;
    }

    pub fn set_total_len(&mut self, len: u16) {
        self.length = len;
    }

    pub fn src_port(&self) -> u16 {
        self.src_port
    }

    pub fn total_len(&self) -> u16 {
        self.length
    }

    pub fn unify(&mut self, meta: &UdpMeta) {
        self.src_port = meta.src;
        self.dst_port = meta.dst;
    }
}

impl Header for UdpHdr {
    type Error = UdpHdrError;

    fn parse<'a, 'b, R>(rdr: &'b mut R) -> Result<Self, Self::Error>
    where
        R: PacketRead<'a>,
    {
        let raw = UdpHdrRaw::raw_zc(rdr)?;
        let mut udp = UdpHdr::try_from(&raw)?;

        if udp.csum != [0; 2] {
            let mut raw_clone = raw.clone();
            raw_clone.csum = [0; 2];
            let hc = HeaderChecksum::wrap(udp.csum);
            let mut csum_mh = Checksum::from(hc);
            csum_mh.sub(&raw_clone.as_bytes());
            udp.csum_minus_hdr = csum_mh;
        }

        Ok(udp)
    }
}

impl From<&UdpMeta> for UdpHdr {
    fn from(meta: &UdpMeta) -> Self {
        UdpHdr {
            src_port: meta.src,
            dst_port: meta.dst,
            length: Self::SIZE as u16,
            csum: [0; 2],
            csum_minus_hdr: Checksum::from(0),
        }
    }
}

#[derive(Debug)]
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

impl TryFrom<&LayoutVerified<&[u8], UdpHdrRaw>> for UdpHdr {
    type Error = UdpHdrError;

    fn try_from(
        raw: &LayoutVerified<&[u8], UdpHdrRaw>,
    ) -> Result<Self, Self::Error> {
        let src_port = u16::from_be_bytes(raw.src_port);

        if src_port == DYNAMIC_PORT {
            return Err(UdpHdrError::BadSrcPort { src_port });
        }

        let dst_port = u16::from_be_bytes(raw.dst_port);

        if dst_port == DYNAMIC_PORT {
            return Err(UdpHdrError::BadDstPort { dst_port });
        }

        let length = u16::from_be_bytes(raw.length);

        if length < UdpHdr::SIZE as u16 {
            return Err(UdpHdrError::BadLength { length });
        }

        Ok(UdpHdr {
            src_port,
            dst_port,
            length,
            csum: raw.csum,
            csum_minus_hdr: Checksum::from(0),
        })
    }
}

impl From<UdpHdr> for UlpHdr {
    fn from(udp: UdpHdr) -> Self {
        UlpHdr::Udp(udp)
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

impl<'a> RawHeader<'a> for UdpHdrRaw {
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

impl Default for UdpHdrRaw {
    fn default() -> Self {
        UdpHdrRaw {
            src_port: [0x0; 2],
            dst_port: [0x0; 2],
            length: [0x0; 2],
            csum: [0x0; 2],
        }
    }
}

impl From<&UdpHdr> for UdpHdrRaw {
    fn from(udp: &UdpHdr) -> Self {
        UdpHdrRaw {
            src_port: udp.src_port.to_be_bytes(),
            dst_port: udp.dst_port.to_be_bytes(),
            length: udp.length.to_be_bytes(),
            csum: udp.csum,
        }
    }
}

impl From<&UdpMeta> for UdpHdrRaw {
    fn from(meta: &UdpMeta) -> Self {
        UdpHdrRaw {
            src_port: meta.src.to_be_bytes(),
            dst_port: meta.dst.to_be_bytes(),
            ..Default::default()
        }
    }
}

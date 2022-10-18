// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use super::ether::EtherType;
use super::ether::ETHER_TYPE_ETHER;
use super::headers::Header;
use super::headers::HeaderAction;
use super::headers::HeaderActionModify;
use super::headers::ModifyActionArg;
use super::headers::PushActionArg;
use super::headers::RawHeader;
use super::packet::PacketRead;
use super::packet::ReadErr;
use super::packet::WriteError;
use core::convert::TryFrom;
use core::mem;
pub use opte_api::Vni;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::LayoutVerified;
use zerocopy::Unaligned;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::vec::Vec;
    } else {
        use std::vec::Vec;
    }
}

pub const GENEVE_VSN: u8 = 0;
pub const GENEVE_VER_MASK: u8 = 0xC0;
pub const GENEVE_VER_SHIFT: u8 = 6;
pub const GENEVE_OPT_LEN_MASK: u8 = 0x3F;
pub const GENEVE_PORT: u16 = 6081;

#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct GeneveMeta {
    pub vni: Vni,
}

impl PushActionArg for GeneveMeta {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneveMetaOpt {
    vni: Option<Vni>,
}

impl ModifyActionArg for GeneveMetaOpt {}

impl GeneveMeta {
    pub fn push(vni: Vni) -> HeaderAction<GeneveMeta, GeneveMetaOpt> {
        HeaderAction::Push(GeneveMeta { vni })
    }
}

impl From<&GeneveHdr> for GeneveMeta {
    fn from(geneve: &GeneveHdr) -> Self {
        Self { vni: geneve.vni }
    }
}

impl From<&GeneveHdrRaw> for GeneveMeta {
    fn from(raw: &GeneveHdrRaw) -> Self {
        let vni = Vni::new(u32::from_be_bytes([
            0, raw.vni[0], raw.vni[1], raw.vni[2],
        ]))
        .expect("need to verify this beforehand");

        Self { vni }
    }
}

impl HeaderActionModify<GeneveMetaOpt> for GeneveMeta {
    fn run_modify(&mut self, spec: &GeneveMetaOpt) {
        if spec.vni.is_some() {
            self.vni = spec.vni.unwrap();
        }
    }
}

#[derive(Debug)]
pub struct GeneveHdr {
    pub opt_len_bytes: u16,
    pub flags: u8,
    // The Geneve spec calls names this field the "protocol", but its
    // value is an Ether Type.
    pub proto: EtherType,
    pub vni: Vni,
}

impl GeneveHdr {
    // This is for the base header size only.
    pub const SIZE: usize = mem::size_of::<GeneveHdrRaw>();

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.hdr_len());
        let raw = GeneveHdrRaw::from(self);
        bytes.extend_from_slice(raw.as_bytes());
        bytes
    }

    pub fn hdr_len(&self) -> usize {
        usize::from(self.opt_len_bytes) + Self::SIZE
    }

    pub fn new(proto: EtherType, vni: Vni) -> Self {
        Self { opt_len_bytes: 0, flags: 0, proto, vni }
    }

    pub fn options_len_bytes(&self) -> usize {
        usize::from(self.opt_len_bytes)
    }
}

impl Header for GeneveHdr {
    type Error = GeneveHdrError;

    fn parse<'a, 'b, R>(rdr: &'b mut R) -> Result<Self, GeneveHdrError>
    where
        R: PacketRead<'a>,
    {
        GeneveHdr::try_from(&GeneveHdrRaw::raw_zc(rdr)?)
    }
}

impl From<&GeneveMeta> for GeneveHdr {
    fn from(meta: &GeneveMeta) -> Self {
        GeneveHdr {
            opt_len_bytes: 0,
            flags: 0,
            proto: EtherType::Ether,
            vni: meta.vni,
        }
    }
}

#[derive(Debug)]
pub enum GeneveHdrError {
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

impl TryFrom<&LayoutVerified<&[u8], GeneveHdrRaw>> for GeneveHdr {
    type Error = GeneveHdrError;

    fn try_from(
        raw: &LayoutVerified<&[u8], GeneveHdrRaw>,
    ) -> Result<Self, Self::Error> {
        let vsn = raw.version();

        if raw.version() != GENEVE_VSN {
            return Err(GeneveHdrError::BadVersion { vsn });
        }

        if raw.options_len() > 0 {
            todo!("implement geneve options");
        }

        let proto = EtherType::try_from(u16::from_be_bytes(raw.proto))
            .map_err(|_s| GeneveHdrError::UnexpectedProtocol {
                protocol: u16::from_be_bytes(raw.proto),
            })?;

        let vni = Vni::new(u32::from_be_bytes([
            0, raw.vni[0], raw.vni[1], raw.vni[2],
        ]))
        .map_err(|_s| GeneveHdrError::BadVni {
            vni: u32::from_be_bytes([0, raw.vni[0], raw.vni[1], raw.vni[2]]),
        })?;

        Ok(GeneveHdr {
            opt_len_bytes: raw.options_len() as u16 * 4,
            flags: raw.flags,
            proto,
            vni,
        })
    }
}

/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, Debug, FromBytes, AsBytes, Unaligned)]
pub struct GeneveHdrRaw {
    pub ver_opt_len: u8,
    pub flags: u8,
    pub proto: [u8; 2],
    pub vni: [u8; 3],
    pub reserved: u8,
}

impl<'a> GeneveHdrRaw {
    // Return the length of the Geneve options.
    //
    // NOTE: The Geneve header specifies options length in 4-byte units.
    pub fn options_len(&self) -> u8 {
        self.ver_opt_len & GENEVE_OPT_LEN_MASK
    }

    fn version(&self) -> u8 {
        (self.ver_opt_len & GENEVE_VER_MASK) >> GENEVE_VER_SHIFT
    }
}

impl<'a> RawHeader<'a> for GeneveHdrRaw {
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

impl Default for GeneveHdrRaw {
    fn default() -> Self {
        GeneveHdrRaw {
            ver_opt_len: 0x0,
            flags: 0x0,
            proto: ETHER_TYPE_ETHER.to_be_bytes(),
            vni: [0x0; 3],
            reserved: 0,
        }
    }
}

impl From<&GeneveHdr> for GeneveHdrRaw {
    fn from(geneve: &GeneveHdr) -> Self {
        let opt_len_words = geneve.opt_len_bytes / 4;

        GeneveHdrRaw {
            ver_opt_len: opt_len_words as u8,
            flags: geneve.flags,
            proto: (geneve.proto as u16).to_be_bytes(),
            vni: geneve.vni.bytes(),
            reserved: 0,
        }
    }
}

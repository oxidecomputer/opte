// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! ARP headers and data.

use super::ether::EtherHdr;
use super::ether::EtherMeta;
use super::ether::EtherType;
use super::headers::RawHeader;
use super::packet::Initialized;
use super::packet::Packet;
use super::packet::PacketReadMut;
use super::packet::ReadErr;
use crate::d_error::DError;
use core::fmt;
use core::fmt::Display;
use opte_api::Ipv4Addr;
use opte_api::MacAddr;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::Ref;
use zerocopy::Unaligned;

pub const ARP_HTYPE_ETHERNET: u16 = 1;

#[repr(u16)]
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum ArpOp {
    Request = 1,
    Reply = 2,
}

impl ArpOp {
    pub fn to_be_bytes(self) -> [u8; 2] {
        match self {
            ArpOp::Request => 1u16.to_be_bytes(),
            ArpOp::Reply => 2u16.to_be_bytes(),
        }
    }
}

impl TryFrom<u16> for ArpOp {
    type Error = ArpHdrError;

    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            1 => Ok(ArpOp::Request),
            2 => Ok(ArpOp::Reply),
            _ => Err(Self::Error::BadOp { op: val }),
        }
    }
}

impl Display for ArpOp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            ArpOp::Request => "Request",
            ArpOp::Reply => "Reply",
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone, Copy, Debug, DError, Eq, PartialEq)]
#[derror(leaf_data = ArpHdrError::derror_data)]
pub enum ArpHdrError {
    BadOp { op: u16 },
    ReadError(ReadErr),
    UnexpectedProtoLen { plen: u8 },
    UnexpectedProtoType { ptype: u16 },
    UnexpectedHwLen { hlen: u8 },
    UnexpectedHwType { htype: u16 },
}

impl ArpHdrError {
    fn derror_data(&self, data: &mut [u64]) {
        data[0] = match self {
            Self::BadOp { op } => *op as u64,
            Self::UnexpectedProtoLen { plen } => *plen as u64,
            Self::UnexpectedProtoType { ptype } => *ptype as u64,
            Self::UnexpectedHwLen { hlen } => *hlen as u64,
            Self::UnexpectedHwType { htype } => *htype as u64,
            _ => 0,
        };
    }
}

impl From<ReadErr> for ArpHdrError {
    fn from(error: ReadErr) -> Self {
        Self::ReadError(error)
    }
}

/// Generate an ARP reply from SHA/SPA to THA/TPA.
pub fn gen_arp_reply(
    sha: MacAddr,
    spa: Ipv4Addr,
    tha: MacAddr,
    tpa: Ipv4Addr,
) -> Packet<Initialized> {
    let len = EtherHdr::SIZE + ArpEthIpv4Raw::SIZE;
    let mut pkt = Packet::alloc_and_expand(len);
    let mut wtr = pkt.seg0_wtr();

    let eth = EtherMeta { dst: tha, src: sha, ether_type: EtherType::Arp };

    let arp = ArpEthIpv4 {
        htype: ARP_HTYPE_ETHERNET,
        ptype: u16::from(EtherType::Ipv4),
        hlen: 6,
        plen: 4,
        op: ArpOp::Reply,
        sha,
        spa,
        tha,
        tpa,
    };

    eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
    arp.emit(wtr.slice_mut(ArpEthIpv4::SIZE).unwrap());
    pkt
}

#[derive(Clone, Copy, Debug)]
pub struct ArpEthIpv4 {
    pub htype: u16,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub op: ArpOp,
    pub sha: MacAddr,
    pub spa: Ipv4Addr,
    pub tha: MacAddr,
    pub tpa: Ipv4Addr,
}

impl ArpEthIpv4 {
    pub const SIZE: usize = ArpEthIpv4Raw::SIZE;

    pub fn emit(&self, dst: &mut [u8]) {
        debug_assert_eq!(dst.len(), ArpEthIpv4Raw::SIZE);
        let mut raw = ArpEthIpv4Raw::new_mut(dst).unwrap();
        raw.write(ArpEthIpv4Raw::from(self));
    }

    pub fn parse<'a, 'b, R>(rdr: &'b mut R) -> Result<Self, ArpHdrError>
    where
        R: PacketReadMut<'a>,
    {
        let src = rdr.slice_mut(ArpEthIpv4Raw::SIZE)?;
        Self::try_from(&ArpEthIpv4Raw::new(src)?)
    }

    pub fn parse_normally(rdr: &[&[u8]]) -> Result<Self, ArpHdrError> {
        let space_in_front = rdr.get(0).map(|v| !v.is_empty());

        let to_use = match space_in_front {
            None => {
                return Err(ArpHdrError::ReadError(ReadErr::NotEnoughBytes))
            }
            Some(true) => rdr.get(0),
            Some(false) => rdr.get(1),
        };

        if let Some(to_use) = to_use {
            Self::try_from(&ArpEthIpv4Raw::new(to_use)?)
        } else {
            Err(ArpHdrError::ReadError(ReadErr::NotEnoughBytes))
        }
    }
}

impl TryFrom<&Ref<&[u8], ArpEthIpv4Raw>> for ArpEthIpv4 {
    type Error = ArpHdrError;

    // NOTE: This only accepts IPv4/Ethernet ARP.
    fn try_from(raw: &Ref<&[u8], ArpEthIpv4Raw>) -> Result<Self, Self::Error> {
        let htype = u16::from_be_bytes(raw.htype);

        if htype != ARP_HTYPE_ETHERNET {
            return Err(Self::Error::UnexpectedHwType { htype });
        }

        let hlen = raw.hlen;

        if hlen != 6 {
            return Err(Self::Error::UnexpectedHwLen { hlen });
        }

        let ptype = u16::from_be_bytes(raw.ptype);

        if ptype != super::ether::ETHER_TYPE_IPV4 {
            return Err(Self::Error::UnexpectedProtoType { ptype });
        }

        let plen = raw.plen;

        if plen != 4 {
            return Err(Self::Error::UnexpectedProtoLen { plen });
        }

        let op = ArpOp::try_from(u16::from_be_bytes(raw.op))?;

        Ok(Self {
            htype,
            ptype,
            hlen,
            plen,
            op,
            sha: MacAddr::from(raw.sha),
            spa: Ipv4Addr::from(u32::from_be_bytes(raw.spa)),
            tha: MacAddr::from(raw.tha),
            tpa: Ipv4Addr::from(u32::from_be_bytes(raw.tpa)),
        })
    }
}

impl From<&ArpEthIpv4> for ArpEthIpv4Raw {
    fn from(arp: &ArpEthIpv4) -> Self {
        Self {
            htype: arp.htype.to_be_bytes(),
            ptype: arp.ptype.to_be_bytes(),
            hlen: arp.hlen,
            plen: arp.plen,
            op: arp.op.to_be_bytes(),
            sha: arp.sha.bytes(),
            spa: arp.spa.bytes(),
            tha: arp.tha.bytes(),
            tpa: arp.tpa.bytes(),
        }
    }
}

#[repr(C)]
#[derive(
    IntoBytes, Clone, Debug, FromBytes, Unaligned, Immutable, KnownLayout,
)]
pub struct ArpEthIpv4Raw {
    pub htype: [u8; 2],
    pub ptype: [u8; 2],
    pub hlen: u8,
    pub plen: u8,
    pub op: [u8; 2],
    pub sha: [u8; 6],
    pub spa: [u8; 4],
    pub tha: [u8; 6],
    pub tpa: [u8; 4],
}

impl<'a> RawHeader<'a> for ArpEthIpv4Raw {
    #[inline]
    fn new_mut(src: &mut [u8]) -> Result<Ref<&mut [u8], Self>, ReadErr> {
        debug_assert_eq!(src.len(), Self::SIZE);
        let hdr = match Ref::from_bytes(src).ok() {
            Some(hdr) => hdr,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }

    fn new(src: &[u8]) -> Result<Ref<&[u8], Self>, ReadErr> {
        debug_assert_eq!(src.len(), Self::SIZE);
        let hdr = match Ref::from_bytes(src).ok() {
            Some(hdr) => hdr,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }
}

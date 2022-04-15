/// Address Resolution Protocol
///
/// Relevant Docs
///
/// * RFD 9 -- NETWORKING CONSIDERATIONS
/// ** §1.13 ARP
/// * RFC 826 -- An Ethernet Address Resolution Protocol
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

use super::ether::{
    EtherHdr, EtherMeta, ETHER_HDR_SZ, ETHER_TYPE_ARP, ETHER_TYPE_IPV4,
};
use super::headers::{Header, RawHeader};
use super::packet::{
    Packet, PacketMeta, PacketRead, PacketReader, PacketWriter, Parsed,
    ReadErr, WriteError,
};
use super::rule::{
    AllowOrDeny, ArpHtypeMatch, ArpOpMatch, ArpPtypeMatch, DataPredicate,
    EtherAddrMatch, EtherTypeMatch, GenPacketResult, HairpinAction,
    Ipv4AddrMatch, Payload, Predicate,
};
use crate::api::{Ipv4Addr, MacAddr};

pub const ARP_HTYPE_ETHERNET: u16 = 1;

pub const ARP_HDR_SZ: usize = mem::size_of::<ArpHdrRaw>();
pub const ARP_ETH4_PAYLOAD_SZ: usize = mem::size_of::<ArpEth4PayloadRaw>();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArpHardware {
    Ethernet(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArpProtocol {
    Ip4(u8),
}

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

#[derive(
    Clone, Debug, Eq, Deserialize, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct ArpMeta {
    pub htype: u16,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub op: ArpOp,
}

impl From<&ArpHdr> for ArpMeta {
    fn from(arp: &ArpHdr) -> Self {
        Self {
            htype: arp.htype,
            ptype: arp.ptype,
            hlen: arp.hlen,
            plen: arp.plen,
            op: arp.op,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ArpHdr {
    htype: u16,
    ptype: u16,
    hlen: u8,
    plen: u8,
    op: ArpOp,
}

impl ArpHdr {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ARP_HDR_SZ);
        let raw = ArpHdrRaw::from(self);
        bytes.extend_from_slice(raw.as_bytes());
        bytes
    }

    pub fn unify(&mut self, meta: &ArpMeta) {
        self.htype = meta.htype;
        self.ptype = meta.ptype;
        self.hlen = meta.hlen;
        self.plen = meta.plen;
        self.op = meta.op;
    }
}

impl Header for ArpHdr {
    type Error = ArpHdrError;

    fn parse<'a, 'b, R>(rdr: &'b mut R) -> Result<Self, Self::Error>
    where
        R: PacketRead<'a>,
    {
        Self::try_from(&ArpHdrRaw::raw_zc(rdr)?)
    }
}

#[derive(Debug)]
pub enum ArpHdrError {
    BadOp { op: u16 },
    ReadError { error: ReadErr },
    UnexpectedProtoLen { plen: u8 },
    UnexpectedProtoType { ptype: u16 },
    UnexpectedHwLen { hlen: u8 },
    UnexpectedHwType { htype: u16 },
}

impl From<ReadErr> for ArpHdrError {
    fn from(error: ReadErr) -> Self {
        Self::ReadError { error }
    }
}

impl TryFrom<&LayoutVerified<&[u8], ArpHdrRaw>> for ArpHdr {
    type Error = ArpHdrError;

    // NOTE: This only accepts IPv4/Ethernet ARP.
    fn try_from(
        raw: &LayoutVerified<&[u8], ArpHdrRaw>,
    ) -> Result<Self, Self::Error> {
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

        Ok(Self { htype, ptype, hlen, plen, op })
    }
}

impl From<&ArpMeta> for ArpHdr {
    fn from(meta: &ArpMeta) -> Self {
        Self {
            htype: meta.htype,
            ptype: meta.ptype,
            hlen: meta.hlen,
            plen: meta.plen,
            op: meta.op,
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug, FromBytes, AsBytes, Unaligned)]
pub struct ArpHdrRaw {
    pub htype: [u8; 2],
    pub ptype: [u8; 2],
    pub hlen: u8,
    pub plen: u8,
    pub op: [u8; 2],
}

impl<'a> RawHeader<'a> for ArpHdrRaw {
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

impl From<&ArpHdr> for ArpHdrRaw {
    fn from(arp: &ArpHdr) -> Self {
        Self {
            htype: arp.htype.to_be_bytes(),
            ptype: arp.ptype.to_be_bytes(),
            hlen: arp.hlen,
            plen: arp.plen,
            op: arp.op.to_be_bytes(),
        }
    }
}

impl From<&ArpMeta> for ArpHdrRaw {
    fn from(meta: &ArpMeta) -> Self {
        Self {
            htype: meta.htype.to_be_bytes(),
            ptype: meta.ptype.to_be_bytes(),
            hlen: meta.hlen,
            plen: meta.plen,
            op: meta.op.to_be_bytes(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ArpEth4Payload {
    pub sha: MacAddr,
    pub spa: Ipv4Addr,
    pub tha: MacAddr,
    pub tpa: Ipv4Addr,
}

impl Payload for ArpEth4Payload {}

impl From<&LayoutVerified<&[u8], ArpEth4PayloadRaw>> for ArpEth4Payload {
    fn from(raw: &LayoutVerified<&[u8], ArpEth4PayloadRaw>) -> Self {
        ArpEth4Payload {
            sha: MacAddr::from(raw.sha),
            spa: Ipv4Addr::from(u32::from_be_bytes(raw.spa)),
            tha: MacAddr::from(raw.tha),
            tpa: Ipv4Addr::from(u32::from_be_bytes(raw.tpa)),
        }
    }
}

#[repr(C)]
#[derive(AsBytes, Clone, Debug, FromBytes, Unaligned)]
pub struct ArpEth4PayloadRaw {
    sha: [u8; 6],
    spa: [u8; 4],
    tha: [u8; 6],
    tpa: [u8; 4],
}

impl<'a> ArpEth4PayloadRaw {
    pub fn parse<'b, R: PacketRead<'a>>(
        rdr: &'b mut R,
    ) -> Result<LayoutVerified<&'a [u8], Self>, ReadErr> {
        let slice = rdr.slice(mem::size_of::<Self>())?;
        let hdr = match LayoutVerified::new(slice) {
            Some(bytes) => bytes,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }
}

impl From<ArpEth4Payload> for ArpEth4PayloadRaw {
    fn from(arp: ArpEth4Payload) -> Self {
        ArpEth4PayloadRaw {
            sha: arp.sha.bytes(),
            spa: arp.spa.bytes(),
            tha: arp.tha.bytes(),
            tpa: arp.tpa.bytes(),
        }
    }
}

impl ArpEth4PayloadRaw {
    pub fn from_bytes(bytes: &[u8]) -> Option<LayoutVerified<&[u8], Self>> {
        LayoutVerified::new_unaligned(bytes)
    }
}

/// Generate an ARP Reply mapping the TPA to the THA.
pub struct ArpReply {
    tpa: Ipv4Addr,
    tha: MacAddr,
}

impl ArpReply {
    pub fn new(tpa: Ipv4Addr, tha: MacAddr) -> Self {
        ArpReply { tpa, tha }
    }
}

impl fmt::Display for ArpReply {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ArpReply {} => {}", self.tpa, self.tha)
    }
}

impl HairpinAction for ArpReply {
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        let hdr_preds = vec![
            Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(
                ETHER_TYPE_ARP,
            )]),
            Predicate::InnerEtherDst(vec![EtherAddrMatch::Exact(
                MacAddr::BROADCAST,
            )]),
            Predicate::InnerArpHtype(ArpHtypeMatch::Exact(1)),
            Predicate::InnerArpPtype(ArpPtypeMatch::Exact(ETHER_TYPE_IPV4)),
            Predicate::InnerArpOp(ArpOpMatch::Exact(ArpOp::Request)),
        ];

        let data_preds =
            vec![DataPredicate::InnerArpTpa(vec![Ipv4AddrMatch::Exact(
                self.tpa,
            )])];

        (hdr_preds, data_preds)
    }

    fn gen_packet(
        &self,
        meta: &PacketMeta,
        rdr: &mut PacketReader<Parsed, ()>,
    ) -> GenPacketResult {
        // TODO Add 2 bytes to alloc and push b_rptr/b_wptr to make
        // sure IP header is properly aligned.
        let pkt =
            Packet::alloc(ETHER_HDR_SZ + ARP_HDR_SZ + ARP_ETH4_PAYLOAD_SZ);
        let mut wtr = PacketWriter::new(pkt, None);

        let ethm = &meta.inner.ether.as_ref().unwrap();
        let req_raw = ArpEth4PayloadRaw::parse(rdr)?;
        let req = ArpEth4Payload::from(&req_raw);

        let eth_hdr = EtherHdr::from(&EtherMeta {
            dst: ethm.src,
            src: self.tha.into(),
            ether_type: ETHER_TYPE_ARP,
        });

        let _ = wtr.write(&eth_hdr.as_bytes()).unwrap();

        let arp_hdr = ArpHdrRaw::from(&ArpMeta {
            htype: ARP_HTYPE_ETHERNET,
            ptype: ETHER_TYPE_IPV4,
            hlen: 6,
            plen: 4,
            op: ArpOp::Reply,
        });

        let _ = wtr.write(arp_hdr.as_bytes()).unwrap();

        let payload = ArpEth4PayloadRaw::from(ArpEth4Payload {
            sha: self.tha,
            spa: self.tpa,
            tha: req.sha,
            tpa: req.spa,
        });

        let _ = wtr.write(payload.as_bytes()).unwrap();
        let pkt = wtr.finish();
        Ok(AllowOrDeny::Allow(pkt))
    }
}

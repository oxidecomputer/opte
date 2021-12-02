/// Address Resolution Protocol
///
/// Relevant Docs
///
/// * RFD 9 -- NETWORKING CONSIDERATIONS
/// ** §1.13 ARP
/// * RFC 826 -- An Ethernet Address Resolution Protocol
use core::convert::TryFrom;
use core::fmt::{self, Display};

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::string::String;
#[cfg(any(feature = "std", test))]
use std::string::String;

use serde::{Deserialize, Serialize};

use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

use crate::ether::{
    EtherAddr, EtherHdrRaw, EtherMeta, ETHER_HDR_SZ, ETHER_TYPE_ARP,
    ETHER_TYPE_IPV4,
};
use crate::ip4::Ipv4Addr;
use crate::packet::{
    Initialized, Packet, PacketMeta, PacketRead, PacketReader, PacketWriter,
    Parsed, ReadErr,
};
use crate::rule::{GenErr, GenResult, HairpinAction, Payload};

pub const ARP_HTYPE_ETHERNET: u16 = 1;

pub const ARP_HDR_SZ: usize = std::mem::size_of::<ArpHdrRaw>();
pub const ARP_ETH4_PAYLOAD_SZ: usize = std::mem::size_of::<ArpEth4PayloadRaw>();

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
    fn to_be_bytes(self) -> [u8; 2] {
        match self {
            ArpOp::Request => 1u16.to_be_bytes(),
            ArpOp::Reply => 2u16.to_be_bytes(),
        }
    }
}

impl TryFrom<u16> for ArpOp {
    type Error = String;

    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            1 => Ok(ArpOp::Request),
            2 => Ok(ArpOp::Reply),
            _ => Err(format!("bad ARP oper: {}", val)),
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

impl TryFrom<&LayoutVerified<&[u8], ArpHdrRaw>> for ArpMeta {
    type Error = String;

    fn try_from(
        raw: &LayoutVerified<&[u8], ArpHdrRaw>,
    ) -> Result<Self, String> {
        let op = ArpOp::try_from(u16::from_be_bytes(raw.op))?;

        Ok(ArpMeta {
            htype: u16::from_be_bytes(raw.htype),
            ptype: u16::from_be_bytes(raw.ptype),
            hlen: raw.hlen,
            plen: raw.plen,
            op,
        })
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

impl ArpHdrRaw {
    pub fn parse<R: PacketRead>(
        rdr: &mut R,
    ) -> Result<LayoutVerified<&[u8], Self>, ReadErr> {
        let slice = rdr.slice(std::mem::size_of::<Self>())?;
        let hdr = match LayoutVerified::new(slice) {
            Some(bytes) => bytes,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }
}

impl From<&ArpMeta> for ArpHdrRaw {
    fn from(meta: &ArpMeta) -> Self {
        ArpHdrRaw {
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
    pub sha: EtherAddr,
    pub spa: Ipv4Addr,
    pub tha: EtherAddr,
    pub tpa: Ipv4Addr,
}

impl Payload for ArpEth4Payload {}

impl From<&LayoutVerified<&[u8], ArpEth4PayloadRaw>> for ArpEth4Payload {
    fn from(raw: &LayoutVerified<&[u8], ArpEth4PayloadRaw>) -> Self {
        ArpEth4Payload {
            sha: EtherAddr::from(raw.sha),
            spa: Ipv4Addr::from(u32::from_be_bytes(raw.spa)),
            tha: EtherAddr::from(raw.tha),
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

impl ArpEth4PayloadRaw {
    pub fn parse<R: PacketRead>(
        rdr: &mut R,
    ) -> Result<LayoutVerified<&[u8], Self>, ReadErr> {
        let slice = rdr.slice(std::mem::size_of::<Self>())?;
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
            sha: arp.sha.to_bytes(),
            spa: arp.spa.to_be_bytes(),
            tha: arp.tha.to_bytes(),
            tpa: arp.tpa.to_be_bytes(),
        }
    }
}

impl ArpEth4PayloadRaw {
    pub fn from_bytes(bytes: &[u8]) -> Option<LayoutVerified<&[u8], Self>> {
        LayoutVerified::new_unaligned(bytes)
    }
}

/// Generate an ARP Reply mapping the TPA to the THA. It is expected
/// this is paired with a rule which filters on the TPA of an ARP
/// Request.
pub struct ArpReply {
    tpa: Ipv4Addr,
    tha: EtherAddr,
}

impl ArpReply {
    pub fn new(tpa: Ipv4Addr, tha: EtherAddr) -> Self {
        ArpReply { tpa, tha }
    }
}

impl HairpinAction for ArpReply {
    fn gen_packet(
        &self,
        meta: &PacketMeta,
        rdr: &mut PacketReader<Parsed, ()>,
    ) -> GenResult<Packet<Initialized>> {
        // TODO Add 2 bytes to alloc and push b_rptr/b_wptr to make
        // sure IP header is properly aligned.
        let pkt =
            Packet::alloc(ETHER_HDR_SZ + ARP_HDR_SZ + ARP_ETH4_PAYLOAD_SZ);
        let mut wtr = PacketWriter::new(pkt, None);

        let ethm = match meta.inner_ether.as_ref() {
            Some(v) => v,
            None => return Err(GenErr::MissingMeta),
        };

        let req_raw = match ArpEth4PayloadRaw::parse(rdr) {
            Ok(v) => v,
            Err(e) => return Err(GenErr::BadPayload(e)),
        };

        let req = ArpEth4Payload::from(&req_raw);

        let eth_hdr = EtherHdrRaw::from(&EtherMeta {
            dst: ethm.src,
            src: self.tha,
            ether_type: ETHER_TYPE_ARP,
        });

        let _ = wtr.write(eth_hdr.as_bytes()).unwrap();

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
        Ok(pkt)
    }
}

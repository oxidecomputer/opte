/// Address Resolution Protocol
///
/// Relevant Docs
///
/// * RFD 9 -- NETWORKING CONSIDERATIONS
/// ** §1.13 ARP
/// * RFC 826 -- An Ethernet Address Resolution Protocol
use crate::input::{PacketReader, ReadErr};

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::prelude::v1::*;

#[cfg(any(feature = "std", test))]
use std::prelude::v1::*;

use std::convert::TryFrom;
use std::mem::size_of;

use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

pub const ARP_HTYPE_ETHERNET: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArpHardware {
    Ethernet(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArpProtocol {
    Ip4(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArpOp {
    Req,
    Reply,
}

impl TryFrom<u16> for ArpOp {
    type Error = String;

    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            1 => Ok(ArpOp::Req),
            2 => Ok(ArpOp::Reply),
            _ => Err(format!("bad ARP oper: {}", val)),
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

impl ArpHdrRaw {
    // TODO avoid trait object.
    pub fn parse<R: PacketReader>(
        rdr: &mut dyn PacketReader,
    ) -> Result<LayoutVerified<&[u8], Self>, ReadErr> {
        let slice = rdr.get_slice(size_of::<Self>())?;
        let hdr = match LayoutVerified::new(slice) {
            Some(bytes) => bytes,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }
}

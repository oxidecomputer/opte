//! ICMP headers.
//!
//! We treat each ICMP type as its own header type. When parsing, we
//! use `IcmpBaseHdrRaw` to determine which type of ICMP message we
//! are ultimately parsing.
use std::mem;

extern crate zerocopy;
use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

use crate::input::{PacketReader, ReadErr};

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACHABLE: u8 = 3;
pub const ICMP_ECHO: u8 = 8;

/// The base ICMP header
/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, FromBytes, AsBytes, Unaligned)]
pub struct IcmpBaseHdrRaw {
    pub icmp_type: u8,
    pub code: u8,
    pub csum: [u8; 2],
}

impl IcmpBaseHdrRaw {
    // TODO avoid trait object.
    pub fn parse<R: PacketReader>(
        rdr: &mut dyn PacketReader,
    ) -> Result<LayoutVerified<&[u8], Self>, ReadErr> {
        let slice = rdr.get_slice(mem::size_of::<Self>())?;
        let hdr = match LayoutVerified::new(slice) {
            Some(bytes) => bytes,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }

    pub fn parse_mut<R: PacketReader>(
        rdr: &mut dyn PacketReader,
    ) -> Result<LayoutVerified<&mut [u8], Self>, ReadErr> {
        let slice = rdr.get_slice_mut(mem::size_of::<Self>())?;
        let hdr = match LayoutVerified::new(slice) {
            Some(bytes) => bytes,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }
}

/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, FromBytes, AsBytes, Unaligned)]
pub struct IcmpEchoHdrRaw {
    pub icmp_type: u8,
    pub code: u8,
    pub csum: [u8; 2],
    pub id: [u8; 2],
    pub seq: [u8; 2],
}

impl IcmpEchoHdrRaw {
    // TODO avoid trait object.
    pub fn parse<R: PacketReader>(
        rdr: &mut dyn PacketReader,
    ) -> Result<LayoutVerified<&[u8], Self>, ReadErr> {
        let slice = rdr.get_slice(mem::size_of::<Self>())?;
        let hdr = match LayoutVerified::new(slice) {
            Some(bytes) => bytes,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }

    pub fn parse_mut<R: PacketReader>(
        rdr: &mut dyn PacketReader,
    ) -> Result<LayoutVerified<&mut [u8], Self>, ReadErr> {
        let slice = rdr.get_slice_mut(mem::size_of::<Self>())?;
        let hdr = match LayoutVerified::new(slice) {
            Some(bytes) => bytes,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }
}

/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, FromBytes, AsBytes, Unaligned)]
pub struct IcmpDuHdrRaw {
    pub icmp_type: u8,
    pub code: u8,
    pub csum: [u8; 2],
    pub unused: [u8; 4],
    pub ip_hdr: [u8; 20],
    pub ulp_start: [u8; 8],
}

impl IcmpDuHdrRaw {
    // TODO avoid trait object.
    pub fn parse<R: PacketReader>(
        rdr: &mut dyn PacketReader,
    ) -> Result<LayoutVerified<&[u8], Self>, ReadErr> {
        let slice = rdr.get_slice(mem::size_of::<Self>())?;
        let hdr = match LayoutVerified::new(slice) {
            Some(bytes) => bytes,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }

    pub fn parse_mut<R: PacketReader>(
        rdr: &mut dyn PacketReader,
    ) -> Result<LayoutVerified<&mut [u8], Self>, ReadErr> {
        let slice = rdr.get_slice_mut(mem::size_of::<Self>())?;
        let hdr = match LayoutVerified::new(slice) {
            Some(bytes) => bytes,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }
}

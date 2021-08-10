extern crate zerocopy;
use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

use crate::input::{PacketReader, ReadErr};

use std::mem::size_of;

pub const ETHER_TYPE_IPV4: u16 = 0x0800;
pub const ETHER_TYPE_ARP: u16 = 0x0806;

pub const ETHER_ADDR_LEN: usize = 6;

pub type EtherAddr = [u8; ETHER_ADDR_LEN];

/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, Debug, FromBytes, AsBytes, Unaligned)]
pub struct EtherHdrRaw {
    pub dst: EtherAddr,
    pub src: EtherAddr,
    pub ether_type: [u8; 2],
}

impl EtherHdrRaw {
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

    pub fn parse_mut<R: PacketReader>(
        rdr: &mut dyn PacketReader,
    ) -> Result<LayoutVerified<&mut [u8], Self>, ReadErr> {
        let slice = rdr.get_slice_mut(size_of::<Self>())?;
        let hdr = match LayoutVerified::new(slice) {
            Some(bytes) => bytes,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }
}

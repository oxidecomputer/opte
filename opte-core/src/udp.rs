extern crate zerocopy;
use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

use crate::input::{PacketReader, ReadErr};

use std::mem::size_of;

/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, FromBytes, AsBytes, Unaligned)]
pub struct UdpHdrRaw {
    pub src_port: [u8; 2],
    pub dst_port: [u8; 2],
    pub length: [u8; 2],
    pub csum: [u8; 2],
}

impl UdpHdrRaw {
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

extern crate zerocopy;
use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

use crate::headers::UdpMeta;
use crate::packet::{PacketRead, ReadErr, WriteErr};

pub const UDP_HDR_SZ: usize = std::mem::size_of::<UdpHdrRaw>();

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

    pub fn parse_mut(
        dst: &mut [u8],
    ) -> Result<LayoutVerified<&mut [u8], Self>, WriteErr> {
        let hdr = match LayoutVerified::new(dst) {
            Some(bytes) => bytes,
            None => return Err(WriteErr::BadLayout),
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

impl From<&UdpMeta> for UdpHdrRaw {
    fn from(meta: &UdpMeta) -> Self {
        UdpHdrRaw {
            src_port: meta.src.to_be_bytes(),
            dst_port: meta.dst.to_be_bytes(),
            ..Default::default()
        }
    }
}

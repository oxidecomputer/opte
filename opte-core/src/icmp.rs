//! ICMP headers.
//!
//! We treat each ICMP type as its own header type. When parsing, we
//! use `IcmpBaseHdrRaw` to determine which type of ICMP message we
//! are ultimately parsing.
use core::mem;
use core::fmt::{self, Display};

use serde::{Deserialize, Serialize};

use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

use crate::headers::RawHeader;
use crate::packet::{PacketRead, ReadErr, WriteError};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum IcmpType {
    DestUnreachable = 3,
    EchoReply = 0,
    EchoRequest = 8,
}

impl Display for IcmpType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Self::DestUnreachable => "Dest Unreachable",
            Self::EchoReply => "Echo Reply",
            Self::EchoRequest => "Echo Request",
        };
        write!(f, "{}", s)
    }
}

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACHABLE: u8 = 3;
pub const ICMP_REDIRECT: u8 = 5;
pub const ICMP_ECHO: u8 = 8;

// TODO replace IcmpType with pattern that I used for DhcpMessageType.
// Just doing this for now to get a demo working before I hop on a
// train.
impl From<smoltcp::wire::Icmpv4Message> for IcmpType {
    fn from(x: smoltcp::wire::Icmpv4Message) -> Self {
        use smoltcp::wire::Icmpv4Message::*;

        match x {
            EchoReply => Self::EchoReply,
            EchoRequest => Self::EchoRequest,
            _ => todo!("not now damnit!"),
        }
    }
}

/// The base ICMP header
/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, FromBytes, AsBytes, Unaligned)]
pub struct IcmpBaseHdrRaw {
    pub icmp_type: u8,
    pub code: u8,
    pub csum: [u8; 2],
}

impl<'a> IcmpBaseHdrRaw {
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

    pub fn parse_mut(
        dst: &mut [u8],
    ) -> Result<LayoutVerified<&mut [u8], Self>, WriteError> {
        let hdr = match LayoutVerified::new(dst) {
            Some(bytes) => bytes,
            None => return Err(WriteError::BadLayout),
        };
        Ok(hdr)
    }
}

/// XXX
///
///  * There is actually a length in octect 5 (2nd octet in unused) as
///  specific in RFC 4884. This length describes how long the ULP field is.
///
///  * The ip_hdr may be more than 20 bytes if options are specified.
///
///  * The ULP field may be longer than 8 bytes (as specified by the
///  length field), but for our purposes we only care about the first
///  8 bytes anyways.
///
/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, FromBytes, AsBytes, Unaligned)]
pub struct IcmpDuHdrRaw {
    pub icmp_type: u8,
    pub code: u8,
    // XXX Make sure to update this csum when changing any fields in
    // the body (e.g., during NAT rewrite).
    pub csum: [u8; 2],
    pub unused: u8,
    pub ulp_length: u8,
    pub next_hop_mtu: [u8; 2],
    // pub ip_base_hdr: [u8; 20],
}

impl<'a> RawHeader<'a> for IcmpDuHdrRaw {
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

/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, FromBytes, AsBytes, Unaligned)]
pub struct IcmpRedirectHdrRaw {
    pub icmp_type: u8,
    pub code: u8,
    pub csum: [u8; 2],
    pub gateway_ip: [u8; 4],
    pub ip_hdr: [u8; 20],
    pub ulp_start: [u8; 8],
}

impl<'a> RawHeader<'a> for IcmpRedirectHdrRaw {
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

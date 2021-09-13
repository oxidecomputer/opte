use std::fmt::{self, Display};

use serde::{Deserialize, Serialize};

use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

use crate::packet::{PacketRead, ReadErr, WriteErr};

pub const TCP_HDR_SZ: usize = std::mem::size_of::<TcpHdrRaw>();

pub const TCP_PORT_RDP: u16 = 3389;
pub const TCP_PORT_SSH: u16 = 22;

/// The standard TCP flags. We don't bother with the experimental NS
/// flag.
pub mod TcpFlags {
    pub const FIN: u8 = crate::bit_on(0);
    pub const SYN: u8 = crate::bit_on(1);
    pub const RST: u8 = crate::bit_on(2);
    pub const PSH: u8 = crate::bit_on(3);
    pub const ACK: u8 = crate::bit_on(4);
    pub const URG: u8 = crate::bit_on(5);
    pub const ECE: u8 = crate::bit_on(6);
    pub const CWR: u8 = crate::bit_on(7);
}

// The standard TCP states.
//
// See Figure 13-8 of TCP/IP Illustrated Vol. 1 Ed. 2
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynRcvd,
    Established,
    CloseWait,
    LastAck,
    FinWait1,
    FinWait2,
    TimeWait,
}

impl Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            TcpState::Closed => "CLOSED",
            TcpState::Listen => "LISTEN",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynRcvd => "SYN_RCVD",
            TcpState::Established => "ESTABLISHED",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::LastAck => "LAST_ACK",
            TcpState::FinWait1 => "FIN_WAIT_1",
            TcpState::FinWait2 => "FIN_WAIT_2",
            TcpState::TimeWait => "TIME_WAIT",
        };
        write!(f, "{}", s)
    }
}

/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, FromBytes, AsBytes, Unaligned)]
pub struct TcpHdrRaw {
    pub src_port: [u8; 2],
    pub dst_port: [u8; 2],
    pub seq: [u8; 4],
    pub ack: [u8; 4],
    pub offset: u8,
    pub flags: u8,
    pub win: [u8; 2],
    pub csum: [u8; 2],
    pub urg: [u8; 2],
}

impl TcpHdrRaw {
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

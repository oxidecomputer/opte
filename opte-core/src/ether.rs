use core::convert::TryFrom;
use core::fmt::{self, Debug, Display};
use core::mem;
use core::result;
use core::str::FromStr;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::String;
        use alloc::vec::Vec;
    } else {
        use std::string::String;
        use std::vec::Vec;
    }
}

use serde::{Deserialize, Serialize};
use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

use crate::api;
use crate::headers::{
    Header, HeaderAction, HeaderActionModify, ModActionArg, PushActionArg,
    RawHeader,
};
use crate::packet::{PacketRead, ReadErr, WriteError};

pub const ETHER_TYPE_ETHER: u16 = 0x6558;
pub const ETHER_TYPE_IPV4: u16 = 0x0800;
pub const ETHER_TYPE_ARP: u16 = 0x0806;
pub const ETHER_TYPE_IPV6: u16 = 0x86DD;

pub const ETHER_BROADCAST: EtherAddr = EtherAddr { bytes: [0xFF; 6] };
pub const ETHER_ADDR_LEN: usize = 6;

pub const ETHER_HDR_SZ: usize = mem::size_of::<EtherHdrRaw>();

#[repr(u16)]
#[derive(
    Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum EtherType {
    Ether = 0x6558,
    Ipv4 = 0x0800,
    Arp = 0x0806,
    Ipv6 = 0x86DD,
}

impl TryFrom<u16> for EtherType {
    type Error = EtherHdrError;

    fn try_from(raw: u16) -> Result<Self, Self::Error> {
        let val = match raw {
            ETHER_TYPE_ETHER => Self::Ether,
            ETHER_TYPE_ARP => Self::Arp,
            ETHER_TYPE_IPV4 => Self::Ipv4,
            ETHER_TYPE_IPV6 => Self::Ipv6,

            _ => {
                return Err(EtherHdrError::UnsupportedEtherType {
                    ether_type: raw,
                })
            }
        };

        Ok(val)
    }
}

impl Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:04X}", *self as u16)
    }
}

/// We are never really interested in internal representation of
/// [`EtherType`].
impl Debug for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

#[derive(
    Clone, Copy, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct EtherAddr {
    bytes: [u8; ETHER_ADDR_LEN],
}

impl EtherAddr {
    pub fn to_bytes(self) -> [u8; ETHER_ADDR_LEN] {
        self.bytes
    }
    pub fn zero() -> Self {
        EtherAddr { bytes: [0u8; ETHER_ADDR_LEN] }
    }
    pub fn as_ptr(&self) -> *const u8 {
        &self.bytes as *const u8
    }
}

impl From<api::MacAddr> for EtherAddr {
    fn from(mac: api::MacAddr) -> Self {
        Self { bytes: mac.bytes() }
    }
}

impl From<[u8; ETHER_ADDR_LEN]> for EtherAddr {
    fn from(bytes: [u8; ETHER_ADDR_LEN]) -> Self {
        EtherAddr { bytes }
    }
}

impl FromStr for EtherAddr {
    type Err = String;

    fn from_str(val: &str) -> Result<Self, Self::Err> {
        let octets: Vec<u8> = val
            .split(":")
            .map(|s| {
                u8::from_str_radix(s, 16).or(Err(format!("bad octet: {}", s)))
            })
            .collect::<result::Result<Vec<u8>, _>>()?;

        if octets.len() != 6 {
            return Err(format!("incorrect number of bytes: {}", octets.len()));
        }

        // At the time of writing there is no TryFrom impl for Vec to
        // array in the alloc create. Honestly this looks a bit
        // cleaner anyways.
        let bytes =
            [octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]];

        Ok(EtherAddr::from(bytes))
    }
}

impl From<EtherAddr> for smoltcp::wire::EthernetAddress {
    fn from(addr: EtherAddr) -> Self {
        Self(addr.bytes)
    }
}

impl Display for EtherAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[3],
            self.bytes[4],
            self.bytes[5]
        )
    }
}

/// We are never really interested in internal representation of
/// EtherAddr.
impl Debug for EtherAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

#[derive(
    Clone,
    Debug,
    Default,
    Deserialize,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct EtherMeta {
    pub dst: EtherAddr,
    pub src: EtherAddr,
    pub ether_type: u16,
}

impl PushActionArg for EtherMeta {}

impl From<&EtherHdr> for EtherMeta {
    fn from(eth: &EtherHdr) -> Self {
        EtherMeta {
            src: eth.src,
            dst: eth.dst,
            ether_type: eth.ether_type as u16,
        }
    }
}

impl HeaderActionModify<EtherMetaOpt> for EtherMeta {
    fn run_modify(&mut self, spec: &EtherMetaOpt) {
        if spec.src.is_some() {
            self.src = spec.src.unwrap()
        }

        if spec.dst.is_some() {
            self.dst = spec.dst.unwrap()
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EtherMetaOpt {
    src: Option<EtherAddr>,
    dst: Option<EtherAddr>,
}

impl ModActionArg for EtherMetaOpt {}

impl EtherMeta {
    pub fn modify(
        src: Option<EtherAddr>,
        dst: Option<EtherAddr>,
    ) -> HeaderAction<EtherMeta, EtherMetaOpt> {
        HeaderAction::Modify(EtherMetaOpt { src, dst })
    }

    // XXX We could probably infer the various bits of pushed headers.
    // E.g., given a fully specified Header Transposition, we could
    // infer things like Ether Type and IP Protocol. However,
    // refactoring the code to make that work feels like it could be a
    // bit of a time suck at the moment. For now we set these values
    // explicitly, but it would be nice to eventually have the API
    // changed to infer these values, leaving one less bug that the
    // developer can introduce into the code.
    pub fn push(
        src: EtherAddr,
        dst: EtherAddr,
        ether_type: u16,
    ) -> HeaderAction<EtherMeta, EtherMetaOpt> {
        HeaderAction::Push(EtherMeta { dst, src, ether_type })
    }
}

#[derive(Clone, Debug)]
pub struct EtherHdr {
    dst: EtherAddr,
    src: EtherAddr,
    ether_type: EtherType,
}

#[macro_export]
macro_rules! assert_eth {
    ($left:expr, $right:expr) => {
        assert!(
            $left.dst() == $right.dst(),
            "ether dst mismatch: {} != {}",
            $left.dst(),
            $right.dst(),
        );
        assert!(
            $left.src() == $right.src(),
            "ether src mismatch: {} != {}",
            $left.src(),
            $right.src(),
        );
        assert!(
            $left.ether_type() == $right.ether_type(),
            "ether type mismatch: {} != {}",
            $left.ether_type(),
            $right.ether_type(),
        );
    };
}

#[test]
#[should_panic]
fn test_eth_macro() {
    let eth1 = EtherHdr {
        ether_type: EtherType::Ipv4,
        dst: EtherAddr::from([0; 6]),
        src: EtherAddr::from([1; 6]),
    };

    let mut eth2 = eth1.clone();
    eth2.dst = EtherAddr::from([0xa; 6]);
    assert_eth!(eth1, eth2);
}

impl EtherHdr {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ETHER_HDR_SZ);
        let raw = EtherHdrRaw::from(self);
        bytes.extend_from_slice(raw.as_bytes());
        bytes
    }

    /// Get the frame's destination address.
    pub fn dst(&self) -> EtherAddr {
        self.dst
    }

    /// Get the frame's Ether Type.
    pub fn ether_type(&self) -> EtherType {
        self.ether_type
    }

    pub fn new<A: Into<EtherAddr>>(
        ether_type: EtherType,
        src: A,
        dst: A,
    ) -> Self {
        Self { dst: dst.into(), src: src.into(), ether_type }
    }

    /// Get the frame's source address.
    pub fn src(&self) -> EtherAddr {
        self.src
    }

    /// Unify the header with the metadata.
    pub fn unify(&mut self, meta: &EtherMeta) {
        self.dst = meta.dst;
        self.src = meta.src;
        self.ether_type = EtherType::try_from(meta.ether_type).unwrap();
    }
}

impl Header for EtherHdr {
    type Error = EtherHdrError;

    fn parse<'a, 'b, R>(rdr: &'b mut R) -> Result<Self, EtherHdrError>
    where
        R: PacketRead<'a>,
    {
        EtherHdr::try_from(&EtherHdrRaw::raw_zc(rdr)?)
    }
}

pub enum EtherHdrError {
    ReadError { error: ReadErr },
    UnsupportedEtherType { ether_type: u16 },
}

impl From<ReadErr> for EtherHdrError {
    fn from(error: ReadErr) -> Self {
        EtherHdrError::ReadError { error }
    }
}

impl Display for EtherHdrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::UnsupportedEtherType { ether_type } => {
                write!(f, "Unsupported Ether Type: 0x{:04X}", ether_type)
            }

            err => {
                write!(f, "{:?}", err)
            }
        }
    }
}

impl Debug for EtherHdrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl TryFrom<&LayoutVerified<&[u8], EtherHdrRaw>> for EtherHdr {
    type Error = EtherHdrError;

    fn try_from(
        raw: &LayoutVerified<&[u8], EtherHdrRaw>,
    ) -> Result<Self, Self::Error> {
        let ether_type =
            EtherType::try_from(u16::from_be_bytes(raw.ether_type))?;

        Ok(Self {
            dst: EtherAddr::from(raw.dst),
            src: EtherAddr::from(raw.src),
            ether_type,
        })
    }
}

impl From<&EtherMeta> for EtherHdr {
    fn from(meta: &EtherMeta) -> Self {
        EtherHdr {
            dst: meta.dst,
            src: meta.src,
            // XXX: Temporary until I change EtherMeta to use EtherType
            ether_type: EtherType::try_from(meta.ether_type).unwrap(),
        }
    }
}

/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, Debug, Default, FromBytes, AsBytes, Unaligned)]
pub struct EtherHdrRaw {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ether_type: [u8; 2],
}

impl<'a> RawHeader<'a> for EtherHdrRaw {
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

impl From<&EtherHdr> for EtherHdrRaw {
    fn from(eth: &EtherHdr) -> Self {
        EtherHdrRaw {
            dst: eth.dst.to_bytes(),
            src: eth.src.to_bytes(),
            ether_type: (eth.ether_type() as u16).to_be_bytes(),
        }
    }
}

impl From<&EtherMeta> for EtherHdrRaw {
    fn from(meta: &EtherMeta) -> Self {
        EtherHdrRaw {
            dst: meta.dst.to_bytes(),
            src: meta.src.to_bytes(),
            ether_type: meta.ether_type.to_be_bytes(),
        }
    }
}

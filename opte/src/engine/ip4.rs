use core::convert::TryFrom;
use core::fmt::{self, Debug, Display};
use core::mem;
use core::num::ParseIntError;
use core::result;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::String;
        use alloc::vec::Vec;
    } else {
        use std::string::String;
        use std::vec::Vec;
    }
}

// A fixed-size Vec.
use heapless::Vec as FVec;
use serde::{Deserialize, Serialize};
use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

use super::checksum::{Checksum, HeaderChecksum};
use super::headers::{
    Header, HeaderAction, HeaderActionModify, IpMeta, IpMetaOpt, ModActionArg,
    RawHeader,
};
use super::packet::{PacketRead, ReadErr, WriteError};
use super::rule::{
    MatchExact, MatchExactVal, MatchPrefix, MatchPrefixVal, MatchRangeVal,
};
pub use crate::api::{
    Ipv4Addr, Ipv4Cidr, Protocol, IPV4_ANY_ADDR, IPV4_LOCAL_BCAST,
};

pub const IPV4_HDR_LEN_MASK: u8 = 0x0F;
pub const IPV4_HDR_VER_MASK: u8 = 0xF0;
pub const IPV4_HDR_VER_SHIFT: u8 = 4;
pub const IPV4_HDR_SZ: usize = mem::size_of::<Ipv4HdrRaw>();
pub const IPV4_VERSION: u8 = 4;

pub const DEF_ROUTE: &'static str = "0.0.0.0/0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpError {
    BadPrefix(u8),
    Ipv4NonPrivateNetwork(Ipv4Addr),
    MalformedCidr(String),
    MalformedInt,
    MalformedIp(String),
    MalformedPrefix(String),
    Other(String),
}

impl From<ParseIntError> for IpError {
    fn from(_err: ParseIntError) -> Self {
        IpError::MalformedInt
    }
}

impl From<String> for IpError {
    fn from(err: String) -> Self {
        IpError::Other(err)
    }
}

impl Display for IpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use IpError::*;

        match self {
            BadPrefix(prefix) => {
                write!(f, "bad prefix: {}", prefix)
            }

            Ipv4NonPrivateNetwork(addr) => {
                write!(f, "non-private network: {}", addr)
            }

            MalformedCidr(cidr) => {
                write!(f, "malformed CIDR: {}", cidr)
            }

            MalformedInt => {
                write!(f, "malformed integer")
            }

            MalformedIp(ip) => {
                write!(f, "malformed IP: {}", ip)
            }

            MalformedPrefix(prefix) => {
                write!(f, "malformed prefix: {}", prefix)
            }

            Other(msg) => {
                write!(f, "{}", msg)
            }
        }
    }
}

impl From<IpError> for String {
    fn from(err: IpError) -> Self {
        format!("{}", err)
    }
}

impl MatchPrefixVal for Ipv4Cidr {}

impl Ipv4Cidr {
    pub fn ip(&self) -> Ipv4Addr {
        self.parts().0
    }

    /// Does this CIDR represent the default route subnet?
    pub fn is_default(&self) -> bool {
        let (ip, prefix_len) = self.parts();
        ip == IPV4_ANY_ADDR && prefix_len.val() == 0
    }

    pub fn prefix_len(self) -> u8 {
        self.parts().1.val()
    }

    /// Is this `ip` a member of the CIDR?
    pub fn is_member(&self, ip: Ipv4Addr) -> bool {
        ip.safe_mask(self.parts().1) == self.ip()
    }

    /// Convert the CIDR prefix length into a subnet mask.
    pub fn to_mask(self) -> Ipv4Addr {
        let mut bits = i32::MIN;
        bits = bits >> (self.prefix_len() - 1);
        Ipv4Addr::from(bits.to_be_bytes())
    }
}

#[test]
fn cidr_match() {
    let ip1 = "192.168.2.22".parse::<Ipv4Addr>().unwrap();
    let cidr1 = "192.168.2.0/24".parse().unwrap();
    assert!(ip1.match_prefix(&cidr1));

    let ip2 = "10.7.7.7".parse::<Ipv4Addr>().unwrap();
    let cidr2 = "10.0.0.0/8".parse().unwrap();
    assert!(ip2.match_prefix(&cidr2));

    let ip3 = "52.10.128.69".parse::<Ipv4Addr>().unwrap();
    let cidr3 = DEF_ROUTE.parse().unwrap();
    assert!(ip3.match_prefix(&cidr3));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4CidrPrefix {
    val: u8,
}

impl Ipv4CidrPrefix {
    pub fn new(net_prefix: u8) -> result::Result<Self, IpError> {
        if net_prefix > 32 {
            return Err(IpError::BadPrefix(net_prefix));
        }

        Ok(Ipv4CidrPrefix { val: net_prefix })
    }
}

impl MatchExactVal for Ipv4Addr {}
impl MatchRangeVal for Ipv4Addr {}

impl Ipv4Addr {
    /// Produce a `u32` which itself is stored in memory in network
    /// order. This is needed for passing this type up to DTrace so
    /// its inet_ntoa() subroutine works.
    pub fn to_be(self) -> u32 {
        // First we create a native-endian u32 from the network-order
        // bytes, then we convert that to an in-memroy network-order
        // u32.
        u32::from_be_bytes(self.bytes()).to_be()
    }
}

pub type Ipv4AddrTuple = (u8, u8, u8, u8);

impl From<Ipv4Addr> for Ipv4AddrTuple {
    fn from(ip: Ipv4Addr) -> Ipv4AddrTuple {
        let bytes = ip.bytes();
        (bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

impl From<smoltcp::wire::Ipv4Address> for Ipv4Addr {
    fn from(smolip4: smoltcp::wire::Ipv4Address) -> Self {
        let bytes = smolip4.as_bytes();
        Self::from([bytes[0], bytes[1], bytes[2], bytes[3]])
    }
}

impl From<Ipv4Addr> for smoltcp::wire::Ipv4Address {
    fn from(ip: Ipv4Addr) -> Self {
        Self::from_bytes(&ip.bytes())
    }
}

#[test]
fn ip4_addr_to_tuple() {
    assert_eq!(
        Ipv4AddrTuple::from("44.241.36.226".parse::<Ipv4Addr>().unwrap()),
        (44, 241, 36, 226)
    );
}

impl MatchExact<Ipv4Addr> for Ipv4Addr {
    fn match_exact(&self, val: &Ipv4Addr) -> bool {
        *self == *val
    }
}

impl MatchPrefix<Ipv4Cidr> for Ipv4Addr {
    fn match_prefix(&self, prefix: &Ipv4Cidr) -> bool {
        prefix.is_member(*self)
    }
}

#[test]
fn match_check() {
    let ip = "192.168.2.11".parse::<Ipv4Addr>().unwrap();
    assert!(ip.match_exact(&ip));
    assert!(ip.match_prefix(&"192.168.2.0/24".parse::<Ipv4Cidr>().unwrap()));
}

impl MatchExactVal for Protocol {}

impl MatchExact<Protocol> for Protocol {
    fn match_exact(&self, val: &Protocol) -> bool {
        *self == *val
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct Ipv4Meta {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: Protocol,
}

impl Ipv4Meta {
    // XXX check that at least one field was specified.
    pub fn modify(
        src: Option<Ipv4Addr>,
        dst: Option<Ipv4Addr>,
        proto: Option<Protocol>,
    ) -> HeaderAction<IpMeta, IpMetaOpt> {
        HeaderAction::Modify(Ipv4MetaOpt { src, dst, proto }.into())
    }
}

impl From<&Ipv4Hdr> for Ipv4Meta {
    fn from(ip4: &Ipv4Hdr) -> Self {
        Ipv4Meta { src: ip4.src, dst: ip4.dst, proto: ip4.proto }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Ipv4MetaOpt {
    src: Option<Ipv4Addr>,
    dst: Option<Ipv4Addr>,
    proto: Option<Protocol>,
}

impl ModActionArg for Ipv4MetaOpt {}

impl HeaderActionModify<Ipv4MetaOpt> for Ipv4Meta {
    fn run_modify(&mut self, spec: &Ipv4MetaOpt) {
        if spec.src.is_some() {
            self.src = spec.src.unwrap()
        }

        if spec.dst.is_some() {
            self.dst = spec.dst.unwrap()
        }

        if spec.proto.is_some() {
            self.proto = spec.proto.unwrap()
        }
    }
}

#[derive(Clone, Debug)]
pub struct Ipv4Hdr {
    // Don't need version as it's implicit
    hdr_len_bytes: u8,
    dscp_ecn: u8,
    total_len: u16,
    ident: u16,
    frag_and_flags: [u8; 2],
    ttl: u8,
    proto: Protocol,
    // XXX The checksum type could tell us if this was HW or SW
    // validated, and would have routines for performing incremental
    // update. csum: Checksum,
    csum: [u8; 2],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    // XXX We could have a Vec, array, anymap of header options here.
}

#[macro_export]
macro_rules! assert_ip4 {
    ($left:expr, $right:expr) => {
        assert!(
            $left.hdr_len() == $right.hdr_len(),
            "IPv4 hdr len mismatch: {} != {}",
            $left.hdr_len(),
            $right.hdr_len(),
        );

        assert!(
            $left.total_len() == $right.total_len(),
            "IPv4 total len mismatch: {} != {}",
            $left.total_len(),
            $right.total_len(),
        );

        assert!(
            $left.ident() == $right.ident(),
            "IPv4 ident mistmach: {} != {}",
            $left.ident(),
            $right.ident(),
        );

        assert!(
            $left.ttl() == $right.ttl(),
            "IPv4 ttl mismatch: {} != {}",
            $left.ttl(),
            $right.ttl(),
        );

        assert!(
            $left.proto() == $right.proto(),
            "IPv4 protocol mismatch: {} != {}",
            $left.proto(),
            $right.proto(),
        );

        let lcsum = $left.csum();
        let rcsum = $right.csum();

        assert!(
            lcsum == rcsum,
            "IPv4 csum mismatch: 0x{:02X}{:02X} != 0x{:02X}{:02X}",
            lcsum[0],
            lcsum[1],
            rcsum[0],
            rcsum[1],
        );

        assert!(
            $left.src() == $right.src(),
            "IPv4 src mismatch: {} != {}",
            $left.src(),
            $right.src(),
        );

        assert!(
            $left.dst() == $right.dst(),
            "IPv4 dst mismatch: {} != {}",
            $left.dst(),
            $right.dst(),
        );
    };
}

pub enum UlpCsumOpt {
    Partial,
    Full,
}

impl Ipv4Hdr {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.hdr_len());
        let raw = Ipv4HdrRaw::from(self);
        bytes.extend_from_slice(raw.as_bytes());
        bytes
    }

    fn compute_pseudo_csum(&self) -> Checksum {
        Checksum::compute(&self.pseudo_bytes())
    }

    pub fn compute_hdr_csum(&mut self) {
        self.csum = [0; 2];
        self.csum =
            HeaderChecksum::from(Checksum::compute(&self.as_bytes())).bytes();
    }

    pub fn compute_ulp_csum(
        &self,
        opt: UlpCsumOpt,
        ulp_hdr: &[u8],
        body: &[u8],
    ) -> Checksum {
        match opt {
            UlpCsumOpt::Partial => todo!("implement partial csum"),
            UlpCsumOpt::Full => {
                let mut csum = self.compute_pseudo_csum();
                csum.add(ulp_hdr);
                csum.add(body);
                csum
            }
        }
    }

    pub fn csum(&self) -> [u8; 2] {
        self.csum
    }

    pub fn dst(&self) -> Ipv4Addr {
        self.dst
    }

    /// Return the length of the header porition of the packet, in bytes.
    pub fn hdr_len(&self) -> usize {
        self.hdr_len_bytes as usize
    }

    pub fn ident(&self) -> u16 {
        self.ident
    }

    #[cfg(any(feature = "std", test))]
    pub fn new_tcp<A: Into<Ipv4Addr>>(
        tcp: &mut super::tcp::TcpHdr,
        body: &[u8],
        src: A,
        dst: A,
    ) -> Self {
        let data_len = tcp.hdr_len() as u16 + body.len() as u16;

        Self {
            hdr_len_bytes: IPV4_HDR_SZ as u8,
            dscp_ecn: 0,
            total_len: IPV4_HDR_SZ as u16 + data_len,
            ident: 0,
            frag_and_flags: [0x40, 0x00],
            ttl: 255,
            proto: Protocol::TCP,
            csum: [0; 2],
            src: src.into(),
            dst: dst.into(),
        }
    }

    /// Return the length of the payload portion of the packet.
    pub fn pay_len(&self) -> usize {
        self.total_len as usize - self.hdr_len()
    }

    /// Return the [`Protocol`] of the packet.
    pub fn proto(&self) -> Protocol {
        self.proto
    }

    /// Return the pseudo header bytes.
    pub fn pseudo_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&self.src.bytes());
        bytes.extend_from_slice(&self.dst.bytes());
        let len_bytes = (self.pay_len() as u16).to_be_bytes();
        bytes.extend_from_slice(&[
            0u8,
            self.proto as u8,
            len_bytes[0],
            len_bytes[1],
        ]);
        bytes
    }

    /// Return a [`Checksum`] of the pseudo header.
    pub fn pseudo_csum(&self) -> Checksum {
        Checksum::compute(&self.pseudo_bytes())
    }

    pub fn set_total_len(&mut self, len: u16) {
        self.total_len = len
    }

    pub fn src(&self) -> Ipv4Addr {
        self.src
    }

    pub fn total_len(&self) -> u16 {
        self.total_len
    }

    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    pub fn unify(&mut self, meta: &Ipv4Meta) {
        let mut csum = Checksum::from(HeaderChecksum::wrap(self.csum));
        // Subtract old bytes.
        //
        // XXX Might be nice to have Checksum work on iterator of u8
        // instead, then we could chain slice iterators together.
        let mut old: FVec<u8, 10> = FVec::new();
        old.extend_from_slice(&self.src.bytes()).unwrap();
        old.extend_from_slice(&self.dst.bytes()).unwrap();
        old.extend_from_slice(&[0, self.proto as u8]).unwrap();
        csum.sub(&old);
        let _ = csum.finalize();

        // Add new bytes.
        let mut new: FVec<u8, 10> = FVec::new();
        new.extend_from_slice(&meta.src.bytes()).unwrap();
        new.extend_from_slice(&meta.dst.bytes()).unwrap();
        new.extend_from_slice(&[0, meta.proto as u8]).unwrap();
        csum.add(&new);

        self.src = meta.src;
        self.dst = meta.dst;
        self.proto = meta.proto;
        self.csum = HeaderChecksum::from(csum).bytes();
    }
}

impl Header for Ipv4Hdr {
    type Error = Ipv4HdrError;

    fn parse<'a, 'b, R>(rdr: &'b mut R) -> Result<Self, Ipv4HdrError>
    where
        R: PacketRead<'a>,
    {
        Ipv4Hdr::try_from(&Ipv4HdrRaw::raw_zc(rdr)?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Ipv4HdrError {
    BadTotalLen { total_len: u16 },
    BadVersion { vsn: u8 },
    HeaderTruncated { hdr_len_bytes: u8 },
    ReadError { error: ReadErr },
    UnexpectedProtocol { protocol: u8 },
}

impl From<ReadErr> for Ipv4HdrError {
    fn from(error: ReadErr) -> Self {
        Ipv4HdrError::ReadError { error }
    }
}

impl TryFrom<&LayoutVerified<&[u8], Ipv4HdrRaw>> for Ipv4Hdr {
    type Error = Ipv4HdrError;

    fn try_from(
        raw: &LayoutVerified<&[u8], Ipv4HdrRaw>,
    ) -> Result<Self, Self::Error> {
        let vsn = (raw.ver_hdr_len & IPV4_HDR_VER_MASK) >> IPV4_HDR_VER_SHIFT;

        if vsn != IPV4_VERSION {
            return Err(Ipv4HdrError::BadVersion { vsn });
        }

        let hdr_len_bytes = u8::from(raw.ver_hdr_len & IPV4_HDR_LEN_MASK) * 4;

        if hdr_len_bytes < 20 {
            return Err(Ipv4HdrError::HeaderTruncated { hdr_len_bytes });
        }

        let total_len = u16::from_be_bytes(raw.total_len);

        // In realiy we also want to check that the total length
        // matches up with the protocol and the remaining bytes in the
        // packet; however, we delay that check until later in the
        // main parsing code, at which time we have more information
        // to work with. For this check we only want to make sure the
        // total length is at least as large as the header length.
        if total_len < hdr_len_bytes as u16 {
            return Err(Ipv4HdrError::BadTotalLen { total_len });
        }

        let proto = Protocol::try_from(raw.proto).map_err(|_s| {
            Ipv4HdrError::UnexpectedProtocol { protocol: raw.proto }
        })?;

        let src = Ipv4Addr::from(u32::from_be_bytes(raw.src));
        let dst = Ipv4Addr::from(u32::from_be_bytes(raw.dst));

        Ok(Ipv4Hdr {
            hdr_len_bytes,
            dscp_ecn: raw.dscp_ecn,
            total_len,
            ident: u16::from_be_bytes(raw.ident),
            frag_and_flags: raw.frag_and_flags,
            ttl: raw.ttl,
            proto,
            csum: raw.csum,
            src,
            dst,
        })
    }
}

impl From<&Ipv4Meta> for Ipv4Hdr {
    fn from(meta: &Ipv4Meta) -> Self {
        Ipv4Hdr {
            hdr_len_bytes: 20,
            dscp_ecn: 0,
            total_len: 20,
            ident: 0,
            frag_and_flags: [0x40, 0x0],
            ttl: 64,
            proto: meta.proto,
            csum: [0; 2],
            src: meta.src,
            dst: meta.dst,
        }
    }
}

/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, Debug, FromBytes, AsBytes, Unaligned)]
pub struct Ipv4HdrRaw {
    pub ver_hdr_len: u8,
    pub dscp_ecn: u8,
    pub total_len: [u8; 2],
    pub ident: [u8; 2],
    pub frag_and_flags: [u8; 2],
    pub ttl: u8,
    pub proto: u8,
    pub csum: [u8; 2],
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

impl<'a> RawHeader<'a> for Ipv4HdrRaw {
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
        src: &mut [u8],
    ) -> Result<LayoutVerified<&mut [u8], Self>, WriteError> {
        let hdr = match LayoutVerified::new(src) {
            Some(bytes) => bytes,
            None => return Err(WriteError::BadLayout),
        };
        Ok(hdr)
    }
}

impl Default for Ipv4HdrRaw {
    fn default() -> Self {
        Ipv4HdrRaw {
            ver_hdr_len: 0x45,
            dscp_ecn: 0x0,
            total_len: [0x0; 2],
            ident: [0x0; 2],
            frag_and_flags: [0x40, 0x0],
            ttl: 64,
            proto: Protocol::Reserved as u8,
            csum: [0x0; 2],
            src: [0x0; 4],
            dst: [0x0; 4],
        }
    }
}

impl From<&Ipv4Hdr> for Ipv4HdrRaw {
    fn from(ip4: &Ipv4Hdr) -> Self {
        let hdr_len = ip4.hdr_len_bytes / 4;

        Ipv4HdrRaw {
            ver_hdr_len: 0x40 | hdr_len,
            dscp_ecn: ip4.dscp_ecn,
            total_len: ip4.total_len.to_be_bytes(),
            ident: ip4.ident.to_be_bytes(),
            frag_and_flags: ip4.frag_and_flags,
            ttl: ip4.ttl,
            proto: ip4.proto as u8,
            csum: ip4.csum,
            src: ip4.src.bytes(),
            dst: ip4.dst.bytes(),
        }
    }
}

impl From<&Ipv4Meta> for Ipv4HdrRaw {
    fn from(meta: &Ipv4Meta) -> Self {
        Ipv4HdrRaw {
            src: meta.src.bytes(),
            dst: meta.dst.bytes(),
            proto: meta.proto as u8,
            ..Default::default()
        }
    }
}

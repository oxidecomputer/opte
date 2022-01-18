use core::convert::TryFrom;
use core::fmt::{self, Debug, Display};
use core::num::ParseIntError;
use core::result;
use core::str::FromStr;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::string::{String, ToString};
#[cfg(any(feature = "std", test))]
use std::string::{String, ToString};
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::vec::Vec;
#[cfg(any(feature = "std", test))]
use std::vec::Vec;

// A fixed-size Vec.
use heapless::Vec as FVec;
use serde::{Deserialize, Serialize};
use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

use crate::checksum::{Checksum, HeaderChecksum};
use crate::headers::{
    Header, HeaderAction, HeaderActionModify, IpMeta, IpMetaOpt, ModActionArg,
    RawHeader
};
use crate::packet::{PacketRead, ReadErr, WriteError};
use crate::rule::{
    MatchExact, MatchExactVal, MatchPrefix, MatchPrefixVal, MatchRangeVal,
};

pub const IPV4_HDR_LEN_MASK: u8 = 0x0F;
pub const IPV4_HDR_VER_MASK: u8 = 0xF0;
pub const IPV4_HDR_VER_SHIFT: u8 = 4;
pub const IPV4_HDR_SZ: usize = std::mem::size_of::<Ipv4HdrRaw>();
pub const IPV4_VERSION: u8 = 4;

pub const LOCAL_BROADCAST: Ipv4Addr = Ipv4Addr::new([255; 4]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpError {
    BadNetPrefix(u8),
    Ipv4NonPrivateNetwork(Ipv4Addr),
    MalformedCidr(String),
    MalformedInt,
    MalformedIp(String),
    MalformedNetPrefix(String),
}

impl From<ParseIntError> for IpError {
    fn from(_err: ParseIntError) -> Self {
        IpError::MalformedInt
    }
}

impl Display for IpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use IpError::*;

        match self {
            BadNetPrefix(prefix) => {
                write!(f, "bad net prefix: {}", prefix)
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

            MalformedNetPrefix(prefix) => {
                write!(f, "malformed net prefix: {}", prefix)
            }
        }
    }
}

impl From<IpError> for String {
    fn from(err: IpError) -> Self {
        format!("{}", err)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ipv4Cidr {
    ip: Ipv4Addr,
    net_prefix: u8,
}

impl MatchPrefixVal for Ipv4Cidr {}

impl Ipv4Cidr {
    pub fn get_ip(self) -> Ipv4Addr {
        self.ip
    }

    pub fn get_net_prefix(self) -> u8 {
        self.net_prefix
    }

    /// Is this `ip` a member of the CIDR?
    pub fn is_member(&self, ip: Ipv4Addr) -> bool {
        ip.mask(self.net_prefix) == self.ip
    }

    pub fn new(ip: Ipv4Addr, net_prefix: u8) -> result::Result<Self, IpError> {
        // In this case we are only checking that it's a valid CIDR in
        // the general sense; VPC-specific CIDR enforcement is done by
        // the VPC types.
        if net_prefix > 32 {
            return Err(IpError::BadNetPrefix(net_prefix));
        }

        let ip = ip.mask(net_prefix);
        Ok(Ipv4Cidr { ip, net_prefix })
    }
}

impl Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.ip, self.net_prefix)
    }
}

impl FromStr for Ipv4Cidr {
    type Err = IpError;

    /// Convert a string like "192.168.2.0/24" into an `Ipv4Cidr`.
    fn from_str(val: &str) -> result::Result<Self, Self::Err> {
        let (ip_s, net_prefix_s) = match val.split_once("/") {
            Some(v) => v,
            None => return Err(IpError::MalformedCidr(val.to_string())),
        };

        let ip = match ip_s.parse() {
            Ok(v) => v,
            Err(err) => return Err(err),
        };

        let net_prefix = match net_prefix_s.parse::<u8>() {
            Ok(v) => v,
            Err(_) => {
                return Err(IpError::MalformedNetPrefix(
                    net_prefix_s.to_string(),
                ));
            }
        };

        Ipv4Cidr::new(ip, net_prefix)
    }
}

#[test]
fn bad_cidr() {
    let ip = "10.0.0.1".parse().unwrap();
    assert_eq!(Ipv4Cidr::new(ip, 33), Err(IpError::BadNetPrefix(33)));
    assert_eq!(
        "192.168.2.9/33".parse::<Ipv4Cidr>(),
        Err(IpError::BadNetPrefix(33))
    );
}

#[test]
fn good_cidr() {
    let ip = "192.168.2.0".parse().unwrap();
    assert_eq!(
        Ipv4Cidr::new(ip, 24),
        Ok(Ipv4Cidr {
            ip: Ipv4Addr { inner: [192, 168, 2, 0] },
            net_prefix: 24
        })
    );

    assert_eq!(
        "192.168.2.0/24".parse(),
        Ok(Ipv4Cidr {
            ip: Ipv4Addr { inner: [192, 168, 2, 0] },
            net_prefix: 24
        })
    );

    assert_eq!(
        "192.168.2.9/24".parse(),
        Ok(Ipv4Cidr {
            ip: Ipv4Addr { inner: [192, 168, 2, 0] },
            net_prefix: 24
        })
    );

    assert_eq!(
        "192.168.2.9/24".parse::<Ipv4Cidr>().unwrap().to_string(),
        "192.168.2.0/24".to_string()
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4CidrPrefix {
    val: u8,
}

impl Ipv4CidrPrefix {
    pub fn new(net_prefix: u8) -> result::Result<Self, IpError> {
        if net_prefix > 32 {
            return Err(IpError::BadNetPrefix(net_prefix));
        }

        Ok(Ipv4CidrPrefix { val: net_prefix })
    }
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Default,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct Ipv4Addr {
    // These bytes are kept in network order.
    inner: [u8; 4],
}

impl MatchExactVal for Ipv4Addr {}
impl MatchRangeVal for Ipv4Addr {}

impl Ipv4Addr {
    pub fn iter(&self) -> core::slice::Iter<u8> {
        (&self.inner).iter()
    }

    // TODO Consider creating Ipv4CidrPrefix so we can have a
    // compile-time guarantee that prefix is valid.
    pub const fn mask(mut self, net_prefix: u8) -> Self {
        if net_prefix == 0 {
            return self;
        }

        let mut n = u32::from_be_bytes(self.inner);

        let mut bits = i32::MIN;
        bits = bits >> (net_prefix - 1);
        n = n & bits as u32;
        self.inner = n.to_be_bytes();
        self
    }

    /// Create a new `IPv4Addr` from an array of bytes in network order.
    pub const fn new(bytes: [u8; 4]) -> Self {
        Self { inner: bytes }
    }

    /// Produce a `u32` which itself is stored in memory in network
    /// order. This is needed for passing this type up to DTrace so
    /// its inet_ntoa() subroutine works.
    pub fn to_be(self) -> u32 {
        // First we create a native-endian u32 from the network-order
        // bytes, then we convert that to an in-memroy network-order
        // u32.
        u32::from_be_bytes(self.inner).to_be()
    }

    /// Return the bytes in network-order.
    pub fn to_be_bytes(self) -> [u8; 4] {
        self.inner
    }
}

pub type Ipv4AddrTuple = (u8, u8, u8, u8);

impl From<Ipv4Addr> for Ipv4AddrTuple {
    fn from(ip: Ipv4Addr) -> Ipv4AddrTuple {
        let bytes = ip.inner;
        (bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

impl From<Ipv4AddrTuple> for Ipv4Addr {
    fn from(tuple: Ipv4AddrTuple) -> Self {
        Self::new([tuple.0, tuple.1, tuple.2, tuple.3])
    }
}

#[test]
fn ip4_addr_to_tuple() {
    assert_eq!(
        Ipv4AddrTuple::from("44.241.36.226".parse::<Ipv4Addr>().unwrap()),
        (44, 241, 36, 226)
    );
}

impl From<Ipv4Addr> for u32 {
    fn from(ip: Ipv4Addr) -> u32 {
        u32::from_be_bytes(ip.inner)
    }
}

impl From<u32> for Ipv4Addr {
    fn from(val: u32) -> Self {
        Self { inner: val.to_be_bytes() }
    }
}

impl FromStr for Ipv4Addr {
    type Err = IpError;

    fn from_str(val: &str) -> result::Result<Self, Self::Err> {
        let octets: Vec<u8> = val
            .split(".")
            .map(|s| s.parse())
            .collect::<std::result::Result<Vec<u8>, _>>()?;

        if octets.len() != 4 {
            return Err(IpError::MalformedIp(val.to_string()));
        }

        // At the time of writing there is no TryFrom impl for Vec to
        // array in the alloc create. Honestly this looks a bit
        // cleaner anyways.
        Ok(Self { inner: [octets[0], octets[1], octets[2], octets[3]] })
    }
}

#[test]
fn ipv4_addr_good() {
    assert_eq!(
        "192.168.33.10".parse(),
        Ok(Ipv4Addr { inner: [192, 168, 33, 10] })
    );
}

#[test]
fn ipv4_addr_bad() {
    assert_eq!("192.168.33.1O".parse::<Ipv4Addr>(), Err(IpError::MalformedInt));
    assert_eq!(
        "192.168.33.256".parse::<Ipv4Addr>(),
        Err(IpError::MalformedInt)
    );
}

impl Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.inner[0],
            self.inner[1],
            self.inner[2],
            self.inner[3],
        )
    }
}

// There's no real reason to view an Ipv4Addr as its raw array, so
// just present it in a human-friendly manner.
impl Debug for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ipv4Addr {{ inner: {} }}", self)
    }
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

#[cfg(any(feature = "std", test))]
impl From<std::net::Ipv4Addr> for Ipv4Addr {
    fn from(ip4_std: std::net::Ipv4Addr) -> Self {
        Ipv4Addr::from(u32::from(ip4_std))
    }
}

/// An IP protocol value.
///
/// TODO repr(u8)?
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum Protocol {
    ICMP = 0x1,
    IGMP = 0x2,
    TCP = 0x6,
    UDP = 0x11,
    Reserved = 0xFF,
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Reserved
    }
}

impl Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Protocol::ICMP => write!(f, "ICMP"),
            Protocol::IGMP => write!(f, "IGMP"),
            Protocol::TCP => write!(f, "TCP"),
            Protocol::UDP => write!(f, "UDP"),
            Protocol::Reserved => write!(f, "Reserved"),
        }
    }
}

impl TryFrom<u8> for Protocol {
    type Error = String;

    fn try_from(proto: u8) -> core::result::Result<Self, Self::Error> {
        match proto {
            0x1 => Ok(Protocol::ICMP),
            0x2 => Ok(Protocol::IGMP),
            0x6 => Ok(Protocol::TCP),
            0x11 => Ok(Protocol::UDP),
            proto => Err(format!("unhandled IP protocol: 0x{:X}", proto)),
        }
    }
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
        Ipv4Meta {
            src: ip4.src,
            dst: ip4.dst,
            proto: ip4.proto,
        }
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
            lcsum[0], lcsum[1],
            rcsum[0], rcsum[1],
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
    }
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
        self.csum = HeaderChecksum::from(
            Checksum::compute(&self.as_bytes())
        ).bytes();
    }

    pub fn compute_ulp_csum(
        &self,
        opt: UlpCsumOpt,
        body: &[u8]
    ) -> Checksum {
        match opt {
            UlpCsumOpt::Partial => todo!("implement partial csum"),
            UlpCsumOpt::Full => {
                let mut csum = self.compute_pseudo_csum();
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
        tcp: &mut crate::tcp::TcpHdr,
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

    pub fn pseudo_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&self.src.to_be_bytes());
        bytes.extend_from_slice(&self.dst.to_be_bytes());
        let len_bytes = self.pay_len().to_be_bytes();
        bytes.extend_from_slice(
            &[0u8, self.proto as u8, len_bytes[0], len_bytes[1]]
        );
        bytes
    }

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
        old.extend_from_slice(&self.src.to_be_bytes()).unwrap();
        old.extend_from_slice(&self.dst.to_be_bytes()).unwrap();
        old.extend_from_slice(&[0, self.proto as u8]).unwrap();
        csum.sub(&old);
        let _ = csum.finalize();

        // Add new bytes.
        let mut new: FVec<u8, 10> = FVec::new();
        new.extend_from_slice(&meta.src.to_be_bytes()).unwrap();
        new.extend_from_slice(&meta.dst.to_be_bytes()).unwrap();
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
        R: PacketRead<'a>
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
        raw: &LayoutVerified<&[u8], Ipv4HdrRaw>
    ) -> Result<Self, Self::Error> {
        let vsn = (raw.ver_hdr_len & IPV4_HDR_VER_MASK) >> IPV4_HDR_VER_SHIFT;

        if vsn != IPV4_VERSION {
            return Err(Ipv4HdrError::BadVersion { vsn });
        }

        let hdr_len_bytes =
            u8::from(raw.ver_hdr_len & IPV4_HDR_LEN_MASK) * 4;

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

        let proto = Protocol::try_from(raw.proto)
            .map_err(|_s| Ipv4HdrError::UnexpectedProtocol {
                protocol: raw.proto
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
        let slice = rdr.slice(std::mem::size_of::<Self>())?;
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
            src: ip4.src.to_be_bytes(),
            dst: ip4.dst.to_be_bytes(),
        }
    }
}

impl From<&Ipv4Meta> for Ipv4HdrRaw {
    fn from(meta: &Ipv4Meta) -> Self {
        Ipv4HdrRaw {
            src: meta.src.to_be_bytes(),
            dst: meta.dst.to_be_bytes(),
            proto: meta.proto as u8,
            ..Default::default()
        }
    }
}

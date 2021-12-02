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

use serde::{Deserialize, Serialize};

use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

use crate::headers::Ipv4Meta;
use crate::packet::{PacketRead, ReadErr, WriteErr};
use crate::rule::{
    MatchExact, MatchExactVal, MatchPrefix, MatchPrefixVal, MatchRangeVal,
};

#[cfg(all(not(feature = "std"), not(test)))]
use illumos_ddi_dki::uintptr_t;

#[cfg(any(feature = "std", test))]
use crate::uintptr_t;

pub const IPV4_HDR_SZ: usize = std::mem::size_of::<Ipv4HdrRaw>();

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
            ip: Ipv4Addr { val: u32::from_be_bytes([192, 168, 2, 0]) },
            net_prefix: 24
        })
    );

    assert_eq!(
        "192.168.2.0/24".parse(),
        Ok(Ipv4Cidr {
            ip: Ipv4Addr { val: u32::from_be_bytes([192, 168, 2, 0]) },
            net_prefix: 24
        })
    );

    assert_eq!(
        "192.168.2.9/24".parse(),
        Ok(Ipv4Cidr {
            ip: Ipv4Addr { val: u32::from_be_bytes([192, 168, 2, 0]) },
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
    val: u32,
}

impl MatchExactVal for Ipv4Addr {}
impl MatchRangeVal for Ipv4Addr {}

impl Ipv4Addr {
    // TODO Consider creating Ipv4CidrPrefix so we can have a
    // compile-time guarantee that prefix is valid.
    pub fn mask(mut self, net_prefix: u8) -> Self {
        if net_prefix == 0 {
            return self;
        }

        let mut bits = i32::MIN;
        bits = bits >> (net_prefix - 1);
        self.val = self.val & bits as u32;
        self
    }

    /// Create a new `IPv4Addr` from an array of bytes in network order.
    pub const fn new(bytes: [u8; 4]) -> Self {
        // We really aren't concerned with LE vs. BE here, but the
        // fact is that an IPv4 address is represented as four octets
        // in network-order, so we use the BE parsing function here,
        // even though we're storing the u32 in native-endian, and we
        // still need to convert it to network order when writing to
        // packet byte stream.
        Self { val: u32::from_be_bytes(bytes) }
    }

    /// Produce a `u32` of `self` in network byte order.
    pub fn to_be(self) -> u32 {
        self.val.to_be()
    }

    pub fn to_be_bytes(self) -> [u8; 4] {
        self.val.to_be_bytes()
    }

    /// Produce a value of `self` in network order as a type
    /// appropriate for passing to SDT probes.
    pub fn to_be_sdt(self) -> uintptr_t {
        self.val.to_be() as uintptr_t
    }
}

pub type Ipv4AddrTuple = (u8, u8, u8, u8);

impl From<Ipv4Addr> for Ipv4AddrTuple {
    fn from(ip: Ipv4Addr) -> Ipv4AddrTuple {
        let bytes = ip.to_be_bytes();
        (bytes[0], bytes[1], bytes[2], bytes[3])
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
        ip.val
    }
}

impl From<u32> for Ipv4Addr {
    fn from(val: u32) -> Ipv4Addr {
        Ipv4Addr { val }
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
        let octets_arr = [octets[0], octets[1], octets[2], octets[3]];
        Ok(Ipv4Addr { val: u32::from_be_bytes(octets_arr) })
    }
}

#[test]
fn ipv4_addr_good() {
    assert_eq!(
        "192.168.33.10".parse(),
        Ok(Ipv4Addr { val: u32::from_be_bytes([192, 168, 33, 10]) })
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
            (self.val >> 24) & 0xFF,
            (self.val >> 16) & 0xFF,
            (self.val >> 8) & 0xFF,
            self.val & 0xFF
        )
    }
}

// It helps to have the Debug output include a human-friendly version
// of the address.
impl Debug for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ipv4Addr {{ val: {} ({}) }}", self.val, self)
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

impl Ipv4HdrRaw {
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

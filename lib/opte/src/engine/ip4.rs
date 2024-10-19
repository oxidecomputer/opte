// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! IPv4 headers.

use super::predicate::MatchExact;
use super::predicate::MatchExactVal;
use super::predicate::MatchPrefix;
use super::predicate::MatchPrefixVal;
use super::predicate::MatchRangeVal;
use alloc::string::String;
use core::fmt;
use core::fmt::Debug;
use core::fmt::Display;
use core::num::ParseIntError;
use core::result;
pub use opte_api::Ipv4Addr;
pub use opte_api::Ipv4Cidr;
pub use opte_api::Ipv4PrefixLen;
pub use opte_api::Protocol;
use serde::Deserialize;
use serde::Serialize;

pub const IPV4_HDR_LEN_MASK: u8 = 0x0F;
pub const IPV4_HDR_VER_MASK: u8 = 0xF0;
pub const IPV4_HDR_VER_SHIFT: u8 = 4;
pub const IPV4_VERSION: u8 = 4;

pub const DEF_ROUTE: &str = "0.0.0.0/0";

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
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct Ipv4Push {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: Protocol,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Ipv4Mod {
    pub src: Option<Ipv4Addr>,
    pub dst: Option<Ipv4Addr>,
    pub proto: Option<Protocol>,
}

/// Options for computing a ULP checksum.
#[derive(Clone, Copy, Debug)]
pub enum UlpCsumOpt {
    /// Compute a partial checksum, using only the pseudo-header.
    ///
    /// This is intended in situations in which computing the checksum of the
    /// body itself can be offloaded to hardware.
    Partial,
    /// Compute the full checksum, including the pseudo-header, ULP header and
    /// the ULP body.
    Full,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::engine::packet::Packet;

    #[test]
    fn emit() {
        let ip = Ipv4Meta {
            src: Ipv4Addr::from([10, 0, 0, 54]),
            dst: Ipv4Addr::from([52, 10, 128, 69]),
            proto: Protocol::TCP,
            ttl: 64,
            ident: 2662,
            hdr_len: 20,
            total_len: 60,
            csum: [0; 2],
        };

        let len = ip.hdr_len();
        assert_eq!(20, len);

        let mut pkt = Packet::alloc_and_expand(len);
        let mut wtr = pkt.seg0_wtr();
        ip.emit(wtr.slice_mut(ip.hdr_len()).unwrap());
        assert_eq!(len, pkt.len());

        #[rustfmt::skip]
        let expected_bytes = vec![
            // version + IHL
            0x45,
            // DSCP + ECN
            0x00,
            // total length
            0x00, 0x3C,
            // ident
            0x0A, 0x66,
            // flags + frag offset
            0x40, 0x00,
            // TTL
            0x40,
            // protocol
            0x06,
            // checksum
            0x00, 0x00,
            // source
            0x0A, 0x00, 0x00, 0x36,
            // dest
            0x34, 0x0A, 0x80, 0x45,
        ];
        assert_eq!(&expected_bytes, pkt.seg_bytes(0));
    }
}

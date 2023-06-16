// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! IPv4 headers.

use core::fmt;
use core::fmt::Debug;
use core::fmt::Display;
use core::num::ParseIntError;
use core::result;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::LayoutVerified;
use zerocopy::Unaligned;

use super::checksum::Checksum;
use super::checksum::HeaderChecksum;
use super::headers::ModifyAction;
use super::headers::PushAction;
use super::headers::RawHeader;
use super::packet::PacketReadMut;
use super::packet::ReadErr;
use super::predicate::MatchExact;
use super::predicate::MatchExactVal;
use super::predicate::MatchPrefix;
use super::predicate::MatchPrefixVal;
use super::predicate::MatchRangeVal;
pub use opte_api::Ipv4Addr;
pub use opte_api::Ipv4Cidr;
pub use opte_api::Ipv4PrefixLen;
pub use opte_api::Protocol;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::String;
    } else {
        use std::string::String;
    }
}

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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Ipv4Meta {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: Protocol,
    pub ttl: u8,
    pub ident: u16,
    pub total_len: u16,
    pub csum: [u8; 2],
    // We keep the options as raw bytes and don't parse them out.
    pub options_bytes: Option<[u8; Ipv4Hdr::MAX_OPTION_SIZE]>,
    pub options_len: usize,
}

impl Default for Ipv4Meta {
    fn default() -> Self {
        Self {
            src: Ipv4Addr::ANY_ADDR,
            dst: Ipv4Addr::ANY_ADDR,
            proto: Protocol::Unknown(255),
            ttl: 64,
            ident: 0,
            total_len: 0,
            csum: [0; 2],
            options_bytes: None,
            options_len: 0,
        }
    }
}

impl Ipv4Meta {
    pub fn compute_hdr_csum(&mut self) {
        let mut hdr = [0; Ipv4Hdr::MAX_SIZE];
        self.csum = [0; 2];
        self.emit(&mut hdr[..self.hdr_len()]);
        let csum = Checksum::compute(&hdr);
        self.csum = HeaderChecksum::from(csum).bytes();
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
                let mut csum = self.pseudo_csum();
                csum.add_bytes(ulp_hdr);
                csum.add_bytes(body);
                csum
            }
        }
    }

    #[inline]
    pub fn emit(&self, dst: &mut [u8]) {
        debug_assert_eq!(dst.len(), self.hdr_len());
        // The header must be an integral number of 32-bit words
        debug_assert_eq!(self.hdr_len() % 4, 0);
        let base = &mut dst[..Ipv4HdrRaw::SIZE];
        let mut raw = Ipv4HdrRaw::new_mut(base).unwrap();
        raw.write(Ipv4HdrRaw::from(self));
        if let Some(bytes) = self.options_bytes {
            dst[Ipv4Hdr::BASE_SIZE..]
                .copy_from_slice(&bytes[..self.options_len]);
        }
    }

    /// Return the length of the header needed to emit the metadata.
    pub fn hdr_len(&self) -> usize {
        Ipv4Hdr::BASE_SIZE + self.options_len
    }

    /// Populate `bytes` with the pseudo header bytes.
    pub fn pseudo_bytes(&self, bytes: &mut [u8; 12]) {
        bytes[0..4].copy_from_slice(&self.src.bytes());
        bytes[4..8].copy_from_slice(&self.dst.bytes());
        // `self` is a valid `Ipv4Meta` so we know `hdr_len` fits in a `u16`.
        let hdr_len = u16::try_from(self.hdr_len()).unwrap();
        let ulp_len = self.total_len - hdr_len;
        let len_bytes = ulp_len.to_be_bytes();
        bytes[8..12].copy_from_slice(&[
            0,
            u8::from(self.proto),
            len_bytes[0],
            len_bytes[1],
        ]);
    }

    /// Return a [`Checksum`] of the pseudo header.
    pub fn pseudo_csum(&self) -> Checksum {
        let mut pseudo_bytes = [0u8; 12];
        self.pseudo_bytes(&mut pseudo_bytes);
        Checksum::compute(&pseudo_bytes)
    }
}

impl<'a> From<&Ipv4Hdr<'a>> for Ipv4Meta {
    fn from(ip4: &Ipv4Hdr) -> Self {
        let (options_bytes, options_len) = ip4
            .options_raw()
            .map(|opts| {
                let mut dst = [0; Ipv4Hdr::MAX_OPTION_SIZE];
                dst[..opts.len()].copy_from_slice(opts);
                (Some(dst), opts.len())
            })
            .unwrap_or_default();
        let raw = ip4.bytes.read();
        Self {
            src: Ipv4Addr::from(raw.src),
            dst: Ipv4Addr::from(raw.dst),
            proto: Protocol::from(raw.proto),
            ttl: raw.ttl,
            ident: u16::from_be_bytes(raw.ident),
            total_len: u16::from_be_bytes(raw.total_len),
            csum: raw.csum,
            options_bytes,
            options_len,
        }
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

impl PushAction<Ipv4Meta> for Ipv4Push {
    fn push(&self) -> Ipv4Meta {
        Ipv4Meta {
            src: self.src,
            dst: self.dst,
            proto: self.proto,
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Ipv4Mod {
    pub src: Option<Ipv4Addr>,
    pub dst: Option<Ipv4Addr>,
    pub proto: Option<Protocol>,
}

impl ModifyAction<Ipv4Meta> for Ipv4Mod {
    fn modify(&self, meta: &mut Ipv4Meta) {
        if let Some(src) = self.src {
            meta.src = src;
        }

        if let Some(dst) = self.dst {
            meta.dst = dst;
        }

        if let Some(proto) = self.proto {
            meta.proto = proto;
        }
    }
}

#[derive(Debug)]
pub struct Ipv4Hdr<'a> {
    bytes: LayoutVerified<&'a mut [u8], Ipv4HdrRaw>,
    options: Option<&'a mut [u8]>,
}

impl<'a> Ipv4Hdr<'a> {
    /// The size of the fixed IPv4 header.
    ///
    /// IPv4 headers are variable length, including a fixed, 20-byte portion as
    /// well as a variable number of options, each with potentially different
    /// sizes. This size describes the fixed portion.
    pub const BASE_SIZE: usize = Ipv4HdrRaw::SIZE;

    /// The maximum size of an IPv4 header.
    ///
    /// The header length is a 4-bit field (IHL) which gives the size in 32-bit
    /// words; the maximum header size is therefore (2^4 - 1) * 4 = 60 bytes.
    pub const MAX_SIZE: usize = 60;

    /// The maximum size of any options in an IPv4 header.
    pub const MAX_OPTION_SIZE: usize = Self::MAX_SIZE - Self::BASE_SIZE;

    pub const CSUM_BEGIN: usize = 10;
    pub const CSUM_END: usize = 12;

    #[inline]
    pub fn csum(&self) -> [u8; 2] {
        self.bytes.csum
    }

    #[inline]
    pub fn dst(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.bytes.dst)
    }

    /// Return the header length (including options), in bytes.
    #[inline]
    pub fn hdr_len(&self) -> usize {
        usize::from((self.bytes.ver_hdr_len & IPV4_HDR_LEN_MASK) * 4)
    }

    /// Return the options bytes, if any.
    pub fn options_raw(&self) -> Option<&[u8]> {
        self.options.as_deref()
    }

    #[inline]
    pub fn ident(&self) -> u16 {
        u16::from_be_bytes(self.bytes.ident)
    }

    pub fn parse<'b, R>(rdr: &'b mut R) -> Result<Self, Ipv4HdrError>
    where
        R: PacketReadMut<'a>,
    {
        let src = rdr.slice_mut(Ipv4HdrRaw::SIZE)?;
        let mut ip = Self { bytes: Ipv4HdrRaw::new_mut(src)?, options: None };

        let hdr_len = ip.hdr_len();

        if hdr_len < Self::BASE_SIZE {
            return Err(Ipv4HdrError::HeaderTruncated { hdr_len });
        }

        if hdr_len > Self::BASE_SIZE {
            let opts_len = hdr_len - Self::BASE_SIZE;
            ip.options = rdr
                .slice_mut(opts_len)
                .map(Some)
                .map_err(|error| Ipv4HdrError::OptionsTruncated { error })?;
        }

        let total_len = ip.total_len();
        if total_len < hdr_len {
            return Err(Ipv4HdrError::BadTotalLen { total_len });
        }

        let _proto = Protocol::try_from(ip.bytes.proto).map_err(|_s| {
            Ipv4HdrError::UnexpectedProtocol { protocol: ip.bytes.proto }
        })?;

        Ok(ip)
    }

    /// Return the [`Protocol`].
    #[inline]
    pub fn proto(&self) -> Protocol {
        // Unwrap: We verified the proto is good upon parsing.
        Protocol::try_from(self.bytes.proto).unwrap()
    }

    /// Populate `bytes` with the pseudo header bytes.
    pub fn pseudo_bytes(&self, bytes: &mut [u8; 12]) {
        bytes[0..4].copy_from_slice(&self.bytes.src);
        bytes[4..8].copy_from_slice(&self.bytes.dst);
        let len_bytes = self.ulp_len().to_be_bytes();
        bytes[8..12].copy_from_slice(&[
            0,
            self.bytes.proto,
            len_bytes[0],
            len_bytes[1],
        ]);
    }

    /// Return a [`Checksum`] of the pseudo header.
    pub fn pseudo_csum(&self) -> Checksum {
        let mut pseudo_bytes = [0u8; 12];
        self.pseudo_bytes(&mut pseudo_bytes);
        Checksum::compute(&pseudo_bytes)
    }

    #[inline]
    pub fn set_csum(&mut self, csum: [u8; 2]) {
        self.bytes.csum = csum;
    }

    /// Set the `Total Length` field.
    #[inline]
    pub fn set_total_len(&mut self, len: u16) {
        self.bytes.total_len = len.to_be_bytes()
    }

    /// Return the source address.
    #[inline]
    pub fn src(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.bytes.src)
    }

    /// Return the value of the `Total Length` field.
    #[inline]
    pub fn total_len(&self) -> usize {
        usize::from(u16::from_be_bytes(self.bytes.total_len))
    }

    #[inline]
    pub fn ttl(&self) -> u8 {
        self.bytes.ttl
    }

    /// Return the length of the Upper Layer Protocol (ULP) portion of
    /// the packet.
    #[inline]
    pub fn ulp_len(&self) -> usize {
        self.total_len() - self.hdr_len()
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv4HdrError {
    BadTotalLen { total_len: usize },
    BadVersion { vsn: u8 },
    HeaderTruncated { hdr_len: usize },
    OptionsTruncated { error: ReadErr },
    ReadError { error: ReadErr },
    UnexpectedProtocol { protocol: u8 },
}

impl From<ReadErr> for Ipv4HdrError {
    fn from(error: ReadErr) -> Self {
        Ipv4HdrError::ReadError { error }
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
    #[inline]
    fn new_mut(
        src: &mut [u8],
    ) -> Result<LayoutVerified<&mut [u8], Self>, ReadErr> {
        debug_assert_eq!(src.len(), Self::SIZE);
        let hdr = match LayoutVerified::new(src) {
            Some(hdr) => hdr,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }
}

impl Default for Ipv4HdrRaw {
    fn default() -> Self {
        Ipv4HdrRaw {
            ver_hdr_len: (IPV4_VERSION << IPV4_HDR_VER_SHIFT)
                | u8::try_from(Ipv4Hdr::BASE_SIZE / 4).unwrap(),
            dscp_ecn: 0x0,
            total_len: [0x0; 2],
            ident: [0x0; 2],
            frag_and_flags: [0x40, 0x0],
            ttl: 64,
            proto: u8::from(Protocol::Unknown(255)),
            csum: [0x0; 2],
            src: [0x0; 4],
            dst: [0x0; 4],
        }
    }
}

impl From<&Ipv4Meta> for Ipv4HdrRaw {
    #[inline]
    fn from(meta: &Ipv4Meta) -> Self {
        Ipv4HdrRaw {
            ver_hdr_len: (IPV4_VERSION << IPV4_HDR_VER_SHIFT)
                | u8::try_from(meta.hdr_len() / 4).unwrap(),
            dscp_ecn: 0x0,
            total_len: meta.total_len.to_be_bytes(),
            ident: meta.ident.to_be_bytes(),
            frag_and_flags: [0x40, 0x0],
            ttl: meta.ttl,
            proto: u8::from(meta.proto),
            csum: meta.csum,
            src: meta.src.bytes(),
            dst: meta.dst.bytes(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::engine::packet::Packet;

    #[test]
    fn emit_no_options() {
        let ip = Ipv4Meta {
            src: Ipv4Addr::from([10, 0, 0, 54]),
            dst: Ipv4Addr::from([52, 10, 128, 69]),
            proto: Protocol::TCP,
            ttl: 64,
            ident: 2662,
            total_len: 60,
            csum: [0; 2],
            options_bytes: None,
            options_len: 0,
        };

        // No IPv4 options included, so length
        // should be just the base header length
        let len = ip.hdr_len();
        assert_eq!(len, Ipv4Hdr::BASE_SIZE);

        let mut pkt = Packet::alloc_and_expand(len);
        let mut wtr = pkt.seg0_wtr();
        ip.emit(wtr.slice_mut(ip.hdr_len()).unwrap());
        assert_eq!(len, pkt.len());

        #[rustfmt::skip]
        let expected_bytes = vec![
            // version + IHL (5 => 5*4 = 20 bytes of header)
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

    #[test]
    fn emit_with_options() {
        let mut options_bytes = [0x00; Ipv4Hdr::MAX_OPTION_SIZE];
        #[rustfmt::skip]
        let options = [
            // NOPs
            0x01, 0x01, 0x01,
            // EOOL (End of Options List)
            0x00,
        ];
        options_bytes[..options.len()].copy_from_slice(&options);

        let ip = Ipv4Meta {
            src: Ipv4Addr::from([10, 0, 0, 54]),
            dst: Ipv4Addr::from([52, 10, 128, 69]),
            proto: Protocol::TCP,
            ttl: 64,
            ident: 2662,
            total_len: 60,
            csum: [0; 2],
            options_bytes: Some(options_bytes),
            options_len: options.len(),
        };

        // Header length should include options
        let len = ip.hdr_len();
        assert_eq!(len, Ipv4Hdr::BASE_SIZE + options.len());

        let mut pkt = Packet::alloc_and_expand(len);
        let mut wtr = pkt.seg0_wtr();
        ip.emit(wtr.slice_mut(ip.hdr_len()).unwrap());
        assert_eq!(len, pkt.len());

        #[rustfmt::skip]
        let mut expected_bytes = vec![
            // version + IHL (6 => 6*4=20 bytes base header + 4 bytes options)
            0x46,
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
        expected_bytes.extend(options);
        assert_eq!(&expected_bytes, pkt.seg_bytes(0));
    }

    #[test]
    fn parse_options_truncated() {
        #[rustfmt::skip]
        let option_bytes = [
            // NOPs
            0x01, 0x01, 0x01,
            // EOOL (End of Options List)
            0x00,
        ];

        let hdr_len = Ipv4Hdr::BASE_SIZE
            + option_bytes.len()
            // Indicate there's an extra 32-bit word of options
            + 4;

        #[rustfmt::skip]
        let base_bytes = vec![
            // version + IHL
            0x40 | ((hdr_len / 4) as u8),
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
        assert_eq!(base_bytes.len(), Ipv4Hdr::BASE_SIZE);

        let pkt_bytes = base_bytes
            .iter()
            .copied()
            .chain(option_bytes.iter().copied())
            .collect::<Vec<_>>();

        let mut pkt = Packet::copy(&pkt_bytes);
        let mut rdr = pkt.get_rdr_mut();
        let ip4_hdr_err = Ipv4Hdr::parse(&mut rdr)
            .expect_err("expected to fail parsing malformed IPv4 header");

        assert_eq!(
            ip4_hdr_err,
            Ipv4HdrError::OptionsTruncated { error: ReadErr::NotEnoughBytes }
        );
    }
}

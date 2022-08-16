// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use super::checksum::Checksum;
use super::headers::{
    Header, HeaderAction, IpMeta, IpMetaOpt, ModActionArg, PushActionArg,
    RawHeader,
};
use super::ip4::Protocol;
use super::packet::{PacketRead, ReadErr, WriteError};
use core::convert::TryFrom;
use core::mem::size_of;
pub use opte_api::{Ipv6Addr, Ipv6Cidr};
use serde::{Deserialize, Serialize};
use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::vec::Vec;
    } else {
        use std::vec::Vec;
    }
}

pub const IPV6_HDR_VSN_MASK: u8 = 0xF0;
pub const IPV6_HDR_VSN_SHIFT: u8 = 4;
pub const IPV6_HDR_SZ: usize = size_of::<Ipv6HdrRaw>();
pub const IPV6_VERSION: u8 = 6;

#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct Ipv6Meta {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub proto: Protocol,
}

impl PushActionArg for Ipv6Meta {}

impl From<&Ipv6Hdr> for Ipv6Meta {
    fn from(ip6: &Ipv6Hdr) -> Self {
        Ipv6Meta {
            src: ip6.src,
            dst: ip6.dst,
            // XXX Parse extension headers
            //
            // * Create ExtensionHdrs enum and various Extension
            // Header types
            //
            // * Create a NextHdr enum which can be either Protocol or ExtHdr
            //
            // * Write parse_ipv6_ext() function to parse various ext
            // headers. Call that in parse_ipv6().
            //
            // * Change how this meta structure is built. That is,
            // replace this function with something that builds the
            // IPv6 Metadata from base header + extensions.
            //
            // * Remember that you don't need to do all this right
            // now, you have a demo to make.
            proto: ip6.next_hdr,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Ipv6MetaOpt {
    src: Option<[u8; 16]>,
    dst: Option<[u8; 16]>,
}

impl ModActionArg for Ipv6MetaOpt {}

impl Ipv6Meta {
    pub fn push(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        proto: Protocol,
    ) -> HeaderAction<IpMeta, IpMetaOpt> {
        HeaderAction::Push(IpMeta::Ip6(Ipv6Meta { src, dst, proto }))
    }
}

#[derive(Clone, Debug)]
pub struct Ipv6Hdr {
    vsn_class_flow: [u8; 4],
    payload_len: u16,
    // The next_hdr is the first Next Header value. The proto is the
    // actual upper layer protocol.
    next_hdr: Protocol,
    proto: Protocol,
    hop_limit: u8,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    // XXX Add vec, array, anymap of extension headers
}

#[macro_export]
macro_rules! assert_ip6 {
    ($left:expr, $right:expr) => {
        assert!(
            $left.pay_len() == $right.pay_len(),
            "ip6 payload len mismatch: {} != {}",
            $left.pay_len(),
            $right.pay_len(),
        );

        assert!(
            $left.src() == $right.src(),
            "ip6 src mismatch: {} != {}",
            $left.src(),
            $right.src(),
        );

        assert!(
            $left.dst() == $right.dst(),
            "ip6 dst mismatch: {} != {}",
            $left.dst(),
            $right.dst(),
        );
    };
}

impl Ipv6Hdr {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.hdr_len());
        let base = Ipv6HdrRaw::from(self);
        bytes.extend_from_slice(base.as_bytes());
        bytes
    }

    pub fn dst(&self) -> Ipv6Addr {
        self.dst
    }

    /// The length of the extension headers, if any.
    ///
    /// XXX We currently don't check for extension headers.
    pub fn ext_len(&self) -> usize {
        0
    }

    /// Return the length of the header porition of the packet.
    ///
    /// XXX We currently don't check for extension headers.
    pub fn hdr_len(&self) -> usize {
        IPV6_HDR_SZ
    }

    /// Return the first next header of the packet.
    pub fn next_hdr(&self) -> Protocol {
        self.next_hdr
    }

    /// Return the length of the payload portion of the packet.
    ///
    /// NOTE: This currently does not entertain Jumbograms.
    ///
    /// XXX We should probably check for the Jumbogram extension
    /// header and drop any packets with it.
    pub fn pay_len(&self) -> usize {
        self.payload_len as usize - self.ext_len()
    }

    /// Return the [`Protocol`] of the packet.
    pub fn proto(&self) -> Protocol {
        self.proto
    }

    /// Return the pseudo header bytes.
    pub fn pseudo_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(&self.src.bytes());
        bytes.extend_from_slice(&self.dst.bytes());
        bytes.extend_from_slice(&(self.pay_len() as u32).to_be_bytes());
        bytes.extend_from_slice(&[0u8, 0u8, 0u8, self.next_hdr as u8]);
        assert_eq!(bytes.len(), 40);
        bytes
    }

    /// Return a [`Checksum`] of the pseudo header.
    pub fn pseudo_csum(&self) -> Checksum {
        Checksum::compute(&self.pseudo_bytes())
    }

    pub fn set_total_len(&mut self, len: u16) {
        self.payload_len = len - self.hdr_len() as u16;
    }

    pub fn src(&self) -> Ipv6Addr {
        self.src
    }

    pub fn unify(&mut self, meta: &Ipv6Meta) {
        self.proto = meta.proto;
        self.src = meta.src;
        self.dst = meta.dst;
    }
}

impl Header for Ipv6Hdr {
    type Error = Ipv6HdrError;

    fn parse<'a, 'b, R>(rdr: &'b mut R) -> Result<Self, Self::Error>
    where
        R: PacketRead<'a>,
    {
        Ipv6Hdr::try_from(&Ipv6HdrRaw::raw_zc(rdr)?)
    }
}

#[derive(Debug)]
pub enum Ipv6HdrError {
    BadVersion { vsn: u8 },
    ReadError { error: ReadErr },
    UnexpectedNextHeader { next_header: u8 },
}

impl From<ReadErr> for Ipv6HdrError {
    fn from(error: ReadErr) -> Self {
        Ipv6HdrError::ReadError { error }
    }
}

impl TryFrom<&LayoutVerified<&[u8], Ipv6HdrRaw>> for Ipv6Hdr {
    type Error = Ipv6HdrError;

    fn try_from(
        raw: &LayoutVerified<&[u8], Ipv6HdrRaw>,
    ) -> Result<Self, Self::Error> {
        let vsn_class_flow = raw.vsn_class_flow;
        let vsn = (vsn_class_flow[0] & IPV6_HDR_VSN_MASK) >> IPV6_HDR_VSN_SHIFT;

        if vsn != IPV6_VERSION {
            return Err(Ipv6HdrError::BadVersion { vsn });
        }

        let next_hdr = Protocol::try_from(raw.next_hdr).map_err(|_s| {
            Ipv6HdrError::UnexpectedNextHeader { next_header: raw.next_hdr }
        })?;

        Ok(Ipv6Hdr {
            vsn_class_flow,
            payload_len: u16::from_be_bytes(raw.payload_len),
            next_hdr,
            proto: next_hdr,
            hop_limit: raw.hop_limit,
            src: Ipv6Addr::from(raw.src),
            dst: Ipv6Addr::from(raw.dst),
        })
    }
}

impl From<&Ipv6Meta> for Ipv6Hdr {
    fn from(meta: &Ipv6Meta) -> Self {
        Ipv6Hdr {
            vsn_class_flow: [0x60, 0x00, 0x00, 0x00],
            payload_len: 0,
            // The next_hdr is the first Next Header value. The proto is the
            // actual upper layer protocol.
            next_hdr: meta.proto,
            proto: meta.proto,
            hop_limit: 255,
            src: meta.src,
            dst: meta.dst,
        }
    }
}

/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, Debug, FromBytes, AsBytes, Unaligned)]
pub struct Ipv6HdrRaw {
    pub vsn_class_flow: [u8; 4],
    pub payload_len: [u8; 2],
    pub next_hdr: u8,
    pub hop_limit: u8,
    pub src: [u8; 16],
    pub dst: [u8; 16],
}

impl<'a> Ipv6HdrRaw {
    /// Return the length of the payload portion of the packet.
    ///
    /// NOTE: This currently does not enternain Jumbograms.
    ///
    /// XXX We should probably check for the Jumbogram extension
    /// header and drop any packets with it.
    pub fn pay_len(&self) -> usize {
        u16::from_be_bytes(self.payload_len) as usize
    }
}

impl<'a> RawHeader<'a> for Ipv6HdrRaw {
    fn raw_zc<'b, R: PacketRead<'a>>(
        rdr: &'b mut R,
    ) -> Result<LayoutVerified<&'a [u8], Self>, ReadErr> {
        let slice = rdr.slice(size_of::<Self>())?;
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

impl Default for Ipv6HdrRaw {
    fn default() -> Self {
        Self {
            // Version=6, Traffic Class=0, Flow=0
            vsn_class_flow: [0x60, 0x00, 0x00, 0x00],
            payload_len: [0, 2],
            next_hdr: 0,
            hop_limit: 255,
            src: [0; 16],
            dst: [0; 16],
        }
    }
}

impl From<&Ipv6Hdr> for Ipv6HdrRaw {
    fn from(ip6: &Ipv6Hdr) -> Self {
        Ipv6HdrRaw {
            vsn_class_flow: ip6.vsn_class_flow,
            payload_len: ip6.payload_len.to_be_bytes(),
            next_hdr: ip6.next_hdr as u8,
            hop_limit: ip6.hop_limit,
            src: ip6.src.bytes(),
            dst: ip6.dst.bytes(),
        }
    }
}

impl From<Ipv6Meta> for Ipv6HdrRaw {
    fn from(meta: Ipv6Meta) -> Self {
        Ipv6HdrRaw {
            src: meta.src.bytes(),
            dst: meta.dst.bytes(),
            next_hdr: meta.proto as u8,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod test {
    fn from_pairs() {
        let ip6 = super::Ipv6Addr::from([
            0x2601, 0x0284, 0x4100, 0xE240, 0x0000, 0x0000, 0xC0A8, 0x01F5,
        ]);

        assert_eq!(
            ip6.bytes(),
            [
                0x26, 0x01, 0x02, 0x84, 0x41, 0x00, 0xE2, 0x40, 0x00, 0x00,
                0x00, 0x00, 0xC0, 0xA8, 0x01, 0xF5
            ]
        );
    }
}

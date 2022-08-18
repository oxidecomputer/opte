// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use super::checksum::Checksum;
use super::headers::{
    Header, HeaderAction, IpMeta, IpMetaOpt, ModifyActionArg, PushActionArg,
};
use super::ip4::Protocol;
use super::packet::{PacketRead, ReadErr};
use core::convert::TryFrom;
pub use opte_api::{Ipv6Addr, Ipv6Cidr};
use serde::{Deserialize, Serialize};
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv6FragmentHeader;
use smoltcp::wire::Ipv6HopByHopHeader;
use smoltcp::wire::Ipv6Packet;
use smoltcp::wire::Ipv6RoutingHeader;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::vec::Vec;
    } else {
        use std::vec::Vec;
    }
}

pub const IPV6_HDR_VSN_MASK: u8 = 0xF0;
pub const IPV6_HDR_VSN_SHIFT: u8 = 4;
pub const IPV6_HDR_SZ: usize = smoltcp::wire::IPV6_HEADER_LEN;
pub const IPV6_VERSION: u8 = 6;
pub const DDM_HEADER_ID: u8 = 0xFE;

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
        Ipv6Meta { src: ip6.src, dst: ip6.dst, proto: ip6.proto }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Ipv6MetaOpt {
    src: Option<[u8; 16]>,
    dst: Option<[u8; 16]>,
}

impl ModifyActionArg for Ipv6MetaOpt {}

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
    // Length of payload, including extension headers
    payload_len: u16,
    // Protocol of the next header, which may be an extension or the upper-layer
    // protocol.
    next_hdr: IpProtocol,
    // The upper-layer protocol
    proto: Protocol,
    hop_limit: u8,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    extension_headers: Vec<u8>,
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
    #[cfg(any(feature = "std", test))]
    pub fn new_tcp<A: Into<Ipv6Addr>>(
        tcp: &super::tcp::TcpHdr,
        body: &[u8],
        next_hdr: IpProtocol,
        extension_headers: &[u8],
        src: A,
        dst: A,
    ) -> Self {
        let payload_len =
            (tcp.hdr_len() + body.len() + extension_headers.len()) as u16;

        Self {
            vsn_class_flow: [IPV6_VERSION, 0, 0, 0],
            payload_len,
            next_hdr,
            proto: Protocol::TCP,
            hop_limit: 255,
            src: src.into(),
            dst: dst.into(),
            extension_headers: extension_headers.to_vec(),
        }
    }
    /// Return the bytes of the header, including the base and any extensions
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.hdr_len());
        bytes.extend_from_slice(&self.vsn_class_flow);
        bytes.extend_from_slice(&self.payload_len.to_be_bytes());
        bytes.extend_from_slice(&[u8::from(self.next_hdr), self.hop_limit]);
        bytes.extend_from_slice(&self.src.bytes());
        bytes.extend_from_slice(&self.dst.bytes());
        bytes.extend_from_slice(&self.extension_headers);
        bytes
    }

    /// Return the destination IPv6 address
    pub fn dst(&self) -> Ipv6Addr {
        self.dst
    }

    /// The length of the extension headers, if any.
    pub fn ext_len(&self) -> usize {
        self.extension_headers.len()
    }

    /// Return the length of the header portion of the packet, including
    /// extension headers
    pub fn hdr_len(&self) -> usize {
        IPV6_HDR_SZ + self.ext_len()
    }

    /// Return the first next header of the packet, which may be the upper-layer
    /// protocol, or the protocol of an extension header.
    pub fn next_hdr(&self) -> IpProtocol {
        self.next_hdr
    }

    /// Return the length of the payload portion of the packet, including any
    /// extension headers.
    ///
    /// NOTE: This currently does not entertain Jumbograms.
    ///
    /// XXX We should probably check for the Jumbogram extension
    /// header and drop any packets with it.
    pub fn pay_len(&self) -> usize {
        usize::from(self.payload_len)
    }

    /// Return the length of the upper-layer protocol payload.
    pub fn ulp_len(&self) -> usize {
        self.pay_len() - self.ext_len()
    }

    /// Return the upper-layer [`Protocol`] of the packet.
    pub fn proto(&self) -> Protocol {
        self.proto
    }

    /// Return the pseudo header bytes.
    pub fn pseudo_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(&self.src.bytes());
        bytes.extend_from_slice(&self.dst.bytes());
        bytes.extend_from_slice(&(self.pay_len() as u32).to_be_bytes());
        bytes.extend_from_slice(&[0u8, 0u8, 0u8, u8::from(self.next_hdr)]);
        assert_eq!(bytes.len(), 40);
        bytes
    }

    /// Return a [`Checksum`] of the pseudo header.
    pub fn pseudo_csum(&self) -> Checksum {
        Checksum::compute(&self.pseudo_bytes())
    }

    /// Set the total length of the packet
    pub fn set_total_len(&mut self, len: u16) {
        self.payload_len = len - self.hdr_len() as u16;
    }

    /// Return the source IPv6 address
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
        // Parse the base IPv6 header
        let buf = rdr.slice(IPV6_HDR_SZ)?;
        let base_header = Ipv6Packet::new_unchecked(buf);
        let vsn_class_flow = [buf[0], buf[1], buf[2], buf[3]];
        let payload_len = base_header.payload_len();
        let next_hdr = base_header.next_header();
        let hop_limit = base_header.hop_limit();
        let src = Ipv6Addr::from(base_header.src_addr().0);
        let dst = Ipv6Addr::from(base_header.dst_addr().0);

        // Parse any extension headers.
        //
        // At this point, we don't need any information out of the headers other
        // than their length (to determine the boundary with the ULP). We'll
        // verify that the headers are supported, but otherwise maintain only a
        // byte array with their contents.
        let mut extension_headers = vec![];
        let mut next_header = next_hdr;
        while !is_ulp_protocol(next_header) {
            match next_header {
                IpProtocol::HopByHop => {
                    let buf = rdr.slice(rdr.seg_left())?;
                    let header = Ipv6HopByHopHeader::new_checked(buf)?;
                    let n_bytes = 8 * (usize::from(header.header_len()) + 1);
                    extension_headers.extend_from_slice(&buf[..n_bytes]);
                    next_header = header.next_header();

                    // Put back any bytes in the segment not needed for this header.
                    rdr.seek_back(buf.len() - n_bytes)?;
                }
                IpProtocol::Ipv6Route => {
                    let buf = rdr.slice(rdr.seg_left())?;
                    let header = Ipv6RoutingHeader::new_checked(buf)?;
                    let n_bytes = 8 * (usize::from(header.header_len()) + 1);
                    extension_headers.extend_from_slice(&buf[..n_bytes]);
                    next_header = header.next_header();
                    rdr.seek_back(buf.len() - n_bytes)?;
                }
                IpProtocol::Ipv6Frag => {
                    // This header's length is fixed.
                    //
                    // We'd like to use `size_of::<Ipv6FragmentRepr>()`, but
                    // that is not `repr(packed)`, so we'd possibly count
                    // padding.
                    const FRAGMENT_HDR_SIZE: usize = 8;
                    let buf = rdr.slice(FRAGMENT_HDR_SIZE)?;
                    let header = Ipv6FragmentHeader::new_checked(buf)?;
                    extension_headers.extend_from_slice(buf);
                    next_header = header.next_header();
                }
                IpProtocol::Unknown(x) if x == DDM_HEADER_ID => {
                    // The DDM header packet begins with next_header and the
                    // length, which describes the entire header excluding
                    // next_header.
                    const FIXED_LEN: usize = 2;
                    let fixed_buf = rdr.slice(FIXED_LEN)?;
                    next_header = IpProtocol::from(fixed_buf[0]);
                    let total_length = usize::from(fixed_buf[1]) + 1;
                    let remainder = rdr.slice(total_length - FIXED_LEN)?;
                    extension_headers.extend_from_slice(fixed_buf);
                    extension_headers.extend_from_slice(remainder);
                }
                x => {
                    return Err(Ipv6HdrError::UnexpectedNextHeader {
                        next_header: x.into(),
                    });
                }
            }
        }
        // Panic: The protocol is the last value of next header, and since
        // we've matched on everything we support in the `try_from` impl, this
        // unwrap can't panic.
        let proto = Protocol::try_from(next_header).unwrap();

        Ok(Ipv6Hdr {
            vsn_class_flow,
            payload_len,
            next_hdr,
            proto,
            hop_limit,
            src,
            dst,
            extension_headers,
        })
    }
}

fn is_ulp_protocol(proto: IpProtocol) -> bool {
    use IpProtocol::*;
    matches!(proto, Icmp | Igmp | Tcp | Udp | Icmpv6)
}

#[derive(Debug)]
pub enum Ipv6HdrError {
    BadVersion { vsn: u8 },
    ReadError { error: ReadErr },
    UnexpectedNextHeader { next_header: u8 },
    Truncated,
    Malformed,
}

impl From<smoltcp::Error> for Ipv6HdrError {
    fn from(err: smoltcp::Error) -> Ipv6HdrError {
        use smoltcp::Error::*;
        match err {
            Truncated => Ipv6HdrError::Truncated,
            Malformed => Ipv6HdrError::Malformed,
            _ => unreachable!("Impossible smoltcp error variant: {:#?}", err),
        }
    }
}

impl From<ReadErr> for Ipv6HdrError {
    fn from(error: ReadErr) -> Self {
        Ipv6HdrError::ReadError { error }
    }
}

impl From<&Ipv6Meta> for Ipv6Hdr {
    fn from(meta: &Ipv6Meta) -> Self {
        Ipv6Hdr {
            vsn_class_flow: [0x60, 0x00, 0x00, 0x00],
            payload_len: 0,
            // The next_hdr is the first Next Header value. The proto is the
            // actual upper layer protocol.
            next_hdr: meta.proto.into(),
            proto: meta.proto,
            hop_limit: 255,
            src: meta.src,
            dst: meta.dst,
            extension_headers: vec![],
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::Ipv6Hdr;
    use super::DDM_HEADER_ID;
    use super::IPV6_HDR_SZ;
    use crate::engine::headers::Header;
    use crate::engine::packet::Initialized;
    use crate::engine::packet::Packet;
    use crate::engine::packet::PacketReader;
    use itertools::Itertools;
    use smoltcp::wire::IpProtocol;
    use smoltcp::wire::Ipv6Address;
    use smoltcp::wire::Ipv6FragmentHeader;
    use smoltcp::wire::Ipv6FragmentRepr;
    use smoltcp::wire::Ipv6HopByHopHeader;
    use smoltcp::wire::Ipv6HopByHopRepr;
    use smoltcp::wire::Ipv6Packet;
    use smoltcp::wire::Ipv6Repr;
    use smoltcp::wire::Ipv6RoutingHeader;
    use smoltcp::wire::Ipv6RoutingRepr;
    use std::vec::Vec;

    // Test packet size and payload length
    const BUFFER_LEN: usize = 512;
    const PAYLOAD_LEN: usize = 512 - IPV6_HDR_SZ;
    pub(crate) const SUPPORTED_EXTENSIONS: [IpProtocol; 4] = [
        IpProtocol::HopByHop,
        IpProtocol::Ipv6Route,
        IpProtocol::Ipv6Frag,
        IpProtocol::Unknown(DDM_HEADER_ID),
    ];

    #[test]
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

    fn base_header() -> Ipv6Repr {
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            dst_addr: Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            next_header: IpProtocol::Tcp,
            payload_len: PAYLOAD_LEN,
            hop_limit: 6,
        }
    }

    fn hop_by_hop_header() -> Ipv6HopByHopRepr<'static> {
        // in 8-octet units, not including the first
        const OPTION_LEN: usize = 1;
        // Pad to the next multiple of 8, then one more 8-octet unit
        const LEN: usize = 6 + OPTION_LEN * 8;
        static OPTIONS: [u8; LEN] = [0; LEN];
        Ipv6HopByHopRepr {
            next_header: IpProtocol::Tcp,
            length: OPTION_LEN as _,
            options: &OPTIONS,
        }
    }

    fn route_header() -> Ipv6RoutingRepr<'static> {
        // In 8-octet units, not including the first, i.e., this just needs the
        // home address, 128 bits.
        let length = 2;
        let segments_left = 1;
        let home_address = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        Ipv6RoutingRepr::Type2 {
            next_header: IpProtocol::Tcp,
            length,
            segments_left,
            home_address,
        }
    }

    fn fragment_header() -> Ipv6FragmentRepr {
        Ipv6FragmentRepr {
            next_header: IpProtocol::Tcp,
            frag_offset: 128,
            more_frags: false,
            ident: 0x17,
        }
    }

    // Generate a test packet.
    //
    // This creates a base IPv6 header, and any extension headers with protocols
    // defined by `extensions`. There is always a base header, and the ULP is
    // always defined to be TCP. `extensions` can be empty.
    //
    // This returns the byte array of the packet, plus the size of the entire
    // header, including extensions.
    pub(crate) fn generate_test_packet(
        extensions: &[IpProtocol],
    ) -> (Vec<u8>, usize) {
        // Create a chain of headers, starting with the base. Emit them into
        // byte arrays, to test parsing.
        let mut data = vec![0; BUFFER_LEN];
        let mut header_start = 0;
        let mut next_header_pos = 6;
        let mut header_end = IPV6_HDR_SZ;
        let mut buf = &mut data[header_start..];

        // The base header. The payload length is always the same, but the base
        // protocol may be updated.
        let base = base_header();
        let mut packet = Ipv6Packet::new_checked(&mut buf).unwrap();
        base.emit(&mut packet);

        if extensions.is_empty() {
            // No extensions at all, just base header with a TCP ULP
            return (buf.to_vec(), IPV6_HDR_SZ);
        }

        let mut it = extensions.iter();
        while let Some(extension) = it.next() {
            // First, update the _previous_ next_header with the type of this
            // extension header. They form a linked-list. We do this first, so
            // that in the case of the first extension header, we're rewriting
            // the `next_header` value in the base header.
            buf[next_header_pos] = u8::from(*extension);

            // For every extension header, the `next_header` is the first octet.
            // That is, the base header is the only one where it's a different
            // position.
            next_header_pos = 0;

            // Grab the remaining packet buffer, from the end of the previous
            // header. This is where we'll start inserting the current extension
            // header.
            buf = &mut data[header_end..];

            // Insert the bytes of each extension header, returning the number
            // of octets written.
            use IpProtocol::*;
            let len = match extension {
                HopByHop => {
                    let hbh = hop_by_hop_header();
                    let mut packet =
                        Ipv6HopByHopHeader::new_checked(&mut buf).unwrap();
                    hbh.emit(&mut packet);
                    hbh.buffer_len()
                }
                Ipv6Frag => {
                    let frag = fragment_header();
                    let mut packet =
                        Ipv6FragmentHeader::new_checked(&mut buf).unwrap();
                    frag.emit(&mut packet);
                    frag.buffer_len()
                }
                Ipv6Route => {
                    let route = route_header();
                    let mut packet =
                        Ipv6RoutingHeader::new_checked(&mut buf).unwrap();
                    route.emit(&mut packet);
                    route.buffer_len()
                }
                Unknown(x) if x == &DDM_HEADER_ID => {
                    // Starts with next_header, then a length excluding that.
                    const DDM_HDR_LEN: usize = 15;
                    buf[1] = DDM_HDR_LEN as u8;
                    DDM_HDR_LEN + 1
                }
                _ => unimplemented!(
                    "Extension header {:#?} unsupported",
                    extension
                ),
            };

            // Move the position markers to the new header.
            header_start = header_end;
            header_end += len;
        }

        // Set the last header to point to the ULP
        data[header_start] = u8::from(IpProtocol::Tcp);

        (data, header_end)
    }

    // Test every permuation of the supported extension headers, verifying the
    // computed lengths of:
    //
    // - Payload length
    // - ULP length
    // - Extension header length
    // - Full header length
    #[test]
    fn test_extension_header_lengths_ok() {
        for n_extensions in 0..SUPPORTED_EXTENSIONS.len() {
            for extensions in
                SUPPORTED_EXTENSIONS.into_iter().permutations(n_extensions)
            {
                let (buf, pos) = generate_test_packet(extensions.as_slice());
                let bytes = Packet::<Initialized>::copy(&buf);
                let mut reader = PacketReader::new(&bytes, ());
                let header = Ipv6Hdr::parse(&mut reader).unwrap();
                assert_all_lengths_ok(&header, pos);
            }
        }
    }

    fn assert_all_lengths_ok(header: &Ipv6Hdr, header_end: usize) {
        assert_eq!(
            header.as_bytes().len(),
            header.hdr_len(),
            "Header length does not match the octet count of the \
            header bytes themselves"
        );
        assert_eq!(
            header.hdr_len(),
            header_end,
            "Header length does not include all extension headers"
        );
        assert_eq!(
            header.pay_len(),
            PAYLOAD_LEN,
            "Payload length does not include all extension headers",
        );
        assert_eq!(
            header.ext_len(),
            header_end - IPV6_HDR_SZ,
            "Extension header size is incorrect",
        );
        assert_eq!(
            header.ulp_len(),
            PAYLOAD_LEN - header.ext_len(),
            "ULP length is not correct"
        );
    }
}

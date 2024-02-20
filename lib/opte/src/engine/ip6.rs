// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! IPv6 headers.

use super::checksum::Checksum;
use super::d_error::DError;
use super::headers::ModifyAction;
use super::headers::PushAction;
use super::ip4::Protocol;
pub use super::ip4::UlpCsumOpt;
use super::packet::PacketReadMut;
use super::packet::ReadErr;
use crate::engine::predicate::MatchExact;
use crate::engine::predicate::MatchExactVal;
use crate::engine::predicate::MatchPrefix;
use crate::engine::predicate::MatchPrefixVal;
pub use opte_api::Ipv6Addr;
pub use opte_api::Ipv6Cidr;
use serde::Deserialize;
use serde::Serialize;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv6ExtHeader;
use smoltcp::wire::Ipv6FragmentHeader;
use smoltcp::wire::Ipv6HopByHopHeader;
use smoltcp::wire::Ipv6Packet;
use smoltcp::wire::Ipv6RoutingHeader;

pub const IPV6_HDR_VSN_MASK: u8 = 0xF0;
pub const IPV6_HDR_VSN_SHIFT: u8 = 4;
pub const IPV6_VERSION: u8 = 6;
pub const DDM_HEADER_ID: u8 = 0xFE;

impl MatchExactVal for Ipv6Addr {}
impl MatchPrefixVal for Ipv6Cidr {}

impl MatchExact<Ipv6Addr> for Ipv6Addr {
    fn match_exact(&self, val: &Ipv6Addr) -> bool {
        *self == *val
    }
}

impl MatchPrefix<Ipv6Cidr> for Ipv6Addr {
    fn match_prefix(&self, prefix: &Ipv6Cidr) -> bool {
        prefix.is_member(*self)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Ipv6Meta {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub next_hdr: IpProtocol,
    pub proto: Protocol,
    pub hop_limit: u8,
    pub pay_len: u16,

    // For now we hold extensions as raw bytes. Ideally, each extension
    // we support should get its own meta-like type and be declared
    // optional.
    //
    // ```
    // pub hbh: Option<HopByHop>,
    // pub routing: Option<Routing>,
    // pub frag: Option<Fragment>,
    // ...
    // ```
    pub ext: Option<[u8; 64]>,
    // NOTE: We need `ext_len` explicitly, because `ext` is a fixed-size array.
    pub ext_len: usize,
}

impl Default for Ipv6Meta {
    fn default() -> Self {
        Self {
            src: Ipv6Addr::from([0; 16]),
            dst: Ipv6Addr::from([0; 16]),
            next_hdr: IpProtocol::Unknown(255),
            proto: Protocol::Unknown(255),
            hop_limit: 128,
            pay_len: 0,
            ext: None,
            ext_len: 0,
        }
    }
}

impl Ipv6Meta {
    /// Compute the [`Checksum`] of the contained ULP datagram.
    ///
    /// This computes the checksum of the pseudo-header, and adds to it the sum
    /// of the ULP header and body.
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
        let base = &mut dst[0..Ipv6Hdr::BASE_SIZE];
        let mut pkt = Ipv6Packet::new_unchecked(base);
        pkt.set_version(6);
        // For now assume no traffic class or flow label.
        pkt.set_traffic_class(0);
        pkt.set_flow_label(0);
        pkt.set_payload_len(self.pay_len);
        pkt.set_next_header(self.next_hdr);
        pkt.set_hop_limit(self.hop_limit);
        pkt.set_src_addr(self.src.into());
        pkt.set_dst_addr(self.dst.into());

        if let Some(ext_bytes) = self.ext {
            dst[Ipv6Hdr::BASE_SIZE..]
                .copy_from_slice(&ext_bytes[0..self.ext_len]);
        }
    }

    /// Return the length of the IPv6 header, including the base header and
    /// extension headers.
    pub fn hdr_len(&self) -> usize {
        Ipv6Hdr::BASE_SIZE + self.ext_len
    }

    /// Return the pseudo header bytes.
    pub fn pseudo_bytes(&self, bytes: &mut [u8; 40]) {
        bytes[0..16].copy_from_slice(&self.src.bytes());
        bytes[16..32].copy_from_slice(&self.dst.bytes());
        bytes[32..36].copy_from_slice(&((self.pay_len as u32).to_be_bytes()));
        bytes[36..40].copy_from_slice(&[0u8, 0u8, 0u8, u8::from(self.proto)]);
    }

    /// Return a [`Checksum`] of the pseudo header.
    pub fn pseudo_csum(&self) -> Checksum {
        let mut bytes = [0u8; 40];
        self.pseudo_bytes(&mut bytes);
        Checksum::compute(&bytes)
    }

    /// Return the total length of the packet, including the base header, any
    /// extension headers, and the payload itself.
    pub fn total_len(&self) -> u16 {
        Ipv6Hdr::BASE_SIZE as u16 + self.pay_len
    }
}

impl<'a> From<&Ipv6Hdr<'a>> for Ipv6Meta {
    fn from(ip6: &Ipv6Hdr) -> Self {
        let (ext, ext_len) = if let Some((ext_bytes, _proto_off)) = &ip6.ext {
            let ext_len = ext_bytes.len();
            assert!(ext_len <= 64);
            let mut ext = [0; 64];
            ext[0..ext_len].copy_from_slice(ext_bytes);
            (Some(ext), ext_len)
        } else {
            (None, 0)
        };

        Ipv6Meta {
            src: ip6.src(),
            dst: ip6.dst(),
            proto: ip6.proto(),
            next_hdr: ip6.next_hdr(),
            hop_limit: ip6.hop_limit(),
            pay_len: ip6.pay_len() as u16,
            ext,
            ext_len,
        }
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct Ipv6Push {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub proto: Protocol,
}

impl PushAction<Ipv6Meta> for Ipv6Push {
    fn push(&self) -> Ipv6Meta {
        Ipv6Meta {
            src: self.src,
            dst: self.dst,
            proto: self.proto,
            // For now you cannot push extension headers.
            next_hdr: IpProtocol::from(self.proto),
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Ipv6Mod {
    pub src: Option<Ipv6Addr>,
    pub dst: Option<Ipv6Addr>,
    pub proto: Option<Protocol>,
}

impl ModifyAction<Ipv6Meta> for Ipv6Mod {
    fn modify(&self, meta: &mut Ipv6Meta) {
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

/// An IPv6 packet header.
#[derive(Debug)]
pub struct Ipv6Hdr<'a> {
    base: Ipv6Packet<&'a mut [u8]>,
    // The proto reference points to the last next_header value (aka
    // the upper-layer protocol number).
    // proto: &'a mut u8,

    // (extensions bytes, protocol field offset)
    ext: Option<(&'a mut [u8], usize)>,
}

impl<'a> Ipv6Hdr<'a> {
    /// The size of the fixed IPv6 header.
    ///
    /// IPv6 headers are variable length, including a fixed, 40-byte portion as
    /// well as a variable number of extension headers, each with potentially
    /// different sizes. This size describes the fixed portion.
    pub const BASE_SIZE: usize = 40;

    /// The offset of the Protocol (Next Header) field in the base header.
    pub const BASE_HDR_PROTO_OFFSET: usize = 6;

    /// Return the destination address.
    pub fn dst(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.base.dst_addr())
    }

    /// Return the length of the extensions headers, or 0 if there are
    /// none.
    fn ext_len(&self) -> usize {
        match &self.ext {
            None => 0,
            Some((ext_bytes, _)) => ext_bytes.len(),
        }
    }

    /// Return the length of the header portion of the packet, including
    /// extension headers
    pub fn hdr_len(&self) -> usize {
        Self::BASE_SIZE + self.ext_len()
    }

    /// Return the hop limit value.
    pub fn hop_limit(&self) -> u8 {
        self.base.hop_limit()
    }

    fn next_hdr(&self) -> IpProtocol {
        self.base.next_header()
    }

    /// Parse an IPv6 packet out of a reader, if possible.
    pub fn parse<'b>(
        rdr: &'b mut impl PacketReadMut<'a>,
    ) -> Result<Self, Ipv6HdrError> {
        // Parse the base IPv6 header.
        let buf = rdr.slice_mut(Self::BASE_SIZE)?;
        let base = Ipv6Packet::new_unchecked(buf);

        // Parse any extension headers.
        //
        // At this point, we don't need any information out of the headers other
        // than their length (to determine the boundary with the ULP). We'll
        // verify that the headers are supported, but otherwise maintain only a
        // byte array with their contents.
        let mut ext_len = 0;
        let mut next_header = base.next_header();

        // Either we have no extensions or we are parsing zero'd
        // header data for the purpose of emitting.
        if is_ulp_protocol(next_header) {
            return Ok(Self { base, ext: None });
        }

        // XXX: smoltcp now more or less imposes the same pattern on all these
        //      branches. This could do with some cleanup as a result.
        let mut proto_offset: usize = 0;
        while !is_ulp_protocol(next_header) {
            match next_header {
                IpProtocol::HopByHop => {
                    let buf = rdr.slice_mut(rdr.seg_left())?;
                    let mut header = Ipv6ExtHeader::new_checked(buf)?;
                    _ = Ipv6HopByHopHeader::new_checked(header.payload_mut())?;
                    let n_bytes = 8 * (usize::from(header.header_len()) + 1);
                    next_header = header.next_header();
                    let buf = header.into_inner();
                    ext_len += n_bytes;

                    // Put back any bytes in the segment not needed
                    // for this header.
                    rdr.seek_back(buf.len() - n_bytes)?;

                    if !is_ulp_protocol(next_header) {
                        proto_offset += n_bytes;
                    }
                }

                IpProtocol::Ipv6Route => {
                    let buf = rdr.slice_mut(rdr.seg_left())?;
                    let mut header = Ipv6ExtHeader::new_checked(buf)?;
                    _ = Ipv6RoutingHeader::new_checked(header.payload_mut())?;
                    let n_bytes = 8 * (usize::from(header.header_len()) + 1);
                    next_header = header.next_header();
                    let buf = header.into_inner();
                    ext_len += n_bytes;
                    rdr.seek_back(buf.len() - n_bytes)?;

                    if !is_ulp_protocol(next_header) {
                        proto_offset += n_bytes;
                    }
                }

                IpProtocol::Ipv6Frag => {
                    // This header's length is fixed.
                    //
                    // We'd like to use `size_of::<Ipv6FragmentRepr>()`, but
                    // that is not `repr(packed)`, so we'd possibly count
                    // padding.
                    const FRAGMENT_HDR_SIZE: usize = 8;
                    let buf = rdr.slice_mut(FRAGMENT_HDR_SIZE)?;
                    ext_len += buf.len();
                    let mut header = Ipv6ExtHeader::new_checked(buf)?;
                    _ = Ipv6FragmentHeader::new_checked(header.payload_mut())?;
                    next_header = header.next_header();

                    if !is_ulp_protocol(next_header) {
                        proto_offset += FRAGMENT_HDR_SIZE;
                    }
                }

                IpProtocol::Unknown(x) if x == DDM_HEADER_ID => {
                    // The DDM header packet begins with next_header and the
                    // length, which describes the entire header excluding
                    // next_header.
                    const FIXED_LEN: usize = 2;
                    let fixed_buf = rdr.slice_mut(FIXED_LEN)?;
                    next_header = IpProtocol::from(fixed_buf[0]);
                    // We add one to account for the next_header byte,
                    // as the DDM length does not include it.
                    let total_len = usize::from(fixed_buf[1]) + 1;
                    // We need to read remainder so that the reader is
                    // in the correct place for the proto_offset to be
                    // calculated correctly.
                    let _remainder = rdr.slice_mut(total_len - FIXED_LEN);
                    ext_len += total_len;

                    if !is_ulp_protocol(next_header) {
                        proto_offset += total_len;
                    }
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
        let _protocol = Protocol::from(next_header);

        // Seek back to the start of the extensions, then take a slice of
        // all the options.
        rdr.seek_back(ext_len)?;
        let ext = Some((rdr.slice_mut(ext_len)?, proto_offset));
        Ok(Self { base, ext })
    }

    /// Return the payload length.
    ///
    /// This length includes any extension headers along with the
    /// body.
    pub fn pay_len(&self) -> usize {
        usize::from(self.base.payload_len())
    }

    /// Return the Upper Layer Protocol in use.
    ///
    /// Even when extension headers are in play, this call always
    /// returns the ULP. In other words, it always returns the final
    /// "Next Header" value at the end of the extension header chain.
    pub fn proto(&self) -> Protocol {
        // Unwrap: We verified the proto is good upon parsing.
        if let Some((bytes, proto_offset)) = &self.ext {
            Protocol::from(bytes[*proto_offset])
        } else {
            Protocol::from(self.base.next_header())
        }
    }

    /// Populate `bytes` with the pseudo header bytes.
    pub fn pseudo_bytes(&self, bytes: &mut [u8; 40]) {
        bytes[0..16].copy_from_slice(self.base.src_addr().as_bytes());
        bytes[16..32].copy_from_slice(self.base.dst_addr().as_bytes());
        bytes[32..36].copy_from_slice(&(self.pay_len() as u32).to_be_bytes());
        bytes[36..40].copy_from_slice(&[0u8, 0u8, 0u8, u8::from(self.proto())]);
    }

    /// Return a [`Checksum`] of the pseudo header.
    pub fn pseudo_csum(&self) -> Checksum {
        let mut pseudo_bytes = [0u8; 40];
        self.pseudo_bytes(&mut pseudo_bytes);
        Checksum::compute(&pseudo_bytes)
    }

    /// Set the total length of the packet.
    ///
    /// There is no "total length" for IPv6; it keeps a payload
    /// length. However, this API is useful for having a consistent
    /// method for setting lengths when emitting headers.
    pub fn set_total_len(&mut self, len: u16) {
        // The Payload Length field of the IPv6 header includes the ULP payload
        // _and_ the length of any extension headers.
        self.base.set_payload_len(len - Self::BASE_SIZE as u16);
    }

    /// Return the source address.
    pub fn src(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.base.src_addr())
    }

    /// Return the total length of the packet, including the base header, any
    /// extension headers, and the payload itself.
    pub fn total_len(&self) -> usize {
        self.pay_len() + Self::BASE_SIZE
    }

    /// Return the length of the upper-layer protocol payload.
    pub fn ulp_len(&self) -> usize {
        self.pay_len() - self.ext_len()
    }
}

fn is_ulp_protocol(proto: IpProtocol) -> bool {
    use IpProtocol::*;
    matches!(proto, Icmp | Igmp | Tcp | Udp | Icmpv6)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, DError)]
#[derror(leaf_data = Ipv6HdrError::derror_data)]
pub enum Ipv6HdrError {
    BadVersion { vsn: u8 },
    ReadError(ReadErr),
    UnexpectedNextHeader { next_header: u8 },
    Malformed,
}

impl Ipv6HdrError {
    fn derror_data(&self, data: &mut [u64]) {
        data[0] = match self {
            Self::BadVersion { vsn } => *vsn as u64,
            Self::UnexpectedNextHeader { next_header } => *next_header as u64,
            _ => 0,
        }
    }
}

impl From<smoltcp::wire::Error> for Ipv6HdrError {
    fn from(_error: smoltcp::wire::Error) -> Ipv6HdrError {
        Ipv6HdrError::Malformed
    }
}

impl From<ReadErr> for Ipv6HdrError {
    fn from(error: ReadErr) -> Self {
        Ipv6HdrError::ReadError(error)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::engine::packet::Packet;
    use itertools::Itertools;
    use smoltcp::wire::IpProtocol;
    use smoltcp::wire::Ipv6Address;
    use smoltcp::wire::Ipv6FragmentHeader;
    use smoltcp::wire::Ipv6FragmentRepr;
    use smoltcp::wire::Ipv6HopByHopHeader;
    use smoltcp::wire::Ipv6HopByHopRepr;
    use smoltcp::wire::Ipv6OptionRepr;
    use smoltcp::wire::Ipv6Packet;
    use smoltcp::wire::Ipv6Repr;
    use smoltcp::wire::Ipv6RoutingHeader;
    use smoltcp::wire::Ipv6RoutingRepr;
    use std::vec::Vec;

    // Test packet size and payload length
    const BUFFER_LEN: usize = 512;
    const PAYLOAD_LEN: usize = 512 - Ipv6Hdr::BASE_SIZE;
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
        // SmolTCP limits us to 2 max HBH options in its repr.
        // Pad to the next multiple of 8, then one more 8-octet unit.
        // - Ext header takes 2B
        // - PadN(n) takes 2B, then n bytes.
        // => 4 + fill
        const LEN: usize = 4 + OPTION_LEN * 8;
        static OPTIONS: [Ipv6OptionRepr; 1] =
            [Ipv6OptionRepr::PadN(LEN as u8); 1];
        Ipv6HopByHopRepr {
            options: heapless::Vec::from_slice(&OPTIONS).unwrap(),
        }
    }

    fn route_header() -> Ipv6RoutingRepr<'static> {
        // In 8-octet units, not including the first, i.e., this just needs the
        // home address, 128 bits.
        let segments_left = 1;
        let home_address = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        Ipv6RoutingRepr::Type2 { segments_left, home_address }
    }

    fn fragment_header() -> Ipv6FragmentRepr {
        Ipv6FragmentRepr { frag_offset: 128, more_frags: false, ident: 0x17 }
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
        let mut header_end = Ipv6Hdr::BASE_SIZE;
        let mut buf = &mut data[header_start..];

        // The base header. The payload length is always the same, but the base
        // protocol may be updated.
        let base = base_header();
        let mut packet = Ipv6Packet::new_checked(&mut buf).unwrap();
        base.emit(&mut packet);

        if extensions.is_empty() {
            // No extensions at all, just base header with a TCP ULP
            return (buf.to_vec(), Ipv6Hdr::BASE_SIZE);
        }

        for extension in extensions {
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
            //
            // For each extension header, we need to build the top level ExtHeader
            // and set length manually: this is (inner_len / 8) := the number of
            // 8-byte blocks FOLLOWING the first.
            use IpProtocol::*;
            let len = match extension {
                HopByHop => {
                    let hbh = hop_by_hop_header();
                    let mut packet =
                        Ipv6ExtHeader::new_checked(&mut buf).unwrap();
                    packet.set_next_header(IpProtocol::Tcp);
                    packet.set_header_len((hbh.buffer_len() / 8) as u8);
                    let mut hbh_packet =
                        Ipv6HopByHopHeader::new_checked(packet.payload_mut())
                            .unwrap();
                    hbh.emit(&mut hbh_packet);
                    2 + hbh.buffer_len()
                }
                Ipv6Frag => {
                    let frag = fragment_header();
                    let mut packet =
                        Ipv6ExtHeader::new_checked(&mut buf).unwrap();
                    packet.set_next_header(IpProtocol::Tcp);
                    packet.set_header_len(0);
                    let mut frag_packet =
                        Ipv6FragmentHeader::new_checked(packet.payload_mut())
                            .unwrap();
                    frag.emit(&mut frag_packet);
                    2 + frag.buffer_len()
                }
                Ipv6Route => {
                    let route = route_header();
                    let mut packet =
                        Ipv6ExtHeader::new_checked(&mut buf).unwrap();
                    packet.set_next_header(IpProtocol::Tcp);
                    packet.set_header_len((route.buffer_len() / 8) as u8);
                    let mut route_packet =
                        Ipv6RoutingHeader::new_checked(packet.payload_mut())
                            .unwrap();
                    route.emit(&mut route_packet);
                    2 + route.buffer_len()
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
                let mut pkt = Packet::copy(&buf);
                let mut reader = pkt.get_rdr_mut();
                let header = Ipv6Hdr::parse(&mut reader).unwrap();
                assert_all_lengths_ok(&header, pos);
            }
        }
    }

    fn assert_all_lengths_ok(header: &Ipv6Hdr, header_end: usize) {
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
            header_end - Ipv6Hdr::BASE_SIZE,
            "Extension header size is incorrect",
        );
        assert_eq!(
            header.ulp_len(),
            PAYLOAD_LEN - header.ext_len(),
            "ULP length is not correct"
        );
        assert_eq!(
            header.total_len(),
            PAYLOAD_LEN + Ipv6Hdr::BASE_SIZE,
            "Total packet length is not correct",
        );
    }

    #[test]
    fn test_ipv6_addr_match_exact() {
        let addr: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(addr.match_exact(&addr));
        assert!(!addr.match_exact(&("fd00::2".parse().unwrap())));
    }

    #[test]
    fn test_ipv6_cidr_match_prefix() {
        let cidr: Ipv6Cidr = "fd00::1/16".parse().unwrap();
        let addr: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(addr.match_prefix(&cidr));

        let addr: Ipv6Addr = "fd00::2".parse().unwrap();
        assert!(addr.match_prefix(&cidr));

        let addr: Ipv6Addr = "fd01::1".parse().unwrap();
        assert!(!addr.match_prefix(&cidr));

        let addr: Ipv6Addr = "fd01::2".parse().unwrap();
        assert!(!addr.match_prefix(&cidr));
    }

    #[test]
    fn emit() {
        let ip = Ipv6Meta {
            src: Ipv6Addr::from_const([
                0xFE80, 0x0000, 0x0000, 0x0000, 0xBAF8, 0x53FF, 0xFEAF, 0x537D,
            ]),
            dst: Ipv6Addr::from_const([
                0xFE80, 0x000, 0x0000, 0x0000, 0x56BE, 0xF7FF, 0xFE0B, 0x09EC,
            ]),
            proto: Protocol::ICMPv6,
            next_hdr: IpProtocol::Icmpv6,
            hop_limit: 255,
            pay_len: 32,
            ext: None,
            ext_len: 0,
        };

        let len = ip.hdr_len();
        let mut pkt = Packet::alloc_and_expand(len);
        let mut wtr = pkt.seg0_wtr();
        ip.emit(wtr.slice_mut(ip.hdr_len()).unwrap());
        assert_eq!(len, pkt.len());

        #[rustfmt::skip]
        let expected_bytes = [
            // version + class + label
            0x60, 0x00, 0x00, 0x00,
            // payload len
            0x00, 0x20,
            // next header + hop limit
            0x3A, 0xFF,
            // source address
            0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xBA, 0xF8, 0x53, 0xFF, 0xFE, 0xAF, 0x53, 0x7D,
            // dest address
            0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x56, 0xBE, 0xF7, 0xFF, 0xFE, 0x0B, 0x09, 0xEC,
        ];
        assert_eq!(&expected_bytes, pkt.seg_bytes(0));
    }

    #[test]
    fn test_set_total_len() {
        // Create a packet with one extension header.
        let (buf, _) = generate_test_packet(&[IpProtocol::Ipv6Frag]);
        let mut pkt = Packet::copy(&buf);
        let mut reader = pkt.get_rdr_mut();
        let mut header = Ipv6Hdr::parse(&mut reader).unwrap();

        // Set the total length to 128.
        //
        // The Payload Length field contains the length of both the extension
        // headers and the actual ULP. Because we have the Fragmentation header,
        // which is a fixed 8-octet thing, this should result in a Payload
        // Length of 128 - Ipv6Hdr::BASE_SIZE = 78.
        const NEW_SIZE: usize = 128;
        header.set_total_len(NEW_SIZE as _);
        assert_eq!(header.total_len(), NEW_SIZE);
        assert_eq!(header.hdr_len(), Ipv6Hdr::BASE_SIZE + 8);
        assert_eq!(header.pay_len(), NEW_SIZE - Ipv6Hdr::BASE_SIZE);
    }

    #[test]
    fn test_ip6_meta_total_len() {
        // Create a packet with one extension header.
        let (buf, _) = generate_test_packet(&[IpProtocol::Ipv6Frag]);
        let mut pkt = Packet::copy(&buf);
        let mut reader = pkt.get_rdr_mut();
        let header = Ipv6Hdr::parse(&mut reader).unwrap();

        // Previously, the `Ipv6Meta::total_len` method double-counted the
        // extension header length. Assert we don't do that here.
        let meta = Ipv6Meta::from(&header);
        assert!(meta.ext.is_some());
        assert_eq!(meta.ext_len, 8); // Fixed size
        assert_eq!(
            meta.total_len() as usize,
            header.hdr_len() + header.ulp_len()
        );
    }
}

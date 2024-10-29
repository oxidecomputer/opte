// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Types for creating, reading, and writing network packets.
//!
//! TODO
//!
//! * Add hardware offload information to [`Packet`].
//!

use super::headers::IpAddr;
use super::headers::AF_INET;
use super::headers::AF_INET6;
use super::ip::v4::Ipv4Addr;
use super::ip::v4::Protocol;
use super::ip::v6::Ipv6Addr;
use super::Direction;
use crate::d_error::DError;
use alloc::string::String;
use core::ffi::CStr;
use core::fmt;
use core::fmt::Display;
use core::hash::Hash;
use core::result;
use crc32fast::Hasher;
use dyn_clone::DynClone;
use ingot::types::PacketParseError;
use serde::Deserialize;
use serde::Serialize;

pub static FLOW_ID_DEFAULT: InnerFlowId = InnerFlowId {
    proto: 255,
    addrs: AddrPair::V4 { src: Ipv4Addr::ANY_ADDR, dst: Ipv4Addr::ANY_ADDR },
    src_port: 0,
    dst_port: 0,
};

/// The flow identifier.
///
/// In this case the flow identifier is the 5-tuple of the inner IP
/// packet.
///
/// NOTE: This should not be defined in `opte`. Rather, the engine
/// should be generic in regards to the flow identifier, and it should
/// be up to the `NetworkImpl` to define it.
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[repr(C, align(4))]
pub struct InnerFlowId {
    // Using a `u8` here for `proto` hides the enum repr from SDTs.
    pub proto: u8,
    // We could also theoretically get to a 38B packing if we reduce
    // AddrPair's repr from `u16` to `u8`. However, on the dtrace/illumos
    // side `union addrs` is 4B aligned -- in6_addr_t has a 4B alignment.
    // So, this layout has to match that constraint -- placing addrs at
    // offset 0x2 with `u16` discriminant sets up 4B alignment for the
    // enum variant data (and this struct itself is 4B aligned).
    pub addrs: AddrPair,
    pub src_port: u16,
    pub dst_port: u16,
}

impl InnerFlowId {
    pub fn crc32(&self) -> u32 {
        let mut hasher = Hasher::new();
        self.hash(&mut hasher);
        hasher.finalize()
    }
}

impl Default for InnerFlowId {
    fn default() -> Self {
        FLOW_ID_DEFAULT
    }
}

/// Tagged union of a source-dest IP address pair, used to avoid
/// duplicating the discriminator.
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[repr(C, u16)]
pub enum AddrPair {
    V4 { src: Ipv4Addr, dst: Ipv4Addr } = AF_INET as u16,
    V6 { src: Ipv6Addr, dst: Ipv6Addr } = AF_INET6 as u16,
}

impl AddrPair {
    pub fn mirror(self) -> Self {
        match self {
            Self::V4 { src, dst } => Self::V4 { src: dst, dst: src },
            Self::V6 { src, dst } => Self::V6 { src: dst, dst: src },
        }
    }
}

impl InnerFlowId {
    /// Swap IP source and destination as well as ULP port source and
    /// destination.
    pub fn mirror(self) -> Self {
        Self {
            proto: self.proto,
            addrs: self.addrs.mirror(),
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }

    pub fn src_ip(&self) -> IpAddr {
        match self.addrs {
            AddrPair::V4 { src, .. } => src.into(),
            AddrPair::V6 { src, .. } => src.into(),
        }
    }

    pub fn dst_ip(&self) -> IpAddr {
        match self.addrs {
            AddrPair::V4 { dst, .. } => dst.into(),
            AddrPair::V6 { dst, .. } => dst.into(),
        }
    }

    pub fn protocol(&self) -> Protocol {
        Protocol::from(self.proto)
    }
}

impl Display for InnerFlowId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}:{}",
            self.protocol(),
            self.src_ip(),
            self.src_port,
            self.dst_ip(),
            self.dst_port,
        )
    }
}

pub trait PacketState {}

/// A packet body transformation.
///
/// A body transformation allows an action to modify zero, one, or
/// more bytes of a packet's body. The body starts directly after the
/// ULP header, and continues to the last byte of the packet. This
/// transformation is currently limited to only modifying bytes; it
/// does not allow adding or removing bytes (e.g. to encrypt the body).
pub trait BodyTransform: fmt::Display + DynClone {
    /// Execute the body transformation. The body segments include
    /// **only** body data, starting directly after the end of the ULP
    /// header.
    ///
    /// # Errors
    ///
    /// The transformation can choose to return a
    /// [`BodyTransformError`] at any time if the body is not
    /// acceptable. On error, none or some of the bytes may have been
    /// modified.
    fn run(
        &self,
        dir: Direction,
        body_segs: &mut [&mut [u8]],
    ) -> Result<(), BodyTransformError>;
}

dyn_clone::clone_trait_object!(BodyTransform);

#[derive(Debug)]
pub enum BodyTransformError {
    NoPayload,
    ParseFailure(String),
    Todo(String),
    UnexpectedBody(String),
}

impl From<smoltcp::wire::Error> for BodyTransformError {
    fn from(e: smoltcp::wire::Error) -> Self {
        Self::ParseFailure(format!("{}", e))
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SegAdjustError {
    /// Attempt to place the end of the writable/readable area of the
    /// segment past the limit of the underlying buffer.
    EndPastLimit,

    /// Attempt to place the start of the writable/readable area of
    /// the segment before the base of the underlying buffer.
    StartBeforeBase,

    /// Attempt to place the start the writable/readable area of the
    /// segment outside the range of the underlying buffer.
    StartPastEnd,
}

#[derive(Clone, Copy, Debug)]
pub enum ModifierCreateError {
    StartOutOfRange,
    EndOutOfRange,
}

#[derive(Clone, Copy, Debug, DError)]
pub enum WrapError {
    /// We tried to wrap a NULL pointer.
    NullPtr,
    /// We tried to wrap a packet chain as though it were a single mblk.
    Chain,
}

#[derive(Clone, Debug, Eq, PartialEq, DError)]
#[derror(leaf_data = ParseError::data)]
pub enum ParseError {
    IngotError(PacketParseError),
    IllegalValue(MismatchError),
    BadLength(MismatchError),
    UnrecognisedTunnelOpt { class: u16, ty: u8 },
}

impl ParseError {
    fn data(&self, data: &mut [u64]) {
        match self {
            ParseError::UnrecognisedTunnelOpt { class, ty } => {
                [data[0], data[1]] = [*class as u64, *ty as u64];
            }
            _ => {}
        }
    }
}

impl DError for PacketParseError {
    fn discriminant(&self) -> &'static core::ffi::CStr {
        self.header().as_cstr()
    }

    fn child(&self) -> Option<&dyn DError> {
        Some(self.error())
    }
}

impl DError for ingot::types::ParseError {
    fn discriminant(&self) -> &'static core::ffi::CStr {
        self.as_cstr()
    }

    fn child(&self) -> Option<&dyn DError> {
        None
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MismatchError {
    pub location: &'static CStr,
    pub expected: u64,
    pub actual: u64,
}

impl DError for MismatchError {
    fn discriminant(&self) -> &'static CStr {
        self.location
    }

    fn child(&self) -> Option<&dyn DError> {
        None
    }

    fn leaf_data(&self, data: &mut [u64]) {
        if let Some(v) = data.get_mut(0) {
            *v = self.expected;
        }
        if let Some(v) = data.get_mut(1) {
            *v = self.expected;
        }
    }
}

impl From<PacketParseError> for ParseError {
    fn from(value: PacketParseError) -> Self {
        Self::IngotError(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteError {
    BadLayout,
    EndOfPacket,
    NotEnoughBytes { available: usize, needed: usize },
    StraddledWrite,
}

pub type WriteResult<T> = result::Result<T, WriteError>;

#[cfg(test)]
mod test {
    use super::*;
    use crate::ddi::mblk::MsgBlk;
    use crate::engine::ether::Ethernet;
    use crate::engine::ether::EthernetRef;
    use crate::engine::ingot_packet::Packet;
    use crate::engine::ip::v4::Ipv4;
    use crate::engine::ip::v4::Ipv4Ref;
    use crate::engine::ip::v6::Ipv6;
    use crate::engine::ip::v6::Ipv6Ref;
    use crate::engine::GenericUlp;
    use ingot::ethernet::Ethertype;
    use ingot::ip::IpProtocol;
    use ingot::tcp::Tcp;
    use ingot::tcp::TcpFlags;
    use ingot::tcp::TcpRef;
    use ingot::types::HeaderLen;
    use ingot::udp::Udp;
    use opte_api::Ipv6Addr;
    use opte_api::MacAddr;

    const SRC_MAC: MacAddr =
        MacAddr::from_const([0xa8, 0x40, 0x25, 0x00, 0x00, 0x63]);
    const DST_MAC: MacAddr =
        MacAddr::from_const([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d]);

    const SRC_IP4: Ipv4Addr = Ipv4Addr::from_const([10, 0, 0, 99]);
    const DST_IP4: Ipv4Addr = Ipv4Addr::from_const([52, 10, 128, 69]);

    const SRC_IP6: Ipv6Addr =
        Ipv6Addr::from_const([0xFD00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1]);
    const DST_IP6: Ipv6Addr =
        Ipv6Addr::from_const([0xFD00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2]);

    fn tcp_pkt(body: &[u8]) -> MsgBlk {
        let tcp = Tcp {
            source: 3839,
            destination: 80,
            sequence: 4224936861,
            flags: TcpFlags::SYN,
            ..Default::default()
        };

        let ip4_total_len =
            Ipv4::MINIMUM_LENGTH + (&tcp, &body).packet_length();
        let ip4 = Ipv4 {
            source: SRC_IP4,
            destination: DST_IP4,
            protocol: IpProtocol::TCP,
            hop_limit: 64,
            identification: 99,
            total_len: ip4_total_len as u16,
            ..Default::default()
        };

        let eth = Ethernet {
            destination: DST_MAC,
            source: SRC_MAC,
            ethertype: Ethertype::IPV4,
        };

        MsgBlk::new_ethernet_pkt((eth, ip4, tcp, body))
    }

    #[test]
    fn read_single_segment() {
        let mut pkt = tcp_pkt(&[]);
        let parsed = Packet::new(pkt.iter_mut())
            .parse_outbound(GenericUlp {})
            .unwrap()
            .to_full_meta();

        let eth_meta = parsed.meta().inner_ether();
        assert_eq!(eth_meta.destination(), DST_MAC);
        assert_eq!(eth_meta.source(), SRC_MAC);
        assert_eq!(eth_meta.ethertype(), Ethertype::IPV4);

        let ip4_meta = parsed.meta().inner_ip4().unwrap();
        assert_eq!(ip4_meta.source(), SRC_IP4);
        assert_eq!(ip4_meta.destination(), DST_IP4);
        assert_eq!(ip4_meta.protocol(), IpProtocol::TCP);

        let tcp_meta = parsed.meta().inner_tcp().unwrap();
        assert_eq!(tcp_meta.source(), 3839);
        assert_eq!(tcp_meta.destination(), 80);
        assert_eq!(tcp_meta.flags(), TcpFlags::SYN);
        assert_eq!(tcp_meta.sequence(), 4224936861);
        assert_eq!(tcp_meta.acknowledgement(), 0);
    }

    #[test]
    fn read_multi_segment() {
        let mut mp1 = MsgBlk::new_ethernet_pkt(Ethernet {
            destination: DST_MAC,
            source: SRC_MAC,
            ethertype: Ethertype::IPV4,
        });

        let tcp = Tcp {
            source: 3839,
            destination: 80,
            flags: TcpFlags::SYN,
            sequence: 4224936861,
            ..Default::default()
        };

        let ip4 = Ipv4 {
            source: SRC_IP4,
            destination: DST_IP4,
            protocol: IpProtocol::TCP,
            total_len: (Ipv4::MINIMUM_LENGTH + tcp.packet_length()) as u16,
            ..Default::default()
        };

        let mp2 = MsgBlk::new_pkt((ip4, tcp));

        mp1.append(mp2);

        let pkt = Packet::new(mp1.iter_mut())
            .parse_outbound(GenericUlp {})
            .unwrap()
            .to_full_meta();

        let eth_parsed = pkt.meta().inner_ether();
        assert_eq!(eth_parsed.destination(), DST_MAC);
        assert_eq!(eth_parsed.source(), SRC_MAC);
        assert_eq!(eth_parsed.ethertype(), Ethertype::IPV4);

        let ip4_parsed = pkt.meta().inner_ip4().unwrap();
        assert_eq!(ip4_parsed.source(), SRC_IP4);
        assert_eq!(ip4_parsed.destination(), DST_IP4);
        assert_eq!(ip4_parsed.protocol(), IpProtocol::TCP);

        let tcp_parsed = pkt.meta().inner_tcp().unwrap();
        assert_eq!(tcp_parsed.source(), 3839);
        assert_eq!(tcp_parsed.destination(), 80);
        assert_eq!(tcp_parsed.flags(), TcpFlags::SYN);
        assert_eq!(tcp_parsed.sequence(), 4224936861);
        assert_eq!(tcp_parsed.acknowledgement(), 0);
    }

    // Verify that if the TCP header straddles an mblk we return an
    // error.
    #[test]
    fn straddled_tcp() {
        let base = tcp_pkt(&[]);

        let mut st1 = MsgBlk::copy(&base[..42]);
        let st2 = MsgBlk::copy(&base[42..]);

        st1.append(st2);

        assert_eq!(st1.seg_len(), 2);
        assert_eq!(st1.byte_len(), base.len());

        assert!(matches!(
            Packet::new(st1.iter_mut()).parse_outbound(GenericUlp {}),
            Err(ParseError::IngotError(_))
        ));
    }

    // Verify that we correctly parse an IPv6 packet with extension headers
    #[test]
    fn parse_ipv6_extension_headers_ok() {
        use crate::engine::ip::v6::test::generate_test_packet;
        use crate::engine::ip::v6::test::SUPPORTED_EXTENSIONS;
        use itertools::Itertools;
        use smoltcp::wire::IpProtocol;
        for n_extensions in 0..SUPPORTED_EXTENSIONS.len() {
            for extensions in
                SUPPORTED_EXTENSIONS.into_iter().permutations(n_extensions)
            {
                // Generate a full IPv6 test packet, but pull out the extension
                // headers as a byte array.
                let (buf, ipv6_header_size) =
                    generate_test_packet(extensions.as_slice());

                let next_hdr =
                    *(extensions.first().unwrap_or(&IpProtocol::Tcp));
                let ext_hdrs = &buf[Ipv6::MINIMUM_LENGTH..ipv6_header_size];

                // Append a TCP header
                let tcp = Tcp {
                    source: 3839,
                    destination: 80,
                    sequence: 4224936861,
                    ..Default::default()
                };

                let pay_len = tcp.packet_length() + ext_hdrs.len();
                let ip6 = Ipv6 {
                    source: SRC_IP6,
                    destination: DST_IP6,
                    next_header: IpProtocol(u8::from(next_hdr)),
                    hop_limit: 255,
                    payload_len: pay_len as u16,

                    // Manually append extension hdrs rather than including
                    // here -- either way will test ingot's parsing logic.
                    ..Default::default()
                };
                let eth = Ethernet {
                    destination: DST_MAC,
                    source: SRC_MAC,
                    ethertype: Ethertype::IPV6,
                };

                let mut pkt =
                    MsgBlk::new_ethernet_pkt((eth, ip6, ext_hdrs, tcp));
                let pkt = Packet::new(pkt.iter_mut())
                    .parse_outbound(GenericUlp {})
                    .unwrap()
                    .to_full_meta();

                // Assert that the packet parses back out, and we can reach
                // the TCP meta no matter which permutation of EHs we have.
                assert_eq!(
                    pkt.meta().inner_ip6().unwrap().v6ext_ref().packet_length(),
                    ipv6_header_size - Ipv6::MINIMUM_LENGTH
                );
                let tcp_meta = pkt.meta().inner_tcp().unwrap();
                assert_eq!(tcp_meta.source(), 3839);
                assert_eq!(tcp_meta.destination(), 80);
                assert_eq!(tcp_meta.sequence(), 4224936861);
            }
        }
    }

    #[test]
    fn small_packet_with_padding() {
        const MINIMUM_ETH_FRAME_SZ: usize = 64;
        const FRAME_CHECK_SEQ_SZ: usize = 4;

        // Start with a test packet that's smaller than the minimum
        // ethernet frame size (64).
        let body = [];
        let mut pkt = tcp_pkt(&body);
        assert!(pkt.len() < MINIMUM_ETH_FRAME_SZ);

        // Many (most?) NICs will pad out any such frames so that
        // the total size is 64.
        let padding_len = MINIMUM_ETH_FRAME_SZ
            - pkt.len()
            // Discount the 4 bytes for the Frame Check Sequence (FCS)
            // which is usually not visible to upstack software.
            - FRAME_CHECK_SEQ_SZ;

        // Tack on a new segment filled with zero to pad the packet so that
        // it meets the minimum frame size.
        // Note that we do NOT update any of the packet headers themselves
        // as this padding process should be transparent to the upper
        // layers.
        let mut padding_seg = MsgBlk::new(padding_len);
        padding_seg.resize(padding_len).unwrap();

        pkt.append(padding_seg);
        assert_eq!(pkt.byte_len(), MINIMUM_ETH_FRAME_SZ - FRAME_CHECK_SEQ_SZ);

        // Generate the metadata by parsing the packet
        let parsed = Packet::new(pkt.iter_mut())
            .parse_inbound(GenericUlp {})
            .unwrap()
            .to_full_meta();

        // Grab parsed metadata
        let ip4_meta = parsed.meta().inner_ip4().unwrap();
        let tcp_meta = parsed.meta().inner_tcp().unwrap();

        // Length in packet headers shouldn't reflect include padding
        // This should not fail even though there are more bytes in
        // the initialised area ofthe mblk chain than the packet expects.
        assert_eq!(
            usize::from(ip4_meta.total_len()),
            (ip4_meta, tcp_meta, &body[..]).packet_length(),
        );
    }

    #[test]
    fn udp6_packet_with_padding() {
        let body = [1, 2, 3, 4];
        let udp = Udp {
            source: 124,
            destination: 5673,
            length: u16::try_from(Udp::MINIMUM_LENGTH + body.len()).unwrap(),
            ..Default::default()
        };
        let ip6 = Ipv6 {
            source: SRC_IP6,
            destination: DST_IP6,
            next_header: IpProtocol::UDP,
            hop_limit: 255,
            payload_len: (&udp, &body[..]).packet_length() as u16,

            ..Default::default()
        };
        let eth = Ethernet {
            destination: DST_MAC,
            source: SRC_MAC,
            ethertype: Ethertype::IPV6,
        };

        let pkt_sz = eth.packet_length()
            + ip6.packet_length()
            + usize::from(ip6.payload_len);
        let mut pkt = MsgBlk::new_ethernet_pkt((eth, ip6, udp, &body[..]));
        assert_eq!(pkt.len(), pkt_sz);

        // Tack on a new segment filled zero padding at
        // the end that's not part of the payload as indicated
        // by the packet headers.
        let padding_len = 8;
        let mut padding_seg = MsgBlk::new(padding_len);
        padding_seg.resize(padding_len).unwrap();
        pkt.append(padding_seg);
        assert_eq!(pkt.byte_len(), pkt_sz + padding_len);

        // Generate the metadata by parsing the packet.
        // This should not fail even though there are more bytes in
        // the initialised area ofthe mblk chain than the packet expects.
        let pkt = Packet::new(pkt.iter_mut())
            .parse_inbound(GenericUlp {})
            .unwrap()
            .to_full_meta();

        // Grab parsed metadata
        let ip6_meta = pkt.meta().inner_ip6().unwrap();
        let udp_meta = pkt.meta().inner_udp().unwrap();

        // Length in packet headers shouldn't reflect include padding
        assert_eq!(
            usize::from(ip6_meta.payload_len()),
            udp_meta.packet_length() + body.len(),
        );
    }
}

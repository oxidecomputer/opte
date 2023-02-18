// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Types for creating, reading, and writing network packets.
//!
//! TODO
//!
//! * Add a PacketChain type to represent a chain of one or more
//! indepenndent packets. Also consider having chains that represent
//! multiple packets for the same flow if it would be advantageous to
//! do so.
//!
//! * Add hardware offload information to [`Packet`].
//!

use super::arp::ArpHdrError;
use super::checksum::Checksum;
use super::checksum::HeaderChecksum;
use super::ether::EtherHdr;
use super::ether::EtherHdrError;
use super::ether::EtherMeta;
use super::geneve::GeneveHdr;
use super::geneve::GeneveHdrError;
use super::geneve::GeneveMeta;
use super::headers::EncapMeta;
use super::headers::IpAddr;
use super::headers::IpMeta;
use super::headers::UlpHdr;
use super::headers::UlpMeta;
use super::ip4::Ipv4Addr;
use super::ip4::Ipv4Hdr;
use super::ip4::Ipv4HdrError;
use super::ip4::Ipv4Meta;
use super::ip4::Protocol;
use super::ip6::Ipv6Hdr;
use super::ip6::Ipv6HdrError;
use super::ip6::Ipv6Meta;
use super::NetworkParser;
use core::convert::TryInto;
use core::fmt;
use core::fmt::Display;
use core::ptr;
use core::result;
use core::slice;
use dyn_clone::DynClone;
use serde::Deserialize;
use serde::Serialize;
// TODO should probably move these two into this module now.
use super::rule::HdrTransform;
use super::rule::HdrTransformError;
use super::tcp::TcpHdr;
use super::tcp::TcpHdrError;
use super::tcp::TcpMeta;
use super::udp::UdpHdr;
use super::udp::UdpHdrError;
use super::udp::UdpMeta;
use super::Direction;
use illumos_sys_hdrs::dblk_t;
use illumos_sys_hdrs::mblk_t;
use illumos_sys_hdrs::uintptr_t;
use opte_api::MacAddr;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::boxed::Box;
        use alloc::string::String;
        use alloc::vec::Vec;
        use illumos_sys_hdrs as ddi;
    } else {
        use std::boxed::Box;
        use std::string::String;
        use std::vec::Vec;
        use illumos_sys_hdrs::c_uchar;
    }
}

pub static MBLK_MAX_SIZE: usize = u16::MAX as usize;

pub static FLOW_ID_DEFAULT: InnerFlowId = InnerFlowId {
    proto: Protocol::Unknown(255),
    src_ip: IpAddr::Ip4(Ipv4Addr::ANY_ADDR),
    src_port: 0,
    dst_ip: IpAddr::Ip4(Ipv4Addr::ANY_ADDR),
    dst_port: 0,
};

/// The flow identifier.
///
/// In this case the flow identifier is the 5-tuple of the inner IP
/// packet.
///
/// NOTE: This should not be defined in `opte`. Rather, the engine
/// should be generic in regards to the flow identifier, and it should
/// be up to the `NetowrkImpl` to define it.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct InnerFlowId {
    pub proto: Protocol,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl InnerFlowId {
    /// Swap IP source and destination as well as ULP port source and
    /// destination.
    pub fn mirror(self) -> Self {
        Self {
            proto: self.proto,
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
        }
    }
}

impl Display for InnerFlowId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}:{}",
            self.proto, self.src_ip, self.src_port, self.dst_ip, self.dst_port,
        )
    }
}

impl From<&PacketMeta> for InnerFlowId {
    fn from(meta: &PacketMeta) -> Self {
        let (proto, src_ip, dst_ip) = match &meta.inner.ip {
            Some(IpMeta::Ip4(ip4)) => {
                (ip4.proto, IpAddr::Ip4(ip4.src), IpAddr::Ip4(ip4.dst))
            }
            Some(IpMeta::Ip6(ip6)) => {
                (ip6.proto, IpAddr::Ip6(ip6.src), IpAddr::Ip6(ip6.dst))
            }
            None => (
                Protocol::Unknown(255),
                IpAddr::Ip4(Ipv4Addr::from([0; 4])),
                IpAddr::Ip4(Ipv4Addr::from([0; 4])),
            ),
        };

        let (src_port, dst_port) = match &meta.inner.ulp {
            Some(UlpMeta::Tcp(tcp)) => (tcp.src, tcp.dst),
            Some(UlpMeta::Udp(udp)) => (udp.src, udp.dst),
            None => (0, 0),
        };

        InnerFlowId { proto, src_ip, src_port, dst_ip, dst_port }
    }
}

/// The outer header metadata.
///
/// All outer headers are always optional.
#[derive(Debug, Default)]
pub struct OuterMeta {
    pub ether: Option<EtherMeta>,
    pub ip: Option<IpMeta>,
    pub encap: Option<EncapMeta>,
}

impl OuterMeta {
    fn hdr_len(&self) -> usize {
        let mut hdr_len = 0;

        if let Some(ether) = self.ether {
            hdr_len += usize::from(ether.hdr_len());
        }

        if let Some(ip) = self.ip {
            hdr_len += usize::from(ip.hdr_len());
        }

        if let Some(encap) = self.encap {
            hdr_len += encap.hdr_len();
        }

        hdr_len
    }
}

/// The inner header metadata.
///
/// There is always an Ethernet frame.
#[derive(Debug, Default)]
pub struct InnerMeta {
    pub ether: EtherMeta,
    pub ip: Option<IpMeta>,
    pub ulp: Option<UlpMeta>,
}

impl InnerMeta {
    fn has_ip_csum(&self) -> bool {
        match self.ip {
            Some(ip) => ip.has_csum(),
            None => false,
        }
    }

    fn has_ulp_csum(&self) -> bool {
        match self.ulp {
            Some(ulp) => ulp.has_csum(),
            None => false,
        }
    }

    fn hdr_len(&self) -> usize {
        let mut hdr_len = self.ether.hdr_len();

        if let Some(ip) = self.ip {
            hdr_len += usize::from(ip.hdr_len());
        }

        if let Some(ulp) = self.ulp {
            hdr_len += usize::from(ulp.hdr_len());
        }

        hdr_len
    }

    pub fn is_tcp(&self) -> bool {
        match self.ip.as_ref() {
            Some(IpMeta::Ip4(ip4)) => ip4.proto == Protocol::TCP,
            Some(IpMeta::Ip6(ip6)) => ip6.proto == Protocol::TCP,
            _ => false,
        }
    }
}

/// The various metadata of a packet.
///
/// The packet metadata is a logical representation of the header data
/// that is relevant to processing.
#[derive(Debug, Default)]
pub struct PacketMeta {
    pub outer: OuterMeta,
    pub inner: InnerMeta,
}

impl PacketMeta {
    /// Return the number of bytes requires to emit the header
    /// metadata into full headers.
    fn hdr_len(&self) -> usize {
        self.outer.hdr_len() + self.inner.hdr_len()
    }

    /// Return the inner Ether metadata.
    pub fn inner_ether(&self) -> &EtherMeta {
        &self.inner.ether
    }

    /// Return the inner IPv4 metadata.
    pub fn inner_ip4(&self) -> Option<&Ipv4Meta> {
        match &self.inner.ip {
            Some(IpMeta::Ip4(ip4_meta)) => Some(ip4_meta),
            _ => None,
        }
    }

    /// Return the inner IPv6 metadata.
    pub fn inner_ip6(&self) -> Option<&Ipv6Meta> {
        match &self.inner.ip {
            Some(IpMeta::Ip6(x)) => Some(x),
            _ => None,
        }
    }

    /// Return the inner TCP metadata, if the inner ULP is TCP.
    /// Otherwise, return `None`.
    pub fn inner_tcp(&self) -> Option<&TcpMeta> {
        match &self.inner.ulp {
            Some(UlpMeta::Tcp(tcp)) => Some(tcp),
            _ => None,
        }
    }

    /// Return true if the inner ULP is TCP.
    pub fn is_inner_tcp(&self) -> bool {
        self.inner.is_tcp()
    }

    /// Return the inner UDP metadata, if the inner ULP is UDP.
    /// Otherwise return `None`.
    pub fn inner_udp(&self) -> Option<&UdpMeta> {
        match &self.inner.ulp {
            Some(UlpMeta::Udp(udp)) => Some(udp),
            _ => None,
        }
    }
}

/// A network packet.
///
/// The [`Packet`] type presents an abstraction for manipulating
/// network packets in both a `std` and `no_std` environment. The
/// first is useful for writing tests against the OPTE core engine and
/// executing them in userland, without the need for standing up a
/// full-blown virtual machine. To the engine this [`Packet`] is
/// absolutely no different than if it was running in-kernel for a
/// real virtual machine.
///
/// The `no_std` implementation is used when running in-kernel. The
/// main difference is the `mblk_t` and `dblk_t` structures are coming
/// from viona (outbound/Tx) and mac (inbound/Rx), and we consume them
/// via [`Packet::wrap_mblk()`]. In reality this is typically holding
/// an Ethernet _frame_, but we prefer to use the colloquial
/// nomenclature of "packet".
///
/// A [`Packet`] is made up of one or more segments ([`PacketSeg`]).
/// Any given header is *always* contained in a single segment, i.e. a
/// header never straddles multiple segments. While it's preferable to
/// have all headers in the first segment, it *may* be the case that
/// the headers span multiple segments; but a *single* header type
/// (e.g. the IP header) will *never* straddle two segments. The
/// payload, however, *may* span multiple segments.
///
/// # illumos terminology
///
/// In illumos there is no real notion of an mblk "packet" or
/// "segment": a packet is just a linked list of `mblk_t` values.
/// The "packet" is simply a pointer to the first `mblk_t` in the
/// list, which also happens to be the first "segment", and any
/// further segments are linked via `b_cont`. In the illumos
/// kernel code you'll *sometimes* find variables named `mp_head`
/// to indicate that it points to a packet.
///
/// There is also the notion of a "chain" of packets. This is
/// represented by a list of `mblk_t` structure as well, but instead
/// of using `b_cont` the individual packets are linked via the
/// `b_next` field. In the illumos kernel code this this is often
/// referred to with the variable name `mp_chain`, but sometimes also
/// `mp_head` (or just `mp`). It's a bit ambiguous, and something you
/// kind of figure out as you work in the code more. Though part of me
/// would like to create some rust-like "new type pattern" in C to
/// disambiguate packets from packet chains across APIs so the
/// compiler can detect when your API is working against the wrong
/// contract (for example a function that expects a single packet but
/// is being fed a packet chain).
///
/// TODOx
///
/// * Document the various type states, their purpose, their data, and
/// how the [`Packet`] generally transitions between them.
///
/// * Somewhere we'll want to enforce and document a 2-byte prefix pad
/// to keep IP header alignment (the host expects this).
///
#[derive(Debug)]
pub struct Packet<S: PacketState> {
    avail: usize,
    source: PacketSource,
    segs: Vec<PacketSeg>,
    state: S,
}

#[derive(Clone, Copy, Debug)]
enum PacketSource {
    Allocated,
    Wrapped,
}

/// The type state of a packet that has been initialized and allocated, but
/// about which nothing else is known besides the length.
#[derive(Debug)]
pub struct Initialized {
    // Total length of packet, in bytes. This is equal to the sum of
    // the length of the _initialized_ window in all the segments
    // (`b_wptr - b_rptr`).
    len: usize,
}

/// The offset and length of a header.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HdrOffset {
    /// The header's offset from start of packet, in bytes.
    pub pkt_pos: usize,

    /// The index of the segment the header lives in, starting at 0.
    pub seg_idx: usize,

    /// The header's offset from the start of the segment, in bytes.
    pub seg_pos: usize,

    /// The length of the header.
    pub hdr_len: usize,
}

impl HdrOffset {
    fn new(rdr_offset: ReaderOffset, hdr_len: usize) -> Self {
        // We always take the reader offset _after_ parsing, thus we
        // need to adjust the positions based on the header length.
        Self {
            pkt_pos: rdr_offset.pkt_pos - hdr_len,
            seg_idx: rdr_offset.seg_idx,
            seg_pos: rdr_offset.seg_pos - hdr_len,
            hdr_len,
        }
    }
}

/// Bytes offsets for the outer headers.
///
/// All outer headers are optional.
#[derive(Clone, Debug, Default)]
pub struct OuterHeaderOffsets {
    pub ether: Option<HdrOffset>,
    pub ip: Option<HdrOffset>,
    pub encap: Option<HdrOffset>,
}

/// Byte offsets for the inner headers.
///
/// The inner headers must consist of at least an Ethernet header.
#[derive(Clone, Debug, Default)]
pub struct InnerHeaderOffsets {
    pub ether: HdrOffset,
    pub ip: Option<HdrOffset>,
    pub ulp: Option<HdrOffset>,
}

/// Byte offsets for all headers.
#[derive(Clone, Debug, Default)]
pub struct HeaderOffsets {
    pub outer: OuterHeaderOffsets,
    pub inner: InnerHeaderOffsets,
}

pub struct HdrInfo<M> {
    pub meta: M,
    pub offset: HdrOffset,
}

pub struct PacketInfo {
    pub meta: PacketMeta,
    pub offsets: HeaderOffsets,
    // The body's checksum. It is up to the `NetworkImpl::Parser` on
    // whether to populate this field or not. The reason for
    // populating this field is to avoid duplicate work if the client
    // has provided a ULP checksum. Rather than redoing the body
    // checksum calculation, we can use incremental checksum
    // techniques to stash the body's checksum for reuse when emitting
    // the new headers.
    //
    // However, if the client does not provide a checksum, presumably
    // because they are relying on checksum offload, this value should
    // be `None`. In such case, `emit_headers()` will perform no ULP
    // checksum update.
    //
    // This value may also be none if the packet has no notion of a
    // ULP checksum; e.g., ARP.
    pub body_csum: Option<Checksum>,
}

/// Body offset and length information.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BodyInfo {
    pub pkt_offset: usize,
    pub seg_index: usize,
    pub seg_offset: usize,
    pub len: usize,
}

/// The type state of a parsed packet.
///
/// The parsed type state represents that a packet has been
/// successfully parsed and contains all pertinent information derived
/// from parsing.
#[derive(Debug)]
pub struct Parsed {
    len: usize,
    meta: PacketMeta,
    flow: InnerFlowId,
    hdr_offsets: HeaderOffsets,
    body_csum: Option<Checksum>,
    body: BodyInfo,
    body_modified: bool,
}

pub trait PacketState {}

pub trait CanRead {
    fn len(&self) -> usize;
}

impl PacketState for Initialized {}
impl PacketState for Parsed {}

impl CanRead for Initialized {
    fn len(&self) -> usize {
        self.len
    }
}

impl CanRead for Parsed {
    fn len(&self) -> usize {
        self.len
    }
}

impl<S: PacketState> Packet<S> {
    /// Return the amount of buffer space available to this packet.
    pub fn avail(&self) -> usize {
        self.avail
    }

    /// Return the pointer address of the underlying mblk_t.
    ///
    /// NOTE: This is purely to allow passing the pointer value up to
    /// DTrace so that the mblk can be inspected (read only) in probe
    /// context.
    pub fn mblk_addr(&self) -> uintptr_t {
        self.segs[0].mp as uintptr_t
    }

    /// Return the number of segments that make up this packet.
    pub fn num_segs(&self) -> usize {
        self.segs.len()
    }

    /// Return the head of the underlying `mblk_t` segment chain and
    /// consume `self`. The caller of this function now owns the
    /// `mblk_t` segment chain.
    pub fn unwrap_mblk(mut self) -> *mut mblk_t {
        let mp_head = self.segs[0].mp;
        // We need to make sure to NULL out the mp pointer or else
        // `drop()` will `freemsg(9F)` even though ownership of the
        // mblk has passed on to someone else.
        self.segs[0].mp = ptr::null_mut();
        mp_head
    }
}

/// For the `no_std`/illumos kernel environment, we want the `mblk_t`
/// drop to occur at the [`Packet`] level, where we can make use of
/// `freemsg(9F)`.
impl<S: PacketState> Drop for Packet<S> {
    fn drop(&mut self) {
        // Drop the segment chain if there is one. Consumers of Packet
        // will never own a packet with no segments. Rather, this
        // happens when a Packet transitions from one type-state to
        // another, and the segments are passed onto the new Packet.
        // This guarantees that we only free the segment chain once.
        if self.segs.len() != 0 {
            let head_mp = self.segs[0].mp;
            drop(&mut self.segs);
            cfg_if! {
                if #[cfg(all(not(feature = "std"), not(test)))] {
                    // Safety: This is safe as long as the original
                    // `mblk_t` came from a call to `allocb(9F)` (or
                    // similar API).
                    unsafe { ddi::freemsg(head_mp) };
                } else {
                    mock_freemsg(head_mp);
                }
            }
        }
    }
}

impl Packet<Initialized> {
    /// Allocate a new [`Packet`] containing a data buffer of `size`
    /// bytes.
    ///
    /// The returned packet consists of exactly one [`PacketSeg`].
    ///
    /// In the kernel environment this uses `allocb(9F)` and
    /// `freemsg(9F)` under the hood.
    ///
    /// In the `std` environment this uses a mock implementation of
    /// `allocb(9F)` and `freeb(9F)`, which contains enough scaffolding
    /// to satisfy OPTE's use of the underlying `mblk_t` and `dblk_t`
    /// structures.
    pub fn alloc(size: usize) -> Self {
        let mp = allocb(size);

        // Safety: We know this is safe because we just built the `mp`
        // in a safe manner.
        let seg = unsafe { PacketSeg::wrap_mblk(mp) };
        Packet::new(seg)
    }

    pub fn alloc_and_expand(size: usize) -> Self {
        let mut seg = PacketSeg::alloc(size);
        seg.expand_end(size).unwrap();
        Packet::new(seg)
    }

    /// Create a [`Packet<Initialized>`] value from the passed in
    /// `bytes`.
    ///
    /// The returned packet consists of exactly one [`PacketSeg`] with
    /// enough space to hold `bytes.len()`.
    pub fn copy(bytes: &[u8]) -> Self {
        let mut pkt = Packet::alloc_and_expand(bytes.len());
        let mut wtr = pkt.seg0_wtr();
        // Unwrap: We know there cannot be an error because we
        // allocate a packet large enough to hold all bytes.
        wtr.write(bytes).unwrap();
        pkt.state.len = bytes.len();
        pkt
    }

    pub fn get_rdr(&self) -> PacketReader {
        PacketReader::new(&self.segs)
    }

    pub fn get_rdr_mut(&mut self) -> PacketReaderMut {
        PacketReaderMut::new(&mut self.segs)
    }

    /// Create a new packet from `seg0`.
    fn new(seg0: PacketSeg) -> Self {
        let segs = vec![seg0];
        let len: usize = segs.iter().map(|s| s.len).sum();
        let avail: usize = segs.iter().map(|s| s.avail).sum();

        Packet {
            avail,
            source: PacketSource::Allocated,
            segs,
            state: Initialized { len },
        }
    }

    #[cfg(test)]
    fn new2(seg0: PacketSeg, seg1: PacketSeg) -> Self {
        let segs = vec![seg0, seg1];
        let len: usize = segs.iter().map(|s| s.len).sum();
        let avail: usize = segs.iter().map(|s| s.avail).sum();

        Packet {
            avail,
            source: PacketSource::Allocated,
            segs,
            state: Initialized { len },
        }
    }

    pub fn parse_ether<'a, 'b>(
        rdr: &'b mut PacketReaderMut<'a>,
    ) -> Result<(HdrInfo<EtherMeta>, EtherHdr<'a>), ParseError> {
        let ether = EtherHdr::parse(rdr)?;
        let offset = HdrOffset::new(rdr.offset(), ether.hdr_len());
        let meta = EtherMeta::from(&ether);
        Ok((HdrInfo { meta, offset }, ether))
    }

    pub fn parse_ip4<'a, 'b>(
        rdr: &'b mut PacketReaderMut<'a>,
    ) -> Result<(HdrInfo<IpMeta>, Ipv4Hdr<'a>), ParseError> {
        let ip = Ipv4Hdr::parse(rdr)?;
        let offset = HdrOffset::new(rdr.offset(), usize::from(ip.hdr_len()));
        let meta = IpMeta::from(Ipv4Meta::from(&ip));
        Ok((HdrInfo { meta, offset }, ip))
    }

    pub fn parse_ip6<'a, 'b>(
        rdr: &'b mut PacketReaderMut<'a>,
    ) -> Result<(HdrInfo<IpMeta>, Ipv6Hdr<'a>), ParseError> {
        let ip = Ipv6Hdr::parse(rdr)?;
        let offset = HdrOffset::new(rdr.offset(), usize::from(ip.hdr_len()));
        let meta = IpMeta::from(Ipv6Meta::from(&ip));
        Ok((HdrInfo { meta, offset }, ip))
    }

    pub fn parse_tcp<'a, 'b>(
        rdr: &'b mut PacketReaderMut<'a>,
    ) -> Result<(HdrInfo<UlpMeta>, UlpHdr<'a>), ParseError> {
        let tcp = TcpHdr::parse(rdr)?;
        let offset = HdrOffset::new(rdr.offset(), tcp.hdr_len());
        let meta = UlpMeta::from(TcpMeta::from(&tcp));
        Ok((HdrInfo { meta, offset }, UlpHdr::from(tcp)))
    }

    pub fn parse_udp<'a, 'b>(
        rdr: &'b mut PacketReaderMut<'a>,
    ) -> Result<(HdrInfo<UlpMeta>, UlpHdr<'a>), ParseError> {
        let udp = UdpHdr::parse(rdr)?;
        let offset = HdrOffset::new(rdr.offset(), udp.hdr_len());
        let meta = UlpMeta::from(UdpMeta::from(&udp));
        Ok((HdrInfo { meta, offset }, UlpHdr::from(udp)))
    }

    pub fn parse_geneve<'a, 'b>(
        rdr: &'b mut PacketReaderMut<'a>,
    ) -> Result<(HdrInfo<GeneveMeta>, GeneveHdr<'a>), ParseError> {
        let geneve = GeneveHdr::parse(rdr)?;
        let offset = HdrOffset::new(rdr.offset(), geneve.hdr_len());
        let meta = GeneveMeta::from(&geneve);
        Ok((HdrInfo { meta, offset }, geneve))
    }

    pub fn parse(
        mut self,
        dir: Direction,
        net: impl NetworkParser,
    ) -> Result<Packet<Parsed>, ParseError> {
        let mut rdr = self.get_rdr_mut();

        let info = match dir {
            Direction::Out => net.parse_outbound(&mut rdr)?,
            Direction::In => net.parse_inbound(&mut rdr)?,
        };

        let (pkt_offset, mut seg_index, mut seg_offset, end_of_seg) =
            rdr.finish();

        // If we finished on the end of a segment, and there are more
        // segments to go, then bump the segment index and reset the
        // segment offset to properly indicate the start of the body.
        if end_of_seg && ((seg_index + 1) < self.segs.len()) {
            seg_index += 1;
            seg_offset = 0;
        }

        let body = BodyInfo {
            pkt_offset,
            seg_index,
            seg_offset,
            len: self.state.len - pkt_offset,
        };

        let flow = InnerFlowId::from(&info.meta);
        Ok(Packet {
            avail: self.avail,
            source: self.source,
            // The new packet is taking ownership of the segments.
            segs: core::mem::take(&mut self.segs),
            state: Parsed {
                len: self.state.len,
                hdr_offsets: info.offsets,
                meta: info.meta,
                flow,
                body_csum: info.body_csum,
                body,
                body_modified: false,
            },
        })
    }

    pub fn seg0_wtr(&mut self) -> PacketSegWriter {
        self.segs[0].get_writer()
    }

    /// Wrap the `mblk_t` packet in a [`Packet`], taking ownership of
    /// the `mblk_t` packet as a result. An `mblk_t` packet consists
    /// of one or more `mblk_t` segments chained together via
    /// `b_cont`. As a result, this [`Packet`] may consist of *one or
    /// more* [`PacketSeg`]s. When the [`Packet`] is dropped, the
    /// underlying `mblk_t` segment chain is freed. If you wish to
    /// pass on ownership you must call the [`Packet::unwrap_mblk()`]
    /// function.
    ///
    /// # Safety
    ///
    /// The `mp` pointer must point to an `mblk_t` allocated by
    /// `allocb(9F)` or provided by some kernel API which itself used
    /// one of the DDI/DKI APIs to allocate it.
    ///
    /// # Errors
    ///
    /// * Return [`WrapError::NullPtr`] is `mp` is `NULL`.
    pub unsafe fn wrap_mblk(mp: *mut mblk_t) -> Result<Self, WrapError> {
        if mp.is_null() {
            return Err(WrapError::NullPtr);
        }

        // Compute the number of `mblk_t`s in this segment chain.
        //
        // We are currently forced to take at least one memory allocation.
        // That's because we're wrapping each `mblk_t` in a segment chain (the
        // `b_cont` items) in a `PacketSeg`, and then storing all those in
        // `self`. We previously had a statically-sized array here, of length 4,
        // to avoid those allocs. However, that obviously assumes we never have
        // chains of more than 4 elements, which we've now hit.
        //
        // We pass over the linked-list twice here: once to compute the length,
        // so that we can allocate exactly once, and once to actually wrap
        // everything.
        let mut n_segments = 1;
        let mut next_seg = (*mp).b_cont;
        while next_seg != ptr::null_mut() {
            n_segments += 1;
            next_seg = (*next_seg).b_cont;
        }
        let mut segs = Vec::with_capacity(n_segments);

        // Restore `next_seg`, since we iterate over the list another time to
        // actually wrap the `mblk_t`s.
        let mut next_seg = (*mp).b_cont;
        let mut len = 0;
        let mut avail = 0;
        let mut seg = PacketSeg::wrap_mblk(mp);
        avail += seg.avail;
        len += seg.len;
        segs.push(seg);

        while next_seg != ptr::null_mut() {
            let tmp = (*next_seg).b_cont;
            seg = PacketSeg::wrap_mblk(next_seg);
            avail += seg.avail;
            len += seg.len;
            segs.push(seg);
            next_seg = tmp;
        }

        Ok(Packet {
            avail: avail.try_into().unwrap(),
            source: PacketSource::Wrapped,
            segs,
            state: Initialized { len },
        })
    }

    /// A combination of [`Self::wrap_mblk()`] followed by [`Self::parse()`].
    ///
    /// This is a bit more convenient than dealing with the possible
    /// error from each separately.
    pub unsafe fn wrap_mblk_and_parse<N: NetworkParser>(
        mp: *mut mblk_t,
        dir: Direction,
        net: N,
    ) -> Result<Packet<Parsed>, PacketError> {
        let pkt = Self::wrap_mblk(mp)?;
        pkt.parse(dir, net).map_err(|e| PacketError::from(e))
    }
}

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

impl From<smoltcp::Error> for BodyTransformError {
    fn from(e: smoltcp::Error) -> Self {
        Self::ParseFailure(format!("{}", e))
    }
}

impl Packet<Parsed> {
    /// XXX-EXT-IP This is here purely for the use by the external IP
    /// hack.
    pub fn write_dst_mac(&mut self, addr: MacAddr) {
        self.state.meta.inner.ether.dst = addr.into();
        let off = self.state.hdr_offsets.inner.ether.seg_pos;
        let mut rdr = PacketReaderMut::new(&mut self.segs[0..1]);
        // Unwrap: Assuming we didn't mess up calculating the offsets,
        // we know we can seek forward by this amount.
        rdr.seek(off).unwrap();
        let mut ether = EtherHdr::parse(&mut rdr).unwrap();
        ether.set_dst(addr);
    }

    pub fn body_csum(&self) -> Option<Checksum> {
        self.state.body_csum
    }

    pub fn body_info(&self) -> BodyInfo {
        self.state.body
    }

    pub fn body_offset(&self) -> usize {
        self.state.body.pkt_offset
    }

    /// Run the [`BodyTransform`] against this packet.
    pub fn body_transform(
        &mut self,
        dir: Direction,
        xform: &Box<dyn BodyTransform>,
    ) -> Result<(), BodyTransformError> {
        // We set the flag now with the assumption that the transform
        // could fail after modifying part of the body. In the future
        // we could have something more sophisticated that only sets
        // the flag if at least one byte was modified, but for now
        // this does the job as nothing that needs top performance
        // should make use of body transformations.
        self.state.body_modified = true;

        match self.body_segs_mut() {
            Some(mut body_segs) => xform.run(dir, &mut body_segs),

            None => {
                self.state.body_modified = false;
                Err(BodyTransformError::NoPayload)
            }
        }
    }

    pub fn body_seg(&self) -> usize {
        self.state.body.seg_index
    }

    /// Return a list of the body segments, or `None` if there is no
    /// body.
    pub fn body_segs(&self) -> Option<Vec<&[u8]>> {
        if self.state.body.len == 0 {
            return None;
        }

        let mut body_segs = vec![];
        let body_seg = self.state.body.seg_index;

        for (i, seg) in self.segs[body_seg..].iter().enumerate() {
            if i == 0 {
                // Panic: We are slicing with the parse data. If
                // we parsed correctly, this should not panic.
                body_segs.push(
                    seg.slice_unchecked(self.state.body.seg_offset, None),
                );
            } else {
                body_segs.push(seg.slice());
            }
        }

        Some(body_segs)
    }

    /// Return a list of mutable body segments, or `None` if there is
    /// no body.
    pub fn body_segs_mut(&mut self) -> Option<Vec<&mut [u8]>> {
        if self.state.body.len == 0 {
            return None;
        }

        let mut body_segs = vec![];
        let body_seg = self.state.body.seg_index;

        for (i, seg) in self.segs[body_seg..].iter_mut().enumerate() {
            if i == 0 {
                // Panic: We are slicing with the parse data. If
                // we parsed correctly, this should not panic.
                body_segs.push(
                    seg.slice_mut_unchecked(self.state.body.seg_offset, None),
                );
            } else {
                body_segs.push(seg.slice_mut());
            }
        }

        Some(body_segs)
    }

    /// Compute ULP and IP header checksum from scratch.
    ///
    /// This should really only be used for testing.
    pub fn compute_checksums(&mut self) {
        match self.state.hdr_offsets.inner.ulp {
            Some(ulp_off) => {
                let mut body_rdr = self.get_body_rdr();
                let mut csum = Checksum::from(0u32);
                loop {
                    let len = body_rdr.seg_left();
                    match body_rdr.slice(len) {
                        Ok(seg_bytes) => csum.add_bytes(&seg_bytes),
                        _ => break,
                    }
                }

                self.state.body_csum = Some(csum);

                // Unwrap: Can't have a ULP without an IP.
                let ip = self.meta().inner.ip.unwrap();
                // Add pseudo header checksum.
                let pseudo_csum = ip.pseudo_csum();
                csum += pseudo_csum;
                // All headers must reside in the first segment.
                let seg0_bytes = self.segs[0].slice_mut();
                // Determine ULP slice and add its bytes to the
                // checksum.
                let ulp_start = ulp_off.seg_pos;
                let ulp_end = ulp_start + ulp_off.hdr_len;
                let ulp = &mut seg0_bytes[ulp_start..ulp_end];

                match self.state.meta.inner.ulp.as_mut().unwrap() {
                    UlpMeta::Tcp(tcp) => {
                        Self::update_tcp_csum(tcp, csum, ulp);
                    }

                    UlpMeta::Udp(udp) => {
                        Self::update_udp_csum(udp, csum, ulp);
                    }
                }
            }

            None => (),
        }

        // Compute and fill in the IPv4 header checksum.
        if let Some(IpMeta::Ip4(ip)) = self.state.meta.inner.ip.as_mut() {
            let ip_off = self.state.hdr_offsets.inner.ip.unwrap();
            let all_hdr_bytes = self.segs[0].slice_mut();
            let ip_start = ip_off.seg_pos;
            let ip_end = ip_start + ip_off.hdr_len;
            let csum = HeaderChecksum::from(Checksum::compute(
                &all_hdr_bytes[ip_start..ip_end],
            ))
            .bytes();

            // Update the metadata.
            ip.csum = csum;

            // Update the header bytes.
            let csum_begin = ip_start + Ipv4Hdr::CSUM_BEGIN;
            let csum_end = ip_start + Ipv4Hdr::CSUM_END;
            all_hdr_bytes[csum_begin..csum_end].copy_from_slice(&csum[..]);
        }
    }

    fn update_tcp_csum(tcp: &mut TcpMeta, mut csum: Checksum, ulp: &mut [u8]) {
        let csum_start = TcpHdr::CSUM_BEGIN_OFFSET;
        let csum_end = TcpHdr::CSUM_END_OFFSET;

        // First we must zero the existing checksum.
        ulp[csum_start..csum_end].copy_from_slice(&[0; 2]);
        // Then we can add the ULP header bytes to the checksum.
        csum.add_bytes(ulp);
        // Convert the checksum to its final form.
        let ulp_csum = HeaderChecksum::from(csum).bytes();
        // Update the TCP metadata.
        tcp.csum = ulp_csum;
        // Update the TCP header bytes.
        ulp[csum_start..csum_end].copy_from_slice(&ulp_csum);
    }

    fn update_udp_csum(udp: &mut UdpMeta, mut csum: Checksum, ulp: &mut [u8]) {
        let csum_start = UdpHdr::CSUM_BEGIN_OFFSET;
        let csum_end = UdpHdr::CSUM_END_OFFSET;

        // First we must zero the existing checksum.
        ulp[csum_start..csum_end].copy_from_slice(&[0; 2]);
        // Then we can add the ULP header bytes to the checksum.
        csum.add_bytes(ulp);
        // Convert the checksum to its final form.
        let ulp_csum = HeaderChecksum::from(csum).bytes();
        // Update the UDP metadata.
        udp.csum = ulp_csum;
        // Update the UDP header bytes.
        ulp[csum_start..csum_end].copy_from_slice(&ulp_csum);
    }

    /// Perform an incremental checksum update for the ULP checksums
    /// based on the stored body checksum.
    ///
    /// This avoids duplicating work already done by the client in the
    /// case where checksums are **not** being offloaded to the hardware.
    fn update_checksums(&mut self, update_ip: bool, update_ulp: bool) {
        // If a ULP exists, then compute and set its checksum.
        match (update_ulp, self.state.hdr_offsets.inner.ulp) {
            (true, Some(ulp_off)) => {
                // Start by reusing the known checksum of the body.
                let mut csum = self.state.body_csum.unwrap();
                // Unwrap: Can't have a ULP without an IP.
                let ip = self.meta().inner.ip.unwrap();
                // Add pseudo header checksum.
                let pseudo_csum = ip.pseudo_csum();
                csum += pseudo_csum;
                // All headers must reside in the first segment.
                let all_hdr_bytes = self.segs[0].slice_mut();
                // Determine ULP slice and add its bytes to the
                // checksum.
                let ulp_start = ulp_off.seg_pos;
                let ulp_end = ulp_start + ulp_off.hdr_len;
                let ulp = &mut all_hdr_bytes[ulp_start..ulp_end];

                match self.state.meta.inner.ulp.as_mut().unwrap() {
                    UlpMeta::Tcp(tcp) => {
                        Self::update_tcp_csum(tcp, csum, ulp);
                    }

                    UlpMeta::Udp(udp) => {
                        Self::update_udp_csum(udp, csum, ulp);
                    }
                }
            }

            _ => (),
        }

        // Compute and fill in the IPv4 header checksum.
        match (update_ip, self.state.meta.inner.ip.as_mut()) {
            (true, Some(IpMeta::Ip4(ip))) => {
                let ip_off = self.state.hdr_offsets.inner.ip.unwrap();
                let all_hdr_bytes = self.segs[0].slice_mut();
                let ip_start = ip_off.seg_pos;
                let ip_end = ip_start + ip_off.hdr_len;
                let ip_bytes = &mut all_hdr_bytes[ip_start..ip_end];
                let csum_start = Ipv4Hdr::CSUM_BEGIN;
                let csum_end = Ipv4Hdr::CSUM_END;
                ip_bytes[csum_start..csum_end].copy_from_slice(&[0; 2]);
                let csum =
                    HeaderChecksum::from(Checksum::compute(&ip_bytes)).bytes();

                // Update the metadata.
                ip.csum = csum;

                // Update the header bytes.
                ip_bytes[csum_start..csum_end].copy_from_slice(&csum[..]);
            }

            _ => (),
        }
    }

    pub fn hdr_offsets(&self) -> HeaderOffsets {
        self.state.hdr_offsets.clone()
    }

    /// Run the [`HdrTransform`] against this packet.
    #[inline]
    pub fn hdr_transform(
        &mut self,
        xform: &HdrTransform,
    ) -> Result<(), HdrTransformError> {
        xform.run(&mut self.state.meta)?;
        self.state.flow = InnerFlowId::from(&self.state.meta);
        Ok(())
    }

    /// Return a reference to the flow ID of this packet.
    #[inline]
    pub fn flow(&self) -> &InnerFlowId {
        &self.state.flow
    }

    pub fn get_body_rdr(&self) -> PacketReader {
        let mut rdr = PacketReader::new(&self.segs);
        // XXX While this works for now it might be nice to have a
        // better mechanism for dealing with the body. For example, we
        // know this seek() call can't fail, but the current
        // abstraction isn't powerful enough to encode that in the
        // type system.
        rdr.seek(self.body_offset()).expect("failed to seek to body");
        rdr
    }

    pub fn get_rdr(&self) -> PacketReader {
        PacketReader::new(&self.segs)
    }

    pub fn get_rdr_mut(&mut self) -> PacketReaderMut {
        PacketReaderMut::new(&mut self.segs)
    }

    #[inline]
    pub fn is_tcp(&self) -> bool {
        self.state.meta.inner.is_tcp()
    }

    #[inline]
    pub fn meta(&self) -> &PacketMeta {
        &self.state.meta
    }

    #[inline]
    pub fn meta_mut(&mut self) -> &mut PacketMeta {
        &mut self.state.meta
    }

    /// Return the mblk pointer value as a formatted String. This is
    /// for debugging purposes.
    pub fn mblk_ptr_str(&self) -> String {
        format!("{:p}", self.segs[0].mp)
    }

    // Determine if the new header fits in the existing first segment.
    // If it does, then modify the mblk pointers to reflect the length
    // of the new header. If it does not, then insert a new segment to
    // the front.
    fn hdr_seg(
        segs: &mut Vec<PacketSeg>,
        new_hdr_len: usize,
        body: &mut BodyInfo,
    ) {
        let prefix_len = segs[0].prefix_len();
        // Determine the length of the original headers. This is
        // equivalent to where the body starts.
        let old_hdr_len = body.pkt_offset;

        if new_hdr_len > old_hdr_len {
            if prefix_len + old_hdr_len >= new_hdr_len {
                // In this case we can fix the new headers in the existing
                // first segment.
                let delta = new_hdr_len - old_hdr_len;
                segs[0].expand_start(delta).unwrap();

                // If the body starts in this first segment, then make
                // sure to update its segment offset.
                if body.seg_index == 0 {
                    body.seg_offset = new_hdr_len;
                }
            } else {
                // In this case we need to "erase" the old headers and
                // allocate an mblk to hold the new headers.
                //
                // XXX This assumes that the headers all reside in the
                // first segment. For any typical implementation, this
                // should be true (it's better for performance, and
                // just makes the most sense). However, if that
                // invariant doesn't hold true, this method of erasing
                // the original header data is incomplete. It will
                // only partially erase the data, leading to confusion
                // downstream somewhere. The best solution is to check
                // for this during parsing. If the header straddles
                // segments, then just copy all header data into a new
                // segment, and replace the old header data with that
                // one segment. This means a hit on performance, but
                // it also means sanity for all downstream code.
                // Besides, any network stack that cares about
                // performance will already make sure to place the
                // headers in a single buffer.
                segs[0].shrink_start(old_hdr_len).unwrap();

                // Create the new segment for holding the new headers.
                let mut seg = unsafe {
                    let mp = allocb(new_hdr_len);
                    PacketSeg::wrap_mblk(mp)
                };

                // Make room to write the new headers.
                seg.expand_end(new_hdr_len).unwrap();

                // We shrunk the first segment to erase the old
                // headers. If the body starts in this same segment,
                // then we need to adjust its segment offset to
                // reflect the fact that there is no header data
                // before it. That is, since we know we are erasing
                // the entirety of the original headers in the
                // original first segment, we also know that the body
                // must now start at segment offset 0.
                //
                // If the body **does not** start in the same segment
                // as the original headers, then its offset does not
                // change, because its segment is not adjusted.
                if body.seg_index == 0 {
                    assert_eq!(body.seg_offset - old_hdr_len, 0);
                    body.seg_offset = 0;
                }
                seg.link(&segs[0]);

                // TODO-performance: This may necessitate another allocation. We
                // will want to measure how often we hit this branch, and the
                // impact of the allocation.
                segs.insert(0, seg);

                // We've added a segment to the front of the list; the
                // body segment moves over by one.
                body.seg_index += 1;
            }
        } else if new_hdr_len < old_hdr_len {
            let delta = old_hdr_len - new_hdr_len;
            segs[0].shrink_start(delta).unwrap();

            // If the body starts in this first segment, then make
            // sure to update its segment offset.
            if body.seg_index == 0 {
                body.seg_offset = new_hdr_len;
            }
        }

        unsafe {
            assert!((*segs[0].mp).b_rptr >= (*segs[0].dblk).db_base);
            assert!((*segs[0].mp).b_rptr <= (*segs[0].mp).b_wptr);
        }

        // With regards to the overall packet, we know the body should
        // start after the new headers.
        body.pkt_offset = new_hdr_len;
    }

    /// Emit the new headers to the [`Packet`] based on its current
    /// metadata.
    pub fn emit_new_headers(&mut self) -> Result<(), WriteError> {
        // At this point the packet metadata represents the
        // transformations made by the pipeline. We take the following
        // steps to emit the new headers and update the packet data.
        //
        // 1. Figure out length required to emit the new headers.
        //
        // 2. Determine if this length can be met by the current first
        //    segment. If not, allocate a new segment to prepend to
        //    the xlist.
        //
        // 3. Emit the new header bytes based on the current metadata.
        //
        // 4. Update the headers offsets, body info, and checksums.
        let innerm = &self.state.meta.inner;

        // Flag to indicate if an IP header/ULP checksums were
        // provided. If the checksum is zero, it's assumed heardware
        // checksum offload is being used, and OPTE should not update
        // the checksum.
        let inner_ip_csum = innerm.has_ip_csum();
        let inner_ulp_csum = innerm.has_ulp_csum();

        // The length of the new headers.
        let new_hdr_len = self.state.meta.hdr_len();
        // The total length of the new packet, including headers and
        // body. This is used to determine the offset/length values of
        // the new headers.
        let new_pkt_len = usize::from(new_hdr_len) + self.state.body.len;

        // Given the new header length requirement, determine if it
        // can be met with the current segment buffers, or if a new
        // segment must be allocated and tacked onto the front of the
        // segment list.
        //
        // Upon returning from this function the header offsets are no
        // longer correct. New offsets are calculated as part of
        // emitting the new headers below.
        //
        // The body offset **is** updated as part of this function,
        // and is correct upon return.
        Self::hdr_seg(&mut self.segs, new_hdr_len, &mut self.state.body);
        let mut wtr = self.segs[0].get_writer();
        let new_offsets = Self::emit_headers(
            &mut wtr,
            &mut self.state.meta.outer,
            &mut self.state.meta.inner,
            new_pkt_len,
        )?;
        drop(wtr);

        // Update the header offsets.
        self.state.hdr_offsets = new_offsets;
        self.avail = self.segs.iter().map(|s| s.avail).sum();
        self.state.len = self.segs.iter().map(|s| s.len).sum();

        // Update the ULP and IP header checksums.
        self.update_checksums(inner_ip_csum, inner_ulp_csum);
        Ok(())
    }

    fn emit_outer_headers<'a>(
        wtr: &mut PacketSegWriter,
        meta: &mut OuterMeta,
        new_pkt_len: usize,
    ) -> Result<(usize, OuterHeaderOffsets), WriteError> {
        let mut offsets = OuterHeaderOffsets::default();
        let mut pkt_offset = 0;

        match &meta.ether {
            Some(ether) => {
                ether.emit(wtr.slice_mut(EtherHdr::SIZE)?);
                offsets.ether = Some(HdrOffset {
                    pkt_pos: pkt_offset,
                    seg_idx: 0,
                    seg_pos: pkt_offset,
                    hdr_len: EtherHdr::SIZE,
                });
                pkt_offset += EtherHdr::SIZE;
            }

            // If there is no outer Ethernet, then there can be no
            // outer headers at all.
            None => return Ok((pkt_offset, offsets)),
        }

        match meta.ip.as_mut() {
            Some(IpMeta::Ip4(ip4)) => {
                ip4.total_len = (new_pkt_len - pkt_offset) as u16;
                ip4.emit(wtr.slice_mut(ip4.hdr_len())?);
                offsets.ip = Some(HdrOffset {
                    pkt_pos: pkt_offset,
                    seg_idx: 0,
                    seg_pos: pkt_offset,
                    hdr_len: ip4.hdr_len() as usize,
                });
                pkt_offset += usize::from(ip4.hdr_len());
            }

            Some(IpMeta::Ip6(ip6)) => {
                ip6.pay_len = (new_pkt_len - pkt_offset) as u16;
                ip6.emit(wtr.slice_mut(ip6.hdr_len())?);
                offsets.ip = Some(HdrOffset {
                    pkt_pos: pkt_offset,
                    seg_idx: 0,
                    seg_pos: pkt_offset,
                    hdr_len: ip6.hdr_len() as usize,
                });
                pkt_offset += usize::from(ip6.hdr_len());
            }

            None => return Ok((pkt_offset, offsets)),
        }

        match meta.encap.as_mut() {
            Some(EncapMeta::Geneve(geneve)) => {
                geneve.len = (new_pkt_len - pkt_offset) as u16;
                geneve.emit(wtr.slice_mut(geneve.hdr_len())?);
                offsets.ip = Some(HdrOffset {
                    pkt_pos: pkt_offset,
                    seg_idx: 0,
                    seg_pos: pkt_offset,
                    hdr_len: geneve.hdr_len(),
                });
                pkt_offset += geneve.hdr_len();
            }

            None => return Ok((pkt_offset, offsets)),
        }

        Ok((pkt_offset, offsets))
    }

    fn emit_inner_headers<'a>(
        wtr: &mut PacketSegWriter,
        meta: &mut InnerMeta,
        mut pkt_offset: usize,
        new_pkt_len: usize,
    ) -> Result<InnerHeaderOffsets, WriteError> {
        let mut offsets = InnerHeaderOffsets::default();

        // ================================================================
        // Ether
        // ================================================================
        meta.ether.emit(wtr.slice_mut(EtherHdr::SIZE)?);
        offsets.ether = HdrOffset {
            pkt_pos: pkt_offset,
            seg_idx: 0,
            seg_pos: pkt_offset,
            hdr_len: EtherHdr::SIZE,
        };
        pkt_offset += EtherHdr::SIZE;

        // ================================================================
        // IP
        // ================================================================
        match meta.ip.as_mut() {
            Some(IpMeta::Ip4(ip4)) => {
                ip4.total_len = (new_pkt_len - pkt_offset) as u16;
                ip4.emit(wtr.slice_mut(ip4.hdr_len())?);
                offsets.ip = Some(HdrOffset {
                    pkt_pos: pkt_offset,
                    seg_idx: 0,
                    seg_pos: pkt_offset,
                    hdr_len: ip4.hdr_len() as usize,
                });
                pkt_offset += ip4.hdr_len();
            }

            Some(IpMeta::Ip6(ip6)) => {
                ip6.pay_len = (new_pkt_len - pkt_offset) as u16;
                ip6.emit(wtr.slice_mut(ip6.hdr_len())?);
                offsets.ip = Some(HdrOffset {
                    pkt_pos: pkt_offset,
                    seg_idx: 0,
                    seg_pos: pkt_offset,
                    hdr_len: ip6.hdr_len() as usize,
                });
                pkt_offset += usize::from(ip6.hdr_len());
            }

            None => return Ok(offsets),
        }

        // ================================================================
        // ULP
        // ================================================================
        match meta.ulp.as_mut() {
            Some(UlpMeta::Udp(udp)) => {
                udp.len = (new_pkt_len - pkt_offset) as u16;
                udp.emit(wtr.slice_mut(udp.hdr_len())?);
                offsets.ulp = Some(HdrOffset {
                    pkt_pos: pkt_offset,
                    seg_idx: 0,
                    seg_pos: pkt_offset,
                    hdr_len: usize::from(udp.hdr_len()),
                });
            }

            Some(UlpMeta::Tcp(tcp)) => {
                tcp.emit(wtr.slice_mut(tcp.hdr_len())?);
                offsets.ulp = Some(HdrOffset {
                    pkt_pos: pkt_offset,
                    seg_idx: 0,
                    seg_pos: pkt_offset,
                    hdr_len: usize::from(tcp.hdr_len()),
                });
            }

            None => return Ok(offsets),
        }

        Ok(offsets)
    }

    /// Emit header bytes to the given writer based on the passed-in
    /// metadata.
    fn emit_headers<'a>(
        wtr: &mut PacketSegWriter<'a>,
        outer_meta: &mut OuterMeta,
        inner_meta: &mut InnerMeta,
        new_pkt_len: usize,
    ) -> Result<HeaderOffsets, WriteError> {
        let (pkt_offset, outer_offsets) =
            Self::emit_outer_headers(wtr, outer_meta, new_pkt_len)?;

        let inner_offsets =
            Self::emit_inner_headers(wtr, inner_meta, pkt_offset, new_pkt_len)?;

        Ok(HeaderOffsets { outer: outer_offsets, inner: inner_offsets })
    }
}

impl<S: CanRead + PacketState> Packet<S> {
    /// Clone and return all bytes. This is used for testing.
    pub fn all_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.state.len());
        for seg in &self.segs {
            let s = unsafe { slice::from_raw_parts((*seg.mp).b_rptr, seg.len) };
            bytes.extend_from_slice(s);
        }
        bytes
    }

    /// Return the length of the packet.
    ///
    /// NOTE: This length only includes the _initialized_ bytes of the
    /// packet. Each [`PacketSeg`] may contain _uninitialized_ bytes
    /// at the head or tail (or both) of the segment.
    ///
    /// This is equivalent to the `msgsize(9F)` function in illumos.
    pub fn len(&self) -> usize {
        self.state.len()
    }

    /// Return a byte slice of the bytes in `seg`.
    pub fn seg_bytes(&self, seg: usize) -> &[u8] {
        let seg = &self.segs[seg];
        // Safety: As long as the `mp` pointer is legit this is safe.
        unsafe { slice::from_raw_parts((*seg.mp).b_rptr, seg.len) }
    }
}

/// A packet segment represents one or more (or all) bytes of a
/// [`Packet`].
#[derive(Clone, Debug)]
pub struct PacketSeg {
    mp: *mut mblk_t,
    dblk: *mut dblk_t,
    len: usize,
    avail: usize,
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

impl PacketSeg {
    fn alloc(len: usize) -> Self {
        // Safety: We know this is safe because we are literally
        // passing in an mblk derived from `allocb(9F)`.
        unsafe { PacketSeg::wrap_mblk(allocb(len)) }
    }

    /// Return the bytes of the packet.
    ///
    /// This is useful for testing.
    #[cfg(test)]
    pub fn bytes(&self) -> &[u8] {
        unsafe { &slice::from_raw_parts((*self.mp).b_rptr, self.len) }
    }

    /// Expand the writable/readable area by pushing `b_wptr` out by
    /// len.
    ///
    /// # Errors
    ///
    /// `SegAdjustError::EndPastLimit`: Expanding by `len` would put the
    /// `b_wptr` past the underlying buffer's limit (`db_lim`).
    pub fn expand_end(&mut self, len: usize) -> Result<(), SegAdjustError> {
        let wptr = unsafe { (*self.mp).b_wptr };
        let lim = unsafe { (*self.dblk).db_lim };
        let new_wptr = unsafe { wptr.add(len) };

        if new_wptr > lim {
            return Err(SegAdjustError::EndPastLimit);
        }

        unsafe {
            (*self.mp).b_wptr = new_wptr;
        }
        self.len = unsafe {
            (*self.mp).b_wptr.offset_from((*self.mp).b_rptr) as usize
        };
        Ok(())
    }

    /// Expand the writable/readable area by shifting `b_rptr` by len;
    /// effectively adding bytes to the start of the packet.
    ///
    /// # Errors
    ///
    /// `SegAdjustError::StartBeforeBase`: Shift the read pointer left
    /// by `len` bytes would place `b_rptr` before the underlying
    /// buffer's base (`db_base`).
    pub fn expand_start(&mut self, len: usize) -> Result<(), SegAdjustError> {
        let rptr = unsafe { (*self.mp).b_rptr };
        let base = unsafe { (*self.dblk).db_base };
        let new_rptr = unsafe { rptr.sub(len) };

        if new_rptr < base {
            return Err(SegAdjustError::StartBeforeBase);
        }

        unsafe {
            (*self.mp).b_rptr = new_rptr;
        }
        self.len = unsafe {
            (*self.mp).b_wptr.offset_from((*self.mp).b_rptr) as usize
        };
        Ok(())
    }

    /// Shrink the writable/readable area by shifting the `b_rptr` by
    /// `len`; effectively removing bytes from the start of the packet.
    ///
    /// # Errors
    ///
    /// `SegAdjustError::StartPastEnd`: Shifting the read pointer by
    /// `len` would move `b_rptr` past `b_wptr`.
    pub fn shrink_start(&mut self, len: usize) -> Result<(), SegAdjustError> {
        let wptr = unsafe { (*self.mp).b_wptr };
        let rptr = unsafe { (*self.mp).b_rptr };
        let new_rptr = unsafe { rptr.add(len) };

        if new_rptr > wptr {
            return Err(SegAdjustError::StartPastEnd);
        }

        unsafe {
            (*self.mp).b_rptr = new_rptr;
        }
        self.len = unsafe {
            (*self.mp).b_wptr.offset_from((*self.mp).b_rptr) as usize
        };
        Ok(())
    }

    pub fn get_writer(&mut self) -> PacketSegWriter {
        PacketSegWriter::new(self, 0, self.len).unwrap()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    fn link(&mut self, seg: &PacketSeg) {
        unsafe { (*self.mp).b_cont = seg.mp };
    }

    // The amount of space available between the data buffer's base
    // (`dblk_t.db_base`) and the packet's start (`mblk_t.b_rptr`).
    fn prefix_len(&self) -> usize {
        let prefix =
            unsafe { (*self.mp).b_rptr.offset_from((*self.dblk).db_base) };
        assert!(prefix >= 0);
        prefix as usize
    }

    /// Get a slice of the entire segment.
    fn slice(&self) -> &[u8] {
        // Panic: We are using the segment's own data to take a slice
        // of the entire segment.
        self.slice_unchecked(0, None)
    }

    /// Get a mutable slice of the entire segment.
    fn slice_mut(&mut self) -> &mut [u8] {
        // Panic: We are using the segment's own data to take a slice
        // of the entire segment.
        self.slice_mut_unchecked(0, None)
    }

    /// Get a slice of the segment.
    ///
    /// The slice starts at `offset` and consists of `len` bytes. If
    /// the length is `None`, then the slice extends to the end of the
    /// segment. This includes only the part of the dblk which has
    /// been written, i.e. the bytes from `mblk.b_rptr` to
    /// `mblk.b_wptr`.
    ///
    /// # Safety
    ///
    /// It is up to the caller to ensure that `offset` and `offset +
    /// len` reside within the segment boundaries.
    ///
    /// # Panic
    ///
    /// The slice formed by the `offset` and `offset + len` MUST be
    /// within the bounds of the segment, otherwise panic.
    fn slice_unchecked(&self, offset: usize, len: Option<usize>) -> &[u8] {
        if offset > self.len {
            panic!(
                "offset is outside the bounds of the mblk: \
                    offset: {} len: {} mblk: {:p}",
                offset, self.len, self.mp
            );
        }

        // Safety: This pointer was handed to us by the system.
        let start = unsafe { (*self.mp).b_rptr.add(offset) };
        let len = len.unwrap_or(self.len - offset);
        // Safety: If this end is outside the bound of the segment we
        // panic below.
        let end = unsafe { start.add(len) };
        // Safety: This pointer was handed to us by the system.
        let b_wptr = unsafe { (*self.mp).b_wptr };
        assert!(
            end <= b_wptr,
            "slice past end of segment: offset: {} len: {} end: {:p} \
             mblk: {:p} b_wptr: {:p}",
            offset,
            len,
            end,
            self.mp,
            b_wptr,
        );

        // Safety: We have verified that the slice is within the
        // bounds of the segment.
        unsafe { slice::from_raw_parts(start, len) }
    }

    /// Get a mutable slice of the segment.
    ///
    /// The slice starts at `offset` and consists of `len` bytes. If
    /// the length is `None`, then the slice extends to the end of the
    /// segment. This includes only the part of the dblk which has
    /// been written, i.e. the bytes from `mblk.b_rptr` to
    /// `mblk.b_wptr`.
    ///
    /// # Panic
    ///
    /// The slice formed by the `offset` and `offset + len` MUST be
    /// within the bounds of the segment, otherwise panic.
    fn slice_mut_unchecked(
        &mut self,
        offset: usize,
        len: Option<usize>,
    ) -> &mut [u8] {
        if offset > self.len {
            panic!(
                "offset is outside the bounds of the mblk: \
                    offset: {} len: {} mblk: {:p}",
                offset, self.len, self.mp
            );
        }

        // Safety: This pointer was handed to us by the system.
        let start = unsafe { (*self.mp).b_rptr.add(offset) };
        let len = len.unwrap_or(self.len - offset);
        // Safety: If this end is outside the bound of the segment we
        // panic below.
        let end = unsafe { start.add(len) };
        // Safety: This pointer was handed to us by the system.
        let b_wptr = unsafe { (*self.mp).b_wptr };
        assert!(
            end <= b_wptr,
            "slice past end of segment: offset: {} len: {} end: {:p} \
             mblk: {:p} b_wptr: {:p}",
            offset,
            len,
            end,
            self.mp,
            b_wptr,
        );

        // Safety: We have verified that the slice is within the
        // bounds of the segment.
        unsafe { slice::from_raw_parts_mut(start, len) }
    }

    // Wrap an existing `mblk_t`, taking ownership of it.
    //
    // # Safety
    //
    // The `mp` passed must be a non-NULL pointer to an `mblk_t`
    // created by one of the `allocb(9F)` family of calls.
    //
    // After calling this function, the original mp pointer should
    // not be dereferenced.
    unsafe fn wrap_mblk(mp: *mut mblk_t) -> Self {
        let dblk = (*mp).b_datap as *mut dblk_t;
        let len = (*mp).b_wptr.offset_from((*mp).b_rptr) as usize;
        let avail = (*dblk).db_lim.offset_from((*dblk).db_base) as usize;
        PacketSeg { mp, dblk, avail, len }
    }
}

/// Modify the bytes of a packet segment.
///
/// This type allows one to modify all or some of the bytes of a
/// [`PacketSeg`]. This is limited to the initialized bytes of the
/// segment, i.e., those that sit between `b_rptr` and `b_wptr`.
pub struct PacketSegWriter<'a> {
    // Current position in the bytes slice.
    pos: usize,
    avail: usize,
    bytes: &'a mut [u8],
}

#[derive(Clone, Copy, Debug)]
pub enum ModifierCreateError {
    StartOutOfRange,
    EndOutOfRange,
}

impl<'a> PacketSegWriter<'a> {
    /// Create a new [`PacketSegWriter`], starting at `offset` from
    /// `b_rptr`, and running for `len` bytes.
    ///
    /// The slice of bytes selected must be within `b_rptr` and `b_wptr`.
    ///
    /// # Errors
    ///
    /// `ModifierCreateError::StartOutOfRange`: The `offset` value has
    /// gone beyond `b_wptr`.
    ///
    /// `ModifierCreateError::EndOutOfRange`: The `b_rptr + offset +
    /// len` has gone beyond `b_wptr`.
    fn new<'b>(
        seg: &'a mut PacketSeg,
        offset: usize,
        len: usize,
    ) -> Result<Self, ModifierCreateError> {
        let b_rptr = unsafe { (*seg.mp).b_rptr };
        let b_wptr = unsafe { (*seg.mp).b_wptr };
        let start = unsafe { b_rptr.add(offset) };

        if start > b_wptr {
            return Err(ModifierCreateError::StartOutOfRange);
        }

        let end = unsafe { start.add(len) };

        if end > b_wptr {
            return Err(ModifierCreateError::EndOutOfRange);
        }

        let bytes = unsafe { slice::from_raw_parts_mut(start, len) };

        Ok(Self { pos: 0, bytes, avail: len })
    }

    pub fn slice_mut(&mut self, len: usize) -> Result<&mut [u8], WriteError> {
        if len > self.avail {
            return Err(WriteError::NotEnoughBytes {
                available: self.avail,
                needed: len,
            });
        }

        let end = self.pos + len;
        let slice = &mut self.bytes[self.pos..end];
        self.pos += len;
        self.avail -= len;
        Ok(slice)
    }

    pub fn write(&mut self, src: &[u8]) -> Result<(), WriteError> {
        debug_assert!(self.bytes[self.pos..].len() >= src.len());
        let len = src.len();
        if len > self.avail {
            return Err(WriteError::NotEnoughBytes {
                available: self.avail,
                needed: len,
            });
        }

        let end = self.pos + len;
        self.bytes[self.pos..end].copy_from_slice(src);
        self.pos += len;
        self.avail -= len;
        Ok(())
    }

    pub fn write_u8(&mut self, val: u8) -> Result<(), WriteError> {
        self.write(&[val])
    }

    pub fn write_u16(&mut self, val: u16) -> Result<(), WriteError> {
        self.write(&val.to_be_bytes())
    }

    pub fn write_u32(&mut self, val: u32) -> Result<(), WriteError> {
        self.write(&val.to_be_bytes())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum WrapError {
    /// We tried to wrap a NULL pointer.
    NullPtr,
}

/// Some functions may return multiple types of errors.
#[derive(Clone, Debug)]
pub enum PacketError {
    Parse(ParseError),
    Wrap(WrapError),
}

impl From<ParseError> for PacketError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

impl From<WrapError> for PacketError {
    fn from(e: WrapError) -> Self {
        Self::Wrap(e)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    BadHeader(String),
    BadInnerIpLen { expected: usize, actual: usize },
    BadInnerUlpLen { expected: usize, actual: usize },
    BadOuterIpLen { expected: usize, actual: usize },
    BadOuterUlpLen { expected: usize, actual: usize },
    BadRead(ReadErr),
    TruncatedBody { expected: usize, actual: usize },
    UnexpectedEtherType(super::ether::EtherType),
    UnsupportedEtherType(u16),
    UnexpectedProtocol(Protocol),
    UnsupportedProtocol(Protocol),
}

impl From<ReadErr> for ParseError {
    fn from(err: ReadErr) -> Self {
        Self::BadRead(err)
    }
}

impl From<EtherHdrError> for ParseError {
    fn from(err: EtherHdrError) -> Self {
        Self::BadHeader(format!("{}", err))
    }
}

impl From<ArpHdrError> for ParseError {
    fn from(err: ArpHdrError) -> Self {
        Self::BadHeader(format!("ARP: {:?}", err))
    }
}

impl From<Ipv4HdrError> for ParseError {
    fn from(err: Ipv4HdrError) -> Self {
        Self::BadHeader(format!("IPv4: {:?}", err))
    }
}

impl From<Ipv6HdrError> for ParseError {
    fn from(err: Ipv6HdrError) -> Self {
        Self::BadHeader(format!("IPv6: {:?}", err))
    }
}

impl From<TcpHdrError> for ParseError {
    fn from(err: TcpHdrError) -> Self {
        Self::BadHeader(format!("TCP: {:?}", err))
    }
}

impl From<UdpHdrError> for ParseError {
    fn from(err: UdpHdrError) -> Self {
        Self::BadHeader(format!("UDP: {:?}", err))
    }
}

impl From<GeneveHdrError> for ParseError {
    fn from(err: GeneveHdrError) -> Self {
        Self::BadHeader(format!("{:?}", err))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadErr {
    BadLayout,
    EndOfPacket,
    NotEnoughBytes,
    OutOfRange,
    StraddledRead,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteError {
    BadLayout,
    EndOfPacket,
    EtherHdr(EtherHdrError),
    GeneveHdr(GeneveHdrError),
    Ipv4Hdr(Ipv4HdrError),
    Ipv6Hdr(Ipv6HdrError),
    NotEnoughBytes { available: usize, needed: usize },
    Read(ReadErr),
    StraddledWrite,
    TcpHdr(TcpHdrError),
    UdpHdr(UdpHdrError),
}

impl From<TcpHdrError> for WriteError {
    fn from(e: TcpHdrError) -> Self {
        Self::TcpHdr(e)
    }
}

impl From<UdpHdrError> for WriteError {
    fn from(e: UdpHdrError) -> Self {
        Self::UdpHdr(e)
    }
}

impl From<EtherHdrError> for WriteError {
    fn from(e: EtherHdrError) -> Self {
        Self::EtherHdr(e)
    }
}

impl From<GeneveHdrError> for WriteError {
    fn from(e: GeneveHdrError) -> Self {
        Self::GeneveHdr(e)
    }
}

impl From<Ipv4HdrError> for WriteError {
    fn from(e: Ipv4HdrError) -> Self {
        Self::Ipv4Hdr(e)
    }
}

impl From<Ipv6HdrError> for WriteError {
    fn from(e: Ipv6HdrError) -> Self {
        Self::Ipv6Hdr(e)
    }
}

impl From<ReadErr> for WriteError {
    fn from(e: ReadErr) -> Self {
        Self::Read(e)
    }
}

pub type ReadResult<T> = result::Result<T, ReadErr>;
pub type WriteResult<T> = result::Result<T, WriteError>;

/// A trait for reading bytes from packets.
///
/// All operations start from the current position and move it
/// forward, with the exception of `seek_back()`, which moves the
/// position backwards within the current segment.
pub trait PacketRead<'a> {
    /// Copy all bytes from current position to the end of the packet
    /// leaving the reader's internal state untouched.
    fn copy_remaining(&self) -> Vec<u8>;

    /// Return the current position in the packet.
    fn pos(&self) -> usize;

    /// Seek forwards from the current position by `amount`. The seek
    /// may cross segment boundaries.
    ///
    /// # Errors
    ///
    /// If the seek would move beyond the end of the packet, then a
    /// [`ReadErr::EndOfPacket`] is returned.
    fn seek(&mut self, amount: usize) -> ReadResult<()>;

    /// Seek backwards from the current position by `amount`.
    ///
    /// # Errors
    ///
    /// If the seek would move beyond the beginning of the current
    /// segment, then an error is returned.
    fn seek_back(&mut self, amount: usize) -> ReadResult<()>;

    fn seg_left(&self) -> usize;
    fn seg_idx(&self) -> usize;
    fn seg_pos(&self) -> usize;

    /// Return the slice of `len` bytes starting from the current
    /// position.
    ///
    /// The slice *must* exist entirely in a single packet segment --
    /// it can never straddle multiple segments.
    ///
    /// # Errors
    ///
    /// If `self` cannot satisfy this request a `ReadErr` is returned.
    fn slice<'b>(&'b mut self, len: usize) -> ReadResult<&'a [u8]>;
}

/// Append: Append to the end of the segment or packet, i.e. start at
/// `b_wptr`.
///
/// Modify(offset): Modify bytes starting at `offset` from the
/// beginning of the segment or packet (`b_rptr`). The length of the
/// write must fit within the end of the current segment (`b_wptr`).
pub enum WritePos {
    Append,
    Modify(u16),
}

#[derive(Debug)]
pub struct PacketReader<'a> {
    pkt_segs: &'a [PacketSeg],
    pkt_pos: usize,
    seg_idx: usize,
    seg_pos: usize,
    seg_len: usize,
}

impl<'a> PacketReader<'a> {
    pub fn finish(self) -> (usize, usize, usize, bool) {
        let end_of_seg = self.seg_pos == self.seg_len;
        (self.pkt_pos, self.seg_idx, self.seg_pos, end_of_seg)
    }

    pub fn new(pkt_segs: &'a [PacketSeg]) -> Self {
        let seg_len = pkt_segs[0].len;

        PacketReader { pkt_segs, pkt_pos: 0, seg_idx: 0, seg_pos: 0, seg_len }
    }

    pub fn pkt_pos(&self) -> usize {
        self.pkt_pos
    }
}

impl<'a> PacketRead<'a> for PacketReader<'a> {
    fn pos(&self) -> usize {
        self.pkt_pos as usize
    }

    fn seek(&mut self, mut amount: usize) -> ReadResult<()> {
        while self.seg_pos + amount > self.seg_len {
            if self.seg_idx + 1 == self.pkt_segs.len() {
                return Err(ReadErr::OutOfRange);
            }

            self.seg_idx += 1;
            amount -= self.seg_len - self.seg_pos;
            self.pkt_pos += self.seg_len - self.seg_pos;
            self.seg_len = self.pkt_segs[self.seg_idx].len;
            self.seg_pos = 0;
        }

        self.seg_pos += amount;
        self.pkt_pos += amount;
        Ok(())
    }

    /// Seek backwards by `offset`.
    ///
    /// NOTE: Currently we only allow seeking back to the beginning of
    /// the current segment, which should be enough in all situations
    /// this is needed (this API is in flux so no point putting in
    /// work that isn't needed at the moment).
    fn seek_back(&mut self, amount: usize) -> ReadResult<()> {
        if amount > self.seg_pos {
            return Err(ReadErr::NotEnoughBytes);
        }

        self.seg_pos -= amount;
        self.pkt_pos -= amount;
        Ok(())
    }

    fn seg_left(&self) -> usize {
        self.seg_len - self.seg_pos
    }

    fn seg_idx(&self) -> usize {
        self.seg_idx
    }

    fn seg_pos(&self) -> usize {
        self.seg_pos
    }

    fn slice<'b>(&'b mut self, len: usize) -> ReadResult<&'a [u8]> {
        let mut seg = &self.pkt_segs[self.seg_idx];

        // If we've reached the end of the initialized bytes in this
        // segment.
        if self.seg_pos == seg.len {
            // There are no more segments to be read.
            if (self.seg_idx + 1) == self.pkt_segs.len() {
                return Err(ReadErr::EndOfPacket);
            }

            // Move onto next segment.
            self.seg_idx += 1;
            seg = &self.pkt_segs[self.seg_idx];
            self.seg_pos = 0;
            self.seg_len = seg.len;
        }

        if self.seg_pos + len > self.seg_len {
            return Err(ReadErr::NotEnoughBytes);
        }

        let ret = unsafe {
            let start = (*seg.mp).b_rptr.add(self.seg_pos);
            slice::from_raw_parts(start, len)
        };

        self.pkt_pos += len;
        self.seg_pos += len;
        Ok(ret)
    }

    fn copy_remaining(&self) -> Vec<u8> {
        let total_len: usize = self.pkt_segs.iter().map(|s| s.len).sum();
        let mut bytes = Vec::with_capacity(total_len - self.pkt_pos);
        let mut seg_idx = self.seg_idx;
        let mut seg_pos = self.seg_pos;
        let mut seg_len = self.seg_len;
        let mut seg = &self.pkt_segs[seg_idx];

        loop {
            let seg_slice = unsafe {
                let start = (*seg.mp).b_rptr.add(seg_pos);
                slice::from_raw_parts(start, seg_len - seg_pos)
            };
            bytes.extend_from_slice(seg_slice);

            seg_idx += 1;

            if seg_idx >= self.pkt_segs.len() {
                break;
            }

            seg = &self.pkt_segs[seg_idx];
            seg_pos = 0;
            seg_len = seg.len
        }

        bytes
    }
}

/// A trait for getting mutable slices of bytes from packets.
///
/// All operations start from the current position and move it
/// forward.
pub trait PacketReadMut<'a>: PacketRead<'a> {
    /// Reutrn the current offset into the packet.
    fn offset(&self) -> ReaderOffset;

    /// Return a mutable reference to a slice of `len` bytes starting
    /// from the current position.
    ///
    /// The slice *must* exist entirely in a single packet segment --
    /// it can never straddle multiple segments.
    ///
    /// # Errors
    ///
    /// If `self` cannot satisfy this request a `ReadErr` is returned.
    fn slice_mut<'b>(&'b mut self, len: usize) -> ReadResult<&'a mut [u8]>;
}

#[derive(Debug)]
pub struct PacketReaderMut<'a> {
    pkt_segs: &'a mut [PacketSeg],
    pkt_pos: usize,
    seg_idx: usize,
    seg_pos: usize,
    seg_len: usize,
}

impl<'a> PacketReaderMut<'a> {
    pub fn finish(self) -> (usize, usize, usize, bool) {
        let end_of_seg = self.seg_pos == self.seg_len;
        (self.pkt_pos, self.seg_idx, self.seg_pos, end_of_seg)
    }

    pub fn new(pkt_segs: &'a mut [PacketSeg]) -> Self {
        let seg_len = pkt_segs[0].len;

        PacketReaderMut {
            pkt_segs,
            pkt_pos: 0,
            seg_idx: 0,
            seg_pos: 0,
            seg_len,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ReaderOffset {
    pub pkt_pos: usize,
    pub seg_idx: usize,
    pub seg_pos: usize,
}

impl<'a> PacketRead<'a> for PacketReaderMut<'a> {
    fn pos(&self) -> usize {
        self.pkt_pos as usize
    }

    fn seek(&mut self, mut amount: usize) -> ReadResult<()> {
        while self.seg_pos + amount > self.seg_len {
            if self.seg_idx + 1 == self.pkt_segs.len() {
                return Err(ReadErr::OutOfRange);
            }

            self.seg_idx += 1;
            amount -= self.seg_len - self.seg_pos;
            self.pkt_pos += self.seg_len - self.seg_pos;
            self.seg_len = self.pkt_segs[self.seg_idx].len;
            self.seg_pos = 0;
        }

        self.seg_pos += amount;
        self.pkt_pos += amount;
        Ok(())
    }

    /// Seek backwards by `offset`.
    ///
    /// NOTE: Currently we only allow seeking back to the beginning of
    /// the current segment, which should be enough in all situations
    /// this is needed (this API is in flux so no point putting in
    /// work that isn't needed at the moment).
    fn seek_back(&mut self, amount: usize) -> ReadResult<()> {
        if amount > self.seg_pos {
            return Err(ReadErr::NotEnoughBytes);
        }

        self.seg_pos -= amount;
        self.pkt_pos -= amount;
        Ok(())
    }

    fn seg_idx(&self) -> usize {
        self.seg_idx
    }

    fn seg_left(&self) -> usize {
        self.seg_len - self.seg_pos
    }

    fn seg_pos(&self) -> usize {
        self.seg_pos
    }

    fn slice<'b>(&'b mut self, len: usize) -> ReadResult<&'a [u8]> {
        let mut seg = &self.pkt_segs[self.seg_idx];

        // If we've reached the end of the initialized bytes in this
        // segment.
        if self.seg_pos == seg.len {
            // There are no more segments to be read.
            if (self.seg_idx + 1) == self.pkt_segs.len() {
                return Err(ReadErr::EndOfPacket);
            }

            // Move onto next segment.
            self.seg_idx += 1;
            seg = &self.pkt_segs[self.seg_idx];
            self.seg_pos = 0;
            self.seg_len = seg.len;
        }

        if self.seg_pos + len > self.seg_len {
            return Err(ReadErr::NotEnoughBytes);
        }

        let ret = unsafe {
            let start = (*seg.mp).b_rptr.add(self.seg_pos);
            slice::from_raw_parts(start, len)
        };

        self.pkt_pos += len;
        self.seg_pos += len;
        Ok(ret)
    }

    fn copy_remaining(&self) -> Vec<u8> {
        let total_len: usize = self.pkt_segs.iter().map(|s| s.len).sum();
        let mut bytes = Vec::with_capacity(total_len - self.pkt_pos);
        let mut seg_idx = self.seg_idx;
        let mut seg_pos = self.seg_pos;
        let mut seg_len = self.seg_len;
        let mut seg = &self.pkt_segs[seg_idx];

        loop {
            let seg_slice = unsafe {
                let start = (*seg.mp).b_rptr.add(seg_pos);
                slice::from_raw_parts(start, seg_len - seg_pos)
            };
            bytes.extend_from_slice(seg_slice);

            seg_idx += 1;

            if seg_idx >= self.pkt_segs.len() {
                break;
            }

            seg = &self.pkt_segs[seg_idx];
            seg_pos = 0;
            seg_len = seg.len
        }

        bytes
    }
}

impl<'a> PacketReadMut<'a> for PacketReaderMut<'a> {
    fn offset(&self) -> ReaderOffset {
        ReaderOffset {
            pkt_pos: self.pkt_pos,
            seg_idx: self.seg_idx,
            seg_pos: self.seg_pos,
        }
    }

    fn slice_mut<'b>(&'b mut self, len: usize) -> ReadResult<&'a mut [u8]> {
        let mut seg = &self.pkt_segs[self.seg_idx];

        // If we've reached the end of the initialized bytes in this
        // segment.
        if self.seg_pos == seg.len {
            // There are no more segments to be read.
            if (self.seg_idx + 1) == self.pkt_segs.len() {
                return Err(ReadErr::EndOfPacket);
            }

            // Move onto next segment.
            self.seg_idx += 1;
            seg = &self.pkt_segs[self.seg_idx];
            self.seg_pos = 0;
            self.seg_len = seg.len;
        }

        if self.seg_pos + len > self.seg_len {
            return Err(ReadErr::NotEnoughBytes);
        }

        let ret = unsafe {
            let start = (*seg.mp).b_rptr.add(self.seg_pos);
            slice::from_raw_parts_mut(start, len)
        };

        self.pkt_pos += len;
        self.seg_pos += len;
        Ok(ret)
    }
}

/// The common entry into an `allocb(9F)` implementation that works in
/// both std and `no_std` environments.
///
/// NOTE: We do not emulate the priority argument as it is not
/// relevant to OPTE's implementation. In the case of `no_std`, we
/// always pass a priority value of `0` to `allocb(9F)`.
pub fn allocb(size: usize) -> *mut mblk_t {
    assert!(size <= MBLK_MAX_SIZE);

    #[cfg(any(feature = "std", test))]
    return mock_allocb(size);

    // Safety: allocb(9F) should be safe for any size equal to or
    // less than MBLK_MAX_SIZE.
    #[cfg(all(not(feature = "std"), not(test)))]
    unsafe {
        ddi::allocb(size, 0)
    }
}

#[cfg(any(feature = "std", test))]
pub fn mock_allocb(size: usize) -> *mut mblk_t {
    // If the requested size is 0 we mimic allocb(9F) and allocate 16
    // bytes. See `uts/common/io/stream.c`.
    let size = if size == 0 { 16 } else { size };
    let buf = Vec::with_capacity(size);
    mock_desballoc(buf)
}

#[cfg(any(feature = "std", test))]
pub fn mock_desballoc(buf: Vec<u8>) -> *mut mblk_t {
    let mut buf = std::mem::ManuallyDrop::new(buf);
    let ptr = buf.as_mut_ptr();
    let len = buf.len();
    let avail = buf.capacity();

    // For the purposes of mocking in std the only fields that
    // matter here are the ones relating to the data buffer:
    // db_base and db_lim.
    let dblk = Box::new(dblk_t {
        db_frtnp: ptr::null(),
        db_base: ptr,
        // Safety: We rely on the Vec implementation to give us
        // the correct value for avail.
        db_lim: unsafe { ptr.add(avail) },
        db_ref: 0,
        db_type: 0,
        db_flags: 0,
        db_struioflag: 0,
        db_cpid: 0,
        db_cache: ptr::null(),
        db_mblk: ptr::null(),
        db_free: ptr::null(),
        db_lastfree: ptr::null(),
        db_cksumstart: 0,
        db_cksumend: 0,
        db_cksumstuff: 0,
        db_struioun: 0,
        db_fthdr: ptr::null(),
        db_credp: ptr::null(),
    });

    let dbp = Box::into_raw(dblk);

    // For the purposes of mocking in std the only fields that
    // matter are b_rptr and b_wptr. However, in the future we
    // will probably want to mock segments packets via b_cont and
    // packet chains via b_next.
    let mblk = Box::new(mblk_t {
        b_next: ptr::null_mut(),
        b_prev: ptr::null_mut(),
        b_cont: ptr::null_mut(),
        // Safety: We know dbp is valid because we just created it.
        b_rptr: unsafe { (*dbp).db_base as *mut c_uchar },
        b_wptr: unsafe { (*dbp).db_base.add(len) as *mut c_uchar },
        b_datap: dbp,
        b_band: 0,
        b_tag: 0,
        b_flag: 0,
        b_queue: ptr::null(),
    });

    let mp = Box::into_raw(mblk);
    // Safety: We know dbp is valid because we just created it.
    unsafe { (*dbp).db_mblk = mp as *const mblk_t };

    mp
}

// The std equivalent to `freemsg(9F)`.
#[cfg(any(feature = "std", test))]
fn mock_freemsg(mut mp: *mut mblk_t) {
    while mp != ptr::null_mut() {
        let cont = unsafe { (*mp).b_cont };
        mock_freeb(mp);
        mp = cont;
    }
}

// The std equivalent to `freeb(9F)`.
#[cfg(any(feature = "std", test))]
fn mock_freeb(mp: *mut mblk_t) {
    // Safety: All of these were created safely in `mock_alloc()`.
    // As long as the other methods don't do any of the following,
    // this is safe:
    //
    // * Modify the `mp`/`dblk` pointers.
    // * Increase `len` beyond `limit`.
    // * Modify `limit`.
    unsafe {
        let bmblk = Box::from_raw(mp);
        let bdblk = Box::from_raw(bmblk.b_datap as *mut dblk_t);
        let buffer = Vec::from_raw_parts(
            bdblk.db_base as *mut u8,
            bmblk.b_wptr.offset_from(bmblk.b_rptr) as usize,
            bdblk.db_lim.offset_from(bdblk.db_base) as usize,
        );
        drop(buffer);
        drop(bdblk);
        drop(bmblk);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::engine::ether::EtherHdr;
    use crate::engine::ether::EtherType;
    use crate::engine::ip4::Ipv4Hdr;
    use crate::engine::ip6::Ipv6Hdr;
    use crate::engine::tcp::TcpFlags;
    use crate::engine::tcp::TcpHdr;
    use crate::engine::GenericUlp;
    use opte_api::Direction::*;
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

    const PKT_SZ: usize =
        EtherHdr::SIZE + Ipv4Hdr::BASE_SIZE + TcpHdr::BASE_SIZE;

    fn tcp_pkt() -> Packet<Initialized> {
        let tcp = TcpMeta {
            src: 3839,
            dst: 80,
            seq: 4224936861,
            flags: TcpFlags::SYN,
            ..Default::default()
        };

        let ip4 = Ipv4Meta {
            src: SRC_IP4,
            dst: DST_IP4,
            proto: Protocol::TCP,
            ttl: 64,
            ident: 99,
            hdr_len: 20,
            total_len: 40,
            csum: [0; 2],
        };

        let eth = EtherMeta {
            ether_type: EtherType::Ipv4,
            src: SRC_MAC,
            dst: DST_MAC,
        };

        let mut seg = PacketSeg::alloc(PKT_SZ);
        seg.expand_end(PKT_SZ).unwrap();
        let mut wtr = seg.get_writer();
        eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
        ip4.emit(wtr.slice_mut(ip4.hdr_len()).unwrap());
        tcp.emit(wtr.slice_mut(tcp.hdr_len()).unwrap());
        let pkt = Packet::new(seg);
        assert_eq!(pkt.len(), PKT_SZ);
        pkt
    }

    #[test]
    fn zero_byte_packet() {
        let pkt = Packet::alloc(0);
        assert_eq!(pkt.len(), 0);
        assert_eq!(pkt.num_segs(), 1);
        assert_eq!(pkt.avail(), 16);
        let res = pkt.parse(Out, GenericUlp {});
        match res {
            Err(ParseError::BadHeader(msg)) => {
                assert_eq!(msg, "read error: EndOfPacket");
            }

            _ => panic!("expected read error, got: {:?}", res),
        }

        let pkt2 = Packet::copy(&vec![]);
        assert_eq!(pkt2.len(), 0);
        assert_eq!(pkt2.num_segs(), 1);
        assert_eq!(pkt2.avail(), 16);
        let res = pkt2.parse(Out, GenericUlp {});
        match res {
            Err(ParseError::BadHeader(msg)) => {
                assert_eq!(msg, "read error: EndOfPacket");
            }

            _ => panic!("expected read error, got: {:?}", res),
        }
    }

    // Verify uninitialized packet.
    #[test]
    fn uninitialized_packet() {
        let pkt = Packet::alloc(200);
        assert_eq!(pkt.avail(), 200);
        assert_eq!(pkt.num_segs(), 1);
    }

    // Verify that a segment's bytes can be read in the CanRead state.
    #[test]
    fn read_seg() {
        let buf1 = vec![0x1, 0x2, 0x3, 0x4];
        let buf2 = vec![0x5, 0x6];
        let mp1 = mock_desballoc(buf1);
        let mp2 = mock_desballoc(buf2);

        unsafe {
            (*mp1).b_cont = mp2;
        }

        let pkt = unsafe { Packet::wrap_mblk(mp1).unwrap() };
        assert_eq!(pkt.len(), 6);
        assert_eq!(pkt.num_segs(), 2);
        assert_eq!(pkt.seg_bytes(0), &[0x1, 0x2, 0x3, 0x4]);
        assert_eq!(pkt.seg_bytes(1), &[0x5, 0x6]);
    }

    #[test]
    fn wrap() {
        let mut buf1 = Vec::with_capacity(20);
        let mut buf2 = Vec::with_capacity(2);
        buf1.extend_from_slice(&[0x1, 0x2, 0x3, 0x4]);
        buf2.extend_from_slice(&[0x5, 0x6]);
        let mp1 = mock_desballoc(buf1);
        let mp2 = mock_desballoc(buf2);

        unsafe {
            (*mp1).b_cont = mp2;
        }

        let pkt = unsafe { Packet::wrap_mblk(mp1).unwrap() };
        assert_eq!(pkt.num_segs(), 2);
        assert_eq!(pkt.avail(), 22);
        assert_eq!(pkt.len(), 6);
    }

    #[test]
    fn read_single_segment() {
        let parsed = tcp_pkt().parse(Out, GenericUlp {}).unwrap();
        assert_eq!(parsed.state.hdr_offsets.inner.ether.seg_idx, 0);
        assert_eq!(parsed.state.hdr_offsets.inner.ether.seg_pos, 0);

        let eth_meta = parsed.state.meta.inner.ether;
        assert_eq!(eth_meta.ether_type, EtherType::Ipv4);
        assert_eq!(eth_meta.dst, DST_MAC);
        assert_eq!(eth_meta.src, SRC_MAC);

        let offsets = &parsed.state.hdr_offsets;

        let ip4_meta = match parsed.state.meta.inner.ip.as_ref().unwrap() {
            IpMeta::Ip4(v) => v,
            _ => panic!("expected IPv4"),
        };
        assert_eq!(ip4_meta.src, SRC_IP4.into());
        assert_eq!(ip4_meta.dst, DST_IP4.into());
        assert_eq!(ip4_meta.proto, Protocol::TCP);
        assert_eq!(offsets.inner.ip.as_ref().unwrap().seg_idx, 0);
        assert_eq!(offsets.inner.ip.as_ref().unwrap().seg_pos, 14);

        let tcp_meta = match parsed.state.meta.inner.ulp.as_ref().unwrap() {
            UlpMeta::Tcp(v) => v,
            _ => panic!("expected TCP"),
        };
        assert_eq!(tcp_meta.src, 3839);
        assert_eq!(tcp_meta.dst, 80);
        assert_eq!(tcp_meta.flags, TcpFlags::SYN);
        assert_eq!(tcp_meta.seq, 4224936861);
        assert_eq!(tcp_meta.ack, 0);
        assert_eq!(offsets.inner.ulp.as_ref().unwrap().seg_idx, 0);
        assert_eq!(offsets.inner.ulp.as_ref().unwrap().seg_pos, 34);
    }

    #[test]
    fn write_and_read_multi_segment() {
        let mp1 = allocb(34);
        let mp2 = allocb(20);

        unsafe {
            (*mp1).b_cont = mp2;
        }

        let mut seg1 = unsafe { PacketSeg::wrap_mblk(mp1) };
        let mut seg2 = unsafe { PacketSeg::wrap_mblk(mp2) };

        let tcp = TcpMeta {
            src: 3839,
            dst: 80,
            flags: TcpFlags::SYN,
            seq: 4224936861,
            ..Default::default()
        };
        let ip4 = Ipv4Meta {
            src: SRC_IP4,
            dst: DST_IP4,
            proto: Protocol::TCP,
            total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len()) as u16,
            ..Default::default()
        };
        let eth = EtherMeta {
            ether_type: EtherType::Ipv4,
            src: SRC_MAC,
            dst: DST_MAC,
        };
        seg1.expand_end(34).unwrap();
        let mut wtr1 = seg1.get_writer();
        eth.emit(wtr1.slice_mut(EtherHdr::SIZE).unwrap());
        ip4.emit(wtr1.slice_mut(ip4.hdr_len()).unwrap());

        seg2.expand_end(20).unwrap();
        let mut wtr2 = seg2.get_writer();
        tcp.emit(wtr2.slice_mut(tcp.hdr_len()).unwrap());
        let pkt = Packet::new2(seg1, seg2);
        let parsed = pkt.parse(Out, GenericUlp {}).unwrap();

        let eth_parsed = parsed.state.meta.inner.ether;
        assert_eq!(parsed.state.hdr_offsets.inner.ether.seg_idx, 0);
        assert_eq!(parsed.state.hdr_offsets.inner.ether.seg_pos, 0);
        assert_eq!(eth_parsed.ether_type, EtherType::Ipv4);
        assert_eq!(eth_parsed.dst, DST_MAC);
        assert_eq!(eth_parsed.src, SRC_MAC);

        let offsets = &parsed.state.hdr_offsets;

        let ip4_parsed = match parsed.state.meta.inner.ip.unwrap() {
            IpMeta::Ip4(v) => v,
            _ => panic!("expected IPv4"),
        };
        assert_eq!(ip4_parsed.src, SRC_IP4.into());
        assert_eq!(ip4_parsed.dst, DST_IP4.into());
        assert_eq!(ip4_parsed.proto, Protocol::TCP);
        assert_eq!(offsets.inner.ip.as_ref().unwrap().seg_idx, 0);
        assert_eq!(offsets.inner.ip.as_ref().unwrap().seg_pos, 14);

        let tcp_parsed = match parsed.state.meta.inner.ulp.unwrap() {
            UlpMeta::Tcp(v) => v,
            _ => panic!("expected TCP"),
        };
        assert_eq!(tcp_parsed.src, 3839);
        assert_eq!(tcp_parsed.dst, 80);
        assert_eq!(tcp_parsed.flags, TcpFlags::SYN);
        assert_eq!(tcp_parsed.seq, 4224936861);
        assert_eq!(tcp_parsed.ack, 0);
        assert_eq!(offsets.inner.ulp.as_ref().unwrap().seg_idx, 1);
        assert_eq!(offsets.inner.ulp.as_ref().unwrap().seg_pos, 0);
    }

    // Verify that we catch when a read requires more bytes than are
    // available.
    #[test]
    fn not_enough_bytes_read() {
        let eth = EtherMeta {
            ether_type: EtherType::Ipv4,
            src: SRC_MAC,
            dst: DST_MAC,
        };

        let mut seg = PacketSeg::alloc(34);
        seg.expand_end(24).unwrap();
        let mut wtr = seg.get_writer();
        eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
        // The actual bytes do not matter for this test.
        let ip4_partial = [0xA; 10];
        wtr.write(&ip4_partial).unwrap();
        let pkt = Packet::new(seg);
        assert_eq!(pkt.num_segs(), 1);
        assert_eq!(pkt.len(), 24);
        assert_eq!(pkt.avail(), 34);
        let mut rdr = pkt.get_rdr();
        let _ = rdr.slice(EtherHdr::SIZE);
        assert!(matches!(
            rdr.slice(Ipv4Hdr::BASE_SIZE),
            Err(ReadErr::NotEnoughBytes)
        ));
    }

    #[test]
    #[should_panic]
    fn slice_unchecked_bad_offset() {
        let parsed = tcp_pkt().parse(Out, GenericUlp {}).unwrap();
        // Offset past end of segment.
        parsed.segs[0].slice_unchecked(99, None);
    }

    #[test]
    #[should_panic]
    fn slice_mut_unchecked_bad_offset() {
        let mut parsed = tcp_pkt().parse(Out, GenericUlp {}).unwrap();
        // Offset past end of segment.
        parsed.segs[0].slice_mut_unchecked(99, None);
    }

    #[test]
    #[should_panic]
    fn slice_unchecked_bad_len() {
        let parsed = tcp_pkt().parse(Out, GenericUlp {}).unwrap();
        // Length past end of segment.
        parsed.segs[0].slice_unchecked(0, Some(99));
    }

    #[test]
    #[should_panic]
    fn slice_mut_unchecked_bad_len() {
        let mut parsed = tcp_pkt().parse(Out, GenericUlp {}).unwrap();
        // Length past end of segment.
        parsed.segs[0].slice_mut_unchecked(0, Some(99));
    }

    #[test]
    fn slice_unchecked_zero() {
        let parsed = tcp_pkt().parse(Out, GenericUlp {}).unwrap();
        // Set offset to end of packet and slice the "rest" by
        // passing None.
        assert_eq!(parsed.segs[0].slice_unchecked(54, None).len(), 0);
    }

    #[test]
    fn slice_mut_unchecked_zero() {
        let mut parsed = tcp_pkt().parse(Out, GenericUlp {}).unwrap();
        // Set offset to end of packet and slice the "rest" by
        // passing None.
        assert_eq!(parsed.segs[0].slice_mut_unchecked(54, None).len(), 0);
    }

    // Verify that if the TCP header straddles an mblk we return an
    // error.
    #[test]
    fn straddled_tcp() {
        let mp1 = allocb(46);
        let mp2 = allocb(8);

        unsafe {
            (*mp1).b_cont = mp2;
        }

        let mut seg1 = unsafe { PacketSeg::wrap_mblk(mp1) };
        let mut seg2 = unsafe { PacketSeg::wrap_mblk(mp2) };

        let tcp = TcpMeta { src: 3839, dst: 80, ..Default::default() };
        let ip4 = Ipv4Meta {
            src: SRC_IP4,
            dst: DST_IP4,
            proto: Protocol::TCP,
            total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len()) as u16,
            ..Default::default()
        };
        let eth = EtherMeta {
            ether_type: EtherType::Ipv4,
            src: SRC_MAC,
            dst: DST_MAC,
        };
        seg1.expand_end(46).unwrap();
        let mut wtr1 = seg1.get_writer();
        eth.emit(wtr1.slice_mut(EtherHdr::SIZE).unwrap());
        ip4.emit(wtr1.slice_mut(ip4.hdr_len()).unwrap());
        let mut tcp_bytes = vec![0u8; tcp.hdr_len()];
        tcp.emit(&mut tcp_bytes);
        wtr1.write(&tcp_bytes[0..12]).unwrap();

        seg2.expand_end(8).unwrap();
        let mut wtr2 = seg2.get_writer();
        wtr2.write(&tcp_bytes[12..]).unwrap();
        let pkt = Packet::new2(seg1, seg2);
        assert_eq!(pkt.num_segs(), 2);
        assert_eq!(
            pkt.len(),
            EtherHdr::SIZE + Ipv4Hdr::BASE_SIZE + TcpHdr::BASE_SIZE
        );
        assert!(matches!(
            pkt.parse(Out, GenericUlp {}),
            Err(ParseError::BadHeader(_))
        ));
    }

    // Verify that we correctly parse an IPv6 packet with extension headers
    #[test]
    fn parse_ipv6_extension_headers_ok() {
        use crate::engine::ip6::test::generate_test_packet;
        use crate::engine::ip6::test::SUPPORTED_EXTENSIONS;
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
                let ext_hdrs = &buf[Ipv6Hdr::BASE_SIZE..ipv6_header_size];

                // Append a TCP header
                let tcp = TcpMeta {
                    src: 3839,
                    dst: 80,
                    seq: 4224936861,
                    ..Default::default()
                };
                let mut ext_bytes = [0; 64];
                let ext_len = ext_hdrs.len();
                assert!(ext_len <= 64);
                ext_bytes[0..ext_len].copy_from_slice(ext_hdrs);

                let pay_len = tcp.hdr_len() + ext_len;
                let ip6 = Ipv6Meta {
                    src: Ipv6Addr::from(SRC_IP6),
                    dst: DST_IP6,
                    proto: Protocol::TCP,
                    next_hdr: next_hdr,
                    hop_limit: 255,
                    pay_len: pay_len as u16,
                    ext: Some(ext_bytes),
                    ext_len: ext_len,
                };
                let eth = EtherMeta {
                    ether_type: EtherType::Ipv6,
                    src: SRC_MAC,
                    dst: DST_MAC,
                };

                let mut seg = PacketSeg::alloc(1024);
                seg.expand_end(14 + ipv6_header_size + tcp.hdr_len()).unwrap();
                let mut wtr = seg.get_writer();
                eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
                ip6.emit(wtr.slice_mut(ip6.hdr_len()).unwrap());
                tcp.emit(wtr.slice_mut(tcp.hdr_len()).unwrap());
                let parsed =
                    Packet::new(seg).parse(Out, GenericUlp {}).unwrap();

                // Assert that the computed offsets of the headers and payloads
                // are accurate
                let offsets = &parsed.state.hdr_offsets;
                let ip = offsets
                    .inner
                    .ip
                    .as_ref()
                    .expect("Expected IP header offsets");
                assert_eq!(
                    ip.seg_idx, 0,
                    "Expected IP headers to be in segment 0"
                );
                assert_eq!(
                    ip.seg_pos,
                    EtherHdr::SIZE,
                    "Expected the IP header to start immediately \
                    after the Ethernet header"
                );
                assert_eq!(
                    ip.pkt_pos,
                    EtherHdr::SIZE,
                    "Expected the IP header to start immediately \
                    after the Ethernet header"
                );
                let ulp = &offsets
                    .inner
                    .ulp
                    .as_ref()
                    .expect("Expected ULP header offsets");
                assert_eq!(
                    ulp.seg_idx, 0,
                    "Expected the ULP header to be in segment 0"
                );
                assert_eq!(
                    ulp.seg_pos,
                    EtherHdr::SIZE + ipv6_header_size,
                    "Expected the ULP header to start immediately \
                    after the IP header",
                );
                assert_eq!(
                    ulp.pkt_pos,
                    EtherHdr::SIZE + ipv6_header_size,
                    "Expected the ULP header to start immediately \
                    after the IP header",
                );
            }
        }
    }

    #[test]
    fn seg_writer() {
        let mut seg = PacketSeg::alloc(18);
        seg.expand_end(18).unwrap();

        // Verify that an offset past the end results in error.
        assert!(matches!(
            PacketSegWriter::new(&mut seg, 20, 20),
            Err(ModifierCreateError::StartOutOfRange),
        ));

        // Verify that a length past the end results in error.
        assert!(matches!(
            PacketSegWriter::new(&mut seg, 0, 20),
            Err(ModifierCreateError::EndOutOfRange),
        ));

        // Writer for entire segment.
        let wtr = PacketSegWriter::new(&mut seg, 0, 18).unwrap();
        assert_eq!(wtr.pos, 0);
        assert_eq!(wtr.avail, 18);

        // Writer for last 4 bytes of segment.
        let wtr = PacketSegWriter::new(&mut seg, 14, 4).unwrap();
        assert_eq!(wtr.pos, 0);
        assert_eq!(wtr.avail, 4);
    }

    #[test]
    fn expand_and_shrink() {
        let mut seg = PacketSeg::alloc(18);
        assert_eq!(seg.len(), 0);
        seg.expand_end(18).unwrap();
        assert_eq!(seg.len(), 18);
        seg.shrink_start(4).unwrap();
        assert_eq!(seg.len(), 14);
        seg.expand_start(4).unwrap();
        assert_eq!(seg.len(), 18);
        assert!(matches!(seg.expand_end(20), Err(_)));
        assert!(matches!(seg.shrink_start(20), Err(_)));
        assert!(matches!(seg.expand_start(4), Err(_)));
    }

    #[test]
    fn prefix_len() {
        let mut seg = PacketSeg::alloc(18);
        assert_eq!(seg.prefix_len(), 0);
        seg.expand_end(18).unwrap();
        assert_eq!(seg.prefix_len(), 0);
        seg.shrink_start(4).unwrap();
        assert_eq!(seg.prefix_len(), 4);
        seg.expand_start(4).unwrap();
        assert_eq!(seg.prefix_len(), 0);
    }

    // Verify that we do not panic when we get long chains of mblks linked by
    // `b_cont`. This is a regression test for
    // https://github.com/oxidecomputer/opte/issues/335
    #[test]
    fn test_long_packet_continuation() {
        const N_SEGMENTS: usize = 8;
        let mut blocks: Vec<*mut mblk_t> = Vec::with_capacity(N_SEGMENTS);
        for i in 0..N_SEGMENTS {
            let mp = allocb(32);

            // Link previous block to this one.
            if i > 0 {
                let mut prev = blocks[i - 1];
                unsafe {
                    (*prev).b_cont = mp;
                }
            }
            blocks.push(mp);
        }

        // Wrap the first mblk in a Packet, and check that we still have a
        // reference to everything.
        let packet = unsafe { Packet::wrap_mblk(blocks[0]) }
            .expect("Failed to wrap mblk chain with many segments");

        assert_eq!(packet.segs.len(), N_SEGMENTS);
        assert_eq!(packet.segs.len(), blocks.len());
        for (seg, mblk) in packet.segs.iter().zip(blocks) {
            assert_eq!(seg.mp, mblk);
        }
    }
}

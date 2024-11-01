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

use super::checksum::Checksum;
use super::ether::Ethernet;
use super::ether::EthernetPacket;
use super::ether::ValidEthernet;
use super::headers::EncapMeta;
use super::headers::EncapPush;
use super::headers::IpAddr;
use super::headers::IpPush;
use super::headers::SizeHoldingEncap;
use super::headers::ValidEncapMeta;
use super::headers::AF_INET;
use super::headers::AF_INET6;
use super::ip::v4::Ipv4Addr;
use super::ip::v4::Ipv4Packet;
use super::ip::v4::Ipv4Ref;
use super::ip::v4::Protocol;
use super::ip::v6::Ipv6Addr;
use super::ip::v6::Ipv6Packet;
use super::ip::v6::Ipv6Ref;
use super::ip::L3Repr;
use super::ip::L3;
use super::parse::NoEncap;
use super::parse::Ulp;
use super::parse::UlpRepr;
use super::rule::CompiledEncap;
use super::rule::CompiledTransform;
use super::rule::HdrTransform;
use super::rule::HdrTransformError;
use super::Direction;
use super::LightweightMeta;
use super::NetworkParser;
use crate::d_error::DError;
use crate::ddi::mblk::MsgBlk;
use crate::ddi::mblk::MsgBlkIterMut;
use crate::ddi::mblk::MsgBlkNode;
use crate::engine::geneve::valid_geneve_has_oxide_external;
use crate::engine::geneve::GeneveMeta;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::Cell;
use core::ffi::CStr;
use core::fmt;
use core::fmt::Display;
use core::hash::Hash;
use core::result;
use core::sync::atomic::AtomicPtr;
use crc32fast::Hasher;
use dyn_clone::DynClone;
use illumos_sys_hdrs::uintptr_t;
use ingot::geneve::GeneveRef;
use ingot::icmp::IcmpV4Mut;
use ingot::icmp::IcmpV4Packet;
use ingot::icmp::IcmpV4Ref;
use ingot::icmp::IcmpV6Mut;
use ingot::icmp::IcmpV6Packet;
use ingot::icmp::IcmpV6Ref;
use ingot::tcp::TcpMut;
use ingot::tcp::TcpPacket;
use ingot::tcp::TcpRef;
use ingot::types::BoxedHeader;
use ingot::types::Emit;
use ingot::types::Header;
use ingot::types::HeaderLen;
use ingot::types::InlineHeader;
use ingot::types::IntoBufPointer;
use ingot::types::NextLayer;
use ingot::types::PacketParseError;
use ingot::types::Parsed as IngotParsed;
use ingot::types::Read;
use ingot::types::ToOwnedPacket;
use ingot::udp::UdpMut;
use ingot::udp::UdpPacket;
use ingot::udp::UdpRef;
use opte_api::Vni;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::ByteSlice;
use zerocopy::ByteSliceMut;
use zerocopy::IntoBytes;

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
pub trait BodyTransform: fmt::Display + DynClone + Send + Sync {
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
        // Allow due to possibility of future options.
        #[allow(clippy::single_match)]
        match self {
            ParseError::UnrecognisedTunnelOpt { class, ty } => {
                [data[0], data[1]] = [*class as u64, *ty as u64];
            }
            _ => {}
        }
    }
}

impl DError for PacketParseError {
    #[inline]
    fn discriminant(&self) -> &'static core::ffi::CStr {
        self.header().as_cstr()
    }

    #[inline]
    fn child(&self) -> Option<&dyn DError> {
        Some(self.error())
    }
}

impl DError for ingot::types::ParseError {
    #[inline]
    fn discriminant(&self) -> &'static core::ffi::CStr {
        self.as_cstr()
    }

    #[inline]
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

/// The initial parsed length of every header in a packet.
///
/// Used to track structural changes to any packet headers
/// which would require full serialisation of a header and
/// its prior layers.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct InitialLayerLens {
    pub outer_eth: usize,
    pub outer_l3: usize,
    pub outer_encap: usize,

    pub inner_eth: usize,
    pub inner_l3: usize,
    pub inner_ulp: usize,
}

impl InitialLayerLens {
    #[inline]
    pub fn hdr_len(&self) -> usize {
        self.outer_eth
            + self.outer_l3
            + self.outer_encap
            + self.inner_eth
            + self.inner_l3
            + self.inner_ulp
    }
}

/// Full metadata representation for a packet entering the standard ULP
/// path, or a full table walk over the slowpath.
pub struct OpteMeta<T: ByteSlice> {
    pub outer_eth: Option<InlineHeader<Ethernet, ValidEthernet<T>>>,
    pub outer_l3: Option<L3<T>>,
    pub outer_encap: Option<InlineHeader<EncapMeta, ValidEncapMeta<T>>>,

    pub inner_eth: EthernetPacket<T>,
    pub inner_l3: Option<L3<T>>,
    pub inner_ulp: Option<Ulp<T>>,
}

/// Helper for reusing access to all packet body segments.
///
/// This is necessary because `MsgBlk`s in particular do not
/// allow us to walk backward within a packet -- if we need them,
/// then we need to save them out for all future uses.
/// The other part is that the majority of packets (ULP hits)
/// do not want to interact with body segments at all.
struct PktBodyWalker<T: Read> {
    base: Cell<Option<(Option<T::Chunk>, T)>>,
    slice: AtomicPtr<Vec<(*mut u8, usize)>>,
}

impl<T: Read> Drop for PktBodyWalker<T> {
    fn drop(&mut self) {
        let ptr = self.slice.load(core::sync::atomic::Ordering::Relaxed);
        if !ptr.is_null() {
            // Reacquire and drop.
            unsafe {
                let _ = Box::from_raw(ptr);
            }
        }
    }
}

impl<'a, T: Read + 'a> PktBodyWalker<T>
where
    <T as Read>::Chunk: ByteSliceMut + IntoBufPointer<'a>,
{
    fn reify_body_segs(&self) {
        if let Some((first, mut rest)) = self.base.take() {
            // SAFETY: ByteSlice requires as part of its API
            // that any implementors are stable, so we will always
            // get the same view via deref. We are then consuming them
            // into references which live exactly as long as their initial
            // form.
            //
            // IntoBufPointer guarantees that what we are working with are,
            // in actual fact, slices (or, at least, that any necessary behaviour
            // on owned conversion into a slice [Drop, etc.] occurs).
            //
            // The next question is one of ownership.
            // We know that these chunks are at least &[u8]s, they
            // *will* be exclusive if ByteSliceMut is met (because they are
            // sourced from an exclusive borrow on something which owns a [u8]).
            // This allows us to cast to &mut later, but not here!
            let mut to_hold = Vec::with_capacity(1);
            if let Some(chunk) = first {
                let len = chunk.len();
                let ptr = unsafe { chunk.into_buf_ptr() };
                to_hold.push((ptr, len));
            }

            while let Ok(chunk) = rest.next_chunk() {
                let len = chunk.len();
                let ptr = unsafe { chunk.into_buf_ptr() };
                to_hold.push((ptr, len));
            }

            let to_store = Box::into_raw(Box::new(to_hold));

            self.slice
                .compare_exchange(
                    core::ptr::null_mut(),
                    to_store,
                    core::sync::atomic::Ordering::Relaxed,
                    core::sync::atomic::Ordering::Relaxed,
                )
                .expect("unexpected concurrent access to body_seg memoiser");

            // While today the only T we're operating on are IterMuts bound
            // to the lifetime of an actual packet (via &mut), there's a chance
            // in future that dropping the iterator could invalidate the byte
            // slices we're holding onto. Hang onto `rest` to prevent this.
            self.base.set(Some((None, rest)));
        }
    }

    fn body_segs(&self) -> &[&[u8]] {
        let mut slice_ptr =
            self.slice.load(core::sync::atomic::Ordering::Relaxed);
        if slice_ptr.is_null() {
            self.reify_body_segs();
            slice_ptr = self.slice.load(core::sync::atomic::Ordering::Relaxed);
        }
        debug_assert!(!slice_ptr.is_null());

        unsafe {
            let a = (&*(*slice_ptr)) as *const _;
            &*(a as *const [&[u8]])
        }
    }

    fn body_segs_mut(&mut self) -> &mut [&mut [u8]] {
        let mut slice_ptr =
            self.slice.load(core::sync::atomic::Ordering::Relaxed);
        if slice_ptr.is_null() {
            self.reify_body_segs();
            slice_ptr = self.slice.load(core::sync::atomic::Ordering::Relaxed);
        }
        debug_assert!(!slice_ptr.is_null());

        // SAFETY: We have an exclusive reference, and the ByteSliceMut
        // bound guarantees that this packet view was construced from
        // an exclusive reference. In turn, we know that we are the only
        // possible referent.
        unsafe {
            let a = (&mut *(*slice_ptr)) as *mut _;
            &mut *(a as *mut [&mut [u8]])
        }
    }
}

/// Packet state for the standard ULP path, or a full table walk over the slowpath.
pub struct PacketData<T: Read> {
    pub(crate) headers: OpteMeta<T::Chunk>,
    initial_lens: Option<Box<InitialLayerLens>>,
    body: PktBodyWalker<T>,
}

impl<T: ByteSlice> From<NoEncap<T>> for OpteMeta<T> {
    #[inline]
    fn from(value: NoEncap<T>) -> Self {
        OpteMeta {
            outer_eth: None,
            outer_l3: None,
            outer_encap: None,
            inner_eth: value.inner_eth,
            inner_l3: value.inner_l3,
            inner_ulp: value.inner_ulp,
        }
    }
}

impl<T: Read> core::fmt::Debug for PacketData<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PacketHeaders(..)")
    }
}

impl<'a, T: Read + 'a> PacketData<T> {
    pub fn initial_lens(&self) -> Option<&InitialLayerLens> {
        self.initial_lens.as_deref()
    }

    pub fn outer_ether(
        &self,
    ) -> Option<&InlineHeader<Ethernet, ValidEthernet<T::Chunk>>> {
        self.headers.outer_eth.as_ref()
    }

    pub fn outer_ip(&self) -> Option<&L3<T::Chunk>> {
        self.headers.outer_l3.as_ref()
    }

    /// Returns whether this packet is sourced from outside the rack,
    /// in addition to its VNI.
    pub fn outer_encap_geneve_vni_and_origin(&self) -> Option<(Vni, bool)> {
        match &self.headers.outer_encap {
            Some(InlineHeader::Repr(EncapMeta::Geneve(g))) => {
                Some((g.vni, g.oxide_external_pkt))
            }
            Some(InlineHeader::Raw(ValidEncapMeta::Geneve(_, g))) => {
                Some((g.vni(), valid_geneve_has_oxide_external(g)))
            }
            None => None,
        }
    }

    pub fn inner_ether(&self) -> &EthernetPacket<T::Chunk> {
        &self.headers.inner_eth
    }

    pub fn inner_l3(&self) -> Option<&L3<T::Chunk>> {
        self.headers.inner_l3.as_ref()
    }

    pub fn inner_ulp(&self) -> Option<&Ulp<T::Chunk>> {
        self.headers.inner_ulp.as_ref()
    }

    pub fn inner_ip4(&self) -> Option<&Ipv4Packet<T::Chunk>> {
        self.inner_l3().and_then(|v| match v {
            L3::Ipv4(v) => Some(v),
            _ => None,
        })
    }

    pub fn inner_ip6(&self) -> Option<&Ipv6Packet<T::Chunk>> {
        self.inner_l3().and_then(|v| match v {
            L3::Ipv6(v) => Some(v),
            _ => None,
        })
    }

    pub fn inner_icmp(&self) -> Option<&IcmpV4Packet<T::Chunk>> {
        self.inner_ulp().and_then(|v| match v {
            Ulp::IcmpV4(v) => Some(v),
            _ => None,
        })
    }

    pub fn inner_icmp6(&self) -> Option<&IcmpV6Packet<T::Chunk>> {
        self.inner_ulp().and_then(|v| match v {
            Ulp::IcmpV6(v) => Some(v),
            _ => None,
        })
    }

    pub fn inner_tcp(&self) -> Option<&TcpPacket<T::Chunk>> {
        self.inner_ulp().and_then(|v| match v {
            Ulp::Tcp(v) => Some(v),
            _ => None,
        })
    }

    pub fn inner_udp(&self) -> Option<&UdpPacket<T::Chunk>> {
        self.inner_ulp().and_then(|v| match v {
            Ulp::Udp(v) => Some(v),
            _ => None,
        })
    }

    pub fn is_inner_tcp(&self) -> bool {
        matches!(self.inner_ulp(), Some(Ulp::Tcp(_)))
    }

    pub fn body_segs(&self) -> &[&[u8]]
    where
        T::Chunk: ByteSliceMut + IntoBufPointer<'a>,
    {
        self.body.body_segs()
    }

    pub fn copy_remaining(&self) -> Vec<u8>
    where
        T::Chunk: ByteSliceMut + IntoBufPointer<'a>,
    {
        let base = self.body_segs();
        let len = base.iter().map(|v| v.len()).sum();
        let mut out = Vec::with_capacity(len);
        for el in base {
            out.extend_from_slice(el);
        }
        out
    }

    pub fn append_remaining(&self, buf: &mut Vec<u8>)
    where
        T::Chunk: ByteSliceMut + IntoBufPointer<'a>,
    {
        let base = self.body_segs();
        let len = base.iter().map(|v| v.len()).sum();
        buf.reserve_exact(len);
        for el in base {
            buf.extend_from_slice(el);
        }
    }

    pub fn body_segs_mut(&mut self) -> &mut [&mut [u8]]
    where
        T::Chunk: ByteSliceMut + IntoBufPointer<'a>,
    {
        self.body.body_segs_mut()
    }

    /// Return whether the IP layer has a checksum both structurally
    /// and that it is non-zero (i.e., not offloaded).
    pub fn has_ip_csum(&self) -> bool {
        match &self.headers.inner_l3 {
            Some(L3::Ipv4(v4)) => v4.checksum() != 0,
            Some(L3::Ipv6(_)) => false,
            None => false,
        }
    }

    /// Return whether the ULP layer has a checksum both structurally
    /// and that it is non-zero (i.e., not offloaded).
    pub fn has_ulp_csum(&self) -> bool {
        let csum = match &self.headers.inner_ulp {
            Some(Ulp::Tcp(t)) => t.checksum(),
            Some(Ulp::Udp(u)) => u.checksum(),
            Some(Ulp::IcmpV4(i4)) => i4.checksum(),
            Some(Ulp::IcmpV6(i6)) => i6.checksum(),
            None => return false,
        };

        csum != 0
    }
}

impl<T: Read> From<&PacketData<T>> for InnerFlowId {
    #[inline]
    fn from(meta: &PacketData<T>) -> Self {
        let (proto, addrs) = match meta.inner_l3() {
            Some(L3::Ipv4(pkt)) => (
                pkt.protocol().0,
                AddrPair::V4 { src: pkt.source(), dst: pkt.destination() },
            ),
            Some(L3::Ipv6(pkt)) => (
                pkt.next_layer().unwrap_or_default().0,
                AddrPair::V6 { src: pkt.source(), dst: pkt.destination() },
            ),
            None => (255, FLOW_ID_DEFAULT.addrs),
        };

        let (src_port, dst_port) = meta
            .inner_ulp()
            .map(|ulp| {
                (
                    ulp.true_src_port()
                        .or_else(|| ulp.pseudo_port())
                        .unwrap_or(0),
                    ulp.true_dst_port()
                        .or_else(|| ulp.pseudo_port())
                        .unwrap_or(0),
                )
            })
            .unwrap_or((0, 0));

        InnerFlowId { proto, addrs, src_port, dst_port }
    }
}

/// A network packet.
///
/// A packet is made up of one or more segments. Any given header is
/// *always* contained in a single segment, i.e. a  header never straddles
/// multiple segments. While it's preferable to have all headers in the
/// first segment, it *may* be the case that the headers span multiple
/// segments; but a *single* header type (e.g. the IP header) will *never*
/// straddle two segments. The payload, however, *may* span multiple segments.
///
/// # illumos terminology
///
/// In illumos there is no real notion of an mblk "packet" or
/// "segment": a packet is just a linked list of `mblk_t` values.
/// This type indicates that an `mblk_t` chain is to be treated as
/// a network packet, as far as its bytes are concerned.
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
/// kind of figure out as you work in the code more. In OPTE, we
/// disambiguate using the `MsgBlk` and `MsgBlkChain` types. The former
/// enforces that `b_next` and `b_prev` are disconnected.
// TODO: In theory, this can be any `Read` type giving us `&mut [u8]`s,
// but in practice we are internally reliant on returning `MsgBlk`s in
// hairpin actions and the like. Fighting the battle of making this generic
// is a bridge too far for the `ingot` datapath rewrite. This might have
// value in future.
#[derive(Debug)]
pub struct Packet<S: PacketState> {
    state: S,
}

pub type LiteInPkt<T, NP> =
    Packet<LiteParsed<T, <NP as NetworkParser>::InMeta<<T as Read>::Chunk>>>;
pub type LiteOutPkt<T, NP> =
    Packet<LiteParsed<T, <NP as NetworkParser>::OutMeta<<T as Read>::Chunk>>>;

impl<'a, T: Read + BufferState + 'a, M: LightweightMeta<T::Chunk>>
    Packet<LiteParsed<T, M>>
where
    T::Chunk: ByteSliceMut + IntoBufPointer<'a>,
{
    #[inline]
    pub fn parse_inbound<NP: NetworkParser<InMeta<T::Chunk> = M>>(
        pkt: T,
        net: NP,
    ) -> Result<LiteInPkt<T, NP>, ParseError> {
        let len = pkt.len();
        let base_ptr = pkt.base_ptr();

        let meta = net.parse_inbound(pkt)?;
        meta.stack.validate(len)?;

        Ok(Packet { state: LiteParsed { meta, base_ptr, len } })
    }

    #[inline]
    pub fn parse_outbound<NP: NetworkParser<OutMeta<T::Chunk> = M>>(
        pkt: T,
        net: NP,
    ) -> Result<LiteOutPkt<T, NP>, ParseError> {
        let len = pkt.len();
        let base_ptr = pkt.base_ptr();

        let meta = net.parse_outbound(pkt)?;
        meta.stack.validate(len)?;

        Ok(Packet { state: LiteParsed { meta, base_ptr, len } })
    }

    #[inline]
    pub fn to_full_meta(self) -> Packet<FullParsed<T>> {
        let Packet { state: LiteParsed { len, base_ptr, meta } } = self;
        let IngotParsed { stack: headers, data, last_chunk } = meta;

        // TODO: we can probably not do this in some cases, but we
        // don't have a way for `HeaderAction`s to signal that they
        // *may* change the fields we need in the slowpath.
        let body_csum = headers.compute_body_csum();
        let flow = headers.flow();

        let headers: OpteMeta<_> = headers.into();
        let initial_lens = Some(
            InitialLayerLens {
                outer_eth: headers.outer_eth.packet_length(),
                outer_l3: headers.outer_l3.packet_length(),
                outer_encap: headers.outer_encap.packet_length(),
                inner_eth: headers.inner_eth.packet_length(),
                inner_l3: headers.inner_l3.packet_length(),
                inner_ulp: headers.inner_ulp.packet_length(),
            }
            .into(),
        );
        let body = PktBodyWalker {
            base: Some((last_chunk, data)).into(),
            slice: Default::default(),
        };
        let meta = Box::new(PacketData { headers, initial_lens, body });

        Packet {
            state: FullParsed {
                meta,
                flow,
                body_csum,
                base_ptr,
                l4_hash: Memoised::Uninit,
                body_modified: false,
                len,
                inner_csum_dirty: false,
            },
        }
    }

    #[inline]
    pub fn meta(&self) -> &M {
        &self.state.meta.stack
    }

    #[inline]
    pub fn meta_mut(&mut self) -> &mut M {
        &mut self.state.meta.stack
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.state.len
    }

    #[inline]
    pub fn mblk_addr(&self) -> uintptr_t {
        self.state.base_ptr
    }

    #[inline]
    pub fn flow(&self) -> InnerFlowId {
        self.meta().flow()
    }
}

impl<'a, T: Read + 'a> Packet<FullParsed<T>> {
    pub fn meta(&self) -> &PacketData<T> {
        &self.state.meta
    }

    pub fn meta_mut(&mut self) -> &mut PacketData<T> {
        &mut self.state.meta
    }

    pub fn checksums_dirty(&self) -> bool {
        self.state.inner_csum_dirty
    }

    #[inline]
    /// Convert a packet's metadata into a set of instructions
    /// needed to serialize all its changes to the wire.
    pub fn emit_spec(&mut self) -> Result<EmitSpec, ingot::types::ParseError>
    where
        T::Chunk: ByteSliceMut,
    {
        // Roughly how this works:
        // - Identify rightmost structural-changed field.
        // - fill out owned versions into the push_spec of all
        //   present fields we rewound past.
        // - Rewind up to+including that point in original
        //   pkt space.
        let l4_hash = self.l4_hash();
        let state = &self.state;
        let init_lens = state.meta.initial_lens.as_ref().unwrap();
        let headers = &state.meta.headers;
        let payload_len = state.len - init_lens.hdr_len();
        let mut encapped_len = payload_len;

        let mut push_spec = OpteEmit::default();
        let mut rewind = 0;

        // structural change if:
        // hdr_len is different.
        // needs_emit is true (i.e., now on an owned repr).

        // Part of the initial design idea of ingot was the desire to automatically
        // do this sort of thing. We are so, so far from that...
        let mut force_serialize = false;

        match &headers.inner_ulp {
            Some(ulp) => {
                let l = ulp.packet_length();
                encapped_len += l;

                if ulp.needs_emit() || l != init_lens.inner_ulp {
                    let inner =
                        push_spec.inner.get_or_insert_with(Default::default);

                    inner.ulp = Some(match ulp {
                        Ulp::Tcp(Header::Repr(t)) => UlpRepr::Tcp(*t.clone()),
                        Ulp::Tcp(Header::Raw(t)) => UlpRepr::Tcp(t.into()),
                        Ulp::Udp(Header::Repr(t)) => UlpRepr::Udp(*t.clone()),
                        Ulp::Udp(Header::Raw(t)) => UlpRepr::Udp(t.into()),
                        Ulp::IcmpV4(Header::Repr(t)) => {
                            UlpRepr::IcmpV4(*t.clone())
                        }
                        Ulp::IcmpV4(Header::Raw(t)) => {
                            UlpRepr::IcmpV4(t.into())
                        }
                        Ulp::IcmpV6(Header::Repr(t)) => {
                            UlpRepr::IcmpV6(*t.clone())
                        }
                        Ulp::IcmpV6(Header::Raw(t)) => {
                            UlpRepr::IcmpV6(t.into())
                        }
                    });
                    force_serialize = true;
                    rewind += init_lens.inner_ulp;
                }
            }
            None if init_lens.inner_ulp != 0 => {
                force_serialize = true;
                rewind += init_lens.inner_ulp;
            }
            _ => {}
        }

        match &headers.inner_l3 {
            Some(l3) => {
                let l = l3.packet_length();
                encapped_len += l;

                if force_serialize || l3.needs_emit() || l != init_lens.inner_l3
                {
                    let inner =
                        push_spec.inner.get_or_insert_with(Default::default);

                    inner.l3 = Some(match l3 {
                        L3::Ipv4(Header::Repr(v4)) => L3Repr::Ipv4(*v4.clone()),
                        L3::Ipv4(Header::Raw(v4)) => L3Repr::Ipv4(v4.into()),
                        L3::Ipv6(Header::Repr(v6)) => L3Repr::Ipv6(*v6.clone()),

                        // We can't actually do structural mods here today using OPTE,
                        // but account for the possibility at least.
                        L3::Ipv6(Header::Raw(v6)) => {
                            L3Repr::Ipv6(v6.to_owned(None)?)
                        }
                    });
                    force_serialize = true;
                    rewind += init_lens.inner_l3;
                }
            }
            None if init_lens.inner_l3 != 0 => {
                force_serialize = true;
                rewind += init_lens.inner_l3;
            }
            _ => {}
        }

        // inner eth
        encapped_len += headers.inner_eth.packet_length();
        if force_serialize {
            let inner = push_spec.inner.get_or_insert_with(Default::default);
            inner.eth = match &headers.inner_eth {
                Header::Repr(p) => **p,
                Header::Raw(p) => p.into(),
            };
            rewind += init_lens.inner_eth;
        }

        match &headers.outer_encap {
            Some(encap)
                if force_serialize
                    || encap.needs_emit()
                    || encap.packet_length() != init_lens.outer_encap =>
            {
                push_spec.outer_encap = Some(match encap {
                    InlineHeader::Repr(o) => *o,
                    InlineHeader::Raw(ValidEncapMeta::Geneve(u, g)) => {
                        EncapMeta::Geneve(GeneveMeta {
                            entropy: u.source(),
                            vni: g.vni(),
                            oxide_external_pkt: valid_geneve_has_oxide_external(
                                g,
                            ),
                        })
                    }
                });

                force_serialize = true;
                rewind += init_lens.outer_encap;
            }
            None if init_lens.outer_encap != 0 => {
                force_serialize = true;
                rewind += init_lens.outer_encap;
            }
            _ => {}
        }

        match &headers.outer_l3 {
            Some(l3)
                if force_serialize
                    || l3.needs_emit()
                    || l3.packet_length() != init_lens.outer_l3 =>
            {
                let encap_len = push_spec.outer_encap.packet_length();

                push_spec.outer_ip = Some(match l3 {
                    L3::Ipv6(BoxedHeader::Repr(o)) => L3Repr::Ipv6(*o.clone()),
                    L3::Ipv4(BoxedHeader::Repr(o)) => L3Repr::Ipv4(*o.clone()),
                    L3::Ipv6(BoxedHeader::Raw(o)) => {
                        L3Repr::Ipv6(o.to_owned(None)?)
                    }
                    L3::Ipv4(BoxedHeader::Raw(o)) => L3Repr::Ipv4(o.into()),
                });

                let inner_sz = (encapped_len + encap_len) as u16;

                match &mut push_spec.outer_ip {
                    Some(L3Repr::Ipv4(v4)) => {
                        v4.total_len = (v4.ihl as u16) * 4 + inner_sz;
                    }
                    Some(L3Repr::Ipv6(v6)) => {
                        v6.payload_len = inner_sz;
                    }
                    _ => {}
                }

                force_serialize = true;
                rewind += init_lens.outer_l3;
            }
            None if init_lens.outer_l3 != 0 => {
                force_serialize = true;
                rewind += init_lens.outer_l3;
            }
            _ => {}
        }

        match &headers.outer_eth {
            Some(eth)
                if force_serialize
                    || eth.needs_emit()
                    || eth.packet_length() != init_lens.outer_eth =>
            {
                push_spec.outer_eth = Some(match eth {
                    InlineHeader::Repr(o) => *o,
                    InlineHeader::Raw(r) => r.into(),
                });

                rewind += init_lens.outer_eth;
            }
            None if init_lens.outer_eth != 0 => {
                rewind += init_lens.outer_eth;
            }
            _ => {}
        }

        Ok(EmitSpec {
            rewind: rewind as u16,
            ulp_len: encapped_len as u32,
            prepend: PushSpec::Slowpath(push_spec.into()),
            l4_hash,
        })
    }

    pub fn len(&self) -> usize {
        self.state.len
    }

    #[inline]
    pub fn flow(&self) -> &InnerFlowId {
        &self.state.flow
    }

    /// Run the [`HdrTransform`] against this packet.
    #[inline]
    pub fn hdr_transform(
        &mut self,
        xform: &HdrTransform,
    ) -> Result<(), HdrTransformError>
    where
        T::Chunk: ByteSliceMut,
    {
        self.state.inner_csum_dirty |= xform.run(&mut self.state.meta)?;

        // Recomputing this is a little bit wasteful, since we're moving
        // rebuilding a static repr from packet fields. This is a necessary
        // part of slowpath use because layers are designed around intermediate
        // flowkeys.
        //
        // We *could* elide this on non-compiled UFT transforms, but we do not
        // need those today.
        self.state.flow = InnerFlowId::from(self.meta());
        Ok(())
    }

    /// Run the [`BodyTransform`] against this packet.
    pub fn body_transform(
        &mut self,
        dir: Direction,
        xform: &dyn BodyTransform,
    ) -> Result<(), BodyTransformError>
    where
        T::Chunk: ByteSliceMut + IntoBufPointer<'a>,
    {
        // We set the flag now with the assumption that the transform
        // could fail after modifying part of the body. In the future
        // we could have something more sophisticated that only sets
        // the flag if at least one byte was modified, but for now
        // this does the job as nothing that needs top performance
        // should make use of body transformations.
        self.state.body_modified = true;

        match self.body_segs_mut() {
            Some(body_segs) => xform.run(dir, body_segs),
            None => {
                self.state.body_modified = false;
                Err(BodyTransformError::NoPayload)
            }
        }
    }

    #[inline]
    pub fn body_segs(&self) -> Option<&[&[u8]]>
    where
        T::Chunk: ByteSliceMut + IntoBufPointer<'a>,
    {
        let out = self.state.meta.body_segs();
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    #[inline]
    pub fn body_segs_mut(&mut self) -> Option<&mut [&mut [u8]]>
    where
        T::Chunk: ByteSliceMut + IntoBufPointer<'a>,
    {
        let out = self.state.meta.body_segs_mut();
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    #[inline]
    pub fn mblk_addr(&self) -> uintptr_t {
        self.state.base_ptr
    }

    /// Compute ULP and IP header checksum from scratch.
    ///
    /// This should really only be used for testing, or in the case
    /// where we have applied body transforms and know that any initial
    /// body_csum cannot be valid.
    pub fn compute_checksums(&mut self)
    where
        T::Chunk: ByteSliceMut + IntoBufPointer<'a>,
    {
        let mut body_csum = Checksum::new();
        for seg in self.body_segs_mut().unwrap_or_default() {
            body_csum.add_bytes(seg);
        }
        self.state.body_csum = Some(body_csum);

        if let Some(ulp) = &mut self.state.meta.headers.inner_ulp {
            let mut csum = body_csum;

            // Unwrap: Can't have a ULP without an IP.
            let ip = self.state.meta.headers.inner_l3.as_ref().unwrap();
            // Add pseudo header checksum.
            let pseudo_csum = ip.pseudo_header();
            csum += pseudo_csum;
            // Determine ULP slice and add its bytes to the
            // checksum.
            match ulp {
                // ICMP4 requires the body_csum *without*
                // the pseudoheader added back in.
                Ulp::IcmpV4(i4) => {
                    let mut bytes = [0u8; 8];
                    i4.set_checksum(0);
                    i4.emit_raw(&mut bytes[..]);
                    body_csum.add_bytes(&bytes[..]);
                    i4.set_checksum(body_csum.finalize_for_ingot());
                }
                Ulp::IcmpV6(i6) => {
                    let mut bytes = [0u8; 8];
                    i6.set_checksum(0);
                    i6.emit_raw(&mut bytes[..]);
                    csum.add_bytes(&bytes[..]);
                    i6.set_checksum(csum.finalize_for_ingot());
                }
                Ulp::Tcp(tcp) => {
                    tcp.set_checksum(0);
                    match tcp {
                        Header::Repr(tcp) => {
                            let mut bytes = [0u8; 56];
                            tcp.emit_raw(&mut bytes[..]);
                            csum.add_bytes(&bytes[..]);
                        }
                        Header::Raw(tcp) => {
                            csum.add_bytes(tcp.0.as_bytes());
                            match &tcp.1 {
                                Header::Repr(opts) => {
                                    csum.add_bytes(opts);
                                }
                                Header::Raw(opts) => {
                                    csum.add_bytes(opts);
                                }
                            }
                        }
                    }
                    tcp.set_checksum(csum.finalize_for_ingot());
                }
                Ulp::Udp(udp) => {
                    udp.set_checksum(0);
                    match udp {
                        Header::Repr(udp) => {
                            let mut bytes = [0u8; 8];
                            udp.emit_raw(&mut bytes[..]);
                            csum.add_bytes(&bytes[..]);
                        }
                        Header::Raw(udp) => {
                            csum.add_bytes(udp.0.as_bytes());
                        }
                    }
                    udp.set_checksum(csum.finalize_for_ingot());
                }
            }
        }

        // Compute and fill in the IPv4 header checksum.
        if let Some(l3) = self.state.meta.headers.inner_l3.as_mut() {
            l3.compute_checksum();
        }
    }

    pub fn body_csum(&mut self) -> Option<Checksum> {
        self.state.body_csum
    }

    pub fn l4_hash(&mut self) -> u32 {
        *self.state.l4_hash.get(|| {
            let mut hasher = crc32fast::Hasher::new();
            self.state.flow.hash(&mut hasher);
            hasher.finalize()
        })
    }

    pub fn set_l4_hash(&mut self, hash: u32) {
        self.state.l4_hash.set(hash);
    }

    /// Perform an incremental checksum update for the ULP checksums
    /// based on the stored body checksum.
    ///
    /// This avoids duplicating work already done by the client in the
    /// case where checksums are **not** being offloaded to the hardware.
    pub fn update_checksums(&mut self)
    where
        T::Chunk: ByteSliceMut + IntoBufPointer<'a>,
    {
        // If we know that no transform touched a field which features in
        // an inner transport cksum (L4/L3 src/dst, most realistically),
        // and no body transform occurred then we can exit early.
        if !self.checksums_dirty() && !self.state.body_modified {
            return;
        }

        // Flag to indicate if an IP header/ULP checksums were
        // provided. If the checksum is zero, it's assumed heardware
        // checksum offload is being used, and OPTE should not update
        // the checksum.
        let update_ip = self.state.meta.has_ip_csum();
        let update_ulp = self.state.meta.has_ulp_csum();

        // We expect that any body transform will necessarily invalidate
        // the body_csum. Recompute from scratch.
        if self.state.body_modified && (update_ip || update_ulp) {
            return self.compute_checksums();
        }

        // Start by reusing the known checksum of the body.
        let mut body_csum = self.body_csum().unwrap_or_default();

        // If a ULP exists, then compute and set its checksum.
        if let (true, Some(ulp)) =
            (update_ulp, &mut self.state.meta.headers.inner_ulp)
        {
            let mut csum = body_csum;
            // Unwrap: Can't have a ULP without an IP.
            let ip = self.state.meta.headers.inner_l3.as_ref().unwrap();
            // Add pseudo header checksum.
            let pseudo_csum = ip.pseudo_header();
            csum += pseudo_csum;
            // Determine ULP slice and add its bytes to the
            // checksum.
            match ulp {
                // ICMP4 requires the body_csum *without*
                // the pseudoheader added back in.
                Ulp::IcmpV4(i4) => {
                    let mut bytes = [0u8; 8];
                    i4.set_checksum(0);
                    i4.emit_raw(&mut bytes[..]);
                    body_csum.add_bytes(&bytes[..]);
                    i4.set_checksum(body_csum.finalize_for_ingot());
                }
                Ulp::IcmpV6(i6) => {
                    let mut bytes = [0u8; 8];
                    i6.set_checksum(0);
                    i6.emit_raw(&mut bytes[..]);
                    csum.add_bytes(&bytes[..]);
                    i6.set_checksum(csum.finalize_for_ingot());
                }
                Ulp::Tcp(tcp) => {
                    tcp.set_checksum(0);
                    match tcp {
                        Header::Repr(tcp) => {
                            let mut bytes = [0u8; 56];
                            tcp.emit_raw(&mut bytes[..]);
                            csum.add_bytes(&bytes[..]);
                        }
                        Header::Raw(tcp) => {
                            csum.add_bytes(tcp.0.as_bytes());
                            match &tcp.1 {
                                Header::Repr(opts) => {
                                    csum.add_bytes(opts);
                                }
                                Header::Raw(opts) => {
                                    csum.add_bytes(opts);
                                }
                            }
                        }
                    }
                    tcp.set_checksum(csum.finalize_for_ingot());
                }
                Ulp::Udp(udp) => {
                    udp.set_checksum(0);
                    match udp {
                        Header::Repr(udp) => {
                            let mut bytes = [0u8; 8];
                            udp.emit_raw(&mut bytes[..]);
                            csum.add_bytes(&bytes[..]);
                        }
                        Header::Raw(udp) => {
                            csum.add_bytes(udp.0.as_bytes());
                        }
                    }
                    udp.set_checksum(csum.finalize_for_ingot());
                }
            }
        }

        // Compute and fill in the IPv4 header checksum.
        if let (true, Some(l3)) =
            (update_ip, &mut self.state.meta.headers.inner_l3)
        {
            l3.compute_checksum();
        }
    }
}

impl<T: Read, M: LightweightMeta<T::Chunk>> PacketState for LiteParsed<T, M> {}
impl<T: Read> PacketState for FullParsed<T> {}

/// Zerocopy view onto a parsed packet, accompanied by locally
/// computed state.
pub struct FullParsed<T: Read> {
    /// Total length of packet, in bytes. This is equal to the sum of
    /// the length of the _initialized_ window in all the segments
    /// (`b_wptr - b_rptr`).
    len: usize,
    /// Base pointer of the contained T, used in dtrace SDTs and the like
    /// for correlation and inspection of packet events.
    base_ptr: uintptr_t,
    /// Access to parsed packet headers and the packet body.
    meta: Box<PacketData<T>>,
    /// Current Flow ID of this packet, accountgin for any applied
    /// transforms.
    flow: InnerFlowId,

    /// The body's checksum. It is up to the `NetworkImpl::Parser` on
    /// whether to populate this field or not. The reason for
    /// populating this field is to avoid duplicate work if the client
    /// has provided a ULP checksum. Rather than redoing the body
    /// checksum calculation, we can use incremental checksum
    /// techniques to stash the body's checksum for reuse when emitting
    /// the new headers.
    ///
    /// However, if the client does not provide a checksum, presumably
    /// because they are relying on checksum offload, this value should
    /// be `None`. In such case, `emit_headers()` will perform no ULP
    /// checksum update.
    ///
    /// This value may also be none if the packet has no notion of a
    /// ULP checksum; e.g., ARP.
    body_csum: Option<Checksum>,
    /// L4 hash for this packet, computed from the flow ID.
    l4_hash: Memoised<u32>,
    /// Tracks whether any body transforms have been executed on this
    /// packet.
    body_modified: bool,
    /// Tracks whether any transform has been applied to this packet
    /// which would dirty the inner L3 and/or ULP header checksums.
    inner_csum_dirty: bool,
}

/// Minimum-size zerocopy view onto a parsed packet, sufficient for fast
/// packet transformation.
pub struct LiteParsed<T: Read, M: LightweightMeta<T::Chunk>> {
    /// Total length of packet, in bytes. This is equal to the sum of
    /// the length of the _initialized_ window in all the segments
    /// (`b_wptr - b_rptr`).
    len: usize,
    /// Base pointer of the contained T, used in dtrace SDTs and the like
    /// for correlation and inspection of packet events.
    base_ptr: uintptr_t,
    meta: IngotParsed<M, T>,
}

impl<T: Read, M: LightweightMeta<T::Chunk>> LiteParsed<T, M> {}

// These are needed for now to account for not wanting to redesign
// ActionDescs to be generic over T (trait object safety rules, etc.),
// in addition to needing to rework Hairpin actions.
pub type MblkPacketData<'a> = PacketData<MsgBlkIterMut<'a>>;
pub type MblkFullParsed<'a> = FullParsed<MsgBlkIterMut<'a>>;
pub type MblkLiteParsed<'a, M> = LiteParsed<MsgBlkIterMut<'a>, M>;

pub trait BufferState {
    fn len(&self) -> usize;
    fn base_ptr(&self) -> uintptr_t;
}

/// A set of headers to be emitted at the head of a packet.
#[derive(Clone, Debug, Default)]
pub struct OpteEmit {
    outer_eth: Option<Ethernet>,
    outer_ip: Option<L3Repr>,
    outer_encap: Option<EncapMeta>,

    // We can (but do not often) push/pop inner meta.
    // Splitting via Box minimises struct size in the general case.
    inner: Option<Box<OpteInnerEmit>>,
}

/// Inner headers needing completely rewritten/emitted in a packet.
#[derive(Clone, Debug, Default)]
pub struct OpteInnerEmit {
    eth: Ethernet,
    l3: Option<L3Repr>,
    ulp: Option<UlpRepr>,
}

/// A specification of how a packet should be modified to finish processing,
/// after existing fields have been updated.
///
/// This will add and/or remove several layers from the underlying `MsgBlk`,
/// and can be queried for routing specific info (access to new encap, l4 hash).
#[derive(Clone, Debug)]
pub struct EmitSpec {
    pub(crate) prepend: PushSpec,
    pub(crate) l4_hash: u32,
    pub(crate) rewind: u16,
    pub(crate) ulp_len: u32,
}

impl Default for EmitSpec {
    fn default() -> Self {
        Self { prepend: PushSpec::NoOp, l4_hash: 0, rewind: 0, ulp_len: 0 }
    }
}

impl EmitSpec {
    /// Return the L4 hash of the inner flow, used for multipath selection.
    #[inline]
    #[must_use]
    pub fn l4_hash(&self) -> u32 {
        self.l4_hash
    }

    /// Perform final structural transformations to a packet (removal of
    /// existing headers, and copying in new/replacement headers).
    #[inline]
    #[must_use]
    pub fn apply(&self, mut pkt: MsgBlk) -> MsgBlk {
        // Rewind
        {
            let mut slots = heapless::Vec::<&mut MsgBlkNode, 6>::new();
            let mut to_rewind = self.rewind as usize;

            if to_rewind > 0 {
                let mut reader = pkt.iter_mut();
                while to_rewind != 0 {
                    let this = reader.next();
                    let Some(node) = this else {
                        break;
                    };

                    let has = node.len();
                    let droppable = to_rewind.min(has);
                    node.drop_front_bytes(droppable)
                        .expect("droppable should be bounded above by len");
                    to_rewind -= droppable;

                    slots.push(node).unwrap();
                }
            }
        }

        // TODO: actually push in to existing slots we rewound past if needed,
        // then run this step at the end.
        // This is not really an issue in practice -- no packets should need
        // to rewind *and* prepend new segments with how we're using OPTE today,
        // much less so in the fastpath.
        pkt.drop_empty_segments();

        let out = match &self.prepend {
            PushSpec::Fastpath(push_spec) => {
                push_spec.encap.prepend(pkt, self.ulp_len as usize)
            }
            PushSpec::Slowpath(push_spec) => {
                let mut needed_push = push_spec.outer_eth.packet_length()
                    + push_spec.outer_ip.packet_length()
                    + push_spec.outer_encap.packet_length();

                if let Some(inner_new) = &push_spec.inner {
                    needed_push += inner_new.eth.packet_length()
                        + inner_new.l3.packet_length()
                        + inner_new.ulp.packet_length();
                }

                let needed_alloc = needed_push;

                let mut prepend = if needed_alloc > 0 {
                    let mut new_mblk = MsgBlk::new_ethernet(needed_alloc);
                    new_mblk.pop_all();
                    Some(new_mblk)
                } else {
                    None
                };

                if let Some(inner_new) = &push_spec.inner {
                    if let Some(inner_ulp) = &inner_new.ulp {
                        let target = if let Some(v) = prepend.as_mut() {
                            v
                        } else {
                            &mut pkt
                        };

                        target.emit_front(inner_ulp).unwrap();
                    }

                    if let Some(inner_l3) = &inner_new.l3 {
                        let target = if let Some(v) = prepend.as_mut() {
                            v
                        } else {
                            &mut pkt
                        };

                        target.emit_front(inner_l3).unwrap();
                    }

                    let target = if let Some(v) = prepend.as_mut() {
                        v
                    } else {
                        &mut pkt
                    };

                    target.emit_front(inner_new.eth).unwrap();
                }

                if let Some(outer_encap) = &push_spec.outer_encap {
                    let encap = SizeHoldingEncap {
                        encapped_len: self.ulp_len as u16,
                        meta: outer_encap,
                    };

                    let target = if let Some(v) = prepend.as_mut() {
                        v
                    } else {
                        &mut pkt
                    };

                    target.emit_front(&encap).unwrap();
                }

                if let Some(outer_ip) = &push_spec.outer_ip {
                    let target = if let Some(v) = prepend.as_mut() {
                        v
                    } else {
                        &mut pkt
                    };

                    target.emit_front(outer_ip).unwrap();
                }

                if let Some(outer_eth) = &push_spec.outer_eth {
                    let target = if let Some(v) = prepend.as_mut() {
                        v
                    } else {
                        &mut pkt
                    };

                    target.emit_front(outer_eth).unwrap();
                }

                if let Some(mut prepend) = prepend {
                    prepend.append(pkt);
                    prepend
                } else {
                    pkt
                }
            }
            PushSpec::NoOp => pkt,
        };

        out
    }

    /// Returns the Geneve VNI when this spec pushes Geneve encapsulation.
    #[inline]
    pub fn outer_encap_vni(&self) -> Option<Vni> {
        match &self.prepend {
            PushSpec::Fastpath(c) => match &c.encap {
                CompiledEncap::Push { encap: EncapPush::Geneve(g), .. } => {
                    Some(g.vni)
                }
                _ => None,
            },
            PushSpec::Slowpath(s) => match &s.outer_encap {
                Some(EncapMeta::Geneve(g)) => Some(g.vni),
                _ => None,
            },
            PushSpec::NoOp => None,
        }
    }

    /// Returns the outer IPv6 src/dst when this spec pushes Geneve encapsulation.
    #[inline]
    pub fn outer_ip6_addrs(&self) -> Option<(Ipv6Addr, Ipv6Addr)> {
        match &self.prepend {
            PushSpec::Fastpath(c) => match &c.encap {
                CompiledEncap::Push { ip: IpPush::Ip6(v6), .. } => {
                    Some((v6.src, v6.dst))
                }
                _ => None,
            },
            PushSpec::Slowpath(s) => match &s.outer_ip {
                Some(L3Repr::Ipv6(v6)) => Some((v6.source, v6.destination)),
                _ => None,
            },
            PushSpec::NoOp => None,
        }
    }
}

/// Specification of additional header layers to push at the head of a packet.
#[derive(Clone, Debug)]
pub enum PushSpec {
    /// Bytes to prepend to packet which have been serialised ahead of time
    /// and can be copied in one shot.
    Fastpath(Arc<CompiledTransform>),
    /// Full representations of each header to serialise and prepend ahead
    /// of the current packet contents.
    Slowpath(Box<OpteEmit>),
    /// No prepend.
    NoOp,
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Default)]
pub enum Memoised<T> {
    #[default]
    Uninit,
    Known(T),
}

impl<T> Memoised<T> {
    #[inline]
    pub fn get(&mut self, or: impl FnOnce() -> T) -> &T {
        if self.try_get().is_none() {
            self.set(or());
        }

        self.try_get().unwrap()
    }

    #[inline]
    pub fn try_get(&self) -> Option<&T> {
        match self {
            Memoised::Uninit => None,
            Memoised::Known(v) => Some(v),
        }
    }

    #[inline]
    pub fn set(&mut self, val: T) {
        *self = Self::Known(val);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ddi::mblk::MsgBlk;
    use crate::engine::ether::Ethernet;
    use crate::engine::ether::EthernetRef;
    use crate::engine::ip::v4::Ipv4;
    use crate::engine::ip::v4::Ipv4Ref;
    use crate::engine::ip::v6::Ipv6;
    use crate::engine::ip::v6::Ipv6Ref;
    use crate::engine::packet::Packet;
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
        let parsed = Packet::parse_outbound(pkt.iter_mut(), GenericUlp {})
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

        let pkt = Packet::parse_outbound(mp1.iter_mut(), GenericUlp {})
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
            Packet::parse_outbound(st1.iter_mut(), GenericUlp {}),
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
                let pkt = Packet::parse_outbound(pkt.iter_mut(), GenericUlp {})
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
        let parsed = Packet::parse_inbound(pkt.iter_mut(), GenericUlp {})
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
        let pkt = Packet::parse_inbound(pkt.iter_mut(), GenericUlp {})
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

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use super::checksum::Checksum;
use super::ether::EtherMeta;
use super::ether::EtherMod;
use super::ether::Ethernet;
use super::ether::EthernetMut;
use super::ether::EthernetPacket;
use super::ether::ValidEthernet;
use super::geneve::OxideOption;
use super::geneve::GENEVE_OPT_CLASS_OXIDE;
use super::geneve::GENEVE_PORT;
use super::headers::EncapMeta;
use super::headers::EncapMod;
use super::headers::EncapPush;
use super::headers::HasInnerCksum;
use super::headers::HeaderActionError;
use super::headers::HeaderActionModify;
use super::headers::IpMod;
use super::headers::IpPush;
use super::headers::PushAction;
use super::headers::UlpMetaModify;
use super::icmp::IcmpEchoMut;
use super::icmp::IcmpEchoRef;
use super::icmp::QueryEcho;
use super::icmp::ValidIcmpEcho;
use super::ip::v4::Ipv4;
use super::ip::v4::Ipv4Mut;
use super::ip::v4::Ipv4Packet;
use super::ip::v4::Ipv4Ref;
use super::ip::v6::Ipv6;
use super::ip::v6::Ipv6Mut;
use super::ip::v6::Ipv6Packet;
use super::ip::v6::Ipv6Ref;
use super::ip::L3Repr;
use super::ip::ValidL3;
use super::ip::L3;
use super::packet::AddrPair;
use super::packet::BodyTransform;
use super::packet::BodyTransformError;
use super::packet::InnerFlowId;
use super::packet::PacketState;
use super::packet::ParseError;
use super::packet::FLOW_ID_DEFAULT;
use super::parse::NoEncap;
use super::parse::Ulp;
use super::parse::UlpRepr;
use super::rule::CompiledEncap;
use super::rule::CompiledTransform;
use super::rule::HdrTransform;
use super::rule::HdrTransformError;
use super::LightweightMeta;
use super::NetworkParser;
use crate::ddi::mblk::MsgBlk;
use crate::ddi::mblk::MsgBlkIterMut;
use crate::ddi::mblk::MsgBlkNode;
use crate::engine::geneve::valid_geneve_has_oxide_external;
use crate::engine::geneve::GeneveMeta;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::Cell;
use core::hash::Hash;
use core::ops::Deref;
use core::ops::DerefMut;
use core::sync::atomic::AtomicPtr;
use illumos_sys_hdrs::uintptr_t;
use ingot::ethernet::Ethertype;
use ingot::geneve::Geneve;
use ingot::geneve::GeneveMut;
use ingot::geneve::GeneveOpt;
use ingot::geneve::GeneveOptionType;
use ingot::geneve::GeneveRef;
use ingot::geneve::ValidGeneve;
use ingot::icmp::IcmpV4Mut;
use ingot::icmp::IcmpV4Packet;
use ingot::icmp::IcmpV4Ref;
use ingot::icmp::IcmpV6Mut;
use ingot::icmp::IcmpV6Packet;
use ingot::icmp::IcmpV6Ref;
use ingot::ip::IpProtocol;
use ingot::ip::Ipv4Flags;
use ingot::tcp::TcpFlags;
use ingot::tcp::TcpMut;
use ingot::tcp::TcpPacket;
use ingot::tcp::TcpRef;
use ingot::types::util::Repeated;
use ingot::types::BoxedHeader;
use ingot::types::Emit;
use ingot::types::Header as IngotHeader;
use ingot::types::HeaderLen;
use ingot::types::HeaderParse;
use ingot::types::InlineHeader;
use ingot::types::NextLayer;
use ingot::types::Parsed as IngotParsed;
use ingot::types::Read;
use ingot::types::ToOwnedPacket;
use ingot::udp::Udp;
use ingot::udp::UdpMut;
use ingot::udp::UdpPacket;
use ingot::udp::UdpRef;
use ingot::udp::ValidUdp;
use opte_api::Direction;
use opte_api::Ipv6Addr;
use opte_api::Vni;
use zerocopy::ByteSlice;
use zerocopy::ByteSliceMut;
use zerocopy::IntoBytes;

pub struct OpteUnifiedLengths {
    pub outer_eth: usize,
    pub outer_l3: usize,
    pub outer_encap: usize,

    pub inner_eth: usize,
    pub inner_l3: usize,
    pub inner_ulp: usize,
}

impl OpteUnifiedLengths {
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

pub enum ValidEncapMeta<B: ByteSlice> {
    Geneve(ValidUdp<B>, ValidGeneve<B>),
}

pub struct OpteMeta<T: ByteSlice> {
    pub outer_eth: Option<InlineHeader<Ethernet, ValidEthernet<T>>>,
    pub outer_l3: Option<L3<T>>,
    pub outer_encap: Option<InlineHeader<EncapMeta, ValidEncapMeta<T>>>,

    pub inner_eth: EthernetPacket<T>,
    pub inner_l3: Option<L3<T>>,
    pub inner_ulp: Option<Ulp<T>>,
}

pub type OpteParsed<T> = IngotParsed<OpteMeta<<T as Read>::Chunk>, T>;
pub type OpteParsed2<T, M> = IngotParsed<M, T>;

impl<T: ByteSlice> OpteMeta<T> {
    #[inline]
    pub fn convert_ingot<U: Into<Self>, Q: Read<Chunk = T>>(
        value: IngotParsed<U, Q>,
    ) -> OpteParsed<Q> {
        let IngotParsed { stack: headers, data, last_chunk } = value;

        IngotParsed { stack: headers.into(), data, last_chunk }
    }
}

struct SizeHoldingEncap<'a> {
    encapped_len: u16,
    meta: &'a EncapMeta,
}

unsafe impl<'a> ingot::types::EmitDoesNotRelyOnBufContents
    for SizeHoldingEncap<'a>
{
}

impl<'a> HeaderLen for SizeHoldingEncap<'a> {
    const MINIMUM_LENGTH: usize = EncapMeta::MINIMUM_LENGTH;

    #[inline]
    fn packet_length(&self) -> usize {
        self.meta.packet_length()
    }
}

impl<'a> Emit for SizeHoldingEncap<'a> {
    #[inline]
    fn emit_raw<V: ByteSliceMut>(&self, buf: V) -> usize {
        match self.meta {
            EncapMeta::Geneve(g) => {
                let mut opts = vec![];

                if g.oxide_external_pkt {
                    opts.push(GeneveOpt {
                        class: GENEVE_OPT_CLASS_OXIDE,
                        option_type: GeneveOptionType(
                            OxideOption::External.opt_type(),
                        ),
                        ..Default::default()
                    });
                }

                let options = Repeated::new(opts);
                let opt_len_unscaled = options.packet_length();
                let opt_len = (opt_len_unscaled >> 2) as u8;

                let geneve = Geneve {
                    protocol_type: Ethertype::ETHERNET,
                    vni: g.vni,
                    opt_len,
                    options,
                    ..Default::default()
                };

                let length = self.encapped_len
                    + (Udp::MINIMUM_LENGTH + geneve.packet_length()) as u16;

                (
                    Udp {
                        source: g.entropy,
                        destination: GENEVE_PORT,
                        length,
                        ..Default::default()
                    },
                    &geneve,
                )
                    .emit_raw(buf)
            }
        }
    }

    #[inline]
    fn needs_emit(&self) -> bool {
        true
    }
}

impl Emit for EncapMeta {
    #[inline]
    fn emit_raw<V: ByteSliceMut>(&self, buf: V) -> usize {
        SizeHoldingEncap { encapped_len: 0, meta: self }.emit_raw(buf)
    }

    #[inline]
    fn needs_emit(&self) -> bool {
        true
    }
}

impl<B: ByteSliceMut> Emit for ValidEncapMeta<B> {
    #[inline]
    fn emit_raw<V: ByteSliceMut>(&self, buf: V) -> usize {
        match self {
            ValidEncapMeta::Geneve(u, g) => (u, g).emit_raw(buf),
        }
    }

    #[inline]
    fn needs_emit(&self) -> bool {
        match self {
            ValidEncapMeta::Geneve(u, g) => u.needs_emit() && g.needs_emit(),
        }
    }
}

impl HeaderLen for EncapMeta {
    const MINIMUM_LENGTH: usize = Udp::MINIMUM_LENGTH + Geneve::MINIMUM_LENGTH;

    #[inline]
    fn packet_length(&self) -> usize {
        match self {
            EncapMeta::Geneve(g) => {
                Self::MINIMUM_LENGTH
                    + g.oxide_external_pkt.then_some(4).unwrap_or_default()
            }
        }
    }
}

impl<B: ByteSlice> HeaderLen for ValidEncapMeta<B> {
    const MINIMUM_LENGTH: usize = Udp::MINIMUM_LENGTH + Geneve::MINIMUM_LENGTH;

    #[inline]
    fn packet_length(&self) -> usize {
        match self {
            ValidEncapMeta::Geneve(u, g) => {
                u.packet_length() + g.packet_length()
            }
        }
    }
}

// This really needs a rethink, but also I just need to get this working...
struct PktBodyWalker<T: Read> {
    base: Cell<Option<(Option<T::Chunk>, T)>>,
    slice: AtomicPtr<Box<[(*mut u8, usize)]>>,
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

impl<T: Read> PktBodyWalker<T> {
    fn reify_body_segs(&self)
    where
        <T as Read>::Chunk: ByteSliceMut,
    {
        if let Some((mut first, mut rest)) = self.base.take() {
            // SAFETY: ByteSlice requires as part of its API
            // that any implementors are stable, so we will always
            // get the same view via deref. We are then consuming them
            // into references which live exactly as long as their initial
            // form.
            //
            // The next question is one of ownership.
            // We know that these chunks are at least &[u8]s, they
            // *will* be exclusive if ByteSliceMut is met (because they are
            // sourced from an exclusive borrow on something which ownas a [u8]).
            // This allows us to cast to &mut later, but not here!
            let mut to_hold = vec![];
            if let Some(ref mut chunk) = first {
                let as_bytes = chunk.deref_mut();
                to_hold.push(unsafe { core::mem::transmute(as_bytes) });
            }

            // TODO(drop-safety): we need to give these chunks a longer life, too.
            while let Ok(chunk) = rest.next_chunk() {
                let as_bytes = chunk.deref();
                to_hold.push(unsafe { core::mem::transmute(as_bytes) });
            }

            let to_store = Box::into_raw(Box::new(to_hold.into_boxed_slice()));

            self.slice
                .compare_exchange(
                    core::ptr::null_mut(),
                    to_store,
                    core::sync::atomic::Ordering::Relaxed,
                    core::sync::atomic::Ordering::Relaxed,
                )
                .expect("unexpected concurrent access to body_seg memoiser");

            // SAFETY:
            // Replace contents to get correct drop behaviour on T.
            // Currently the only ByteSlice impls are &[u8] and friends,
            // but this may extend to e.g. Vec<u8> in future.
            self.base.set(Some((first, rest)));
        }
    }

    fn body_segs(&self) -> &[&[u8]]
    where
        T::Chunk: ByteSliceMut,
    {
        let mut slice_ptr =
            self.slice.load(core::sync::atomic::Ordering::Relaxed);
        if slice_ptr.is_null() {
            self.reify_body_segs();
            slice_ptr = self.slice.load(core::sync::atomic::Ordering::Relaxed);
        }
        assert!(!slice_ptr.is_null());

        // let use_ref: &[_] = &b;
        unsafe {
            let a = (&*(*slice_ptr)) as *const _;
            core::mem::transmute(a)
        }
    }

    fn body_segs_mut(&mut self) -> &mut [&mut [u8]]
    where
        T::Chunk: ByteSliceMut,
    {
        let mut slice_ptr =
            self.slice.load(core::sync::atomic::Ordering::Relaxed);
        if slice_ptr.is_null() {
            self.reify_body_segs();
            slice_ptr = self.slice.load(core::sync::atomic::Ordering::Relaxed);
        }
        assert!(!slice_ptr.is_null());

        // SAFETY: We have an exclusive reference, and the ByteSliceMut
        // bound guarantees that this packet view was construced from
        // an exclusive reference. In turn, we know that we are the only
        // possible referent.
        unsafe {
            let a = (&mut *(*slice_ptr)) as *mut _;
            core::mem::transmute(a)
        }
    }
}

pub struct PacketData<T: Read> {
    pub(crate) headers: OpteMeta<T::Chunk>,
    initial_lens: Option<Box<OpteUnifiedLengths>>,
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

pub fn ulp_src_port<B: ByteSlice>(pkt: &Ulp<B>) -> Option<u16> {
    match pkt {
        Ulp::Tcp(t) => Some(t.source()),
        Ulp::Udp(t) => Some(t.source()),
        _ => None,
    }
}

pub fn ulp_dst_port<B: ByteSlice>(pkt: &Ulp<B>) -> Option<u16> {
    match pkt {
        Ulp::Tcp(t) => Some(t.destination()),
        Ulp::Udp(t) => Some(t.destination()),
        _ => None,
    }
}

impl<T: Read> PacketData<T> {
    pub fn initial_lens(&self) -> Option<&OpteUnifiedLengths> {
        self.initial_lens.as_ref().map(|v| &**v)
    }

    pub fn outer_ether(
        &self,
    ) -> Option<&InlineHeader<Ethernet, ValidEthernet<T::Chunk>>> {
        self.headers.outer_eth.as_ref()
    }

    pub fn outer_ip(&self) -> Option<&L3<T::Chunk>> {
        self.headers.outer_l3.as_ref()
    }

    // Need to expose this a lil cleaner...
    /// Returns whether this packet is sourced from outside the rack,
    /// in addition to its VNI.
    pub fn outer_encap_geneve_vni_and_origin(&self) -> Option<(Vni, bool)> {
        match &self.headers.outer_encap {
            Some(InlineHeader::Repr(EncapMeta::Geneve(g))) => {
                Some((g.vni, g.oxide_external_pkt))
            }
            Some(InlineHeader::Raw(ValidEncapMeta::Geneve(_, g))) => {
                Some((g.vni(), valid_geneve_has_oxide_external(&g)))
            }
            None => None,
        }
    }

    // Again: really need to make Owned/Direct choices better-served by ingot.
    // this interface sucks.
    pub fn outer_ip6_addrs(&self) -> Option<(Ipv6Addr, Ipv6Addr)> {
        match &self.headers.outer_l3 {
            Some(L3::Ipv6(v6)) => Some((v6.source(), v6.destination())),
            _ => None,
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
        T::Chunk: ByteSliceMut,
    {
        self.body.body_segs()
    }

    // right place for this to live? Or is `meta()` misnamed?
    pub fn copy_remaining(&self) -> Vec<u8>
    where
        T::Chunk: ByteSliceMut,
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
        T::Chunk: ByteSliceMut,
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
        T::Chunk: ByteSliceMut,
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

        InnerFlowId { proto: proto.into(), addrs, src_port, dst_port }
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
//
// TODO: In theory, this can be any `Read` type giving us `&mut [u8]`s,
// but in practice we are internally reliant on returning `MsgBlk`s in
// hairpin actions and the like. Fighting the battle of making this generic
// is a bridge too far for the `ingot` datapath rewrite. This might have
// value in future.
#[derive(Debug)]
pub struct Packet<S: PacketState> {
    state: S,
}

impl<T: Read + QueryLen> Packet<Initialized2<T>> {
    pub fn new(pkt: T) -> Self
    where
        Initialized2<T>: PacketState,
    {
        let len = pkt.len();
        Self { state: Initialized2 { len, inner: pkt } }
    }
}

impl<'a, T: Read + 'a> Packet<Initialized2<T>>
where
    T::Chunk: ingot::types::IntoBufPointer<'a> + ByteSliceMut,
{
    // TODO: cleanup type aliases.

    #[inline]
    pub fn len(&self) -> usize {
        self.state.len
    }

    #[inline]
    pub fn parse_inbound<NP: NetworkParser>(
        self,
        net: NP,
    ) -> Result<Packet<LiteParsed<T, NP::InMeta<T::Chunk>>>, ParseError> {
        let Packet { state: Initialized2 { len, inner } } = self;

        let meta = net.parse_inbound(inner)?;
        meta.stack.validate(len)?;

        Ok(Packet { state: LiteParsed { meta, len } })
    }

    #[inline]
    pub fn parse_outbound<NP: NetworkParser>(
        self,
        net: NP,
    ) -> Result<Packet<LiteParsed<T, NP::OutMeta<T::Chunk>>>, ParseError> {
        let Packet { state: Initialized2 { len, inner } } = self;

        let meta = net.parse_outbound(inner)?;
        meta.stack.validate(len)?;

        Ok(Packet { state: LiteParsed { meta, len } })
    }
}

impl<'a, T: Read + 'a, M: LightweightMeta<T::Chunk>> Packet<LiteParsed<T, M>>
where
    T::Chunk: ingot::types::IntoBufPointer<'a>,
{
    #[inline]
    pub fn to_full_meta(self) -> Packet<FullParsed<T>> {
        let Packet { state: LiteParsed { len, meta } } = self;
        let IngotParsed { stack: headers, data, last_chunk } = meta;

        // TODO: we can probably not do this in some cases, but we
        // don't have a way for headeractions to signal that they
        // *may* change the fields we need in the slowpath.
        let body_csum = headers.compute_body_csum();
        let flow = headers.flow();

        let headers: OpteMeta<_> = headers.into();
        let initial_lens = Some(
            OpteUnifiedLengths {
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
    pub fn flow(&self) -> InnerFlowId {
        self.meta().flow()
    }
}

impl<T: Read> Packet<FullParsed<T>> {
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
    pub fn emit_spec(self) -> Result<OldEmitSpec, ingot::types::ParseError>
    where
        T::Chunk: ByteSliceMut,
    {
        // Roughly how this works:
        // - Identify rightmost structural-changed field.
        // - fill out owned versions into the push_spec of all
        //   extant fields we rewound past.
        // - Rewind up to+including that point in original
        //   pkt space.
        let state = self.state;
        let init_lens = state.meta.initial_lens.unwrap();
        let headers = state.meta.headers;
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

        use ingot::types::InlineHeader;

        match headers.inner_ulp {
            Some(ulp) => {
                let l = ulp.packet_length();
                encapped_len += l;

                if ulp.needs_emit() || l != init_lens.inner_ulp {
                    let inner =
                        push_spec.inner.get_or_insert_with(Default::default);

                    inner.ulp = Some(match ulp {
                        Ulp::Tcp(IngotHeader::Repr(t)) => UlpRepr::Tcp(*t),
                        Ulp::Tcp(IngotHeader::Raw(t)) => {
                            UlpRepr::Tcp((&t).into())
                        }
                        Ulp::Udp(IngotHeader::Repr(t)) => UlpRepr::Udp(*t),
                        Ulp::Udp(IngotHeader::Raw(t)) => {
                            UlpRepr::Udp((&t).into())
                        }
                        Ulp::IcmpV4(IngotHeader::Repr(t)) => {
                            UlpRepr::IcmpV4(*t)
                        }
                        Ulp::IcmpV4(IngotHeader::Raw(t)) => {
                            UlpRepr::IcmpV4((&t).into())
                        }
                        Ulp::IcmpV6(IngotHeader::Repr(t)) => {
                            UlpRepr::IcmpV6(*t)
                        }
                        Ulp::IcmpV6(IngotHeader::Raw(t)) => {
                            UlpRepr::IcmpV6((&t).into())
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

        match headers.inner_l3 {
            Some(l3) => {
                let l = l3.packet_length();
                encapped_len += l;

                if force_serialize || l3.needs_emit() || l != init_lens.inner_l3
                {
                    let inner =
                        push_spec.inner.get_or_insert_with(Default::default);

                    inner.l3 = Some(match l3 {
                        L3::Ipv4(IngotHeader::Repr(v4)) => L3Repr::Ipv4(*v4),
                        L3::Ipv4(IngotHeader::Raw(v4)) => {
                            L3Repr::Ipv4((&v4).into())
                        }
                        L3::Ipv6(IngotHeader::Repr(v6)) => L3Repr::Ipv6(*v6),

                        // We can't actually do structural mods here today using OPTE,
                        // but account for the possibiliry at least.
                        L3::Ipv6(IngotHeader::Raw(v6)) => {
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
            inner.eth = match headers.inner_eth {
                IngotHeader::Repr(p) => *p,
                IngotHeader::Raw(p) => (&p).into(),
            };
            rewind += init_lens.inner_eth;
        }

        match headers.outer_encap {
            Some(encap)
                if force_serialize
                    || encap.needs_emit()
                    || encap.packet_length() != init_lens.outer_encap =>
            {
                push_spec.outer_encap = Some(match encap {
                    InlineHeader::Repr(o) => o,
                    InlineHeader::Raw(ValidEncapMeta::Geneve(u, g)) => {
                        EncapMeta::Geneve(GeneveMeta {
                            entropy: u.source(),
                            vni: g.vni(),
                            oxide_external_pkt: valid_geneve_has_oxide_external(
                                &g,
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

        match headers.outer_l3 {
            Some(l3)
                if force_serialize
                    || l3.needs_emit()
                    || l3.packet_length() != init_lens.outer_l3 =>
            {
                let encap_len = push_spec.outer_encap.packet_length();

                push_spec.outer_ip = Some(match l3 {
                    L3::Ipv6(BoxedHeader::Repr(o)) => L3Repr::Ipv6(*o),
                    L3::Ipv4(BoxedHeader::Repr(o)) => L3Repr::Ipv4(*o),
                    L3::Ipv6(BoxedHeader::Raw(o)) => {
                        L3Repr::Ipv6((&o).to_owned(None)?)
                    }
                    L3::Ipv4(BoxedHeader::Raw(o)) => L3Repr::Ipv4((&o).into()),
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

        match headers.outer_eth {
            Some(eth)
                if force_serialize
                    || eth.needs_emit()
                    || eth.packet_length() != init_lens.outer_eth =>
            {
                push_spec.outer_eth = Some(match eth {
                    InlineHeader::Repr(o) => o,
                    InlineHeader::Raw(r) => (&r).into(),
                });

                rewind += init_lens.outer_eth;
            }
            None if init_lens.outer_eth != 0 => {
                rewind += init_lens.outer_eth;
            }
            _ => {}
        }

        Ok(OldEmitSpec {
            rewind: rewind as u16,
            payload_len: payload_len as u16,
            encapped_len: encapped_len as u16,
            push_spec,
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
        T::Chunk: ByteSliceMut,
    {
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

    #[inline]
    pub fn body_segs(&self) -> Option<&[&[u8]]>
    where
        T::Chunk: ByteSliceMut,
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
        T::Chunk: ByteSliceMut,
    {
        let out = self.state.meta.body_segs_mut();
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    pub fn mblk_addr(&self) -> uintptr_t {
        // TODO.
        0
    }

    /// Compute ULP and IP header checksum from scratch.
    ///
    /// This should really only be used for testing, or in the case
    /// where we have applied body transforms and know that any initial
    /// body_csum cannot be valid.
    pub fn compute_checksums(&mut self)
    where
        T::Chunk: ByteSliceMut,
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
                        IngotHeader::Repr(tcp) => {
                            let mut bytes = [0u8; 56];
                            tcp.emit_raw(&mut bytes[..]);
                            csum.add_bytes(&bytes[..]);
                        }
                        IngotHeader::Raw(tcp) => {
                            csum.add_bytes(tcp.0.as_bytes());
                            match &tcp.1 {
                                IngotHeader::Repr(opts) => {
                                    csum.add_bytes(&*opts);
                                }
                                IngotHeader::Raw(opts) => {
                                    csum.add_bytes(&*opts);
                                }
                            }
                        }
                    }
                    tcp.set_checksum(csum.finalize_for_ingot());
                }
                Ulp::Udp(udp) => {
                    udp.set_checksum(0);
                    match udp {
                        IngotHeader::Repr(udp) => {
                            let mut bytes = [0u8; 8];
                            udp.emit_raw(&mut bytes[..]);
                            csum.add_bytes(&bytes[..]);
                        }
                        IngotHeader::Raw(udp) => {
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
        T::Chunk: ByteSliceMut,
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
                        IngotHeader::Repr(tcp) => {
                            let mut bytes = [0u8; 56];
                            tcp.emit_raw(&mut bytes[..]);
                            csum.add_bytes(&bytes[..]);
                        }
                        IngotHeader::Raw(tcp) => {
                            csum.add_bytes(tcp.0.as_bytes());
                            match &tcp.1 {
                                IngotHeader::Repr(opts) => {
                                    csum.add_bytes(&*opts);
                                }
                                IngotHeader::Raw(opts) => {
                                    csum.add_bytes(&*opts);
                                }
                            }
                        }
                    }
                    tcp.set_checksum(csum.finalize_for_ingot());
                }
                Ulp::Udp(udp) => {
                    udp.set_checksum(0);
                    match udp {
                        IngotHeader::Repr(udp) => {
                            let mut bytes = [0u8; 8];
                            udp.emit_raw(&mut bytes[..]);
                            csum.add_bytes(&bytes[..]);
                        }
                        IngotHeader::Raw(udp) => {
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

/// The type state of a packet that has been initialized and allocated, but
/// about which nothing else is known besides the length.
#[derive(Debug)]
pub struct Initialized2<T: Read> {
    /// Total length of packet, in bytes. This is equal to the sum of
    /// the length of the _initialized_ window in all the segments
    /// (`b_wptr - b_rptr`).
    len: usize,

    inner: T,
}

impl<T: Read> PacketState for Initialized2<T> {}
impl<T: Read> PacketState for FullParsed<T> {}

/// Zerocopy view onto a parsed packet, accompanied by locally
/// computed state.
pub struct FullParsed<T: Read> {
    /// Total length of packet, in bytes. This is equal to the sum of
    /// the length of the _initialized_ window in all the segments
    /// (`b_wptr - b_rptr`).
    len: usize,
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
    len: usize,
    meta: IngotParsed<M, T>,
}

impl<T: Read, M: LightweightMeta<T::Chunk>> PacketState for LiteParsed<T, M> {}

impl<T: Read, M: LightweightMeta<T::Chunk>> LiteParsed<T, M> {}

// XXX: Needed for now to account for not wanting to redesign
// ActionDescs to be generic over T (trait object safety rules, etc.),
// in addition to needing to rework Hairpin actions.
pub type MblkPacketData<'a> = PacketData<MsgBlkIterMut<'a>>;
pub type MblkFullParsed<'a> = FullParsed<MsgBlkIterMut<'a>>;
pub type MblkLiteParsed<'a, M> = LiteParsed<MsgBlkIterMut<'a>, M>;

pub trait QueryLen {
    fn len(&self) -> usize;
}

// TODO: don't really care about pushing 'inner' reprs today.
#[derive(Clone, Debug, Default)]
pub struct OpteEmit {
    outer_eth: Option<Ethernet>,
    outer_ip: Option<L3Repr>,
    outer_encap: Option<EncapMeta>,

    // We can (but do not often) push/pop inner meta.
    // Splitting minimises struct size in the general case.
    inner: Option<Box<OpteInnerEmit>>,
}

#[derive(Clone, Debug, Default)]
pub struct OpteInnerEmit {
    eth: Ethernet,
    l3: Option<L3Repr>,
    ulp: Option<UlpRepr>,
}

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
    #[inline]
    #[must_use]
    pub fn l4_hash(&self) -> u32 {
        self.l4_hash
    }

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
                        let target = if prepend.is_none() {
                            &mut pkt
                        } else {
                            prepend.as_mut().unwrap()
                        };

                        target.emit_front(inner_ulp).unwrap();
                    }

                    if let Some(inner_l3) = &inner_new.l3 {
                        let target = if prepend.is_none() {
                            &mut pkt
                        } else {
                            prepend.as_mut().unwrap()
                        };

                        target.emit_front(inner_l3).unwrap();
                    }

                    let target = if prepend.is_none() {
                        &mut pkt
                    } else {
                        prepend.as_mut().unwrap()
                    };

                    target.emit_front(&inner_new.eth).unwrap();
                }

                if let Some(outer_encap) = &push_spec.outer_encap {
                    let encap = SizeHoldingEncap {
                        encapped_len: self.ulp_len as u16,
                        meta: &outer_encap,
                    };

                    let target = if prepend.is_none() {
                        &mut pkt
                    } else {
                        prepend.as_mut().unwrap()
                    };

                    target.emit_front(&encap).unwrap();
                }

                if let Some(outer_ip) = &push_spec.outer_ip {
                    let target = if prepend.is_none() {
                        &mut pkt
                    } else {
                        prepend.as_mut().unwrap()
                    };

                    target.emit_front(outer_ip).unwrap();
                }

                if let Some(outer_eth) = &push_spec.outer_eth {
                    let target = if prepend.is_none() {
                        &mut pkt
                    } else {
                        prepend.as_mut().unwrap()
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

#[derive(Clone, Debug)]
pub enum PushSpec {
    Fastpath(Arc<CompiledTransform>),
    Slowpath(Box<OpteEmit>),
    NoOp,
}

#[derive(Clone, Debug)]
pub struct OldEmitSpec {
    pub rewind: u16,
    pub encapped_len: u16,
    pub payload_len: u16,
    pub push_spec: OpteEmit,
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

impl<B: ByteSlice> QueryEcho for IcmpV4Packet<B> {
    #[inline]
    fn echo_id(&self) -> Option<u16> {
        match (self.code(), self.ty()) {
            (0, 0) | (0, 8) => {
                ValidIcmpEcho::parse(self.rest_of_hdr_ref().as_slice())
                    .ok()
                    .map(|(v, ..)| v.id())
            }
            _ => None,
        }
    }
}

impl<B: ByteSlice> QueryEcho for IcmpV6Packet<B> {
    #[inline]
    fn echo_id(&self) -> Option<u16> {
        match (self.code(), self.ty()) {
            (0, 128) | (0, 129) => {
                ValidIcmpEcho::parse(&self.rest_of_hdr_ref()[..])
                    .ok()
                    .map(|(v, ..)| v.id())
            }
            _ => None,
        }
    }
}

impl<T: ByteSliceMut> HeaderActionModify<EtherMod>
    for InlineHeader<Ethernet, ValidEthernet<T>>
{
    #[inline]
    fn run_modify(
        &mut self,
        mod_spec: &EtherMod,
    ) -> Result<(), HeaderActionError> {
        match self {
            InlineHeader::Repr(a) => {
                if let Some(src) = mod_spec.src {
                    a.set_source(src);
                }
                if let Some(dst) = mod_spec.dst {
                    a.set_destination(dst);
                }
            }
            InlineHeader::Raw(a) => {
                if let Some(src) = mod_spec.src {
                    a.set_source(src);
                }
                if let Some(dst) = mod_spec.dst {
                    a.set_destination(dst);
                }
            }
        }

        Ok(())
    }
}

impl<T: ByteSliceMut> HeaderActionModify<EtherMod> for EthernetPacket<T> {
    #[inline]
    fn run_modify(
        &mut self,
        mod_spec: &EtherMod,
    ) -> Result<(), HeaderActionError> {
        if let Some(src) = mod_spec.src {
            self.set_source(src);
        }
        if let Some(dst) = mod_spec.dst {
            self.set_destination(dst);
        }

        Ok(())
    }
}

impl<T: ByteSliceMut> HeaderActionModify<IpMod>
    for InlineHeader<L3Repr, ValidL3<T>>
{
    #[inline]
    fn run_modify(
        &mut self,
        mod_spec: &IpMod,
    ) -> Result<(), HeaderActionError> {
        match mod_spec {
            IpMod::Ip4(mods) => match self {
                InlineHeader::Repr(L3Repr::Ipv4(v4)) => {
                    if let Some(src) = mods.src {
                        <Ipv4 as Ipv4Mut<T>>::set_source(v4, src);
                    }
                    if let Some(dst) = mods.dst {
                        <Ipv4 as Ipv4Mut<T>>::set_destination(v4, dst);
                    }
                    if let Some(p) = mods.proto {
                        <Ipv4 as Ipv4Mut<T>>::set_protocol(
                            v4,
                            IpProtocol(u8::from(p)),
                        );
                    }
                }
                InlineHeader::Raw(ValidL3::Ipv4(v4)) => {
                    if let Some(src) = mods.src {
                        v4.set_source(src);
                    }
                    if let Some(dst) = mods.dst {
                        v4.set_destination(dst);
                    }
                    if let Some(p) = mods.proto {
                        v4.set_protocol(IpProtocol(u8::from(p)));
                    }
                }
                _ => return Err(HeaderActionError::MissingHeader),
            },
            IpMod::Ip6(mods) => match self {
                InlineHeader::Repr(L3Repr::Ipv6(v6)) => {
                    if let Some(src) = mods.src {
                        <Ipv6 as Ipv6Mut<T>>::set_source(v6, src);
                    }
                    if let Some(dst) = mods.dst {
                        <Ipv6 as Ipv6Mut<T>>::set_destination(v6, dst);
                    }
                    if let Some(p) = mods.proto {
                        // TODO(kyle)
                        // NOTE: I know this is broken for V6EHs
                        <Ipv6 as Ipv6Mut<T>>::set_next_header(
                            v6,
                            IpProtocol(u8::from(p)),
                        );
                    }
                }
                InlineHeader::Raw(ValidL3::Ipv6(v6)) => {
                    if let Some(src) = mods.src {
                        v6.set_source(src);
                    }
                    if let Some(dst) = mods.dst {
                        v6.set_destination(dst);
                    }
                    if let Some(p) = mods.proto {
                        // TODO(kyle)
                        // NOTE: I know this is broken for V6EHs
                        v6.set_next_header(IpProtocol(u8::from(p)));
                    }
                }
                _ => return Err(HeaderActionError::MissingHeader),
            },
        }

        Ok(())
    }
}

impl<T: ByteSliceMut> HeaderActionModify<IpMod> for L3<T> {
    #[inline]
    fn run_modify(
        &mut self,
        mod_spec: &IpMod,
    ) -> Result<(), HeaderActionError> {
        match (self, mod_spec) {
            (L3::Ipv4(v4), IpMod::Ip4(mods)) => {
                if let Some(src) = mods.src {
                    v4.set_source(src);
                }
                if let Some(dst) = mods.dst {
                    v4.set_destination(dst);
                }
                if let Some(p) = mods.proto {
                    v4.set_protocol(IpProtocol(u8::from(p)));
                }
                Ok(())
            }
            (L3::Ipv6(v6), IpMod::Ip6(mods)) => {
                if let Some(src) = mods.src {
                    v6.set_source(src);
                }
                if let Some(dst) = mods.dst {
                    v6.set_destination(dst);
                }
                if let Some(p) = mods.proto {
                    // NOTE: I know this is broken for V6EHs
                    v6.set_next_header(IpProtocol(u8::from(p)));
                }
                Ok(())
            }
            _ => Err(HeaderActionError::MissingHeader),
        }
    }
}

impl<T: ByteSliceMut> HeaderActionModify<UlpMetaModify> for Ulp<T> {
    #[inline]
    fn run_modify(
        &mut self,
        mod_spec: &UlpMetaModify,
    ) -> Result<(), HeaderActionError> {
        match self {
            Ulp::Tcp(t) => {
                if let Some(src) = mod_spec.generic.src_port {
                    t.set_source(src);
                }
                if let Some(dst) = mod_spec.generic.dst_port {
                    t.set_destination(dst);
                }
                if let Some(flags) = mod_spec.tcp_flags {
                    t.set_flags(TcpFlags::from_bits_retain(flags));
                }
            }
            Ulp::Udp(u) => {
                if let Some(src) = mod_spec.generic.src_port {
                    u.set_source(src);
                }
                if let Some(dst) = mod_spec.generic.dst_port {
                    u.set_destination(dst);
                }
            }
            Ulp::IcmpV4(i4) => {
                if let Some(id) = mod_spec.icmp_id {
                    if i4.echo_id().is_some() {
                        let roh = i4.rest_of_hdr_mut();
                        ValidIcmpEcho::parse(&mut roh[..])
                            .expect(
                                "ICMP ROH is exactly as large as ValidIcmpEcho",
                            )
                            .0
                            .set_id(id);
                    }
                }
            }
            Ulp::IcmpV6(i6) => {
                if let Some(id) = mod_spec.icmp_id {
                    if i6.echo_id().is_some() {
                        let roh = i6.rest_of_hdr_mut();
                        ValidIcmpEcho::parse(&mut roh[..])
                            .expect(
                                "ICMP ROH is exactly as large as ValidIcmpEcho",
                            )
                            .0
                            .set_id(id);
                    }
                }
            }
        }

        Ok(())
    }
}

impl<T: ByteSliceMut> HeaderActionModify<EncapMod>
    for InlineHeader<EncapMeta, ValidEncapMeta<T>>
{
    #[inline]
    fn run_modify(
        &mut self,
        mod_spec: &EncapMod,
    ) -> Result<(), HeaderActionError> {
        match (self, mod_spec) {
            (
                InlineHeader::Repr(EncapMeta::Geneve(g)),
                EncapMod::Geneve(mod_spec),
            ) => {
                if let Some(vni) = mod_spec.vni {
                    g.vni = vni;
                }
            }
            (
                InlineHeader::Raw(ValidEncapMeta::Geneve(_, g)),
                EncapMod::Geneve(mod_spec),
            ) => {
                if let Some(vni) = mod_spec.vni {
                    g.set_vni(vni);
                }
            }
        }

        Ok(())
    }
}

impl<T: ByteSlice> HasInnerCksum for InlineHeader<Ethernet, ValidEthernet<T>> {
    const HAS_CKSUM: bool = false;
}

impl<T: ByteSlice> HasInnerCksum for InlineHeader<L3Repr, ValidL3<T>> {
    const HAS_CKSUM: bool = true;
}

impl<T: ByteSlice> HasInnerCksum
    for InlineHeader<EncapMeta, ValidEncapMeta<T>>
{
    const HAS_CKSUM: bool = false;
}

impl<T: ByteSlice> HasInnerCksum for EthernetPacket<T> {
    const HAS_CKSUM: bool = false;
}

impl<T: ByteSlice> HasInnerCksum for L3<T> {
    const HAS_CKSUM: bool = true;
}

impl<T: ByteSlice> HasInnerCksum for Ulp<T> {
    const HAS_CKSUM: bool = true;
}

impl<T: ByteSlice> From<EtherMeta>
    for ingot::types::Header<Ethernet, ValidEthernet<T>>
{
    #[inline]
    fn from(value: EtherMeta) -> Self {
        ingot::types::Header::Repr(
            Ethernet {
                destination: value.dst,
                source: value.src,
                ethertype: Ethertype(u16::from(value.ether_type)),
            }
            .into(),
        )
    }
}

impl<T: ByteSlice> From<EtherMeta>
    for InlineHeader<Ethernet, ValidEthernet<T>>
{
    #[inline]
    fn from(value: EtherMeta) -> Self {
        InlineHeader::Repr(
            Ethernet {
                destination: value.dst,
                source: value.src,
                ethertype: Ethertype(u16::from(value.ether_type)),
            }
            .into(),
        )
    }
}

impl<T: ByteSlice> From<EncapMeta>
    for ingot::types::Header<EncapMeta, ValidEncapMeta<T>>
{
    #[inline]
    fn from(value: EncapMeta) -> Self {
        ingot::types::Header::Repr(value.into())
    }
}

impl<T: ByteSlice> From<EncapMeta>
    for InlineHeader<EncapMeta, ValidEncapMeta<T>>
{
    #[inline]
    fn from(value: EncapMeta) -> Self {
        InlineHeader::Repr(value)
    }
}

impl<T: ByteSlice> PushAction<InlineHeader<Ethernet, ValidEthernet<T>>>
    for EtherMeta
{
    #[inline]
    fn push(&self) -> InlineHeader<Ethernet, ValidEthernet<T>> {
        InlineHeader::Repr(Ethernet {
            destination: self.dst,
            source: self.src,
            ethertype: Ethertype(u16::from(self.ether_type)),
        })
    }
}

impl<T: ByteSlice> PushAction<EthernetPacket<T>> for EtherMeta {
    #[inline]
    fn push(&self) -> EthernetPacket<T> {
        ingot::types::Header::Repr(
            Ethernet {
                destination: self.dst,
                source: self.src,
                ethertype: Ethertype(u16::from(self.ether_type)),
            }
            .into(),
        )
    }
}

impl<T: ByteSlice> PushAction<L3<T>> for IpPush {
    fn push(&self) -> L3<T> {
        match self {
            IpPush::Ip4(v4) => L3::Ipv4(
                Ipv4 {
                    protocol: IpProtocol(u8::from(v4.proto)),
                    source: v4.src,
                    destination: v4.dst,
                    flags: Ipv4Flags::DONT_FRAGMENT,
                    ..Default::default()
                }
                .into(),
            ),
            IpPush::Ip6(v6) => L3::Ipv6(
                Ipv6 {
                    next_header: IpProtocol(u8::from(v6.proto)),
                    source: v6.src,
                    destination: v6.dst,
                    ..Default::default()
                }
                .into(),
            ),
        }
    }
}

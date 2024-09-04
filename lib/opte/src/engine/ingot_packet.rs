use super::checksum::Checksum as OpteCsum;
use super::checksum::Checksum;
use super::checksum::HeaderChecksum;
use super::headers::EncapPush;
use super::headers::IpPush;
use super::icmp::QueryEcho;
use super::packet::allocb;
use super::packet::AddrPair;
use super::packet::BodyTransform;
use super::packet::BodyTransformError;
use super::packet::Initialized;
use super::packet::InnerFlowId;
use super::packet::Packet;
use super::packet::PacketState;
use super::packet::ParseError;
use super::packet::FLOW_ID_DEFAULT;
use super::rule::HdrTransform;
use super::rule::HdrTransformError;
use super::NetworkParser;
use alloc::sync::Arc;
use core::cell::Cell;
use core::cell::RefCell;
use core::hash::Hash;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::mem::MaybeUninit;
use core::ops::Deref;
use core::ops::DerefMut;
use core::ptr::NonNull;
use core::slice;
use core::sync::atomic::AtomicPtr;
use illumos_sys_hdrs::mblk_t;
use illumos_sys_hdrs::uintptr_t;
use ingot::ethernet::Ethernet;
use ingot::ethernet::EthernetPacket;
use ingot::ethernet::EthernetRef;
use ingot::ethernet::Ethertype;
use ingot::ethernet::ValidEthernet;
use ingot::example_chain::L3Repr;
use ingot::example_chain::Ulp;
use ingot::example_chain::L3;
use ingot::example_chain::L4;
use ingot::geneve::Geneve;
use ingot::geneve::GenevePacket;
use ingot::geneve::ValidGeneve;
use ingot::icmp::IcmpV4Packet;
use ingot::icmp::IcmpV4Ref;
use ingot::icmp::IcmpV6Packet;
use ingot::icmp::IcmpV6Ref;
use ingot::ip::Ipv4Packet;
use ingot::ip::Ipv4Ref;
use ingot::ip::Ipv6Packet;
use ingot::ip::Ipv6Ref;
use ingot::tcp::TcpPacket;
use ingot::tcp::TcpRef;
use ingot::types::Header;
use ingot::types::HeaderStack;
use ingot::types::ParseControl;
use ingot::types::ParseError as IngotParseErr;
use ingot::types::ParseResult;
use ingot::types::Parsed as IngotParsed;
use ingot::types::Read;
use ingot::udp::Udp;
use ingot::udp::UdpPacket;
use ingot::udp::UdpRef;
use ingot::udp::ValidUdp;
use ingot::Parse;
use opte_api::Direction;
use zerocopy::ByteSlice;
use zerocopy::ByteSliceMut;
use zerocopy::IntoBytes;

#[derive(Parse)]
pub struct OpteIn<Q: ByteSlice> {
    pub outer_eth: EthernetPacket<Q>,
    #[ingot(from = "L3<Q>")]
    pub outer_v6: Ipv6Packet<Q>,
    #[ingot(from = "L4<Q>")]
    pub outer_udp: UdpPacket<Q>,
    pub outer_encap: GenevePacket<Q>,

    pub inner_eth: EthernetPacket<Q>,
    // pub inner_l3: L3<Q>,
    pub inner_l3: L3<Q>,
    // pub inner_ulp: L4<Q>,
    pub inner_ulp: Ulp<Q>,
}

#[inline]
fn exit_on_arp<V: ByteSlice>(eth: &EthernetPacket<V>) -> ParseControl {
    if eth.ethertype() == Ethertype::ARP {
        ParseControl::Accept
    } else {
        ParseControl::Continue
    }
}

#[derive(Parse)]
pub struct OpteOut<Q: ByteSlice> {
    #[ingot(control = exit_on_arp)]
    pub inner_eth: EthernetPacket<Q>,
    pub inner_l3: Option<L3<Q>>,
    pub inner_ulp: Option<Ulp<Q>>,
}

// --- REWRITE IN PROGRESS ---
#[derive(Debug)]
pub struct MsgBlk {
    pub inner: NonNull<mblk_t>,
}

#[derive(Debug)]
pub struct MsgBlkNode(mblk_t);

impl Deref for MsgBlkNode {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe {
            let rptr = self.0.b_rptr;
            let len = self.0.b_wptr.offset_from(rptr) as usize;
            slice::from_raw_parts(rptr, len)
        }
    }
}

impl DerefMut for MsgBlkNode {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            let rptr = self.0.b_rptr;
            let len = self.0.b_wptr.offset_from(rptr) as usize;
            slice::from_raw_parts_mut(rptr, len)
        }
    }
}

impl MsgBlkNode {
    pub fn drop_front_bytes(&mut self, n: usize) {
        unsafe {
            assert!(self.0.b_wptr.offset_from(self.0.b_rptr) >= n as isize);
            self.0.b_rptr = self.0.b_rptr.add(n);
        }
    }
}

impl MsgBlk {
    pub fn new(len: usize) -> Self {
        let inner = NonNull::new(allocb(len))
            .expect("somehow failed to get an mblk...");

        Self { inner }
    }

    pub fn new_ethernet(len: usize) -> Self {
        Self::new_with_headroom(2, len)
    }

    pub fn byte_len(&self) -> usize {
        self.iter().map(|el| el.len()).sum()
    }

    pub fn seg_len(&self) -> usize {
        self.iter().count()
    }

    pub fn new_with_headroom(head_len: usize, body_len: usize) -> Self {
        let mut out = Self::new(head_len + body_len);

        // SAFETY: alloc is contiguous and always larger than head_len.
        let mut_out = unsafe { out.inner.as_mut() };
        mut_out.b_rptr = unsafe { mut_out.b_rptr.add(head_len) };
        mut_out.b_wptr = mut_out.b_rptr;

        out
    }

    pub unsafe fn write(
        &mut self,
        n_bytes: usize,
        f: impl FnOnce(&mut [MaybeUninit<u8>]),
    ) {
        let mut_out = unsafe { self.inner.as_mut() };
        let avail_bytes =
            unsafe { (*mut_out.b_datap).db_lim.offset_from(mut_out.b_wptr) };
        assert!(avail_bytes >= 0);
        assert!(avail_bytes as usize >= n_bytes);

        let in_slice = unsafe {
            slice::from_raw_parts_mut(
                mut_out.b_wptr as *mut MaybeUninit<u8>,
                n_bytes,
            )
        };

        f(in_slice);

        mut_out.b_wptr = unsafe { mut_out.b_wptr.add(n_bytes) };
    }

    // TODO: I really need to rethink this one in practice.
    // hacked together for POC.
    pub fn extend_if_one(&mut self, other: Self) {
        let mut_self = unsafe { self.inner.as_mut() };
        if !mut_self.b_cont.is_null() {
            panic!("oopsie daisy")
        }

        mut_self.b_cont = other.unwrap_mblk();
    }

    pub fn iter(&self) -> MsgBlkIter {
        MsgBlkIter { curr: Some(self.inner), marker: PhantomData }
    }

    pub fn iter_mut(&mut self) -> MsgBlkIterMut {
        MsgBlkIterMut { curr: Some(self.inner), marker: PhantomData }
    }

    pub fn as_pkt(self) -> Packet<Initialized> {
        unsafe { Packet::wrap_mblk(self.unwrap_mblk()).expect("already good.") }
    }

    /// Return the pointer address of the underlying mblk_t.
    ///
    /// NOTE: This is purely to allow passing the pointer value up to
    /// DTrace so that the mblk can be inspected (read only) in probe
    /// context.
    pub fn mblk_addr(&self) -> uintptr_t {
        self.inner.as_ptr() as uintptr_t
    }

    pub fn unwrap_mblk(self) -> *mut mblk_t {
        let ptr_out = self.inner.as_ptr();
        _ = ManuallyDrop::new(self);
        ptr_out
    }

    pub unsafe fn wrap_mblk(ptr: *mut mblk_t) -> Option<Self> {
        let inner = NonNull::new(ptr)?;

        Some(Self { inner })
    }
}

#[derive(Debug)]
pub struct MsgBlkIter<'a> {
    curr: Option<NonNull<mblk_t>>,
    marker: PhantomData<&'a MsgBlk>,
}

#[derive(Debug)]
pub struct MsgBlkIterMut<'a> {
    curr: Option<NonNull<mblk_t>>,
    marker: PhantomData<&'a mut MsgBlk>,
}

impl<'a> MsgBlkIterMut<'a> {
    ///
    pub fn next_iter(&self) -> MsgBlkIter {
        let curr = self
            .curr
            .and_then(|ptr| NonNull::new(unsafe { ptr.as_ref() }.b_cont));
        MsgBlkIter { curr, marker: PhantomData }
    }

    pub fn next_iter_mut(&mut self) -> MsgBlkIterMut {
        let curr = self
            .curr
            .and_then(|ptr| NonNull::new(unsafe { ptr.as_ref() }.b_cont));
        MsgBlkIterMut { curr, marker: PhantomData }
    }
}

impl<'a> Iterator for MsgBlkIter<'a> {
    type Item = &'a MsgBlkNode;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(ptr) = self.curr {
            self.curr = NonNull::new(unsafe { (*ptr.as_ptr()).b_cont });
            // SAFETY: MsgBlkNode is identical to mblk_t.
            unsafe { Some(&*(ptr.as_ptr() as *const MsgBlkNode)) }
        } else {
            None
        }
    }
}

impl<'a> Read for MsgBlkIter<'a> {
    type Chunk = &'a [u8];

    fn next_chunk(&mut self) -> ingot::types::ParseResult<Self::Chunk> {
        self.next().ok_or(IngotParseErr::TooSmall).map(|v| v.as_ref())
    }
}

impl<'a> Iterator for MsgBlkIterMut<'a> {
    type Item = &'a mut MsgBlkNode;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(ptr) = self.curr {
            self.curr = NonNull::new(unsafe { (*ptr.as_ptr()).b_cont });
            // SAFETY: MsgBlkNode is identical to mblk_t.
            unsafe { Some(&mut *(ptr.as_ptr() as *mut MsgBlkNode)) }
        } else {
            None
        }
    }
}

impl<'a> Read for MsgBlkIterMut<'a> {
    type Chunk = &'a mut [u8];

    fn next_chunk(&mut self) -> ingot::types::ParseResult<Self::Chunk> {
        self.next().ok_or(IngotParseErr::TooSmall).map(|v| v.as_mut())
    }
}

impl Drop for MsgBlk {
    fn drop(&mut self) {
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                unsafe { ddi::freemsg(self.inner.as_ptr()) };
            } else {
                // mock_freemsg(self.inner.as_ptr());
            }
        }
    }
}

pub struct OpteUnified<Q: ByteSlice> {
    pub outer_eth: Option<EthernetPacket<Q>>,
    pub outer_v6: Option<L3<Q>>,
    pub outer_udp: Option<UdpPacket<Q>>,
    pub outer_encap: Option<GenevePacket<Q>>,

    pub inner_eth: EthernetPacket<Q>,
    pub inner_l3: Option<L3<Q>>,
    pub inner_ulp: Option<Ulp<Q>>,
}

pub struct OpteUnifiedLengths {
    pub outer_eth: usize,
    pub outer_l3: usize,
    pub outer_encap: usize,

    pub inner_eth: usize,
    pub inner_l3: usize,
    pub inner_ulp: usize,
}

// TODO: Choices (L3, etc.) don't have Debug in all the right places yet.
impl<Q: ByteSlice> core::fmt::Debug for OpteUnified<Q> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OpteUnified{ .. }")
    }
}

// THIS IS THE GOAL.

// pub struct OpteUnified3 {
//     pub outer_eth: Weird<Ethernet, ValidEthernet<&[u8]>>,
//     pub outer_v6: Weird<IpPush, L3<&[u8]>>,
//     pub outer_encap: Weird<EncapPush, EncapMeta<&[u8]>>,

//     pub inner_eth: EthernetPacket<&[u8]>,
//     pub inner_l3: Option<L3<&[u8]>>,
//     pub inner_ulp: Option<Ulp<&[u8]>>,
// }

// IDEA: anything can take an encap push which is Into<..> its meta
// type. Modification is another trait.
pub enum Weird<Compact, T> {
    Absent,
    LocalForm(Compact),
    Packeted(T),
}

impl<X, T> From<Option<T>> for Weird<X, T> {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(val) => Self::Packeted(val),
            None => Self::Absent,
        }
    }
}

pub enum EncapMeta<B: ByteSlice> {
    Geneve(UdpPacket<B>, GenevePacket<B>),
}

impl<Q: ByteSlice> From<OpteIn<Q>> for OpteUnified<Q> {
    fn from(value: OpteIn<Q>) -> Self {
        Self {
            outer_eth: Some(value.outer_eth),
            outer_v6: Some(L3::Ipv6(value.outer_v6)),
            outer_udp: Some(value.outer_udp),
            outer_encap: Some(value.outer_encap),
            inner_eth: value.inner_eth,
            inner_l3: Some(value.inner_l3),
            inner_ulp: Some(value.inner_ulp),
        }
    }
}

impl<Q: ByteSlice> From<OpteOut<Q>> for OpteUnified<Q> {
    fn from(value: OpteOut<Q>) -> Self {
        Self {
            outer_eth: None,
            outer_v6: None,
            outer_udp: None,
            outer_encap: None,
            inner_eth: value.inner_eth,
            inner_l3: value.inner_l3,
            inner_ulp: value.inner_ulp,
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
            unsafe { Box::from_raw(ptr) };
        }
    }
}

impl<T: Read> PktBodyWalker<T> {
    fn reify_body_segs(&self)
    where
        <T as Read>::Chunk: ByteSlice,
    {
        if let Some((first, mut rest)) = self.base.take() {
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
            if let Some(ref chunk) = first {
                let as_bytes = chunk.deref();
                to_hold.push(unsafe { core::mem::transmute(as_bytes) });
            }
            while let Ok(chunk) = rest.next_chunk() {
                to_hold.push(unsafe { core::mem::transmute(chunk.deref()) });
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
        T::Chunk: ByteSlice,
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

pub struct PacketHeaders<T: Read> {
    headers: OpteUnified<T::Chunk>,
    initial_lens: OpteUnifiedLengths,
    body: PktBodyWalker<T>,
}

impl<T: Read> From<IngotParsed<OpteUnified<T::Chunk>, T>> for PacketHeaders<T> {
    fn from(value: IngotParsed<OpteUnified<T::Chunk>, T>) -> Self {
        let IngotParsed { stack: HeaderStack(headers), data, last_chunk } =
            value;
        let initial_lens = OpteUnifiedLengths {
            outer_eth: headers.outer_eth.packet_length(),
            outer_l3: headers.outer_v6.packet_length(),
            outer_encap: headers.outer_udp.packet_length()
                + headers.outer_encap.packet_length(),
            inner_eth: headers.inner_eth.packet_length(),
            inner_l3: headers.inner_l3.packet_length(),
            inner_ulp: headers.inner_ulp.packet_length(),
        };
        let body = PktBodyWalker {
            base: Some((last_chunk, data)).into(),
            slice: Default::default(),
        };
        Self { headers, initial_lens, body }
    }
}

impl<T: Read> core::fmt::Debug for PacketHeaders<T> {
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

impl<T: Read> PacketHeaders<T> {
    pub fn outer_ether(&self) -> Option<&EthernetPacket<T::Chunk>> {
        self.headers.outer_eth.as_ref()
    }

    pub fn inner_ether(&self) -> &EthernetPacket<T::Chunk> {
        &self.headers.inner_eth
    }

    pub fn inner_l3(&self) -> Option<&ingot::example_chain::L3<T::Chunk>> {
        self.headers.inner_l3.as_ref()
    }

    pub fn inner_ulp(&self) -> Option<&ingot::example_chain::Ulp<T::Chunk>> {
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

    pub fn body_segs(&self) -> &[&[u8]] {
        self.body.body_segs()
    }

    pub fn copy_remaining(&self) -> Vec<u8> {
        let base = self.body_segs();
        let len = base.iter().map(|v| v.len()).sum();
        let mut out = Vec::with_capacity(len);
        for el in base {
            out.extend_from_slice(el);
        }
        out
    }

    pub fn append_remaining(&self, buf: &mut Vec<u8>) {
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
}

fn actual_src_port<T: ByteSlice>(
    chunk: &ingot::example_chain::Ulp<T>,
) -> Option<u16> {
    match chunk {
        Ulp::Tcp(pkt) => Some(pkt.source()),
        Ulp::Udp(pkt) => Some(pkt.source()),
        _ => None,
    }
}

fn actual_dst_port<T: ByteSlice>(
    chunk: &ingot::example_chain::Ulp<T>,
) -> Option<u16> {
    match chunk {
        Ulp::Tcp(pkt) => Some(pkt.destination()),
        Ulp::Udp(pkt) => Some(pkt.destination()),
        _ => None,
    }
}

fn pseudo_port<T: ByteSlice>(
    chunk: &ingot::example_chain::Ulp<T>,
) -> Option<u16> {
    match chunk {
        Ulp::IcmpV4(pkt)
            if pkt.code() == 0 && (pkt.ty() == 0 || pkt.ty() == 8) =>
        {
            Some(u16::from_be_bytes(pkt.rest_of_hdr()[..2].try_into().unwrap()))
        }
        Ulp::IcmpV6(pkt)
            if pkt.code() == 0 && (pkt.ty() == 128 || pkt.ty() == 129) =>
        {
            Some(u16::from_be_bytes(pkt.rest_of_hdr()[..2].try_into().unwrap()))
        }
        _ => None,
    }
}

impl<T: Read> From<&PacketHeaders<T>> for InnerFlowId {
    fn from(meta: &PacketHeaders<T>) -> Self {
        let (proto, addrs) = match meta.inner_l3() {
            Some(L3::Ipv4(pkt)) => (
                pkt.protocol().0,
                AddrPair::V4 {
                    src: pkt.source().into(),
                    dst: pkt.destination().into(),
                },
            ),
            Some(L3::Ipv6(pkt)) => (
                pkt.next_header().0,
                AddrPair::V6 {
                    src: pkt.source().into(),
                    dst: pkt.destination().into(),
                },
            ),
            None => (255, FLOW_ID_DEFAULT.addrs),
        };

        let (src_port, dst_port) = meta
            .inner_ulp()
            .map(|ulp| {
                (
                    actual_src_port(ulp)
                        .or_else(|| pseudo_port(ulp))
                        .unwrap_or(0),
                    actual_dst_port(ulp)
                        .or_else(|| pseudo_port(ulp))
                        .unwrap_or(0),
                )
            })
            .unwrap_or((0, 0));

        InnerFlowId { proto: proto.into(), addrs, src_port, dst_port }
    }
}

fn transform_parse_stage1<S, P: Read, S2: From<S>>(
    p: IngotParsed<S, P>,
) -> IngotParsed<S2, P> {
    IngotParsed {
        stack: HeaderStack(S2::from(p.stack.0)),
        data: p.data,
        last_chunk: p.last_chunk,
    }
}

// GOAL: get to an absolute minimum point where we:
// - parse into an innerflowid
// - use existing transforms if a ULP entry exists.
#[derive(Debug)]
pub struct Packet2<S: PacketState> {
    state: S,
}

impl<T: Read + QueryLen> Packet2<Initialized2<T>> {
    pub fn new(pkt: T) -> Self
    where
        Initialized2<T>: PacketState,
    {
        let len = pkt.len();
        Self { state: Initialized2 { len, inner: pkt } }
    }
}

impl<T: Read> Packet2<Initialized2<T>> {
    pub fn parse(
        self,
        dir: Direction,
        net: impl NetworkParser,
    ) -> Result<Packet2<Parsed2<T>>, ParseError> {
        let Packet2 { state: Initialized2 { len, inner } } = self;
        let mut meta = match dir {
            Direction::Out => net.parse_outbound(inner)?,
            Direction::In => net.parse_inbound(inner)?,
        };

        let flow = (&meta).into();

        let body_csum = match (&meta.headers).inner_eth.ethertype() {
            Ethertype::ARP => Memoised::Known(None),
            Ethertype::IPV4 | Ethertype::IPV6 => Memoised::Uninit,
            _ => return Err(IngotParseErr::Unwanted.into()),
        };

        let state = Parsed2 {
            meta,
            flow,
            body_csum,
            l4_hash: Memoised::Uninit,
            body_modified: false,
            len,
        };

        Ok(Packet2 { state })
    }
}

impl<T: Read> Packet2<Parsed2<T>> {
    pub fn meta(&self) -> &PacketHeaders<T> {
        &self.state.meta
    }

    pub fn meta_mut(&mut self) -> &mut PacketHeaders<T> {
        &mut self.state.meta
    }

    pub fn emit_spec(&self) -> EmitSpec {
        todo!()
    }

    pub fn len(&self) -> usize {
        self.state.len
    }

    pub fn flow(&self) -> &InnerFlowId {
        &self.state.flow
    }

    /// Run the [`HdrTransform`] against this packet.
    #[inline]
    pub fn hdr_transform(
        &mut self,
        xform: &HdrTransform,
    ) -> Result<(), HdrTransformError> {
        xform.run(&mut self.state.meta)?;
        // Given that n_transform layers is 1 or 2, probably won't
        // save too much by trying to tie to a generation number.
        // TODO: profile.
        self.state.flow = InnerFlowId::from(self.meta());
        Ok(())
    }

    /// Run the [`BodyTransform`] against this packet.
    pub fn body_transform(
        &mut self,
        dir: Direction,
        xform: &dyn BodyTransform,
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

    #[inline]
    pub fn body_segs(&self) -> Option<&[&[u8]]> {
        // TODO. Not needed for today's d'plane.
        None
    }

    #[inline]
    pub fn body_segs_mut(&mut self) -> Option<&mut [&mut [u8]]> {
        // TODO. Not needed for today's d'plane.
        None
    }

    pub fn mblk_addr(&self) -> uintptr_t {
        // TODO.
        0
    }

    pub fn body_csum(&mut self) -> Option<Checksum> {
        *self.state.body_csum.get(|| {
            let use_pseudo = if let Some(v) = self.state.meta.inner_ulp() {
                !matches!(v, Ulp::IcmpV4(_))
            } else {
                false
            };

            // XXX TODO: make these valid even AFTER all packet pushings occur.
            let pseudo_csum = match (&self.state.meta.headers)
                .inner_eth
                .ethertype()
            {
                // ARP
                Ethertype::ARP => {
                    return None;
                }
                // Ipv4
                Ethertype::IPV4 => {
                    let h = &self.state.meta.headers;
                    let mut pseudo_hdr_bytes = [0u8; 12];
                    let Some(L3::Ipv4(ref v4)) = h.inner_l3 else { panic!() };
                    pseudo_hdr_bytes[0..4]
                        .copy_from_slice(&v4.source().octets());
                    pseudo_hdr_bytes[4..8]
                        .copy_from_slice(&v4.destination().octets());
                    pseudo_hdr_bytes[9] = v4.protocol().0;
                    let ulp_len = v4.total_len() - 4 * (v4.ihl() as u16);
                    pseudo_hdr_bytes[10..]
                        .copy_from_slice(&ulp_len.to_be_bytes());

                    Checksum::compute(&pseudo_hdr_bytes)
                }
                // Ipv6
                Ethertype::IPV6 => {
                    let h = &self.state.meta.headers;
                    let mut pseudo_hdr_bytes = [0u8; 40];
                    let Some(L3::Ipv6(ref v6)) = h.inner_l3 else { panic!() };
                    pseudo_hdr_bytes[0..16]
                        .copy_from_slice(&v6.source().octets());
                    pseudo_hdr_bytes[16..32]
                        .copy_from_slice(&v6.destination().octets());
                    pseudo_hdr_bytes[39] = v6.next_header().0;
                    let ulp_len = v6.payload_len() as u32;
                    pseudo_hdr_bytes[32..36]
                        .copy_from_slice(&ulp_len.to_be_bytes());
                    Checksum::compute(&pseudo_hdr_bytes)
                }
                _ => unreachable!(),
            };

            self.state.meta.inner_ulp().and_then(csum_minus_hdr).map(|mut v| {
                if use_pseudo {
                    v -= pseudo_csum;
                }
                v
            })
        })
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
}

/// The type state of a packet that has been initialized and allocated, but
/// about which nothing else is known besides the length.
#[derive(Debug)]
pub struct Initialized2<T: Read> {
    // Total length of packet, in bytes. This is equal to the sum of
    // the length of the _initialized_ window in all the segments
    // (`b_wptr - b_rptr`).
    len: usize,

    inner: T,
}

impl<T: Read> PacketState for Initialized2<T> {}
impl<T: Read> PacketState for Parsed2<T> {}

/// Zerocopy view onto a parsed packet, acompanied by locally
/// computed state.
pub struct Parsed2<T: Read> {
    len: usize,
    meta: PacketHeaders<T>,
    flow: InnerFlowId,
    body_csum: Memoised<Option<Checksum>>,
    l4_hash: Memoised<u32>,
    body_modified: bool,
}

// Needed for now to account for not wanting to redesign ActionDescs
// to be generic over T (trait object safety rules, etc.).
pub type PacketMeta3<'a> = Parsed2<MsgBlkIterMut<'a>>;
pub type PacketHeaders2<'a> = PacketHeaders<MsgBlkIterMut<'a>>;

pub type InitMblk<'a> = Initialized2<MsgBlkIterMut<'a>>;
pub type ParsedMblk<'a> = Parsed2<MsgBlkIterMut<'a>>;

fn csum_minus_hdr<V: ByteSlice>(ulp: &Ulp<V>) -> Option<Checksum> {
    match ulp {
        Ulp::IcmpV4(icmp) => {
            if icmp.checksum() == 0 {
                return None;
            }

            let mut csum = OpteCsum::from(HeaderChecksum::wrap(
                icmp.checksum().to_be_bytes(),
            ));

            csum.sub_bytes(&[icmp.code(), icmp.ty()]);
            csum.sub_bytes(icmp.rest_of_hdr_ref());

            Some(csum)
        }
        Ulp::IcmpV6(icmp) => {
            if icmp.checksum() == 0 {
                return None;
            }

            let mut csum = OpteCsum::from(HeaderChecksum::wrap(
                icmp.checksum().to_be_bytes(),
            ));

            csum.sub_bytes(&[icmp.code(), icmp.ty()]);
            csum.sub_bytes(icmp.rest_of_hdr_ref());

            Some(csum)
        }
        Ulp::Tcp(tcp) => {
            if tcp.checksum() == 0 {
                return None;
            }

            let mut csum = OpteCsum::from(HeaderChecksum::wrap(
                tcp.checksum().to_be_bytes(),
            ));

            let TcpPacket::Raw(t) = tcp else {
                panic!("hmm... maybe one day.")
            };

            let b = t.0.as_bytes();

            csum.sub_bytes(&b[0..16]);
            csum.sub_bytes(&b[18..]);

            // TODO: bad bound?
            // csum.sub_bytes(t.1.as_ref());
            csum.sub_bytes(match &t.1 {
                ingot::types::Packet::Repr(v) => &v[..],
                ingot::types::Packet::Raw(v) => &v[..],
            });

            Some(csum)
        }
        Ulp::Udp(udp) => {
            if udp.checksum() == 0 {
                return None;
            }

            let mut csum = OpteCsum::from(HeaderChecksum::wrap(
                udp.checksum().to_be_bytes(),
            ));

            let UdpPacket::Raw(t) = udp else {
                panic!("hmm... maybe one day.")
            };

            let b = t.0.as_bytes();
            csum.sub_bytes(&b[0..6]);

            Some(csum)
        }
    }
}

trait QueryLen {
    fn len(&self) -> usize;
}

impl<'a> QueryLen for MsgBlkIterMut<'a> {
    fn len(&self) -> usize {
        let own_blk_len = self
            .curr
            .map(|v| unsafe {
                let v = v.as_ref();
                v.b_wptr.offset_from(v.b_rptr) as usize
            })
            .unwrap_or_default();

        own_blk_len + self.next_iter().map(|v| v.len()).sum::<usize>()
    }
}

pub enum Emitter<T> {
    Repr(Box<T>),
    Cached(Arc<[u8]>),
}

// TODO: don't really care about pushing 'inner' reprs today.
pub struct OpteEmit {
    outer_eth: Emitter<Ethernet>,
    outer_ip: Emitter<L3Repr>,
    outer_encap: Emitter<(Udp, Geneve)>,
}

pub struct EmitSpec {
    pub rewind: usize,
    pub push_spec: OpteEmit,
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Default)]
pub enum Memoised<T> {
    #[default]
    Uninit,
    Known(T),
}

impl<T> Memoised<T> {
    pub fn get(&mut self, or: impl FnOnce() -> T) -> &T {
        if self.try_get().is_none() {
            self.set(or());
        }

        self.try_get().unwrap()
    }

    pub fn try_get(&self) -> Option<&T> {
        match self {
            Memoised::Uninit => None,
            Memoised::Known(v) => Some(v),
        }
    }

    pub fn set(&mut self, val: T) {
        *self = Self::Known(val);
    }
}

impl<B: ByteSlice> QueryEcho for IcmpV4Packet<B> {
    fn echo_id(&self) -> Option<u16> {
        match (self.code(), self.ty()) {
            (0, 0) | (0, 8) => Some(u16::from_be_bytes(
                self.rest_of_hdr()[..2].try_into().unwrap(),
            )),
            _ => None,
        }
    }
}

impl<B: ByteSlice> QueryEcho for IcmpV6Packet<B> {
    fn echo_id(&self) -> Option<u16> {
        match (self.code(), self.ty()) {
            (0, 128) | (0, 129) => Some(u16::from_be_bytes(
                self.rest_of_hdr()[..2].try_into().unwrap(),
            )),
            _ => None,
        }
    }
}
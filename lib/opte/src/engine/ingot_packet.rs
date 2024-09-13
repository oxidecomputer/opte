use super::checksum::Checksum as OpteCsum;
use super::checksum::Checksum;
use super::checksum::HeaderChecksum;
use super::ether::EtherMeta;
use super::ether::EtherMod;
use super::geneve::GeneveMeta;
use super::headers::EncapMeta;
use super::headers::EncapMod;
use super::headers::EncapPush;
use super::headers::HasInnerCksum;
use super::headers::HeaderActionError;
use super::headers::HeaderActionModify;
use super::headers::IpMeta;
use super::headers::IpMod;
use super::headers::IpPush;
use super::headers::PushAction;
use super::headers::UlpMetaModify;
use super::headers::UlpMod;
use super::icmp::QueryEcho;
use super::ingot_base::Ethernet;
use super::ingot_base::EthernetMut;
use super::ingot_base::EthernetPacket;
use super::ingot_base::EthernetRef;
use super::ingot_base::Ipv4;
use super::ingot_base::Ipv4Mut;
use super::ingot_base::Ipv4Packet;
use super::ingot_base::Ipv4Ref;
use super::ingot_base::Ipv6;
use super::ingot_base::Ipv6Mut;
use super::ingot_base::Ipv6Packet;
use super::ingot_base::Ipv6Ref;
use super::ingot_base::L3Repr;
use super::ingot_base::Ulp;
use super::ingot_base::UlpRepr;
use super::ingot_base::ValidEthernet;
use super::ingot_base::ValidIpv6;
use super::ingot_base::ValidL3;
use super::ingot_base::ValidUlp;
use super::ingot_base::L3;
use super::ingot_base::L4;
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
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
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
#[cfg(all(not(feature = "std"), not(test)))]
use illumos_sys_hdrs as ddi;
use illumos_sys_hdrs::mblk_t;
use illumos_sys_hdrs::uintptr_t;
use ingot::ethernet::Ethertype;
use ingot::geneve::Geneve;
use ingot::geneve::GeneveMut;
use ingot::geneve::GenevePacket;
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
use ingot::ip::LowRentV6EhRepr;
use ingot::tcp::TcpFlags;
use ingot::tcp::TcpMut;
use ingot::tcp::TcpPacket;
use ingot::tcp::TcpRef;
use ingot::types::primitives::*;
use ingot::types::DirectPacket;
use ingot::types::Emit;
use ingot::types::Header;
use ingot::types::HeaderStack;
use ingot::types::IndirectPacket;
use ingot::types::NextLayer;
use ingot::types::Packet as IngotPacket;
use ingot::types::ParseControl;
use ingot::types::ParseError as IngotParseErr;
use ingot::types::ParseResult;
use ingot::types::Parsed as IngotParsed;
use ingot::types::Read;
use ingot::types::Repeated;
use ingot::udp::Udp;
use ingot::udp::UdpMut;
use ingot::udp::UdpPacket;
use ingot::udp::UdpRef;
use ingot::udp::ValidUdp;
use ingot::Parse;
use opte_api::Direction;
use opte_api::Ipv4Addr;
use opte_api::Ipv6Addr;
use opte_api::Vni;
use zerocopy::ByteSlice;
use zerocopy::ByteSliceMut;
use zerocopy::IntoBytes;

#[derive(Parse)]
pub struct GeneveOverV6<Q: ByteSlice> {
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
pub struct NoEncap<Q: ByteSlice> {
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

    pub fn headroom(&self) -> usize {
        unsafe {
            let inner = self.inner.as_ref();

            inner.b_rptr.offset_from((*inner.b_datap).db_base) as usize
        }
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

    pub unsafe fn write_front(
        &mut self,
        n_bytes: usize,
        f: impl FnOnce(&mut [MaybeUninit<u8>]),
    ) {
        let mut_out = unsafe { self.inner.as_mut() };
        let avail_bytes =
            unsafe { mut_out.b_rptr.offset_from((*mut_out.b_datap).db_base) };

        assert!(avail_bytes >= 0);
        assert!(avail_bytes as usize >= n_bytes);

        let new_head = unsafe { mut_out.b_rptr.sub(n_bytes) };

        let in_slice = unsafe {
            slice::from_raw_parts_mut(new_head as *mut MaybeUninit<u8>, n_bytes)
        };

        f(in_slice);

        mut_out.b_rptr = new_head;
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

    /// Drop all bytes and move the cursor to the very back of the dblk.
    pub fn pop_all(&mut self) {
        unsafe {
            (*self.inner.as_ptr()).b_rptr =
                (*(*self.inner.as_ptr()).b_datap).db_lim;
            (*self.inner.as_ptr()).b_wptr =
                (*(*self.inner.as_ptr()).b_datap).db_lim;
        }
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

// TODO: Choices (L3, etc.) don't have Debug in all the right places yet.
impl<Q: ByteSlice> core::fmt::Debug for OpteUnified<Q> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OpteUnified{ .. }")
    }
}

// THIS IS THE GOAL.

// IE
// pub struct OpteEmit {
//     outer_eth: Option<Ethernet>,
//     outer_ip: Option<L3Repr>,
//     outer_encap: Option<EncapMeta>,

//     // We can (but do not often) push/pop inner meta.
//     // Splitting minimises struct size in the general case.
//     inner: Option<Box<OpteInnerEmit>>,
// }

// pub struct OpteInnerEmit {
//     eth: Ethernet,
//     l3: Option<L3Repr>,
//     ulp: Option<UlpRepr>,
// }

pub enum ValidEncapMeta<B: ByteSlice> {
    Geneve(ValidUdp<B>, ValidGeneve<B>),
}

pub struct OpteMeta<T: ByteSlice> {
    pub outer_eth: Option<DirectPacket<Ethernet, ValidEthernet<T>>>,
    // pub outer_eth: Option<Either<Ethernet, ValidEthernet<&[u8]>>>,
    pub outer_l3: Option<L3<T>>,
    // pub outer_l3: Option<OwnedPacket<L3Repr, ValidL3<T>>>,
    // pub outer_v6: Option<Either<L3Repr, ValidL3<&[u8]>>>,
    pub outer_encap: Option<DirectPacket<EncapMeta, ValidEncapMeta<T>>>,
    // pub outer_encap: Option<Either<EncapMeta, EncapMeta2<&[u8]>>>,
    pub inner_eth: EthernetPacket<T>,
    pub inner_l3: Option<L3<T>>,
    pub inner_ulp: Option<Ulp<T>>,
}

pub type Test = OpteMeta<&'static [u8]>;

pub type OpteParsed<T> = IngotParsed<OpteMeta<<T as Read>::Chunk>, T>;

impl<T: ByteSlice> OpteMeta<T> {
    #[inline]
    pub fn convert_ingot<U: Into<Self>, Q: Read<Chunk = T>>(
        value: IngotParsed<U, Q>,
    ) -> OpteParsed<Q> {
        let IngotParsed { stack: HeaderStack(headers), data, last_chunk } =
            value;

        IngotParsed { stack: HeaderStack(headers.into()), data, last_chunk }
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

impl<'a> Header for SizeHoldingEncap<'a> {
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
                (
                    Udp {
                        source: g.entropy,
                        destination: 6081,
                        // TODO: account for options.
                        length: self.encapped_len + 16,
                        ..Default::default()
                    },
                    Geneve {
                        protocol_type: Ethertype::ETHERNET,
                        vni: g.vni,
                        ..Default::default()
                    },
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
            ValidEncapMeta::Geneve(u, g) => todo!(),
        }
    }

    #[inline]
    fn needs_emit(&self) -> bool {
        match self {
            ValidEncapMeta::Geneve(u, g) => u.needs_emit() && g.needs_emit(),
        }
    }
}

impl Header for EncapMeta {
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

impl<B: ByteSlice> Header for ValidEncapMeta<B> {
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

impl<Q: ByteSlice> From<GeneveOverV6<Q>> for OpteUnified<Q> {
    #[inline]
    fn from(value: GeneveOverV6<Q>) -> Self {
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

impl<Q: ByteSlice> From<NoEncap<Q>> for OpteUnified<Q> {
    #[inline]
    fn from(value: NoEncap<Q>) -> Self {
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

pub struct PacketHeaders<T: Read> {
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

impl<T: ByteSlice> From<GeneveOverV6<T>> for OpteMeta<T> {
    #[inline]
    fn from(value: GeneveOverV6<T>) -> Self {
        // These are practically all Valid, anyhow.
        let outer_encap = match (value.outer_udp, value.outer_encap) {
            (ingot::types::Packet::Raw(u), ingot::types::Packet::Raw(g)) => {
                Some(DirectPacket::Raw(ValidEncapMeta::Geneve(u, g)))
            }
            _ => todo!(),
        };

        // let outer_l3 = match value.outer_v6 {
        //     ingot::types::Packet::Repr(v) => {
        //         Some(DirectPacket::Repr(L3Repr::Ipv6(*v)))
        //     }
        //     ingot::types::Packet::Raw(v) => {
        //         Some(DirectPacket::Raw(ValidL3::Ipv6(v)))
        //     }
        // };

        let outer_l3 = Some(L3::Ipv6(value.outer_v6));

        OpteMeta {
            outer_eth: Some(value.outer_eth.into()),
            outer_l3,
            outer_encap,
            inner_eth: value.inner_eth,
            inner_l3: Some(value.inner_l3),
            inner_ulp: Some(value.inner_ulp),
        }
    }
}

// impl<T: Read> From<IngotParsed<OpteUnified<T::Chunk>, T>> for PacketHeaders<T> {
//     fn from(value: IngotParsed<OpteUnified<T::Chunk>, T>) -> Self {
//         let IngotParsed { stack: HeaderStack(headers), data, last_chunk } =
//             value;
//         let initial_lens = OpteUnifiedLengths {
//             outer_eth: headers.outer_eth.packet_length(),
//             outer_l3: headers.outer_v6.packet_length(),
//             outer_encap: headers.outer_udp.packet_length()
//                 + headers.outer_encap.packet_length(),
//             inner_eth: headers.inner_eth.packet_length(),
//             inner_l3: headers.inner_l3.packet_length(),
//             inner_ulp: headers.inner_ulp.packet_length(),
//         };
//         let body = PktBodyWalker {
//             base: Some((last_chunk, data)).into(),
//             slice: Default::default(),
//         };
//         Self { headers, initial_lens, body }
//     }
// }

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
    pub fn initial_lens(&self) -> Option<&OpteUnifiedLengths> {
        self.initial_lens.as_ref().map(|v| &**v)
    }

    pub fn outer_ether(
        &self,
    ) -> Option<&DirectPacket<Ethernet, ValidEthernet<T::Chunk>>> {
        self.headers.outer_eth.as_ref()
    }

    // Need to expose this a lil cleaner...
    /// Returns whether this packet is sourced from outside the rack,
    /// in addition to its VNI.
    pub fn outer_encap_geneve_vni_and_origin(&self) -> Option<(Vni, bool)> {
        match &self.headers.outer_encap {
            Some(DirectPacket::Repr(EncapMeta::Geneve(g))) => {
                Some((g.vni, g.oxide_external_pkt))
            }
            Some(DirectPacket::Raw(ValidEncapMeta::Geneve(_, g))) => {
                // TODO: hack.
                let oxide_external = g.1.packet_length() != 0;
                Some((g.vni(), oxide_external))
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

fn actual_src_port<T: ByteSlice>(chunk: &Ulp<T>) -> Option<u16> {
    match chunk {
        Ulp::Tcp(pkt) => Some(pkt.source()),
        Ulp::Udp(pkt) => Some(pkt.source()),
        _ => None,
    }
}

fn actual_dst_port<T: ByteSlice>(chunk: &Ulp<T>) -> Option<u16> {
    match chunk {
        Ulp::Tcp(pkt) => Some(pkt.destination()),
        Ulp::Udp(pkt) => Some(pkt.destination()),
        _ => None,
    }
}

fn pseudo_port<T: ByteSlice>(chunk: &Ulp<T>) -> Option<u16> {
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
    #[inline]
    fn from(meta: &PacketHeaders<T>) -> Self {
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

impl<'a, T: Read + 'a> Packet2<Initialized2<T>>
where
    T::Chunk: ingot::types::IntoBufPointer<'a>,
{
    #[inline]
    pub fn parse(
        self,
        dir: Direction,
        net: impl NetworkParser,
    ) -> Result<Packet2<Parsed2<T>>, ParseError> {
        let Packet2 { state: Initialized2 { len, inner } } = self;
        let IngotParsed { stack: HeaderStack(headers), data, last_chunk } =
            match dir {
                Direction::Out => net.parse_outbound(inner)?,
                Direction::In => net.parse_inbound(inner)?,
            };

        let initial_lens = None;

        let body = PktBodyWalker {
            base: Some((last_chunk, data)).into(),
            slice: Default::default(),
        };

        let meta = Box::new(PacketHeaders { headers, initial_lens, body });

        let flow = (&*meta).into();

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
            inner_csum_dirty: false,
        };

        let mut pkt = Packet2 { state };
        // TODO: we can probably not do this in some cases, but we
        // don't have a way for headeractions to signal that they
        // *may* change the fields we need in the slowpath.
        let _ = pkt.body_csum();

        Ok(pkt)
    }
}

impl<T: Read> Packet2<Parsed2<T>> {
    pub fn meta(&self) -> &PacketHeaders<T> {
        &self.state.meta
    }

    pub fn meta_mut(&mut self) -> &mut PacketHeaders<T> {
        &mut self.state.meta
    }

    pub fn store_lens_for_slopath(&mut self) {
        let headers = &self.state.meta.headers;
        self.state.meta.initial_lens = Some(
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
    }

    #[inline]
    /// Convert a packet's metadata into a set of instructions
    /// needed to serialize all its changes to the wire.
    pub fn emit_spec(self) -> EmitSpec
    where
        T::Chunk: ByteSliceMut,
    {
        // Roughly how does this work:
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

        use ingot::types::DirectPacket;

        match headers.inner_ulp {
            Some(ulp) => {
                let l = ulp.packet_length();
                encapped_len += l;

                if ulp.needs_emit() || l != init_lens.inner_ulp {
                    let inner =
                        push_spec.inner.get_or_insert_with(Default::default);
                    // TODO: impl DirectPacket / From<&Ulp> for UlpRepr here? generally seems a bit anaemic.
                    inner.ulp = Some(match ulp {
                        Ulp::Tcp(IngotPacket::Repr(t)) => UlpRepr::Tcp(*t),
                        Ulp::Tcp(IngotPacket::Raw(t)) => {
                            UlpRepr::Tcp((&t).into())
                        }
                        Ulp::Udp(IngotPacket::Repr(t)) => UlpRepr::Udp(*t),
                        Ulp::Udp(IngotPacket::Raw(t)) => {
                            UlpRepr::Udp((&t).into())
                        }
                        Ulp::IcmpV4(IngotPacket::Repr(t)) => {
                            UlpRepr::IcmpV4(*t)
                        }
                        Ulp::IcmpV4(IngotPacket::Raw(t)) => {
                            UlpRepr::IcmpV4((&t).into())
                        }
                        Ulp::IcmpV6(IngotPacket::Repr(t)) => {
                            UlpRepr::IcmpV6(*t)
                        }
                        Ulp::IcmpV6(IngotPacket::Raw(t)) => {
                            UlpRepr::IcmpV6((&t).into())
                        }
                    });
                    // inner.ulp = Some((&ulp).into());
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
                        L3::Ipv4(IngotPacket::Repr(v4)) => L3Repr::Ipv4(*v4),
                        L3::Ipv4(IngotPacket::Raw(v4)) => {
                            L3Repr::Ipv4((&v4).into())
                        }
                        L3::Ipv6(IngotPacket::Repr(v6)) => L3Repr::Ipv6(*v6),

                        // This needs a fuller DirectPacket due to EHs...
                        // We can't actually do structural mods here today using OPTE.
                        L3::Ipv6(IngotPacket::Raw(v6)) => todo!(), // L3Repr::Ipv6((&v6).into()),
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
                IngotPacket::Repr(p) => *p,
                IngotPacket::Raw(p) => (&p).into(),
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
                    DirectPacket::Repr(o) => o,
                    // Needed in fullness of time, but not here.
                    DirectPacket::Raw(_) => todo!(),
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
                // push_spec.outer_ip = Some(match l3 {
                //     DirectPacket::Repr(o) => o,
                //     // Needed in fullness of time, but not here.
                //     DirectPacket::Raw(_) => todo!(),
                // });
                push_spec.outer_ip = Some(match l3 {
                    L3::Ipv6(IndirectPacket::Repr(o)) => L3Repr::Ipv6(*o),
                    L3::Ipv4(IndirectPacket::Repr(o)) => L3Repr::Ipv4(*o),
                    _ => todo!(),
                });

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
                    DirectPacket::Repr(o) => o,
                    // Needed in fullness of time, but not here.
                    DirectPacket::Raw(_) => todo!(),
                });

                force_serialize = true;
                rewind += init_lens.outer_eth;
            }
            None if init_lens.outer_eth != 0 => {
                force_serialize = true;
                rewind += init_lens.outer_eth;
            }
            _ => {}
        }

        EmitSpec {
            rewind: rewind as u16,
            payload_len: payload_len as u16,
            encapped_len: encapped_len as u16,
            push_spec,
        }
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
        // Given that n_transform layers is 1 or 2, probably won't
        // save too much by trying to tie to a generation number.
        // TODO: profile.
        // self.state.flow = InnerFlowId::from(self.meta());
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

    pub fn body_csum(&mut self) -> Option<Checksum> {
        let out = *self.state.body_csum.get(|| {
            let use_pseudo = if let Some(v) = self.state.meta.inner_ulp() {
                !matches!(v, Ulp::IcmpV4(_))
            } else {
                false
            };

            // XXX TODO: make these valid even AFTER all packet pushings occur.
            let pseudo_csum =
                match (&self.state.meta.headers).inner_eth.ethertype() {
                    // ARP
                    Ethertype::ARP => {
                        return None;
                    }
                    Ethertype::IPV4 | Ethertype::IPV6 => self
                        .state
                        .meta
                        .headers
                        .inner_l3
                        .as_ref()
                        .map(l3_pseudo_header),
                    _ => unreachable!(),
                };

            let Some(pseudo_csum) = pseudo_csum else {
                return None;
            };

            self.state.meta.inner_ulp().and_then(csum_minus_hdr).map(|mut v| {
                if use_pseudo {
                    v -= pseudo_csum;
                }
                v
            })
        });

        // let mut manual = Checksum::default();
        // if let Some(segs) = self.body_segs() {
        //     for seg in segs {
        //         manual.add_bytes(*seg);
        //     }

        //     opte::engine::err!("think my csum is {:?}, reality is {:?}", out.map(|mut v| v.finalize()), manual.finalize());
        // }

        out
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
        if !self.state.inner_csum_dirty {
            return;
        }
        let update_ip = self.state.meta.has_ip_csum();
        let update_ulp = self.state.meta.has_ulp_csum();

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
            let pseudo_csum = l3_pseudo_header(ip);
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
                    i4.set_checksum(body_csum.finalize());
                }
                Ulp::IcmpV6(i6) => {
                    let mut bytes = [0u8; 8];
                    i6.set_checksum(0);
                    i6.emit_raw(&mut bytes[..]);
                    csum.add_bytes(&bytes[..]);
                    i6.set_checksum(csum.finalize());
                }
                Ulp::Tcp(tcp) => {
                    tcp.set_checksum(0);
                    match tcp {
                        IngotPacket::Repr(tcp) => {
                            let mut bytes = [0u8; 56];
                            tcp.emit_raw(&mut bytes[..]);
                            csum.add_bytes(&bytes[..]);
                        }
                        IngotPacket::Raw(tcp) => {
                            csum.add_bytes(tcp.0.as_bytes());
                            match &tcp.1 {
                                IngotPacket::Repr(opts) => {
                                    csum.add_bytes(&*opts);
                                }
                                IngotPacket::Raw(opts) => {
                                    csum.add_bytes(&*opts);
                                }
                            }
                        }
                    }
                    tcp.set_checksum(csum.finalize());
                }
                Ulp::Udp(udp) => {
                    udp.set_checksum(0);
                    match udp {
                        IngotPacket::Repr(udp) => {
                            let mut bytes = [0u8; 8];
                            udp.emit_raw(&mut bytes[..]);
                            csum.add_bytes(&bytes[..]);
                        }
                        IngotPacket::Raw(udp) => {
                            csum.add_bytes(udp.0.as_bytes());
                        }
                    }
                    udp.set_checksum(csum.finalize());
                }
            }
        }

        // Compute and fill in the IPv4 header checksum.
        if let (true, Some(L3::Ipv4(ip))) =
            (update_ip, &mut self.state.meta.headers.inner_l3)
        {
            ip.set_checksum(0);

            let mut csum = Checksum::default();

            match ip {
                IngotPacket::Repr(ip) => {
                    let mut bytes = [0u8; 56];
                    ip.emit_raw(&mut bytes[..]);
                    csum.add_bytes(&bytes[..]);
                }
                IngotPacket::Raw(ip) => {
                    csum.add_bytes(ip.0.as_bytes());
                    match &ip.1 {
                        IngotPacket::Repr(opts) => {
                            csum.add_bytes(&*opts);
                        }
                        IngotPacket::Raw(opts) => {
                            csum.add_bytes(&*opts);
                        }
                    }
                }
            }

            ip.set_checksum(csum.finalize());
        }
    }
}

fn l3_pseudo_header<T: ByteSlice>(l3: &L3<T>) -> Checksum {
    match l3 {
        L3::Ipv4(v4) => {
            let mut pseudo_hdr_bytes = [0u8; 12];
            pseudo_hdr_bytes[0..4].copy_from_slice(v4.source().as_ref());
            pseudo_hdr_bytes[4..8].copy_from_slice(v4.destination().as_ref());
            pseudo_hdr_bytes[9] = v4.protocol().0;
            let ulp_len = v4.total_len() - 4 * (v4.ihl() as u16);
            pseudo_hdr_bytes[10..].copy_from_slice(&ulp_len.to_be_bytes());

            Checksum::compute(&pseudo_hdr_bytes)
        }
        L3::Ipv6(v6) => {
            let mut pseudo_hdr_bytes = [0u8; 40];
            pseudo_hdr_bytes[0..16].copy_from_slice(&v6.source().as_ref());
            pseudo_hdr_bytes[16..32]
                .copy_from_slice(&v6.destination().as_ref());
            pseudo_hdr_bytes[39] = v6.next_layer().unwrap_or_default().0;
            let ulp_len = v6.payload_len() as u32;
            pseudo_hdr_bytes[32..36].copy_from_slice(&ulp_len.to_be_bytes());
            Checksum::compute(&pseudo_hdr_bytes)
        }
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
    meta: Box<PacketHeaders<T>>,
    flow: InnerFlowId,
    body_csum: Memoised<Option<Checksum>>,
    l4_hash: Memoised<u32>,
    body_modified: bool,
    inner_csum_dirty: bool,
}

type Quack = Parsed2<MsgBlkIterMut<'static>>;

// Needed for now to account for not wanting to redesign ActionDescs
// to be generic over T (trait object safety rules, etc.).
pub type PacketMeta3<'a> = Parsed2<MsgBlkIterMut<'a>>;
pub type PacketHeaders2<'a> = PacketHeaders<MsgBlkIterMut<'a>>;

pub type InitMblk<'a> = Initialized2<MsgBlkIterMut<'a>>;
pub type ParsedMblk<'a> = Parsed2<MsgBlkIterMut<'a>>;

#[inline]
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
    #[inline]
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
#[derive(Default)]
pub struct OpteEmit {
    outer_eth: Option<Ethernet>,
    outer_ip: Option<L3Repr>,
    outer_encap: Option<EncapMeta>,

    // We can (but do not often) push/pop inner meta.
    // Splitting minimises struct size in the general case.
    inner: Option<Box<OpteInnerEmit>>,
}

#[derive(Default)]
pub struct OpteInnerEmit {
    eth: Ethernet,
    l3: Option<L3Repr>,
    ulp: Option<UlpRepr>,
}

pub struct EmitSpec {
    pub rewind: u16,
    pub encapped_len: u16,
    pub payload_len: u16,
    pub push_spec: OpteEmit,
}

impl EmitSpec {
    #[inline]
    pub fn apply(&mut self, mut pkt: MsgBlk) -> MsgBlk {
        // Rewind
        {
            let mut slots = heapless::Vec::<&mut MsgBlkNode, 6>::new();
            let mut to_rewind = self.rewind as usize;

            if to_rewind > 0 {
                let mut reader = pkt.iter_mut();
                while to_rewind != 0 {
                    let this = reader.next();
                    let Some(node) = this else {
                        to_rewind = 0;
                        break;
                    };

                    let has = node.len();
                    let droppable = to_rewind.min(has);
                    node.drop_front_bytes(droppable);
                    to_rewind -= droppable;

                    slots.push(node).unwrap();
                }
            }

            // TODO: put available layers into said slots?
        }

        // TODO:
        //  - remove all zero-length nodes.
        //  - actually push in to existing slots we rewound past if needed.
        //  - actually support pushing dirty segments apart from the encap.

        let needed_push = self.push_spec.outer_eth.packet_length()
            + self.push_spec.outer_ip.packet_length()
            + self.push_spec.outer_encap.packet_length();
        let needed_alloc = needed_push; //.saturating_sub(pkt.headroom());
        let mut space_in_front = needed_push - needed_alloc;

        let mut prepend = if needed_alloc > 0 {
            let mut new_mblk = MsgBlk::new_ethernet(needed_alloc);
            new_mblk.pop_all();
            Some(new_mblk)
        } else {
            None
        };

        // NOT NEEDED TODAY.
        if let Some(inner_new) = &self.push_spec.inner {
            todo!()
        }

        if let Some(outer_encap) = &self.push_spec.outer_encap {
            let a = SizeHoldingEncap {
                encapped_len: self.encapped_len,
                meta: &outer_encap,
            };

            let l = a.packet_length();

            let target = if prepend.is_none() {
                space_in_front -= l;
                &mut pkt
            } else {
                space_in_front = 0;
                prepend.as_mut().unwrap()
            };

            unsafe {
                target.write_front(l, |v| {
                    a.emit_uninit(v).unwrap();
                })
            }
        }

        if let Some(outer_ip) = &self.push_spec.outer_ip {
            let l = outer_ip.packet_length();
            let target = if prepend.is_none() {
                space_in_front -= l;
                &mut pkt
            } else {
                space_in_front = 0;
                prepend.as_mut().unwrap()
            };

            unsafe {
                target.write_front(l, |v| {
                    outer_ip.emit_uninit(v).unwrap();
                })
            }
        }

        if let Some(outer_eth) = &self.push_spec.outer_eth {
            let l = outer_eth.packet_length();
            let target = if prepend.is_none() {
                space_in_front -= l;
                &mut pkt
            } else {
                space_in_front = 0;
                prepend.as_mut().unwrap()
            };

            unsafe {
                target.write_front(l, |v| {
                    outer_eth.emit_uninit(v).unwrap();
                })
            }
        }

        if let Some(mut prepend) = prepend {
            prepend.extend_if_one(pkt);
            prepend
        } else {
            pkt
        }
    }
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
            (0, 0) | (0, 8) => Some(u16::from_be_bytes(
                self.rest_of_hdr()[..2].try_into().unwrap(),
            )),
            _ => None,
        }
    }
}

impl<B: ByteSlice> QueryEcho for IcmpV6Packet<B> {
    #[inline]
    fn echo_id(&self) -> Option<u16> {
        match (self.code(), self.ty()) {
            (0, 128) | (0, 129) => Some(u16::from_be_bytes(
                self.rest_of_hdr()[..2].try_into().unwrap(),
            )),
            _ => None,
        }
    }
}

// TODO: generate ref/mut traits on DirectPacket AND BoxPacket in ingot to halve the code here...
impl<T: ByteSliceMut> HeaderActionModify<EtherMod>
    for DirectPacket<Ethernet, ValidEthernet<T>>
{
    #[inline]
    fn run_modify(
        &mut self,
        mod_spec: &EtherMod,
    ) -> Result<(), HeaderActionError> {
        match self {
            DirectPacket::Repr(a) => {
                if let Some(src) = mod_spec.src {
                    a.set_source(src);
                }
                if let Some(dst) = mod_spec.dst {
                    a.set_destination(dst);
                }
            }
            DirectPacket::Raw(a) => {
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

// TODO: generate ref/mut traits on DirectPacket AND BoxPacket in ingot to halve the code here...
impl<T: ByteSliceMut> HeaderActionModify<IpMod>
    for DirectPacket<L3Repr, ValidL3<T>>
{
    #[inline]
    fn run_modify(
        &mut self,
        mod_spec: &IpMod,
    ) -> Result<(), HeaderActionError> {
        match mod_spec {
            IpMod::Ip4(mods) => match self {
                DirectPacket::Repr(L3Repr::Ipv4(v4)) => {
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
                DirectPacket::Raw(ValidL3::Ipv4(v4)) => {
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
                // run_modify should be capable of returning error...
                _ => return Err(HeaderActionError::MissingHeader),
            },
            IpMod::Ip6(mods) => match self {
                DirectPacket::Repr(L3Repr::Ipv6(v6)) => {
                    if let Some(src) = mods.src {
                        <Ipv6 as Ipv6Mut<T>>::set_source(v6, src);
                    }
                    if let Some(dst) = mods.dst {
                        <Ipv6 as Ipv6Mut<T>>::set_destination(v6, dst);
                    }
                    if let Some(p) = mods.proto {
                        // NOTE: I know this is broken for V6EHs
                        <Ipv6 as Ipv6Mut<T>>::set_next_header(
                            v6,
                            IpProtocol(u8::from(p)),
                        );
                    }
                }
                DirectPacket::Raw(ValidL3::Ipv6(v6)) => {
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
                }
                // run_modify should be capable of returning error...
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
                        roh[..2].copy_from_slice(&id.to_be_bytes())
                    }
                }
            }
            Ulp::IcmpV6(i6) => {
                if let Some(id) = mod_spec.icmp_id {
                    if i6.echo_id().is_some() {
                        let roh = i6.rest_of_hdr_mut();
                        roh[..2].copy_from_slice(&id.to_be_bytes())
                    }
                }
            }
        }

        Ok(())
    }
}

impl<T: ByteSliceMut> HeaderActionModify<EncapMod>
    for DirectPacket<EncapMeta, ValidEncapMeta<T>>
{
    #[inline]
    fn run_modify(
        &mut self,
        mod_spec: &EncapMod,
    ) -> Result<(), HeaderActionError> {
        match (self, mod_spec) {
            (
                DirectPacket::Repr(EncapMeta::Geneve(g)),
                EncapMod::Geneve(mod_spec),
            ) => {
                if let Some(vni) = mod_spec.vni {
                    g.vni = vni;
                }
            }
            (
                DirectPacket::Raw(ValidEncapMeta::Geneve(u, g)),
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

impl<T: ByteSlice> HasInnerCksum for DirectPacket<Ethernet, ValidEthernet<T>> {
    const HAS_CKSUM: bool = false;
}

impl<T: ByteSlice> HasInnerCksum for DirectPacket<L3Repr, ValidL3<T>> {
    const HAS_CKSUM: bool = true;
}

impl<T: ByteSlice> HasInnerCksum
    for DirectPacket<EncapMeta, ValidEncapMeta<T>>
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

// papering over a lot here...
// need to briefly keep both around while I systematically rewrite the test suite.

impl<T: ByteSlice> From<EtherMeta>
    for ingot::types::Packet<Ethernet, ValidEthernet<T>>
{
    #[inline]
    fn from(value: EtherMeta) -> Self {
        ingot::types::Packet::Repr(
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
    for DirectPacket<Ethernet, ValidEthernet<T>>
{
    #[inline]
    fn from(value: EtherMeta) -> Self {
        DirectPacket::Repr(
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
    for ingot::types::Packet<EncapMeta, ValidEncapMeta<T>>
{
    #[inline]
    fn from(value: EncapMeta) -> Self {
        ingot::types::Packet::Repr(value.into())
    }
}

impl<T: ByteSlice> From<EncapMeta>
    for DirectPacket<EncapMeta, ValidEncapMeta<T>>
{
    #[inline]
    fn from(value: EncapMeta) -> Self {
        DirectPacket::Repr(value)
    }
}

impl<T: ByteSlice> From<IpMeta> for DirectPacket<L3Repr, ValidL3<T>> {
    #[inline]
    fn from(value: IpMeta) -> Self {
        match value {
            IpMeta::Ip4(v4) => DirectPacket::Repr(
                Ipv4 {
                    ihl: (v4.hdr_len / 4) as u8,
                    total_len: v4.total_len,
                    identification: v4.ident,
                    protocol: IpProtocol(u8::from(v4.proto)),
                    checksum: u16::from_be_bytes(v4.csum),
                    source: v4.src,
                    destination: v4.dst,
                    flags: Ipv4Flags::DONT_FRAGMENT,
                    ..Default::default()
                }
                .into(),
            ),
            IpMeta::Ip6(v6) => DirectPacket::Repr(
                Ipv6 {
                    payload_len: v6.pay_len,
                    next_header: IpProtocol(u8::from(v6.next_hdr)),
                    hop_limit: v6.hop_limit,
                    source: v6.src,
                    destination: v6.dst,
                    v6ext: Repeated::default(), // TODO
                    ..Default::default()
                }
                .into(),
            ),
        }
    }
}

impl<T: ByteSlice> From<IpMeta> for L3<T> {
    #[inline]
    fn from(value: IpMeta) -> Self {
        match value {
            IpMeta::Ip4(v4) => L3::Ipv4(
                Ipv4 {
                    ihl: (v4.hdr_len / 4) as u8,
                    total_len: v4.total_len,
                    identification: v4.ident,
                    protocol: IpProtocol(u8::from(v4.proto)),
                    checksum: u16::from_be_bytes(v4.csum),
                    source: v4.src,
                    destination: v4.dst,
                    flags: Ipv4Flags::DONT_FRAGMENT,
                    ..Default::default()
                }
                .into(),
            ),
            IpMeta::Ip6(v6) => L3::Ipv6(
                Ipv6 {
                    payload_len: v6.pay_len,
                    next_header: IpProtocol(u8::from(v6.next_hdr)),
                    hop_limit: v6.hop_limit,
                    source: v6.src,
                    destination: v6.dst,
                    v6ext: Repeated::default(), // TODO
                    ..Default::default()
                }
                .into(),
            ),
        }
    }
}

// impl PushAction<Ethernet> for Ethernet {
//     fn push(&self) -> Ethernet {
//         *self
//     }
// }

impl<T: ByteSlice> PushAction<DirectPacket<Ethernet, ValidEthernet<T>>>
    for EtherMeta
{
    #[inline]
    fn push(&self) -> DirectPacket<Ethernet, ValidEthernet<T>> {
        DirectPacket::Repr(Ethernet {
            destination: self.dst,
            source: self.src,
            ethertype: Ethertype(u16::from(self.ether_type)),
        })
    }
}

impl<T: ByteSlice> PushAction<EthernetPacket<T>> for EtherMeta {
    #[inline]
    fn push(&self) -> EthernetPacket<T> {
        ingot::types::Packet::Repr(
            Ethernet {
                destination: self.dst,
                source: self.src,
                ethertype: Ethertype(u16::from(self.ether_type)),
            }
            .into(),
        )
    }
}

// impl<T: ByteSlice> PushAction<DirectPacket<L3Repr, ValidL3<T>>> for IpPush {
//     fn push(&self) -> DirectPacket<L3Repr, ValidL3<T>> {
//         DirectPacket::Repr(match self {
//             IpPush::Ip4(v4) => L3Repr::Ipv4(Ipv4 {
//                 protocol: IpProtocol(u8::from(v4.proto)),
//                 source: v4.src.bytes().into(),
//                 destination: v4.dst.bytes().into(),
//                 flags: Ipv4Flags::DONT_FRAGMENT,
//                 ..Default::default()
//             }),
//             IpPush::Ip6(v6) => L3Repr::Ipv6(Ipv6 {
//                 next_header: IpProtocol(u8::from(v6.proto)),
//                 source: v6.src.bytes().into(),
//                 destination: v6.dst.bytes().into(),
//                 ..Default::default()
//             }),
//         })
//     }
// }

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

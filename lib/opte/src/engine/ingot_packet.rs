use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::mem::MaybeUninit;
use core::ops::Deref;
use core::ops::DerefMut;
use core::ptr::NonNull;
use core::slice;

use illumos_sys_hdrs as ddi;
use illumos_sys_hdrs::mblk_t;
use ingot::ethernet::EthernetPacket;
use ingot::ethernet::EthernetRef;
use ingot::ethernet::Ethertype;
use ingot::ethernet::ValidEthernet;
use ingot::example_chain::Ulp;
use ingot::example_chain::L3;
use ingot::example_chain::L4;
use ingot::geneve::GenevePacket;
use ingot::icmp::IcmpV4Ref;
use ingot::icmp::IcmpV6Ref;
use ingot::ip::IpProtocol;
use ingot::ip::Ipv4;
use ingot::ip::Ipv4Ref;
use ingot::ip::Ipv6Packet;
use ingot::ip::Ipv6Ref;
use ingot::tcp::TcpPacket;
use ingot::tcp::TcpRef;
use ingot::types::HasView;
use ingot::types::Header;
use ingot::types::HeaderStack;
use ingot::types::ParseControl;
use ingot::types::ParseError as IngotParseErr;
use ingot::types::ParseResult;
use ingot::types::Parsed as IngotParsed;
use ingot::types::Read;
use ingot::udp::UdpPacket;
use ingot::udp::UdpRef;
use ingot::Parse;
use opte_api::Direction;
use zerocopy::ByteSlice;
use zerocopy::ByteSliceMut;
use zerocopy::IntoBytes;
use zerocopy::NetworkEndian;

use super::checksum::Checksum as OpteCsum;
use super::checksum::HeaderChecksum;
use super::packet::allocb;
use super::packet::Initialized;
use super::packet::Packet;
use illumos_sys_hdrs::uintptr_t;

use super::checksum::Checksum;
use super::packet::AddrPair;
use super::packet::InnerFlowId;
use super::packet::FLOW_ID_DEFAULT;

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
pub struct MsgBlk {
    pub inner: NonNull<mblk_t>,
}

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
        let inner = unsafe { NonNull::new(allocb(len)) }
            .expect("somehow failed to get an mblk...");

        unsafe { Self { inner } }
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

    // pub fn write(&mut self, n_bytes: usize, f: impl FnOnce(&mut [MaybeUninit<u8>]) -> &mut [u8]) -> usize {
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
        // let out_slice = f(in_slice);
        f(in_slice);

        // assert!(out_slice.as_ptr() == mut_out.b_wptr);
        // assert!(out_slice.len() <= n_bytes);

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

    pub fn unwrap_mblk(mut self) -> *mut mblk_t {
        let ptr_out = self.inner.as_ptr();
        _ = ManuallyDrop::new(self);
        ptr_out
    }

    pub unsafe fn wrap_mblk(ptr: *mut mblk_t) -> Option<Self> {
        let inner = unsafe { NonNull::new(ptr)? };

        Some(Self { inner })
    }
}

pub struct MsgBlkIter<'a> {
    curr: Option<NonNull<mblk_t>>,
    marker: PhantomData<&'a MsgBlk>,
}

pub struct MsgBlkIterMut<'a> {
    curr: Option<NonNull<mblk_t>>,
    marker: PhantomData<&'a mut MsgBlk>,
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
    pub outer_v6: Option<Ipv6Packet<Q>>,
    pub outer_udp: Option<UdpPacket<Q>>,
    pub outer_encap: Option<GenevePacket<Q>>,

    pub inner_eth: EthernetPacket<Q>,
    pub inner_l3: Option<L3<Q>>,
    pub inner_ulp: Option<Ulp<Q>>,
}

impl<Q: ByteSlice> From<OpteIn<Q>> for OpteUnified<Q> {
    fn from(value: OpteIn<Q>) -> Self {
        Self {
            outer_eth: Some(value.outer_eth),
            outer_v6: Some(value.outer_v6),
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

pub struct PacketMeta3<T: ingot::types::Read>(
    pub IngotParsed<OpteUnified<T::Chunk>, T>,
);

impl<T: Read> PacketMeta3<T> {
    pub fn inner_l3(&self) -> Option<&ingot::example_chain::L3<T::Chunk>> {
        self.0.headers().inner_l3.as_ref()
    }

    pub fn inner_ulp(&self) -> Option<&ingot::example_chain::Ulp<T::Chunk>> {
        self.0.headers().inner_ulp.as_ref()
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
        Ulp::IcmpV4(pkt) if pkt.ty() == 0 || pkt.ty() == 3 => {
            Some(u16::from_be_bytes(pkt.rest_of_hdr()[..2].try_into().unwrap()))
        }
        Ulp::IcmpV6(pkt) if pkt.ty() == 128 || pkt.ty() == 129 => {
            Some(u16::from_be_bytes(pkt.rest_of_hdr()[..2].try_into().unwrap()))
        }
        _ => None,
    }
}

impl<T: Read> From<&PacketMeta3<T>> for InnerFlowId {
    fn from(meta: &PacketMeta3<T>) -> Self {
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

pub struct Parsed2<T: Read> {
    // len: usize,
    pub meta: PacketMeta3<T>,
    pub flow: InnerFlowId,
    pub body_csum: Option<Checksum>,
    pub l4_hash: Option<u32>,
    // body: BodyInfo,
    // body_modified: bool,
}

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

impl<T: Read> Parsed2<T>
// where T::Chunk: ByteSliceMut
{
    pub fn parse(pkt: T, dir: Direction) -> ParseResult<Self> {
        let mut meta = PacketMeta3(match dir {
            Direction::In => {
                OpteIn::parse_read(pkt).map(transform_parse_stage1)
            }
            Direction::Out => {
                OpteOut::parse_read(pkt).map(transform_parse_stage1)
            }
        }?);

        let flow = (&meta).into();

        let use_pseudo = if let Some(v) = meta.inner_ulp() {
            !matches!(v, Ulp::IcmpV4(_))
        } else {
            false
        };

        let pseudo_csum = match meta.0.headers().inner_eth.ethertype() {
            // ARP
            Ethertype::ARP => {
                return Ok(Self { meta, body_csum: None, flow, l4_hash: None });
            }
            // Ipv4
            Ethertype::IPV4 => {
                let h = meta.0.headers();
                let mut pseudo_hdr_bytes = [0u8; 12];
                let Some(L3::Ipv4(ref v4)) = h.inner_l3 else { panic!() };
                pseudo_hdr_bytes[0..4].copy_from_slice(&v4.source().octets());
                pseudo_hdr_bytes[4..8]
                    .copy_from_slice(&v4.destination().octets());
                pseudo_hdr_bytes[9] = v4.protocol().0;
                let ulp_len = v4.total_len() - 4 * (v4.ihl() as u16);
                pseudo_hdr_bytes[10..].copy_from_slice(&ulp_len.to_be_bytes());

                Checksum::compute(&pseudo_hdr_bytes)
            }
            // Ipv6
            Ethertype::IPV6 => {
                let h = meta.0.headers();
                let mut pseudo_hdr_bytes = [0u8; 40];
                let Some(L3::Ipv6(ref v6)) = h.inner_l3 else { panic!() };
                pseudo_hdr_bytes[0..16].copy_from_slice(&v6.source().octets());
                pseudo_hdr_bytes[16..32]
                    .copy_from_slice(&v6.destination().octets());
                pseudo_hdr_bytes[39] = v6.next_header().0;
                let ulp_len = v6.payload_len() as u32;
                pseudo_hdr_bytes[32..36]
                    .copy_from_slice(&ulp_len.to_be_bytes());
                Checksum::compute(&pseudo_hdr_bytes)
            }
            _ => return Err(IngotParseErr::Unwanted),
        };

        let body_csum =
            meta.inner_ulp().and_then(csum_minus_hdr).map(|mut v| {
                if use_pseudo {
                    v -= pseudo_csum;
                }
                v
            });

        Ok(Self { meta, flow, body_csum, l4_hash: None })
    }
}

use core::marker::PhantomData;
use core::ops::Deref;
use core::ops::DerefMut;
use core::ptr::NonNull;
use core::slice;

use illumos_sys_hdrs::mblk_t;
use ingot::types::Chunk;
use ingot::types::HasView;
use ingot::types::ParseControl;
use ingot::types::ParseError as IngotParseErr;
use ingot::types::Parsed as IngotParsed;
use ingot::types::Read;
use ingot::EthernetPacket;
use ingot::EthernetRef;
use ingot::GenevePacket;
use ingot::IcmpV4Ref;
use ingot::IcmpV6Ref;
use ingot::Ipv4Ref;
use ingot::Ipv6Packet;
use ingot::Ipv6Ref;
use ingot::Parse;
use ingot::TcpRef;
use ingot::UdpPacket;
use ingot::UdpRef;
use ingot::Ulp;
use ingot::ValidEthernet;
use ingot::L3;
use ingot::L4;
use zerocopy::ByteSlice;
use zerocopy::NetworkEndian;

// NOTE: these are not being handled correctly and need to be
// stealth-imported in ingot.
use ingot_types::HeaderParse;
use ingot_types::NextLayer;
use ingot_types::ParseChoice;
// (also, need to cleanup ::ingot_types vs. ::ingot::types
// imports, somehow)

use super::checksum::Checksum;
use super::packet::AddrPair;
use super::packet::InnerFlowId;
use super::packet::FLOW_ID_DEFAULT;

#[derive(Parse)]
pub struct OpteIn<Q> {
    pub outer_eth: EthernetPacket<Q>,
    #[ingot(from = "L3<Q>")]
    pub outer_v6: Ipv6Packet<Q>,
    #[ingot(from = "L4<Q>")]
    pub outer_udp: UdpPacket<Q>,
    pub outer_encap: GenevePacket<Q>,

    #[ingot(control = exit_on_arp)]
    pub inner_eth: EthernetPacket<Q>,
    // pub inner_l3: L3<Q>,
    pub inner_l3: Option<L3<Q>>,
    // pub inner_ulp: L4<Q>,
    pub inner_ulp: Option<Ulp<Q>>,
}

#[inline]
fn exit_on_arp<V: ByteSlice>(eth: &ValidEthernet<V>) -> ParseControl {
    if eth.ethertype() == 0x0806 {
        ParseControl::Accept
    } else {
        ParseControl::Continue
    }
}

#[derive(Parse)]
pub struct OpteOut<Q> {
    pub inner_eth: EthernetPacket<Q>,
    pub inner_l3: Option<L3<Q>>,
    pub inner_ulp: Option<Ulp<Q>>,
}

// --- REWRITE IN PROGRESS ---
pub struct MsgBlk {
    inner: NonNull<mblk_t>,
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

impl MsgBlk {}

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
            self.curr = NonNull::new(unsafe { (*ptr.as_ptr()).b_next });
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
            self.curr = NonNull::new(unsafe { (*ptr.as_ptr()).b_next });
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

pub struct OpteUnified<Q> {
    pub outer_eth: Option<EthernetPacket<Q>>,
    pub outer_v6: Option<Ipv6Packet<Q>>,
    pub outer_udp: Option<UdpPacket<Q>>,
    pub outer_encap: Option<GenevePacket<Q>>,

    pub inner_eth: EthernetPacket<Q>,
    pub inner_l3: Option<L3<Q>>,
    pub inner_ulp: Option<Ulp<Q>>,
}

impl<Q> From<OpteIn<Q>> for OpteUnified<Q> {
    fn from(value: OpteIn<Q>) -> Self {
        Self {
            outer_eth: Some(value.outer_eth),
            outer_v6: Some(value.outer_v6),
            outer_udp: Some(value.outer_udp),
            outer_encap: Some(value.outer_encap),
            inner_eth: value.inner_eth,
            inner_l3: value.inner_l3,
            inner_ulp: value.inner_ulp,
        }
    }
}

impl<Q> From<OpteOut<Q>> for OpteUnified<Q> {
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
    IngotParsed<OpteUnified<T::Chunk>, T>,
);

impl<T: Read> PacketMeta3<T> {
    pub fn inner_l3(&self) -> Option<&ingot::L3<T::Chunk>> {
        self.0.headers().inner_l3.as_ref()
    }

    pub fn inner_ulp(&self) -> Option<&ingot::Ulp<T::Chunk>> {
        self.0.headers().inner_ulp.as_ref()
    }
}

pub enum PacketMeta2<T: ingot::types::Read> {
    In(IngotParsed<OpteIn<T::Chunk>, T>),
    Out(IngotParsed<OpteOut<T::Chunk>, T>),
}

impl<T: Read> PacketMeta2<T> {
    pub fn inner_l3(&self) -> Option<&ingot::L3<T::Chunk>> {
        match self {
            PacketMeta2::In(v) => v.stack.0.inner_l3.as_ref(),
            PacketMeta2::Out(v) => v.stack.0.inner_l3.as_ref(),
        }
    }

    pub fn inner_ulp(&self) -> Option<&ingot::Ulp<T::Chunk>> {
        match self {
            PacketMeta2::In(v) => v.stack.0.inner_ulp.as_ref(),
            PacketMeta2::Out(v) => v.stack.0.inner_ulp.as_ref(),
        }
    }
}

fn actual_src_port<T: Chunk>(chunk: &ingot::Ulp<T>) -> Option<u16> {
    match chunk {
        Ulp::Tcp(pkt) => Some(pkt.source()),
        Ulp::Udp(pkt) => Some(pkt.source()),
        _ => None,
    }
}

fn actual_dst_port<T: Chunk>(chunk: &ingot::Ulp<T>) -> Option<u16> {
    match chunk {
        Ulp::Tcp(pkt) => Some(pkt.destination()),
        Ulp::Udp(pkt) => Some(pkt.destination()),
        _ => None,
    }
}

fn pseudo_port<T: Chunk>(chunk: &ingot::Ulp<T>) -> Option<u16> {
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

impl<T: Read> From<&PacketMeta2<T>> for InnerFlowId {
    fn from(meta: &PacketMeta2<T>) -> Self {
        let (proto, addrs) = match meta.inner_l3() {
            Some(L3::Ipv4(pkt)) => (
                pkt.protocol(),
                AddrPair::V4 {
                    src: pkt.source().into(),
                    dst: pkt.destination().into(),
                },
            ),
            Some(L3::Ipv6(pkt)) => (
                pkt.next_header(),
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
                    actual_dst_port(ulp)
                        .or_else(|| pseudo_port(ulp))
                        .unwrap_or(0),
                    actual_src_port(ulp)
                        .or_else(|| pseudo_port(ulp))
                        .unwrap_or(0),
                )
            })
            .unwrap_or((0, 0));

        InnerFlowId { proto: proto.into(), addrs, src_port, dst_port }
    }
}

pub struct Parsed2<T: Read> {
    len: usize,
    meta: PacketMeta2<T>,
    flow: InnerFlowId,
    body_csum: Option<Checksum>,
    // body: BodyInfo,
    body_modified: bool,
}

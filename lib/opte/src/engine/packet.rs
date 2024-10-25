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
use crate::d_error::DError;
use core::ffi::CStr;
use core::fmt;
use core::fmt::Display;
use core::hash::Hash;
use core::ptr;
use core::result;
use crc32fast::Hasher;
use dyn_clone::DynClone;
use serde::Deserialize;
use serde::Serialize;
// TODO should probably move these two into this module now.
use super::Direction;
use alloc::string::String;
use alloc::vec::Vec;
use illumos_sys_hdrs::dblk_t;
use illumos_sys_hdrs::mblk_t;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use illumos_sys_hdrs as ddi;
    } else {
        use std::boxed::Box;
        use illumos_sys_hdrs::c_uchar;
    }
}

pub static MBLK_MAX_SIZE: usize = u16::MAX as usize;

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
    IngotError(ingot::types::PacketParseError),
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

impl DError for ingot::types::PacketParseError {
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

impl From<ingot::types::PacketParseError> for ParseError {
    fn from(value: ingot::types::PacketParseError) -> Self {
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
pub(crate) fn mock_freemsg(mut mp: *mut mblk_t) {
    while !mp.is_null() {
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
            bdblk.db_base,
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
    use crate::engine::tcp::TcpFlags;

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

    fn tcp_pkt(body: &[u8]) -> Packet<Initialized> {
        let tcp = TcpMeta {
            src: 3839,
            dst: 80,
            seq: 4224936861,
            flags: TcpFlags::SYN,
            ..Default::default()
        };

        let ip4_total_len = Ipv4Hdr::BASE_SIZE + tcp.hdr_len() + body.len();
        let ip4 = Ipv4Meta {
            src: SRC_IP4,
            dst: DST_IP4,
            proto: Protocol::TCP,
            ttl: 64,
            ident: 99,
            hdr_len: Ipv4Hdr::BASE_SIZE.try_into().unwrap(),
            total_len: ip4_total_len.try_into().unwrap(),
            csum: [0; 2],
        };

        let eth = EtherMeta {
            ether_type: EtherType::Ipv4,
            src: SRC_MAC,
            dst: DST_MAC,
        };

        let pkt_sz = EtherHdr::SIZE + ip4_total_len;
        let mut seg = PacketSeg::alloc(pkt_sz);
        seg.expand_end(pkt_sz).unwrap();
        let mut wtr = seg.get_writer();
        eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
        ip4.emit(wtr.slice_mut(ip4.hdr_len()).unwrap());
        tcp.emit(wtr.slice_mut(tcp.hdr_len()).unwrap());
        wtr.write(body).unwrap();
        let pkt = Packet::new(seg);
        assert_eq!(pkt.len(), pkt_sz);
        pkt
    }

    // TODO(kyle): equivalent for MsgBlk
    // #[test]
    // fn zero_byte_packet() {
    //     let pkt = Packet::alloc(0);
    //     assert_eq!(pkt.len(), 0);
    //     assert_eq!(pkt.num_segs(), 1);
    //     assert_eq!(pkt.avail(), 16);
    //     let res = pkt.parse(Out, GenericUlp {});
    //     match res {
    //         Err(ParseError::BadHeader(msg)) => {
    //             assert_eq!(
    //                 msg,
    //                 EtherHdrError::ReadError(ReadErr::EndOfPacket).into()
    //             );
    //         }

    //         _ => panic!("expected read error, got: {:?}", res),
    //     }

    //     let pkt2 = Packet::copy(&[]);
    //     assert_eq!(pkt2.len(), 0);
    //     assert_eq!(pkt2.num_segs(), 1);
    //     assert_eq!(pkt2.avail(), 16);
    //     let res = pkt2.parse(Out, GenericUlp {});
    //     match res {
    //         Err(ParseError::BadHeader(msg)) => {
    //             assert_eq!(
    //                 msg,
    //                 EtherHdrError::ReadError(ReadErr::EndOfPacket).into()
    //             );
    //         }

    //         _ => panic!("expected read error, got: {:?}", res),
    //     }
    // }

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

    // TODO(kyle): equivalents for MsgBlk?
    // #[test]
    // fn read_single_segment() {
    //     let parsed = tcp_pkt(&[]).parse(Out, GenericUlp {}).unwrap();
    //     assert_eq!(parsed.state.hdr_offsets.inner.ether.seg_idx, 0);
    //     assert_eq!(parsed.state.hdr_offsets.inner.ether.seg_pos, 0);

    //     let eth_meta = parsed.state.meta.inner.ether;
    //     assert_eq!(eth_meta.ether_type, EtherType::Ipv4);
    //     assert_eq!(eth_meta.dst, DST_MAC);
    //     assert_eq!(eth_meta.src, SRC_MAC);

    //     let offsets = &parsed.state.hdr_offsets;

    //     let ip4_meta = match parsed.state.meta.inner.ip.as_ref().unwrap() {
    //         IpMeta::Ip4(v) => v,
    //         _ => panic!("expected IPv4"),
    //     };
    //     assert_eq!(ip4_meta.src, SRC_IP4);
    //     assert_eq!(ip4_meta.dst, DST_IP4);
    //     assert_eq!(ip4_meta.proto, Protocol::TCP);
    //     assert_eq!(offsets.inner.ip.as_ref().unwrap().seg_idx, 0);
    //     assert_eq!(offsets.inner.ip.as_ref().unwrap().seg_pos, 14);

    //     let tcp_meta = match parsed.state.meta.inner.ulp.as_ref().unwrap() {
    //         UlpMeta::Tcp(v) => v,
    //         _ => panic!("expected TCP"),
    //     };
    //     assert_eq!(tcp_meta.src, 3839);
    //     assert_eq!(tcp_meta.dst, 80);
    //     assert_eq!(tcp_meta.flags, TcpFlags::SYN);
    //     assert_eq!(tcp_meta.seq, 4224936861);
    //     assert_eq!(tcp_meta.ack, 0);
    //     assert_eq!(offsets.inner.ulp.as_ref().unwrap().seg_idx, 0);
    //     assert_eq!(offsets.inner.ulp.as_ref().unwrap().seg_pos, 34);
    // }

    // TODO(kyle): equivalents for MsgBlk?
    // #[test]
    // fn write_and_read_multi_segment() {
    //     let mp1 = allocb(34);
    //     let mp2 = allocb(20);

    //     unsafe {
    //         (*mp1).b_cont = mp2;
    //     }

    //     let mut seg1 = unsafe { PacketSeg::wrap_mblk(mp1) };
    //     let mut seg2 = unsafe { PacketSeg::wrap_mblk(mp2) };

    //     let tcp = TcpMeta {
    //         src: 3839,
    //         dst: 80,
    //         flags: TcpFlags::SYN,
    //         seq: 4224936861,
    //         ..Default::default()
    //     };
    //     let ip4 = Ipv4Meta {
    //         src: SRC_IP4,
    //         dst: DST_IP4,
    //         proto: Protocol::TCP,
    //         total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len()) as u16,
    //         ..Default::default()
    //     };
    //     let eth = EtherMeta {
    //         ether_type: EtherType::Ipv4,
    //         src: SRC_MAC,
    //         dst: DST_MAC,
    //     };
    //     seg1.expand_end(34).unwrap();
    //     let mut wtr1 = seg1.get_writer();
    //     eth.emit(wtr1.slice_mut(EtherHdr::SIZE).unwrap());
    //     ip4.emit(wtr1.slice_mut(ip4.hdr_len()).unwrap());

    //     seg2.expand_end(20).unwrap();
    //     let mut wtr2 = seg2.get_writer();
    //     tcp.emit(wtr2.slice_mut(tcp.hdr_len()).unwrap());
    //     let pkt = Packet::new2(seg1, seg2);
    //     let parsed = pkt.parse(Out, GenericUlp {}).unwrap();

    //     let eth_parsed = parsed.state.meta.inner.ether;
    //     assert_eq!(parsed.state.hdr_offsets.inner.ether.seg_idx, 0);
    //     assert_eq!(parsed.state.hdr_offsets.inner.ether.seg_pos, 0);
    //     assert_eq!(eth_parsed.ether_type, EtherType::Ipv4);
    //     assert_eq!(eth_parsed.dst, DST_MAC);
    //     assert_eq!(eth_parsed.src, SRC_MAC);

    //     let offsets = &parsed.state.hdr_offsets;

    //     let ip4_parsed = match parsed.state.meta.inner.ip.unwrap() {
    //         IpMeta::Ip4(v) => v,
    //         _ => panic!("expected IPv4"),
    //     };
    //     assert_eq!(ip4_parsed.src, SRC_IP4);
    //     assert_eq!(ip4_parsed.dst, DST_IP4);
    //     assert_eq!(ip4_parsed.proto, Protocol::TCP);
    //     assert_eq!(offsets.inner.ip.as_ref().unwrap().seg_idx, 0);
    //     assert_eq!(offsets.inner.ip.as_ref().unwrap().seg_pos, 14);

    //     let tcp_parsed = match parsed.state.meta.inner.ulp.unwrap() {
    //         UlpMeta::Tcp(v) => v,
    //         _ => panic!("expected TCP"),
    //     };
    //     assert_eq!(tcp_parsed.src, 3839);
    //     assert_eq!(tcp_parsed.dst, 80);
    //     assert_eq!(tcp_parsed.flags, TcpFlags::SYN);
    //     assert_eq!(tcp_parsed.seq, 4224936861);
    //     assert_eq!(tcp_parsed.ack, 0);
    //     assert_eq!(offsets.inner.ulp.as_ref().unwrap().seg_idx, 0);
    //     assert_eq!(offsets.inner.ulp.as_ref().unwrap().seg_pos, 34);
    // }

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

    // TODO(kyle): equivalents for MsgBlk?
    // #[test]
    // #[should_panic]
    // fn slice_unchecked_bad_offset() {
    //     let parsed = tcp_pkt(&[]).parse(Out, GenericUlp {}).unwrap();
    //     // Offset past end of segment.
    //     parsed.segs[0].slice_unchecked(99, None);
    // }

    // #[test]
    // #[should_panic]
    // fn slice_mut_unchecked_bad_offset() {
    //     let mut parsed = tcp_pkt(&[]).parse(Out, GenericUlp {}).unwrap();
    //     // Offset past end of segment.
    //     parsed.segs[0].slice_mut_unchecked(99, None);
    // }

    // #[test]
    // #[should_panic]
    // fn slice_unchecked_bad_len() {
    //     let parsed = tcp_pkt(&[]).parse(Out, GenericUlp {}).unwrap();
    //     // Length past end of segment.
    //     parsed.segs[0].slice_unchecked(0, Some(99));
    // }

    // #[test]
    // #[should_panic]
    // fn slice_mut_unchecked_bad_len() {
    //     let mut parsed = tcp_pkt(&[]).parse(Out, GenericUlp {}).unwrap();
    //     // Length past end of segment.
    //     parsed.segs[0].slice_mut_unchecked(0, Some(99));
    // }

    // #[test]
    // fn slice_unchecked_zero() {
    //     let parsed = tcp_pkt(&[]).parse(Out, GenericUlp {}).unwrap();
    //     // Set offset to end of packet and slice the "rest" by
    //     // passing None.
    //     assert_eq!(parsed.segs[0].slice_unchecked(54, None).len(), 0);
    // }

    // #[test]
    // fn slice_mut_unchecked_zero() {
    //     let mut parsed = tcp_pkt(&[]).parse(Out, GenericUlp {}).unwrap();
    //     // Set offset to end of packet and slice the "rest" by
    //     // passing None.
    //     assert_eq!(parsed.segs[0].slice_mut_unchecked(54, None).len(), 0);
    // }

    // TODO(kyle): equivalent for MsgBlk
    // Verify that if the TCP header straddles an mblk we return an
    // error.
    // #[test]
    // fn straddled_tcp() {
    //     let mp1 = allocb(46);
    //     let mp2 = allocb(8);

    //     unsafe {
    //         (*mp1).b_cont = mp2;
    //     }

    //     let mut seg1 = unsafe { PacketSeg::wrap_mblk(mp1) };
    //     let mut seg2 = unsafe { PacketSeg::wrap_mblk(mp2) };

    //     let tcp = TcpMeta { src: 3839, dst: 80, ..Default::default() };
    //     let ip4 = Ipv4Meta {
    //         src: SRC_IP4,
    //         dst: DST_IP4,
    //         proto: Protocol::TCP,
    //         total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len()) as u16,
    //         ..Default::default()
    //     };
    //     let eth = EtherMeta {
    //         ether_type: EtherType::Ipv4,
    //         src: SRC_MAC,
    //         dst: DST_MAC,
    //     };
    //     seg1.expand_end(46).unwrap();
    //     let mut wtr1 = seg1.get_writer();
    //     eth.emit(wtr1.slice_mut(EtherHdr::SIZE).unwrap());
    //     ip4.emit(wtr1.slice_mut(ip4.hdr_len()).unwrap());
    //     let mut tcp_bytes = vec![0u8; tcp.hdr_len()];
    //     tcp.emit(&mut tcp_bytes);
    //     wtr1.write(&tcp_bytes[0..12]).unwrap();

    //     seg2.expand_end(8).unwrap();
    //     let mut wtr2 = seg2.get_writer();
    //     wtr2.write(&tcp_bytes[12..]).unwrap();
    //     let pkt = Packet::new2(seg1, seg2);
    //     assert_eq!(pkt.num_segs(), 2);
    //     assert_eq!(
    //         pkt.len(),
    //         EtherHdr::SIZE + Ipv4Hdr::BASE_SIZE + TcpHdr::BASE_SIZE
    //     );
    //     assert!(matches!(
    //         pkt.parse(Out, GenericUlp {}),
    //         Err(ParseError::BadHeader(_))
    //     ));
    // }

    // TODO(kyle): equivalent for MsgBlk
    // Verify that we correctly parse an IPv6 packet with extension headers
    // #[test]
    // fn parse_ipv6_extension_headers_ok() {
    //     use crate::engine::ip6::test::generate_test_packet;
    //     use crate::engine::ip6::test::SUPPORTED_EXTENSIONS;
    //     use itertools::Itertools;
    //     use smoltcp::wire::IpProtocol;
    //     for n_extensions in 0..SUPPORTED_EXTENSIONS.len() {
    //         for extensions in
    //             SUPPORTED_EXTENSIONS.into_iter().permutations(n_extensions)
    //         {
    //             // Generate a full IPv6 test packet, but pull out the extension
    //             // headers as a byte array.
    //             let (buf, ipv6_header_size) =
    //                 generate_test_packet(extensions.as_slice());

    //             let next_hdr =
    //                 *(extensions.first().unwrap_or(&IpProtocol::Tcp));
    //             let ext_hdrs = &buf[Ipv6Hdr::BASE_SIZE..ipv6_header_size];

    //             // Append a TCP header
    //             let tcp = TcpMeta {
    //                 src: 3839,
    //                 dst: 80,
    //                 seq: 4224936861,
    //                 ..Default::default()
    //             };
    //             let mut ext_bytes = [0; 64];
    //             let ext_len = ext_hdrs.len();
    //             assert!(ext_len <= 64);
    //             ext_bytes[0..ext_len].copy_from_slice(ext_hdrs);

    //             let pay_len = tcp.hdr_len() + ext_len;
    //             let ip6 = Ipv6Meta {
    //                 src: SRC_IP6,
    //                 dst: DST_IP6,
    //                 proto: Protocol::TCP,
    //                 next_hdr,
    //                 hop_limit: 255,
    //                 pay_len: pay_len as u16,
    //                 ext: Some(ext_bytes),
    //                 ext_len,
    //             };
    //             let eth = EtherMeta {
    //                 ether_type: EtherType::Ipv6,
    //                 src: SRC_MAC,
    //                 dst: DST_MAC,
    //             };

    //             let mut seg = PacketSeg::alloc(1024);
    //             seg.expand_end(14 + ipv6_header_size + tcp.hdr_len()).unwrap();
    //             let mut wtr = seg.get_writer();
    //             eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
    //             ip6.emit(wtr.slice_mut(ip6.hdr_len()).unwrap());
    //             tcp.emit(wtr.slice_mut(tcp.hdr_len()).unwrap());
    //             let parsed =
    //                 Packet::new(seg).parse(Out, GenericUlp {}).unwrap();

    //             // Assert that the computed offsets of the headers and payloads
    //             // are accurate
    //             let offsets = &parsed.state.hdr_offsets;
    //             let ip = offsets
    //                 .inner
    //                 .ip
    //                 .as_ref()
    //                 .expect("Expected IP header offsets");
    //             assert_eq!(
    //                 ip.seg_idx, 0,
    //                 "Expected IP headers to be in segment 0"
    //             );
    //             assert_eq!(
    //                 ip.seg_pos,
    //                 EtherHdr::SIZE,
    //                 "Expected the IP header to start immediately \
    //                 after the Ethernet header"
    //             );
    //             assert_eq!(
    //                 ip.pkt_pos,
    //                 EtherHdr::SIZE,
    //                 "Expected the IP header to start immediately \
    //                 after the Ethernet header"
    //             );
    //             let ulp = &offsets
    //                 .inner
    //                 .ulp
    //                 .as_ref()
    //                 .expect("Expected ULP header offsets");
    //             assert_eq!(
    //                 ulp.seg_idx, 0,
    //                 "Expected the ULP header to be in segment 0"
    //             );
    //             assert_eq!(
    //                 ulp.seg_pos,
    //                 EtherHdr::SIZE + ipv6_header_size,
    //                 "Expected the ULP header to start immediately \
    //                 after the IP header",
    //             );
    //             assert_eq!(
    //                 ulp.pkt_pos,
    //                 EtherHdr::SIZE + ipv6_header_size,
    //                 "Expected the ULP header to start immediately \
    //                 after the IP header",
    //             );
    //         }
    //     }
    // }

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
        assert!(seg.expand_end(20).is_err());
        assert!(seg.shrink_start(20).is_err());
        assert!(seg.expand_start(4).is_err());
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
                let prev = blocks[i - 1];
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

    // TODO(kyle): equivalent for MsgBlk
    // #[test]
    // fn small_packet_with_padding() {
    //     const MINIMUM_ETH_FRAME_SZ: usize = 64;
    //     const FRAME_CHECK_SEQ_SZ: usize = 4;

    //     // Start with a test packet that's smaller than the minimum
    //     // ethernet frame size (64).
    //     let body = [];
    //     let mut pkt = tcp_pkt(&body);
    //     assert!(pkt.len() < MINIMUM_ETH_FRAME_SZ);

    //     // Many (most?) NICs will pad out any such frames so that
    //     // the total size is 64.
    //     let padding_len = MINIMUM_ETH_FRAME_SZ
    //         - pkt.len()
    //         // Discount the 4 bytes for the Frame Check Sequence (FCS)
    //         // which is usually not visible to upstack software.
    //         - FRAME_CHECK_SEQ_SZ;

    //     // Tack on a new segment filled with zero to pad the packet so that
    //     // it meets the minimum frame size.
    //     // Note that we do NOT update any of the packet headers themselves
    //     // as this padding process should be transparent to the upper
    //     // layers.
    //     let mut padding_seg_wtr = pkt.add_seg(padding_len).unwrap();
    //     padding_seg_wtr.write(&vec![0; padding_len]).unwrap();
    //     assert_eq!(pkt.len(), MINIMUM_ETH_FRAME_SZ - FRAME_CHECK_SEQ_SZ);

    //     // Generate the metadata by parsing the packet
    //     let mut pkt = pkt.parse(Direction::In, GenericUlp {}).unwrap();

    //     // Grab parsed metadata
    //     let ip4_meta = pkt.meta().inner_ip4().cloned().unwrap();
    //     let tcp_meta = pkt.meta().inner_tcp().cloned().unwrap();

    //     // Length in packet headers shouldn't reflect include padding
    //     assert_eq!(
    //         usize::from(ip4_meta.total_len),
    //         ip4_meta.hdr_len() + tcp_meta.hdr_len() + body.len(),
    //     );

    //     // The computed body length also shouldn't include the padding
    //     assert_eq!(pkt.state.body.len, body.len());

    //     // Pretend some processing happened...
    //     // And now we need to update the packet headers based on the
    //     // modified packet metadata.
    //     pkt.emit_new_headers().unwrap();

    //     // Grab the actual packet headers
    //     let ip4_off = pkt.hdr_offsets().inner.ip.unwrap().pkt_pos;
    //     let mut rdr = pkt.get_rdr_mut();
    //     rdr.seek(ip4_off).unwrap();
    //     let ip4_hdr = Ipv4Hdr::parse(&mut rdr).unwrap();
    //     let tcp_hdr = TcpHdr::parse(&mut rdr).unwrap();

    //     // And make sure they don't include the padding bytes
    //     assert_eq!(
    //         usize::from(ip4_hdr.total_len()),
    //         usize::from(ip4_hdr.hdr_len()) + tcp_hdr.hdr_len() + body.len()
    //     );
    // }

    // TODO(kyle): equivalent for MsgBlk
    // #[test]
    // fn udp6_packet_with_padding() {
    //     let body = [1, 2, 3, 4];
    //     let udp = UdpMeta {
    //         src: 124,
    //         dst: 5673,
    //         len: u16::try_from(UdpHdr::SIZE + body.len()).unwrap(),
    //         ..Default::default()
    //     };
    //     let ip6 = Ipv6Meta {
    //         src: SRC_IP6,
    //         dst: DST_IP6,
    //         proto: Protocol::UDP,
    //         next_hdr: smoltcp::wire::IpProtocol::Udp,
    //         hop_limit: 255,
    //         pay_len: udp.len,
    //         ext: None,
    //         ext_len: 0,
    //     };
    //     let eth = EtherMeta {
    //         ether_type: EtherType::Ipv6,
    //         src: SRC_MAC,
    //         dst: DST_MAC,
    //     };

    //     let pkt_sz = eth.hdr_len() + ip6.hdr_len() + usize::from(ip6.pay_len);
    //     let mut pkt = Packet::alloc_and_expand(pkt_sz);
    //     let mut wtr = pkt.seg0_wtr();
    //     eth.emit(wtr.slice_mut(eth.hdr_len()).unwrap());
    //     ip6.emit(wtr.slice_mut(ip6.hdr_len()).unwrap());
    //     udp.emit(wtr.slice_mut(udp.hdr_len()).unwrap());
    //     wtr.write(&body).unwrap();
    //     assert_eq!(pkt.len(), pkt_sz);

    //     // Tack on a new segment filled zero padding at
    //     // the end that's not part of the payload as indicated
    //     // by the packet headers.
    //     let padding_len = 8;
    //     let mut padding_seg_wtr = pkt.add_seg(padding_len).unwrap();
    //     padding_seg_wtr.write(&vec![0; padding_len]).unwrap();
    //     assert_eq!(pkt.len(), pkt_sz + padding_len);

    //     // Generate the metadata by parsing the packet
    //     let mut pkt = pkt.parse(Direction::In, GenericUlp {}).unwrap();

    //     // Grab parsed metadata
    //     let ip6_meta = pkt.meta().inner_ip6().cloned().unwrap();
    //     let udp_meta = pkt.meta().inner_udp().cloned().unwrap();

    //     // Length in packet headers shouldn't reflect include padding
    //     assert_eq!(
    //         usize::from(ip6_meta.pay_len),
    //         udp_meta.hdr_len() + body.len(),
    //     );

    //     // The computed body length also shouldn't include the padding
    //     assert_eq!(pkt.state.body.len, body.len());

    //     // Pretend some processing happened...
    //     // And now we need to update the packet headers based on the
    //     // modified packet metadata.
    //     pkt.emit_new_headers().unwrap();

    //     // Grab the actual packet headers
    //     let ip6_off = pkt.hdr_offsets().inner.ip.unwrap().pkt_pos;
    //     let mut rdr = pkt.get_rdr_mut();
    //     rdr.seek(ip6_off).unwrap();
    //     let ip6_hdr = Ipv6Hdr::parse(&mut rdr).unwrap();
    //     let udp_hdr = UdpHdr::parse(&mut rdr).unwrap();

    //     // And make sure they don't include the padding bytes
    //     assert_eq!(ip6_hdr.pay_len(), udp_hdr.hdr_len() + body.len());
    // }
}

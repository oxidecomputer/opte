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
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::prelude::v1::*;

#[cfg(any(feature = "std", test))]
use std::prelude::v1::*;

use std::convert::{TryFrom, TryInto};
use std::mem;
use std::ptr;
use std::result;
use std::slice;

use serde::{Deserialize, Serialize};

use crate::arp::{ArpHdrRaw, ArpMeta};
use crate::ether::{
    EtherHdrRaw, EtherMeta, ETHER_HDR_SZ, ETHER_TYPE_ARP, ETHER_TYPE_IPV4,
    ETHER_TYPE_IPV6,
};
use crate::headers::{
    csum_incremental, GeneveMeta, IcmpDuMeta, IcmpEchoMeta, IcmpRedirectMeta,
    IpMeta, Ipv4Meta, Ipv6Meta, TcpMeta, UdpMeta, UlpMeta,
};
use crate::icmp::{
    IcmpBaseHdrRaw, IcmpDuHdrRaw, IcmpEchoHdrRaw, IcmpRedirectHdrRaw,
    ICMP_DEST_UNREACHABLE, ICMP_ECHO, ICMP_ECHO_REPLY, ICMP_REDIRECT,
};
use crate::ip4::{Ipv4HdrRaw, Protocol, IPV4_HDR_SZ};
use crate::ip6::Ipv6HdrRaw;
use crate::tcp::{TcpHdrRaw, TCP_HDR_SZ};
use crate::udp::{UdpHdrRaw, UDP_HDR_SZ};

#[cfg(all(not(feature = "std"), not(test)))]
use illumos_ddi_dki::{allocb, freemsg};

use illumos_ddi_dki::{c_uchar, dblk_t, mblk_t};

pub static MBLK_MAX_SIZE: usize = u16::MAX as usize;

#[derive(
    Clone,
    Debug,
    Default,
    Deserialize,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct PacketMeta {
    pub outer_ether: Option<EtherMeta>,
    pub outer_ip: Option<IpMeta>,
    pub outer_udp: Option<UdpMeta>,
    pub outer_geneve: Option<GeneveMeta>,
    pub inner_ether: Option<EtherMeta>,
    pub inner_arp: Option<ArpMeta>,
    pub inner_ip: Option<IpMeta>,
    // TODO ICMP should have its own field, but that has ramifications
    // throughout the code that I do not have time to deal with at the
    // moment.
    //
    // pub inner_icmp: Option<IcmpMeta>
    pub ulp: Option<UlpMeta>,
}

impl PacketMeta {
    pub fn is_tcp(&self) -> bool {
        match self.inner_ip.as_ref() {
            Some(IpMeta::Ip4(ip4)) => ip4.proto == Protocol::TCP,
            Some(IpMeta::Ip6(ip6)) => ip6.proto == Protocol::TCP,
            _ => false,
        }
    }

    pub fn new() -> Self {
        PacketMeta::default()
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
/// via [`Packet::<Initialized>::wrap()`]. In reality this is
/// typically holding an Ethernet _frame_, but we prefer to use the
/// colloquial nomenclature of "packet".
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
/// TODO
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

use PacketSource::*;

#[derive(Debug)]
pub struct Uninitialized {}

#[derive(Debug)]
pub struct Initialized {
    // Total length of packet, in bytes. This is equal to the sum of
    // the length of the _initialized_ window in all the segments
    // (`b_wptr - b_rptr`).
    len: usize,
}

#[derive(Clone, Copy, Debug)]
struct SegOffset {
    idx: usize,
    pos: usize,
}

#[derive(Clone, Debug, Default)]
pub struct HeaderOffsets {
    inner_ether: Option<SegOffset>,
    inner_arp: Option<SegOffset>,
    inner_ip: Option<SegOffset>,
    ulp: Option<SegOffset>,
}

#[derive(Debug)]
pub struct Parsed {
    len: usize,
    meta: PacketMeta,
    hdr_offsets: HeaderOffsets,
    // (packet offset, segment index, segment offset)
    body_start: (usize, usize, usize),
}

pub trait PacketState {}

pub trait CanRead {
    fn len(&self) -> usize;
}

impl PacketState for Uninitialized {}
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
    pub fn avail(&self) -> usize {
        self.avail
    }

    /// Return the number of segments that make up this packet.
    ///
    /// TODO Make this a non-zero return type and enforce it in
    /// wrap/new.
    pub fn num_segs(&self) -> usize {
        self.segs.len()
    }
}

/// For the `no_std`/illumos kernel environment, we want the `mblk_t`
/// drop to occur at the [`Packet`] level, where we can make use of
/// `freemsg(9F)`.
#[cfg(all(not(feature = "std"), not(test)))]
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
            // Safety: This is safe as long as the original `mblk_t` came
            // from a call to `allocb(9F)` (or similar API).
            unsafe { freemsg(head_mp) };
        }
    }
}

#[cfg(any(feature = "std", test))]
impl<S: PacketState> Drop for Packet<S> {
    fn drop(&mut self) {
        for s in &mut self.segs {
            mock_freeb(s.mp);
            s.mp = ptr::null_mut();
        }
        drop(&mut self.segs);
    }
}

impl Packet<Uninitialized> {
    /// Allocate a new [`Packet`] containing `size` bytes. The
    /// returned packet consists of exactly one [`PacketSeg`]. The
    /// metadata is initialized as `None`.
    ///
    /// In the kernel environment this uses `allocb(9F)` and
    /// `freemsg(9F)` under the hood. However, in the kernel we are
    /// often wrapping mblks which are handed to us by mac or viona,
    /// in which case the [`Packet::<Initialized>::wrap()`] API is
    /// used.
    ///
    /// In the `std` environment this uses a mock implementation of
    /// `allocb(9F)` and `freeb(9F)` which contains enough scaffolding
    /// to satisfy OPTE's use of the underlying `mblk_t` and `dblk_t`
    /// structures.
    pub fn alloc(size: usize) -> Self {
        // TODO Could replace `usize` with a type like MblkSize.
        assert!(size <= MBLK_MAX_SIZE);

        #[cfg(any(feature = "std", test))]
        let mp = mock_allocb(size);
        // Safety: allocb(9F) should be safe for any size equal to or
        // less than MBLK_MAX_SIZE.
        #[cfg(all(not(feature = "std"), not(test)))]
        let mp = unsafe { allocb(size, 0) };

        // Safety: We know `wrap()` is safe because we just built the
        // `mp` in a safe manner.
        Packet::<Uninitialized>::new(vec![unsafe { PacketSeg::wrap(mp) }])
    }

    /// Create a new packet from the specified `segs`.
    pub fn new(segs: Vec<PacketSeg>) -> Self {
        for seg in &segs {
            if seg.len > 0 {
                // We are expecting to have segments with no data in
                // them.
                panic!("cannot create an uninitialized packet from bytes");
            }
        }

        let avail: usize = segs.iter().map(|s| s.avail).sum();

        Packet {
            avail: avail.try_into().unwrap(),
            source: Allocated,
            segs,
            state: Uninitialized {},
        }
    }

    /// Wrap the `mblk_t` packet in a [`Packet`], taking ownership of
    /// the `mblk_t` packet as a result. An `mblk_t` packet consists
    /// of one or more `mblk_t` segments chained together via
    /// `b_cont`. As a result, this [`Packet`] may consist of *one or
    /// more* [`PacketSeg`]s. When the [`Packet`] is dropped, the
    /// underlying `mblk_t` segment chain is freed. If you wish to
    /// pass on ownership you must call the [`Packet::unwrap()`]
    /// function.
    ///
    /// # Safety
    ///
    /// The `mp` pointer must point to an `mblk_t` allocated by
    /// `allocb(9F)` or provided by some kernel API which itself used
    /// one of the DDI/DKI APIs to allocate it. That said, this
    /// function assumes that no packet spans across more than 1024
    /// segments. If such a packet is encountered it panics under the
    /// assumption that something has gone wrong vis-à-vis corruption
    /// or malicious behavior.
    ///
    /// # Panic
    ///
    /// * The `mp` value is `NULL`.
    ///
    /// * The packet spans more than 1024 segments.
    ///
    /// * The packet contains 1 or more initialized bytes.
    ///
    /// TODO: This last point is kind of odd and something that might
    /// change. Basically, we allow wrapping an existing mblk segment
    /// chain with zero bytes written (i.e. all `b_rptr == b_wptr`) as
    /// well as wrapping an existing mblk segment chain with one or
    /// more bytes. The former is this function, returning a
    /// [`Packet<Uninitialized>`]. The later is
    /// [`Packet::<Initialized>::wrap()`], returning a
    /// [`Packet<Initialized>`].
    ///
    pub unsafe fn wrap(mp: *mut mblk_t) -> Self {
        if mp.is_null() {
            panic!("NULL pointer passed to wrap()");
        }

        let mut len = 0;
        let mut avail = 0;
        let mut count = 0;
        let mut segs = Vec::with_capacity(4);
        let mut next_seg = (*mp).b_cont;

        let mut seg = PacketSeg::wrap(mp);
        avail += seg.avail;
        len += seg.len;
        segs.push(seg);

        while next_seg != ptr::null_mut() {
            let tmp = (*next_seg).b_cont;
            count += 1;
            seg = PacketSeg::wrap(next_seg);
            avail += seg.avail;
            len += seg.len;
            segs.push(seg);
            next_seg = tmp;

            // We are chasing a linked list, guard against corruption
            // or someone playing games. You might find a panic harsh
            // here, but harsher still is passing this to freemsg(9F),
            // which if being fed a corrupted mblk may end up doing
            // god knows what.
            if count == 1024 {
                panic!("circular/corrupted mblk_t chain encountered")
            }
        }

        if len != 0 {
            // An uninitialized packet must have zero bytes written.
            panic!("bytes found");
        }

        Packet {
            avail: avail.try_into().unwrap(),
            source: Wrapped,
            segs,
            state: Uninitialized {},
        }
    }
}

impl Packet<Initialized> {
    /// Create a [`Packet<Initialized>`] value from the passed in
    /// `bytes`. The returned packet consists of exactly one
    /// [`PacketSeg`] with exactly enough space to hold `bytes.len()`.
    #[cfg(any(feature = "std", test))]
    pub fn copy(bytes: &[u8]) -> Self {
        let mut buf = Vec::with_capacity(bytes.len());
        buf.extend_from_slice(bytes);
        let mp = mock_desballoc(buf);
        unsafe { Packet::<Initialized>::wrap(mp) }
    }

    /// Create a [`Packet<Initialized>`] from the passed in `bytes`.
    /// The returned packet consists of exactly one [`PacketSeg`] with
    /// exactly enough space to hold `bytes.len()`.
    #[cfg(all(not(feature = "std"), not(test)))]
    pub fn copy(bytes: &[u8]) -> Self {
        if bytes.len() == 0 {
            panic!("attempt to initialize packet from zero bytes");
        }
        let mut wtr = PacketWriter::new(Packet::alloc(bytes.len()), None);
        wtr.write(bytes).expect("impossible");
        wtr.finish()
    }

    /// Create a new packet from the specified `segs`.
    pub fn new(segs: Vec<PacketSeg>) -> Self {
        let len: usize = segs.iter().map(|s| s.len).sum();
        if len == 0 {
            // An "initialized" Packet must have at least one byte.
            panic!("no bytes found");
        }

        let avail: usize = segs.iter().map(|s| s.avail).sum();

        Packet { avail, source: Allocated, segs, state: Initialized { len } }
    }

    fn parse_ipv4(
        rdr: &mut PacketReader<Initialized, HeaderOffsets>,
        meta: &mut PacketMeta,
    ) -> Result<(), ReadErr> {
        let ip4_raw = Ipv4HdrRaw::parse(rdr)?;
        let ip4_meta = Ipv4Meta::from(&ip4_raw);
        let proto = ip4_meta.proto;
        let ip_meta = IpMeta::from(ip4_meta);
        meta.inner_ip = Some(ip_meta);
        let seg_idx = rdr.seg_idx();
        let seg_pos = rdr.seg_pos();
        rdr.state_mut().inner_ip = Some(SegOffset {
            idx: seg_idx,
            pos: seg_pos - IPV4_HDR_SZ,
        });

        match proto {
            Protocol::TCP => Self::parse_tcp(rdr, meta)?,
            Protocol::UDP => Self::parse_udp(rdr, meta)?,
            Protocol::ICMP => Self::parse_icmp(rdr, meta)?,
            _ => (),
        }

        Ok(())
    }

    fn parse_ipv6(
        rdr: &mut PacketReader<Initialized, HeaderOffsets>,
        meta: &mut PacketMeta,
    ) -> Result<(), ReadErr> {
        let ip6_raw = Ipv6HdrRaw::parse(rdr)?;
        let ip6_meta = Ipv6Meta::from(&ip6_raw);
        let proto = ip6_meta.proto;
        let ip_meta = IpMeta::from(ip6_meta);
        meta.inner_ip = Some(ip_meta);

        match proto {
            Protocol::TCP => Self::parse_tcp(rdr, meta)?,
            Protocol::UDP => Self::parse_udp(rdr, meta)?,
            Protocol::ICMP => Self::parse_icmp(rdr, meta)?,
            _ => (),
        }

        Ok(())
    }

    fn parse_arp(
        rdr: &mut PacketReader<Initialized, HeaderOffsets>,
        meta: &mut PacketMeta,
    ) -> Result<(), ReadErr> {
        let raw = ArpHdrRaw::parse(rdr)?;
        let arp = match ArpMeta::try_from(&raw) {
            Ok(arp) => arp,
            // TODO return error
            Err(e) => todo!("error parsing ARP header: {:?}", e),
        };
        meta.inner_arp = Some(arp);
        Ok(())
    }

    fn parse_icmp(
        rdr: &mut PacketReader<Initialized, HeaderOffsets>,
        meta: &mut PacketMeta,
    ) -> Result<(), ReadErr> {
        let icmp_base_raw = IcmpBaseHdrRaw::parse(rdr)?;
        match icmp_base_raw.icmp_type {
            ICMP_ECHO_REPLY | ICMP_ECHO => {
                rdr.seek_back(mem::size_of::<IcmpBaseHdrRaw>())
                    .expect("failed to seek_back");
                match IcmpEchoHdrRaw::parse(rdr) {
                    Ok(raw) => {
                        let icmp_echo_meta = IcmpEchoMeta::from(&raw);
                        let ulp_meta = UlpMeta::from(icmp_echo_meta);
                        meta.ulp = Some(ulp_meta);
                        let seg_idx = rdr.seg_idx();
                        let seg_pos = rdr.seg_pos();
                        rdr.state_mut().ulp = Some(SegOffset {
                            idx: seg_idx,
                            pos: seg_pos - mem::size_of::<IcmpEchoMeta>(),
                        });

                        Ok(())
                    }

                    // TODO return error
                    Err(e) => todo!("error parsing ICMP echo: {:?}", e),
                }
            }

            ICMP_DEST_UNREACHABLE => {
                rdr.seek_back(mem::size_of::<IcmpBaseHdrRaw>())
                    .expect("failed to seek_back");
                match IcmpDuHdrRaw::parse(rdr) {
                    Ok(raw) => {
                        let icmp_du_meta = IcmpDuMeta::from(&raw);
                        let ulp_meta = UlpMeta::from(icmp_du_meta);
                        meta.ulp = Some(ulp_meta);
                        let seg_idx = rdr.seg_idx();
                        let seg_pos = rdr.seg_pos();
                        rdr.state_mut().ulp = Some(SegOffset {
                            idx: seg_idx,
                            pos: seg_pos - mem::size_of::<IcmpDuMeta>(),
                        });

                        Ok(())
                    }

                    Err(e) => todo!("error parsing ICMP DU: {:?}", e),
                }
            }

            ICMP_REDIRECT => {
                rdr.seek_back(mem::size_of::<IcmpBaseHdrRaw>())
                    .expect("failed to seek_back");
                match IcmpRedirectHdrRaw::parse(rdr) {
                    Ok(raw) => {
                        let icmp_redir_meta = IcmpRedirectMeta::from(&raw);
                        let ulp_meta = UlpMeta::from(icmp_redir_meta);
                        meta.ulp = Some(ulp_meta);
                        let seg_idx = rdr.seg_idx();
                        let seg_pos = rdr.seg_pos();
                        rdr.state_mut().ulp = Some(SegOffset {
                            idx: seg_idx,
                            pos: seg_pos - mem::size_of::<IcmpRedirectMeta>(),
                        });

                        Ok(())
                    }

                    Err(e) => panic!("error parsing ICMP Redirect: {:?}", e),
                }
            }

            msg_type => {
                todo!("implement parse_icmp() for type: {}", msg_type);
            }
        }
    }

    fn parse_tcp(
        rdr: &mut PacketReader<Initialized, HeaderOffsets>,
        meta: &mut PacketMeta,
    ) -> Result<(), ReadErr> {
        let tcp_raw = TcpHdrRaw::parse(rdr)?;
        let tcp_meta = TcpMeta::from(&tcp_raw);
        let ulp_meta = UlpMeta::from(tcp_meta);
        meta.ulp = Some(ulp_meta);
        let seg_idx = rdr.seg_idx();
        let seg_pos = rdr.seg_pos();
        rdr.state_mut().ulp = Some(SegOffset {
            idx: seg_idx,
            pos: seg_pos - TCP_HDR_SZ,
        });

        Ok(())
    }

    fn parse_udp(
        rdr: &mut PacketReader<Initialized, HeaderOffsets>,
        meta: &mut PacketMeta,
    ) -> Result<(), ReadErr> {
        let udp_raw = UdpHdrRaw::parse(rdr)?;
        let udp_meta = UdpMeta::from(&udp_raw);
        let ulp_meta = UlpMeta::from(udp_meta);
        meta.ulp = Some(ulp_meta);
        let seg_idx = rdr.seg_idx();
        let seg_pos = rdr.seg_pos();
        rdr.state_mut().ulp = Some(SegOffset {
            idx: seg_idx,
            pos: seg_pos - UDP_HDR_SZ,
        });

        Ok(())
    }

    pub fn parse(mut self) -> Result<Packet<Parsed>, ReadErr> {
        let mut meta = PacketMeta::new();
        let mut rdr = PacketReader::new(&self, HeaderOffsets::default());
        let ether_raw = EtherHdrRaw::parse(&mut rdr)?;
        let ether_meta = EtherMeta::from(&ether_raw);
        let et = ether_meta.ether_type;
        meta.inner_ether = Some(ether_meta);
        let seg_idx = rdr.seg_idx();
        let seg_pos = rdr.seg_pos();
        rdr.state_mut().inner_ether = Some(SegOffset {
            idx: seg_idx,
            pos: seg_pos - ETHER_HDR_SZ,
        });

        match et {
            ETHER_TYPE_IPV4 => Self::parse_ipv4(&mut rdr, &mut meta)?,
            ETHER_TYPE_IPV6 => Self::parse_ipv6(&mut rdr, &mut meta)?,
            ETHER_TYPE_ARP => Self::parse_arp(&mut rdr, &mut meta)?,

            _ => {
                todo!("implement parse for EtherType: 0x{:X}", et);
            }
        }

        let (pkt_pos, seg_idx, seg_pos, hdr_offsets) = rdr.finish();

        Ok(Packet {
            avail: self.avail,
            source: self.source,
            // The new packet is taking ownership of the segments.
            segs: std::mem::take(&mut self.segs),
            state: Parsed {
                len: self.state.len,
                meta,
                hdr_offsets,
                body_start: (pkt_pos, seg_idx, seg_pos),
            },
        })
    }

    /// Return the head of the underlying `mblk_t` segment chain and
    /// consume `self`. The caller of this function now owns the
    /// `mblk_t` segment chain.
    pub fn unwrap(mut self) -> *mut mblk_t {
        // self.segs.pop().unwrap().unwrap()
        let mp_head = self.segs[0].mp;
        // We need to make sure to NULL out the mp pointer or else
        // `drop()` will `freemsg(9F)` even though ownership of the
        // mblk has passed on to someone else.
        self.segs[0].mp = ptr::null_mut();
        mp_head
    }

    /// Wrap the `mblk_t` packet in a [`Packet`], taking ownership of
    /// the `mblk_t` packet as a result. An `mblk_t` packet consists
    /// of one or more `mblk_t` segments chained together via
    /// `b_cont`. As a result, this [`Packet`] may consist of *one or
    /// more* [`PacketSeg`]s. When the [`Packet`] is dropped, the
    /// underlying `mblk_t` segment chain is freed. If you wish to
    /// pass on ownership you must call the [`Packet::unwrap()`]
    /// function.
    ///
    /// # Safety
    ///
    /// The `mp` pointer must point to an `mblk_t` allocated by
    /// `allocb(9F)` or provided by some kernel API which itself used
    /// one of the DDI/DKI APIs to allocate it. That said, this
    /// function assumes that no packet spans across more than 1024
    /// segments. If such a packet is encountered it panics under the
    /// assumption that something has gone wrong vis-à-vis corruption
    /// or malicious behavior.
    ///
    /// # Panic
    ///
    /// * The `mp` value is `NULL`.
    ///
    /// * The packet spans more than 1024 segments.
    ///
    /// * The packet DOES NOT contain as least 1 initialized byte.
    ///
    pub unsafe fn wrap(mp: *mut mblk_t) -> Self {
        if mp.is_null() {
            panic!("NULL pointer passed to wrap()");
        }

        let mut len = 0;
        let mut avail = 0;
        let mut count = 0;
        let mut segs = Vec::with_capacity(4);
        let mut next_seg = (*mp).b_cont;

        let mut seg = PacketSeg::wrap(mp);
        avail += seg.avail;
        len += seg.len;
        segs.push(seg);

        while next_seg != ptr::null_mut() {
            let tmp = (*next_seg).b_cont;
            count += 1;
            seg = PacketSeg::wrap(next_seg);
            avail += seg.avail;
            len += seg.len;
            segs.push(seg);
            next_seg = tmp;

            // We are chasing a linked list, guard against corruption
            // or someone playing games. You might find a panic harsh
            // here, but harsher still is passing this to freemsg(9F),
            // which if being fed a corrupted mblk may end up doing
            // god knows what.
            if count == 1024 {
                panic!("circular/corrupted mblk_t chain encountered")
            }
        }

        if len == 0 {
            // An initialized packet must have at least one byte.
            panic!("no bytes found");
        }

        Packet {
            avail: avail.try_into().unwrap(),
            source: Wrapped,
            segs,
            state: Initialized { len },
        }
    }
}

impl Packet<Parsed> {
    pub fn body_offset(&self) -> usize {
        self.state.body_start.0
    }

    pub fn clone_meta(&self) -> PacketMeta {
        self.state.meta.clone()
    }

    pub fn is_tcp(&self) -> bool {
        self.state.meta.is_tcp()
    }

    fn set_inner_ether(&mut self, meta: &EtherMeta) -> Result<(), WriteErr> {
        let off = self.state.hdr_offsets.inner_ether.as_ref().unwrap();
        let seg = &mut self.segs[off.idx];
        let dst = seg.slice_mut(off.pos, ETHER_HDR_SZ);
        let mut ether = EtherHdrRaw::parse_mut(dst)?;
        ether.src = meta.src.to_bytes();
        ether.dst = meta.dst.to_bytes();
        Ok(())
    }

    fn set_inner_ip(&mut self, meta: &IpMeta) -> Result<(), WriteErr> {
        let off = self.state.hdr_offsets.inner_ip.as_ref().unwrap();

        match meta {
            IpMeta::Ip4(ipm) => {
                let seg = &mut self.segs[off.idx];
                let dst = seg.slice_mut(off.pos, IPV4_HDR_SZ);
                let mut iph = Ipv4HdrRaw::parse_mut(dst)?;
                let old_ip_src = iph.src;
                let old_ip_dst = iph.dst;
                let new_ip_src = ipm.src.to_be_bytes();
                let new_ip_dst = ipm.dst.to_be_bytes();
                let mut csum: u32 = (!u16::from_ne_bytes(iph.csum)) as u32;

                csum_incremental(
                    &mut csum,
                    u16::from_ne_bytes([old_ip_src[0], old_ip_src[1]]),
                    u16::from_ne_bytes([new_ip_src[0], new_ip_src[1]]),
                );
                csum_incremental(
                    &mut csum,
                    u16::from_ne_bytes([old_ip_src[2], old_ip_src[3]]),
                    u16::from_ne_bytes([new_ip_src[2], new_ip_src[3]]),
                );
                csum_incremental(
                    &mut csum,
                    u16::from_ne_bytes([old_ip_dst[0], old_ip_dst[1]]),
                    u16::from_ne_bytes([new_ip_dst[0], new_ip_dst[1]]),
                );
                csum_incremental(
                    &mut csum,
                    u16::from_ne_bytes([old_ip_dst[2], old_ip_dst[3]]),
                    u16::from_ne_bytes([new_ip_dst[2], new_ip_dst[3]]),
                );
                assert_eq!(csum & 0xFFFF_0000, 0);

                iph.src = new_ip_src;
                iph.dst = new_ip_dst;
                // Note: We do not convert the endianness of the
                // checksum because the sum was computed in network
                // order. If you change this to `to_be_bytes()`, you
                // will break the checksum.
                iph.csum = (!(csum as u16)).to_ne_bytes();
            }

            IpMeta::Ip6(_) => todo!("impl set_header for IPv6"),
        }

        Ok(())
    }

    // It's easy to become confused by endianness and networking code
    // when looking at code that deals with checksums; it's worth
    // making clear what is going on.
    //
    // Any logical value stored in a network header (or application
    // data for that matter) needs to consider endianness. That is, a
    // multi-byte value like an IP header's "total length" or TCP's
    // "port", which has a logical value like "total length = 60" or
    // "port = 443", needs to make sure its value is interpreted
    // correctly no matter which byte order the underlying hardware
    // uses. To this effect, all logical values sent across the
    // network are sent in "network order" (big endian) and then
    // adjusted accordingly on the host. In an AMD64 arch you will see
    // network code which calls `hton{s,l}()` in order to convert the
    // logical value in memory to the correct byte order for the
    // network. However, not all values have a logical, numerical
    // meaning. For example, a mac address is made up of 6 consecutive
    // bytes, for which the order is important, but this string of
    // bytes is never interpreted as an integer. Thus, there is no
    // conversion to be made: the bytes are in the same order in the
    // network as they are in memory (because they are just that, a
    // sequence of bytes). The same goes for the various checksums.
    // The internet checksum is just a sequence of two bytes. However,
    // in order to implement the checksum (one's complement sum), we
    // happen to treat these two bytes as a 16-bit integer, and the
    // sequence of bytes to be summed as a set of 16-bit integers.
    // Because of this it's easy to think of the checksum as a logical
    // value when it's really not. This brings us to the point: you
    // never perform byte-order conversion on the checksum field. You
    // treat each pair of bytes (both the checksum field itself, and
    // the bytes you are summing) as if it's a native 16-bit integer.
    // Yes, this means that on a little-endian architecture you are
    // logically flipping the bytes, but as the bytes being summed are
    // all in network-order, you are also storing them in
    // network-order when you write the final sum to memory.
    //
    // While said a slightly different way, this is also covered in
    // RFC 1071 §1.B.
    //
    // > Therefore, the sum may be calculated in exactly the same way
    // > regardless of the byte order ("big-endian" or "little-endian")
    // > of the underlaying hardware. For example, assume a "little-
    // > endian" machine summing data that is stored in memory in
    // > network ("big-endian") order. Fetching each 16-bit word will
    // > swap bytes, resulting in the sum [4]; however, storing the
    // > result back into memory will swap the sum back into network
    // > byte order.
    fn set_ulp(
        &mut self,
        ipm: &IpMeta,
        ulpm: &UlpMeta,
    ) -> Result<(), WriteErr> {
        // We stash these here because we need them for the
        // pseudo-header checksum update for the ULP.
        //
        // TODO The pseudo-header checksum adjustment code needs to
        // be IP version specific. For now we just panic on IPv6.
        let old_ip_src = match self.state.meta.inner_ip.as_ref().unwrap() {
            IpMeta::Ip4(ip4m) => ip4m.src.to_be_bytes(),
            IpMeta::Ip6(_ip6m) => todo!("IPv6 set_ulp"),
        };
        let old_ip_dst = match self.state.meta.inner_ip.as_ref().unwrap() {
            IpMeta::Ip4(ip4m) => ip4m.dst.to_be_bytes(),
            IpMeta::Ip6(_ip6m) => todo!("IPv6 set_ulp"),
        };
        let new_ip_src = match ipm {
            IpMeta::Ip4(ip4m) => ip4m.src.to_be_bytes(),
            IpMeta::Ip6(_ip6m) => todo!("IPv6 set_ulp"),
        };
        let new_ip_dst = match ipm {
            IpMeta::Ip4(ip4m) => ip4m.dst.to_be_bytes(),
            IpMeta::Ip6(_ip6m) => todo!("IPv6 set_ulp"),
        };
        let off = self.state.hdr_offsets.ulp.as_ref().unwrap();

        match ulpm {
            UlpMeta::Tcp(tcpm) => {
                let seg = &mut self.segs[off.idx];
                let mut dst =
                    seg.slice_mut(off.pos, TCP_HDR_SZ);
                let mut tcph = TcpHdrRaw::parse_mut(&mut dst)?;
                let new_sport = tcpm.src.to_be_bytes();
                let new_dport = tcpm.dst.to_be_bytes();
                let mut csum: u32 = (!u16::from_ne_bytes(tcph.csum)) as u32;

                // Update pseudo-header checksum.
                csum_incremental(
                    &mut csum,
                    u16::from_ne_bytes([old_ip_src[0], old_ip_src[1]]),
                    u16::from_ne_bytes([new_ip_src[0], new_ip_src[1]]),
                );
                csum_incremental(
                    &mut csum,
                    u16::from_ne_bytes([old_ip_src[2], old_ip_src[3]]),
                    u16::from_ne_bytes([new_ip_src[2], new_ip_src[3]]),
                );
                csum_incremental(
                    &mut csum,
                    u16::from_ne_bytes([old_ip_dst[0], old_ip_dst[1]]),
                    u16::from_ne_bytes([new_ip_dst[0], new_ip_dst[1]]),
                );
                csum_incremental(
                    &mut csum,
                    u16::from_ne_bytes([old_ip_dst[2], old_ip_dst[3]]),
                    u16::from_ne_bytes([new_ip_dst[2], new_ip_dst[3]]),
                );

                // Update TCP checksum.
                csum_incremental(
                    &mut csum,
                    u16::from_ne_bytes([tcph.src_port[0], tcph.src_port[1]]),
                    u16::from_ne_bytes([new_sport[0], new_sport[1]]),
                );
                csum_incremental(
                    &mut csum,
                    u16::from_ne_bytes([tcph.dst_port[0], tcph.dst_port[1]]),
                    u16::from_ne_bytes([new_dport[0], new_dport[1]]),
                );
                assert_eq!(csum & 0xFFFF_0000, 0);

                tcph.src_port = new_sport;
                tcph.dst_port = new_dport;
                tcph.csum = (!(csum as u16)).to_ne_bytes();
            }

            UlpMeta::Udp(udpm) => {
                let seg = &mut self.segs[off.idx];
                let mut dst = seg.slice_mut(off.pos, UDP_HDR_SZ);
                let mut udph = UdpHdrRaw::parse_mut(&mut dst)?;
                let new_sport = udpm.src.to_be_bytes();
                let new_dport = udpm.dst.to_be_bytes();
                let mut csum: u32 = (!u16::from_ne_bytes(udph.csum)) as u32;

                // Update pseudo-header checksum.
                csum_incremental(
                    &mut csum,
                    u16::from_ne_bytes([old_ip_src[0], old_ip_src[1]]),
                    u16::from_ne_bytes([new_ip_src[0], new_ip_src[1]]),
                );
                csum_incremental(
                    &mut csum,
                    u16::from_ne_bytes([old_ip_src[2], old_ip_src[3]]),
                    u16::from_ne_bytes([new_ip_src[2], new_ip_src[3]]),
                );
                csum_incremental(
                    &mut csum,
                    u16::from_ne_bytes([old_ip_dst[0], old_ip_dst[1]]),
                    u16::from_ne_bytes([new_ip_dst[0], new_ip_dst[1]]),
                );
                csum_incremental(
                    &mut csum,
                    u16::from_ne_bytes([old_ip_dst[2], old_ip_dst[3]]),
                    u16::from_ne_bytes([new_ip_dst[2], new_ip_dst[3]]),
                );

                // Update UDP checksum.
                csum_incremental(
                    &mut csum,
                    u16::from_ne_bytes([udph.src_port[0], udph.src_port[1]]),
                    u16::from_ne_bytes([new_sport[0], new_sport[1]]),
                );
                csum_incremental(
                    &mut csum,
                    u16::from_ne_bytes([udph.dst_port[0], udph.dst_port[1]]),
                    u16::from_ne_bytes([new_dport[0], new_dport[1]]),
                );
                assert_eq!(csum & 0xFFFF_0000, 0);

                udph.src_port = new_sport;
                udph.dst_port = new_dport;
                udph.csum = (!(csum as u16)).to_ne_bytes();
            }

            meta => crate::dbg(format!("impl set_ulp() for {:?}", meta)),
        }

        Ok(())
    }

    pub fn set_headers(&mut self, meta: &PacketMeta) -> Result<(), WriteErr> {
        match meta.inner_ether.as_ref() {
            Some(ether_meta) => self.set_inner_ether(ether_meta)?,
            None => (),
        }

        match meta.inner_ip.as_ref() {
            Some(ip_meta) => self.set_inner_ip(ip_meta)?,
            None => (),
        }

        match meta.ulp.as_ref() {
            Some(ulpm) => {
                // We need to pass in IP meta for potential
                // pseudo-header checksum adjustment.
                let ipm = meta.inner_ip.as_ref().unwrap();
                self.set_ulp(ipm, ulpm)?
            }
            None => (),
        }

        Ok(())
    }

    /// Return the head of the underlying `mblk_t` segment chain and
    /// consume `self`. The caller of this function now owns the
    /// `mblk_t` segment chain.
    pub fn unwrap(mut self) -> *mut mblk_t {
        let mp_head = self.segs[0].mp;
        // We need to make sure to NULL out the mp pointer or else
        // `drop()` will `freemsg(9F)` even though ownership of the
        // mblk has passed on to someone else.
        self.segs[0].mp = ptr::null_mut();
        mp_head
    }
}

impl<S: CanRead + PacketState> Packet<S> {
    /// Return the length of the entire packet.
    ///
    /// NOTE: This length only includes the _initialized_ bytes of the
    /// packet. Each [`PacketSeg`] may contain _uninitialized_ bytes
    /// at the head or tail (or both) of the segment.
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

impl PacketSeg {
    fn slice_mut(&mut self, off: usize, len: usize) -> &mut [u8] {
        unsafe {
            let start = (*self.mp).b_rptr.add(off);
            slice::from_raw_parts_mut(start, len)
        }
    }

    /// Wrap an existing `mblk_t`.
    ///
    /// Safety: The `mp` passed must be a pointer to an existing `mblk_t`.
    pub unsafe fn wrap(mp: *mut mblk_t) -> Self {
        let dblk = (*mp).b_datap as *mut dblk_t;
        let len = (*mp).b_wptr.offset_from((*mp).b_rptr) as usize;
        let avail = (*dblk).db_lim.offset_from((*dblk).db_base) as usize;

        PacketSeg { mp, dblk, avail, len }
    }

    pub fn unwrap(self) -> *mut mblk_t {
        self.mp
    }

    /// Write the bytes in `src` to this segment at the `pos`
    /// specified. If the bytes cannot be written a `WriteErr` is
    /// returned specifying why.
    pub fn write(
        &mut self,
        src: &[u8],
        pos: WritePos,
    ) -> result::Result<(), WriteErr> {
        // Safety: The docs are not very clear on the "allocated
        // object" definition. We are holding a pointer to an array
        // of bytes which was allocated by C code. The Rust compiler
        // has no insight into this allocation, and so I don't see how
        // it could have any notion of where the object begins or
        // ends. As this pointer is coming via FFI, my guess is the
        // compiler disables any optimizations it would have made had
        // it come from casting a reference, and so plain
        // offset/sub/add should be safe.
        let (dst, rptr, wptr, new_len) = match pos {
            WritePos::Append => {
                unsafe {
                    let start = (*self.mp).b_wptr;
                    let end = start.add(src.len());
                    if end > (*self.dblk).db_lim as *mut c_uchar {
                        return Err(WriteErr::NotEnoughBytes);
                    }

                    // Safety: We know add is safe in this case
                    // because we checked the bounds above.
                    let dst = slice::from_raw_parts_mut(start, src.len());
                    let wptr = (*self.mp).b_wptr.add(src.len());
                    (dst, None, Some(wptr), self.len + src.len())
                }
            }

            WritePos::Modify(offset) => unsafe {
                let wptr = (*self.mp).b_wptr;
                let start = (*self.mp).b_rptr.add(offset as usize);
                let end = start.add(src.len());
                if start > wptr || end > wptr {
                    return Err(WriteErr::NotEnoughBytes);
                }

                let dst = slice::from_raw_parts_mut(start, src.len());
                (dst, None, None, self.len)
            },

            WritePos::ModAppend(offset) => unsafe {
                let wptr = (*self.mp).b_wptr;
                let limit = (*self.dblk).db_lim;
                let start = (*self.mp).b_rptr.add(offset as usize);
                let end = start.add(src.len());
                assert!(end >= (*self.mp).b_rptr);
                if start > wptr || end > limit as *mut u8 {
                    return Err(WriteErr::NotEnoughBytes);
                }

                let dst = slice::from_raw_parts_mut(start, src.len());
                let new_wptr = end;
                assert!(end.offset_from(wptr) >= 0);
                (
                    dst,
                    None,
                    Some(new_wptr),
                    self.len + (end.offset_from(wptr) as usize),
                )
            },

            WritePos::Prepend => unsafe {
                let start = (*self.mp).b_rptr.sub(src.len());

                if start < (*self.dblk).db_base as *mut c_uchar {
                    return Err(WriteErr::NotEnoughBytes);
                }

                let dst = slice::from_raw_parts_mut(start, src.len());
                (dst, Some(start), None, self.len + src.len())
            },
        };

        dst.copy_from_slice(src);

        // Make the prepended bytes visible by adjusting the rptr.
        //
        // Safety: We know the mp is legit.
        match rptr {
            Some(ptr) => unsafe { (*self.mp).b_rptr = ptr },
            None => (),
        }

        // Make the appended bytes visible by adjusting the wptr.
        //
        // Safety: We know the mp is legit.
        match wptr {
            Some(ptr) => unsafe { (*self.mp).b_wptr = ptr },
            None => (),
        }

        self.len = new_len;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadErr {
    BadLayout,
    EndOfPacket,
    NotEnoughBytes,
    StraddledRead,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteErr {
    BadLayout,
    EndOfPacket,
    NotEnoughBytes,
    StraddledWrite,
}

pub type ReadResult<T> = result::Result<T, ReadErr>;
pub type WriteResult<T> = result::Result<T, WriteErr>;

/// A trait for reading bytes from packets.
///
/// All operations start from the current position and move it
/// forward, with the exception of `seek_back()`, which moves the
/// position backwards within the current segment.
pub trait PacketRead {
    /// Return the current position in the packet.
    fn pos(&self) -> usize;

    /// Seek forwards from the current position by `amount`. The seek
    /// may cross segment boundaries.
    ///
    /// # Errors
    ///
    /// If the seek would move beyond the end of the packet, then a
    /// [`EndOfPacket`] is returned.
    fn seek(&mut self, amount: usize) -> ReadResult<()>;

    /// Seek backwards from the current position by `amount`.
    ///
    /// # Errors
    ///
    /// If the seek would move beyond the beginning of the current
    /// segment, then an error is returned.
    fn seek_back(&mut self, amount: usize) -> ReadResult<()>;

    /// Return the slice of `len` bytes starting from the current
    /// position.
    ///
    /// The slice *must* exist entirely in a single packet segment --
    /// it can never straddle multiple segments.
    ///
    /// # Errors
    ///
    /// If `self` cannot satisfy this request a `ReadErr` is returned.
    fn slice(&mut self, len: usize) -> ReadResult<&[u8]>;
}

/// Append: Append to the end of the segment or packet, i.e. start at
/// `b_wptr`.
///
/// Modify(offset): Modify bytes starting at `offset` from the
/// beginning of the segment or packet (`b_rptr`). The length of the
/// write must fit within the end of the current segment (`b_wptr`).
///
/// ModAppend(offset): Modify bytes start at `offset` from the
/// beginning of the segment or packet (`b_rptr`). The length of the
/// write may extend the end of the current segment (`b_wptr`), but
/// must fit within the total available bytes in the current segment
/// (`db_lim`).
///
/// Prepend: Prepend bytes to the start of the segment or packet.
/// There must be enough space available between `db_base` and
/// `b_rptr`.
pub enum WritePos {
    Append,
    Modify(u16),
    ModAppend(u16),
    Prepend,
}

pub struct PacketWriter {
    pkt: Packet<Uninitialized>,
    margin: Option<usize>,
    pkt_len: usize,
    pkt_pos: usize,
    seg_idx: usize,
    seg_pos: usize,
}

impl PacketWriter {
    pub fn finish(mut self) -> Packet<Initialized> {
        Packet {
            avail: self.pkt.avail,
            source: self.pkt.source,
            // The new Packet is taking ownership of the segments.
            segs: std::mem::take(&mut self.pkt.segs),
            state: Initialized { len: self.pkt_len },
        }
    }

    pub fn new(pkt: Packet<Uninitialized>, margin: Option<usize>) -> Self {
        // TODO This is temporary just to get things working. There's
        // no real reason margin can't span past the first segment.
        // Though, really, it probably shouldn't be a thing.
        if margin.unwrap_or(0) >= pkt.segs[0].avail {
            panic!("margin must fit in first segment");
        }

        PacketWriter {
            pkt,
            margin,
            pkt_len: 0,
            pkt_pos: margin.unwrap_or(0),
            seg_idx: 0,
            seg_pos: margin.unwrap_or(0),
        }
    }

    pub fn pos(&self) -> usize {
        self.pkt_pos
    }

    pub fn write(&mut self, bytes: &[u8]) -> WriteResult<()> {
        let mut seg = &mut self.pkt.segs[self.seg_idx];

        if self.seg_pos == seg.avail {
            if (self.seg_idx + 1) == self.pkt.num_segs() {
                return Err(WriteErr::EndOfPacket);
            }

            self.seg_idx += 1;
            seg = &mut self.pkt.segs[self.seg_idx];
        }

        seg.write(bytes, WritePos::Append)?;
        self.pkt_len += bytes.len();
        self.pkt_pos += bytes.len();
        self.seg_pos += bytes.len();
        Ok(())
    }
}

// The `S` type is any arbitrary state the caller of [`PacketReader`]
// wants to track while moving through the packet.
pub struct PacketReader<'a, P, S>
where
    P: PacketState + CanRead,
{
    pkt: &'a Packet<P>,
    pkt_pos: usize,
    seg_idx: usize,
    seg_pos: usize,
    seg_len: usize,
    state: S,
}

impl<'a, P, S> PacketReader<'a, P, S>
where
    P: PacketState + CanRead,
{
    pub fn finish(self) -> (usize, usize, usize, S) {
        (self.pkt_pos, self.seg_idx, self.seg_pos, self.state)
    }

    pub fn new(pkt: &'a Packet<P>, state: S) -> Self {
        let seg_len = pkt.segs[0].len;

        PacketReader { pkt, pkt_pos: 0, seg_idx: 0, seg_pos: 0, seg_len, state }
    }

    fn seg_idx(&self) -> usize {
        self.seg_idx
    }

    fn seg_pos(&self) -> usize {
        self.seg_pos
    }

    fn state_mut(&mut self) -> &mut S {
        &mut self.state
    }
}

impl<'a, P, S> PacketRead for PacketReader<'a, P, S>
where
    P: PacketState + CanRead,
{
    fn pos(&self) -> usize {
        self.pkt_pos as usize
    }

    fn seek(&mut self, mut amount: usize) -> ReadResult<()> {
        if self.pkt_pos + amount > self.pkt.len() {
            return Err(ReadErr::EndOfPacket);
        }

        while self.seg_pos + amount > self.seg_len {
            if self.seg_idx + 1 == self.pkt.segs.len() {
                return Err(ReadErr::EndOfPacket);
            }

            self.seg_idx += 1;
            amount -= self.seg_len - self.seg_pos;
            self.pkt_pos += self.seg_len - self.seg_pos;
            self.seg_len = self.pkt.segs[self.seg_idx].len;
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

    fn slice(&mut self, len: usize) -> ReadResult<&[u8]> {
        let mut seg = &self.pkt.segs[self.seg_idx];

        // If we've reached the end of the initialized bytes in this
        // segment.
        if self.seg_pos == seg.len {
            // There are no more segments to be read.
            if (self.seg_idx + 1) == self.pkt.num_segs() {
                return Err(ReadErr::EndOfPacket);
            }

            // Move onto next segment.
            self.seg_idx += 1;
            seg = &self.pkt.segs[self.seg_idx];
            self.seg_pos = 0;
            self.seg_len = seg.len;
        }

        if len > self.seg_len {
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
}

#[cfg(any(feature = "std", test))]
pub fn mock_allocb(size: usize) -> *mut mblk_t {
    let buf = Vec::with_capacity(size);
    mock_desballoc(buf)
}

#[cfg(any(feature = "std", test))]
pub fn mock_desballoc(buf: Vec<u8>) -> *mut mblk_t {
    let (ptr, len, avail) = buf.into_raw_parts();

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

    use zerocopy::AsBytes;

    use crate::ether::EtherAddr;
    use crate::tcp::TcpFlags;

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

        let pkt = unsafe { Packet::<Initialized>::wrap(mp1) };
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

        let pkt = unsafe { Packet::<Initialized>::wrap(mp1) };
        assert_eq!(pkt.num_segs(), 2);
        assert_eq!(pkt.avail(), 22);
        assert_eq!(pkt.len(), 6);
    }

    #[test]
    #[should_panic]
    fn wrap_circular() {
        let buf1 = vec![0x1, 0x2, 0x3, 0x4];
        let buf2 = vec![0x5, 0x6];
        let mp1 = mock_desballoc(buf1);
        let mp2 = mock_desballoc(buf2);

        // Make a circular reference.
        unsafe {
            (*mp1).b_cont = mp2;
            (*mp2).b_cont = mp1;
        }

        let _pkt = unsafe { Packet::<Initialized>::wrap(mp1) };
    }

    #[test]
    fn write_and_read_single_segment() {
        let pkt = Packet::alloc(ETHER_HDR_SZ + 20 + 20);

        let eth_meta = EtherMeta {
            dst: EtherAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d]),
            src: EtherAddr::from([0xa8, 0x40, 0x25, 0x00, 0x00, 0x63]),
            ether_type: ETHER_TYPE_IPV4,
        };

        let ip4 = Ipv4HdrRaw {
            ver_hdr_len: 0x45,
            dscp_ecn: 0x00,
            total_len: [0x00, 0x3c],
            ident: [0x7a, 0x3d],
            frag_and_flags: [0x40, 0x00],
            ttl: 0x40,
            proto: 0x6,
            csum: [0x01, 0xcd],
            src: [0x0a, 0x00, 0x00, 0x63],
            dst: [0x34, 0x0a, 0x80, 0x45],
        };

        let tcp = TcpHdrRaw {
            src_port: [0x0e, 0xff],
            dst_port: [0x00, 0x50],
            seq: [0xfb, 0xd3, 0x6b, 0x9d],
            ack: [0x00, 0x00, 0x00, 0x00],
            offset: 0xa0,
            flags: 0x02,
            win: [0xfa, 0xf0],
            csum: [0x04, 0xe0],
            urg: [0x00, 0x00],
        };

        let mut wtr = PacketWriter::new(pkt, None);
        let _ = wtr.write(EtherHdrRaw::from(&eth_meta).as_bytes()).unwrap();
        assert_eq!(wtr.pos(), ETHER_HDR_SZ);
        let _ = wtr.write(ip4.as_bytes()).unwrap();
        assert_eq!(wtr.pos(), ETHER_HDR_SZ + IPV4_HDR_SZ);
        let _ = wtr.write(tcp.as_bytes()).unwrap();
        assert_eq!(wtr.pos(), ETHER_HDR_SZ + IPV4_HDR_SZ + TCP_HDR_SZ);

        let pkt = wtr.finish();

        assert_eq!(pkt.len(), ETHER_HDR_SZ + IPV4_HDR_SZ + TCP_HDR_SZ);
        assert_eq!(pkt.num_segs(), 1);

        let parsed = pkt.parse().unwrap();
        assert_eq!(
            parsed.state.hdr_offsets.inner_ether.as_ref().unwrap().idx,
            0
        );
        assert_eq!(
            parsed.state.hdr_offsets.inner_ether.as_ref().unwrap().pos,
            0
        );
        let eth_meta = parsed.state.meta.inner_ether.as_ref().unwrap();

        assert_eq!(
            eth_meta.dst,
            EtherAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d])
        );
        assert_eq!(
            eth_meta.src,
            EtherAddr::from([0xa8, 0x40, 0x25, 0x00, 0x00, 0x63])
        );
        assert_eq!(eth_meta.ether_type, ETHER_TYPE_IPV4);

        let ip4_meta = match parsed.state.meta.inner_ip.as_ref().unwrap() {
            IpMeta::Ip4(v) => v,
            _ => panic!("expected IPv4"),
        };
        assert_eq!(ip4_meta.src, "10.0.0.99".parse().unwrap());
        assert_eq!(ip4_meta.dst, "52.10.128.69".parse().unwrap());
        assert_eq!(ip4_meta.proto, Protocol::TCP);
        assert_eq!(parsed.state.hdr_offsets.inner_ip.as_ref().unwrap().idx, 0);
        assert_eq!(parsed.state.hdr_offsets.inner_ip.as_ref().unwrap().pos, 14);

        let tcp_meta = match parsed.state.meta.ulp.as_ref().unwrap() {
            UlpMeta::Tcp(v) => v,
            _ => panic!("expected TCP"),
        };
        assert_eq!(tcp_meta.src, "3839".parse().unwrap());
        assert_eq!(tcp_meta.dst, "80".parse().unwrap());
        assert_eq!(tcp_meta.flags, TcpFlags::SYN);
        assert_eq!(tcp_meta.seq, 4224936861);
        assert_eq!(tcp_meta.ack, 0);
        assert_eq!(parsed.state.hdr_offsets.ulp.as_ref().unwrap().idx, 0);
        assert_eq!(parsed.state.hdr_offsets.ulp.as_ref().unwrap().pos, 34);
    }

    #[test]
    fn write_and_read_multi_segment() {
        let mp1 = mock_allocb(34);
        let mp2 = mock_allocb(20);

        unsafe {
            (*mp1).b_cont = mp2;
        }

        let pkt = unsafe { Packet::<Uninitialized>::wrap(mp1) };
        assert_eq!(pkt.num_segs(), 2);
        assert_eq!(pkt.avail(), 54);

        let eth_meta = EtherMeta {
            dst: EtherAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d]),
            src: EtherAddr::from([0xa8, 0x40, 0x25, 0x00, 0x00, 0x63]),
            ether_type: ETHER_TYPE_IPV4,
        };

        let ip4 = Ipv4HdrRaw {
            ver_hdr_len: 0x45,
            dscp_ecn: 0x00,
            total_len: [0x00, 0x3c],
            ident: [0x7a, 0x3d],
            frag_and_flags: [0x40, 0x00],
            ttl: 0x40,
            proto: 0x6,
            csum: [0x01, 0xcd],
            src: [0x0a, 0x00, 0x00, 0x63],
            dst: [0x34, 0x0a, 0x80, 0x45],
        };

        let tcp = TcpHdrRaw {
            src_port: [0x0e, 0xff],
            dst_port: [0x00, 0x50],
            seq: [0xfb, 0xd3, 0x6b, 0x9d],
            ack: [0x00, 0x00, 0x00, 0x00],
            offset: 0xa0,
            flags: 0x02,
            win: [0xfa, 0xf0],
            csum: [0x04, 0xe0],
            urg: [0x00, 0x00],
        };

        let mut wtr = PacketWriter::new(pkt, None);
        let _ = wtr.write(EtherHdrRaw::from(&eth_meta).as_bytes()).unwrap();
        assert_eq!(wtr.pos(), ETHER_HDR_SZ);
        let _ = wtr.write(ip4.as_bytes()).unwrap();
        assert_eq!(wtr.pos(), ETHER_HDR_SZ + IPV4_HDR_SZ);
        let _ = wtr.write(tcp.as_bytes()).unwrap();
        assert_eq!(wtr.pos(), ETHER_HDR_SZ + IPV4_HDR_SZ + TCP_HDR_SZ);

        let pkt = wtr.finish();

        assert_eq!(pkt.len(), ETHER_HDR_SZ + IPV4_HDR_SZ + TCP_HDR_SZ);
        assert_eq!(pkt.num_segs(), 2);

        let parsed = pkt.parse().unwrap();
        let eth_meta = parsed.state.meta.inner_ether.as_ref().unwrap();

        assert_eq!(
            parsed.state.hdr_offsets.inner_ether.as_ref().unwrap().idx,
            0
        );
        assert_eq!(
            parsed.state.hdr_offsets.inner_ether.as_ref().unwrap().pos,
            0
        );
        assert_eq!(
            eth_meta.dst,
            EtherAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d])
        );
        assert_eq!(
            eth_meta.src,
            EtherAddr::from([0xa8, 0x40, 0x25, 0x00, 0x00, 0x63])
        );
        assert_eq!(eth_meta.ether_type, ETHER_TYPE_IPV4);

        let ip4_meta = match parsed.state.meta.inner_ip.as_ref().unwrap() {
            IpMeta::Ip4(v) => v,
            _ => panic!("expected IPv4"),
        };
        assert_eq!(ip4_meta.src, "10.0.0.99".parse().unwrap());
        assert_eq!(ip4_meta.dst, "52.10.128.69".parse().unwrap());
        assert_eq!(ip4_meta.proto, Protocol::TCP);
        assert_eq!(parsed.state.hdr_offsets.inner_ip.as_ref().unwrap().idx, 0);
        assert_eq!(parsed.state.hdr_offsets.inner_ip.as_ref().unwrap().pos, 14);

        let tcp_meta = match parsed.state.meta.ulp.as_ref().unwrap() {
            UlpMeta::Tcp(v) => v,
            _ => panic!("expected TCP"),
        };
        assert_eq!(tcp_meta.src, "3839".parse().unwrap());
        assert_eq!(tcp_meta.dst, "80".parse().unwrap());
        assert_eq!(tcp_meta.flags, TcpFlags::SYN);
        assert_eq!(tcp_meta.seq, 4224936861);
        assert_eq!(tcp_meta.ack, 0);
        assert_eq!(parsed.state.hdr_offsets.ulp.as_ref().unwrap().idx, 1);
        assert_eq!(parsed.state.hdr_offsets.ulp.as_ref().unwrap().pos, 0);
    }
}

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
use core::convert::TryInto;
use core::ptr;
use core::result;
use core::slice;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::string::String;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::vec::Vec;
#[cfg(any(feature = "std", test))]
use std::string::String;
#[cfg(any(feature = "std", test))]
use std::vec::Vec;

#[cfg(any(feature = "std", test))]
use std::boxed::Box;

use serde::{Deserialize, Serialize};

use crate::arp::{ArpHdr, ArpHdrError, ArpMeta, ARP_HDR_SZ};
use crate::checksum::{Checksum, HeaderChecksum};
use crate::ether::{
    EtherHdr, EtherHdrError, EtherMeta, EtherType, ETHER_HDR_SZ,
};
use crate::geneve::{GeneveHdr, GeneveHdrError, GeneveMeta, GENEVE_HDR_SZ};
use crate::headers::{Header, IpHdr, IpMeta, UlpHdr, UlpMeta};
use crate::ip4::{Ipv4Hdr, Ipv4HdrError, Ipv4Meta, Protocol, IPV4_HDR_SZ};
use crate::ip6::{Ipv6Hdr, Ipv6HdrError, Ipv6Meta, IPV6_HDR_SZ};
use crate::tcp::{TcpHdr, TcpHdrError, TcpMeta};
use crate::udp::{UdpHdr, UdpHdrError, UdpMeta, UDP_HDR_SZ};

#[cfg(all(not(feature = "std"), not(test)))]
use illumos_ddi_dki as ddi;

use illumos_ddi_dki::{c_uchar, dblk_t, mblk_t};

pub static MBLK_MAX_SIZE: usize = u16::MAX as usize;

#[derive(Debug)]
pub struct HeaderGroup {
    pub ether: EtherHdr,
    pub arp: Option<ArpHdr>,
    pub ip: Option<IpHdr>,
    pub ulp: Option<UlpHdr>,
    pub encap: Option<GeneveHdr>,
}

#[macro_export]
macro_rules! assert_hg {
    ($left:expr, $right:expr) => {
        assert_eth!($left.ether, $right.ether);
        assert_ip!($left.ip.as_ref(), $right.ip.as_ref());
        assert_ulp!($left.ulp.as_ref(), $right.ulp.as_ref());
    };
}

impl HeaderGroup {
    fn encap_len(&self) -> usize {
        if self.encap.is_some() {
            self.encap.as_ref().unwrap().hdr_len()
        } else {
            0
        }
    }

    fn is_encap(&self) -> bool {
        self.encap.is_some()
    }

    fn is_ip(&self) -> bool {
        self.ip.is_some()
    }

    fn len(&self) -> usize {
        let mut len = ETHER_HDR_SZ;

        if self.arp.is_some() {
            len += ARP_HDR_SZ;
        }

        if self.ip.is_some() {
            len += self.ip.as_ref().unwrap().hdr_len();
        }

        if self.ulp.is_some() {
            len += self.ulp.as_ref().unwrap().hdr_len();
        }

        if self.encap.is_some() {
            len += GENEVE_HDR_SZ;
        }

        len
    }

    fn new(ether: EtherHdr) -> Self {
        HeaderGroup { ether, arp: None, ip: None, ulp: None, encap: None }
    }

    fn set_lengths(&mut self, offsets: &HeaderGroupOffsets, pkt_len: usize) {
        if self.ip.is_some() {
            self.ip
                .as_mut()
                .unwrap()
                .set_total_len(pkt_len - offsets.ip.unwrap().pkt_pos);
        }

        if self.ulp.is_some() {
            self.ulp
                .as_mut()
                .unwrap()
                .set_total_len(pkt_len - offsets.ulp.unwrap().pkt_pos);
        }

        // Currently only Geneve is supported; it gets its payload
        // length from UDP.

        // if self.encap.is_some() {
        //     todo!("implement encap set_lengths()");
        // }
    }

    fn unify_arp(&mut self, arpm: &ArpMeta) {
        match self.arp.as_mut() {
            Some(arph) => {
                // In this case we are modifying an existing ARP header.
                arph.unify(arpm);
                return;
            }

            None => (),
        }

        // In this case we adding an ARP header.
        self.arp = Some(ArpHdr::from(arpm));
    }

    fn unify_ip4(&mut self, ip4m: &Ipv4Meta) {
        match self.ip.as_mut() {
            Some(iph) => {
                match iph {
                    IpHdr::Ip4(ip4h) => {
                        ip4h.unify(ip4m);
                        return;
                    }

                    // In this case we are overwriting the existing
                    // IPv6 header with an IPv4 header.
                    IpHdr::Ip6(_) => (),
                }
            }

            None => (),
        }

        self.ip = Some(IpHdr::from(Ipv4Hdr::from(ip4m)));
    }

    fn unify_ip6(&mut self, ip6m: &Ipv6Meta) {
        match self.ip.as_mut() {
            Some(iph) => {
                match iph {
                    IpHdr::Ip6(ip6h) => {
                        ip6h.unify(ip6m);
                        return;
                    }

                    // In this case we are overwriting the existing
                    // IPv4 header with an IPv6 header.
                    IpHdr::Ip4(_) => (),
                }
            }

            None => (),
        }

        self.ip = Some(IpHdr::from(Ipv6Hdr::from(ip6m)));
    }

    fn unify_udp(&mut self, udpm: &UdpMeta) {
        match self.ulp.as_mut() {
            Some(ulp) => {
                match ulp {
                    // In this case we are modifying the existing UDP header.
                    UlpHdr::Udp(udph) => {
                        udph.unify(udpm);
                        return;
                    }

                    _ => (),
                }
            }

            None => (),
        }

        // In this case we are overwriting the existing ULP header
        // with a UDP header.
        self.ulp = Some(UlpHdr::from(UdpHdr::from(udpm)));
    }

    fn unify_tcp(&mut self, tcpm: &TcpMeta) {
        match self.ulp.as_mut() {
            Some(ulp) => {
                match ulp {
                    // In this case we are modifying the existing TCP header.
                    UlpHdr::Tcp(tcph) => {
                        tcph.unify(tcpm);
                        return;
                    }
                    _ => (),
                }
            }

            None => (),
        }

        // In this case we are overwriting the existing ULP header
        // with a TCP header.
        self.ulp = Some(UlpHdr::from(TcpHdr::from(tcpm)));
    }

    fn unify_encap(&mut self, genevem: &GeneveMeta) {
        match self.encap.as_mut() {
            // In this case we are modifying an existing Geneve header.
            Some(geneveh) => {
                geneveh.vni = genevem.vni;
                return;
            }

            None => (),
        }

        self.encap = Some(GeneveHdr::from(genevem));
    }

    fn ulp_len(&self) -> usize {
        let mut len = 0;

        if self.ulp.is_some() {
            len += self.ulp.as_ref().unwrap().hdr_len();
        }

        if self.encap.is_some() {
            len += self.encap.as_ref().unwrap().hdr_len();
        }

        len
    }

    fn write(&self, seg: &mut PacketSeg) -> Result<(), WriteError> {
        seg.write(&self.ether.as_bytes(), WritePos::Append)?;

        match self.arp.as_ref() {
            Some(arp) => {
                seg.write(&arp.as_bytes(), WritePos::Append)?;
                return Ok(());
            }

            _ => (),
        }

        match self.ip.as_ref() {
            Some(ip) => match ip {
                IpHdr::Ip4(ip4) => {
                    seg.write(&ip4.as_bytes(), WritePos::Append)?;
                }

                IpHdr::Ip6(ip6) => {
                    seg.write(&ip6.as_bytes(), WritePos::Append)?;
                }
            },

            _ => {
                return Ok(());
            }
        }

        match self.ulp.as_ref() {
            Some(ulp) => match ulp {
                UlpHdr::Tcp(tcp) => {
                    seg.write(&tcp.as_bytes(), WritePos::Append)?;
                }

                UlpHdr::Udp(udp) => {
                    seg.write(&udp.as_bytes(), WritePos::Append)?;
                }
            },

            _ => {
                return Ok(());
            }
        }

        match self.encap.as_ref() {
            Some(geneve) => {
                seg.write(&geneve.as_bytes(), WritePos::Append)?;
            }

            _ => (),
        }

        Ok(())
    }
}

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
pub struct MetaGroup {
    pub ether: Option<EtherMeta>,
    pub arp: Option<ArpMeta>,
    pub ip: Option<IpMeta>,
    pub ulp: Option<UlpMeta>,
    pub encap: Option<GeneveMeta>,
}

impl MetaGroup {
    pub fn is_tcp(&self) -> bool {
        match self.ip.as_ref() {
            Some(IpMeta::Ip4(ip4)) => ip4.proto == Protocol::TCP,
            Some(IpMeta::Ip6(ip6)) => ip6.proto == Protocol::TCP,
            _ => false,
        }
    }
}

impl From<&HeaderGroup> for MetaGroup {
    fn from(hg: &HeaderGroup) -> Self {
        Self {
            ether: Some(EtherMeta::from(&hg.ether)),
            arp: hg.arp.as_ref().map(ArpMeta::from),
            ip: hg.ip.as_ref().map(IpMeta::from),
            ulp: hg.ulp.as_ref().map(UlpMeta::from),
            encap: hg.encap.as_ref().map(GeneveMeta::from),
        }
    }
}

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
    pub outer: MetaGroup,
    pub inner: MetaGroup,
}

impl PacketMeta {
    pub fn new() -> Self {
        PacketMeta::default()
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

#[derive(Clone, Copy, Debug, Default)]
pub struct HdrOffset {
    // The header's offset in bytes from start of packet.
    pub pkt_pos: usize,

    // Which segment the header lives in, starting at 0.
    pub seg_idx: usize,

    // The headers offset in bytes from the start of the segment.
    pub seg_pos: usize,
}

#[derive(Clone, Debug, Default)]
pub struct HeaderGroupOffsets {
    pub ether: HdrOffset,
    pub arp: Option<HdrOffset>,
    pub ip: Option<HdrOffset>,
    pub ulp: Option<HdrOffset>,
    pub encap: Option<HdrOffset>,
}

#[derive(Clone, Debug, Default)]
pub struct HeaderOffsets {
    pub outer: Option<HeaderGroupOffsets>,
    pub inner: HeaderGroupOffsets,
}

#[derive(Debug)]
pub struct PacketHeaders {
    pub outer: Option<HeaderGroup>,
    pub inner: HeaderGroup,
}

#[derive(Debug)]
struct BodyInfo {
    pkt_offset: usize,
    seg_index: usize,
    seg_offset: usize,
    len: usize,
}

#[derive(Debug)]
pub struct Parsed {
    len: usize,
    headers: PacketHeaders,
    meta: PacketMeta,
    hdr_offsets: HeaderOffsets,
    inner_ulp_payload_csum: Option<Checksum>,
    body: BodyInfo,
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
            unsafe { ddi::freemsg(head_mp) };
        }
    }
}

#[cfg(any(feature = "std", test))]
impl<S: PacketState> Drop for Packet<S> {
    fn drop(&mut self) {
        if self.segs.len() != 0 {
            let head_mp = self.segs[0].mp;
            drop(&mut self.segs);
            mock_freemsg(head_mp);
        }
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
        let mp = allocb(size);

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

    fn parse_hg_ipv4<'a>(
        rdr: &mut PacketReader<'a, Initialized, ()>,
        hg: &mut HeaderGroup,
        offsets: &mut HeaderGroupOffsets,
    ) -> Result<(), ParseError> {
        let ip4 = Ipv4Hdr::parse(rdr)?;
        let hdr_len = ip4.hdr_len();

        // XXX While IPv4 header options should be extremely rare we
        // still need to account for them as it changes the starting
        // position of the ULP.
        if hdr_len > IPV4_HDR_SZ {
            todo!("need to deal with IPv4 header options!!!");
        }

        let proto = ip4.proto();
        hg.ip = Some(IpHdr::from(ip4));

        offsets.ip = Some(HdrOffset {
            pkt_pos: rdr.pkt_pos() - hdr_len,
            seg_idx: rdr.seg_idx(),
            seg_pos: rdr.seg_pos() - hdr_len,
        });

        match proto {
            Protocol::TCP => Self::parse_hg_tcp(rdr, hg, offsets)?,
            Protocol::UDP => Self::parse_hg_udp(rdr, hg, offsets)?,
            _ => return Err(ParseError::UnsupportedProtocol(proto)),
        }

        Ok(())
    }

    fn parse_hg_ipv6<'a>(
        rdr: &mut PacketReader<'a, Initialized, ()>,
        hg: &mut HeaderGroup,
        offsets: &mut HeaderGroupOffsets,
    ) -> Result<(), ParseError> {
        let ip6 = Ipv6Hdr::parse(rdr)?;

        if ip6.next_hdr() != Protocol::TCP && ip6.next_hdr() != Protocol::UDP {
            todo!(
                "need to deal with IPv6 header extensions!!! (0x{:X})",
                ip6.next_hdr() as u8
            );
        }

        let proto = ip6.proto();
        hg.ip = Some(IpHdr::from(ip6));

        offsets.ip = Some(HdrOffset {
            pkt_pos: rdr.pkt_pos() - IPV6_HDR_SZ,
            seg_idx: rdr.seg_idx(),
            seg_pos: rdr.seg_pos() - IPV6_HDR_SZ,
        });

        match proto {
            Protocol::TCP => Self::parse_hg_tcp(rdr, hg, offsets)?,
            Protocol::UDP => Self::parse_hg_udp(rdr, hg, offsets)?,
            _ => return Err(ParseError::UnsupportedProtocol(proto)),
        }

        Ok(())
    }

    fn parse_hg_arp<'a>(
        rdr: &mut PacketReader<'a, Initialized, ()>,
        hg: &mut HeaderGroup,
        offsets: &mut HeaderGroupOffsets,
    ) -> Result<(), ParseError> {
        let arp = ArpHdr::parse(rdr)?;
        hg.arp = Some(arp);

        offsets.arp = Some(HdrOffset {
            pkt_pos: rdr.pkt_pos() - ARP_HDR_SZ,
            seg_idx: rdr.seg_idx(),
            seg_pos: rdr.seg_pos() - ARP_HDR_SZ,
        });

        Ok(())
    }

    fn parse_hg_tcp<'a>(
        rdr: &mut PacketReader<'a, Initialized, ()>,
        hg: &mut HeaderGroup,
        offsets: &mut HeaderGroupOffsets,
    ) -> Result<(), ParseError> {
        let tcp = TcpHdr::parse(rdr)?;
        let hdr_len = tcp.hdr_len();
        hg.ulp = Some(UlpHdr::from(tcp));

        offsets.ulp = Some(HdrOffset {
            pkt_pos: rdr.pkt_pos() - hdr_len,
            seg_idx: rdr.seg_idx(),
            seg_pos: rdr.seg_pos() - hdr_len,
        });

        Ok(())
    }

    fn parse_hg_udp<'a>(
        rdr: &mut PacketReader<'a, Initialized, ()>,
        hg: &mut HeaderGroup,
        offsets: &mut HeaderGroupOffsets,
    ) -> Result<(), ParseError> {
        use crate::geneve::GENEVE_PORT;

        let udp = UdpHdr::parse(rdr)?;
        let dport = udp.dst_port();
        hg.ulp = Some(UlpHdr::from(udp));

        offsets.ulp = Some(HdrOffset {
            pkt_pos: rdr.pkt_pos() - UDP_HDR_SZ,
            seg_idx: rdr.seg_idx(),
            seg_pos: rdr.seg_pos() - UDP_HDR_SZ,
        });

        match dport {
            GENEVE_PORT => {
                Self::parse_hg_encap(rdr, hg, offsets)?;
            }

            _ => (),
        }

        Ok(())
    }

    fn parse_hg_encap<'a>(
        rdr: &mut PacketReader<'a, Initialized, ()>,
        hg: &mut HeaderGroup,
        offsets: &mut HeaderGroupOffsets,
    ) -> Result<(), ParseError> {
        let geneve = GeneveHdr::parse(rdr)?;
        let opts_len = geneve.options_len_bytes();

        if opts_len > 0 {
            todo!("add support for options");
        }

        hg.encap = Some(geneve);

        offsets.encap = Some(HdrOffset {
            pkt_pos: rdr.pkt_pos() - (GENEVE_HDR_SZ + opts_len),
            seg_idx: rdr.seg_idx(),
            seg_pos: rdr.seg_pos() - (GENEVE_HDR_SZ + opts_len),
        });

        Ok(())
    }

    fn parse_hg<'a, 'b>(
        rdr: &'b mut PacketReader<'a, Initialized, ()>,
        offsets: &mut HeaderGroupOffsets,
    ) -> Result<HeaderGroup, ParseError> {
        // NOTE: We don't worry about VLANs on inbound because mac
        // strips them for us. On outbound, while our VPC currently
        // only supplies L3 to the guest, it could decide to send us
        // anything. For now we will just reject tagged frames from
        // the guest.
        let ether = EtherHdr::parse(rdr)?;
        let mut hg = HeaderGroup::new(ether);

        offsets.ether = HdrOffset {
            pkt_pos: rdr.pkt_pos() - ETHER_HDR_SZ,
            seg_idx: rdr.seg_idx(),
            seg_pos: rdr.seg_pos() - ETHER_HDR_SZ,
        };

        match hg.ether.ether_type() {
            EtherType::Ipv4 => Self::parse_hg_ipv4(rdr, &mut hg, offsets)?,

            EtherType::Ipv6 => Self::parse_hg_ipv6(rdr, &mut hg, offsets)?,

            EtherType::Arp => Self::parse_hg_arp(rdr, &mut hg, offsets)?,

            EtherType::Ether => {
                return Err(ParseError::BadHeader(format!(
                    "Unexpected EtherType 'Ether' ({}) found in frame (should \
                     only be present in encap header",
                    EtherType::Ether,
                )))
            }
        };

        Ok(hg)
    }

    pub fn parse(mut self) -> Result<Packet<Parsed>, ParseError> {
        let mut outer_offsets = HeaderGroupOffsets::default();
        let mut inner_offsets = HeaderGroupOffsets::default();
        let mut rdr = PacketReader::new(&self, ());
        // From the header group we build the meta.
        let mut outer_headers =
            Some(Self::parse_hg(&mut rdr, &mut outer_offsets)?);

        let inner_headers = if outer_headers.as_ref().unwrap().is_encap() {
            Self::parse_hg(&mut rdr, &mut inner_offsets)?
        } else {
            core::mem::swap(&mut outer_offsets, &mut inner_offsets);
            outer_headers.take().unwrap()
        };

        let hdrs = PacketHeaders { outer: outer_headers, inner: inner_headers };

        let meta = if hdrs.outer.is_some() {
            PacketMeta {
                outer: MetaGroup::from(hdrs.outer.as_ref().unwrap()),
                inner: MetaGroup::from(&hdrs.inner),
            }
        } else {
            PacketMeta {
                outer: Default::default(),
                inner: MetaGroup::from(&hdrs.inner),
            }
        };

        // In order to efficiently update the checksums later we
        // extract the payload portion of the ULP checksum.
        let inner_ulp_payload_csum = match hdrs.inner.ulp.as_ref() {
            Some(ulp) => {
                let mut csum = ulp.csum_minus_hdr();
                let ip = hdrs.inner.ip.as_ref().unwrap();
                csum.sub(&ip.pseudo_bytes());
                Some(csum)
            }

            None => None,
        };

        let hdr_offsets = if hdrs.outer.is_some() {
            HeaderOffsets { outer: Some(outer_offsets), inner: inner_offsets }
        } else {
            HeaderOffsets { outer: None, inner: inner_offsets }
        };

        let (pkt_offset, mut seg_index, mut seg_offset, _, end_of_seg) =
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

        // If we have outer headers, we need to make sure that the
        // outer ULP/IP lengths account for the inner headers +
        // data.
        if hdrs.outer.is_some() && hdrs.outer.as_ref().unwrap().is_ip() {
            let ip = hdrs.outer.as_ref().unwrap().ip.as_ref().unwrap();
            let actual = ip.pay_len();
            let expected = hdrs.outer.as_ref().unwrap().ulp_len()
                + hdrs.inner.len()
                + body.len;

            if ip.pay_len() != expected {
                return Err(ParseError::BadOuterIpLen { expected, actual });
            }
        }

        if hdrs.outer.is_some()
            && hdrs.outer.as_ref().unwrap().is_ip()
            && hdrs.outer.as_ref().unwrap().ulp.is_some()
        {
            match hdrs.outer.as_ref().unwrap().ulp.as_ref().unwrap() {
                // TCP does not specify a body length, rather it
                // specifies a data offset (same as header length) and
                // derives body length from the IP length.
                UlpHdr::Tcp(_) => (),

                // UDP defines a length which includes the fixed
                // header size as well as the length of the body, in
                // bytes.
                UlpHdr::Udp(udp) => {
                    let actual = udp.pay_len();
                    let expected = hdrs.outer.as_ref().unwrap().encap_len()
                        + hdrs.inner.len()
                        + body.len;

                    if actual != expected {
                        return Err(ParseError::BadOuterUlpLen {
                            expected,
                            actual,
                        });
                    }
                }
            }
        }

        // Check the inner IP header length against payload.
        if hdrs.inner.is_ip() {
            let ip = hdrs.inner.ip.as_ref().unwrap();
            let actual = ip.pay_len();
            let expected = hdrs.inner.ulp_len() + body.len;

            if actual != expected {
                return Err(ParseError::BadInnerIpLen { expected, actual });
            }
        }

        // Check the inner ULP header length against the payload.
        if hdrs.inner.is_ip() && hdrs.inner.ulp.is_some() {
            match hdrs.inner.ulp.as_ref().unwrap() {
                // See comment above for outer headers.
                UlpHdr::Tcp(_) => (),

                // See comment above for outer headers.
                UlpHdr::Udp(udp) => {
                    let actual = udp.pay_len();
                    let expected = body.len;

                    if actual != expected {
                        return Err(ParseError::BadInnerUlpLen {
                            expected,
                            actual,
                        });
                    }
                }
            }
        }

        Ok(Packet {
            avail: self.avail,
            source: self.source,
            // The new packet is taking ownership of the segments.
            segs: core::mem::take(&mut self.segs),
            state: Parsed {
                len: self.state.len,
                hdr_offsets,
                headers: hdrs,
                meta,
                inner_ulp_payload_csum,
                body,
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
        self.state.body.pkt_offset
    }

    pub fn body_seg(&self) -> usize {
        self.state.body.seg_index
    }

    pub fn hdr_offsets(&self) -> HeaderOffsets {
        self.state.hdr_offsets.clone()
    }

    pub fn headers(&self) -> &PacketHeaders {
        &self.state.headers
    }

    pub fn get_body_rdr(&self) -> PacketReader<Parsed, ()> {
        let mut rdr = PacketReader::new(self, ());
        // XXX While this works for now it might be nice to have a
        // better mechanism for dealing with the body. For example, we
        // know this seek() call can't fail, but the current
        // abstraction isn't powerful enough to encode that in the
        // type system.
        rdr.seek(self.body_offset()).expect("failed to seek to body");
        rdr
    }

    pub fn is_tcp(&self) -> bool {
        self.state.meta.inner.is_tcp()
    }

    pub fn meta(&self) -> &PacketMeta {
        &self.state.meta
    }

    pub fn meta_mut(&mut self) -> &mut PacketMeta {
        &mut self.state.meta
    }

    /// Return the mblk pointer value as a formatted String. This is
    /// for debugging purposes.
    pub fn mblk_ptr_str(&self) -> String {
        format!("{:p}", self.segs[0].mp)
    }

    fn replace_headers(&mut self, mut hdr_seg: PacketSeg) {
        let body_seg_idx = self.state.body.seg_index;

        for _i in 0..body_seg_idx {
            let mut seg = self.segs.remove(0);
            self.avail -= seg.avail;
            self.state.len -= seg.len;
            self.state.body.pkt_offset -= seg.len;
            self.state.body.seg_index -= 1;
            seg.nullify_cont();
        }

        assert_eq!(self.state.body.seg_index, 0);

        // The first body segment may start with header data. In that
        // case we need to bump the b_rptr to effectively "erase" the
        // remanents of the old headers.
        if self.state.body.seg_offset != 0 {
            self.segs[0].shift_rptr(self.state.body.seg_offset);

            // Reduce the length by the length of headers removed.
            // Also adjust the body offset.
            self.state.len -= self.state.body.seg_offset;
            self.state.body.pkt_offset -= self.state.body.seg_offset;
            self.state.body.seg_offset = 0;
        }

        self.avail += hdr_seg.avail;
        self.state.len += hdr_seg.len;
        self.state.body.pkt_offset += hdr_seg.len;
        self.state.body.seg_index = 1;
        hdr_seg.link(&self.segs[0]);
        self.segs.insert(0, hdr_seg);
    }

    pub fn set_meta(&mut self, meta: PacketMeta) {
        self.state.meta = meta;
    }

    /// Prepend the new headers to the [`Packet`] based on its current
    /// header and meta groups.
    pub fn emit_headers(&mut self) -> Result<(), WriteError> {
        // At this point the packet metadata represents the
        // transformations made by the pipeline, now we need to:
        //
        // 1. apply this to the header groups,
        //
        // 2. emit them to a new segment,
        //
        // 3. prepend the new header segment to the packet, and adjust
        //    the segments to replace the old headers with this new
        //    segment,
        //
        // 4. update the checksums to reflect the new header values.

        // Step 1. Unify the headers with the metadata.
        let total_hdr_len = self.unify_headers()?;

        // Now that the headers have been unified with the metadata
        // some of the length fields may need correction.
        self.state.headers.inner.set_lengths(
            &self.state.hdr_offsets.inner,
            total_hdr_len + self.state.body.len,
        );

        if self.state.headers.outer.is_some() {
            self.state.headers.outer.as_mut().unwrap().set_lengths(
                self.state.hdr_offsets.outer.as_ref().unwrap(),
                total_hdr_len + self.state.body.len,
            );
        }

        // Step 2. Determine the total size requirement of the final
        // headers and allocate a new segment to hold them.
        let mut total_sz = self.state.headers.inner.len();
        if self.state.headers.outer.is_some() {
            total_sz += self.state.headers.outer.as_ref().unwrap().len();
        }

        let mut hdr_seg = unsafe { PacketSeg::wrap(allocb(total_sz)) };

        // Emit each raw header in turn to new segment.
        if self.state.headers.outer.is_some() {
            self.state.headers.outer.as_ref().unwrap().write(&mut hdr_seg)?;
        }

        self.state.headers.inner.write(&mut hdr_seg)?;

        // Step 3. Prepend new header segment to the first body
        // segment. The packet still remains in `Parsed` state because
        // evertying was updated accrodingly and thus all stats such
        // as raw headers, offsets, and meta should be valid. Then
        // modify the segment data to effectively erase the old
        // headers, replacing them with this new header segment.
        self.replace_headers(hdr_seg);

        // Step 4. Update checksums.
        //
        // We start with the payload's original checksum for
        // efficiency. Then we recompute the ULP header portion of the
        // checksum to come up with the final ULP checksum.
        //
        // XXX Need to consider Tx checksum offloads here. For Oxide
        // we will have full hw offloads, but as a generic tool OPTE
        // can't assume that. We need HW capabs stashed somewhere in
        // the Port data. We also need to make sure to transfer any HW
        // offload info set in the mblk. With those two things, we can
        // then determine if and what we should do about checksums. If
        // there is no HW checksum offload, we can still make use of
        // the work the client already did to populate the inner
        // checksums by performing incremental checksums as we change
        // the header values. Furthermore, we should be able to use
        // these checksums as the base for the outer checksums. That
        // is, given the inner IPv4 checksum, we can add the inner
        // ether and outer geneve and use that as the outer UDP
        // checksum.
        match self.state.headers.inner.ulp.as_mut() {
            Some(ulp) => {
                let mut csum =
                    Checksum::from(self.state.inner_ulp_payload_csum.unwrap());
                match ulp {
                    UlpHdr::Tcp(tcp) => {
                        let ip = self.state.headers.inner.ip.as_ref().unwrap();
                        let tcp_off = self.state.hdr_offsets.inner.ulp.unwrap();
                        let csum_off =
                            tcp_off.seg_pos + crate::tcp::TCP_HDR_CSUM_OFF;
                        self.segs[0]
                            .write(&[0; 2], WritePos::Modify(csum_off as u16))
                            .unwrap();
                        let pseudo_csum = ip.pseudo_csum();
                        csum += pseudo_csum;
                        csum.add(
                            self.segs[0].slice(tcp_off.seg_pos, tcp.hdr_len()),
                        );
                        let tcp_csum = HeaderChecksum::from(csum).bytes();
                        self.segs[0]
                            .write(&tcp_csum, WritePos::Modify(csum_off as u16))
                            .unwrap();
                        tcp.set_csum(tcp_csum);
                    }

                    UlpHdr::Udp(udp) => {
                        // If the original packet didn't bother with
                        // the UDP checksum, neither will we.
                        if udp.csum != [0; 2] {
                            let ip =
                                self.state.headers.inner.ip.as_ref().unwrap();
                            let udp_off =
                                self.state.hdr_offsets.inner.ulp.unwrap();
                            let csum_off =
                                udp_off.seg_pos + crate::udp::UDP_HDR_CSUM_OFF;
                            self.segs[0]
                                .write(
                                    &[0; 2],
                                    WritePos::Modify(csum_off as u16),
                                )
                                .unwrap();
                            let pseudo_csum = ip.pseudo_csum();
                            csum += pseudo_csum;
                            csum.add(
                                self.segs[0]
                                    .slice(udp_off.seg_pos, udp.hdr_len()),
                            );
                            let udp_csum = HeaderChecksum::from(csum).bytes();
                            self.segs[0]
                                .write(
                                    &udp_csum,
                                    WritePos::Modify(csum_off as u16),
                                )
                                .unwrap();
                            udp.set_csum(udp_csum);
                        }
                    }
                }
            }

            None => (),
        }

        Ok(())
    }

    fn unify_outer_headers(&mut self) -> Result<usize, WriteError> {
        let outmg = &self.state.meta.outer;
        let mut pkt_offset = 0;
        let mut hgoff = HeaderGroupOffsets::default();

        match &outmg.ether {
            Some(eth) => {
                let ether = EtherHdr::from(eth);
                self.state.headers.outer = Some(HeaderGroup::new(ether));
                pkt_offset += ETHER_HDR_SZ;
            }

            None => {
                // If there is no outer Ethernet, then there can be no
                // outer headers at all.
                self.state.headers.outer = None;
                self.state.hdr_offsets.outer = None;
                return Ok(pkt_offset);
            }
        }

        let outh = self.state.headers.outer.as_mut().unwrap();

        if outmg.arp.is_some() {
            outh.unify_arp(outmg.arp.as_ref().unwrap());
            // TODO Don't I need to update offsets here and return?
            // Yes, this is a bug. Rather than fix it now I want to
            // wait until I have the time to write a test proving the
            // bug. This test is as simple as conjuring an ARP packet,
            // parsing the bytes, and verifying that the offsets are
            // missing.
        }

        if outmg.ip.is_some() {
            hgoff.ip = Some(HdrOffset {
                pkt_pos: pkt_offset,
                seg_idx: 0,
                seg_pos: pkt_offset,
            });

            match outmg.ip.as_ref().unwrap() {
                IpMeta::Ip4(ip4) => outh.unify_ip4(ip4),
                IpMeta::Ip6(ip6) => outh.unify_ip6(ip6),
            }

            pkt_offset += outh.ip.as_ref().unwrap().hdr_len();
        }

        if outmg.ulp.is_some() {
            hgoff.ulp = Some(HdrOffset {
                pkt_pos: pkt_offset,
                seg_idx: 0,
                seg_pos: pkt_offset,
            });

            match outmg.ulp.as_ref().unwrap() {
                UlpMeta::Udp(udp) => outh.unify_udp(udp),
                meta => todo!("implement outer proto: {:?}", meta),
            }

            pkt_offset += outh.ulp.as_ref().unwrap().hdr_len();
        }

        if outmg.encap.is_some() {
            hgoff.encap = Some(HdrOffset {
                pkt_pos: pkt_offset,
                seg_idx: 0,
                seg_pos: pkt_offset,
            });

            outh.unify_encap(outmg.encap.as_ref().unwrap());

            pkt_offset += outh.encap.as_ref().unwrap().hdr_len();
        }

        self.state.hdr_offsets.outer = Some(hgoff);
        Ok(pkt_offset)
    }

    fn unify_inner_headers(
        &mut self,
        mut pkt_offset: usize,
    ) -> Result<usize, WriteError> {
        let inmg = &self.state.meta.inner;
        let inh = &mut self.state.headers.inner;
        let hgoff = &mut self.state.hdr_offsets.inner;
        hgoff.ether =
            HdrOffset { pkt_pos: pkt_offset, seg_idx: 0, seg_pos: pkt_offset };

        let eth = inmg.ether.as_ref().unwrap();
        inh.ether.unify(eth);
        pkt_offset += ETHER_HDR_SZ;

        if inmg.arp.is_some() {
            inh.unify_arp(inmg.arp.as_ref().unwrap());
        }

        if inmg.ip.is_some() {
            hgoff.ip.replace(HdrOffset {
                pkt_pos: pkt_offset,
                seg_idx: 0,
                seg_pos: pkt_offset,
            });

            match inmg.ip.as_ref().unwrap() {
                IpMeta::Ip4(ip4) => inh.unify_ip4(ip4),
                IpMeta::Ip6(ip6) => inh.unify_ip6(ip6),
            }

            pkt_offset += inh.ip.as_ref().unwrap().hdr_len();
        }

        if inmg.ulp.is_some() {
            hgoff.ulp.replace(HdrOffset {
                pkt_pos: pkt_offset,
                seg_idx: 0,
                seg_pos: pkt_offset,
            });

            match inmg.ulp.as_ref().unwrap() {
                UlpMeta::Udp(udp) => inh.unify_udp(udp),
                UlpMeta::Tcp(tcp) => inh.unify_tcp(tcp),
            }

            pkt_offset += inh.ulp.as_ref().unwrap().hdr_len();
        }

        if inmg.encap.is_some() {
            hgoff.encap.replace(HdrOffset {
                pkt_pos: pkt_offset,
                seg_idx: 0,
                seg_pos: pkt_offset,
            });

            inh.unify_encap(inmg.encap.as_ref().unwrap());

            pkt_offset += inh.encap.as_ref().unwrap().hdr_len();
        }

        Ok(pkt_offset)
    }

    /// Unify the headers with the packet's metadata. Return the new
    /// total header length (as headers may have been removed, added,
    /// or adjusted).
    pub fn unify_headers(&mut self) -> Result<usize, WriteError> {
        let pkt_offset = self.unify_outer_headers()?;
        self.unify_inner_headers(pkt_offset)
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
    /// Clone and return all bytes. This is used for testing.
    pub fn all_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.state.len());
        for seg in &self.segs {
            let s = unsafe { slice::from_raw_parts((*seg.mp).b_rptr, seg.len) };
            bytes.extend_from_slice(s);
        }
        bytes
    }

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
    // The mp and dblk effecively live for the same amount of time as
    // far as this rust code is concerned.
    // phantom: PhantomData<&'a ()>,
    len: usize,
    avail: usize,
}

impl PacketSeg {
    fn link(&mut self, seg: &PacketSeg) {
        unsafe { (*self.mp).b_cont = seg.mp };
    }

    fn nullify_cont(&mut self) {
        unsafe { (*self.mp).b_cont = ptr::null_mut() };
    }

    // NOTE: This is used for the purpose of "erasing" header data
    // from a segment that has shared header + payload.
    fn shift_rptr(&mut self, amount: usize) {
        unsafe {
            (*self.mp).b_rptr = (*self.mp).b_rptr.add(amount);
        }

        self.len -= amount;
    }

    fn slice(&mut self, off: usize, len: usize) -> &[u8] {
        unsafe {
            let start = (*self.mp).b_rptr.add(off);
            slice::from_raw_parts(start, len)
        }
    }

    /// Wrap an existing `mblk_t`.
    ///
    /// Safety: The `mp` passed must be a pointer to an existing `mblk_t`.
    pub unsafe fn wrap(mp: *mut mblk_t) -> Self {
        let dblk = (*mp).b_datap as *mut dblk_t;
        let len = (*mp).b_wptr.offset_from((*mp).b_rptr) as usize;
        let avail = (*dblk).db_lim.offset_from((*dblk).db_base) as usize;

        PacketSeg { mp, dblk, avail, len } // phantom: PhantomData }
    }

    pub fn unwrap(self) -> *mut mblk_t {
        self.mp
    }

    /// Write the bytes in `src` to this segment at the `pos`
    /// specified. If the bytes cannot be written a `WriteError` is
    /// returned specifying why.
    pub fn write(
        &mut self,
        src: &[u8],
        pos: WritePos,
    ) -> result::Result<(), WriteError> {
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
                    let limit = (*self.dblk).db_lim;
                    let start = (*self.mp).b_wptr;
                    let end = start.add(src.len());
                    if end > limit as *mut c_uchar {
                        return Err(WriteError::NotEnoughBytes {
                            available: limit.offset_from(start) as usize,
                            needed: src.len(),
                        });
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
                    return Err(WriteError::NotEnoughBytes {
                        available: end.offset_from(start) as usize,
                        needed: src.len(),
                    });
                }

                let dst = slice::from_raw_parts_mut(start, src.len());
                (dst, None, None, self.len)
            },

            // XXX Perhaps I should just get rid of these WritePos
            // types that I'm not using?
            WritePos::ModAppend(offset) => unsafe {
                let wptr = (*self.mp).b_wptr;
                let limit = (*self.dblk).db_lim;
                let start = (*self.mp).b_rptr.add(offset as usize);
                let end = start.add(src.len());
                assert!(end >= (*self.mp).b_rptr);
                if start > wptr {
                    return Err(WriteError::OutOfRange);
                }

                if end > limit as *mut u8 {
                    return Err(WriteError::NotEnoughBytes {
                        available: limit.offset_from(start) as usize,
                        needed: src.len(),
                    });
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
                    return Err(WriteError::OutOfRange);
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    BadHeader(String),
    BadInnerIpLen { expected: usize, actual: usize },
    BadInnerUlpLen { expected: usize, actual: usize },
    BadOuterIpLen { expected: usize, actual: usize },
    BadOuterUlpLen { expected: usize, actual: usize },
    BadRead(ReadErr),
    TruncatedBody { expected: usize, actual: usize },
    UnsupportedEtherType(u16),
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
    NotEnoughBytes { available: usize, needed: usize },
    OutOfRange,
    StraddledWrite,
}

pub type ReadResult<T> = result::Result<T, ReadErr>;
pub type WriteResult<T> = result::Result<T, WriteError>;

/// A trait for reading bytes from packets.
///
/// All operations start from the current position and move it
/// forward, with the exception of `seek_back()`, which moves the
/// position backwards within the current segment.
pub trait PacketRead<'a> {
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
            segs: core::mem::take(&mut self.pkt.segs),
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
                return Err(WriteError::EndOfPacket);
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
#[derive(Debug)]
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
    pub fn finish(self) -> (usize, usize, usize, S, bool) {
        let end_of_seg = self.seg_pos == self.seg_len;
        (self.pkt_pos, self.seg_idx, self.seg_pos, self.state, end_of_seg)
    }

    pub fn new(pkt: &'a Packet<P>, state: S) -> Self {
        let seg_len = pkt.segs[0].len;

        PacketReader { pkt, pkt_pos: 0, seg_idx: 0, seg_pos: 0, seg_len, state }
    }

    fn pkt_pos(&self) -> usize {
        self.pkt_pos
    }

    fn state_mut(&mut self) -> &mut S {
        &mut self.state
    }
}

impl<'a, P, S> PacketRead<'a> for PacketReader<'a, P, S>
where
    P: PacketState + CanRead,
{
    fn pos(&self) -> usize {
        self.pkt_pos as usize
    }

    fn seek(&mut self, mut amount: usize) -> ReadResult<()> {
        while self.seg_pos + amount > self.seg_len {
            if self.seg_idx + 1 == self.pkt.segs.len() {
                return Err(ReadErr::OutOfRange);
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

    fn seg_idx(&self) -> usize {
        self.seg_idx
    }

    fn seg_pos(&self) -> usize {
        self.seg_pos
    }

    fn slice<'b>(&'b mut self, len: usize) -> ReadResult<&'a [u8]> {
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

    use crate::ether::ETHER_TYPE_IPV4;
    use crate::ip4::Ipv4AddrTuple;
    use crate::tcp::{TcpFlags, TCP_HDR_SZ};

    const SRC_MAC: [u8; 6] = [0xa8, 0x40, 0x25, 0x00, 0x00, 0x63];
    const DST_MAC: [u8; 6] = [0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d];

    const SRC_IP4: Ipv4AddrTuple = (10, 0, 0, 99);
    const DST_IP4: Ipv4AddrTuple = (52, 10, 128, 69);

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
        let pkt = Packet::alloc(ETHER_HDR_SZ + IPV4_HDR_SZ + TCP_HDR_SZ);
        let body = vec![];
        let mut tcp = TcpHdr::new(3839, 80);
        tcp.set_seq(4224936861);
        let ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, SRC_IP4, DST_IP4);
        let eth = EtherHdr::new(EtherType::Ipv4, SRC_MAC, DST_MAC);

        let mut wtr = PacketWriter::new(pkt, None);
        let _ = wtr.write(&eth.as_bytes()).unwrap();
        assert_eq!(wtr.pos(), ETHER_HDR_SZ);
        let _ = wtr.write(&ip4.as_bytes()).unwrap();
        assert_eq!(wtr.pos(), ETHER_HDR_SZ + IPV4_HDR_SZ);
        let _ = wtr.write(&tcp.as_bytes()).unwrap();
        assert_eq!(wtr.pos(), ETHER_HDR_SZ + IPV4_HDR_SZ + TCP_HDR_SZ);

        let pkt = wtr.finish();

        assert_eq!(pkt.len(), ETHER_HDR_SZ + IPV4_HDR_SZ + TCP_HDR_SZ);
        assert_eq!(pkt.num_segs(), 1);

        let parsed = pkt.parse().unwrap();
        assert_eq!(parsed.state.hdr_offsets.inner.ether.seg_idx, 0);
        assert_eq!(parsed.state.hdr_offsets.inner.ether.seg_pos, 0);

        let eth_meta = parsed.state.meta.inner.ether.as_ref().unwrap();
        assert_eq!(eth_meta.ether_type, ETHER_TYPE_IPV4);
        assert_eq!(eth_meta.dst, DST_MAC.into());
        assert_eq!(eth_meta.src, SRC_MAC.into());

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

        let pkt = unsafe { Packet::<Uninitialized>::wrap(mp1) };
        assert_eq!(pkt.num_segs(), 2);
        assert_eq!(pkt.avail(), 54);

        let body = vec![];
        let mut tcp = TcpHdr::new(3839, 80);
        tcp.set_seq(4224936861);
        let ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, SRC_IP4, DST_IP4);
        let eth = EtherHdr::new(EtherType::Ipv4, SRC_MAC, DST_MAC);

        let mut wtr = PacketWriter::new(pkt, None);
        let _ = wtr.write(&eth.as_bytes()).unwrap();
        assert_eq!(wtr.pos(), ETHER_HDR_SZ);
        let _ = wtr.write(&ip4.as_bytes()).unwrap();
        assert_eq!(wtr.pos(), ETHER_HDR_SZ + IPV4_HDR_SZ);
        let _ = wtr.write(&tcp.as_bytes()).unwrap();
        assert_eq!(wtr.pos(), ETHER_HDR_SZ + IPV4_HDR_SZ + TCP_HDR_SZ);

        let pkt = wtr.finish();

        assert_eq!(pkt.len(), ETHER_HDR_SZ + IPV4_HDR_SZ + TCP_HDR_SZ);
        assert_eq!(pkt.num_segs(), 2);

        let parsed = pkt.parse().unwrap();

        let eth_meta = parsed.state.meta.inner.ether.as_ref().unwrap();
        assert_eq!(parsed.state.hdr_offsets.inner.ether.seg_idx, 0);
        assert_eq!(parsed.state.hdr_offsets.inner.ether.seg_pos, 0);
        assert_eq!(eth_meta.ether_type, ETHER_TYPE_IPV4);
        assert_eq!(eth_meta.dst, DST_MAC.into());
        assert_eq!(eth_meta.src, SRC_MAC.into());

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
        assert_eq!(offsets.inner.ulp.as_ref().unwrap().seg_idx, 1);
        assert_eq!(offsets.inner.ulp.as_ref().unwrap().seg_pos, 0);
    }

    // Verify that we catch when a write require more bytes than are
    // available.
    #[test]
    fn not_enough_bytes() {
        let mp1 = allocb(42);
        let mp2 = allocb(12);

        unsafe {
            (*mp1).b_cont = mp2;
        }

        let pkt = unsafe { Packet::<Uninitialized>::wrap(mp1) };
        assert_eq!(pkt.num_segs(), 2);
        assert_eq!(pkt.avail(), 54);

        let body = vec![];
        let mut tcp = TcpHdr::new(3839, 80);
        tcp.set_seq(4224936861);
        let ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, SRC_IP4, DST_IP4);
        let eth = EtherHdr::new(EtherType::Ipv4, SRC_MAC, DST_MAC);

        let mut wtr = PacketWriter::new(pkt, None);
        let _ = wtr.write(&eth.as_bytes()).unwrap();
        assert_eq!(wtr.pos(), ETHER_HDR_SZ);
        let _ = wtr.write(&ip4.as_bytes()).unwrap();
        assert_eq!(wtr.pos(), ETHER_HDR_SZ + IPV4_HDR_SZ);
        let tcp_bytes = tcp.as_bytes();
        assert!(matches!(
            wtr.write(&tcp_bytes[0..12]),
            Err(WriteError::NotEnoughBytes { available: 8, needed: 12 })
        ));
    }

    // Verify that we catch when a read requires more bytes than are
    // available.
    #[test]
    fn not_enough_bytes_read() {
        let mp1 = allocb(24);
        let pkt = unsafe { Packet::<Uninitialized>::wrap(mp1) };
        assert_eq!(pkt.num_segs(), 1);
        assert_eq!(pkt.avail(), 24);

        let body = vec![];
        let mut tcp = TcpHdr::new(3839, 80);
        tcp.set_seq(4224936861);
        let ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, SRC_IP4, DST_IP4);
        let eth = EtherHdr::new(EtherType::Ipv4, SRC_MAC, DST_MAC);

        let mut wtr = PacketWriter::new(pkt, None);
        let _ = wtr.write(&eth.as_bytes()).unwrap();
        assert_eq!(wtr.pos(), ETHER_HDR_SZ);
        let _ = wtr.write(&ip4.as_bytes()[0..10]).unwrap();

        let pkt = wtr.finish();
        let mut rdr = PacketReader::new(&pkt, ());
        let _ = rdr.slice(ETHER_HDR_SZ);
        assert!(matches!(rdr.slice(IPV4_HDR_SZ), Err(ReadErr::NotEnoughBytes)));
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

        let pkt = unsafe { Packet::<Uninitialized>::wrap(mp1) };
        assert_eq!(pkt.num_segs(), 2);
        assert_eq!(pkt.avail(), 54);

        let body = vec![];
        let mut tcp = TcpHdr::new(3839, 80);
        tcp.set_seq(4224936861);
        let ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, SRC_IP4, DST_IP4);
        let eth = EtherHdr::new(EtherType::Ipv4, SRC_MAC, DST_MAC);

        let mut wtr = PacketWriter::new(pkt, None);
        let _ = wtr.write(&eth.as_bytes()).unwrap();
        assert_eq!(wtr.pos(), ETHER_HDR_SZ);
        let _ = wtr.write(&ip4.as_bytes()).unwrap();
        assert_eq!(wtr.pos(), ETHER_HDR_SZ + IPV4_HDR_SZ);
        let tcp_bytes = &tcp.as_bytes();
        let _ = wtr.write(&tcp_bytes[0..12]).unwrap();
        let _ = wtr.write(&tcp_bytes[12..]).unwrap();
        assert_eq!(wtr.pos(), ETHER_HDR_SZ + IPV4_HDR_SZ + TCP_HDR_SZ);

        let pkt = wtr.finish();

        assert_eq!(pkt.len(), ETHER_HDR_SZ + IPV4_HDR_SZ + TCP_HDR_SZ);
        assert_eq!(pkt.num_segs(), 2);
        assert!(matches!(pkt.parse(), Err(ParseError::BadHeader(_))));
    }
}

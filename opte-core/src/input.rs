//! TODO document me!
#[cfg(any(feature = "std", test))]
use std::convert::TryInto;

use std::prelude::v1::*;

use crate::ether::EtherAddr;
use crate::ip4::{Ipv4Addr, Protocol};
use crate::Direction;

/// A type that can represent a packet and be used by `PacketReader`.
pub trait Packet {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadErr {
    BadLayout,
    NotEnoughBytes,
    StraddledHeader,
}

// TODO rename ReadResult?
pub type Result<T> = core::result::Result<T, ReadErr>;

/// TODO document me
pub trait PacketReader {
    fn get_pos(&self) -> usize;
    fn get_slice(&mut self, len: usize)
        -> core::result::Result<&[u8], ReadErr>;
    fn get_slice_mut(
        &mut self,
        len: usize,
    ) -> core::result::Result<&mut [u8], ReadErr>;
    fn read_bytes(&mut self, dst: &mut [u8]) -> Result<()>;
    fn read_u8(&mut self, dst: &mut u8) -> Result<()>;
    fn read_u16(&mut self, dst: &mut u16) -> Result<()>;
    fn read_u32(&mut self, dst: &mut u32) -> Result<()>;
    fn seek_back(&mut self, offset: usize) -> Result<()>;
    fn seek(&mut self, offset: usize) -> Result<()>;
}

// ================================================================
// Vec-based packets, useful for testing.
// ================================================================

/// TODO doc
#[cfg(any(feature = "std", test))]
pub struct VecPacket {
    bytes: Vec<u8>,
}

#[cfg(any(feature = "std", test))]
impl VecPacket {
    /// TODO doc
    ///
    /// TODO Could just name this `copy` and take any input that impls
    /// `AsRef<[u8]>`.
    pub fn copy_slice(bslice: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(bslice.len());
        bytes.extend_from_slice(bslice);
        VecPacket { bytes }
    }

    pub fn get_bytes(&self) -> &[u8] {
        &self.bytes[..]
    }
}

#[cfg(any(feature = "std", test))]
impl Packet for VecPacket {}

#[cfg(any(feature = "std", test))]
pub struct VecPacketReader<'a> {
    pkt: &'a mut VecPacket,
    pos: usize,
}

#[cfg(any(feature = "std", test))]
impl<'a> VecPacketReader<'a> {
    pub fn new(pkt: &'a mut VecPacket) -> VecPacketReader<'a> {
        VecPacketReader { pkt, pos: 0 }
    }
}

#[cfg(any(feature = "std", test))]
impl<'a> PacketReader for VecPacketReader<'a> {
    fn get_pos(&self) -> usize {
        self.pos
    }

    fn get_slice(
        &mut self,
        len: usize,
    ) -> core::result::Result<&[u8], ReadErr> {
        if self.pos + len > self.pkt.bytes.len() {
            return Err(ReadErr::NotEnoughBytes);
        }

        let s = &self.pkt.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(s)
    }

    fn get_slice_mut(
        &mut self,
        len: usize,
    ) -> core::result::Result<&mut [u8], ReadErr> {
        if self.pos + len > self.pkt.bytes.len() {
            return Err(ReadErr::NotEnoughBytes);
        }

        let s = &mut self.pkt.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(s)
    }

    fn read_bytes(&mut self, dst: &mut [u8]) -> Result<()> {
        if self.pos + dst.len() > self.pkt.bytes.len() {
            return Err(ReadErr::NotEnoughBytes);
        }

        dst.clone_from_slice(&self.pkt.bytes[self.pos..self.pos + dst.len()]);
        self.pos += dst.len();
        Ok(())
    }

    fn read_u8(&mut self, dst: &mut u8) -> Result<()> {
        if self.pos + 1 > self.pkt.bytes.len() {
            return Err(ReadErr::NotEnoughBytes);
        }

        *dst = self.pkt.bytes[self.pos];
        self.pos += 1;
        Ok(())
    }

    fn read_u16(&mut self, dst: &mut u16) -> Result<()> {
        if self.pos + 2 > self.pkt.bytes.len() {
            return Err(ReadErr::NotEnoughBytes);
        }

        *dst = u16::from_be_bytes(
            (&self.pkt.bytes[self.pos..self.pos + 2]).try_into().unwrap(),
        );
        self.pos += 2;
        Ok(())
    }

    fn read_u32(&mut self, dst: &mut u32) -> Result<()> {
        if self.pos + 4 > self.pkt.bytes.len() {
            return Err(ReadErr::NotEnoughBytes);
        }

        *dst = u32::from_be_bytes(
            (&self.pkt.bytes[self.pos..self.pos + 4]).try_into().unwrap(),
        );
        self.pos += 4;
        Ok(())
    }

    fn seek_back(&mut self, offset: usize) -> Result<()> {
        if offset > self.pos {
            return Err(ReadErr::NotEnoughBytes);
        }

        self.pos -= offset;
        Ok(())
    }

    fn seek(&mut self, offset: usize) -> Result<()> {
        if self.pos + offset > self.pkt.bytes.len() {
            return Err(ReadErr::NotEnoughBytes);
        }

        self.pos += offset;
        Ok(())
    }
}

// ================================================================
// illumos mblk_t parsing
//
// This is only needed in no_std, for the opte kernel module.
// ================================================================
#[cfg(all(not(feature = "std"), not(test)))]
use illumos_ddi_dki::{allocb, bcopy, c_void, mblk_t, msgsize};

#[cfg(all(not(feature = "std"), not(test)))]
#[derive(Clone, Copy)]
pub struct MblkPacket {
    // TODO The more I think about it the more I think I should just
    // convert into a slice via slice::from_raw_parts(). Let's go over
    // the safety requirements of this interface and see how the
    // illumos mblk meets them (I'm going to reference the points in
    // turn and not repeat them verbatim here):
    //
    // I realized as I'm typing this I'm really talking about turning
    // the b_rptr into a slice (`&[u8]`). I should update this struct
    // to instead have `cur_buf: &mut [u8]` along with a raw pointer
    // (or perhaps also a reference for that) to the raw mblk.
    //
    // https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html
    //
    //    o The mblk itself is a single object (allocation) and its
    //      data buffer consist of a single object. Of course, the
    //      real packet may span multiple mblks, but that's when we
    //      walk to the next mblk and update the slice reference (e.g.
    //      when using MblkPacketReader).
    //
    //    o The mblk is non-null, we could also just add a check of
    //      the raw pointer before the call to be extra sure.
    //
    //    o The allocation for the mblk is aligned, as is the data
    //      buffer (which is easy since it's just `char *`).
    //
    //    o The `b_rptr` points to exactly `cur_len` bytes, "properly
    //      initialized", which isn't defined here. I guess it just
    //      means that the mblk's data buffer didn't just come filled
    //      with whatever bytes were left from a previous allocation?
    //      I think we do zero them explicitly before use, but not
    //      really sure how it matters given any string of bits will
    //      make a valid u8. And in fact, the entire reason we are
    //      parsing this buffer stream is to a) check that the stream
    //      of bytes actually makes valid headers, and b) to
    //      initialize header structs from these bytes.
    //
    //    o OPTE is basically an extension of mac, and as with mac it
    //      can and should assume that no other entity is
    //      reading/writing to the buffer as its working with it.
    //      Could a nefarious actor try to break this contract, sure,
    //      and that's why viona's first action in the Tx path is to
    //      copy all header bytes into a fresh, host-owned mblk to
    //      pass to the rest of the system, to prevent TOCTOU attack.
    //      If other part of illumos are violating this contract, then
    //      they would not just be breaking OPTE, but all of mac and
    //      probably other parts of the system. Basically, when an
    //      mblk pointer is passed to a module, that module "owns" it
    //      (really the kmem allocator owns the memory, which
    //      effecitvely makes everyone else a `&mut [u8]` like
    //      consumer). That's all a long way of saying that Rust's
    //      aliasing rules for a unique reference (`&mut`) are upheld
    //      by illumos re mblks.
    //
    //    o The largest mblk buffer is 64K. Perhaps one day that will
    //      increase but it should never touch the realm of
    //      `isize::MAX`, otherwise we have many other harder problems
    //      than this one.
    source_mp: *mut mblk_t,
    cur_len: usize,
}

#[cfg(all(not(feature = "std"), not(test)))]
impl MblkPacket {
    // TODO docs
    pub fn alloc(size: usize) -> Self {
        // TODO Could replace `usize` with a type like MblkSize.
        assert!(size <= u16::MAX as usize);

        // Safety: We know this is safe because allocb should be safe
        // for any size. Furthermore, we restrict size to the typical
        // max IP packet, which is definitely safe.
        let mp = unsafe { allocb(size, 0) };
        MblkPacket::wrap(mp)
    }

    // TODO docs
    pub fn copy_bytes(&mut self, src: &[u8]) {
        // TODO check len against avail and return error.

        // Safety: This is actually unsafe right now until I check
        // that src.len() fits inside the space available between
        // b_wptr and the limit of the dblk.
        unsafe {
            bcopy(
                src.as_ptr() as *const c_void,
                (*self.source_mp).b_wptr as *mut c_void,
                src.len(),
            );

            // TODO Add "safety" annotation here.
            (*self.source_mp).b_wptr = (*self.source_mp).b_wptr.add(src.len());
        }
    }

    /// Get the length of the entire packet.
    ///
    /// TODO In the future we might want to perform memoization, but
    /// we'd have to be careful if we're modifying the underlying
    /// bytes. For now the caller can choose to cache the result if
    /// they want.
    ///
    /// TODO We might want a mblk_lengths() that gives the length of
    /// each fragment (mblk) that makes up the packet.
    ///
    /// ```
    /// fn mblk_lengths(&self) -> Vec<usize>
    /// ```
    pub fn len(&self) -> usize {
        // Safety: If we have an instance of MblkPacket, which can
        // only be created via `new`, then we know there is a valid
        // `mblk_t` pointer in `source_mp`.
        unsafe { msgsize(self.source_mp) }
    }

    // TODO docs
    pub fn unwrap(self) -> *mut mblk_t {
        self.source_mp
    }

    // TODO docs
    pub fn wrap(mp: *mut mblk_t) -> Self {
        let cur_len;
        unsafe {
            cur_len = (*mp).b_wptr.offset_from((*mp).b_rptr) as usize;
        }
        MblkPacket { source_mp: mp, cur_len }
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
impl Packet for MblkPacket {}

#[cfg(all(not(feature = "std"), not(test)))]
pub struct MblkPacketReader {
    pkt: MblkPacket,
    cur_pos: usize,
    total_pos: usize,
}

#[cfg(all(not(feature = "std"), not(test)))]
impl MblkPacketReader {
    // Any given read should _never_ cross a `b_cont` boundary. In
    // fact, a given header should always be contained in one mblk,
    // because when you think about it any given header should be
    // contained in the same allocation. Therefore, I think it is
    // reasonable to reject any packets which have a header crossing a
    // `b_cont` boundary.
    fn check_buf(&mut self, len: usize) -> Result<()> {
        self.follow_cont();

        if self.cur_pos + len > self.pkt.cur_len {
            unsafe {
                if !(*self.pkt.source_mp).b_cont.is_null() {
                    return Err(ReadErr::StraddledHeader);
                }
            }

            return Err(ReadErr::NotEnoughBytes);
        }

        Ok(())
    }

    fn follow_cont(&mut self) {
        assert!(self.cur_pos <= self.pkt.cur_len);

        unsafe {
            if self.cur_pos == self.pkt.cur_len
                && !(*self.pkt.source_mp).b_cont.is_null()
            {
                self.pkt = MblkPacket::wrap((*self.pkt.source_mp).b_cont);
                self.cur_pos = 0;
            }
        }
    }

    pub fn new(pkt: MblkPacket) -> MblkPacketReader {
        MblkPacketReader { pkt, cur_pos: 0, total_pos: 0 }
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
impl PacketReader for MblkPacketReader {
    fn get_pos(&self) -> usize {
        self.total_pos
    }

    fn get_slice(
        &mut self,
        len: usize,
    ) -> core::result::Result<&[u8], ReadErr> {
        self.check_buf(len)?;
        let start = unsafe { (*self.pkt.source_mp).b_rptr.add(self.cur_pos) };
        let ret = unsafe { core::slice::from_raw_parts(start, len) };
        self.cur_pos += len;
        self.total_pos += len;
        Ok(ret)
    }

    fn get_slice_mut(
        &mut self,
        len: usize,
    ) -> core::result::Result<&mut [u8], ReadErr> {
        self.check_buf(len)?;
        let start = unsafe { (*self.pkt.source_mp).b_rptr.add(self.cur_pos) };
        let ret = unsafe { core::slice::from_raw_parts_mut(start, len) };
        self.cur_pos += len;
        self.total_pos += len;
        Ok(ret)
    }

    fn read_bytes(&mut self, dst: &mut [u8]) -> Result<()> {
        self.check_buf(dst.len())?;

        unsafe {
            let start = (*self.pkt.source_mp).b_rptr.add(self.cur_pos);
            start.copy_to_nonoverlapping(dst.as_mut_ptr(), dst.len());
        }

        self.cur_pos += dst.len();
        self.total_pos += dst.len();
        Ok(())
    }

    fn read_u8(&mut self, dst: &mut u8) -> Result<()> {
        self.check_buf(1)?;

        unsafe {
            let mut tmp = [0u8; 1];
            let start = (*self.pkt.source_mp).b_rptr.add(self.cur_pos);
            start.copy_to_nonoverlapping(tmp.as_mut_ptr(), tmp.len());
            *dst = u8::from_be_bytes(tmp);
        }

        self.cur_pos += 1;
        self.total_pos += 1;
        Ok(())
    }

    fn read_u16(&mut self, dst: &mut u16) -> Result<()> {
        self.check_buf(2)?;

        unsafe {
            let mut tmp = [0u8; 2];
            let start = (*self.pkt.source_mp).b_rptr.add(self.cur_pos);
            start.copy_to_nonoverlapping(tmp.as_mut_ptr(), tmp.len());
            *dst = u16::from_be_bytes(tmp);
        }

        self.cur_pos += 2;
        self.total_pos += 2;
        Ok(())
    }

    fn read_u32(&mut self, dst: &mut u32) -> Result<()> {
        self.check_buf(4)?;

        unsafe {
            let mut tmp = [0u8; 4];
            let start = (*self.pkt.source_mp).b_rptr.add(self.cur_pos);
            start.copy_to_nonoverlapping(tmp.as_mut_ptr(), tmp.len());
            *dst = u32::from_be_bytes(tmp);
        }

        self.cur_pos += 4;
        self.total_pos += 4;
        Ok(())
    }

    // We only allow to seek backwards to the beginning of the current
    // mblk, which should be enough in all situations this is needed.
    fn seek_back(&mut self, offset: usize) -> Result<()> {
        if offset > self.cur_pos {
            return Err(ReadErr::NotEnoughBytes);
        }

        self.cur_pos -= offset;
        Ok(())
    }

    fn seek(&mut self, offset: usize) -> Result<()> {
        self.check_buf(offset)?;
        self.cur_pos += offset;
        self.total_pos += offset;
        Ok(())
    }
}

// TODO get rid of this type (it's from older version of OPTE but it's
// still used in places)
#[repr(align(64))]
#[derive(Debug)]
pub struct PacketMetaOld {
    pub dir: Direction,
    pub packet_len: u32,
    pub ether_src: EtherAddr,
    pub ether_dst: EtherAddr,
    pub ip_src: Ipv4Addr,
    pub ip_dst: Ipv4Addr,
    pub ip_proto: Protocol,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_seq: Option<u32>,
    pub tcp_ack: Option<u32>,
    pub tcp_flags: u8,
}

impl PacketMetaOld {
    pub fn new(dir: Direction) -> Self {
        PacketMetaOld {
            dir,
            packet_len: 0,
            ether_src: [0; 6],
            ether_dst: [0; 6],
            ip_src: 0.into(),
            ip_dst: 0.into(),
            ip_proto: Protocol::TCP,
            src_port: None,
            dst_port: None,
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: 0,
        }
    }

    pub fn has_tcp_flag(&self, flag: u8) -> bool {
        (self.tcp_flags & flag) != 0
    }
}

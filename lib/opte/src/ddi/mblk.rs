// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use crate::engine::packet::BufferState;
use crate::engine::packet::Pullup;
use crate::engine::packet::SegAdjustError;
use crate::engine::packet::WrapError;
use crate::engine::packet::WriteError;
#[cfg(any(feature = "std", test))]
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::mem::MaybeUninit;
use core::ops::Deref;
use core::ops::DerefMut;
use core::ptr;
use core::ptr::NonNull;
use core::slice;
#[cfg(all(not(feature = "std"), not(test)))]
use illumos_sys_hdrs as ddi;
#[cfg(any(feature = "std", test))]
use illumos_sys_hdrs::c_uchar;
#[cfg(any(feature = "std", test))]
use illumos_sys_hdrs::dblk_t;
use illumos_sys_hdrs::mac::mac_ether_offload_info_t;
use illumos_sys_hdrs::mac::mac_ether_tun_info_t;
#[cfg(all(not(feature = "std"), not(test)))]
use illumos_sys_hdrs::mac::MacEtherOffloadFlags;
use illumos_sys_hdrs::mac::MacTunType;
use illumos_sys_hdrs::mac::MblkOffloadFlags;
use illumos_sys_hdrs::mblk_t;
use illumos_sys_hdrs::uintptr_t;
use ingot::types::Emit;
use ingot::types::EmitDoesNotRelyOnBufContents;
use ingot::types::ParseError as IngotParseErr;
use ingot::types::Read;

pub static MBLK_MAX_SIZE: usize = u16::MAX as usize;

/// Abstractions over an `mblk_t` which can be returned to their
/// raw pointer representation.
pub trait AsMblk {
    /// Consume `self`, returning the underlying `mblk_t`. The caller of this
    /// function now owns the underlying segment chain.
    fn unwrap_mblk(self) -> Option<NonNull<mblk_t>>;
}

/// The head and tail of an mblk_t list.
struct MsgBlkChainInner {
    head: NonNull<mblk_t>,
    tail: NonNull<mblk_t>,
}

/// A chain of illumos MsgBlk/`mblk_t` buffers.
///
/// Network packets are provided by illumos as a linked list of linked lists,
/// using the `b_next` and `b_prev` fields.
///
/// See the documentation for [`crate::engine::packet::Packet`] and/or [`MsgBlk`]
/// for full context.
// TODO: We might retool this type now that MsgBlk does not decompose
// each mblk_t into individual segments (i.e., packets could be allocated
// a lifetime via PhantomData based on whether we want to remove them from the chain or modify in place).
// Today's code is all equivalent to always using 'static, because
// we remove and re-add the mblks to work on them.
// We might want also want to return either a chain/mblk_t in an enum, but
// practically XDE will always assume it has a chain from MAC.
pub struct MsgBlkChain(Option<MsgBlkChainInner>);

impl MsgBlkChain {
    /// Create an empty packet chain.
    pub fn empty() -> Self {
        Self(None)
    }

    /// Convert an mblk_t packet chain into a safe source of `MsgBlk`s.
    ///
    /// # Safety
    /// The `mp` pointer must point to an `mblk_t` allocated by
    /// `allocb(9F)` or provided by some kernel API which itself used
    /// one of the DDI/DKI APIs to allocate it.
    /// Packets must form a valid linked list (no loops).
    /// The original mblk_t pointer must not be used again.
    pub unsafe fn new(mp: *mut mblk_t) -> Result<Self, WrapError> {
        let head = NonNull::new(mp).ok_or(WrapError::NullPtr)?;

        // Walk the chain to find the tail, and support faster append.
        let mut tail = head;
        while let Some(next_ptr) = NonNull::new((*tail.as_ptr()).b_next) {
            tail = next_ptr;
        }

        Ok(Self(Some(MsgBlkChainInner { head, tail })))
    }

    /// Removes the next packet from the top of the chain and returns
    /// it, taking ownership.
    pub fn pop_front(&mut self) -> Option<MsgBlk> {
        if let Some(ref mut list) = &mut self.0 {
            unsafe {
                let curr_b = list.head;
                let curr = curr_b.as_ptr();
                let next = NonNull::new((*curr).b_next);

                // Break the forward link on the packet we have access to,
                // and the backward link on the next element if possible.
                if let Some(next) = next {
                    (*next.as_ptr()).b_prev = ptr::null_mut();
                }
                (*curr).b_next = ptr::null_mut();

                // Update the current head. If the next element is null,
                // we're now empty.
                if let Some(next) = next {
                    list.head = next;
                } else {
                    self.0 = None;
                }

                Some(MsgBlk(curr_b))
            }
        } else {
            None
        }
    }

    /// Adds an owned `MsgBlk` to the end of this chain.
    ///
    /// Internally, this unwraps the `MsgBlk` back into an mblk_t,
    /// before placing it at the tail.
    pub fn append(&mut self, packet: MsgBlk) {
        // Unwrap safety: a valid Packet implies a non-null mblk_t.
        // Jamming `NonNull` into PacketSeg/Packet might take some
        // work just to avoid this unwrap.
        let pkt = packet.unwrap_mblk();

        // We're guaranteeing today that a 'static Packet has
        // no neighbours and is not part of a chain.
        // This simplifies tail updates in both cases (no chain walk).
        unsafe {
            assert!((*pkt.as_ptr()).b_prev.is_null());
            assert!((*pkt.as_ptr()).b_next.is_null());
        }

        if let Some(ref mut list) = &mut self.0 {
            let pkt_p = pkt.as_ptr();
            let tail_p = list.tail.as_ptr();
            unsafe {
                (*tail_p).b_next = pkt_p;
                (*pkt_p).b_prev = tail_p;
                // pkt_p->b_next is already null.
            }
            list.tail = pkt;
        } else {
            self.0 = Some(MsgBlkChainInner { head: pkt, tail: pkt });
        }
    }
}

impl AsMblk for MsgBlkChain {
    fn unwrap_mblk(mut self) -> Option<NonNull<mblk_t>> {
        self.0.take().map(|v| v.head)
    }
}

impl Drop for MsgBlkChain {
    fn drop(&mut self) {
        // This is a minor variation on MsgBlk's logic. illumos
        // contains helper functions from STREAMS to just drop a whole
        // chain.
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                // Safety: This is safe as long as the original
                // `mblk_t` came from a call to `allocb(9F)` (or
                // similar API).
                if let Some(list) = &self.0 {
                    unsafe { ddi::freemsgchain(list.head.as_ptr()) };
                }
            } else {
                while let Some(pkt) = self.pop_front() {
                    drop(pkt);
                }
            }
        }
    }
}

/// An individual illumos `mblk_t` -- a single bytestream
/// comprised of a linked list of data segments.
///
/// To facilitate testing the OPTE core, [`MsgBlk`] is an abstraction for
/// manipulating network packets in both a `std` and `no_std` environment.
/// The first is useful for writing tests against the OPTE core engine and
/// executing them in userland, without the need for standing up a full-blown
/// virtual machine.
///
/// The `no_std` implementation is used when running in-kernel. The
/// main difference is the `mblk_t` and `dblk_t` structures are coming
/// from viona (outbound/Tx) and mac (inbound/Rx), and we consume them
/// via [`MsgBlk::wrap_mblk()`]. In reality this is typically holding
/// an Ethernet _frame_, but we prefer to use the colloquial
/// nomenclature of "packet".
#[derive(Debug)]
pub struct MsgBlk(NonNull<mblk_t>);

impl Deref for MsgBlk {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe {
            let self_ptr = self.0.as_ptr();
            let rptr = (*self_ptr).b_rptr;
            let len = (*self_ptr).b_wptr.offset_from(rptr) as usize;
            slice::from_raw_parts(rptr, len)
        }
    }
}

impl DerefMut for MsgBlk {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            let self_ptr = self.0.as_ptr();
            let rptr = (*self_ptr).b_rptr;
            let len = (*self_ptr).b_wptr.offset_from(rptr) as usize;
            slice::from_raw_parts_mut(rptr, len)
        }
    }
}

impl MsgBlk {
    /// Allocate a new [`MsgBlk`] containing a data buffer of `len`
    /// bytes.
    ///
    /// The returned packet consists of exactly one segment, and the
    /// underlying `dblk_t` will have only a single referent making
    /// mutable access safe.
    ///
    /// In the kernel environment this uses `allocb(9F)` and
    /// `freemsg(9F)` under the hood.
    ///
    /// In the `std` environment this uses a mock implementation of
    /// `allocb(9F)` and `freeb(9F)`, which contains enough scaffolding
    /// to satisfy OPTE's use of the underlying `mblk_t` and `dblk_t`
    /// structures.
    pub fn new(len: usize) -> Self {
        let inner = NonNull::new(allocb(len))
            .expect("somehow failed to get an mblk...");

        Self(inner)
    }

    /// Allocates a new [`MsgBlk`] of size `buf.len()`, copying its
    /// contents.
    pub fn copy(buf: impl AsRef<[u8]>) -> Self {
        let mut out = Self::new(buf.as_ref().len());
        // Unwrap safety -- just allocated length of input buffer.
        out.write_bytes_back(buf).unwrap();
        out
    }

    /// Creates a new [`MsgBlk`] using a given set of packet headers.
    pub fn new_pkt(emit: impl Emit + EmitDoesNotRelyOnBufContents) -> Self {
        let mut pkt = Self::new(emit.packet_length());
        pkt.emit_back(emit).unwrap();
        pkt
    }

    /// Returns the number of bytes available for writing ahead of the
    /// read pointer in the current datablock.
    pub fn head_capacity(&self) -> usize {
        unsafe {
            let inner = self.0.as_ptr();

            (*inner).b_rptr.offset_from((*(*inner).b_datap).db_base) as usize
        }
    }

    /// Returns the number of bytes available for writing after the
    /// write pointer in the current datablock.
    pub fn tail_capacity(&self) -> usize {
        unsafe {
            let inner = self.0.as_ptr();

            (*(*inner).b_datap).db_lim.offset_from((*inner).b_wptr) as usize
        }
    }

    /// Returns the number of bytes allocated in all datablocks in
    /// this message.
    pub fn all_segs_capacity(&self) -> usize {
        self.iter()
            .map(|v| unsafe {
                let tail = (*v.0.b_datap).db_lim;
                let head = (*v.0.b_datap).db_base;

                tail.offset_from(head) as usize
            })
            .sum()
    }

    /// Creates a new [`MsgBlk`] containing a data buffer of `len`
    /// bytes with 2B of headroom/alignment.
    ///
    /// This sets up 4B alignment on all post-ethernet headers.
    pub fn new_ethernet(len: usize) -> Self {
        Self::new_with_headroom(2, len)
    }

    /// Creates a new [`MsgBlk`] using a given set of packet headers
    /// with 2B of headroom/alignment.
    ///
    /// This sets up 4B alignment on all post-ethernet headers.
    pub fn new_ethernet_pkt(
        emit: impl Emit + EmitDoesNotRelyOnBufContents,
    ) -> Self {
        let mut pkt = Self::new_ethernet(emit.packet_length());
        pkt.emit_back(emit).unwrap();
        pkt
    }

    /// Return the number of initialised bytes in this `MsgBlk` over
    /// all linked segments.
    pub fn byte_len(&self) -> usize {
        unsafe { count_mblk_bytes(Some(self.0)) }
    }

    /// Return the number of segments in this `MsgBlk`.
    pub fn seg_len(&self) -> usize {
        self.iter().len()
    }

    /// Truncates an `MsgBlk` chain, dropping any elements such that
    /// it contains at most `len` bytes.
    pub fn truncate_chain(&mut self, len: usize) {
        let mut seen = 0;
        let mut curr = Some(self.0);
        let mut old_tail = ptr::null_mut();

        while let Some(valid_curr) = curr.take() {
            let valid_curr = valid_curr.as_ptr();

            let seg_len = usize::try_from(unsafe {
                (*valid_curr).b_wptr.offset_from((*valid_curr).b_rptr)
            })
            .expect("operating on packet with end before start");

            let seen_til_now = seen;
            seen += seg_len;

            if seen >= len {
                let to_keep = len.saturating_sub(seen_til_now);

                // SAFETY: this will only reduce the read window of this slice,
                // so derived byteslices will remain in capacity.
                unsafe {
                    (*valid_curr).b_wptr = (*valid_curr).b_rptr.add(to_keep);

                    core::ptr::swap(
                        &raw mut (*valid_curr).b_cont,
                        &raw mut old_tail,
                    );
                }
            } else {
                curr = NonNull::new(unsafe { (*valid_curr).b_cont });
            }
        }

        // SAFETY: we have exclusive ownership of this element
        // via self, and we have just disconnected it from the chain.
        // This method also handles the nullptr case on our behalf.
        drop(unsafe { Self::wrap_mblk(old_tail) })
    }

    /// Allocate a new [`MsgBlk`] containing a data buffer of size
    /// `head_len + body_len`.
    ///
    /// The read/write pointer is set to have `head_len` bytes of
    /// headroom and `body_len` bytes of capacity at the back.
    pub fn new_with_headroom(head_len: usize, body_len: usize) -> Self {
        let out = Self::new(head_len + body_len);

        // SAFETY: alloc is contiguous and always larger than head_len.
        let mut_out = out.0.as_ptr();
        unsafe {
            (*mut_out).b_rptr = (*mut_out).b_rptr.add(head_len);
            (*mut_out).b_wptr = (*mut_out).b_rptr;
        }

        out
    }

    /// Provides a slice of length `n_bytes` at the back of an [`MsgBlk`]
    /// (if capacity exists) to be initialised, before increasing `len`
    /// by `n_bytes`.
    ///
    /// # Safety
    /// Users must write a value to every element of the `MaybeUninit`
    /// buffer at least once in the `MsgBlk` lifecycle -- all `n_bytes`
    /// are assumed to be initialised.
    pub unsafe fn write_back(
        &mut self,
        n_bytes: usize,
        f: impl FnOnce(&mut [MaybeUninit<u8>]),
    ) -> Result<(), WriteError> {
        let mut_out = self.0.as_ptr();
        let avail_bytes = unsafe {
            (*(*mut_out).b_datap).db_lim.offset_from((*mut_out).b_wptr)
        };

        if avail_bytes < 0 || (avail_bytes as usize) < n_bytes {
            return Err(WriteError::NotEnoughBytes {
                available: avail_bytes.max(0) as usize,
                needed: n_bytes,
            });
        }

        let in_slice = unsafe {
            slice::from_raw_parts_mut(
                (*mut_out).b_wptr as *mut MaybeUninit<u8>,
                n_bytes,
            )
        };

        f(in_slice);

        unsafe {
            (*mut_out).b_wptr = (*mut_out).b_wptr.add(n_bytes);
        }

        Ok(())
    }

    /// Provides a slice of length `n_bytes` at the front of an [`MsgBlk`]
    /// (if capacity exists) to be initialised, before increasing `len`
    /// by `n_bytes`.
    ///
    /// # Safety
    /// Users must write a value to every element of the `MaybeUninit`
    /// buffer at least once in the `MsgBlk` lifecycle -- all `n_bytes`
    /// are assumed to be initialised.
    pub unsafe fn write_front(
        &mut self,
        n_bytes: usize,
        f: impl FnOnce(&mut [MaybeUninit<u8>]),
    ) -> Result<(), WriteError> {
        let mut_out = self.0.as_ptr();
        let avail_bytes = unsafe {
            (*mut_out).b_rptr.offset_from((*(*mut_out).b_datap).db_base)
        };

        if avail_bytes < 0 || (avail_bytes as usize) < n_bytes {
            return Err(WriteError::NotEnoughBytes {
                available: avail_bytes.max(0) as usize,
                needed: n_bytes,
            });
        }

        let new_head = unsafe { (*mut_out).b_rptr.sub(n_bytes) };

        let in_slice = unsafe {
            slice::from_raw_parts_mut(new_head as *mut MaybeUninit<u8>, n_bytes)
        };

        f(in_slice);

        (*mut_out).b_rptr = new_head;

        Ok(())
    }

    /// Adjusts the write pointer for this MsgBlk, initialising any extra bytes to 0.
    pub fn resize(&mut self, new_len: usize) -> Result<(), WriteError> {
        let len = self.len();
        match new_len.cmp(&len) {
            Ordering::Less => unsafe {
                let mut_inner = self.0.as_ptr();
                (*mut_inner).b_wptr = (*mut_inner).b_wptr.sub(len - new_len);
                Ok(())
            },
            Ordering::Greater => unsafe {
                self.write_back(new_len - len, |v| {
                    // MaybeUninit::fill is unstable.
                    let n = v.len();
                    v.as_mut_ptr().write_bytes(0, n);
                })
            },
            Ordering::Equal => Ok(()),
        }
    }

    /// Adjusts the write pointer for this MsgBlk, initialising any extra bytes to 0.
    pub fn expand_front(&mut self, n: usize) -> Result<(), SegAdjustError> {
        unsafe {
            self.write_front(n, |v| {
                // MaybeUninit::fill is unstable.
                let n = v.len();
                v.as_mut_ptr().write_bytes(0, n);
            })
            .map_err(|_| SegAdjustError::StartBeforeBase)
        }
    }

    /// Shrink the writable/readable area by shifting the `b_rptr` by
    /// `len`; effectively removing bytes from the start of the packet.
    ///
    /// # Errors
    ///
    /// `SegAdjustError::StartPastEnd`: Shifting the read pointer by
    /// `len` would move `b_rptr` past `b_wptr`.
    pub fn drop_front_bytes(&mut self, n: usize) -> Result<(), SegAdjustError> {
        let node = self
            .iter_mut()
            .next()
            .expect("There will always be a front element by definition");

        node.drop_front_bytes(n)
    }

    /// Emits an `ingot` packet after any bytes present in this mblk.
    pub fn emit_back(
        &mut self,
        pkt: impl Emit + EmitDoesNotRelyOnBufContents,
    ) -> Result<(), WriteError> {
        unsafe {
            self.write_back(pkt.packet_length(), |v| {
                // Unwrap safety: write will return an Error if
                // unsuccessful.
                pkt.emit_uninit(v).unwrap();
            })
        }
    }

    /// Emits an `ingot` packet before any bytes present in this mblk.
    pub fn emit_front(
        &mut self,
        pkt: impl Emit + EmitDoesNotRelyOnBufContents,
    ) -> Result<(), WriteError> {
        unsafe {
            self.write_front(pkt.packet_length(), |v| {
                pkt.emit_uninit(v).unwrap();
            })
        }
    }

    /// Copies a byte slice into the region after any bytes present in this mblk.
    pub fn write_bytes_back(
        &mut self,
        bytes: impl AsRef<[u8]>,
    ) -> Result<(), WriteError> {
        let bytes = bytes.as_ref();
        unsafe {
            self.write_back(bytes.len(), |v| {
                // feat(maybe_uninit_write_slice) -> copy_from_slice
                // is unstable.
                let uninit_src: &[MaybeUninit<u8>] =
                    core::mem::transmute(bytes);
                v.copy_from_slice(uninit_src);
            })
        }
    }

    /// Copies a byte slice into the region before any bytes present in this mblk.
    pub fn write_bytes_front(
        &mut self,
        bytes: impl AsRef<[u8]>,
    ) -> Result<(), WriteError> {
        let bytes = bytes.as_ref();
        unsafe {
            self.write_front(bytes.len(), |v| {
                // feat(maybe_uninit_write_slice) -> copy_from_slice
                // is unstable.
                let uninit_src: &[MaybeUninit<u8>] =
                    core::mem::transmute(bytes);
                v.copy_from_slice(uninit_src);
            })
        }
    }

    /// Places another `MsgBlk` at the end of this packet's
    /// b_cont chain.
    pub fn append(&mut self, other: Self) {
        // Find the last element in the pkt chain
        // i.e., whose b_cont is null.
        let mut curr = self.0.as_ptr();
        while unsafe { !(*curr).b_cont.is_null() } {
            curr = unsafe { (*curr).b_cont };
        }

        unsafe {
            (*curr).b_cont = other.unwrap_mblk().as_ptr();
        }
    }

    /// Drop all bytes and move the cursor to the very back of the dblk.
    pub fn pop_all(&mut self) {
        let mut_out = self.0.as_ptr();
        unsafe {
            (*mut_out).b_rptr = (*(*mut_out).b_datap).db_lim;
            (*mut_out).b_wptr = (*(*mut_out).b_datap).db_lim;
        }
    }

    /// Returns a shared cursor over all segments in this `MsgBlk`.
    pub fn iter(&self) -> MsgBlkIter {
        MsgBlkIter { curr: Some(self.0), marker: PhantomData }
    }

    /// Returns a mutable cursor over all segments in this `MsgBlk`.
    pub fn iter_mut(&mut self) -> MsgBlkIterMut {
        MsgBlkIterMut { curr: Some(self.0), marker: PhantomData }
    }

    /// Return the pointer address of the underlying mblk_t.
    ///
    /// NOTE: This is purely to allow passing the pointer value up to
    /// DTrace so that the mblk can be inspected (read only) in probe
    /// context.
    pub fn mblk_addr(&self) -> uintptr_t {
        self.0.as_ptr() as uintptr_t
    }

    /// Return the head of the underlying `mblk_t` segment chain and
    /// consume `self`. The caller of this function now owns the
    /// `mblk_t` segment chain.
    pub fn unwrap_mblk(self) -> NonNull<mblk_t> {
        AsMblk::unwrap_mblk(self).unwrap()
    }

    /// Wrap the `mblk_t` packet in a [`MsgBlk`], taking ownership of
    /// the `mblk_t` packet as a result. An `mblk_t` packet consists
    /// of one or more `mblk_t` segments chained together via
    /// `b_cont`. When the [`MsgBlk`] is dropped, the
    /// underlying `mblk_t` segment chain is freed. If you wish to
    /// pass on ownership you must call the [`MsgBlk::unwrap_mblk()`]
    /// function.
    ///
    /// # Safety
    ///
    /// The `mp` pointer must point to an `mblk_t` allocated by
    /// `allocb(9F)` or provided by some kernel API which itself used
    /// one of the DDI/DKI APIs to allocate it.
    ///
    /// Users *must* be certain that, for any `mblk_t` in the `b_cont` chain,
    /// any underlying `dblk_t`s have only a single referent (this chain) if
    /// they are going to read (or &mut) the backing byteslice. This is a
    /// possibility for, e.g., packets served by `viona` whose mblks after
    /// the initial header pullup will point directly into guest memory (!!!).
    /// We do not currently have an API for conditionally handing out slices
    /// and performing pullup on the fly based on refcnt -- potentially untrusted
    /// mblk uses (e.g. read/write of body segs) *must* perform a manual pullup.
    ///
    /// # Errors
    ///
    /// * Return [`WrapError::NullPtr`] is `mp` is `NULL`.
    /// * Return [`WrapError::Chain`] is `mp->b_next` or `mp->b_prev` are set.
    pub unsafe fn wrap_mblk(ptr: *mut mblk_t) -> Result<Self, WrapError> {
        let inner = NonNull::new(ptr).ok_or(WrapError::NullPtr)?;
        let inner_ref = inner.as_ptr();

        if (*inner_ref).b_next.is_null() && (*inner_ref).b_prev.is_null() {
            Ok(Self(inner))
        } else {
            Err(WrapError::Chain)
        }
    }

    /// Copy out all bytes within this mblk and its successors
    /// to a single contiguous buffer.
    pub fn copy_all(&self) -> Vec<u8> {
        let len = self.byte_len();
        let mut out = Vec::with_capacity(len);

        for node in self.iter() {
            out.extend_from_slice(node)
        }

        out
    }

    /// Drops all empty mblks from the start of this chain where possible
    /// (i.e., any empty mblk is followed by another mblk).
    pub fn drop_empty_segments(&mut self) {
        // We should not be creating message block continuations to zero
        // sized blocks. This is not a generally expected thing and has
        // caused NIC hardware to stop working.
        // Stripping these out where possible is necessary.
        let mut head = self.0;
        let mut neighbour = unsafe { (*head.as_ptr()).b_cont };

        let offload_info = unsafe { offload_info(head) };

        while !neighbour.is_null()
            && unsafe { (*head.as_ptr()).b_rptr == (*head.as_ptr()).b_wptr }
        {
            // Replace head with neighbour.
            // Disconnect head from neighbour, and drop head.
            unsafe {
                (*head.as_ptr()).b_cont = ptr::null_mut();
                drop(MsgBlk::wrap_mblk(head.as_ptr()));

                // SAFETY: we know neighbour is non_null.
                head = NonNull::new_unchecked(neighbour);
                neighbour = (*head.as_ptr()).b_cont
            }
        }

        // Carry over offload flags and MSS information.
        // SAFETY: db_struioun contains no payload-specific offsets,
        // only flags pertaining to *required* offloads and the path MTU/MSS.
        unsafe {
            set_offload_info(head, offload_info);
        }

        self.0 = head;
    }

    #[allow(unused)]
    pub fn request_offload(&mut self, is_tcp: bool, mss: u32) {
        let ckflags = MblkOffloadFlags::HCK_IPV4_HDRCKSUM
            | MblkOffloadFlags::HCK_FULLCKSUM;
        #[cfg(all(not(feature = "std"), not(test)))]
        unsafe {
            illumos_sys_hdrs::mac::mac_hcksum_set(
                self.0.as_ptr(),
                0,
                0,
                0,
                0,
                ckflags.bits() as u32,
            );
            if is_tcp {
                illumos_sys_hdrs::mac::lso_info_set(
                    self.0.as_ptr(),
                    mss,
                    MblkOffloadFlags::HW_LSO.bits() as u32,
                );
            }
        }
    }

    #[allow(unused)]
    pub fn set_tuntype(&mut self, tuntype: MacTunType) {
        #[cfg(all(not(feature = "std"), not(test)))]
        unsafe {
            (*(*self.0.as_ptr()).b_datap).db_mett.mett_tuntype = tuntype;
            (*(*self.0.as_ptr()).b_datap).db_mett.mett_flags |=
                MacEtherOffloadFlags::TUNINFO_SET;
        }
    }

    #[allow(unused)]
    pub fn fill_offload_info(
        &mut self,
        tun_meoi: &mac_ether_tun_info_t,
        ulp_meoi: &mac_ether_offload_info_t,
    ) {
        #[cfg(all(not(feature = "std"), not(test)))]
        unsafe {
            (*(*self.0.as_ptr()).b_datap).db_mett = *tun_meoi;
            (*(*self.0.as_ptr()).b_datap).db_meoi = *ulp_meoi;
        }
    }

    #[allow(unused)]
    pub fn cksum_flags(&self) -> MblkOffloadFlags {
        let mut out = 0u32;

        #[cfg(all(not(feature = "std"), not(test)))]
        unsafe {
            illumos_sys_hdrs::mac::mac_hcksum_get(
                self.0.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut out,
            )
        };

        MblkOffloadFlags::from_bits_retain(out as u16)
    }
}

impl AsMblk for MsgBlk {
    fn unwrap_mblk(self) -> Option<NonNull<mblk_t>> {
        let ptr_out = self.0;
        _ = ManuallyDrop::new(self);
        Some(ptr_out)
    }
}

/// An interior node of an [`MsgBlk`]'s chain, accessed via iterator.
///
/// This supports a reduced set of operations compared to [`MsgBlk`],
/// primarily to allow (mutable) access to the inner bytes while preventing
/// iterator invalidation.
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
    /// Shrink the writable/readable area by shifting the `b_rptr` by
    /// `len`; effectively removing bytes from the start of the packet.
    ///
    /// # Errors
    ///
    /// `SegAdjustError::StartPastEnd`: Shifting the read pointer by
    /// `len` would move `b_rptr` past `b_wptr`.
    pub fn drop_front_bytes(&mut self, n: usize) -> Result<(), SegAdjustError> {
        unsafe {
            if self.0.b_wptr.offset_from(self.0.b_rptr) < n as isize {
                return Err(SegAdjustError::StartPastEnd);
            }
            self.0.b_rptr = self.0.b_rptr.add(n);
        }

        Ok(())
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

impl MsgBlkIterMut<'_> {
    pub fn next_iter(&self) -> MsgBlkIter {
        let curr = self
            .curr
            .and_then(|ptr| NonNull::new(unsafe { (*ptr.as_ptr()).b_cont }));
        MsgBlkIter { curr, marker: PhantomData }
    }

    pub fn next_iter_mut(&mut self) -> MsgBlkIterMut {
        let curr = self
            .curr
            .and_then(|ptr| NonNull::new(unsafe { (*ptr.as_ptr()).b_cont }));
        MsgBlkIterMut { curr, marker: PhantomData }
    }
}

impl Pullup for MsgBlkIterMut<'_> {
    fn pullup(&self, prepend: Option<&[u8]>) -> MsgBlk {
        let prepend = prepend.unwrap_or_default();
        let bytes_in_self = BufferState::len(self);
        let needed_alloc = prepend.len() + bytes_in_self;
        let mut new_seg = MsgBlk::new(needed_alloc);

        new_seg
            .write_bytes_back(prepend)
            .expect("allocated enough bytes for prepend and self");

        let offload_info = self.curr.map(|v| unsafe { offload_info(v) });

        if bytes_in_self != 0 {
            // SAFETY: We need to make use of ptr::copy for a pullup
            // because we cannot guarantee a dblk refcnt of 1 -- thus
            // using Deref<[u8]> for these segments is not safe.
            unsafe {
                new_seg
                    .write_back(bytes_in_self, |mut buf| {
                        let mut curr = self.curr;
                        while let Some(valid_curr) = curr {
                            let valid_curr = valid_curr.as_ptr();
                            let src = (*valid_curr).b_rptr;
                            let seg_len = usize::try_from(
                                (*valid_curr).b_wptr.offset_from(src),
                            )
                            .expect("invalid mblk -- slice end before start");

                            // Safety: slice contains exactly bytes_in_self bytes (!= 0).
                            // Cast replicates `MaybeUninit::slice_as_mut_ptr` (unstable).
                            let dst = buf.as_mut_ptr() as *mut u8;

                            dst.copy_from_nonoverlapping(
                                (*valid_curr).b_rptr,
                                seg_len,
                            );

                            curr = NonNull::new((*valid_curr).b_cont);
                            buf = buf.split_at_mut(seg_len).1;
                        }
                    })
                    .expect("allocated enough bytes for prepend and self");
            }
        }

        // Carry over offload flags and MSS information.
        // SAFETY: db_struioun contains no payload-specific offsets,
        // only flags pertaining to *required* offloads and the path MTU/MSS.
        if let Some(info) = offload_info {
            unsafe {
                set_offload_info(new_seg.0, info);
            }
        }

        new_seg
    }
}

/// Counts the number of segments in an `mblk_t` from `head`, linked
/// via `b_cont`.
unsafe fn count_mblk_chain(mut head: Option<NonNull<mblk_t>>) -> usize {
    let mut count = 0;
    while let Some(valid_head) = head {
        count += 1;
        head = NonNull::new((*valid_head.as_ptr()).b_cont);
    }
    count
}

/// Counts the number of bytes in an `mblk_t` from `head`, linked
/// via `b_cont`.
///
/// This is used to avoid contructing a &[] over slices which may/may not
/// have a higher refcnt.
unsafe fn count_mblk_bytes(mut head: Option<NonNull<mblk_t>>) -> usize {
    let mut count = 0;
    while let Some(valid_head) = head {
        let headref = valid_head.as_ptr();
        count +=
            (*headref).b_wptr.offset_from((*headref).b_rptr).max(0) as usize;
        head = NonNull::new((*headref).b_cont);
    }
    count
}

/// Copy out the opaque representation of offload flags and sizes
/// associated with this packet.
unsafe fn offload_info(head: NonNull<mblk_t>) -> u64 {
    unsafe { (*(*head.as_ptr()).b_datap).db_struioun }
}

/// Set the opaque representation of offload flags and sizes
/// associated with this packet.
unsafe fn set_offload_info(head: NonNull<mblk_t>, info: u64) {
    unsafe {
        (*(*head.as_ptr()).b_datap).db_struioun = info;
    }
}

impl<'a> Iterator for MsgBlkIter<'a> {
    type Item = &'a MsgBlkNode;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(ptr) = self.curr {
            self.curr = NonNull::new(unsafe { (*ptr.as_ptr()).b_cont });
            // SAFETY: MsgBlkNode has identical layout to mblk_t.
            unsafe { Some(&*(ptr.as_ptr() as *const MsgBlkNode)) }
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = unsafe { count_mblk_chain(self.curr) };
        (len, Some(len))
    }
}

impl ExactSizeIterator for MsgBlkIter<'_> {}

impl<'a> Read for MsgBlkIter<'a> {
    type Chunk = &'a [u8];

    fn next_chunk(&mut self) -> ingot::types::ParseResult<Self::Chunk> {
        self.next().ok_or(IngotParseErr::TooSmall).map(|v| v.as_ref())
    }

    fn chunks_len(&self) -> usize {
        ExactSizeIterator::len(self)
    }
}

impl<'a> Iterator for MsgBlkIterMut<'a> {
    type Item = &'a mut MsgBlkNode;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(ptr) = self.curr {
            self.curr = NonNull::new(unsafe { (*ptr.as_ptr()).b_cont });
            // SAFETY: MsgBlkNode has identical layout to mblk_t.
            unsafe { Some(&mut *(ptr.as_ptr() as *mut MsgBlkNode)) }
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = unsafe { count_mblk_chain(self.curr) };
        (len, Some(len))
    }
}

impl ExactSizeIterator for MsgBlkIterMut<'_> {}

impl<'a> Read for MsgBlkIterMut<'a> {
    type Chunk = &'a mut [u8];

    fn next_chunk(&mut self) -> ingot::types::ParseResult<Self::Chunk> {
        self.next().ok_or(IngotParseErr::TooSmall).map(|v| v.as_mut())
    }

    fn chunks_len(&self) -> usize {
        ExactSizeIterator::len(self)
    }
}

impl BufferState for MsgBlkIterMut<'_> {
    #[inline]
    fn len(&self) -> usize {
        unsafe { count_mblk_bytes(self.curr) }
    }

    #[inline]
    fn base_ptr(&self) -> uintptr_t {
        self.curr.map(|v| v.as_ptr() as uintptr_t).unwrap_or(0)
    }
}

/// For the `no_std`/illumos kernel environment, we want the `mblk_t`
/// drop to occur at the packet level, where we can make use of
/// `freemsg(9F)`.
impl Drop for MsgBlk {
    fn drop(&mut self) {
        // Drop the segment chain if there is one. Consumers of MsgBlk
        // will never own a packet with no segments.
        // This guarantees that we only free the segment chain once.
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                // Safety: This is safe as long as the original
                // `mblk_t` came from a call to `allocb(9F)` (or
                // similar API).
                unsafe { ddi::freemsg(self.0.as_ptr()) };
            } else {
                mock_freemsg(self.0.as_ptr());
            }
        }
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

        ..Default::default()
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
        let bdblk = Box::from_raw(bmblk.b_datap);
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
    use crate::engine::packet::Packet;
    use crate::engine::packet::ParseError;
    use crate::engine::GenericUlp;
    use ingot::types::ParseError as IngotParseError;

    #[test]
    fn zero_byte_packet() {
        let mut pkt = MsgBlk::new(0);
        assert_eq!(pkt.len(), 0);
        assert_eq!(pkt.seg_len(), 1);
        assert_eq!(pkt.tail_capacity(), 16);

        let res = Packet::parse_outbound(pkt.iter_mut(), GenericUlp {});
        match res {
            Err(ParseError::IngotError(err)) => {
                assert_eq!(err.header().as_str(), "inner_eth");
                assert_eq!(err.error(), &IngotParseError::TooSmall);
            }

            Err(e) => panic!("expected read error, got: {:?}", e),
            _ => panic!("expected failure, accidentally succeeded at parsing"),
        }

        let pkt2 = MsgBlk::copy(&[]);
        assert_eq!(pkt2.len(), 0);
        assert_eq!(pkt2.seg_len(), 1);
        assert_eq!(pkt2.tail_capacity(), 16);
        let res = Packet::parse_outbound(pkt.iter_mut(), GenericUlp {});
        match res {
            Err(ParseError::IngotError(err)) => {
                assert_eq!(err.header().as_str(), "inner_eth");
                assert_eq!(err.error(), &IngotParseError::TooSmall);
            }

            Err(e) => panic!("expected read error, got: {:?}", e),
            _ => panic!("expected failure, accidentally succeeded at parsing"),
        }
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

        let pkt = unsafe { MsgBlk::wrap_mblk(mp1).unwrap() };
        assert_eq!(pkt.seg_len(), 2);
        assert_eq!(pkt.all_segs_capacity(), 22);
        assert_eq!(pkt.byte_len(), 6);
    }

    #[test]
    fn read_seg() {
        let buf1 = vec![0x1, 0x2, 0x3, 0x4];
        let buf2 = vec![0x5, 0x6];
        let mp1 = mock_desballoc(buf1);
        let mp2 = mock_desballoc(buf2);

        unsafe {
            (*mp1).b_cont = mp2;
        }

        let pkt = unsafe { MsgBlk::wrap_mblk(mp1).unwrap() };
        assert_eq!(pkt.byte_len(), 6);
        assert_eq!(pkt.seg_len(), 2);

        let mut segs = pkt.iter();
        assert_eq!(segs.next().map(|v| &v[..]).unwrap(), &[0x1, 0x2, 0x3, 0x4]);
        assert_eq!(segs.next().map(|v| &v[..]).unwrap(), &[0x5, 0x6]);
    }

    #[test]
    fn truncate() {
        let mut p1 = MsgBlk::copy(&[0, 1, 2, 3]);
        p1.append(MsgBlk::copy(&[4, 5, 6, 7]));
        p1.append(MsgBlk::copy(&[8, 9, 10, 11]));

        assert_eq!(p1.seg_len(), 3);
        assert_eq!(p1.byte_len(), 12);

        // Assert drop of followup segments.
        p1.truncate_chain(7);
        assert_eq!(p1.seg_len(), 2);
        assert_eq!(p1.byte_len(), 7);
        let mut iter = p1.iter();
        let el1 = iter.next().unwrap();
        let el2 = iter.next().unwrap();
        assert_eq!(&el1[..], &[0, 1, 2, 3]);
        assert_eq!(&el2[..], &[4, 5, 6]);
    }

    // Verify uninitialized packet.
    #[test]
    fn uninitialized_packet() {
        let pkt = MsgBlk::new(200);
        assert_eq!(pkt.len(), 0);
        assert_eq!(pkt.seg_len(), 1);
        assert_eq!(pkt.tail_capacity(), 200);
    }

    #[test]
    fn expand_and_shrink() {
        let mut seg = MsgBlk::new(18);
        assert_eq!(seg.len(), 0);
        seg.resize(18).unwrap();
        assert_eq!(seg.len(), 18);
        seg.drop_front_bytes(4).unwrap();
        assert_eq!(seg.len(), 14);
        seg.expand_front(4).unwrap();
        assert_eq!(seg.len(), 18);

        assert!(seg.resize(20).is_err());
        assert!(seg.drop_front_bytes(20).is_err());
        assert!(seg.expand_front(4).is_err());
    }

    #[test]
    fn prefix_len() {
        let mut seg = MsgBlk::new(18);
        assert_eq!(seg.head_capacity(), 0);
        seg.resize(18).unwrap();
        assert_eq!(seg.head_capacity(), 0);
        seg.drop_front_bytes(4).unwrap();
        assert_eq!(seg.head_capacity(), 4);
        seg.expand_front(4).unwrap();
        assert_eq!(seg.head_capacity(), 0);
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
        let packet = unsafe { MsgBlk::wrap_mblk(blocks[0]) }
            .expect("Failed to wrap mblk chain with many segments");

        assert_eq!(packet.seg_len(), N_SEGMENTS);
        for (seg, mblk) in packet.iter().zip(blocks) {
            assert_eq!(core::ptr::addr_of!(seg.0) as *mut _, mblk);
        }
    }

    fn create_linked_mblks(n: usize) -> Vec<*mut mblk_t> {
        let mut els = vec![];
        for _ in 0..n {
            els.push(allocb(8));
        }

        // connect the elements in a chain
        for (lhs, rhs) in els.iter().zip(els[1..].iter()) {
            unsafe {
                (**lhs).b_next = *rhs;
                (**rhs).b_prev = *lhs;
            }
        }

        els
    }

    #[test]
    fn chain_has_correct_ends() {
        let els = create_linked_mblks(3);

        let chain = unsafe { MsgBlkChain::new(els[0]) }.unwrap();
        let chain_inner = chain.0.as_ref().unwrap();
        assert_eq!(chain_inner.head.as_ptr(), els[0]);
        assert_eq!(chain_inner.tail.as_ptr(), els[2]);
    }

    #[test]
    fn chain_breaks_links() {
        let els = create_linked_mblks(3);

        let mut chain = unsafe { MsgBlkChain::new(els[0]) }.unwrap();

        let p0 = chain.pop_front().unwrap();
        assert_eq!(p0.mblk_addr(), els[0] as uintptr_t);
        unsafe {
            assert!((*els[0]).b_prev.is_null());
            assert!((*els[0]).b_next.is_null());
        }

        // Chain head/tail ptrs are correct
        let chain_inner = chain.0.as_ref().unwrap();
        assert_eq!(chain_inner.head.as_ptr(), els[1]);
        assert_eq!(chain_inner.tail.as_ptr(), els[2]);
        unsafe {
            assert!((*els[1]).b_prev.is_null());
            assert!((*els[2]).b_next.is_null());
        }
    }

    #[test]
    fn chain_append_links() {
        let els = create_linked_mblks(3);
        let new_el = allocb(8);

        let mut chain = unsafe { MsgBlkChain::new(els[0]) }.unwrap();
        let pkt = unsafe { MsgBlk::wrap_mblk(new_el) }.unwrap();

        chain.append(pkt);

        // Chain head/tail ptrs are correct
        let chain_inner = chain.0.as_ref().unwrap();
        assert_eq!(chain_inner.head.as_ptr(), els[0]);
        assert_eq!(chain_inner.tail.as_ptr(), new_el);

        // Last el has been linked to the new pkt, and it has a valid
        // backward link.
        unsafe {
            assert_eq!((*new_el).b_prev, els[2]);
            assert!((*new_el).b_next.is_null());
            assert_eq!((*els[2]).b_next, new_el);
        }
    }

    #[test]
    fn chain_drain_complete() {
        let els = create_linked_mblks(64);

        let mut chain = unsafe { MsgBlkChain::new(els[0]) }.unwrap();

        for i in 0..els.len() {
            let pkt = chain.pop_front().unwrap();
            assert_eq!(pkt.mblk_addr(), els[i] as uintptr_t);
        }

        assert!(chain.pop_front().is_none());
    }
}

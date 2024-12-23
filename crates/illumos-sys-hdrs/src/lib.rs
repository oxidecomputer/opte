// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company
#![cfg_attr(feature = "kernel", feature(extern_types))]
#![allow(non_camel_case_types)]
#![no_std]

#[cfg(feature = "kernel")]
pub mod kernel;
#[cfg(feature = "kernel")]
pub use kernel::*;

use core::mem::transmute;
use core::ptr;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

// The following are "C type" aliases for native Rust types so that
// the native illumos structures may be defined almost verbatim to the
// source. These definitions assume AMD64 arch/LP64.
pub type c_void = core::ffi::c_void;
pub type c_schar = i8;
pub type c_uchar = u8;
pub type c_char = c_schar;
pub type c_short = i16;
pub type c_ushort = u16;
pub type c_int = i32;
pub type c_uint = u32;
pub type c_long = i64;
pub type c_ulong = u64;
pub type c_longlong = i64;
pub type c_ulonglong = u64;

pub type int32_t = i32;

pub type uint16_t = u16;
pub type uint32_t = u32;

pub type size_t = usize;
pub type intptr_t = isize;
pub type uintptr_t = usize;
pub type ssize_t = isize;

// ======================================================================
// uts/common/sys/errno.h
// ======================================================================
pub const ENOENT: c_int = 2;
pub const ENXIO: c_int = 6;
pub const EAGAIN: c_int = 11;
pub const ENOMEM: c_int = 12;
pub const EFAULT: c_int = 14;
pub const EBUSY: c_int = 16;
pub const EEXIST: c_int = 17;
pub const EINVAL: c_int = 22;
pub const ENFILE: c_int = 23;
pub const ENOTTY: c_int = 25;
pub const EPIPE: c_int = 32;
pub const ENOMSG: c_int = 35;
pub const ENOTSUP: c_int = 48;
pub const ENOSTR: c_int = 60;
pub const EPROTO: c_int = 71;
pub const ENOBUFS: c_int = 132;

// ======================================================================
// uts/common/sys/file.h
// ======================================================================
pub const FREAD: c_int = 0x1;
pub const FWRITE: c_int = 0x2;
pub const FNDELAY: c_int = 0x4;
pub const FNONBLOCK: c_int = 0x80;
pub const FEXCL: c_int = 0x400;
pub const FOFFMAX: c_int = 0x2000;
pub const FCLOEXEC: c_int = 0x800000;

// ======================================================================
// uts/common/sys/open.h
// ======================================================================
pub const OTYP_CHR: c_int = 2;

// ======================================================================
// uts/common/sys/kstat.h
// ======================================================================
pub type kid_t = c_int;

pub const KSTAT_STRLEN: usize = 31;

#[repr(C)]
pub struct kstat_t {
    _ks_crtime: hrtime_t,
    _ks_next: *const kstat_t,
    _ks_kid: kid_t,
    _ks_module: [c_char; KSTAT_STRLEN],
    _ks_resv: c_uchar,
    _ks_instance: c_int,
    _ks_name: [c_char; KSTAT_STRLEN],
    _ks_type: c_uchar,
    _ks_class: [c_char; KSTAT_STRLEN],
    _ks_flags: c_uchar,
    pub ks_data: *mut c_void,
    _ks_ndata: c_uint,
    _ks_data_size: size_t,
    _ks_snaptime: hrtime_t,
    _ks_update: *const c_void,
    _ks_private: *const c_void,
    _ks_snapshot: *const c_void,
    pub ks_lock: *mut c_void,
}

#[repr(C)]
pub struct kstat_named_t {
    pub name: [c_char; KSTAT_STRLEN],
    pub dtype: c_uchar,
    pub value: KStatNamedValue,
}

impl kstat_named_t {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn val_u64(&self) -> u64 {
        self.value.as_u64().load(Ordering::Relaxed)
    }
}

impl Default for kstat_named_t {
    fn default() -> Self {
        Self {
            name: [0; KSTAT_STRLEN],
            dtype: 0,
            value: KStatNamedValue { _c: [0; 16] },
        }
    }
}

#[repr(C)]
pub union KStatNamedValue {
    _c: [c_char; 16],
    _i32: i32,
    _u32: u32,
    _i64: i64,
    _u64: u64,
}

impl core::ops::AddAssign<u64> for KStatNamedValue {
    #[inline]
    fn add_assign(&mut self, other: u64) {
        self.incr_u64(other);
    }
}

impl core::ops::SubAssign<u64> for KStatNamedValue {
    #[inline]
    fn sub_assign(&mut self, other: u64) {
        self.decr_u64(other);
    }
}

impl KStatNamedValue {
    /// Validates at compile time whether ._u64 can be safely used as
    /// an AtomicU64.
    const KSTAT_ATOMIC_U64_SAFE: () = if align_of::<KStatNamedValue>() % 8 == 0
    {
    } else {
        panic!("Platform does not meet u64 8B alignment for AtomicU64");
    };

    #[inline(always)]
    #[allow(clippy::let_unit_value)]
    pub fn as_u64(&self) -> &AtomicU64 {
        _ = Self::KSTAT_ATOMIC_U64_SAFE;
        // SAFETY: KStatNamedValue must have 8B alignment on target platform.
        //         Validated by compile time check in `KSTAT_ATOMIC_U64_SAFE`.
        unsafe { transmute::<&u64, &AtomicU64>(&self._u64) }
    }

    #[inline]
    pub fn set_u64(&self, val: u64) {
        core::hint::black_box(self.as_u64().store(val, Ordering::Relaxed));
    }

    #[inline]
    pub fn incr_u64(&self, val: u64) {
        core::hint::black_box(self.as_u64().fetch_add(val, Ordering::Relaxed));
    }

    #[inline]
    pub fn decr_u64(&self, val: u64) {
        core::hint::black_box(self.as_u64().fetch_sub(val, Ordering::Relaxed));
    }
}

pub const KSTAT_FLAG_VIRTUAL: c_int = 0x1;

pub const KSTAT_TYPE_NAMED: c_int = 1;

pub const KSTAT_DATA_CHAR: c_int = 0;
pub const KSTAT_DATA_INT32: c_int = 1;
pub const KSTAT_DATA_UINT32: c_int = 2;
pub const KSTAT_DATA_INT64: c_int = 3;
pub const KSTAT_DATA_UINT64: c_int = 4;

// ======================================================================
// uts/common/sys/param.h
// ======================================================================
pub const MAXLINKNAMELEN: c_int = 32;
pub const MAXNAMELEN: c_int = 256;

// ======================================================================
// uts/common/sys/mutex.h
// ======================================================================
#[repr(C)]
pub enum kmutex_type_t {
    MUTEX_ADAPTIVE = 0, // spin if owner is running, otherwise block
    MUTEX_SPIN = 1,     // block interrupts and spin
    MUTEX_DRIVER = 4,   // driver (DDI) mutex
    MUTEX_DEFAULT = 6,  // kernel default mutex
}

// This type is opaque to us, we just need to define it here to make
// sure it's a sized type, and that size should be 64-bit to match the
// kernel.
#[repr(C)]
pub struct kmutex_t {
    pub _opaque: u64,
}

// ======================================================================
// uts/common/sys/rwlock.h
// ======================================================================

/// `krwlock_t` type passed to `rw_init(9F)`.
#[repr(C)]
pub enum krw_type_t {
    /// Lock for use by (DDI) drivers.
    RW_DRIVER = 2,
    /// Kernel default lock.
    RW_DEFAULT = 4,
}

// ======================================================================
// uts/common/sys/stream.h
// ======================================================================

// Many of these fields are not needed at the moment and thus defined
// imprecisely for expediency.
#[repr(C)]
#[derive(Debug)]
pub struct dblk_t {
    pub db_frtnp: *const c_void, // imprecise
    pub db_base: *mut c_uchar,
    pub db_lim: *mut c_uchar,
    pub db_ref: c_uchar,
    pub db_type: c_uchar,
    pub db_flags: c_uchar,
    pub db_struioflag: c_uchar,
    pub db_cpid: pid_t,
    pub db_cache: *const c_void,
    pub db_mblk: *const mblk_t,
    pub db_free: *const c_void,     // imprecise
    pub db_lastfree: *const c_void, // imprecise
    pub db_cksumstart: intptr_t,
    pub db_cksumend: intptr_t,
    pub db_cksumstuff: intptr_t,
    pub db_struioun: u64,        // imprecise
    pub db_fthdr: *const c_void, // imprecise
    pub db_credp: *const c_void, // imprecise
}

impl Default for dblk_t {
    fn default() -> Self {
        dblk_t {
            db_frtnp: ptr::null(),
            db_base: ptr::null_mut(),
            db_lim: ptr::null_mut(),
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
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct mblk_t {
    pub b_next: *mut mblk_t,
    pub b_prev: *mut mblk_t,
    pub b_cont: *mut mblk_t,
    pub b_rptr: *mut c_uchar,
    pub b_wptr: *mut c_uchar,
    pub b_datap: *mut dblk_t,
    pub b_band: c_uchar,
    pub b_tag: c_uchar,
    pub b_flag: c_ushort,
    // *Sigh* STREAMS, I could really use those 8 bytes. Actually, we
    // could probably have an optional flag in OPTE/mac to say that
    // certain path aren't using STREAMS and could repurpose these 8
    // bytes.
    pub b_queue: *const c_void,
}

impl Default for mblk_t {
    fn default() -> Self {
        mblk_t {
            b_next: ptr::null_mut(),
            b_prev: ptr::null_mut(),
            b_cont: ptr::null_mut(),
            b_rptr: ptr::null_mut(),
            b_wptr: ptr::null_mut(),
            b_datap: ptr::null_mut(),
            b_band: 0,
            b_tag: 0,
            b_flag: 0,
            b_queue: ptr::null_mut(),
        }
    }
}

// ======================================================================
// uts/common/sys/time.h
// ======================================================================
pub type hrtime_t = c_longlong;

// ======================================================================
// uts/common/sys/types.h
// ======================================================================
pub type datalink_id_t = uint32_t;
pub type dev_t = c_ulong;
pub type id_t = c_int;
pub type major_t = c_uint;
pub type minor_t = c_uint;
pub type offset_t = c_longlong;
pub type pid_t = c_int;
pub type zoneid_t = id_t;

/// A standard boolean in illumos.
///
/// This is a commonly used illumos kernel type. Originally I was
/// basing these C types on the cty crate. But really we should just
/// define the illumos types directly. These would make up the base
/// types, and then each additional kernel crate/module would define
/// additional types, e.g. DDI/DKI and mac.
///
/// Note: While Rust's `bool` is compatible/FFI-safe with C99's
/// `_Bool`, it is NOT compatible with illumos's `boolean_t`, as the
/// later is a C enum, and the former is 1 byte.
#[repr(C)]
pub enum boolean_t {
    B_FALSE,
    B_TRUE,
}

// The source for this structure makes use of the
// `_LONG_LONG_{LTOH,HTOL}` ISA macros. My guess is this is needed
// for 32-bit userland applications using `long long *` for things
// like file/memory addresses (where we have a 32-bit pointer
// pointing to a 64-bit value). The macro determines if the pointer
// is to the high 32 bits or the low 32 bits. Currently, illumos
// always sets `_LONG_LONG_HTOL`.
#[repr(C)]
pub union lloff_t {
    pub _f: offset_t, // full 64-bits
    pub _p: upper_lower,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct upper_lower {
    pub _u: int32_t, // upper 32-bits
    pub _l: int32_t, // lower 32-bits
}

// ======================================================================
// uts/common/sys/uio.h
// ======================================================================

// This definition assumes applications are compiled with XPG4v2
// (`_XPG4_2`) or later support. If we want Rust drivers to have
// maximum userland support we will want to also support pre-XPG4v2.
#[repr(C)]
pub struct iovec_t {
    pub iov_base: *mut c_void,
    pub iov_len: size_t,
}

#[repr(C)]
pub enum uio_seg_t {
    UIO_USERSPACE,
    UIO_SYSSPACE,
    UIO_USERIPSACE,
}

#[repr(C)]
pub struct uio {
    pub uio_iov: *mut iovec_t,
    pub uio_iovcnt: c_int,
    pub _uio_offset: lloff_t,
    pub uio_segflg: uio_seg_t,
    pub uio_fmode: uint16_t,
    pub uio_extflg: uint16_t,
    pub _uio_limit: lloff_t,
    pub uio_resid: ssize_t,
}

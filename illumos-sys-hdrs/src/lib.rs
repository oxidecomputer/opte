#![allow(non_camel_case_types)]
#![no_std]

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
pub const EAGAIN: c_int = 11;
pub const ENOMEM: c_int = 12;
pub const EFAULT: c_int = 14;
pub const EBUSY: c_int = 16;
pub const EEXIST: c_int = 17;
pub const EINVAL: c_int = 22;
pub const ENFILE: c_int = 23;
pub const EPIPE: c_int = 32;
pub const ENOMSG: c_int = 35;
pub const ENOTSUP: c_int = 48;
pub const EPROTO: c_int = 71;
pub const ENOBUFS: c_int = 132;

// ======================================================================
// uts/common/sys/modctl.h
// ======================================================================

// ======================================================================
// uts/common/sys/param.h
// ======================================================================
pub const MAXLINKNAMELEN: c_int = 32;
pub const MAXNAMELEN: c_int = 256;


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
pub type minor_t = c_uint;
pub type offset_t = c_longlong;
pub type pid_t = c_int;
pub type zoneid_t = id_t;

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

/// The source for this structure makes use of the
/// `_LONG_LONG_{LTOH,HTOL}` ISA macros. My guess is this is needed
/// for 32-bit userland applications using `long long *` for things
/// like file/memory addresses (where we have a 32-bit pointer
/// pointing to a 64-bit value). The macro determines if the pointer
/// is to the high 32 bits or the low 32 bits. Currently, illumos
/// always sets `_LONG_LONG_HTOL`.
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

/// This definition assumes applications are compiled with XPG4v2
/// (`_XPG4_2`) or later support. If we want Rust drivers to have
/// maximum userland support we will want to also support pre-XPG4v2.
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

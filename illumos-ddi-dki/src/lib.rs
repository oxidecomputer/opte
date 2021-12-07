// This is a "sys" (raw interface) crate for the illumos DDI/DKI
// interfaces. It contains definitions of C macros, opaque types, 9F
// prototypes, and 9S structures which are required for proper use of
// the DDI/DKI interface.
//
// TODO It might be better to break out the types + functions into
// modules that map to their module/filename in illumos. But for now
// we just use comments and group them accordingly.
#![feature(extern_types)]
#![feature(const_fn_fn_ptr_basics)]
#![allow(non_camel_case_types)]
#![no_std]

// The following are "C type" aliases for native Rust types so that
// the native illumos structures may be defined almost verbatim to the
// source. These definitions assume AMD64 arch/LP64.
pub type c_void = core::ffi::c_void;
pub type c_schar = i8;
pub type c_uchar = u8;
pub type c_char = c_schar;
pub type c_ushort = u16;
pub type c_int = i32;
pub type c_uint = u32;
pub type c_long = i64;
pub type c_ulong = u64;
pub type c_longlong = i64;

pub type int32_t = i32;

pub type uint16_t = u16;
pub type uint32_t = u32;

pub type size_t = usize;
pub type intptr_t = isize;
pub type uintptr_t = usize;
pub type ssize_t = isize;

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

// The following are illumos kernel type aliases for the above C
// types, defined just as they are natively.
pub type datalink_id_t = uint32_t;
pub type dev_t = c_ulong;
pub type hrtime_t = c_longlong;
pub type id_t = c_int;
pub type minor_t = c_uint;
pub type offset_t = c_longlong;
pub type pid_t = c_int;

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum ddi_info_cmd_t {
    DDI_INFO_DEVT2DEVINFO = 0, // Convert a dev_t to a dev_info_t
    DDI_INFO_DEVT2INSTANCE = 1, // Convert a dev_t to an instance #
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum ddi_attach_cmd_t {
    DDI_ATTACH = 0,
    DDI_RESUME = 1,
    DDI_PM_RESUME = 2,
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum ddi_detach_cmd_t {
    DDI_DETACH = 0,
    DDI_SUSPEND = 1,
    DDI_PM_SUSPEND = 2,
    DDI_HOTPLUG_DETACH = 3,
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum ddi_reset_cmd_t {
    DDI_RESET_FORCE = 0,
}

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

// TODO Technically this is not a "raw" interface. This should live
// somewhere else.
use core::ptr;
impl kmutex_t {
    pub fn new(mtype: kmutex_type_t) -> Self {
        let mut kmutex = kmutex_t { _opaque: 0 };
        unsafe {
            mutex_init(&mut kmutex, ptr::null(), mtype, ptr::null());
        }
        kmutex
    }
}

// This definition assumes applications are compiled with XPG4v2
// (`_XPG4_2`) or later support. If we want Rust drivers to have
// maximum userland support we will want to also support pre-XPG4v2.
//
// uts/common/sys/uio.h:63
#[repr(C)]
pub struct iovec_t {
    pub iov_base: *mut c_void,
    pub iov_len: size_t,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct upper_lower {
    pub _u: int32_t, // upper 32-bits
    pub _l: int32_t, // lower 32-bits
}

// The source for this structure makes use of the
// `_LONG_LONG_{LTOH,HTOL}` ISA macros. My guess is this is needed for
// 32-bit userland applications using `long long *` for things like
// file/memory addresses (where we have a 32-bit pointer pointing to a
// 64-bit value). The macro determines if the pointer is to the high
// 32 bits or the low 32 bits. Currently, illumos always sets
// `_LONG_LONG_HTOL`.
//
// usr/src/uts/common/sys/types.h
#[repr(C)]
pub union lloff_t {
    pub _f: offset_t, // full 64-bits
    pub _p: upper_lower,
}

// usr/src/uts/common/sys/uio.h
#[repr(C)]
pub enum uio_seg_t {
    UIO_USERSPACE,
    UIO_SYSSPACE,
    UIO_USERIPSACE,
}

// uts/common/sys/uio.h
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

// Not all of these callback signatures are filled out completely, the
// unused ones leave out the function parameters.
//
// See the the Intro(9E) and cb_ops(9S) man pages for more information
// on device driver callbacks.
//
// See usr/src/uts/common/sys/devops.h
#[repr(C)]
pub struct cb_ops {
    pub cb_open: unsafe extern "C" fn(
        devp: *mut dev_t,
        flag: c_int,
        otyp: c_int,
        credp: *mut cred_t,
    ) -> c_int,
    pub cb_close: unsafe extern "C" fn(
        dev: dev_t,
        flag: c_int,
        otyp: c_int,
        credp: *mut cred_t,
    ) -> c_int,

    // The next three are exclusive to block devices.
    //
    // XXX As there is currently no need for a block device we leave
    // these callbacks underspecified -- some of the argument types,
    // such as `struct buf` are quite large.
    pub cb_strategy: unsafe extern "C" fn() -> c_int,
    pub cb_print: unsafe extern "C" fn() -> c_int,
    pub cb_dump: unsafe extern "C" fn() -> c_int,

    // The rest of the callbacks are exclusive to character devices.
    pub cb_read: unsafe extern "C" fn(
        dev: dev_t,
        uiop: *mut uio,
        credp: *mut cred_t,
    ) -> c_int,
    pub cb_write: unsafe extern "C" fn(
        dev: dev_t,
        uiop: *mut uio,
        credp: *mut cred_t,
    ) -> c_int,
    pub cb_ioctl: unsafe extern "C" fn(
        dev: dev_t,
        cmd: c_int,
        arg: intptr_t,
        mode: c_int,
        credp: *mut cred_t,
        rvalp: *mut c_int,
    ) -> c_int,

    // XXX Like the block device callbacks, we leave these
    // underspecified for now.
    pub cb_devmap: unsafe extern "C" fn() -> c_int,
    pub cb_mmap: unsafe extern "C" fn() -> c_int,
    pub cb_segmap: unsafe extern "C" fn() -> c_int,
    pub cb_chpoll: unsafe extern "C" fn() -> c_int,

    // XXX Left underspecified until needed.
    pub cb_prop_op: unsafe extern "C" fn() -> c_int,

    // The next member is only for STREAMS drivers.
    pub cb_str: *mut streamtab,

    // Flag and rev info.
    pub cb_flag: c_int,
    pub cb_rev: c_int,

    // Async I/O.
    //
    // XXX Left underspecified until needed.
    pub cb_aread: unsafe extern "C" fn() -> c_int,
    pub cb_awrite: unsafe extern "C" fn() -> c_int,
}
unsafe impl Sync for cb_ops {}

// See dev_ops(9S) for more information on the device operations
// structure and its associated callbacks.
//
// uts/common/sys/devops.h
#[repr(C)]
pub struct dev_ops {
    pub devo_rev: c_int,
    pub devo_refcnt: c_int,
    pub devo_getinfo: unsafe extern "C" fn(
        dip: *mut dev_info,
        infocmd: ddi_info_cmd_t,
        arg: *mut c_void,
        result: *mut *mut c_void,
    ) -> c_int,
    pub devo_identify: unsafe extern "C" fn(dip: *mut dev_info) -> c_int,
    pub devo_probe: unsafe extern "C" fn(dip: *mut dev_info) -> c_int,
    pub devo_attach:
        unsafe extern "C" fn(*mut dev_info, ddi_attach_cmd_t) -> c_int,
    pub devo_detach:
        unsafe extern "C" fn(*mut dev_info, ddi_detach_cmd_t) -> c_int,
    pub devo_reset:
        unsafe extern "C" fn(dip: *mut dev_info, cmd: ddi_reset_cmd_t) -> c_int,
    pub devo_cb_ops: *const cb_ops,
    pub devo_bus_ops: *const bus_ops,
    pub devo_power: unsafe extern "C" fn(
        dip: *mut dev_info,
        component: c_int,
        level: c_int,
    ) -> c_int,
    pub devo_quiesce: unsafe extern "C" fn(*mut dev_info) -> c_int,
}
unsafe impl Sync for dev_ops {}

// C allows us to sidestep strict type definition conformance when
// setting callback functions, but Rust doesn't. Therefore, we can't
// just assign generic callbacks like `nulldev()` to these structure
// members once we are in Rust. We define wrapper functions with the
// correct function signatures in order to bridge the gap.
#[no_mangle]
pub unsafe extern "C" fn nulldev_identify(_dip: *mut dev_info) -> c_int {
    nulldev()
}

#[no_mangle]
pub unsafe extern "C" fn nulldev_probe(_dip: *mut dev_info) -> c_int {
    nulldev()
}

#[no_mangle]
pub unsafe extern "C" fn nodev_getinfo(
    _dip: *mut dev_info,
    _infocmd: ddi_info_cmd_t,
    _arg: *mut c_void,
    _result: *mut *mut c_void,
) -> c_int {
    nodev()
}

#[no_mangle]
pub unsafe extern "C" fn nodev_reset(
    _dip: *mut dev_info,
    _cmd: ddi_reset_cmd_t,
) -> c_int {
    nodev()
}

pub unsafe extern "C" fn nodev_power(
    _dip: *mut dev_info,
    _component: c_int,
    _level: c_int,
) -> c_int {
    nodev()
}

// Many of these fields are not needed at the moment and thus defined
// imprecisely for expediency.
#[repr(C)]
#[derive(Debug)]
pub struct dblk_t {
    pub db_frtnp: *const c_void, // imprecise
    pub db_base: *const c_uchar,
    pub db_lim: *const c_uchar,
    pub db_ref: c_uchar,
    pub db_type: c_uchar,
    pub db_flags: c_uchar,
    pub db_struioflag: c_uchar,
    pub db_cpid: pid_t,
    pub db_cache: *const c_void,
    pub db_mblk: *const mblk_t,
    pub db_free: *const c_void, // imprecise
    pub db_lastfree: *const c_void, // imprecise
    pub db_cksumstart: intptr_t,
    pub db_cksumend: intptr_t,
    pub db_cksumstuff: intptr_t,
    pub db_struioun: u64, // imprecise
    pub db_fthdr: *const c_void, // imprecise
    pub db_credp: *const c_void, // imprecise
}

impl Default for dblk_t {
    fn default() -> Self {
        dblk_t {
            db_frtnp: ptr::null(),
            db_base: ptr::null(),
            db_lim: ptr::null(),
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
    pub b_datap: *const dblk_t,
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
            b_datap: ptr::null(),
            b_band: 0,
            b_tag: 0,
            b_flag: 0,
            b_queue: ptr::null_mut(),
        }
    }
}

#[repr(C)]
pub struct modlinkage {
    pub ml_rev: c_int,
    pub ml_linkage: [*const c_void; 7],
}
unsafe impl Sync for modlinkage {}

#[repr(C)]
pub struct modldrv {
    pub drv_modops: *const mod_ops,
    pub drv_linkinfo: *const c_char,
    pub drv_dev_ops: *const dev_ops,
}
unsafe impl Sync for modldrv {}

pub const CB_REV: c_int = 1;
pub const CE_NOTE: c_int = 1;
pub const CE_WARN: c_int = 2;

pub const DEVO_REV: c_int = 4;
pub const D_MTSAFE: c_int = 0x0020;
pub const D_MP: c_int = D_MTSAFE;

pub const DDI_DEV_T_NONE: dev_t = dev_t::MAX;
pub const DDI_DEV_T_ANY: dev_t = dev_t::MAX - 1;

pub const DDI_PROP_DONTPASS: c_uint = 0x0001;
pub const DDI_PROP_CANSLEEP: c_uint = 0x0002;

pub const DDI_PROP_SUCCESS: c_int = 0;

pub const DDI_IPL_0: c_int = 0;

pub const DDI_IPL_1: c_int = 1;
pub const DDI_IPL_2: c_int = 2;
pub const DDI_IPL_3: c_int = 3;
pub const DDI_IPL_4: c_int = 4;
pub const DDI_IPL_5: c_int = 5;
pub const DDI_IPL_6: c_int = 6;
pub const DDI_IPL_7: c_int = 7;
pub const DDI_IPL_8: c_int = 8;
pub const DDI_IPL_9: c_int = 9;
pub const DDI_IPL_10: c_int = 10;

pub const DDI_SUCCESS: c_int = 0;
pub const DDI_FAILURE: c_int = -1;
pub const DDI_PSEUDO: *const c_char = b"ddi_pseudo\0".as_ptr() as *const c_char;

pub const ENOENT: c_int = 2;
pub const EFAULT: c_int = 14;
pub const EBUSY: c_int = 16;
pub const EINVAL: c_int = 22;
pub const ENOBUFS: c_int = 132;

pub const KM_SLEEP: i32 = 0x0000;
pub const KM_NOSLEEP: i32 = 0x0001;

pub const MAXNAMELEN: c_int = 256;
pub const MODREV_1: c_int = 1;

pub const S_IFCHR: c_int = 0x2000;

pub type periodic_cb = unsafe extern "C" fn(arg: *mut c_void);

extern "C" {
    // DDI/DKI types
    pub type bus_ops;

    pub type cred_t;

    pub type ddi_periodic;
    pub type dev_info;

    pub type id_space_t;

    pub type mod_ops;
    pub type modinfo;

    pub type queue_t; // Definitely not using STREAMS.

    pub type streamtab;

    // DDI/DKI 9F
    pub fn allocb(size: size_t, pri: c_uint) -> *mut mblk_t;

    pub fn bcopy(src: *const c_void, dst: *mut c_void, count: size_t);

    pub fn cmn_err(code: c_int, msg: *const c_char, ...);

    pub fn ddi_copyin(
        buf: *const c_void,
        driverbuf: *mut c_void,
        cn: size_t,
        flags: c_int,
    ) -> c_int;
    pub fn ddi_copyout(
        dirverbuf: *const c_void,
        buf: *mut c_void,
        cn: size_t,
        flags: c_int,
    ) -> c_int;
    pub fn ddi_create_minor_node(
        dip: *mut dev_info,
        name: *const c_char,
        spec_type: c_int,
        minor_num: minor_t,
        node_type: *const c_char,
        flag: c_int,
    ) -> c_int;
    pub fn ddi_get_driver_private(dip: *mut dev_info) -> *mut c_void;
    pub fn ddi_get_soft_state(state: *mut c_void, item: c_int) -> *mut c_void;
    pub fn ddi_periodic_add(
        cb: periodic_cb,
        arg: *const c_void,
        interval: hrtime_t,
        level: c_int,
    ) -> *const ddi_periodic;
    pub fn ddi_periodic_delete(request: *const ddi_periodic);
    pub fn ddi_prop_free(data: *mut c_void);
    pub fn ddi_prop_lookup_string(
        match_dev: dev_t,
        dip: *mut dev_info,
        flags: c_uint,
        name: *const c_char,
        datap: *mut *const c_char,
    ) -> c_int;
    pub fn ddi_prop_op() -> c_int;
    pub fn ddi_quiesce_not_needed(dip: *mut dev_info) -> c_int;
    pub fn ddi_remove_minor_node(dip: *mut dev_info, name: *const c_char);
    pub fn ddi_report_dev(dip: *mut dev_info);
    pub fn ddi_set_driver_private(dip: *mut dev_info, data: *mut c_void);
    pub fn ddi_soft_state_init(
        state_p: *mut *mut c_void,
        size: size_t,
        n_items: size_t,
    ) -> c_int;
    pub fn ddi_soft_state_fini(state_p: *mut *mut c_void);
    pub fn ddi_soft_state_zalloc(state: *mut c_void, item: c_int) -> c_int;

    pub fn freemsg(mp: *mut mblk_t);

    pub fn gethrtime() -> hrtime_t;
    pub fn getminor(dev: dev_t) -> minor_t;

    pub fn id_alloc_nosleep(idspace: *const id_space_t) -> id_t;
    pub fn id_free(idspace: *const id_space_t, id: id_t);
    pub fn id_space_create(
        name: *const c_char,
        low: id_t,
        high: id_t,
    ) -> *mut id_space_t;
    pub fn id_space_destroy(idspace: *mut id_space_t);

    pub fn kmem_alloc(size: size_t, flag: c_int) -> *mut c_void;
    pub fn kmem_free(data: *mut c_void, size: size_t);
    pub fn kmem_zalloc(size: size_t, flag: c_int) -> *mut c_void;

    pub fn mod_install(linkage: *const modlinkage) -> c_int;
    pub fn mod_remove(linkage: *const modlinkage) -> c_int;
    pub fn mod_info(
        linkage: *const modlinkage,
        modinfop: *mut modinfo,
    ) -> c_int;

    pub fn msgsize(mp: *const mblk_t) -> size_t;

    pub fn mutex_destroy(mp: *mut kmutex_t);
    pub fn mutex_enter(mp: *mut kmutex_t);
    pub fn mutex_exit(mp: *mut kmutex_t);
    pub fn mutex_init(
        mp: *mut kmutex_t,
        name: *const c_char,
        mtype: kmutex_type_t,
        arg: *const c_void,
    );
    pub fn mutex_owned(mp: *mut kmutex_t) -> c_int;
    pub fn mutex_tryenter(mp: *mut kmutex_t) -> c_int;

    pub fn nochpoll() -> c_int;
    pub fn nodev() -> c_int;
    pub fn nulldev() -> c_int;

    pub fn panic(msg: *const c_char, ...) -> !;

    pub fn snprintf(
        s: *mut c_char,
        n: size_t,
        format: *const c_char,
        ...
    ) -> c_int;

    // External static symbols
    pub static mod_driverops: mod_ops;
}

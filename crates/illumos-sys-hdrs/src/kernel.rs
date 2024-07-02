// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

#![allow(clippy::missing_safety_doc)]

use super::*;

/// Command argument passed to `getinfo(9E)`.
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct ddi_info_cmd_t(pub c_int);
impl ddi_info_cmd_t {
    /// Convert a `dev_t` to a `dev_info_t`.
    pub const DDI_INFO_DEVT2DEVINFO: Self = Self(0);
    /// Convert a `dev_t` to an instance number.
    pub const DDI_INFO_DEVT2INSTANCE: Self = Self(1);
}

/// Attach command type passed to `attach(9E)`.
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct ddi_attach_cmd_t(pub c_int);
impl ddi_attach_cmd_t {
    /// Initialize a given device instance.
    pub const DDI_ATTACH: Self = Self(0);
    /// Resume a previously suspended device.
    pub const DDI_RESUME: Self = Self(1);
}

/// Detach command type passed to `detach(9E)`.
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct ddi_detach_cmd_t(pub c_int);
impl ddi_detach_cmd_t {
    /// Remove state associated with given device instance.
    pub const DDI_DETACH: Self = Self(0);
    /// Suspend a given device instance.
    pub const DDI_SUSPEND: Self = Self(1);
}

/// Reset type passed to driver's `devo_reset` routine.
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct ddi_reset_cmd_t(pub c_int);
impl ddi_reset_cmd_t {
    /// Force a reset of the device.
    pub const DDI_RESET_FORCE: Self = Self(0);
}

// TODO Technically this is not a "raw" interface. This should live
// somewhere else.
impl kmutex_t {
    pub fn new(mtype: kmutex_type_t) -> Self {
        let mut kmutex = kmutex_t { _opaque: 0 };
        unsafe {
            mutex_init(&mut kmutex, ptr::null(), mtype, ptr::null());
        }
        kmutex
    }
}

#[repr(C)]
pub struct krwlock_t {
    pub _opaque: u64,
}

/// Lock acquisition type passed to `rw_[try]enter(9F)`.
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct krw_t(pub c_int);
impl krw_t {
    /// Acquire lock exclusively.
    pub const RW_WRITER: Self = Self(0);
    /// Acquire lock non-exclusively.
    pub const RW_READER: Self = Self(1);
    /// Acquire lock non-exclusively, ignoring waiting writers.
    pub const RW_READER_STARVEWRITER: Self = Self(2);
}

extern "C" {
    type module_info;
    type module_stat;
    type struiod_t;
    type infod_t;
}

// See qinit(9S) for more information.
//
// uts/common/sys/stream.h
#[repr(C)]
pub struct qinit {
    pub qi_putp:
        unsafe extern "C" fn(q: *mut queue_t, mp: *mut mblk_t) -> c_int,
    pub qi_srvp: unsafe extern "C" fn(q: *mut queue_t) -> c_int,
    pub qi_qopen: unsafe extern "C" fn(
        q: *mut queue_t,
        devp: *mut dev_t,
        oflag: c_int,
        sflag: c_int,
        credp: *mut cred_t,
    ) -> c_int,
    pub qi_qclose: unsafe extern "C" fn(
        q: *mut queue_t,
        flag: c_int,
        credp: *mut cred_t,
    ) -> c_int,
    pub qi_qadmin: unsafe extern "C" fn() -> c_int,

    qi_minfo: *mut module_info,
    qi_mstat: *mut module_stat,
    qi_rwp: unsafe extern "C" fn(q: *mut queue_t, _: *mut struiod_t) -> c_int,
    qi_infop: unsafe extern "C" fn(q: *mut queue_t, _: *mut infod_t) -> c_int,
    qi_struiot: c_int,
}

// See streamtab(9S) for more information.
//
// uts/common/sys/stream.h
#[repr(C)]
pub struct streamtab {
    pub st_rdinit: *mut qinit,
    pub st_wrinit: *mut qinit,
    pub st_muxrinit: *mut qinit,
    pub st_muxwinit: *mut qinit,
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
    pub devo_getinfo: Option<
        unsafe extern "C" fn(
            dip: *mut dev_info,
            infocmd: ddi_info_cmd_t,
            arg: *mut c_void,
            result: *mut *mut c_void,
        ) -> c_int,
    >,
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
pub unsafe extern "C" fn nulldev_open(
    _devp: *mut dev_t,
    _flags: c_int,
    _otype: c_int,
    _credp: *mut cred_t,
) -> c_int {
    nulldev()
}

#[no_mangle]
pub unsafe extern "C" fn nulldev_close(
    _dev: dev_t,
    _flags: c_int,
    _otype: c_int,
    _credp: *mut cred_t,
) -> c_int {
    nulldev()
}

#[no_mangle]
pub unsafe extern "C" fn nodev_reset(
    _dip: *mut dev_info,
    _cmd: ddi_reset_cmd_t,
) -> c_int {
    nodev()
}

#[no_mangle]
pub unsafe extern "C" fn nodev_power(
    _dip: *mut dev_info,
    _component: c_int,
    _level: c_int,
) -> c_int {
    nodev()
}

#[no_mangle]
pub unsafe extern "C" fn nodev_read(
    _dev: dev_t,
    _uiop: *mut uio,
    _credp: *mut cred_t,
) -> c_int {
    nodev()
}

#[no_mangle]
pub unsafe extern "C" fn nodev_ioctl(
    _dev: dev_t,
    _cmd: c_int,
    _arg: intptr_t,
    _mode: c_int,
    _credp: *mut cred_t,
    _rvalp: *mut c_int,
) -> c_int {
    nodev()
}

#[no_mangle]
pub unsafe extern "C" fn nodev_write(
    _dev: dev_t,
    _uiop: *mut uio,
    _credp: *mut cred_t,
) -> c_int {
    nodev()
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
pub const DDI_PROP_NOT_FOUND: c_int = 1;

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
pub const DDI_PSEUDO: *const c_char = c"ddi_pseudo".as_ptr();

pub const KM_SLEEP: i32 = 0x0000;
pub const KM_NOSLEEP: i32 = 0x0001;

pub const MODREV_1: c_int = 1;

pub const S_IFCHR: c_int = 0x2000;

pub const MAC_VERSION_V1: c_int = 0x1;
pub const MAC_VERSION: c_int = MAC_VERSION_V1;
pub const MAC_PLUGIN_IDENT_ETHER: *const c_char = c"mac_ether".as_ptr();

pub type periodic_cb = unsafe extern "C" fn(arg: *mut c_void);

// XXX Define this so mod_ops has a known size to rustc. I had to do
// this to avoid an ICE (Internal Compiler Error) when updating to
// a newer toolchain. Otherwise, rustc would crash with the following:
//
// ```
// thread 'rustc' panicked at 'assertion failed: !layout.is_unsized()',
// compiler/rustc_const_eval/src/interpret/memory.rs:686:17
//
// query stack during panic:
// #0 [eval_to_allocation_raw] const-evaluating + checking `xde::xde_modldrv`
// #1 [eval_to_allocation_raw] const-evaluating + checking `xde::xde_modldrv`
// #2 [lint_mod] linting module `xde`
// #3 [analysis] running analysis passes on this crate
// ```
#[repr(C)]
pub struct mod_ops {
    modm_install: unsafe extern "C" fn() -> c_int,
    modm_remove: unsafe extern "C" fn() -> c_int,
    modm_info: unsafe extern "C" fn() -> c_int,
}

extern "C" {
    // DDI/DKI types
    pub type bus_ops;

    pub type cred_t;

    pub type ddi_periodic;
    pub type dev_info;

    pub type id_space_t;

    pub type modinfo;

    pub type queue_t; // Definitely not using STREAMS.

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
    pub fn ddi_get_instance(dip: *mut dev_info) -> c_int;
    pub fn ddi_get_soft_state(state: *mut c_void, item: c_int) -> *mut c_void;
    pub fn ddi_periodic_add(
        cb: periodic_cb,
        arg: *const c_void,
        interval: hrtime_t,
        level: c_int,
    ) -> *const ddi_periodic;
    pub fn ddi_periodic_delete(request: *const ddi_periodic);
    pub fn ddi_prop_exists(
        match_dev: dev_t,
        dip: *mut dev_info,
        flags: c_uint,
        name: *const c_char,
    ) -> c_int;
    pub fn ddi_prop_free(data: *mut c_void);
    pub fn ddi_prop_get_int(
        match_dev: dev_t,
        dip: *mut dev_info,
        flags: c_uint,
        name: *const c_char,
        defvalue: c_int,
    ) -> c_int;
    pub fn ddi_prop_get_int64(
        match_dev: dev_t,
        dip: *mut dev_info,
        flags: c_uint,
        name: *const c_char,
        defvalue: i64,
    ) -> i64;
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

    pub fn freeb(mp: *mut mblk_t);
    pub fn freemsg(mp: *mut mblk_t);
    pub fn freemsgchain(mp: *mut mblk_t);

    pub fn gethrtime() -> hrtime_t;

    pub fn getmajor(dev: dev_t) -> major_t;
    pub fn getminor(dev: dev_t) -> minor_t;
    pub fn makedevice(major: major_t, minor: minor_t) -> dev_t;

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

    pub fn kstat_create(
        ks_module: *const c_char,
        ks_instnace: c_int,
        ks_name: *const c_char,
        ks_class: *const c_char,
        ks_type: c_uchar,
        ks_ndata: c_ulong,
        ks_flag: c_uchar,
    ) -> *mut kstat_t;
    pub fn kstat_delete(ksp: *const kstat_t);
    pub fn kstat_install(ksp: *const kstat_t);
    pub fn kstat_named_init(
        knp: *const kstat_named_t,
        name: *const c_char,
        data_type: c_uchar,
    );

    pub fn miocnak(
        wq: *mut queue_t,
        mp: *mut mblk_t,
        count: c_int,
        error: c_int,
    );

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

    pub fn rw_init(
        rwlp: *mut krwlock_t,
        name: *const c_char,
        typ: krw_type_t,
        arg: *const c_void,
    );
    pub fn rw_destroy(rwlp: *mut krwlock_t);
    pub fn rw_enter(rwlp: *mut krwlock_t, enter_type: krw_t);
    pub fn rw_exit(rwlp: *mut krwlock_t);
    pub fn rw_tryenter(rwlp: *mut krwlock_t, enter_type: krw_t);
    pub fn rw_downgrade(rwlp: *mut krwlock_t);
    pub fn rw_tryupgrade(rwlp: *mut krwlock_t);
    pub fn rw_read_locked(rwlp: *mut krwlock_t);

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

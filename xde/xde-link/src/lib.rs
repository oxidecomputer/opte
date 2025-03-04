#![allow(non_camel_case_types)]
#![no_std]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    #[link(name = "c")]
    unsafe extern "C" {
        fn abort() -> !;
    }
    unsafe { abort() }
}

// devfsadm expects 2 symbols to be exported:
// - _devfsadm_create_reg: link creation registration
// - _devfsadm_remove_reg: link removal registration

/// devfsadm plugin link creation registration
/// Exported plugin entry point for
#[unsafe(no_mangle)]
pub static _devfsadm_create_reg: _devfsadm_create_reg_t =
    _devfsadm_create_reg_t {
        version: DEVFSADM_V0,
        count: 1,
        tblp: &devfsadm_create_t {
            device_class: c"pseudo".as_ptr(),
            node_type: DDI_PSEUDO,
            drv_name: c"xde".as_ptr(),
            flags: TYPE_EXACT | DRV_EXACT,
            interpose_lvl: ILEVEL_0,
            callback_fcn: create_xde_link,
        },
    };

/// devfsadm plugin link removal registration
#[unsafe(no_mangle)]
pub static _devfsadm_remove_reg: _devfsadm_remove_reg_t =
    _devfsadm_remove_reg_t {
        version: DEVFSADM_V0,
        count: 1,
        tblp: &devfsadm_remove_t {
            device_class: c"pseudo".as_ptr(),
            dev_dirs_re: c"^xde$".as_ptr(),
            flags: RM_HOT | RM_PRE | RM_ALWAYS,
            interpose_lvl: ILEVEL_0,
            callback_fcn: devfsadm_rm_all,
        },
    };

/// Create xde /dev link for the control device
///     /dev/xde => /devices/pseudo/xde@0:ctl
unsafe extern "C" fn create_xde_link(
    minor: *const di_minor,
    node: *const di_node,
) -> c_int {
    #[link(name = "c")]
    unsafe extern "C" {
        fn strcmp(s1: *const c_char, s2: *const c_char) -> c_int;
    }
    if strcmp(di_minor_name(minor), c"ctl".as_ptr()) == 0 {
        devfsadm_mklink(c"xde".as_ptr(), node, minor, 0);
    }
    0
}

use core::ffi::c_char;
use core::ffi::c_int;
use core::ffi::c_uint;

/// devfsadm plugin interface version 0
pub const DEVFSADM_V0: c_uint = 0;

/// Create /dev link at the root
pub const ILEVEL_0: c_int = 0;

/// Match minor node type exactly
pub const TYPE_EXACT: c_int = 0x01;

/// Match driver name exactly
pub const DRV_EXACT: c_int = 0x10;

/// Remove /dev link when device is hot-removed
pub const RM_HOT: c_int = 0x01;

/// Remove /dev link before processing entire devinfo tree
pub const RM_PRE: c_int = 0x02;

/// Remove /dev link even if cleanup wasn't requested
pub const RM_ALWAYS: c_int = 0x08;

/// Minor node type for pseudo devices
pub const DDI_PSEUDO: *const c_char = c"ddi_pseudo".as_ptr();

/// Opaque minor node handle
type di_minor = core::ffi::c_void;

/// Opaque device node handle
type di_node = core::ffi::c_void;

// See lib/libdevinfo/libdevinfo.h
#[link(name = "devinfo")]
unsafe extern "C" {
    /// Returns name for give minor node
    fn di_minor_name(minor: *const di_minor) -> *const c_char;
}

// These symbols exist in the `devfsadm` binary itself which is the one
// that will be `dlopen()`'ing the plugin.
unsafe extern "C" {
    fn devfsadm_mklink(
        link: *const c_char,
        node: *const di_node,
        minor: *const di_minor,
        flags: c_int,
    ) -> c_int;
    fn devfsadm_rm_all(file: *const c_char);
}

/// Predicates used to match a device and how to create its /dev link
///
/// cmd/devfsadm/devfsadm.h
#[repr(C)]
struct devfsadm_create_t {
    /// Device class to match (e.g. "pseudo", "disk")
    device_class: *const c_char,
    /// Minor node type to match (e.g. DDI_PSEUDO, DDI_NT_BLOCK)
    node_type: *const c_char,
    /// Driver name to match
    drv_name: *const c_char,
    /// Flags to control matching
    flags: c_int,
    /// Level at which to create /dev/ link
    /// (e.g. ILEVEL_0, ILEVEL_1, ILEVEL_2)
    interpose_lvl: c_int,
    /// Callback to create /dev/ link
    callback_fcn:
        unsafe extern "C" fn(*const di_minor, *const di_node) -> c_int,
}

/// devfsadm plugin link creation registration information
#[repr(C)]
pub struct _devfsadm_create_reg_t {
    /// devfsadm plugin interface version
    version: c_uint,
    /// Number of entries in the creation entry table (`tblp`)
    count: c_uint,
    /// Table of link creation entries
    tblp: *const devfsadm_create_t,
}
// SAFETY: Sync is required to stick this in a static.
//         The only non-Sync field is `tblp` which is never modified.
unsafe impl Sync for _devfsadm_create_reg_t {}

/// Predicates used to match a device and how to remove its /dev link
#[repr(C)]
struct devfsadm_remove_t {
    /// Device class to match (e.g. "pseudo", "disk")
    device_class: *const c_char,
    /// Regex to match /dev directories
    dev_dirs_re: *const c_char,
    /// Flags to control removal
    flags: c_int,
    /// /dev/ dir nesting level
    interpose_lvl: c_int,
    /// Callback to remove /dev/ links
    callback_fcn: unsafe extern "C" fn(*const c_char),
}

/// devfsadm plugin link deletion registration information
#[repr(C)]
pub struct _devfsadm_remove_reg_t {
    /// devfsadm plugin interface version
    version: c_uint,
    /// Number of entries in the removal entry table (`tblp`)
    count: c_uint,
    /// Table of link removal entries
    tblp: *const devfsadm_remove_t,
}
// SAFETY: Sync is required to stick this in a static.
//         The only non-Sync field is `tblp` which is never modified.
unsafe impl Sync for _devfsadm_remove_reg_t {}

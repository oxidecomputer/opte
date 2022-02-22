// xde - a mac provider for OPTE and the onramp to the Oxide rack network
#![feature(extern_types)]
#![feature(lang_items)]
#![feature(panic_info_message)]
#![no_std]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(improper_ctypes)] // for long double -> u128
#![allow(non_camel_case_types)] // for bindgen code in ip.rs
#![allow(non_snake_case)] // for bindgen code in ip.rs
#![feature(alloc_error_handler)]
#![feature(rustc_private)]

mod ioctl;

#[macro_use]
extern crate alloc;

use core::{
    alloc::{GlobalAlloc, Layout},
    panic::PanicInfo,
};

use cstr_core::CString;

pub mod dld;
pub mod dls;
pub mod mac;
pub mod secpolicy;
pub mod xde;
pub mod ip;

use illumos_ddi_dki::{
    c_void, cmn_err, kmem_alloc, kmem_free, panic, size_t, CE_WARN, KM_SLEEP,
};

struct KmemAlloc;
unsafe impl GlobalAlloc for KmemAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() > 8 {
            panic!("kernel alloc greater than 8-byte alignment");
        }
        kmem_alloc(layout.size(), KM_SLEEP) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        kmem_free(ptr as *mut c_void, layout.size() as size_t)
    }
}

#[panic_handler]
fn panic_hdlr(info: &PanicInfo) -> ! {
    let msg = CString::new(format!("{}", info)).expect("cstring new");
    unsafe {
        cmn_err(CE_WARN, msg.as_ptr());
        panic(msg.as_ptr());
    }
}

#[alloc_error_handler]
fn alloc_error(_: Layout) -> ! {
    panic!("allocation error");
}

#[global_allocator]
static A: KmemAlloc = KmemAlloc;

#[macro_export]
macro_rules! warn {
    ($format:expr) => {
        let msg = format!($format);
        cmn_err(
            CE_WARN,
            CString::new(msg).unwrap().as_ptr(),
        );
    };
    ($format:expr, $($args:expr),*) => {
        let msg = format!($format, $($args),*);
        cmn_err(
            CE_WARN,
            CString::new(msg).unwrap().as_ptr(),
        );
    };
}

#[macro_export]
macro_rules! note {
    ($format:expr) => {
        let msg = format!($format);
        cmn_err(
            CE_NOTE,
            CString::new(msg).unwrap().as_ptr(),
        );
    };
    ($format:expr, $($args:expr),*) => {
        let msg = format!($format, $($args),*);
        cmn_err(
            CE_NOTE,
            CString::new(msg).unwrap().as_ptr(),
        );
    };
}

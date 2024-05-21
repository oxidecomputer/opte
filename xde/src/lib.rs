// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

// xde - A mac provider for OPTE-based network implementations.
#![feature(extern_types)]
#![feature(panic_info_message)]
#![no_std]
#![allow(non_upper_case_globals)]
// XXX We do not use double in the kernel. We should not allow
// "improper C types". This hack is here is because of the ip.rs code
// generated by bindgen. It brings in a bunch of stuff we do not use.
// At some point we could hand write the stuff that is actually
// needed, or come up with a better solution like using CTF data to
// generate Rust types for only the stuff we need.
#![allow(improper_ctypes)] // for long double -> u128
#![allow(non_camel_case_types)] // for bindgen code in ip.rs
#![allow(non_snake_case)] // for bindgen code in ip.rs
#![feature(alloc_error_handler)]
#![feature(rustc_private)]
#![deny(unused_must_use)]

mod ioctl;

#[macro_use]
extern crate alloc;

use alloc::ffi::CString;
use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use core::panic::PanicInfo;
use illumos_sys_hdrs::c_void;
use illumos_sys_hdrs::cmn_err;
use illumos_sys_hdrs::kmem_alloc;
use illumos_sys_hdrs::kmem_free;
use illumos_sys_hdrs::panic;
use illumos_sys_hdrs::size_t;
use illumos_sys_hdrs::CE_WARN;
use illumos_sys_hdrs::KM_SLEEP;

pub mod dls;
pub mod ip;
pub mod mac;
mod mac_sys;
pub mod secpolicy;
pub mod sys;
pub mod xde;

// On alignment, `kmem_alloc(9F)` has this of offer:
//
// > The allocated memory is at least double-word aligned, so it can
// > hold any C data structure. No greater alignment can be assumed.
//
// I really hate when documentation uses "word", because that seems to
// mean different things in different contexts. In this case I have to
// assume it means native integer size, or 32-bit in the case our our
// AMD64 kernel. This implis all allocations are at least 8-byte
// aligned, but could be more. However, the last sentence in the quote
// above says that you cannot assume alignment is ever greater than 8
// bytes. Therefore, it seems best to assume it's 8 bytes. For the
// purposes of implementing GlobalAlloc, I believe this means that we
// should return NULL for any Layout which requests more than 8-byte
// alignment (or probably just panic since I never expect this).
// Furthermore, things that can use smaller alignment will just have
// to live with the larger alignment.
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

// The GlobalAlloc is using KM_SLEEP; we can never hit this. However, the
// compiler forces us to define it, so we do.
#[alloc_error_handler]
fn alloc_error(_: Layout) -> ! {
    panic!("allocation error");
}

#[global_allocator]
static A: KmemAlloc = KmemAlloc;

// This is a hack to get around the fact that liballoc includes
// calls to _Unwind_Resume, supposedly because it is not compiled
// with `panic=abort`. This is all a little bit beyond me but I just
// want to satisfy the symbol resolution so I can load this module.
//
// https://github.com/rust-lang/rust/issues/47493
#[allow(non_snake_case)]
#[no_mangle]
fn _Unwind_Resume() -> ! {
    panic!("_Unwind_Resume called");
}

// NOTE: We allow unused_unsafe so these macros can be used freely in
// unsafe and non-unsafe functions.
#[macro_export]
macro_rules! warn {
    ($format:expr) => {
        let msg = CString::new(format!($format)).unwrap();
        #[allow(unused_unsafe)]
        unsafe { cmn_err(CE_WARN, msg.as_ptr()) };
    };
    ($format:expr, $($args:expr),*) => {
        let msg = CString::new(format!($format, $($args),*)).unwrap();
        #[allow(unused_unsafe)]
        unsafe { cmn_err(CE_WARN, msg.as_ptr()) };
    };
}

#[macro_export]
macro_rules! note {
    ($format:expr) => {
        let msg = CString::new(format!($format));
        cmn_err(CE_NOTE, msg.as_ptr());
    };
    ($format:expr, $($args:expr),*) => {
        let msg = CString::new(format!($format, $($args),*));
        cmn_err(CE_NOTE, msg.as_ptr());
    };
}

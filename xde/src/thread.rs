// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Illumos kthread support.

use crate::ip::kthread_t;
use crate::ip::p0;
use crate::ip::thread_create;
use crate::ip::thread_exit;
use crate::ip::thread_join;
use crate::ip::TS_RUN;
use alloc::boxed::Box;
use core::ffi::c_void;
use core::ptr;
use core::ptr::addr_of_mut;
use core::ptr::NonNull;

unsafe extern "C" fn kthread_body(arg: *mut c_void) {
    let arg = arg as *mut Box<dyn FnOnce()>;
    let closure = unsafe { Box::from_raw(arg) };

    closure();
    // closure used by val, so dropped before thread exit.

    unsafe {
        thread_exit();
    }
}

pub fn spawn<F>(f: F) -> JoinHandle
where
    F: FnOnce(), // -> T,
    F: Send + 'static,
    // T: Send + 'static,
{
    // A bit of an odd dance here -- we need to double box to get a thin
    // pointer at the `into_raw` side.
    let boxed = Box::new(f) as Box<dyn FnOnce()>;
    let arg = Box::into_raw(Box::new(boxed));
    let handle = unsafe {
        thread_create(
            ptr::null_mut(),
            0, // pulled up to default stack size.
            // Typedef implies no args, reality implies args. Huh.
            Some(core::mem::transmute::<_, unsafe extern "C" fn()>(
                kthread_body as unsafe extern "C" fn(_),
            )),
            arg as *mut c_void,
            0,
            addr_of_mut!(p0),
            TS_RUN as i32,
            60, //minclsyspri
        )
    };

    let handle = NonNull::new(handle)
        .expect("thread_create returned a null ptr, \
            but is documented as infallible");

    JoinHandle { handle }
}

pub struct JoinHandle {
    handle: NonNull<kthread_t>,
}

impl JoinHandle {
    pub fn join(self) {
        unsafe { thread_join((*self.handle.as_ptr()).t_did) }
    }
}

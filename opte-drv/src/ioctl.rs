use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::mem::{self, MaybeUninit};
use core::result;

use ddi::{c_int, c_void};
use illumos_ddi_dki as ddi;

use opte_core::ioctl::{CmdErr, CmdOk, Ioctl};
use opte_core::CString;

use postcard;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub enum Error {
    DeserError(String),
    FailedCopyin,
    FailedCopyout,
    RespTooLong,
}

pub type Result<T> = result::Result<T, Error>;

pub fn to_errno(e: Error) -> c_int {
    match e {
        Error::DeserError(_) => ddi::EINVAL,
        Error::RespTooLong => ddi::ENOBUFS,
        _ => ddi::EFAULT,
    }
}

extern "C" {
    fn __dtrace_probe_copy__out__resp(resp_str: ddi::uintptr_t);
}

fn dtrace_probe_copy_out_resp<T: Debug + Serialize>(resp: &T) {
    let cstr = CString::new(format!("{:?}", resp)).unwrap();
    unsafe {
        __dtrace_probe_copy__out__resp(cstr.as_ptr() as ddi::uintptr_t);
    }
}

extern "C" {
    fn __dtrace_probe_copy__out__resp(resp_str: ddi::uintptr_t);
}

fn dtrace_probe_copy_out_resp<T: Debug + Serialize>(resp: &T) {
    let cstr = CString::new(format!("{:?}", resp)).unwrap();
    unsafe {
        __dtrace_probe_copy__out__resp(cstr.as_ptr() as ddi::uintptr_t);
    }
}

/// An envelope for dealing with `Ioctl`. It contains all information
/// needed to deserialize the user's request and serialize the
/// kernel's response.
pub struct IoctlEnvelope {
    //The kernel-side copy of the user's `Ioctl`.
    ioctl: Ioctl,

    // A pointer to the user's copy of the `Ioctl`.
    arg_ptr: *const c_void,

    // A copy of the `mode` argument passed to the ioctl(9E)
    // interface.
    mode: c_int,
}

impl IoctlEnvelope {
    /// Safety: The `arg_ptr` should come directly from the `arg`
    /// argument passed to the `ioctl(9E)` callback.
    pub unsafe fn new(arg_ptr: *const c_void, mode: c_int) -> Result<Self> {
        let mut ioctl = MaybeUninit::<Ioctl>::uninit();

        let ret = ddi::ddi_copyin(
            arg_ptr,
            ioctl.as_mut_ptr() as *mut c_void,
            mem::size_of::<Ioctl>(),
            mode,
        );

        if ret != 0 {
            return Err(Error::FailedCopyin);
        }

        let ioctl = ioctl.assume_init();
        Ok(IoctlEnvelope { ioctl, arg_ptr, mode })
    }

    fn copy_out_self(&self) -> Result<()> {
        // Safety: We know the `self.ioctl` pointer is valid as our
        // `new()` constructor made the allocation. We also know the
        // `self.arg` pointer is valid as long as the caller obeyed
        // the safety invariant of the constructor: that it's
        // `arg_ptr` be the `arg` passed to `ioctl(9E)`.
        let ret = unsafe {
            ddi::ddi_copyout(
                &self.ioctl as *const Ioctl as *const c_void,
                self.arg_ptr as *mut c_void,
                mem::size_of::<Ioctl>(),
                self.mode,
            )
        };

        if ret != 0 {
            return Err(Error::FailedCopyout);
        }

        Ok(())
    }

    /// Take any type which implements `Serialize`, serialize it, and
    /// then `ddi_copyoyt(9F)` it to the user address specified in
    /// `resp_bytes`. Return an error if the `resp_len` indicates that
    /// the user buffer is not large enough to hold the serialized
    /// bytes.
    pub fn copy_out_resp<T, E>(
        &mut self,
        val: &result::Result<T, E>,
    ) -> Result<()>
    where
        E: CmdErr,
        T: CmdOk,
    {
        dtrace_probe_copy_out_resp(val);

        // We expect the kernel to pass values of `T` which will
        // serialize, thus the use of `unwrap()`.
        let vec = postcard::to_allocvec(val).unwrap();
        self.ioctl.resp_len_needed = vec.len();

        if vec.len() > self.ioctl.resp_len {
            self.copy_out_self()?;
            return Err(Error::RespTooLong);
        }

        // Safety: We know the `vec` pointer is valid as we just
        // created it. We assume the `resp_bytes` pointer is valid,
        // but since it's coming from userspace it could be anything.
        // However, it is `ddi_copyout()`'s job to protect against an
        // invalid pointer, not ours.
        let ret = unsafe {
            ddi::ddi_copyout(
                vec.as_ptr() as *const c_void,
                self.ioctl.resp_bytes as *mut c_void,
                vec.len(),
                self.mode,
            )
        };

        if ret != 0 {
            return Err(Error::FailedCopyout);
        }

        self.copy_out_self()?;
        Ok(())
    }

    /// Given `self`, return the deserialized ioctl request.
    pub fn copy_in_req<T: DeserializeOwned>(&self) -> Result<T> {
        // TODO place upper limit on req_len to prevent
        // malicious/malformed requests from allocating large amounts
        // of kmem.
        let mut bytes = Vec::with_capacity(self.ioctl.req_len);
        let ret = unsafe {
            ddi::ddi_copyin(
                self.ioctl.req_bytes as *const c_void,
                bytes.as_mut_ptr() as *mut c_void,
                self.ioctl.req_len,
                self.mode,
            )
        };

        if ret != 0 {
            return Err(Error::FailedCopyin);
        }

        // Safety: We know the `Vec` has `req_len` capacity, and that
        // `ddi_copyin(9F)` either copied `req_len` bytes or returned
        // an error.
        unsafe { bytes.set_len(self.ioctl.req_len) };

        // TODO Do I need to control the length of how many bytes
        // postcard might read here?
        match postcard::from_bytes(&bytes) {
            Ok(val) => Ok(val),
            Err(deser_error) => {
                Err(Error::DeserError(format!("{}", deser_error)))
            }
        }
    }
}

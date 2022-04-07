use alloc::vec::Vec;
use core::fmt::Debug;
use core::result;

use ddi::{c_int, c_void};
use illumos_ddi_dki as ddi;

use opte_api::{
    CmdOk, OpteCmd, OpteCmdIoctl, OpteError, API_VERSION,
    OPTE_CMD_RESP_COPY_OUT,
};
use opte_core::CString;

use postcard;

use serde::de::DeserializeOwned;
use serde::Serialize;

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
#[derive(Debug)]
pub struct IoctlEnvelope<'a> {
    // The kernel-side copy of the user's ioctl(2) argument.
    ioctl: &'a mut OpteCmdIoctl,

    // A copy of the `mode` argument passed to the ioctl(9E)
    // interface.
    mode: c_int,
}

impl<'a> IoctlEnvelope<'a> {
    pub fn ioctl_cmd(&self) -> OpteCmd {
        self.ioctl.cmd
    }

    /// Safety: The `karg` should come directly from the `karg`
    /// argument passed to the `dld_ioc_info_t` callback.
    pub unsafe fn wrap(
        ioctl: &'a mut OpteCmdIoctl,
        mode: c_int,
    ) -> result::Result<Self, c_int> {
        if !ioctl.check_version() {
            let badver = OpteError::BadApiVersion {
                user: ioctl.api_version,
                kernel: API_VERSION,
            };

            let _ = Self::copy_out_resp_i::<()>(ioctl, &Err(badver), mode);
            return Err(ddi::EPROTO);
        }

        Ok(Self { ioctl, mode })
    }

    /// Given `self`, return the deserialized ioctl request.
    pub fn copy_in_req<T: DeserializeOwned>(
        &mut self,
    ) -> result::Result<T, OpteError> {
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
            let _ = self.copy_out_resp::<()>(&Err(OpteError::CopyinReq));
            return Err(OpteError::CopyinReq);
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
                Err(OpteError::DeserCmdReq(format!("{}", deser_error)))
            }
        }
    }

    fn copy_out_resp_i<T>(
        ioctl: &mut OpteCmdIoctl,
        resp: &result::Result<T, OpteError>,
        mode: c_int,
    ) -> c_int
    where
        T: CmdOk,
    {
        dtrace_probe_copy_out_resp(resp);
        let ser_result = match resp {
            Ok(v) => postcard::to_allocvec(v)
                .map_err(|e| OpteError::SerCmdResp(format!("{}", e))),

            Err(e) => postcard::to_allocvec(e)
                .map_err(|e| OpteError::SerCmdErr(format!("{}", e))),
        };

        // We failed to serialize the response, communicate this with ENOMSG.
        if let Err(_) = ser_result {
            // XXX In this case we aren't trying to serialize +
            // copyout the serialization error. We should do that so
            // there is more context for the caller.
            return ddi::ENOMSG;
        }

        let vec = ser_result.unwrap();
        ioctl.resp_len_actual = vec.len();

        if vec.len() > ioctl.resp_len {
            return ddi::ENOBUFS;
        }

        // Safety: We know the `vec` pointer is valid as we just
        // created it. We assume the `resp_bytes` pointer is valid,
        // but since it's coming from userspace it could be anything.
        // However, it is `ddi_copyout()`'s job to protect against an
        // invalid pointer, not ours.
        let ret = unsafe {
            ddi::ddi_copyout(
                vec.as_ptr() as *const c_void,
                ioctl.resp_bytes as *mut c_void,
                vec.len(),
                mode,
            )
        };

        if ret != 0 {
            // We failed to copyout, respond with the recommended
            // EFAULT.
            return ddi::EFAULT;
        } else {
            // We successfully copied out a response. If the response
            // is a command error, set the errno based on the type of
            // error.
            ioctl.flags |= OPTE_CMD_RESP_COPY_OUT;
            if let Err(err) = resp {
                err.to_errno()
            } else {
                0
            }
        }
    }

    /// Take any type which implements `Serialize`, serialize it, and
    /// then `ddi_copyoyt(9F)` it to the user address specified in
    /// `resp_bytes`. Return an error if the `resp_len` indicates that
    /// the user buffer is not large enough to hold the serialized
    /// bytes.
    pub fn copy_out_resp<T>(
        &mut self,
        val: &result::Result<T, OpteError>,
    ) -> c_int
    where
        T: CmdOk,
    {
        Self::copy_out_resp_i(self.ioctl, val, self.mode)
    }
}

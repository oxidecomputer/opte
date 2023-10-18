// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use opte::api::CmdOk;
use opte::api::NoResp;
use opte::api::OpteCmd;
use opte::api::OpteCmdIoctl;
pub use opte::api::OpteError;
use opte::api::SetXdeUnderlayReq;
use opte::api::API_VERSION;
use opte::api::XDE_IOC_OPTE_CMD;
use oxide_vpc::api::AddRouterEntryReq;
use oxide_vpc::api::CreateXdeReq;
use oxide_vpc::api::DeleteXdeReq;
use oxide_vpc::api::DhcpCfg;
use oxide_vpc::api::ListPortsResp;
use oxide_vpc::api::SetFwRulesReq;
use oxide_vpc::api::SetVirt2PhysReq;
use oxide_vpc::api::VpcCfg;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use thiserror::Error;

/// Errors related to administering the OPTE driver.
#[derive(Debug, Error)]
#[cfg(target_os = "illumos")]
pub enum Error {
    #[error("OPTE driver is not attached")]
    DriverNotAttached,

    #[error("error interacting with device: {0}")]
    Io(std::io::Error),

    /// Something in the opte ioctl(2) handler failed.
    #[error("ioctl {0:?} failed: {1}")]
    IoctlFailed(OpteCmd, String),

    #[error("invalid argument {0}")]
    InvalidArgument(String),

    #[error("netadm failed {0}")]
    NetadmFailed(libnet::Error),

    #[error("request serialization failed for command {0:?}: {1}")]
    ReqSer(OpteCmd, postcard::Error),

    #[error("response deserialization failed for command {0:?}: {1}")]
    RespDeser(OpteCmd, postcard::Error),

    #[error("failed to get response for command {0:?} in {1} attempts")]
    MaxAttempts(OpteCmd, u8),

    #[error("command {0:?} failed: {1:?}")]
    CommandError(OpteCmd, OpteError),
}

#[cfg(target_os = "illumos")]
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => Error::DriverNotAttached,
            _ => Error::Io(e),
        }
    }
}

#[cfg(target_os = "illumos")]
impl From<libnet::Error> for Error {
    fn from(e: libnet::Error) -> Self {
        Self::NetadmFailed(e)
    }
}

/// The handle used to send administration commands to OPTE.
#[derive(Debug)]
#[cfg(target_os = "illumos")]
pub struct OpteHdl {
    device: File,
}

#[cfg(target_os = "illumos")]
impl OpteHdl {
    pub const XDE_CTL: &'static str = "/dev/xde";

    /// Add xde device
    pub fn create_xde(
        &self,
        name: &str,
        cfg: VpcCfg,
        dhcp: DhcpCfg,
        passthrough: bool,
    ) -> Result<NoResp, Error> {
        use libnet::link;

        let linkid = link::create_link_id(
            name,
            libnet::LinkClass::Misc,
            libnet::LinkFlags::Active,
        )?;

        let xde_devname = name.into();
        let cmd = OpteCmd::CreateXde;
        let req = CreateXdeReq { xde_devname, linkid, cfg, dhcp, passthrough };

        let res = run_cmd_ioctl(self.device.as_raw_fd(), cmd, Some(&req));

        if res.is_err() {
            let _ = link::delete_link_id(linkid, libnet::LinkFlags::Active);
        }

        res
    }

    /// Delete xde device
    pub fn delete_xde(&self, name: &str) -> Result<NoResp, Error> {
        let link_id = libnet::LinkHandle::Name(name.into()).id()?;
        let req = DeleteXdeReq { xde_devname: name.into() };
        let cmd = OpteCmd::DeleteXde;
        let resp = run_cmd_ioctl(self.device.as_raw_fd(), cmd, Some(&req))?;
        libnet::link::delete_link_id(link_id, libnet::LinkFlags::Active)?;
        Ok(resp)
    }

    /// List the extant OPTE ports.
    pub fn list_ports(&self) -> Result<ListPortsResp, Error> {
        run_cmd_ioctl(self.device.as_raw_fd(), OpteCmd::ListPorts, None::<&()>)
    }

    /// Create a new handle to the OPTE control node.
    pub fn open(what: &str) -> Result<Self, Error> {
        Ok(OpteHdl {
            device: OpenOptions::new().read(true).write(true).open(what)?,
        })
    }

    pub fn set_v2p(&self, req: &SetVirt2PhysReq) -> Result<NoResp, Error> {
        let cmd = OpteCmd::SetVirt2Phys;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, Some(&req))
    }

    /// Set xde underlay devices.
    pub fn set_xde_underlay(
        &self,
        u1: &str,
        u2: &str,
    ) -> Result<NoResp, Error> {
        let req = SetXdeUnderlayReq { u1: u1.into(), u2: u2.into() };
        let cmd = OpteCmd::SetXdeUnderlay;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, Some(&req))
    }

    pub fn add_router_entry(
        &self,
        req: &AddRouterEntryReq,
    ) -> Result<NoResp, Error> {
        let cmd = OpteCmd::AddRouterEntry;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, Some(&req))
    }

    pub fn set_fw_rules(&self, req: &SetFwRulesReq) -> Result<NoResp, Error> {
        let cmd = OpteCmd::SetFwRules;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, Some(&req))
    }
}

#[cfg(target_os = "illumos")]
pub fn run_cmd_ioctl<T, R>(
    dev: libc::c_int,
    cmd: OpteCmd,
    req: Option<&R>,
) -> Result<T, Error>
where
    T: CmdOk + DeserializeOwned,
    R: Serialize,
{
    let (req_bytes_ptr, req_len) = match req {
        Some(req) => {
            let bytes = postcard::to_allocvec(req)
                .map_err(|e| Error::ReqSer(cmd, e))?;
            let len = bytes.len();
            // This is here to catch the case where you, the
            // developer, have accidentally used a ZST as a request
            // type. I would have added a compile-time check but as
            // far as I can tell there is no way to use size_of with a
            // generic type. This check is sufficient, and is just a
            // means to save you hours of heartache if you were to
            // accidentally create a ZST request type.
            assert!(len > 0, "cannot use ZST for request type");
            (bytes.as_ptr(), len)
        }

        None => (core::ptr::null(), 0),
    };

    // It would be a shame if the command failed and we didn't have
    // enough bytes to serialize the error response, so we set this to
    // default to 16 KiB.
    let mut resp_buf: Vec<u8> = vec![0; 16 * 1024];
    let mut rioctl = OpteCmdIoctl {
        api_version: API_VERSION,
        cmd,
        flags: 0,
        reserved1: 0,
        req_bytes: req_bytes_ptr,
        req_len,
        resp_bytes: resp_buf.as_mut_ptr(),
        resp_len: resp_buf.len(),
        resp_len_actual: 0,
    };

    const MAX_ITERATIONS: u8 = 3;
    for _ in 0..MAX_ITERATIONS {
        let ret = unsafe {
            libc::ioctl(dev, XDE_IOC_OPTE_CMD as libc::c_int, &rioctl)
        };

        // The ioctl(2) failed for a reason other than the response
        // buffer being too small.
        //
        // errno == ENOBUFS
        //
        //    The command ran successfully, but there is not enough
        //    space to copyout(9F) the response. In this case bump
        //    up the size of the response buffer and retry.
        //
        // errno != 0 && OPTE_CMD_RESP_COPY_OUT
        //
        //    The command failed and we have an error response
        //    serialized in the response buffer.
        //
        // errno != 0
        //
        //    Either the command failed or the general ioctl mechanism
        //    failed: make our best guess as to what might have gone
        //    wrong based on errno value.
        if ret == -1 && unsafe { *libc::___errno() } != libc::ENOBUFS {
            // Anytime a response is present it will have more context
            // for the error. Otherwise, we have to approximate the
            // error via errno.
            if let Some(cmd_err) = rioctl.cmd_err_resp() {
                return Err(Error::CommandError(cmd, cmd_err));
            }

            let msg = match unsafe { *libc::___errno() } {
                libc::EPROTO => "API version mismatch".to_string(),

                libc::EFAULT => "failed to copyin/copyout req/resp".to_string(),

                libc::ENOMSG => {
                    "opte driver failed to deser/ser req/resp".to_string()
                }

                libc::EPERM => "permission denied".to_string(),

                errno => {
                    format!("unexpected errno: {}", errno)
                }
            };

            return Err(Error::IoctlFailed(cmd, msg));
        }

        // Check for successful response, try to deserialize it
        assert!(rioctl.resp_len_actual != 0);
        if ret == 0 && rioctl.resp_len_actual <= rioctl.resp_len {
            let response = unsafe {
                std::slice::from_raw_parts(
                    rioctl.resp_bytes,
                    rioctl.resp_len_actual,
                )
            };
            return postcard::from_bytes(response)
                .map_err(|e| Error::RespDeser(cmd, e));
        }

        // The buffer wasn't large enough to hold the response.
        // Enlarge the buffer by asking for more capacity and
        // initializing it so that it is usable.
        resp_buf.resize(rioctl.resp_len_actual, 0);
        rioctl.resp_bytes = resp_buf.as_mut_ptr();
        rioctl.resp_len = resp_buf.len();
        rioctl.resp_len_actual = 0;
    }

    Err(Error::MaxAttempts(cmd, MAX_ITERATIONS))
}

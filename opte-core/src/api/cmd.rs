use illumos_sys_hdrs::{c_int, size_t};
use serde::{Deserialize, Serialize};
use super::API_VERSION;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::String;
    } else {
        use std::string::String;
    }
}

// TODO These two constants belong in xde, not here.
pub const XDE_DLD_PREFIX: i32 = (0xde00u32 << 16) as i32;
pub const XDE_DLD_OPTE_CMD: i32 = XDE_DLD_PREFIX | 7777;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum OpteCmd {
    ListPorts = 1,           // list all ports
    AddFwRule = 20,          // add firewall rule
    RemFwRule = 21,          // remove firewall rule
    DumpTcpFlows = 30,       // dump TCP flows
    DumpLayer = 31,          // dump the specified Layer
    DumpUft = 32,            // dump the Unified Flow Table
    ListLayers = 33,         // list the layers on a given port
    ClearUft = 40,           // clear the UFT
    SetVirt2Phys = 50,       // set a v2p mapping
    DumpVirt2Phys = 51,      // dump the v2p mappings
    AddRouterEntryIpv4 = 60, // add a router entry for IPv4 dest
    CreateXde = 70,          // create a new xde device
    DeleteXde = 71,          // delete an xde device
    SetXdeUnderlay = 72,     // set xde underlay devices
}

impl TryFrom<c_int> for OpteCmd {
    type Error = ();

    fn try_from(num: c_int) -> Result<Self, Self::Error> {
        match num {
            1 => Ok(Self::ListPorts),
            20 => Ok(Self::AddFwRule),
            21 => Ok(Self::RemFwRule),
            30 => Ok(Self::DumpTcpFlows),
            31 => Ok(Self::DumpLayer),
            32 => Ok(Self::DumpUft),
            33 => Ok(Self::ListLayers),
            40 => Ok(Self::ClearUft),
            50 => Ok(Self::SetVirt2Phys),
            51 => Ok(Self::DumpVirt2Phys),
            60 => Ok(Self::AddRouterEntryIpv4),
            70 => Ok(Self::CreateXde),
            71 => Ok(Self::DeleteXde),
            72 => Ok(Self::SetXdeUnderlay),
            _ => Err(()),
        }
    }
}

/// Indicates that a command response has been written to the response
/// buffer (`resp_bytes`).
pub const OPTE_CMD_RESP_COPY_OUT: u64 = 0x1;

/// The `ioctl(2)` argument passed when sending an `OpteCmd`.
///
/// We need `repr(C)` for a stable layout across compilations. This is
/// a generic structure used to carry the various commands; the
/// command's actual request/response data is serialized/deserialized
/// by serde into the user supplied pointers in
/// `req_bytes`/`resp_bytes`. In the future, if we need this to work
/// with non-Rust programs in illumos, we could write an nvlist
/// provider that works with serde.
#[derive(Debug)]
#[repr(C)]
pub struct OpteCmdIoctl {
    pub api_version: u64,
    pub cmd: OpteCmd,
    pub flags: u64,
    // Reserve some additional bytes in case we need them in the
    // future.
    pub reserved1: u64,
    pub req_bytes: *const u8,
    pub req_len: size_t,
    pub resp_bytes: *mut u8,
    pub resp_len: size_t,
    pub resp_len_actual: size_t,
}

impl OpteCmdIoctl {
    pub fn cmd_err_resp(&self) -> Option<OpteError> {
        if self.has_cmd_resp() {
            // Safety: We know the resp_bytes point to a Vec and that
            // resp_len_actual is within range.
            let resp = unsafe {
                core::slice::from_raw_parts(
                    self.resp_bytes,
                    self.resp_len_actual,
                )
            };

            match postcard::from_bytes(resp) {
                Ok(cmd_err) => Some(cmd_err),
                Err(deser_err) => {
                    Some(OpteError::DeserCmdErr(format!("{}", deser_err)))
                }
            }
        } else {
            None
        }
    }

    fn has_cmd_resp(&self) -> bool {
        (self.flags & OPTE_CMD_RESP_COPY_OUT) != 0
    }
}

impl OpteCmdIoctl {
    /// Is this the expected API version?
    ///
    /// NOTE: This function is compiled twice: once for the userland
    /// client, again for the kernel driver. As long as we remember to
    /// update the `API_VERSION` value when making API changes, this
    /// method will return `false` when user and kernel disagree.
    pub fn check_version(&self) -> bool {
        self.api_version == API_VERSION
    }
}

// cfg_if! {
//     if #[cfg(all(target_os = "illumos", feature = "std"))] {
//         use super::encap::Vni;
//         use super::mac::MacAddr;
//         use super::oxide_vpc::*;
//         use std::fs::{File, OpenOptions};
//         use std::os::unix::io::AsRawFd;
//         use libc;
//         use serde::de::DeserializeOwned;
//         // use thiserror::Error;
//     }
// }

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum OpteError {
    BadApiVersion { user: u64, kernel: u64 },
    BadLayerPos { layer: String, pos: String },
    BadName,
    CopyinReq,
    CopyoutResp,
    DeserCmdErr(String),
    DeserCmdReq(String),
    FlowExists(String),
    InvalidRouteDest(String),
    LayerNotFound(String),
    MaxCapacity(u64),
    PortNotFound(String),
    RespTooLarge { needed: usize, given: usize },
    RuleNotFound(u64),
    SerCmdErr(String),
    SerCmdResp(String),
    System { errno: c_int, msg: String },
}

impl OpteError {
    /// Convert to an errno value.
    ///
    /// NOTE: In order for `run_cmd_ioctl()` to function correctly
    /// only `RespTooLarge` may use `ENOBUFS`.
    ///
    /// XXX We should probably add the extra code necessary to enforce
    /// this constraint at compile time.
    pub fn to_errno(&self) -> c_int {
        use illumos_sys_hdrs::*;

        match self {
            Self::BadApiVersion { .. } => EPROTO,
            Self::BadLayerPos { .. } => EINVAL,
            Self::BadName => EINVAL,
            Self::CopyinReq => EFAULT,
            Self::CopyoutResp => EFAULT,
            Self::DeserCmdErr(_) => ENOMSG,
            Self::DeserCmdReq(_) => ENOMSG,
            Self::FlowExists(_) => EEXIST,
            Self::InvalidRouteDest(_) => EINVAL,
            Self::LayerNotFound(_) => ENOENT,
            Self::MaxCapacity(_) => ENFILE,
            Self::PortNotFound(_) => ENOENT,
            Self::RespTooLarge { .. } => ENOBUFS,
            Self::RuleNotFound(_) => ENOENT,
            Self::SerCmdErr(_) => ENOMSG,
            Self::SerCmdResp(_) => ENOMSG,
            Self::System { errno, .. } => *errno,
        }
    }
}

/// A marker trait indicating a success response type that is returned
/// from a command and may be passed across the ioctl/API boundary.
pub trait CmdOk: core::fmt::Debug + Serialize {}

impl CmdOk for () {}

/// Indicates no meaningful response value on success.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct NoResp {
    pub unused: u64,
}

impl CmdOk for NoResp {}

// #[derive(Debug, Error)]
// #[cfg(all(target_os = "illumos", feature = "user"))]
// pub enum Error {
//     #[error("OPTE driver is not attached")]
//     DriverNotAttached,

//     #[error("error interacting with device: {0}")]
//     Io(std::io::Error),

//     /// Something in the opte ioctl(2) handler failed.
//     #[error("ioctl {0:?} failed: {1}")]
//     IoctlFailed(OpteCmd, String),

//     #[error("invalid argument {0}")]
//     InvalidArgument(String),

//     #[error("netadm failed {0}")]
//     NetadmFailed(libnet::Error),

//     #[error("request serialization failed for command {0:?}: {1}")]
//     ReqSer(OpteCmd, postcard::Error),

//     #[error("response deserialization failed for command {0:?}: {1}")]
//     RespDeser(OpteCmd, postcard::Error),

//     #[error("failed to get response for command {0:?} in {1} attempts")]
//     MaxAttempts(OpteCmd, u8),

//     #[error("command {0:?} failed: {1:?}")]
//     CommandError(OpteCmd, OpteError),
// }

// #[cfg(all(target_os = "illumos", feature = "user"))]
// impl From<std::io::Error> for Error {
//     fn from(e: std::io::Error) -> Self {
//         match e.kind() {
//             std::io::ErrorKind::NotFound => Error::DriverNotAttached,
//             _ => Error::Io(e),
//         }
//     }
// }

// #[cfg(all(target_os = "illumos", feature = "user"))]
// impl From<libnet::Error> for Error {
//     fn from(e: libnet::Error) -> Self {
//         Self::NetadmFailed(e)
//     }
// }

// /// The handle used to send administration commands to OPTE.
// #[derive(Debug)]
// #[cfg(all(target_os = "illumos", feature = "user"))]
// pub struct OpteHdl {
//     device: File,
// }

// #[cfg(all(target_os = "illumos", feature = "user"))]
// impl OpteHdl {
//     pub const DLD_CTL: &'static str = "/dev/dld";

//     /// Add xde device
//     pub fn create_xde(
//         &self,
//         name: &str,
//         private_mac: MacAddr,
//         private_ip: std::net::Ipv4Addr,
//         gw_mac: MacAddr,
//         gw_ip: std::net::Ipv4Addr,
//         bsvc_addr: std::net::Ipv6Addr,
//         bsvc_vni: Vni,
//         vpc_vni: Vni,
//         src_underlay_addr: std::net::Ipv6Addr,
//         passthrough: bool,
//     ) -> Result<NoResp, Error> {
//         let linkid = libnet::link::create_link_id(
//             name,
//             libnet::LinkClass::Xde,
//             libnet::LinkFlags::Active,
//         )?;

//         let xde_devname = name.into();
//         let cmd = OpteCmd::CreateXde;
//         let req = CreateXdeReq {
//             xde_devname,
//             linkid,
//             private_mac,
//             private_ip: private_ip.into(),
//             gw_mac,
//             gw_ip: gw_ip.into(),
//             bsvc_addr: bsvc_addr.into(),
//             bsvc_vni,
//             vpc_vni,
//             src_underlay_addr: src_underlay_addr.into(),
//             passthrough,
//         };

//         run_cmd_ioctl(self.device.as_raw_fd(), cmd, &req)
//     }

//     /// Delete xde device
//     pub fn delete_xde(&self, name: &str) -> Result<NoResp, Error> {
//         let link_id = libnet::LinkHandle::Name(name.into()).id()?;
//         let req = DeleteXdeReq { xde_devname: name.into() };
//         let cmd = OpteCmd::DeleteXde;
//         let resp = run_cmd_ioctl(self.device.as_raw_fd(), cmd, &req)?;
//         libnet::link::delete_link_id(link_id, libnet::LinkFlags::Active)?;
//         Ok(resp)
//     }

//     /// Create a new handle to the OPTE control node.
//     pub fn open(what: &str) -> Result<Self, Error> {
//         Ok(OpteHdl {
//             device: OpenOptions::new().read(true).write(true).open(what)?,
//         })
//     }

//     pub fn set_v2p(&self, req: &SetVirt2PhysReq) -> Result<NoResp, Error> {
//         let cmd = OpteCmd::SetVirt2Phys;
//         run_cmd_ioctl(self.device.as_raw_fd(), cmd, &req)
//     }

//     pub fn add_router_entry_ip4(
//         &self,
//         req: &AddRouterEntryIpv4Req,
//     ) -> Result<NoResp, Error> {
//         let cmd = OpteCmd::AddRouterEntryIpv4;
//         run_cmd_ioctl(self.device.as_raw_fd(), cmd, &req)
//     }
// }

// #[cfg(all(target_os = "illumos", feature = "user"))]
// pub fn run_cmd_ioctl<T, R>(
//     dev: libc::c_int,
//     cmd: OpteCmd,
//     req: &R,
// ) -> Result<T, Error>
// where
//     T: CmdOk + DeserializeOwned,
//     R: Serialize,
// {
//     use std::string::ToString;
//     use std::vec::Vec;

//     let req_bytes =
//         postcard::to_allocvec(req).map_err(|e| Error::ReqSer(cmd, e))?;

//     // It would be a shame if the command failed and we didn't have
//     // enough bytes to serialize the error response, so we set this to
//     // default to 16 KiB.
//     let mut resp_buf: Vec<u8> = vec![0; 16 * 1024];
//     let mut rioctl = OpteCmdIoctl {
//         api_version: API_VERSION,
//         cmd,
//         flags: 0,
//         reserved1: 0,
//         req_bytes: req_bytes.as_ptr(),
//         req_len: req_bytes.len(),
//         resp_bytes: resp_buf.as_mut_ptr(),
//         resp_len: resp_buf.len(),
//         resp_len_actual: 0,
//     };

//     const MAX_ITERATIONS: u8 = 3;
//     for _ in 0..MAX_ITERATIONS {
//         let ret = unsafe {
//             libc::ioctl(dev, XDE_DLD_OPTE_CMD as libc::c_int, &rioctl)
//         };

//         // The ioctl(2) failed for a reason other than the response
//         // buffer being too small.
//         //
//         // errno == ENOBUFS
//         //
//         //    The command ran successfully, but there is not enough
//         //    space to copyout(9F) the response. In this case bump
//         //    up the size of the response buffer and retry.
//         //
//         // errno != 0 && OPTE_CMD_RESP_COPY_OUT
//         //
//         //    The command failed and we have an error response
//         //    serialized in the response buffer.
//         //
//         // errno != 0
//         //
//         //    Either the command failed or the general ioctl mechanism
//         //    failed: make our best guess as to what might have gone
//         //    wrong based on errno value.
//         if ret == -1 && unsafe { *libc::___errno() } != libc::ENOBUFS {
//             // Anytime a response is present it will have more context
//             // for the error. Otherwise, we have to approximate the
//             // error via errno.
//             if let Some(cmd_err) = rioctl.cmd_err_resp() {
//                 return Err(Error::CommandError(cmd, cmd_err));
//             }

//             let msg = match unsafe { *libc::___errno() } {
//                 libc::EPROTO => "API version mismatch".to_string(),

//                 libc::EFAULT => "failed to copyin/copyout req/resp".to_string(),

//                 libc::ENOMSG => {
//                     "opte driver failed to deser/ser req/resp".to_string()
//                 }

//                 errno => {
//                     format!("unexpected errno: {}", errno)
//                 }
//             };

//             return Err(Error::IoctlFailed(cmd, msg));
//         }

//         // Check for successful response, try to deserialize it
//         assert!(rioctl.resp_len_actual != 0);
//         if ret == 0 && rioctl.resp_len_actual <= rioctl.resp_len {
//             let response = unsafe {
//                 std::slice::from_raw_parts(
//                     rioctl.resp_bytes,
//                     rioctl.resp_len_actual,
//                 )
//             };
//             return postcard::from_bytes(response)
//                 .map_err(|e| Error::RespDeser(cmd, e));
//         }

//         // The buffer wasn't large enough to hold the response.
//         // Enlarge the buffer by asking for more capacity and
//         // initializing it so that it is usable.
//         resp_buf.resize(rioctl.resp_len_actual, 0);
//         rioctl.resp_bytes = resp_buf.as_mut_ptr();
//         rioctl.resp_len = resp_buf.len();
//         rioctl.resp_len_actual = 0;
//     }

//     Err(Error::MaxAttempts(cmd, MAX_ITERATIONS))
// }

//! OPTE driver administration library
// Copyright 2021 Oxide Computer Company

use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;

// use libc;
// use serde::{de::DeserializeOwned, Serialize};
// use thiserror::Error;

use opte_core::api::{
    AddRouterEntryIpv4Req, CreateXdeReq, DeleteXdeReq,
    MacAddr, NoResp, OpteCmd, SetVirt2PhysReq, Vni,
};
use opte_core::ioctl::{self as api, SetXdeUnderlayReq};
use opte_core::oxide_net::firewall::{
    AddFwRuleReq, FirewallRule, RemFwRuleReq,
};
use opte_core::oxide_net::overlay;
use opte_ioctl::{Error, run_cmd_ioctl};

/// Errors related to administering the OPTE driver.
// #[derive(Debug, Error)]
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

// impl From<std::io::Error> for Error {
//     fn from(e: std::io::Error) -> Self {
//         match e.kind() {
//             std::io::ErrorKind::NotFound => Error::DriverNotAttached,
//             _ => Error::Io(e),
//         }
//     }
// }

// impl From<libnet::Error> for Error {
//     fn from(e: libnet::Error) -> Self {
//         Self::NetadmFailed(e)
//     }
// }

/// The handle used to send administration commands to the OPTE
/// control node.
#[derive(Debug)]
pub struct OpteAdm {
    device: File,
}

impl OpteAdm {
    pub const DLD_CTL: &'static str = "/dev/dld";

    /// Add xde device
    pub fn create_xde(
        &self,
        name: &str,
        private_mac: MacAddr,
        private_ip: std::net::Ipv4Addr,
        gw_mac: MacAddr,
        gw_ip: std::net::Ipv4Addr,
        bsvc_addr: std::net::Ipv6Addr,
        bsvc_vni: Vni,
        vpc_vni: Vni,
        src_underlay_addr: std::net::Ipv6Addr,
        passthrough: bool,
    ) -> Result<NoResp, Error> {
        let linkid = libnet::link::create_link_id(
            name,
            libnet::LinkClass::Xde,
            libnet::LinkFlags::Active,
        )?;

        let xde_devname = name.into();
        let cmd = OpteCmd::CreateXde;
        let req = CreateXdeReq {
            xde_devname,
            linkid,
            private_mac,
            private_ip: private_ip.into(),
            gw_mac,
            gw_ip: gw_ip.into(),
            bsvc_addr: bsvc_addr.into(),
            bsvc_vni,
            vpc_vni,
            src_underlay_addr: src_underlay_addr.into(),
            passthrough,
        };

        run_cmd_ioctl(self.device.as_raw_fd(), cmd, &req)
    }

    /// Delete xde device
    pub fn delete_xde(&self, name: &str) -> Result<NoResp, Error> {
        let link_id = libnet::LinkHandle::Name(name.into()).id()?;
        let req = DeleteXdeReq { xde_devname: name.into() };
        let cmd = OpteCmd::DeleteXde;
        let resp = run_cmd_ioctl(self.device.as_raw_fd(), cmd, &req)?;
        libnet::link::delete_link_id(link_id, libnet::LinkFlags::Active)?;
        Ok(resp)
    }

    /// Set xde underlay devices
    pub fn set_xde_underlay(
        &self,
        u1: &str,
        u2: &str,
    ) -> Result<NoResp, Error> {
        let req = SetXdeUnderlayReq { u1: u1.into(), u2: u2.into() };
        let cmd = OpteCmd::SetXdeUnderlay;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, &req)
    }

    /// Add a firewall rule
    pub fn add_firewall_rule(
        &self,
        port_name: &str,
        rule: &FirewallRule,
    ) -> Result<NoResp, Error> {
        let cmd = OpteCmd::AddFwRule;
        let req = AddFwRuleReq {
            port_name: port_name.to_string(),
            rule: rule.clone(),
        };
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, &req)
    }

    /// Return the contents of an OPTE layer.
    pub fn get_layer_by_name(
        &self,
        port_name: &str,
        name: &str,
    ) -> Result<api::DumpLayerResp, Error> {
        let cmd = OpteCmd::DumpLayer;
        let req = api::DumpLayerReq {
            port_name: port_name.to_string(),
            name: name.to_string(),
        };
        run_cmd_ioctl::<api::DumpLayerResp, _>(
            self.device.as_raw_fd(),
            cmd,
            &req,
        )
    }

    /// List all the ports.
    pub fn list_ports(&self) -> Result<api::ListPortsResp, Error> {
        let cmd = OpteCmd::ListPorts;
        run_cmd_ioctl::<api::ListPortsResp, _>(
            self.device.as_raw_fd(),
            cmd,
            &api::ListPortsReq { unused: () },
        )
    }

    pub fn list_layers(
        &self,
        port: &str,
    ) -> Result<api::ListLayersResp, Error> {
        let cmd = OpteCmd::ListLayers;
        run_cmd_ioctl::<api::ListLayersResp, _>(
            self.device.as_raw_fd(),
            cmd,
            &api::ListLayersReq { port_name: port.to_string() },
        )
    }

    /// Create a new handle to the OPTE control node.
    pub fn open(what: &str) -> Result<Self, Error> {
        Ok(OpteAdm {
            device: OpenOptions::new().read(true).write(true).open(what)?,
        })
    }

    /// Remove a firewall rule.
    pub fn remove_firewall_rule(
        &self,
        req: &RemFwRuleReq,
    ) -> Result<NoResp, Error> {
        let cmd = OpteCmd::RemFwRule;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, req)
    }

    /// Return the TCP flows.
    pub fn dump_tcp_flows(
        &self,
        port_name: &str,
    ) -> Result<api::DumpTcpFlowsResp, Error> {
        let cmd = OpteCmd::DumpTcpFlows;
        run_cmd_ioctl::<api::DumpTcpFlowsResp, _>(
            self.device.as_raw_fd(),
            cmd,
            &api::DumpTcpFlowsReq { port_name: port_name.to_string() },
        )
    }

    /// Clear all entries from the Unified Flow Table (UFT).
    pub fn clear_uft(&self, port_name: &str) -> Result<NoResp, Error> {
        let cmd = OpteCmd::ClearUft;
        run_cmd_ioctl(
            self.device.as_raw_fd(),
            cmd,
            &api::ClearUftReq { port_name: port_name.to_string() },
        )
    }

    /// Return the Unified Flow Table (UFT).
    pub fn dump_uft(&self, port_name: &str) -> Result<api::DumpUftResp, Error> {
        let cmd = OpteCmd::DumpUft;
        run_cmd_ioctl::<api::DumpUftResp, _>(
            self.device.as_raw_fd(),
            cmd,
            &api::DumpUftReq { port_name: port_name.to_string() },
        )
    }

    pub fn set_v2p(&self, req: &SetVirt2PhysReq) -> Result<NoResp, Error> {
        let cmd = OpteCmd::SetVirt2Phys;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, &req)
    }

    /// Dump the Virtual-to-Physical mappings.
    pub fn dump_v2p(&self) -> Result<overlay::DumpVirt2PhysResp, Error> {
        let cmd = OpteCmd::DumpVirt2Phys;
        run_cmd_ioctl::<overlay::DumpVirt2PhysResp, _>(
            self.device.as_raw_fd(),
            cmd,
            &overlay::DumpVirt2PhysReq { unused: 99 },
        )
    }

    pub fn add_router_entry_ip4(
        &self,
        req: &AddRouterEntryIpv4Req,
    ) -> Result<NoResp, Error> {
        let cmd = OpteCmd::AddRouterEntryIpv4;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, &req)
    }
}

// #[cfg(not(target_os = "illumos"))]
// fn run_cmd_ioctl<T, R>(
//     _dev: libc::c_int,
//     _cmd: OpteCmd,
//     _req: &R,
// ) -> Result<Result<T, E>, Error>
// where
//     T: CmdOk + DeserializeOwned,
//     R: Serialize,
// {
//     panic!("non-illumos system, your ioctl(2) is no good here");
// }

// #[cfg(target_os = "illumos")]
// fn run_cmd_ioctl<T, R>(
//     dev: libc::c_int,
//     cmd: OpteCmd,
//     req: &R,
// ) -> Result<T, Error>
// where
//     T: CmdOk + DeserializeOwned,
//     R: Serialize,
// {
//     let req_bytes =
//         postcard::to_allocvec(req).map_err(|e| Error::ReqSer(cmd, e))?;

//     // It would be a shame if the command failed and we didn't have
//     // enough bytes to serialize the error response, so we set this to
//     // default to 16 KiB.
//     let mut resp_buf: Vec<u8> = vec![0; 16 * 1024];
//     let mut rioctl = OpteCmdIoctl {
//         api_version: opte_core::api::API_VERSION,
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
//             libc::ioctl(
//                 dev,
//                 opte_core::api::XDE_DLD_OPTE_CMD as libc::c_int,
//                 &rioctl
//             )
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

//! OPTE driver administration library
// Copyright 2021 Oxide Computer Company

use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::slice;

use libc::{c_int, ioctl};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

use opte_core::oxide_net::firewall::{FirewallRule, FwAddRuleReq, FwRemRuleReq};
use opte_core::flow_table::FlowEntryDump;
use opte_core::ioctl::{
    CmdResp, Ioctl, IoctlCmd, ListPortsReq, ListPortsResp, RegisterPortReq,
    UnregisterPortReq
};
use opte_core::layer::{InnerFlowId, LayerDumpReq, LayerDumpResp};
use opte_core::port::{
    TcpFlowsDumpReq, TcpFlowsDumpResp, UftDumpReq, UftDumpResp,
};

/// Errors related to administering the OPTE driver.
#[derive(Debug, Error)]
pub enum Error {
    #[error("OPTE driver is not attached")]
    DriverNotAttached,

    #[error("error interacting with device: {0}")]
    Io(std::io::Error),

    #[error("error transferring data to/from driver: {0}")]
    Serdes(String),

    /// Something in the opte ioctl(2) handler failed.
    #[error("ioctl {0:?} failed: {1}")]
    IoctlFailed(IoctlCmd, String),

    #[error("command {0:?} failed: {1}")]
    CommandFailed(IoctlCmd, String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        match e.kind() {
            std::io::ErrorKind::NotFound => Error::DriverNotAttached,
            _ => Error::Io(e),
        }
    }
}

impl From<postcard::Error> for Error {
    fn from(e: postcard::Error) -> Error {
        Error::Serdes(e.to_string())
    }
}

/// The handle used to send administration commands to the OPTE
/// control node.
#[derive(Debug)]
pub struct OpteAdm {
    device: File,
}

impl OpteAdm {
    pub const OPTE_CTL: &'static str = "/devices/pseudo/opte@0:opte";

    /// Add a firewall rule
    pub fn add_firewall_rule(
        &self,
        port_name: &str,
        rule: &FirewallRule
    ) -> Result<(), Error> {
        let cmd = IoctlCmd::FwAddRule;
        let req = FwAddRuleReq {
            port_name: port_name.to_string(),
            rule: rule.clone()
        };
        let resp = run_ioctl(self.device.as_raw_fd(), cmd, &req)?;
        resp.map_err(|msg| Error::CommandFailed(cmd, msg))
    }

    /// Return the contents of an OPTE layer
    pub fn get_layer_by_name(
        &self,
        port_name: &str,
        name: &str,
    ) -> Result<LayerDumpResp, Error> {
        let cmd = IoctlCmd::LayerDump;
        let req = LayerDumpReq {
            port_name: port_name.to_string(),
            name: name.to_string()
        };
        let resp = run_ioctl(self.device.as_raw_fd(), cmd, &req)?;
        resp.map_err(|msg| Error::CommandFailed(cmd, msg))
    }

    /// List all ports registered with the OPTE control node.
    pub fn list_ports(&self) -> Result<ListPortsResp, Error> {
        let cmd = IoctlCmd::ListPorts;
        let resp = run_ioctl(
            self.device.as_raw_fd(),
            cmd,
            &ListPortsReq { unused: () }
        )?;
        resp.map_err(|msg| Error::CommandFailed(cmd, msg))
    }

    /// Create a new handle to the OPTE control node.
    pub fn open() -> Result<Self, Error> {
        Ok(OpteAdm {
            device: OpenOptions::new()
                .read(true)
                .write(true)
                .open(Self::OPTE_CTL)?,
        })
    }

    pub fn register_port(&self, req: &RegisterPortReq) -> Result<(), Error> {
        let cmd = IoctlCmd::RegisterPort;
        let resp = run_ioctl(self.device.as_raw_fd(), cmd, req)?;
        resp.map_err(|msg| Error::CommandFailed(cmd, msg))
    }

    /// Remove a firewall rule
    pub fn remove_firewall_rule(
        &self,
        req: &FwRemRuleReq,
    ) -> Result<(), Error> {
        let cmd = IoctlCmd::FwRemRule;
        let resp = run_ioctl(self.device.as_raw_fd(), cmd, req)?;
        resp.map_err(|msg| Error::CommandFailed(cmd, msg))
    }

    /// Return the TCP flows
    pub fn tcp_flows(
        &self,
        port_name: &str,
    ) -> Result<Vec<(InnerFlowId, FlowEntryDump)>, Error> {
        let cmd = IoctlCmd::TcpFlowsDump;
        let resp: CmdResp<TcpFlowsDumpResp> = run_ioctl(
            self.device.as_raw_fd(),
            cmd,
            &TcpFlowsDumpReq { port_name: port_name.to_string() },
        )?;
        resp.map(|r| r.flows).map_err(|msg| Error::CommandFailed(cmd, msg))
    }

    /// Return the unified flow table (UFT)
    pub fn uft(&self, port_name: &str) -> Result<UftDumpResp, Error> {
        let cmd = IoctlCmd::UftDump;
        let resp = run_ioctl(
            self.device.as_raw_fd(),
            cmd,
            &UftDumpReq { port_name: port_name.to_string() }
        )?;
        resp.map_err(|msg| Error::CommandFailed(cmd, msg))
    }

    pub fn unregister_port(&self, name: &str) -> Result<(), Error> {
        let cmd = IoctlCmd::UnregisterPort;
        let req = UnregisterPortReq { name: name.to_string() };
        let resp = run_ioctl(self.device.as_raw_fd(), cmd, &req)?;
        resp.map_err(|msg| Error::CommandFailed(cmd, msg))
    }
}

fn run_ioctl<R, P>(
    dev: c_int,
    cmd: IoctlCmd,
    req: &R
) -> Result<CmdResp<P>, Error>
where
    R: Serialize,
    P: DeserializeOwned,
{
    let req_bytes = postcard::to_allocvec(req).unwrap();
    let mut resp_buf: Vec<u8> = vec![0; 1024];
    let mut rioctl = Ioctl {
        req_bytes: req_bytes.as_ptr(),
        req_len: req_bytes.len(),
        resp_bytes: resp_buf.as_mut_ptr(),
        resp_len: resp_buf.len(),
        resp_len_needed: 0,
    };

    const MAX_ITERATIONS: usize = 3;
    for _ in 0..MAX_ITERATIONS {
        let ret = unsafe { ioctl(dev, cmd as c_int, &rioctl) };

        // The ioctl(2) failed for a reason other than the response
        // buffer being too small.
        if ret == -1 && unsafe { *libc::___errno() } != libc::ENOBUFS {
            let msg = match unsafe { *libc::___errno() } {
                // This should never really happen. It indicates a
                // mismatch between the minor number of the device
                // node used to send the ioctl and the key used in the
                // opte driver's `clients` map.
                libc::ENOENT => {
                    "port not found".to_string()
                }

                libc::EFAULT => {
                    "opte driver failed to copyin/copyout req/resp".to_string()
                }

                libc::EINVAL => {
                    "opte driver failed to deserialize request".to_string()
                }

                errno => {
                    format!("errno: {}", errno)
                }
            };

            return Err(Error::IoctlFailed(cmd, msg));
        }

        // Check for successful response, try to deserialize it
        assert!(rioctl.resp_len_needed != 0);
        if rioctl.resp_len_needed <= rioctl.resp_len {
            let response = unsafe {
                slice::from_raw_parts(rioctl.resp_bytes, rioctl.resp_len_needed)
            };
            return postcard::from_bytes(response).map_err(Error::from);
        }

        // The buffer wasn't large enough to hold the response.
        // Enlarge the buffer by asking for more capacity and
        // initializing it so that it is usable.
        resp_buf.resize(rioctl.resp_len_needed, 0);
        rioctl.resp_bytes = resp_buf.as_mut_ptr();
        rioctl.resp_len = resp_buf.len();
        rioctl.resp_len_needed = 0;
    }

    panic!(
        "failed to allocate sufficient ioctl(2) response \
            buffer in {} iterations",
        MAX_ITERATIONS
    );
}

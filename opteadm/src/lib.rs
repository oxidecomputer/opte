//! OPTE driver administration library
// Copyright 2021 Oxide Computer Company

use std::fs::{File, OpenOptions};
use std::str::FromStr;
use std::os::unix::io::AsRawFd;

use libc;
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

use opte_core::ioctl::{
    self as api, AddPortReq, CmdErr, CmdOk, DeletePortReq, IoctlCmd, 
    CreateXdeReq, DeleteXdeReq,
};
use opte_core::oxide_net::firewall::{
    FirewallRule, FwAddRuleReq, FwRemRuleReq,
};
use opte_core::oxide_net::overlay::{self, SetOverlayReq, SetVirt2PhysReq};
use opte_core::oxide_net::router;
use opte_core::ip6::Ipv6Addr;
use opte_core::ip4::Ipv4Addr;
use opte_core::ether::EtherAddr;
use opte_core::geneve::Vni;

/// Errors related to administering the OPTE driver.
#[derive(Debug, Error)]
pub enum Error {
    #[error("OPTE driver is not attached")]
    DriverNotAttached,

    #[error("error interacting with device: {0}")]
    Io(std::io::Error),

    #[error("error with serdes: {0}")]
    Serdes(String),

    /// Something in the opte ioctl(2) handler failed.
    #[error("ioctl {0:?} failed: {1}")]
    IoctlFailed(IoctlCmd, String),

    #[error("command {0:?} failed: {1}")]
    CommandFailed(IoctlCmd, String),

    #[error("invalid argument {0}")]
    InvalidArgument(String),

    #[error("netadm failed {0}")]
    NetadmFailed(libnet::Error)
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
    //XXX remove this when xde marges into opte-drv
    pub const XDE_CTL: &'static str = "/devices/pseudo/xde@0:xde";

    /// Add xde device
    pub fn create_xde(
        &self,
        name: &str,
        private_mac: &str,
        private_ip: &str,
        gw_mac: &str,
        gw_ip: &str,
        boundary_services_addr: std::net::Ipv6Addr,
        boundary_services_vni: Vni,
        vpc_vni: Vni,
        src_underlay_addr: std::net::Ipv6Addr,
        passthrough: bool
    ) -> Result<(), Error> {

        let linkid = libnet::link::create_link_id(
            name,
            libnet::LinkClass::Xde,
            libnet::LinkFlags::Active,
        ).map_err(|e| Error::NetadmFailed(e))?;

        let private_mac = EtherAddr::from_str(private_mac)
            .map_err(|e| Error::InvalidArgument(e))?;

        let gw_mac = EtherAddr::from_str(gw_mac)
            .map_err(|e| Error::InvalidArgument(e))?;

        let private_ip = Ipv4Addr::from_str(private_ip)
            .map_err(|e| Error::InvalidArgument(e.to_string()))?;

        let gw_ip = Ipv4Addr::from_str(gw_ip)
            .map_err(|e| Error::InvalidArgument(e.to_string()))?;

        let xde_devname = name.into();
        let boundary_services_addr = Ipv6Addr::from(boundary_services_addr.octets());
        let src_underlay_addr = Ipv6Addr::from(src_underlay_addr.octets());

        let cmd = IoctlCmd::XdeCreate;
        let req = CreateXdeReq {
            xde_devname,
            linkid,
            private_mac,
            private_ip,
            gw_mac,
            gw_ip,
            boundary_services_addr,
            boundary_services_vni,
            vpc_vni,
            src_underlay_addr,
            passthrough,
            .. Default::default()
        };

        let resp = run_ioctl::<(), api::XdeError, _>(
            self.device.as_raw_fd(),
            cmd,
            &req
        )?;
        resp.map_err(|e| Error::CommandFailed(cmd, format!("{:?}", e)))

    }

    /// Delete xde device
    pub fn delete_xde(&self, name: &str) -> Result<(), Error> {

        let link_id = libnet::LinkHandle::Name(name.into())
            .id()
            .expect("get link id");

        let req = DeleteXdeReq{ xde_devname: name.into() };
        let cmd = IoctlCmd::XdeDelete;
        let resp = run_ioctl::<(), api::XdeError, _>(
            self.device.as_raw_fd(),
            cmd,
            &req
        )?;

        libnet::link::delete_link_id(link_id, libnet::LinkFlags::Active)
            .expect("delete link id");

        resp.map_err(|e| Error::CommandFailed(cmd, format!("{:?}", e)))
    }

    /// Add a firewall rule
    pub fn add_firewall_rule(
        &self,
        port_name: &str,
        rule: &FirewallRule,
    ) -> Result<(), Error> {
        let cmd = IoctlCmd::FwAddRule;
        let req = FwAddRuleReq {
            port_name: port_name.to_string(),
            rule: rule.clone(),
        };
        let resp = run_ioctl::<(), api::AddFwRuleError, _>(
            self.device.as_raw_fd(),
            cmd,
            &req,
        )?;
        resp.map_err(|e| Error::CommandFailed(cmd, format!("{:?}", e)))
    }

    /// Return the contents of an OPTE layer.
    pub fn get_layer_by_name(
        &self,
        port_name: &str,
        name: &str,
    ) -> Result<api::DumpLayerResp, Error> {
        let cmd = IoctlCmd::DumpLayer;
        let req = api::DumpLayerReq {
            port_name: port_name.to_string(),
            name: name.to_string(),
        };
        let resp = run_ioctl::<api::DumpLayerResp, api::DumpLayerError, _>(
            self.device.as_raw_fd(),
            cmd,
            &req,
        )?;
        resp.map_err(|e| Error::CommandFailed(cmd, format!("{:?}", e)))
    }

    /// List all the ports.
    pub fn list_ports(&self) -> Result<api::ListPortsResp, Error> {
        let cmd = IoctlCmd::ListPorts;
        let resp = run_ioctl::<api::ListPortsResp, (), _>(
            self.device.as_raw_fd(),
            cmd,
            &api::ListPortsReq { unused: () },
        )?;
        resp.map_err(|e| Error::CommandFailed(cmd, format!("{:?}", e)))
    }

    pub fn list_layers(
        &self,
        port: &str,
    ) -> Result<api::ListLayersResp, Error> {
        let cmd = IoctlCmd::ListLayers;
        let resp = run_ioctl::<api::ListLayersResp, (), _>(
            self.device.as_raw_fd(),
            cmd,
            &api::ListLayersReq { port_name: port.to_string() },
        )?;
        resp.map_err(|e| Error::CommandFailed(cmd, format!("{:?}", e)))
    }

    /// Create a new handle to the OPTE control node.
    pub fn open(what: &str) -> Result<Self, Error> {
        Ok(OpteAdm {
            device: OpenOptions::new()
                .read(true)
                .write(true)
                .open(what)?
        })
    }

    /// Add a new port.
    pub fn add_port(&self, req: &AddPortReq) -> Result<(), Error> {
        let cmd = IoctlCmd::AddPort;
        let resp = run_ioctl::<(), api::AddPortError, _>(
            self.device.as_raw_fd(),
            cmd,
            req,
        )?;
        resp.map_err(|e| Error::CommandFailed(cmd, format!("{:?}", e)))
    }

    pub fn set_overlay(&self, req: &SetOverlayReq) -> Result<(), Error> {
        let cmd = IoctlCmd::SetOverlay;
        let resp = run_ioctl::<(), overlay::SetOverlayError, _>(
            self.device.as_raw_fd(),
            cmd,
            req,
        )?;
        resp.map_err(|e| Error::CommandFailed(cmd, format!("{:?}", e)))
    }

    /// Remove a firewall rule.
    pub fn remove_firewall_rule(
        &self,
        req: &FwRemRuleReq,
    ) -> Result<(), Error> {
        let cmd = IoctlCmd::FwRemRule;
        let resp = run_ioctl::<(), api::RemFwRuleError, _>(
            self.device.as_raw_fd(),
            cmd,
            req,
        )?;
        resp.map_err(|e| Error::CommandFailed(cmd, format!("{:?}", e)))
    }

    /// Return the TCP flows.
    pub fn tcp_flows(
        &self,
        port_name: &str,
    ) -> Result<api::DumpTcpFlowsResp, Error> {
        let cmd = IoctlCmd::DumpTcpFlows;
        let resp = run_ioctl::<api::DumpTcpFlowsResp, api::DumpTcpFlowsError, _>(
            self.device.as_raw_fd(),
            cmd,
            &api::DumpTcpFlowsReq { port_name: port_name.to_string() },
        )?;
        resp.map_err(|e| Error::CommandFailed(cmd, format!("{:?}", e)))
    }

    /// Return the unified flow table (UFT).
    pub fn uft(&self, port_name: &str) -> Result<api::DumpUftResp, Error> {
        let cmd = IoctlCmd::DumpUft;
        let resp = run_ioctl::<api::DumpUftResp, api::DumpUftError, _>(
            self.device.as_raw_fd(),
            cmd,
            &api::DumpUftReq { port_name: port_name.to_string() },
        )?;
        resp.map_err(|e| Error::CommandFailed(cmd, format!("{:?}", e)))
    }

    /// Delete a port.
    pub fn delete_port(&self, name: &str) -> Result<(), Error> {
        let cmd = IoctlCmd::DeletePort;
        let req = DeletePortReq { name: name.to_string() };
        let resp = run_ioctl::<(), api::DeletePortError, _>(
            self.device.as_raw_fd(),
            cmd,
            &req,
        )?;
        resp.map_err(|e| Error::CommandFailed(cmd, format!("{:?}", e)))
    }

    pub fn set_v2p(&self, req: &SetVirt2PhysReq) -> Result<(), Error> {
        let cmd = IoctlCmd::SetVirt2Phys;
        let resp = run_ioctl::<(), (), _>(self.device.as_raw_fd(), cmd, &req)?;
        resp.map_err(|e| Error::CommandFailed(cmd, format!("{:?}", e)))
    }

    pub fn get_v2p(
        &self,
    ) -> Result<overlay::GetVirt2PhysResp, Error> {
        let cmd = IoctlCmd::GetVirt2Phys;
        let resp = run_ioctl::<overlay::GetVirt2PhysResp, (), _>(
            self.device.as_raw_fd(),
            cmd,
            &overlay::GetVirt2PhysReq { unused: () }
        )?;
        resp.map_err(|e| Error::CommandFailed(cmd, format!("{:?}", e)))
    }

    pub fn add_router_entry_ip4(
        &self,
        req: &router::AddRouterEntryIpv4Req,
    ) -> Result<(), Error> {
        let cmd = IoctlCmd::AddRouterEntryIpv4;
        let resp = run_ioctl::<(), router::AddEntryError, _>(
            self.device.as_raw_fd(),
            cmd,
            &req,
        )?;
        resp.map_err(|e| Error::CommandFailed(cmd, format!("{:?}", e)))
    }
}

#[cfg(not(target_os = "illumos"))]
fn run_ioctl<T, E, R>(
    _dev: libc::c_int,
    _cmd: IoctlCmd,
    _req: &R,
) -> Result<Result<T, E>, Error>
where
    T: CmdOk + DeserializeOwned,
    E: CmdErr + DeserializeOwned,
    R: Serialize,
{
    panic!("non-illumos system, your ioctl(2) is no good here");
}

// An ioctl is going to return in one of two ways:
//
// 1. success: errno == 0 and we have a command response (Ok or Err)
// to deser.
//
// 2. system failure: errno != 0, there is no command response.
//
// This requires a nested Result. The outer Result indicates a command
// response vs. system error with the ioctl machinery. If the outer
// result is Ok, the inner Result indicates whether the command ran
// successfully or not. This allows us to give more detailed error
// response to a failed command instead of trying to map everything to
// a Unix errno.
#[cfg(target_os = "illumos")]
fn run_ioctl<T, E, R>(
    dev: libc::c_int,
    cmd: IoctlCmd,
    req: &R,
) -> Result<Result<T, E>, Error>
where
    T: CmdOk + DeserializeOwned,
    E: CmdErr + DeserializeOwned,
    R: Serialize,
{
    let req_bytes = postcard::to_allocvec(req).unwrap();
    // It would be a shame if the command failed and we didn't have
    // enough bytes to serialize the error response, so we set this to
    // default to 16 KiB.
    let mut resp_buf: Vec<u8> = vec![0; 16 * 1024];
    let mut rioctl = opte_core::ioctl::Ioctl {
        req_bytes: req_bytes.as_ptr(),
        req_len: req_bytes.len(),
        resp_bytes: resp_buf.as_mut_ptr(),
        resp_len: resp_buf.len(),
        resp_len_needed: 0,
    };

    const MAX_ITERATIONS: usize = 3;
    for _ in 0..MAX_ITERATIONS {
        let ret = unsafe { libc::ioctl(dev, cmd as libc::c_int, &rioctl) };

        // The ioctl(2) failed for a reason other than the response
        // buffer being too small.
        if ret == -1 && unsafe { *libc::___errno() } != libc::ENOBUFS {
            let msg = match unsafe { *libc::___errno() } {
                libc::ENOENT => "port not found".to_string(),

                libc::EFAULT => {
                    "opte driver failed to copyin/copyout req/resp".to_string()
                }

                libc::EINVAL => {
                    "opte driver failed to deser/ser req/resp".to_string()
                }

                errno => {
                    format!("unexpected errno: {}", errno)
                }
            };

            return Err(Error::IoctlFailed(cmd, msg));
        }

        // Check for successful response, try to deserialize it
        assert!(rioctl.resp_len_needed != 0);
        if rioctl.resp_len_needed <= rioctl.resp_len {
            let response = unsafe {
                std::slice::from_raw_parts(
                    rioctl.resp_bytes,
                    rioctl.resp_len_needed,
                )
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

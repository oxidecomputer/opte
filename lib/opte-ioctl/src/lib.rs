// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

use opte::api::API_VERSION;
use opte::api::ClearLftReq;
use opte::api::ClearUftReq;
use opte::api::ClearXdeUnderlayReq;
use opte::api::CmdOk;
use opte::api::Direction;
use opte::api::DumpLayerReq;
use opte::api::DumpLayerResp;
use opte::api::DumpTcpFlowsReq;
use opte::api::DumpTcpFlowsResp;
use opte::api::DumpUftReq;
use opte::api::DumpUftResp;
use opte::api::ListLayersReq;
use opte::api::ListLayersResp;
use opte::api::NoResp;
use opte::api::OpteCmd;
use opte::api::OpteCmdIoctl;
pub use opte::api::OpteError;
use opte::api::SetXdeUnderlayReq;
use opte::api::XDE_IOC_OPTE_CMD;
use opte::engine::packet::InnerFlowId;
use oxide_vpc::api::AddFwRuleReq;
use oxide_vpc::api::AddRouterEntryReq;
use oxide_vpc::api::AllowCidrReq;
use oxide_vpc::api::ClearVirt2BoundaryReq;
use oxide_vpc::api::ClearVirt2PhysReq;
use oxide_vpc::api::CreateXdeReq;
use oxide_vpc::api::DelRouterEntryReq;
use oxide_vpc::api::DelRouterEntryResp;
use oxide_vpc::api::DeleteXdeReq;
use oxide_vpc::api::DhcpCfg;
use oxide_vpc::api::DumpVirt2BoundaryReq;
use oxide_vpc::api::DumpVirt2BoundaryResp;
use oxide_vpc::api::DumpVirt2PhysReq;
use oxide_vpc::api::DumpVirt2PhysResp;
use oxide_vpc::api::IpCidr;
use oxide_vpc::api::ListPortsResp;
use oxide_vpc::api::RemFwRuleReq;
use oxide_vpc::api::RemoveCidrReq;
use oxide_vpc::api::RemoveCidrResp;
use oxide_vpc::api::SetExternalIpsReq;
use oxide_vpc::api::SetFwRulesReq;
use oxide_vpc::api::SetVirt2BoundaryReq;
use oxide_vpc::api::SetVirt2PhysReq;
use oxide_vpc::api::VpcCfg;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use thiserror::Error;

/// Errors related to administering the OPTE driver.
#[derive(Debug, Error)]
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

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => Error::DriverNotAttached,
            _ => Error::Io(e),
        }
    }
}

impl From<libnet::Error> for Error {
    fn from(e: libnet::Error) -> Self {
        Self::NetadmFailed(e)
    }
}

/// The handle used to send administration commands to OPTE.
#[derive(Debug)]
pub struct OpteHdl {
    device: File,
}

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

    /// List all layers in a given port.
    pub fn list_layers(&self, port: &str) -> Result<ListLayersResp, Error> {
        let cmd = OpteCmd::ListLayers;
        run_cmd_ioctl(
            self.device.as_raw_fd(),
            cmd,
            Some(&ListLayersReq { port_name: port.to_string() }),
        )
    }

    /// Return the contents of an OPTE layer.
    pub fn dump_layer(
        &self,
        port_name: &str,
        name: &str,
    ) -> Result<DumpLayerResp<InnerFlowId>, Error> {
        let cmd = OpteCmd::DumpLayer;
        let req = DumpLayerReq {
            port_name: port_name.to_string(),
            name: name.to_string(),
        };
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, Some(&req))
    }

    /// Create a new handle to an OPTE control node on an arbitrary file.
    pub fn open_on(what: &str) -> Result<Self, Error> {
        Ok(OpteHdl {
            device: OpenOptions::new().read(true).write(true).open(what)?,
        })
    }

    /// Create a new handle to the OPTE control node.
    pub fn open() -> Result<Self, Error> {
        Self::open_on(Self::XDE_CTL)
    }

    /// Dump the Virtual-to-Physical mappings.
    pub fn dump_v2p(&self) -> Result<DumpVirt2PhysResp, Error> {
        let cmd = OpteCmd::DumpVirt2Phys;
        run_cmd_ioctl(
            self.device.as_raw_fd(),
            cmd,
            Some(&DumpVirt2PhysReq { unused: 0 }),
        )
    }

    pub fn set_v2p(&self, req: &SetVirt2PhysReq) -> Result<NoResp, Error> {
        let cmd = OpteCmd::SetVirt2Phys;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, Some(&req))
    }

    pub fn clear_v2p(&self, req: &ClearVirt2PhysReq) -> Result<NoResp, Error> {
        let cmd = OpteCmd::ClearVirt2Phys;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, Some(&req))
    }

    pub fn set_v2b(&self, req: &SetVirt2BoundaryReq) -> Result<NoResp, Error> {
        let cmd = OpteCmd::SetVirt2Boundary;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, Some(&req))
    }

    pub fn clear_v2b(
        &self,
        req: &ClearVirt2BoundaryReq,
    ) -> Result<NoResp, Error> {
        let cmd = OpteCmd::ClearVirt2Boundary;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, Some(&req))
    }

    /// Dump the Virtual-to-Boundary mappings.
    pub fn dump_v2b(&self) -> Result<DumpVirt2BoundaryResp, Error> {
        let cmd = OpteCmd::DumpVirt2Boundary;
        run_cmd_ioctl(
            self.device.as_raw_fd(),
            cmd,
            Some(&DumpVirt2BoundaryReq { unused: 99 }),
        )
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

    /// Clear xde underlay devices.
    pub fn clear_xde_underlay(&self) -> Result<NoResp, Error> {
        let req = ClearXdeUnderlayReq { _unused: 0 };
        let cmd = OpteCmd::ClearXdeUnderlay;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, Some(&req))
    }

    pub fn add_router_entry(
        &self,
        req: &AddRouterEntryReq,
    ) -> Result<NoResp, Error> {
        let cmd = OpteCmd::AddRouterEntry;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, Some(&req))
    }

    pub fn del_router_entry(
        &self,
        req: &DelRouterEntryReq,
    ) -> Result<DelRouterEntryResp, Error> {
        let cmd = OpteCmd::DelRouterEntry;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, Some(&req))
    }

    /// Add a firewall rule
    pub fn add_firewall_rule(
        &self,
        req: &AddFwRuleReq,
    ) -> Result<NoResp, Error> {
        let cmd = OpteCmd::AddFwRule;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, Some(&req))
    }

    /// Remove a firewall rule.
    pub fn remove_firewall_rule(
        &self,
        req: &RemFwRuleReq,
    ) -> Result<NoResp, Error> {
        let cmd = OpteCmd::RemFwRule;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, Some(req))
    }

    pub fn set_firewall_rules(
        &self,
        req: &SetFwRulesReq,
    ) -> Result<NoResp, Error> {
        let cmd = OpteCmd::SetFwRules;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, Some(&req))
    }

    pub fn set_external_ips(
        &self,
        req: &SetExternalIpsReq,
    ) -> Result<NoResp, Error> {
        let cmd = OpteCmd::SetExternalIps;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, Some(&req))
    }

    pub fn allow_cidr(
        &self,
        port_name: &str,
        cidr: IpCidr,
        dir: Direction,
    ) -> Result<NoResp, Error> {
        let cmd = OpteCmd::AllowCidr;
        run_cmd_ioctl(
            self.device.as_raw_fd(),
            cmd,
            Some(&AllowCidrReq { cidr, port_name: port_name.into(), dir }),
        )
    }

    pub fn remove_cidr(
        &self,
        port_name: &str,
        cidr: IpCidr,
        dir: Direction,
    ) -> Result<RemoveCidrResp, Error> {
        let cmd = OpteCmd::RemoveCidr;
        run_cmd_ioctl(
            self.device.as_raw_fd(),
            cmd,
            Some(&RemoveCidrReq { cidr, port_name: port_name.into(), dir }),
        )
    }

    /// Return the TCP flows.
    pub fn dump_tcp_flows(
        &self,
        port_name: &str,
    ) -> Result<DumpTcpFlowsResp<InnerFlowId>, Error> {
        let cmd = OpteCmd::DumpTcpFlows;
        run_cmd_ioctl(
            self.device.as_raw_fd(),
            cmd,
            Some(&DumpTcpFlowsReq { port_name: port_name.to_string() }),
        )
    }

    /// Clear all entries from the Unified Flow Table (UFT).
    pub fn clear_uft(&self, port_name: &str) -> Result<NoResp, Error> {
        let cmd = OpteCmd::ClearUft;
        run_cmd_ioctl(
            self.device.as_raw_fd(),
            cmd,
            Some(&ClearUftReq { port_name: port_name.to_string() }),
        )
    }

    /// Clear all entries from the given Layer's Flow Table (LFT).
    pub fn clear_lft(
        &self,
        port_name: &str,
        layer_name: &str,
    ) -> Result<NoResp, Error> {
        let cmd = OpteCmd::ClearLft;
        run_cmd_ioctl(
            self.device.as_raw_fd(),
            cmd,
            Some(&ClearLftReq {
                port_name: port_name.to_string(),
                layer_name: layer_name.to_string(),
            }),
        )
    }

    /// Return the Unified Flow Table (UFT).
    pub fn dump_uft(
        &self,
        port_name: &str,
    ) -> Result<DumpUftResp<InnerFlowId>, Error> {
        let cmd = OpteCmd::DumpUft;
        run_cmd_ioctl(
            self.device.as_raw_fd(),
            cmd,
            Some(&DumpUftReq { port_name: port_name.to_string() }),
        )
    }
}

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

    // It would be a shame if the command failed and we didn't have enough bytes
    // to serialize the error response, so we set this to default to 16 KiB.
    const BASE_CAPACITY: usize = 16 * 1024;
    let mut resp_buf = Vec::with_capacity(BASE_CAPACITY);
    let mut rioctl = OpteCmdIoctl {
        api_version: API_VERSION,
        cmd,
        flags: 0,
        reserved1: 0,
        req_bytes: req_bytes_ptr,
        req_len,
        resp_bytes: resp_buf.as_mut_ptr(),
        resp_len: resp_buf.capacity(),
        resp_len_actual: 0,
    };

    const MAX_ITERATIONS: u8 = 3;
    for _ in 0..MAX_ITERATIONS {
        let ret =
            unsafe { ioctl(dev, XDE_IOC_OPTE_CMD as libc::c_int, &mut rioctl) };

        if ret == -1 {
            let err = std::io::Error::last_os_error();
            let raw_err = err.raw_os_error().unwrap();

            // The command ran successfully, but there is not enough space to
            // copyout(9F) the response. In this case bump up the size of the
            // response buffer and retry.
            if raw_err == libc::ENOBUFS {
                assert!(rioctl.resp_len_actual != 0);
                assert!(rioctl.resp_len_actual > resp_buf.capacity());

                // Make room for at least the size the kernel claims to need.
                // This can be slightly tricky: since every retry reruns the
                // command, the size of the next resp could change from under
                // us (increase or decrease). Keep some headroom to account
                // for this.
                let wanted_capacity =
                    BASE_CAPACITY / 4 + rioctl.resp_len_actual;

                // XDE could write into `resp_buf` (but does not).
                // .len() *should* be zero -- but don't bank on it.
                resp_buf.reserve(wanted_capacity - resp_buf.len());
                rioctl.resp_bytes = resp_buf.as_mut_ptr();
                rioctl.resp_len = resp_buf.capacity();
                rioctl.resp_len_actual = 0;
                continue;
            }

            // Anytime a response is present it will have more context
            // for the error. Otherwise, we have to approximate the
            // error via errno.
            if let Some(cmd_err) = rioctl.cmd_err_resp() {
                return Err(Error::CommandError(cmd, cmd_err));
            }

            let msg = match raw_err {
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
        } else {
            // Check for successful response, try to deserialize it
            assert!(rioctl.resp_len_actual <= resp_buf.capacity());
            // Safety:
            // The xde ioctl has promised that it has populated
            // `resp_len_actual` bytes in the buffer which we provided to it.
            unsafe {
                resp_buf.set_len(rioctl.resp_len_actual);
            }
            return postcard::from_bytes(&resp_buf)
                .map_err(|e| Error::RespDeser(cmd, e));
        }
    }

    Err(Error::MaxAttempts(cmd, MAX_ITERATIONS))
}

unsafe fn ioctl<T>(
    fd: libc::c_int,
    req: libc::c_int,
    arg: *mut T,
) -> libc::c_int {
    // Most other OSes define the request argument to be ulong_t rather than int
    // Cast that away here so that it compiles in both places
    #[cfg(not(target_os = "illumos"))]
    let req = req as libc::c_ulong;

    unsafe { libc::ioctl(fd, req, arg) }
}

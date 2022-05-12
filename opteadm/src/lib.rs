// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! OPTE driver administration library
// Copyright 2021 Oxide Computer Company

use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;

use opte::api::{MacAddr, NoResp, OpteCmd, SetXdeUnderlayReq, Vni};
use opte::engine::ioctl::{self as api};
use opte::oxide_vpc::api::{
    AddFwRuleReq, AddRouterEntryIpv4Req, CreateXdeReq, DeleteXdeReq,
    FirewallRule, ListPortsReq, ListPortsResp, RemFwRuleReq, SetFwRulesReq,
    SetVirt2PhysReq,
};
use opte::oxide_vpc::engine::overlay;
use opte_ioctl::{run_cmd_ioctl, Error};

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

    pub fn set_firewall_rules(
        &self,
        port_name: &str,
        rules: Vec<FirewallRule>,
    ) -> Result<NoResp, Error> {
        let cmd = OpteCmd::SetFwRules;
        let req =
            SetFwRulesReq { port_name: port_name.to_string(), rules: rules };
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
    pub fn list_ports(&self) -> Result<ListPortsResp, Error> {
        let cmd = OpteCmd::ListPorts;
        run_cmd_ioctl::<ListPortsResp, _>(
            self.device.as_raw_fd(),
            cmd,
            &ListPortsReq { unused: () },
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

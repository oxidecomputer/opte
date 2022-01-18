//! The ioctl interface.
use core::convert::TryFrom;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::string::String;
#[cfg(any(feature = "std", test))]
use std::string::String;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::sync::Arc;
#[cfg(any(feature = "std", test))]
use std::sync::Arc;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::vec::Vec;
#[cfg(any(feature = "std", test))]
use std::vec::Vec;

#[cfg(all(not(feature = "std"), not(test)))]
use illumos_ddi_dki::{c_int, size_t};
#[cfg(any(feature = "std", test))]
use libc::{c_int, size_t};

use serde::{Deserialize, Serialize};

use crate::ether::EtherAddr;
use crate::ip4::Ipv4Addr;
use crate::oxide_net::{firewall as fw, overlay};
use crate::layer;
use crate::port;
use crate::rule;
use crate::vpc::VpcSubnet4;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum IoctlCmd {
    ListPorts = 1,     // list all ports
    AddPort = 2,     // add new port
    DeletePort = 3,     // delete a port
    FwAddRule = 20,     // add firewall rule
    FwRemRule = 21,     // remove firewall rule
    DumpTcpFlows = 30,  // dump TCP flows
    DumpLayer = 31,     // dump the specified Layer
    DumpUft = 32,       // dump the Unified Flow Table
    SetOverlay = 40     // set the overlay config
}

impl TryFrom<c_int> for IoctlCmd {
    type Error = ();

    fn try_from(num: c_int) -> Result<Self, Self::Error> {
        match num {
            1 => Ok(IoctlCmd::ListPorts),
            2 => Ok(IoctlCmd::AddPort),
            3 => Ok(IoctlCmd::DeletePort),
            20 => Ok(IoctlCmd::FwAddRule),
            21 => Ok(IoctlCmd::FwRemRule),
            30 => Ok(IoctlCmd::DumpTcpFlows),
            31 => Ok(IoctlCmd::DumpLayer),
            32 => Ok(IoctlCmd::DumpUft),
            40 => Ok(IoctlCmd::SetOverlay),
            _ => Err(()),
        }
    }
}

pub trait ApiError {}

#[derive(Debug, Deserialize, Serialize)]
pub enum PortError {
    Active,
    Exists,
    Inactive,
    MacOpenFailed(c_int),
    NotFound,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum AddPortError {
    Exists,
    MacOpenFailed(c_int),
}

#[derive(Debug, Deserialize, Serialize)]
pub enum DeletePortError {
    InUse,
    NotFound,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum AddFwRuleError {
    FirewallNotEnabled,
}

impl ApiError for AddFwRuleError {}

#[derive(Debug, Deserialize, Serialize)]
pub enum RemFwRuleError {
    FirewallNotEnabled,
    RuleNotFound,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum DumpLayerError {
    LayerNotFound
}

impl From<port::DumpLayerError> for DumpLayerError {
    fn from(e: port::DumpLayerError) -> Self {
        use port::DumpLayerError as Dle;

        match e {
            Dle::LayerNotFound => Self::LayerNotFound,
        }
    }
}

pub fn add_fw_rule(
    port: &port::Port<port::Active>,
    req: &fw::FwAddRuleReq
) -> Result<(), AddFwRuleError> {
    let action = match req.rule.action {
        fw::Action::Allow => {
            port.layer_action(fw::FW_LAYER_NAME, 0).unwrap().clone()
        }

        fw::Action::Deny => rule::Action::Deny,
    };

    let rule = fw::from_fw_rule(req.rule.clone(), action);

    let res = port.add_rule(
        fw::FW_LAYER_NAME,
        req.rule.direction,
        rule,
    );

    match res {
        Ok(()) => Ok(()),
        Err(port::AddRuleError::LayerNotFound) => {
            Err(AddFwRuleError::FirewallNotEnabled)
        }
    }
}

pub fn rem_fw_rule(
    port: &port::Port<port::Active>,
    req: &fw::FwRemRuleReq,
) -> Result<(), RemFwRuleError> {
    let res = port.remove_rule(fw::FW_LAYER_NAME, req.dir, req.id);
    match res {
        Ok(()) => Ok(()),
        Err(port::RemoveRuleError::LayerNotFound) => {
            Err(RemFwRuleError::FirewallNotEnabled)
        }
        Err(port::RemoveRuleError::RuleNotFound) => {
            Err(RemFwRuleError::RuleNotFound)
        }
    }
}

pub fn dump_layer(
    port: &port::Port<port::Active>,
    req: &layer::DumpLayerReq,
) -> Result<layer::DumpLayerResp, DumpLayerError> {
    port.dump_layer(&req.name).map_err(DumpLayerError::from)
}

pub fn dump_tcp_flows(
    port: &port::Port<port::Active>,
    _req: &port::DumpTcpFlowsReq,
) -> port::DumpTcpFlowsResp {
    port.dump_tcp_flows()
}

pub fn dump_uft(
    port: &port::Port<port::Active>,
    _req: &port::DumpUftReq,
) -> port::DumpUftResp {
    port.dump_uft()
}

pub fn set_overlay(
    port: &port::Port<port::Inactive>,
    req: &overlay::SetOverlayReq,
    v2p: Arc<overlay::Virt2Phys>,
) {
    // let cfg = OverlayCfg {
    //     // TODO Using nonsense for BS for the moment.
    //     boundary_services: PhysNet {
    //         ether: EtherAddr::from([0; 6]),
    //         ip: Ipv6Addr::from([0; 16]),
    //         vni: Vni::new(11),
    //     },
    //     vni: 
    // }
    overlay::setup(port, &req.cfg, v2p);
}

// We need repr(C) for a stable layout across compilations. This is a
// generic structure for all ioctls, the actual request/response data
// is serialized/deserialized by serde. In the future, if we need this
// to work with non-Rust programs in illumos, we could write an nvlist
// provider that works with serde.
#[derive(Debug)]
#[repr(C)]
pub struct Ioctl {
    pub req_bytes: *const u8,
    pub req_len: size_t,
    pub resp_bytes: *mut u8,
    pub resp_len: size_t,
    pub resp_len_needed: size_t,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SnatCfg {
    pub public_mac: EtherAddr,
    pub public_ip: Ipv4Addr,
    pub port_start: u16,
    pub port_end: u16,
    pub vpc_sub4: VpcSubnet4,
}

// TODO Rename this PortConfig
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IpCfg {
    pub private_ip: Ipv4Addr,
    pub snat: Option<SnatCfg>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AddPortReq {
    pub link_name: String,
    pub ip_cfg: IpCfg,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeletePortReq {
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListPortsReq {
    pub unused: (),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PortInfo {
    pub name: String,
    pub mac_addr: EtherAddr,
    pub ip4_addr: Ipv4Addr,
    pub in_use: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListPortsResp {
    pub ports: Vec<PortInfo>,
}

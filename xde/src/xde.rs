// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! xde - A mac provider for OPTE.
//!
//! An illumos kernel driver that implements the mac provider
//! interface, allowing one to run network implementations written in
//! the OPTE framework.

// TODO
// - ddm integration to choose correct underlay device (currently just using
//   first device)

use crate::dls;
use crate::ioctl::IoctlEnvelope;
use crate::ip;
use crate::mac;
use crate::mac::mac_getinfo;
use crate::mac::mac_private_minor;
use crate::mac::MacClientHandle;
use crate::mac::MacHandle;
use crate::mac::MacOpenFlags;
use crate::mac::MacPromiscHandle;
use crate::mac::MacTxFlags;
use crate::mac::MacUnicastHandle;
use crate::secpolicy;
use crate::sys;
use crate::warn;
use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::convert::TryInto;
use core::ffi::CStr;
use core::num::NonZeroU32;
use core::ptr;
use core::time::Duration;
use illumos_sys_hdrs::*;
use opte::api::CmdOk;
use opte::api::Direction;
use opte::api::NoResp;
use opte::api::OpteCmd;
use opte::api::OpteCmdIoctl;
use opte::api::OpteError;
use opte::api::SetXdeUnderlayReq;
use opte::api::XDE_IOC_OPTE_CMD;
use opte::ddi::sync::KMutex;
use opte::ddi::sync::KMutexType;
use opte::ddi::sync::KRwLock;
use opte::ddi::sync::KRwLockType;
use opte::ddi::time::Interval;
use opte::ddi::time::Moment;
use opte::ddi::time::Periodic;
use opte::engine::ether::EtherAddr;
use opte::engine::geneve::Vni;
use opte::engine::headers::EncapMeta;
use opte::engine::headers::IpAddr;
use opte::engine::ioctl::{self as api};
use opte::engine::ip6::Ipv6Addr;
use opte::engine::packet::Initialized;
use opte::engine::packet::Packet;
use opte::engine::packet::PacketError;
use opte::engine::packet::Parsed;
use opte::engine::port::meta::ActionMeta;
use opte::engine::port::Port;
use opte::engine::port::PortBuilder;
use opte::engine::port::ProcessResult;
use opte::ExecCtx;
use oxide_vpc::api::AddFwRuleReq;
use oxide_vpc::api::AddRouterEntryReq;
use oxide_vpc::api::CreateXdeReq;
use oxide_vpc::api::DeleteXdeReq;
use oxide_vpc::api::IpCfg;
use oxide_vpc::api::ListPortsResp;
use oxide_vpc::api::PhysNet;
use oxide_vpc::api::PortInfo;
use oxide_vpc::api::RemFwRuleReq;
use oxide_vpc::api::SetFwRulesReq;
use oxide_vpc::api::SetVirt2PhysReq;
use oxide_vpc::api::VpcCfg;
use oxide_vpc::engine::firewall;
use oxide_vpc::engine::gateway;
use oxide_vpc::engine::nat;
use oxide_vpc::engine::overlay;
use oxide_vpc::engine::router;
use oxide_vpc::engine::VpcNetwork;
use oxide_vpc::engine::VpcParser;

// Entry limits for the various flow tables.
//
// Safety: Despite the name of `new_unchecked`, there actually is a compile-time
// check that these values are non-zero.
const FW_FT_LIMIT: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(8096) };
const FT_LIMIT_ONE: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(1) };

/// The name of this driver.
const XDE_STR: *const c_char = b"xde\0".as_ptr() as *const c_char;

/// Name of the control device.
const XDE_CTL_STR: *const c_char = b"ctl\0".as_ptr() as *const c_char;

/// Minor number for the control device.
// Set once in `xde_attach`.
static mut XDE_CTL_MINOR: minor_t = 0;

/// A list of xde devices instantiated through xde_ioc_create.
static mut xde_devs: KRwLock<Vec<Box<XdeDev>>> = KRwLock::new(Vec::new());

/// DDI dev info pointer to the attached xde device.
static mut xde_dip: *mut dev_info = 0 as *mut dev_info;

// This block is purely for SDT probes.
extern "C" {
    pub fn __dtrace_probe_bad__packet(
        port: uintptr_t,
        dir: uintptr_t,
        mp: uintptr_t,
        msg: uintptr_t,
    );
    pub fn __dtrace_probe_guest__loopback(
        mp: uintptr_t,
        flow: uintptr_t,
        src_port: uintptr_t,
        dst_port: uintptr_t,
    );
    pub fn __dtrace_probe_hdlr__resp(resp_str: uintptr_t);
    pub fn __dtrace_probe_next__hop(
        dst: uintptr_t,
        gw: uintptr_t,
        gw_ether_src: uintptr_t,
        gw_ether_dst: uintptr_t,
        msg: uintptr_t,
    );
    pub fn __dtrace_probe_rx(mp: uintptr_t);
    pub fn __dtrace_probe_rx__chain__todo(mp: uintptr_t);
    pub fn __dtrace_probe_tx(mp: uintptr_t);
}

fn bad_packet_parse_probe(
    port: Option<&CString>,
    dir: Direction,
    mp: *mut mblk_t,
    err: &PacketError,
) {
    let msg = format!("{:?}", err);
    bad_packet_probe(port, dir, mp, &msg);
}

fn bad_packet_probe(
    port: Option<&CString>,
    dir: Direction,
    mp: *mut mblk_t,
    msg: &str,
) {
    let port_str = match port {
        None => b"unknown\0" as *const u8 as *const i8,
        Some(name) => name.as_ptr(),
    };
    let msg_arg = CString::new(msg).unwrap();
    unsafe {
        __dtrace_probe_bad__packet(
            port_str as uintptr_t,
            dir as uintptr_t,
            mp as uintptr_t,
            msg_arg.as_ptr() as uintptr_t,
        )
    };
}

fn next_hop_probe(
    dst: &Ipv6Addr,
    gw: Option<&Ipv6Addr>,
    gw_eth_src: EtherAddr,
    gw_eth_dst: EtherAddr,
    msg: &[u8],
) {
    let gw_bytes = gw.unwrap_or(&Ipv6Addr::from([0u8; 16])).bytes();

    unsafe {
        __dtrace_probe_next__hop(
            dst.bytes().as_ptr() as uintptr_t,
            gw_bytes.as_ptr() as uintptr_t,
            gw_eth_src.to_bytes().as_ptr() as uintptr_t,
            gw_eth_dst.to_bytes().as_ptr() as uintptr_t,
            msg.as_ptr() as uintptr_t,
        );
    }
}

/// Underlay port state.
#[derive(Debug)]
struct xde_underlay_port {
    /// Name of the link being used for this underlay port.
    name: String,

    /// The MAC address associated with this underlay port.
    mac: [u8; 6],

    /// MAC handle to the underlay link.
    mh: Arc<MacHandle>,

    /// MAC client handle for tx/rx on the underlay link.
    mch: Arc<MacClientHandle>,

    /// MAC client handle for tx/rx on the underlay link.
    muh: MacUnicastHandle,

    /// MAC promiscuous handle for receiving packets on the underlay link.
    mph: MacPromiscHandle,
}

struct XdeState {
    ectx: Arc<ExecCtx>,
    vpc_map: Arc<overlay::VpcMappings>,
    underlay: KMutex<Option<UnderlayState>>,
}

struct UnderlayState {
    // each xde driver has a handle to two underlay ports that are used for I/O
    // onto the underlay network
    u1: Arc<xde_underlay_port>,
    u2: Arc<xde_underlay_port>,
}

fn get_xde_state() -> &'static mut XdeState {
    // Safety: The opte_dip pointer is write-once and is a valid
    // pointer passed to attach(9E). The returned pointer is valid as
    // it was derived from Box::into_raw() during `xde_attach`.
    unsafe {
        let p = ddi_get_driver_private(xde_dip);
        &mut *(p as *mut XdeState)
    }
}

impl XdeState {
    fn new() -> Self {
        let ectx = Arc::new(ExecCtx { log: Box::new(opte::KernelLog {}) });
        XdeState {
            underlay: KMutex::new(None, KMutexType::Driver),
            ectx,
            vpc_map: Arc::new(overlay::VpcMappings::new()),
        }
    }
}

#[repr(C)]
struct XdeDev {
    devname: String,
    linkid: datalink_id_t,
    mh: *mut mac::mac_handle,
    link_state: mac::link_state_t,

    // The OPTE port associated with this xde device.
    //
    // XXX Ideally the xde driver would be a generic driver which
    // could setup ports for any number of network implementations.
    // However, that's not where things are today.
    port: Arc<Port<VpcNetwork>>,
    vpc_cfg: VpcCfg,
    port_periodic: Periodic<Arc<Port<VpcNetwork>>>,
    port_v2p: Arc<overlay::Virt2Phys>,

    // Pass the packets through to the underlay devices, skipping
    // opte-core processing.
    passthrough: bool,

    vni: Vni,

    // These are clones of the underlay ports initialized by the
    // driver.
    u1: Arc<xde_underlay_port>,
    u2: Arc<xde_underlay_port>,
}

#[cfg(not(test))]
#[no_mangle]
unsafe extern "C" fn _init() -> c_int {
    xde_devs.init(KRwLockType::Driver);
    mac::mac_init_ops(&mut xde_devops, XDE_STR);

    match mod_install(&xde_linkage) {
        0 => 0,
        err => {
            warn!("mod_install failed: {}", err);
            mac::mac_fini_ops(&mut xde_devops);
            err
        }
    }
}

#[no_mangle]
unsafe extern "C" fn _info(modinfop: *mut modinfo) -> c_int {
    mod_info(&xde_linkage, modinfop)
}

#[cfg(not(test))]
#[no_mangle]
unsafe extern "C" fn _fini() -> c_int {
    match mod_remove(&xde_linkage) {
        0 => {
            mac::mac_fini_ops(&mut xde_devops);
            0
        }
        err => {
            warn!("mod remove failed: {}", err);
            err
        }
    }
}

/// Handle `open(9E)` for non-MAC managed devices.
///
/// MAC providers are STREAMS drivers and thus use the `str_ops` entrypoints,
/// leaving `cb_open` and others typically set to `nodev`. However, the MAC
/// framework does allow drivers to provide its own set of minor nodes as
/// regular char/block devices. We create one such device (/dev/xde) in
/// `xde_attach`. See also `xde_getinfo`.
/// MAC will return `ENOSTR` from its STREAMS-based `open(9E)` routine if
/// passed a minor node reserved for driver private use. In that case,
/// the system will retry the open with the driver's `cb_open` routine.
#[no_mangle]
unsafe extern "C" fn xde_open(
    devp: *mut dev_t,
    flags: c_int,
    otyp: c_int,
    credp: *mut cred_t,
) -> c_int {
    assert!(!xde_dip.is_null());

    if otyp != OTYP_CHR {
        return EINVAL;
    }

    let minor = getminor(*devp);
    if minor != XDE_CTL_MINOR {
        return ENXIO;
    }

    match secpolicy::secpolicy_dl_config(credp) {
        0 => {}
        err => {
            warn!("secpolicy_dl_config failed: {err}");
            return err;
        }
    }

    if (flags & (FEXCL | FNDELAY | FNONBLOCK)) != 0 {
        return EINVAL;
    }

    0
}

#[no_mangle]
unsafe extern "C" fn xde_close(
    dev: dev_t,
    _flag: c_int,
    otyp: c_int,
    _credp: *mut cred_t,
) -> c_int {
    assert!(!xde_dip.is_null());

    if otyp != OTYP_CHR {
        return EINVAL;
    }

    let minor = getminor(dev);
    if minor != XDE_CTL_MINOR {
        return ENXIO;
    }

    0
}

#[no_mangle]
unsafe extern "C" fn xde_ioctl(
    dev: dev_t,
    cmd: c_int,
    arg: intptr_t,
    mode: c_int,
    _credp: *mut cred_t,
    _rvalp: *mut c_int,
) -> c_int {
    assert!(!xde_dip.is_null());

    let minor = getminor(dev);
    if minor != XDE_CTL_MINOR {
        return ENXIO;
    }

    if cmd != XDE_IOC_OPTE_CMD {
        return ENOTTY;
    }

    // TODO: this is using KM_SLEEP, is that ok?
    let mut buf = Vec::<u8>::with_capacity(IOCTL_SZ);
    if ddi_copyin(arg as _, buf.as_mut_ptr() as _, IOCTL_SZ, mode) != 0 {
        return EFAULT;
    }

    let err = xde_ioc_opte_cmd(buf.as_mut_ptr() as _, mode);

    if ddi_copyout(buf.as_ptr() as _, arg as _, IOCTL_SZ, mode) != 0 && err == 0
    {
        return EFAULT;
    }

    err
}

fn dtrace_probe_hdlr_resp<T>(resp: &Result<T, OpteError>)
where
    T: CmdOk,
{
    let resp_arg = CString::new(format!("{:?}", resp)).unwrap();
    unsafe {
        __dtrace_probe_hdlr__resp(resp_arg.as_ptr() as uintptr_t);
    }
}

// Convert the handler's response to the appropriate ioctl(2) return
// value and copyout the serialized response.
fn hdlr_resp<T>(env: &mut IoctlEnvelope, resp: Result<T, OpteError>) -> c_int
where
    T: CmdOk,
{
    dtrace_probe_hdlr_resp(&resp);
    env.copy_out_resp(&resp)
}

fn create_xde_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: CreateXdeReq = env.copy_in_req()?;
    create_xde(&req)
}

fn delete_xde_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: DeleteXdeReq = env.copy_in_req()?;
    delete_xde(&req)
}

fn set_xde_underlay_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: SetXdeUnderlayReq = env.copy_in_req()?;
    set_xde_underlay(&req)
}

// This is the entry point for all OPTE commands. It verifies the API
// version and then multiplexes the command to its appropriate handler.
#[no_mangle]
unsafe extern "C" fn xde_ioc_opte_cmd(karg: *mut c_void, mode: c_int) -> c_int {
    let ioctl: &mut OpteCmdIoctl = &mut *(karg as *mut OpteCmdIoctl);
    let mut env = match IoctlEnvelope::wrap(ioctl, mode) {
        Ok(v) => v,
        Err(errno) => return errno,
    };

    match env.ioctl_cmd() {
        OpteCmd::ListPorts => {
            // The list-ports command has no request body, so there is
            // no need to pass the envelope.
            let resp = list_ports_hdlr();
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::AddFwRule => {
            let resp = add_fw_rule_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::RemFwRule => {
            // XXX At the moment a default rule can be removed. That's
            // something we may want to prevent at the OPTE layer
            // moving forward. Or we may want to allow complete
            // freedom at this level and place that enforcement at the
            // control plane level.
            let resp = rem_fw_rule_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::SetFwRules => {
            let resp = set_fw_rules_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::CreateXde => {
            let resp = create_xde_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::DeleteXde => {
            let resp = delete_xde_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::SetXdeUnderlay => {
            let resp = set_xde_underlay_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::DumpLayer => {
            let resp = dump_layer_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::ClearUft => {
            let resp = clear_uft_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::DumpUft => {
            let resp = dump_uft_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::ListLayers => {
            let resp = list_layers_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::DumpVirt2Phys => {
            let resp = dump_v2p_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::SetVirt2Phys => {
            let resp = set_v2p_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::AddRouterEntry => {
            let resp = add_router_entry_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::DumpTcpFlows => {
            let resp = dump_tcp_flows_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }
    }
}

const ONE_SECOND: Interval = Interval::from_duration(Duration::new(1, 0));

#[no_mangle]
fn expire_periodic(port: &mut Arc<Port<VpcNetwork>>) {
    // XXX The call fails if the port is paused; in which case we
    // ignore the error. Eventually xde will also have logic for
    // moving a port to a paused state, and in that state the periodic
    // should probably be canceled.
    let _ = port.expire_flows(Moment::now());
}

#[no_mangle]
fn create_xde(req: &CreateXdeReq) -> Result<NoResp, OpteError> {
    // TODO name validation
    let state = get_xde_state();
    let underlay_ = state.underlay.lock();
    let underlay = match *underlay_ {
        Some(ref u) => u,
        None => {
            return Err(OpteError::System {
                errno: EINVAL,
                msg: "underlay not initialized".to_string(),
            })
        }
    };

    // It's imperative to take the devices write lock early. We want
    // to hold it for the rest of this function in order for device
    // creation to be atomic with regard to other threads.
    //
    // This does mean that the current Rx path is blocked on device
    // creation, but that's a price we need to pay for the moment.
    let mut devs = unsafe { xde_devs.write() };
    match devs.iter().find(|x| x.devname == req.xde_devname) {
        Some(_) => return Err(OpteError::PortExists(req.xde_devname.clone())),
        None => (),
    };

    let cfg = &req.cfg;
    match devs
        .iter()
        .find(|x| x.vni == cfg.vni && x.port.mac_addr() == cfg.guest_mac.into())
    {
        Some(_) => {
            return Err(OpteError::MacExists {
                port: req.xde_devname.clone(),
                vni: cfg.vni,
                mac: cfg.guest_mac,
            })
        }
        None => (),
    }

    // If this is the first guest in this VPC, then create a new
    // mapping for said VPC. Otherwise, pull the existing one.
    //
    // We need to insert mappings for both IPv4 and IPv6 addresses, should the
    // guest have them. They should return the same `Virt2Phys` mapping, since
    // they're mapping both IP addresses to the same host.
    let phys_net =
        PhysNet { ether: cfg.guest_mac, ip: cfg.phys_ip, vni: cfg.vni };
    let port_v2p = match cfg.ip_cfg {
        IpCfg::Ipv4(ref ipv4) => {
            state.vpc_map.add(IpAddr::Ip4(ipv4.private_ip), phys_net)
        }
        IpCfg::Ipv6(ref ipv6) => {
            state.vpc_map.add(IpAddr::Ip6(ipv6.private_ip), phys_net)
        }
        IpCfg::DualStack { ref ipv4, ref ipv6 } => {
            state.vpc_map.add(IpAddr::Ip4(ipv4.private_ip), phys_net);
            state.vpc_map.add(IpAddr::Ip6(ipv6.private_ip), phys_net)
        }
    };

    let port = new_port(
        req.xde_devname.clone(),
        &cfg,
        state.vpc_map.clone(),
        port_v2p.clone(),
        state.ectx.clone(),
    )?;

    let port_periodic = Periodic::new(
        port.name_cstr().clone(),
        expire_periodic,
        Box::new(port.clone()),
        ONE_SECOND,
    );

    let mut xde = Box::new(XdeDev {
        devname: req.xde_devname.clone(),
        linkid: req.linkid,
        mh: 0 as *mut mac::mac_handle,
        link_state: mac::link_state_t::Down,
        port,
        port_periodic,
        port_v2p,
        vpc_cfg: cfg.clone(),
        passthrough: req.passthrough,
        vni: cfg.vni,
        u1: underlay.u1.clone(),
        u2: underlay.u2.clone(),
    });
    drop(underlay_);

    // set up upper mac
    let mreg = match unsafe { mac::mac_alloc(MAC_VERSION as u32).as_mut() } {
        Some(x) => x,
        None => {
            return Err(OpteError::System {
                errno: ENOMEM,
                msg: "failed to alloc mac".to_string(),
            })
        }
    };

    mreg.m_type_ident = MAC_PLUGIN_IDENT_ETHER;
    mreg.m_driver = xde.as_mut() as *mut XdeDev as *mut c_void;
    mreg.m_dst_addr = core::ptr::null_mut();
    mreg.m_pdata = core::ptr::null_mut();
    mreg.m_pdata_size = 0;
    mreg.m_priv_props = core::ptr::null_mut();
    mreg.m_instance = c_uint::MAX; // let mac handle this
    mreg.m_min_sdu = 1;
    mreg.m_max_sdu = 1500; // TODO hardcode
    mreg.m_multicast_sdu = 0;
    mreg.m_margin = sys::VLAN_TAGSZ;
    mreg.m_v12n = mac::MAC_VIRT_NONE as u32;

    unsafe {
        mreg.m_dip = xde_dip;
        mreg.m_callbacks = &mut xde_mac_callbacks;
    }

    // TODO Total hack to allow a VNIC atop of xde to have the guest's
    // MAC address. The VNIC **NEEDS** to have the guest's MAC address
    // or else none of the ethernet rule predicates will match.
    //
    // The real answer is to stop putting VNICs atop xde. The xde
    // device needs to sit in the place where a VNIC would usually go.
    mreg.m_src_addr = EtherAddr::from([0xA8, 0x40, 0x25, 0x77, 0x77, 0x77])
        .to_bytes()
        .as_mut_ptr();

    let reg_res = unsafe {
        mac::mac_register(mreg as *mut mac::mac_register_t, &mut xde.mh)
    };
    match reg_res {
        0 => {}
        err => {
            unsafe { mac::mac_free(mreg) };
            return Err(OpteError::System {
                errno: err,
                msg: "fail to register mac provider".to_string(),
            });
        }
    }

    unsafe { mac::mac_free(mreg) };

    // setup dls
    match unsafe { dls::dls_devnet_create(xde.mh, req.linkid, 0) } {
        0 => {}
        err => {
            unsafe {
                mac::mac_unregister(xde.mh);
            }
            return Err(OpteError::System {
                errno: err,
                msg: "failed to create DLS devnet".to_string(),
            });
        }
    }

    xde.link_state = mac::link_state_t::Up;
    unsafe {
        mac::mac_link_update(xde.mh, xde.link_state);
        mac::mac_tx_update(xde.mh);
    }

    devs.push(xde);
    Ok(NoResp::default())
}

#[no_mangle]
fn delete_xde(req: &DeleteXdeReq) -> Result<NoResp, OpteError> {
    let state = get_xde_state();
    let mut devs = unsafe { xde_devs.write() };
    let index = match devs.iter().position(|x| x.devname == req.xde_devname) {
        Some(index) => index,
        None => return Err(OpteError::PortNotFound(req.xde_devname.clone())),
    };
    let xde = &mut devs[index];

    // Destroy DLS devnet device.
    let ret = unsafe {
        let mut tmpid = xde.linkid;
        dls::dls_devnet_destroy(xde.mh, &mut tmpid, boolean_t::B_TRUE)
    };

    match ret {
        0 => {}
        err => {
            return Err(OpteError::System {
                errno: err,
                msg: format!("failed to destroy DLS devnet: {}", err),
            });
        }
    }

    // Unregister this xde's mac handle.
    match unsafe { mac::mac_unregister(xde.mh) } {
        0 => {}
        err => {
            match unsafe { dls::dls_devnet_create(xde.mh, xde.linkid, 0) } {
                0 => {}
                err => {
                    warn!("failed to recreate DLS devnet entry: {}", err);
                }
            };
            return Err(OpteError::System {
                errno: err,
                msg: format!("failed to unregister mac: {}", err),
            });
        }
    }

    // Remove the VPC mappings for this port.
    let cfg = &xde.vpc_cfg;
    let phys_net =
        PhysNet { ether: cfg.guest_mac, ip: cfg.phys_ip, vni: cfg.vni };
    match cfg.ip_cfg {
        IpCfg::Ipv4(ref ipv4) => {
            state.vpc_map.del(&IpAddr::Ip4(ipv4.private_ip), &phys_net)
        }
        IpCfg::Ipv6(ref ipv6) => {
            state.vpc_map.del(&IpAddr::Ip6(ipv6.private_ip), &phys_net)
        }
        IpCfg::DualStack { ref ipv4, ref ipv6 } => {
            state.vpc_map.del(&IpAddr::Ip4(ipv4.private_ip), &phys_net);
            state.vpc_map.del(&IpAddr::Ip6(ipv6.private_ip), &phys_net)
        }
    };

    // Remove the xde device entry.
    devs.remove(index);
    Ok(NoResp::default())
}

#[no_mangle]
fn set_xde_underlay(req: &SetXdeUnderlayReq) -> Result<NoResp, OpteError> {
    let state = get_xde_state();
    let mut underlay = state.underlay.lock();
    if underlay.is_some() {
        return Err(OpteError::System {
            errno: EEXIST,
            msg: "underlay already initialized".into(),
        });
    }
    *underlay = Some(unsafe {
        init_underlay_ingress_handlers(req.u1.clone(), req.u2.clone())?
    });

    Ok(NoResp::default())
}

const IOCTL_SZ: usize = core::mem::size_of::<OpteCmdIoctl>();

#[no_mangle]
unsafe extern "C" fn xde_getinfo(
    dip: *mut dev_info,
    cmd: ddi_info_cmd_t,
    arg: *mut c_void,
    resultp: *mut *mut c_void,
) -> c_int {
    if xde_dip.is_null() {
        return DDI_FAILURE;
    }

    let minor = match cmd {
        ddi_info_cmd_t::DDI_INFO_DEVT2DEVINFO
        | ddi_info_cmd_t::DDI_INFO_DEVT2INSTANCE => getminor(arg as dev_t),
        // We call into `mac_getinfo` here rather than just fail
        // with `DDI_FAILURE` to let it handle if ever there's a new
        // `ddi_info_cmd_t` variant.
        _ => return mac_getinfo(dip, cmd, arg, resultp),
    };

    // If this isn't one of our private minors,
    // let the GLDv3 framework handle it.
    if minor < mac_private_minor() {
        return mac_getinfo(dip, cmd, arg, resultp);
    }

    // We currently only expose a single minor node,
    // bail on anything else.
    if minor != XDE_CTL_MINOR {
        return DDI_FAILURE;
    }

    match cmd {
        ddi_info_cmd_t::DDI_INFO_DEVT2DEVINFO => {
            *resultp = xde_dip.cast();
            DDI_SUCCESS
        }
        ddi_info_cmd_t::DDI_INFO_DEVT2INSTANCE => {
            *resultp = ddi_get_instance(xde_dip) as _;
            DDI_SUCCESS
        }
        _ => DDI_FAILURE,
    }
}

#[no_mangle]
unsafe extern "C" fn xde_attach(
    dip: *mut dev_info,
    cmd: ddi_attach_cmd_t,
) -> c_int {
    match cmd {
        ddi_attach_cmd_t::DDI_RESUME => return DDI_SUCCESS,
        ddi_attach_cmd_t::DDI_ATTACH => {}
        _ => return DDI_FAILURE,
    }

    assert!(xde_dip.is_null());

    // We need to share the minor number space with the GLDv3 framework.
    // We'll use the first private minor number for our control device.
    XDE_CTL_MINOR = mac_private_minor();

    // Create xde control device
    match ddi_create_minor_node(
        dip,
        XDE_CTL_STR,
        S_IFCHR,
        XDE_CTL_MINOR,
        DDI_PSEUDO,
        0,
    ) {
        0 => {}
        err => {
            warn!("failed to create xde control device: {err}");
            return DDI_FAILURE;
        }
    }

    xde_dip = dip;

    let state = Box::new(XdeState::new());
    ddi_set_driver_private(xde_dip, Box::into_raw(state) as *mut c_void);

    ddi_report_dev(xde_dip);

    return DDI_SUCCESS;
}

/// Setup underlay port atop the given link.
fn create_underlay_port(
    link_name: String,
    mc_name: &str,
) -> Result<xde_underlay_port, OpteError> {
    // Grab mac handle for underlying link
    let mh = MacHandle::open_by_link_name(&link_name).map(Arc::new).map_err(
        |e| OpteError::System {
            errno: EFAULT,
            msg: format!("failed to open link {link_name} for underlay: {e}"),
        },
    )?;

    // Get a mac client handle as well.
    //
    let oflags = MacOpenFlags::NONE;
    let mch = MacClientHandle::open(&mh, Some(mc_name), oflags, 0)
        .map(Arc::new)
        .map_err(|e| OpteError::System {
            errno: EFAULT,
            msg: format!("mac_client_open failed for {link_name}: {e}"),
        })?;

    // Setup promiscuous callback to receive all packets on this link.
    //
    // We specify `MAC_PROMISC_FLAGS_NO_TX_LOOP` here to skip receiving copies
    // of outgoing packets we sent ourselves.
    let mph = mch
        .add_promisc(
            mac::mac_client_promisc_type_t::MAC_CLIENT_PROMISC_ALL,
            xde_rx,
            mac::MAC_PROMISC_FLAGS_NO_TX_LOOP,
        )
        .map_err(|e| OpteError::System {
            errno: EFAULT,
            msg: format!("mac_promisc_add failed for {link_name}: {e}"),
        })?;

    // Set up a unicast callback. The MAC address here is a sentinel value with
    // nothing real behind it. This is why we picked the zero value in the Oxide
    // OUI space for virtual MACs. The reason this is being done is that illumos
    // requires that if there is a single mac client on a link, that client must
    // have an L2 address. This was not caught until recently, because this is
    // only enforced as a debug assert in the kernel.
    let mac = EtherAddr::from([0xa8, 0x40, 0x25, 0xff, 0x00, 0x00]);
    let muh = mch.add_unicast(mac).map_err(|e| OpteError::System {
        errno: EFAULT,
        msg: format!("mac_unicast_add failed for {link_name}: {e}"),
    })?;

    Ok(xde_underlay_port {
        name: link_name,
        mac: mh.get_mac_addr(),
        mh,
        mch,
        mph,
        muh,
    })
}

#[no_mangle]
unsafe fn init_underlay_ingress_handlers(
    u1_name: String,
    u2_name: String,
) -> Result<UnderlayState, OpteError> {
    let u1 = Arc::new(create_underlay_port(u1_name, "xdeu0")?);
    let u2 = Arc::new(create_underlay_port(u2_name, "xdeu1")?);
    Ok(UnderlayState { u1, u2 })
}

#[no_mangle]
unsafe fn driver_prop_exists(dip: *mut dev_info, pname: &str) -> bool {
    let name = match CString::new(pname) {
        Ok(s) => s,
        Err(e) => {
            warn!("bad driver prop string name: {}: {:?}", pname, e);
            return false;
        }
    };

    let ret = ddi_prop_exists(
        DDI_DEV_T_ANY,
        dip,
        DDI_PROP_DONTPASS,
        name.as_ptr() as *const c_char,
    );

    ret == 1
}

#[no_mangle]
unsafe fn get_driver_prop_bool(
    dip: *mut dev_info,
    pname: &str,
) -> Option<bool> {
    let name = match CString::new(pname) {
        Ok(s) => s,
        Err(e) => {
            warn!("bad driver prop string name: {}: {:?}", pname, e);
            return None;
        }
    };

    let ret = ddi_prop_get_int(
        DDI_DEV_T_ANY,
        dip,
        DDI_PROP_DONTPASS,
        name.as_ptr() as *const c_char,
        99,
    );

    // Technically, the system could also return DDI_PROP_NOT_FOUND,
    // which indicates the property cannot be decoded as an int.
    // However, DDI_PROP_NOT_FOUND has a value of 1, which is totally
    // broken given that 1 is a perfectly reasonable value for someone
    // to want to use for their property. This means that from the
    // perspective of the driver there is no way to differentiate
    // between a true value of 1 and the case where the user entered
    // gibberish. In this case we treat gibberish as true.
    if ret == 99 {
        warn!("driver prop {} not found", pname);
        return None;
    }

    Some(ret == 1)
}

#[no_mangle]
unsafe fn get_driver_prop_string(
    dip: *mut dev_info,
    pname: &str,
) -> Option<String> {
    let name = match CString::new(pname) {
        Ok(s) => s,
        Err(e) => {
            warn!("bad driver prop string name: {}: {:?}", pname, e);
            return None;
        }
    };

    let mut value: *const c_char = ptr::null();
    let ret = ddi_prop_lookup_string(
        DDI_DEV_T_ANY,
        dip,
        DDI_PROP_DONTPASS,
        name.as_ptr() as *const c_char,
        &mut value,
    );
    if ret != DDI_PROP_SUCCESS {
        warn!("failed to get driver property {}", pname);
        return None;
    }
    let s = CStr::from_ptr(value);
    let s = match s.to_str() {
        Ok(s) => s,
        Err(e) => {
            warn!(
                "failed to create string from property value for {}: {:?}",
                pname, e
            );
            return None;
        }
    };
    Some(s.into())
}

#[no_mangle]
unsafe extern "C" fn xde_detach(
    _dip: *mut dev_info,
    cmd: ddi_detach_cmd_t,
) -> c_int {
    assert!(!xde_dip.is_null());

    match cmd {
        ddi_detach_cmd_t::DDI_DETACH => {}
        _ => return DDI_FAILURE,
    }

    if xde_devs.read().len() > 0 {
        warn!("failed to detach: outstanding ports");
        return DDI_FAILURE;
    }

    let rstate = ddi_get_driver_private(xde_dip);
    assert!(!rstate.is_null());
    let state = Box::from_raw(rstate as *mut XdeState);
    let underlay = state.underlay.into_inner();

    match underlay {
        Some(underlay) => {
            // There shouldn't be anymore refs to the underlay given we checked for
            // 0 ports above.
            let Ok(u1) = Arc::try_unwrap(underlay.u1) else {
                warn!("failed to detach: underlay u1 has outstanding refs");
                return DDI_FAILURE;
            };
            let Ok(u2) = Arc::try_unwrap(underlay.u2) else {
                warn!("failed to detach: underlay u2 has outstanding refs");
                return DDI_FAILURE;
            };

            for u in [u1, u2] {
                // Clear all Rx paths
                u.mch.clear_rx();

                // We have a chain of refs here:
                //  1. `MacPromiscHandle` holds a ref to `MacClientHandle`, and
                //  2. `MacUnicastHandle` holds a ref to `MacClientHandle`, and
                //  3. `MacClientHandle` holds a ref to `MacHandle`.
                // We explicitly drop them in order here to ensure there are no
                // outstanding refs.

                // 1. Remove promisc and unicast callbacks
                drop(u.mph);
                drop(u.muh);

                // 2. Remove MAC client handle
                if Arc::strong_count(&u.mch) > 1 {
                    warn!(
                        "underlay {} has outstanding mac client handle refs",
                        u.name
                    );
                    return DDI_FAILURE;
                }
                drop(u.mch);

                // Finally, we can cleanup the MAC handle for this underlay
                if Arc::strong_count(&u.mh) > 1 {
                    warn!(
                        "underlay {} has outstanding mac handle refs",
                        u.name
                    );
                    return DDI_FAILURE;
                }
                drop(u.mh);
            }
        }
        None => {}
    };

    // Remove control device
    ddi_remove_minor_node(xde_dip, XDE_STR);

    xde_dip = ptr::null_mut::<c_void>() as *mut dev_info;
    DDI_SUCCESS
}

#[no_mangle]
static mut xde_cb_ops: cb_ops = cb_ops {
    cb_open: xde_open,
    cb_close: xde_close,
    cb_strategy: nodev,
    cb_print: nodev,
    cb_dump: nodev,
    cb_read: nodev_read,
    cb_write: nodev_write,
    cb_ioctl: xde_ioctl,
    cb_devmap: nodev,
    cb_mmap: nodev,
    cb_segmap: nodev,
    cb_chpoll: nochpoll,
    cb_prop_op: ddi_prop_op,
    cb_str: ptr::null_mut::<c_void>() as *mut streamtab,
    cb_flag: D_MP,
    cb_rev: CB_REV,
    cb_aread: nodev,
    cb_awrite: nodev,
};

#[no_mangle]
static mut xde_devops: dev_ops = dev_ops {
    devo_rev: DEVO_REV,
    devo_refcnt: 0,
    devo_getinfo: xde_getinfo,
    devo_identify: nulldev_identify,
    devo_probe: nulldev_probe,
    devo_attach: xde_attach,
    devo_detach: xde_detach,
    devo_reset: nodev_reset,
    // Safety: Yes, this is a mutable static. No, there is no race as
    // it's mutated only during `_init()`. Yes, it needs to be mutable
    // to allow `dld_init_ops()` to set `cb_str`.
    devo_cb_ops: unsafe { &xde_cb_ops },
    devo_bus_ops: 0 as *const bus_ops,
    devo_power: nodev_power,
    devo_quiesce: ddi_quiesce_not_needed,
};

#[no_mangle]
static xde_modldrv: modldrv = unsafe {
    modldrv {
        drv_modops: &mod_driverops,
        drv_linkinfo: XDE_STR,
        drv_dev_ops: &xde_devops,
    }
};

#[no_mangle]
static xde_linkage: modlinkage = modlinkage {
    ml_rev: MODREV_1,
    ml_linkage: [
        (&xde_modldrv as *const modldrv).cast(),
        ptr::null(),
        ptr::null(),
        ptr::null(),
        ptr::null(),
        ptr::null(),
        ptr::null(),
    ],
};

#[no_mangle]
static mut xde_mac_callbacks: mac::mac_callbacks_t = mac::mac_callbacks_t {
    mc_callbacks: (mac::MC_GETCAPAB | mac::MC_PROPERTIES) as c_uint,
    mc_reserved: core::ptr::null_mut(),
    mc_getstat: xde_mc_getstat,
    mc_start: xde_mc_start,
    mc_stop: xde_mc_stop,
    mc_setpromisc: xde_mc_setpromisc,
    mc_multicst: xde_mc_multicst,
    mc_unicst: Some(xde_mc_unicst),
    mc_tx: Some(xde_mc_tx),
    mc_ioctl: None,
    mc_getcapab: Some(xde_mc_getcapab),
    mc_open: None,
    mc_close: None,
    mc_getprop: Some(xde_mc_getprop),
    mc_setprop: Some(xde_mc_setprop),
    mc_propinfo: Some(xde_mc_propinfo),
};

#[no_mangle]
unsafe extern "C" fn xde_mc_getstat(
    _arg: *mut c_void,
    _stat: c_uint,
    _val: *mut u64,
) -> c_int {
    ENOTSUP
}

// The mac framework calls this when the first client has opened the
// xde device. From ths point on we know that this port is in use and
// remains in use until `xde_mc_stop()` is called.
#[no_mangle]
unsafe extern "C" fn xde_mc_start(arg: *mut c_void) -> c_int {
    let dev = arg as *mut XdeDev;
    (*dev).port.start();
    0
}

// The mac framework calls this when the last client closes its handle
// to the device. At this point we know the port is no longer in use.
#[no_mangle]
unsafe extern "C" fn xde_mc_stop(arg: *mut c_void) {
    let dev = arg as *mut XdeDev;
    (*dev).port.reset();
}

#[no_mangle]
unsafe extern "C" fn xde_mc_setpromisc(
    _arg: *mut c_void,
    _val: boolean_t,
) -> c_int {
    0
}

#[no_mangle]
unsafe extern "C" fn xde_mc_multicst(
    _arg: *mut c_void,
    _add: boolean_t,
    _addrp: *const u8,
) -> c_int {
    ENOTSUP
}

#[no_mangle]
unsafe extern "C" fn xde_mc_unicst(
    arg: *mut c_void,
    macaddr: *const u8,
) -> c_int {
    let dev = arg as *mut XdeDev;
    (*dev)
        .port
        .mac_addr()
        .bytes()
        .copy_from_slice(core::slice::from_raw_parts(macaddr, 6));
    0
}

fn guest_loopback_probe(pkt: &Packet<Parsed>, src: &XdeDev, dst: &XdeDev) {
    use opte::engine::rule::flow_id_sdt_arg;

    let fid_arg = flow_id_sdt_arg::from(pkt.flow());

    unsafe {
        __dtrace_probe_guest__loopback(
            pkt.mblk_addr(),
            &fid_arg as *const flow_id_sdt_arg as uintptr_t,
            src.port.name_cstr().as_ptr() as uintptr_t,
            dst.port.name_cstr().as_ptr() as uintptr_t,
        )
    };
}

#[no_mangle]
fn guest_loopback(
    src_dev: &XdeDev,
    mut pkt: Packet<Parsed>,
    vni: Vni,
) -> *mut mblk_t {
    use Direction::*;
    let ether_dst = pkt.meta().inner.ether.dst;
    let devs = unsafe { xde_devs.read() };
    let maybe_dest_dev =
        devs.iter().find(|x| x.vni == vni && x.port.mac_addr() == ether_dst);

    match maybe_dest_dev {
        Some(dest_dev) => {
            guest_loopback_probe(&pkt, src_dev, dest_dev);

            // We have found a matching Port on this host; "loop back"
            // the packet into the inbound processing path of the
            // destination Port.
            match dest_dev.port.process(In, &mut pkt, ActionMeta::new()) {
                Ok(ProcessResult::Modified) => {
                    unsafe {
                        mac::mac_rx(
                            (*dest_dev).mh,
                            0 as *mut mac::mac_resource_handle,
                            pkt.unwrap_mblk(),
                        )
                    };
                    return ptr::null_mut();
                }

                Ok(ProcessResult::Drop { reason }) => {
                    opte::engine::dbg(format!(
                        "loopback rx drop: {:?}",
                        reason
                    ));
                    return ptr::null_mut();
                }

                Ok(ProcessResult::Hairpin(_hppkt)) => {
                    // There should be no reason for an loopback
                    // inbound packet to generate a hairpin response
                    // from the destination port.
                    opte::engine::dbg(format!(
                        "unexpected loopback rx hairpin"
                    ));
                    return ptr::null_mut();
                }

                Ok(ProcessResult::Bypass) => {
                    opte::engine::dbg(format!("loopback rx bypass"));
                    unsafe {
                        mac::mac_rx(
                            (*dest_dev).mh,
                            0 as *mut mac::mac_resource_handle,
                            pkt.unwrap_mblk(),
                        )
                    };
                    return ptr::null_mut();
                }

                Err(e) => {
                    opte::engine::dbg(format!(
                        "loopback port process error: {} -> {} {:?}",
                        src_dev.port.name(),
                        dest_dev.port.name(),
                        e
                    ));
                    return ptr::null_mut();
                }
            }
        }

        None => {
            opte::engine::dbg(format!(
                "underlay dest is same as src but the Port was not found \
                 vni = {}, mac = {}",
                vni.as_u32(),
                ether_dst
            ));
            return ptr::null_mut();
        }
    }
}

#[no_mangle]
unsafe extern "C" fn xde_mc_tx(
    arg: *mut c_void,
    mp_chain: *mut mblk_t,
) -> *mut mblk_t {
    // The device must be started before we can transmit.
    let src_dev = &*(arg as *mut XdeDev);

    // TODO I haven't dealt with chains, though I'm pretty sure it's
    // always just one.
    assert!((*mp_chain).b_next == ptr::null_mut());
    __dtrace_probe_tx(mp_chain as uintptr_t);

    // ================================================================
    // IMPORTANT: Packet now takes ownership of mp_chain. When Packet
    // is dropped so is the chain. Be careful with any calls involving
    // mp_chain after this point. They should only be calls that read,
    // nothing that writes or frees. But really you should think of
    // mp_chain as &mut and avoid any reference to it past this point.
    // Owernship is taken back by calling Packet::unwrap_mblk().
    //
    // XXX Make this fool proof by converting the mblk_t pointer to an
    // &mut or some smart pointer type that can be truly owned by the
    // Packet type. This way rustc gives us lifetime enforcement
    // instead of my code comments. But that work is more involved
    // than the immediate fix that needs to happen.
    // ================================================================
    let parser = src_dev.port.network().parser();
    let mut pkt =
        match Packet::wrap_mblk_and_parse(mp_chain, Direction::Out, parser) {
            Ok(pkt) => pkt,
            Err(e) => {
                // TODO Add bad packet stat.
                //
                // NOTE: We are using mp_chain as read only here to get
                // the pointer value so that the DTrace consumer can
                // examine the packet on failure.
                bad_packet_parse_probe(
                    Some(src_dev.port.name_cstr()),
                    Direction::Out,
                    mp_chain,
                    &e,
                );
                opte::engine::dbg(format!("Tx bad packet: {:?}", e));
                return ptr::null_mut();
            }
        };

    // Choose u1 as a starting point. This may be changed in the next_hop
    // function when we are actually able to determine what interface should be
    // used.
    let mch = &src_dev.u1.mch;
    let hint = 0;

    // Send straight to underlay in passthrough mode.
    if src_dev.passthrough {
        // TODO We need to deal with flow control. This could actually
        // get weird, this is the first provider to use mac_tx(). Is
        // there something we can learn from aggr here? I need to
        // refresh my memory on all of this.
        //
        // TODO Is there way to set mac_tx to must use result?
        mch.tx_drop_on_no_desc(pkt, hint, MacTxFlags::empty());
        return ptr::null_mut();
    }

    let port = &src_dev.port;

    // The port processing code will fire a probe that describes what
    // action was taken -- there should be no need to add probes or
    // prints here.
    let res = port.process(Direction::Out, &mut pkt, ActionMeta::new());
    match res {
        Ok(ProcessResult::Modified) => {
            let meta = pkt.meta();

            // If the outer IPv6 destination is the same as the
            // source, then we need to loop the packet inbound to the
            // guest on this same host.
            let ip = match meta.outer.ip {
                Some(v) => v,
                None => {
                    // XXX add SDT probe
                    // XXX add stat
                    opte::engine::dbg(format!("no outer ip header, dropping"));
                    return ptr::null_mut();
                }
            };

            let ip6 = match ip.ip6() {
                Some(v) => v,
                None => {
                    opte::engine::dbg(format!(
                        "outer IP header is not v6, dropping"
                    ));
                    return ptr::null_mut();
                }
            };

            let vni = match meta.outer.encap {
                Some(EncapMeta::Geneve(geneve)) => geneve.vni,
                None => {
                    // XXX add SDT probe
                    // XXX add stat
                    opte::engine::dbg(format!("no geneve header, dropping"));
                    return ptr::null_mut();
                }
            };

            if ip6.dst == ip6.src {
                return guest_loopback(src_dev, pkt, vni);
            }

            // Currently the overlay layer leaves the outer frame
            // destination and source zero'd. Ask IRE for the route
            // associated with the underlay destination. Then ask NCE
            // for the mac associated with the IRE nexthop to fill in
            // the outer frame of the packet. Also return the underlay
            // device associated with the nexthop
            let (src, dst, underlay_dev) = next_hop(&ip6.dst, src_dev);

            // Get a pointer to the beginning of the outer frame and
            // fill in the dst/src addresses before sending out the
            // device.
            let mblk = pkt.unwrap_mblk();
            let rptr = (*mblk).b_rptr as *mut u8;
            ptr::copy(dst.as_ptr(), rptr, 6);
            ptr::copy(src.as_ptr(), rptr.add(6), 6);
            // Unwrap: We know the packet is good because we just
            // unwrapped it above.
            let new_pkt = Packet::<Initialized>::wrap_mblk(mblk).unwrap();
            underlay_dev.mch.tx_drop_on_no_desc(
                new_pkt,
                hint,
                MacTxFlags::empty(),
            );
        }

        Ok(ProcessResult::Drop { .. }) => {
            return ptr::null_mut();
        }

        Ok(ProcessResult::Hairpin(hpkt)) => {
            mac::mac_rx(
                src_dev.mh,
                0 as *mut mac::mac_resource_handle,
                hpkt.unwrap_mblk(),
            );
        }

        Ok(ProcessResult::Bypass) => {
            mch.tx_drop_on_no_desc(pkt, hint, MacTxFlags::empty());
        }

        Err(_) => {}
    }

    // On return the Packet is dropped and its underlying mblk
    // segments are freed.
    ptr::null_mut()
}

/// This is a generic wrapper for references that should be dropped once not in
/// use.
struct DropRef<DropFn, Arg>
where
    DropFn: Fn(*mut Arg) -> (),
{
    /// A function to drop the reference.
    func: DropFn,
    /// The reference pointer.
    arg: *mut Arg,
}

impl<DropFn, Arg> DropRef<DropFn, Arg>
where
    DropFn: Fn(*mut Arg) -> (),
{
    /// Create a new `DropRef` for the provided reference argument. When this
    /// object is dropped, the provided `func` will be called.
    fn new(func: DropFn, arg: *mut Arg) -> Self {
        Self { func, arg }
    }

    /// Return a pointer to the underlying reference.
    fn inner(&self) -> *mut Arg {
        self.arg
    }
}

impl<DropFn, Arg> Drop for DropRef<DropFn, Arg>
where
    DropFn: Fn(*mut Arg) -> (),
{
    /// Call the cleanup function on the reference argument when we are dropped.
    fn drop(&mut self) {
        if !self.arg.is_null() {
            (self.func)(self.arg);
        }
    }
}

// The following are wrappers for reference drop functions used in XDE.

fn ire_refrele(ire: *mut ip::ire_t) {
    unsafe { ip::ire_refrele(ire) }
}

fn nce_refrele(ire: *mut ip::nce_t) {
    unsafe { ip::nce_refrele(ire) }
}

fn netstack_rele(ns: *mut ip::netstack_t) {
    unsafe { ip::netstack_rele(ns) }
}

// At this point the core engine of OPTE has delivered a Geneve
// encapsulated guest Ethernet Frame (also simply referred to as "the
// packet") to xde to be sent to the specific outer IPv6 destination
// address. This packet includes the outer Ethernet Frame as well;
// however, the outer frame's destination and source addresses are set
// to zero. It is the job of this function to determine what those
// values should be.
//
// Adjacent to xde is the native IPv6 stack along with its routing
// table. This table is routinely updated to indicate the best path to
// any given IPv6 destination that may be specified in the outer IP
// header. As xde is not utilizing the native IPv6 stack to send out
// the packet, but rather is handing it directly to the mac module, it
// must somehow query the native routing table to determine which port
// this packet should egress and fill in the outer frame accordingly.
// This query is done via a private interface which allows a kernel
// module outside of IP to query the routing table.
//
// This process happens in a sequence of steps described below.
//
// 1. With an IPv6 destination in hand we need to determine the next
//    hop, also known as the gateway, for this address. That is, of
//    our neighbors (in this case one of the two switches, which are
//    also acting as routers), who should we forward this packet to in
//    order for it to arrive at its destination? We get this
//    information from the routing table, which contains Internet
//    Routing Entries, or IREs. Specifically, we query the native IPv6
//    routing table using the kernel function
//    `ire_ftable_lookup_simple_v6()`. This function returns an
//    `ire_t`, which includes the member `ire_u`, which contains the
//    address of the gateway as `ire6_gateway_addr`.
//
// 2. We have the gateway IPv6 address; but in the world of the Oxide
//    Network that is not enough to deliver the packet. In the Oxide
//    Network the router (switch) is not a member of the host's
//    network. Instead, we rely on link-local addresses to reach the
//    switches. The lookup in step (1) gave us that link-local address
//    of the gateway; now we need to figure out how to reach it. That
//    requires consulting the routing table a second time: this time
//    to find the IRE for the gateway's link-local address.
//
// 3. The IRE of the link-local address from step (2) allows us to
//    determine which interface this traffic should traverse.
//    Specifically it gives us access to the `ill_t` of the gateway's
//    link-local address. This structure contains the IP Lower Level
//    information. In particular it contains the `ill_phys_addr`
//    which gives us the source MAC address for our outer frame.
//
// 4. The final piece of information to obtain is the destination MAC
//    address. We have the link-local address of the switch port we
//    want to send to. To get the MAC address of this port it must
//    first be assumed that the host and its connected switches have
//    performed NDP in order to learn each other's IPv6 addresses and
//    corresponding MAC addresses. With that information in hand it is
//    a matter of querying the kernel's Neighbor Cache Entry Table
//    (NCE) for the mapping that belongs to our gateway's link-local
//    address. This is done via the `nce_lookup_v6()` kernel function.
//
// With those four steps we have obtained the source and destination
// MAC addresses and the packet can be sent to mac to be delivered to
// the underlying NIC. However, the careful reader may find themselves
// confused about how step (1) actually works.
//
//   If step (1) always returns a single gateway, then how do we
//   actually utilize both NICs/switches?
//
// This is where a bit of knowledge about routing tables comes into
// play along with our very own Delay Driven Multipath in-rack routing
// protocol. You might imagine the IPv6 routing table on an Oxide Sled
// looking something like this.
//
// Destination/Mask             Gateway                 Flags  If
// ----------------          -------------------------  ----- ---------
// default                   fe80::<sc1_p5>             UG     cxgbe0
// default                   fe80::<sc1_p6>             UG     cxgbe1
// fe80::/10                 fe80::<sc1_p5>             U      cxgbe0
// fe80::/10                 fe80::<sc1_p6>             U      cxgbe1
// fd00:<rack1_sled1>::/64   fe80::<sc1_p5>             U      cxgbe0
// fd00:<rack1_sled1>::/64   fe80::<sc1_p6>             U      cxgbe1
//
// Let's say this host (sled1) wants to send a packet to sled2. Our
// sled1 host lives on network `fd00:<rack1_sled1>::/64` while our
// sled2 host lives on `fd00:<rack1_seld2>::/64` -- the key point
// being they are two different networks and thus must be routed to
// talk to each other. For sled1 to send this packet it will attempt
// to look up destination `fd00:<rack1_sled2>::7777` (in this case
// `7777` is the IP of sled2) in the routing table above. The routing
// table will then perform a longest prefix match against the
// `Destination` field for all entries: the longest prefix that
// matches wins and that entry is returned. However, in this case, no
// destinations match except for the `default` ones. When more than
// one entry matches it is left to the system to decide which one to
// return; typically this just means the first one that matches. But
// not for us! This is where DDM comes into play.
//
// Let's reimagine the routing table again, this time with a
// probability added to each gateway entry.
//
// Destination/Mask             Gateway                 Flags  If      P
// ----------------          -------------------------  ----- ------- ----
// default                   fe80::<sc1_p5>             UG     cxgbe0  0.70
// default                   fe80::<sc1_p6>             UG     cxgbe1  0.30
// fe80::/10                 fe80::<sc1_p5>             U      cxgbe0
// fe80::/10                 fe80::<sc1_p6>             U      cxgbe1
// fd00:<rack1_sled1>::/64   fe80::<sc1_p5>             U      cxgbe0
// fd00:<rack1_sled1>::/64   fe80::<sc1_p6>             U      cxgbe1
//
// With these P values added we now have a new option for deciding
// which IRE to return when faced with two matches: give each a
// probability of return based on their P value. In this case, for any
// given gateway IRE lookup, there would be a 70% chance
// `fe80::<sc1_p5>` is returned and a 30% chance `fe80::<sc1_p6>` is
// returned.
//
// But wait, what determines those P values? That's the job of DDM.
// The full story of what DDM is and how it works is outside the scope
// of this already long block comment; but suffice to say it monitors
// the flow of the network based on precise latency measurements and
// with that data constantly refines the P values of all the hosts's
// routing tables to bias new packets towards one path or another.
#[no_mangle]
fn next_hop<'a>(
    ip6_dst: &Ipv6Addr,
    ustate: &'a XdeDev,
) -> (EtherAddr, EtherAddr, &'a xde_underlay_port) {
    unsafe {
        // Use the GZ's routing table.
        let netstack =
            DropRef::new(netstack_rele, ip::netstack_find_by_zoneid(0));
        assert!(!netstack.inner().is_null());
        let ipst = (*netstack.inner()).netstack_u.nu_s.nu_ip;
        assert!(!ipst.is_null());

        let addr = ip::in6_addr_t {
            _S6_un: ip::in6_addr__bindgen_ty_1 { _S6_u8: ip6_dst.bytes() },
        };
        let xmit_hint = 0;
        let mut generation_op = 0u32;

        let mut underlay_port = &*ustate.u1;

        // Step (1): Lookup the IRE for the destination. This is going
        // to return one of the default gateway entries.
        let ire = DropRef::new(
            ire_refrele,
            ip::ire_ftable_lookup_simple_v6(
                &addr,
                xmit_hint,
                ipst,
                &mut generation_op as *mut ip::uint_t,
            ),
        );

        // TODO If there is no entry should we return host
        // unreachable? I'm not sure since really the guest would map
        // that with its VPC network. That is, if a user saw host
        // unreachable they would be correct to think that their VPC
        // routing table is misconfigured, but in reality it would be
        // an underlay network issue. How do we convey this situation
        // to the user/operator?
        if ire.inner().is_null() {
            opte::engine::dbg(format!("no IRE for destination {:?}", ip6_dst));
            next_hop_probe(
                ip6_dst,
                None,
                EtherAddr::zero(),
                EtherAddr::zero(),
                b"no IRE for destination\0",
            );
            return (EtherAddr::zero(), EtherAddr::zero(), underlay_port);
        }
        let ill = (*ire.inner()).ire_ill;
        if ill.is_null() {
            opte::engine::dbg(format!(
                "destination ILL is NULL for {:?}",
                ip6_dst
            ));
            next_hop_probe(
                ip6_dst,
                None,
                EtherAddr::zero(),
                EtherAddr::zero(),
                b"destination ILL is NULL\0",
            );
            return (EtherAddr::zero(), EtherAddr::zero(), underlay_port);
        }

        // Step (2): Lookup the IRE for the gateway's link-local
        // address. This is going to return one of the `fe80::/10`
        // entries.
        let ireu = (*ire.inner()).ire_u;
        let gw = ireu.ire6_u.ire6_gateway_addr;
        let gw_ip6 = Ipv6Addr::from(&ireu.ire6_u.ire6_gateway_addr);

        // NOTE: specifying the ill is important here, because the gateway
        // address is going to be of the form fe80::<interface-id>. This means a
        // simple query that does not specify an ill could come back with any
        // route matching fe80::/10 over any interface. Since all interfaces
        // that have an IPv6 link-local address assigned have an associated
        // fe80::/10 route, we must restrict our search to the interface that
        // actually has a route to the desired (non-link-local) destination.
        let flags = ip::MATCH_IRE_ILL as i32;
        let gw_ire = DropRef::new(
            ire_refrele,
            ip::ire_ftable_lookup_v6(
                &gw,
                ptr::null(),
                ptr::null(),
                0,
                ill,
                sys::ALL_ZONES,
                ptr::null(),
                flags,
                xmit_hint,
                ipst,
                &mut generation_op as *mut ip::uint_t,
            ),
        );

        if gw_ire.inner().is_null() {
            opte::engine::dbg(format!("no IRE for gateway {:?}", gw_ip6));
            next_hop_probe(
                ip6_dst,
                Some(&gw_ip6),
                EtherAddr::zero(),
                EtherAddr::zero(),
                b"no IRE for gateway\0",
            );
            return (EtherAddr::zero(), EtherAddr::zero(), underlay_port);
        }

        // Step (3): Determine the source address of the outer frame
        // from the physical address of the IP Lower Layer object
        // member or the internet routing entry.
        let src = (*ill).ill_phys_addr;
        if src.is_null() {
            opte::engine::dbg(format!(
                "gateway ILL phys addr is NULL for {:?}",
                gw_ip6
            ));
            next_hop_probe(
                ip6_dst,
                Some(&gw_ip6),
                EtherAddr::zero(),
                EtherAddr::zero(),
                b"gateway ILL phys addr is NULL\0",
            );
            return (EtherAddr::zero(), EtherAddr::zero(), underlay_port);
        }

        let src: [u8; 6] = alloc::slice::from_raw_parts(src, 6)
            .try_into()
            .expect("src mac from pointer");

        // Switch to the 2nd underlay device if we determine the source mac
        // belongs to that device.
        if src == ustate.u2.mac {
            underlay_port = &ustate.u2;
        }

        let src = EtherAddr::from(src);

        // Step (4): Determine the destination address of the outer
        // frame by retrieving the NCE entry for the gateway's
        // link-local address.
        let nce = DropRef::new(nce_refrele, ip::nce_lookup_v6(ill, &gw));
        if nce.inner().is_null() {
            opte::engine::dbg(format!("no NCE for gateway {:?}", gw_ip6));
            next_hop_probe(
                ip6_dst,
                Some(&gw_ip6),
                src,
                EtherAddr::zero(),
                b"no NCE for gateway\0",
            );
            return (EtherAddr::zero(), EtherAddr::zero(), underlay_port);
        }

        let nce_common = (*nce.inner()).nce_common;
        if nce_common.is_null() {
            opte::engine::dbg(format!(
                "no NCE common for gateway {:?}",
                gw_ip6
            ));
            next_hop_probe(
                ip6_dst,
                Some(&gw_ip6),
                src,
                EtherAddr::zero(),
                b"no NCE common for gateway\0",
            );
            return (EtherAddr::zero(), EtherAddr::zero(), underlay_port);
        }

        let mac = (*nce_common).ncec_lladdr;
        if mac.is_null() {
            opte::engine::dbg(format!("NCE MAC address is NULL {:?}", gw_ip6));
            next_hop_probe(
                ip6_dst,
                Some(&gw_ip6),
                src,
                EtherAddr::zero(),
                b"NCE MAC address if NULL for gateway\0",
            );
            return (EtherAddr::zero(), EtherAddr::zero(), underlay_port);
        }

        let maclen = (*nce_common).ncec_lladdr_length;
        assert!(maclen == 6);

        let dst: [u8; 6] = alloc::slice::from_raw_parts(mac, 6)
            .try_into()
            .expect("mac from pointer");
        let dst = EtherAddr::from(dst);

        next_hop_probe(ip6_dst, Some(&gw_ip6), src, dst, b"\0");

        (src, dst, underlay_port)
    }
}

#[no_mangle]
unsafe extern "C" fn xde_mc_getcapab(
    _arg: *mut c_void,
    _cap: mac::mac_capab_t,
    _capb_data: *mut c_void,
) -> boolean_t {
    boolean_t::B_FALSE
}

#[no_mangle]
unsafe extern "C" fn xde_mc_setprop(
    _arg: *mut c_void,
    _prop_name: *const c_char,
    _prop_num: mac::mac_prop_id_t,
    _prop_val_size: c_uint,
    _prop_val: *const c_void,
) -> c_int {
    ENOTSUP
}

#[no_mangle]
unsafe extern "C" fn xde_mc_getprop(
    _arg: *mut c_void,
    _prop_name: *const c_char,
    _prop_num: mac::mac_prop_id_t,
    _prop_val_size: c_uint,
    _prop_val: *mut c_void,
) -> c_int {
    ENOTSUP
}

#[no_mangle]
unsafe extern "C" fn xde_mc_propinfo(
    _arg: *mut c_void,
    _prop_name: *const c_char,
    _prop_num: mac::mac_prop_id_t,
    _prh: *mut mac::mac_prop_info_handle,
) {
}

#[no_mangle]
fn new_port(
    name: String,
    cfg: &VpcCfg,
    vpc_map: Arc<overlay::VpcMappings>,
    v2p: Arc<overlay::Virt2Phys>,
    ectx: Arc<ExecCtx>,
) -> Result<Arc<Port<VpcNetwork>>, OpteError> {
    let name_cstr = match CString::new(name.as_str()) {
        Ok(v) => v,
        Err(_) => return Err(OpteError::BadName),
    };

    let mut pb = PortBuilder::new(&name, name_cstr, cfg.guest_mac.into(), ectx);
    firewall::setup(&mut pb, FW_FT_LIMIT)?;

    // XXX some layers have no need for LFT, perhaps have two types
    // of Layer: one with, one without?
    gateway::setup(&mut pb, &cfg, vpc_map, FT_LIMIT_ONE)?;
    router::setup(&mut pb, &cfg, FT_LIMIT_ONE)?;
    let nat_ft_limit = match cfg.n_external_ports() {
        None => FT_LIMIT_ONE,
        Some(0) => return Err(OpteError::InvalidIpCfg),
        Some(n) => NonZeroU32::new(n).unwrap(),
    };
    nat::setup(&mut pb, &cfg, nat_ft_limit)?;
    overlay::setup(&pb, &cfg, v2p, FT_LIMIT_ONE)?;

    // Set the overall unified flow and TCP flow table limits based on the total
    // configuration above, by taking the maximum of size of the individual
    // layer tables. Only the firewall and NAT layers are relevant here, since
    // the others have a size of at most 1 now.
    //
    // Safety: We're extracting the contained value in a `NonZeroU32` to
    // construct a new one, so the unwrap is safe.
    let limit =
        NonZeroU32::new(FW_FT_LIMIT.get().max(nat_ft_limit.get())).unwrap();
    let net = VpcNetwork { cfg: cfg.clone() };
    Ok(Arc::new(pb.create(net, limit, limit)?))
}

#[no_mangle]
unsafe extern "C" fn xde_rx(
    arg: *mut c_void,
    mrh: *mut mac::mac_resource_handle,
    mp_chain: *mut mblk_t,
    _is_loopback: boolean_t,
) {
    // XXX Need to deal with chains. This was an assert but it's
    // blocking other work that's more pressing at the moment as I
    // keep tripping it.
    if !(*mp_chain).b_next.is_null() {
        __dtrace_probe_rx__chain__todo(mp_chain as uintptr_t);
    }
    __dtrace_probe_rx(mp_chain as uintptr_t);

    // Safety: This arg comes from `Arc::as_ptr()` on the `MacClientHandle`
    // corresponding to the underlay port we're receiving on. Being
    // here in the callback means the `MacPromiscHandle` hasn't been
    // dropped yet and thus our `MacClientHandle` is also still valid.
    let mch_ptr = arg as *const MacClientHandle;
    Arc::increment_strong_count(mch_ptr);
    let mch = Arc::from_raw(mch_ptr);

    // We must first parse the packet in order to determine where it
    // is to be delivered.
    let parser = VpcParser {};
    let mut pkt =
        match Packet::wrap_mblk_and_parse(mp_chain, Direction::In, parser) {
            Ok(pkt) => pkt,
            Err(e) => {
                // TODO Add bad packet stat.
                //
                // NOTE: We are using mp_chain as read only here to get
                // the pointer value so that the DTrace consumer can
                // examine the packet on failure.
                //
                // We don't know the port yet, thus the None.
                bad_packet_parse_probe(None, Direction::In, mp_chain, &e);
                opte::engine::dbg(format!("Rx bad packet: {:?}", e));
                return;
            }
        };

    let meta = pkt.meta();
    let devs = xde_devs.read();

    // Determine where to send packet based on Geneve VNI and
    // destination MAC address.
    let geneve = match meta.outer.encap {
        Some(EncapMeta::Geneve(geneve)) => geneve,
        None => {
            // TODO add stat
            let msg = "no geneve header, dropping";
            bad_packet_probe(None, Direction::In, mp_chain, msg);
            opte::engine::dbg(format!("{}", msg));
            return;
        }
    };

    let vni = geneve.vni;
    let ether_dst = meta.inner.ether.dst;
    let dev = match devs
        .iter()
        .find(|x| x.vni == vni && x.port.mac_addr() == ether_dst)
    {
        Some(dev) => dev,
        None => {
            // TODO add SDT probe
            // TODO add stat
            opte::engine::dbg(format!(
                "[encap] no device found for vni: {} mac: {}",
                vni, ether_dst
            ));
            return;
        }
    };

    // We are in passthrough mode, skip OPTE processing.
    if (*dev).passthrough {
        mac::mac_rx((*dev).mh, mrh, mp_chain);
        return;
    }

    let port = &(*dev).port;
    let res = port.process(Direction::In, &mut pkt, ActionMeta::new());
    match res {
        Ok(ProcessResult::Modified) => {
            mac::mac_rx((*dev).mh, mrh, pkt.unwrap_mblk());
        }
        Ok(ProcessResult::Hairpin(hppkt)) => {
            mch.tx_drop_on_no_desc(hppkt, 0, MacTxFlags::empty());
        }
        Ok(ProcessResult::Bypass) => {
            mac::mac_rx((*dev).mh, mrh, mp_chain);
        }
        _ => {}
    }
}

#[no_mangle]
fn add_router_entry_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: AddRouterEntryReq = env.copy_in_req()?;
    let devs = unsafe { xde_devs.read() };
    let mut iter = devs.iter();
    let dev = match iter.find(|x| x.devname == req.port_name) {
        Some(dev) => dev,
        None => return Err(OpteError::PortNotFound(req.port_name)),
    };

    router::add_entry(&dev.port, req.dest.into(), req.target.into())
}

#[no_mangle]
fn add_fw_rule_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: AddFwRuleReq = env.copy_in_req()?;
    let devs = unsafe { xde_devs.read() };
    let mut iter = devs.iter();
    let dev = match iter.find(|x| x.devname == req.port_name) {
        Some(dev) => dev,
        None => return Err(OpteError::PortNotFound(req.port_name)),
    };

    firewall::add_fw_rule(&dev.port, &req)?;
    Ok(NoResp::default())
}

#[no_mangle]
fn rem_fw_rule_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: RemFwRuleReq = env.copy_in_req()?;
    let devs = unsafe { xde_devs.read() };
    let mut iter = devs.iter();
    let dev = match iter.find(|x| x.devname == req.port_name) {
        Some(dev) => dev,
        None => return Err(OpteError::PortNotFound(req.port_name)),
    };

    firewall::rem_fw_rule(&dev.port, &req)?;
    Ok(NoResp::default())
}

#[no_mangle]
fn set_fw_rules_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: SetFwRulesReq = env.copy_in_req()?;
    let devs = unsafe { xde_devs.read() };
    let mut iter = devs.iter();
    let dev = match iter.find(|x| x.devname == req.port_name) {
        Some(dev) => dev,
        None => return Err(OpteError::PortNotFound(req.port_name)),
    };

    firewall::set_fw_rules(&dev.port, &req)?;
    Ok(NoResp::default())
}

#[no_mangle]
fn set_v2p_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: SetVirt2PhysReq = env.copy_in_req()?;
    let state = get_xde_state();
    state.vpc_map.add(req.vip, req.phys);
    Ok(NoResp::default())
}

#[no_mangle]
fn dump_v2p_hdlr(
    env: &mut IoctlEnvelope,
) -> Result<overlay::DumpVirt2PhysResp, OpteError> {
    let _req: overlay::DumpVirt2PhysReq = env.copy_in_req()?;
    let state = get_xde_state();
    Ok(state.vpc_map.dump())
}

#[no_mangle]
fn list_layers_hdlr(
    env: &mut IoctlEnvelope,
) -> Result<api::ListLayersResp, OpteError> {
    let req: api::ListLayersReq = env.copy_in_req()?;
    let devs = unsafe { xde_devs.read() };
    let mut iter = devs.iter();
    let dev = match iter.find(|x| x.devname == req.port_name) {
        Some(dev) => dev,
        None => return Err(OpteError::PortNotFound(req.port_name)),
    };

    Ok(dev.port.list_layers())
}

#[no_mangle]
fn clear_uft_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: api::ClearUftReq = env.copy_in_req()?;
    let devs = unsafe { xde_devs.read() };
    let mut iter = devs.iter();
    let dev = match iter.find(|x| x.devname == req.port_name) {
        Some(dev) => dev,
        None => return Err(OpteError::PortNotFound(req.port_name)),
    };

    dev.port.clear_uft()?;
    Ok(NoResp::default())
}

#[no_mangle]
fn dump_uft_hdlr(
    env: &mut IoctlEnvelope,
) -> Result<api::DumpUftResp, OpteError> {
    let req: api::DumpUftReq = env.copy_in_req()?;
    let devs = unsafe { xde_devs.read() };
    let mut iter = devs.iter();
    let dev = match iter.find(|x| x.devname == req.port_name) {
        Some(dev) => dev,
        None => return Err(OpteError::PortNotFound(req.port_name)),
    };

    dev.port.dump_uft()
}

#[no_mangle]
fn dump_layer_hdlr(
    env: &mut IoctlEnvelope,
) -> Result<api::DumpLayerResp, OpteError> {
    let req: api::DumpLayerReq = env.copy_in_req()?;
    let devs = unsafe { xde_devs.read() };
    let mut iter = devs.iter();
    let dev = match iter.find(|x| x.devname == req.port_name) {
        Some(dev) => dev,
        None => return Err(OpteError::PortNotFound(req.port_name)),
    };

    api::dump_layer(&dev.port, &req)
}

#[no_mangle]
fn dump_tcp_flows_hdlr(
    env: &mut IoctlEnvelope,
) -> Result<api::DumpTcpFlowsResp, OpteError> {
    let req: api::DumpTcpFlowsReq = env.copy_in_req()?;
    let devs = unsafe { xde_devs.read() };
    let mut iter = devs.iter();
    let dev = match iter.find(|x| x.devname == req.port_name) {
        Some(dev) => dev,
        None => return Err(OpteError::PortNotFound(req.port_name)),
    };

    api::dump_tcp_flows(&dev.port, &req)
}

#[no_mangle]
fn list_ports_hdlr() -> Result<ListPortsResp, OpteError> {
    let mut resp = ListPortsResp { ports: vec![] };
    let devs = unsafe { xde_devs.read() };
    for dev in devs.iter() {
        resp.ports.push(PortInfo {
            name: dev.port.name().to_string(),
            mac_addr: dev.port.mac_addr().into(),
            ip4_addr: dev.vpc_cfg.ipv4_cfg().map(|cfg| cfg.private_ip),
            external_ip4_addr: dev
                .vpc_cfg
                .ipv4_cfg()
                .map(|cfg| cfg.external_ips)
                .flatten(),
            ip6_addr: dev.vpc_cfg.ipv6_cfg().map(|cfg| cfg.private_ip),
            external_ip6_addr: dev
                .vpc_cfg
                .ipv6_cfg()
                .map(|cfg| cfg.external_ips)
                .flatten(),
            state: dev.port.state().to_string(),
        });
    }

    Ok(resp)
}

impl From<&crate::ip::in6_addr> for Ipv6Addr {
    fn from(in6: &crate::ip::in6_addr) -> Self {
        // Safety: We are reading from a [u8; 16] and interpreting the
        // value as [u8; 16].
        unsafe { Self::from(in6._S6_un._S6_u8) }
    }
}

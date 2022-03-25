//! XDE - A MAC provider for OPTE
//!
//! This is an illumos kernel driver that provides MAC devices hooked up to
//! OPTE. At the time of writing this driver is being developed in a parallel
//! crate to opte-drv. It's expected that this driver will merge into opte-drv.

// TODO
// - ddm integration to choose correct underlay device (currently just using
//   first device)

use core::convert::TryInto;
use core::ops::Range;
use core::ptr;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use illumos_ddi_dki as ddi;
use illumos_ddi_dki::*;

use crate::ioctl::IoctlEnvelope;
use crate::{dld, dls, ip, mac, secpolicy, sys, warn};
use opte_core::ether::EtherAddr;
use opte_core::geneve::Vni;
use opte_core::headers::{IpCidr, IpHdr};
use opte_core::ioctl::{
    self as api, CmdOk, CreateXdeReq, DeleteXdeReq, NoResp, OpteCmd, SnatCfg,
};
use opte_core::ip4::Ipv4Addr;
use opte_core::ip6::Ipv6Addr;
use opte_core::oxide_net::firewall::{AddFwRuleReq, RemFwRuleReq};
use opte_core::oxide_net::{overlay, router, PortCfg};
use opte_core::packet::{Initialized, Packet, ParseError, Parsed};
use opte_core::port::{Port, ProcessResult};
use opte_core::sync::{KRwLock, KRwLockType};
use opte_core::{CStr, CString, Direction, ExecCtx, OpteError};

/// The name of this driver.
const XDE_STR: *const c_char = b"xde\0".as_ptr() as *const c_char;

/// A list of xde devices instantiated through xde_ioc_create.
static mut xde_devs: KRwLock<Vec<Box<XdeDev>>> = KRwLock::new(Vec::new());

/// DDI dev info pointer to the attached xde device.
static mut xde_dip: *mut dev_info = 0 as *mut dev_info;

// This block is purely for SDT probes.
extern "C" {
    pub fn __dtrace_probe_bad__packet(mp: uintptr_t, msg: uintptr_t);
    pub fn __dtrace_probe_hdlr__resp(resp_str: uintptr_t);
    pub fn __dtrace_probe_rx(mp: uintptr_t);
    pub fn __dtrace_probe_rx__chain__todo(mp: uintptr_t);
    pub fn __dtrace_probe_tx(mp: uintptr_t);
}

fn bad_packet_probe(mp: uintptr_t, err: &ParseError) {
    let msg_arg = CString::new(format!("{:?}", err)).unwrap();
    unsafe { __dtrace_probe_bad__packet(mp, msg_arg.as_ptr() as uintptr_t) };
}

#[repr(u64)]
enum XdeDeviceFlags {
    Started = 1,
}

#[repr(C)]
#[derive(Clone)]
struct xde_underlay_port {
    name: String,
    mh: *mut mac::mac_handle,
    mch: *mut mac::mac_client_handle,
    mph: *mut mac::mac_promisc_handle,
}

struct XdeState {
    ectx: Arc<ExecCtx>,
    v2p: Arc<overlay::Virt2Phys>,

    // each xde driver has a handle to two underlay ports that are used for I/O
    // onto the underlay network
    u1: xde_underlay_port,
    u2: xde_underlay_port,
}

fn get_xde_state() -> &'static XdeState {
    // Safety: The opte_dip pointer is write-once and is a valid
    // pointer passed to attach(9E). The returned pointer is valid as
    // it was derived from Box::into_raw() during attach(9E).
    unsafe { &*(ddi_get_driver_private(xde_dip) as *mut XdeState) }
}

impl XdeState {
    fn new(underlay1: String, underlay2: String) -> Self {
        let ectx = Arc::new(ExecCtx { log: Box::new(opte_core::KernelLog {}) });
        XdeState {
            u1: xde_underlay_port {
                name: underlay1,
                mh: 0 as *mut mac::mac_handle,
                mch: 0 as *mut mac::mac_client_handle,
                mph: 0 as *mut mac::mac_promisc_handle,
            },
            u2: xde_underlay_port {
                name: underlay2,
                mh: 0 as *mut mac::mac_handle,
                mch: 0 as *mut mac::mac_client_handle,
                mph: 0 as *mut mac::mac_promisc_handle,
            },
            ectx,
            v2p: Arc::new(overlay::Virt2Phys::new()),
        }
    }
}

#[repr(C)]
struct XdeDev {
    devname: String,
    linkid: datalink_id_t,

    mh: *mut mac::mac_handle,

    flags: u64,
    link_state: mac::link_state_t,

    // opte port associated with this xde device
    port: Box<Port<opte_core::port::Active>>,
    port_cfg: PortCfg,

    // simply pass the packets through to the underlay devices, skipping
    // opte-core processing.
    passthrough: bool,

    vni: u32,

    // these are clones of the underlay ports initialized by the driver
    u1: xde_underlay_port,
    u2: xde_underlay_port,
}

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

#[no_mangle]
unsafe extern "C" fn xde_ioctl(
    _dev: dev_t,
    _cmd: c_int,
    _arg: intptr_t,
    _mode: c_int,
    _credp: *mut cred_t,
    _rvalp: *mut c_int,
) -> c_int {
    warn!("xde_ioctl not supported, use dld_ioc");
    ENOTSUP
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

// This is the entry point for all OPTE commands. It verifies the API
// version and then multiplexes the command to its appropriate handler.
#[no_mangle]
unsafe extern "C" fn xde_dld_ioc_opte_cmd(
    karg: *mut c_void,
    _arg: intptr_t,
    mode: c_int,
    _cred: *mut cred_t,
    _rvalp: *mut c_int,
) -> c_int {
    let ioctl: &mut api::OpteCmdIoctl = &mut *(karg as *mut api::OpteCmdIoctl);
    let mut env = match IoctlEnvelope::wrap(ioctl, mode) {
        Ok(v) => v,
        Err(errno) => return errno,
    };

    match env.ioctl_cmd() {
        OpteCmd::ListPorts => {
            let resp = list_ports_hdlr(&mut env);
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

        OpteCmd::CreateXde => {
            let resp = create_xde_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::DeleteXde => {
            let resp = delete_xde_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::DumpLayer => {
            let resp = dump_layer_hdlr(&mut env);
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
            let resp = list_v2p_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::SetVirt2Phys => {
            let resp = set_v2p_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::AddRouterEntryIpv4 => {
            let resp = add_router_entry_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::DumpTcpFlows => {
            let resp = dump_tcp_flows_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }
    }
}

#[no_mangle]
fn create_xde(req: &CreateXdeReq) -> Result<NoResp, OpteError> {
    // TODO name validation
    // TODO check if xde is already in list before proceeding
    let state = get_xde_state();

    let (port, port_cfg) = new_port(
        req.xde_devname.clone(),
        req.private_ip,
        req.private_mac,
        req.gw_mac,
        req.gw_ip,
        req.boundary_services_addr,
        req.boundary_services_vni,
        req.src_underlay_addr,
        req.vpc_vni,
        state.ectx.clone(),
        None,
    )?;

    let mut xde = Box::new(XdeDev {
        devname: req.xde_devname.clone(),
        linkid: req.linkid,
        mh: 0 as *mut mac::mac_handle,
        flags: 0,
        link_state: mac::link_state_t::Down,
        port,
        port_cfg,
        passthrough: req.passthrough,
        vni: req.vpc_vni.value(),
        u1: state.u1.clone(),
        u2: state.u2.clone(),
    });

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

    let mut devs = unsafe { xde_devs.write() };
    devs.push(xde);
    Ok(NoResp::default())
}

#[no_mangle]
fn delete_xde(req: &DeleteXdeReq) -> Result<NoResp, OpteError> {
    let mut devs = unsafe { xde_devs.write() };
    let index = match devs.iter().position(|x| x.devname == req.xde_devname) {
        Some(index) => index,
        None => return Err(OpteError::PortNotFound(req.xde_devname.clone())),
    };
    let xde = &mut devs[index];

    // destroy dls devnet device
    let ret = unsafe {
        dls::dls_devnet_destroy(xde.mh, &mut xde.linkid, boolean_t::B_TRUE)
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

    // unregister xde mac handle
    match unsafe { mac::mac_unregister(xde.mh) } {
        0 => {}
        err => {
            return Err(OpteError::System {
                errno: err,
                msg: format!("failed to unregister mac: {}", err),
            });
        }
    }

    // remove xde
    devs.remove(index);
    Ok(NoResp::default())
}

const IOCTL_SZ: usize = core::mem::size_of::<api::OpteCmdIoctl>();

static xde_ioc_list: [dld::dld_ioc_info_t; 1] = [dld::dld_ioc_info_t {
    di_cmd: opte_core::ioctl::XDE_DLD_OPTE_CMD as u32,
    di_flags: dld::DLDCOPYINOUT,
    di_argsize: IOCTL_SZ,
    di_func: xde_dld_ioc_opte_cmd,
    di_priv_func: secpolicy::secpolicy_dl_config,
}];

#[no_mangle]
unsafe extern "C" fn xde_attach(
    dip: *mut dev_info,
    cmd: ddi_attach_cmd_t,
) -> c_int {
    match cmd {
        ddi_attach_cmd_t::DDI_RESUME => return DDI_SUCCESS,
        ddi_attach_cmd_t::DDI_PM_RESUME => return DDI_SUCCESS,
        ddi_attach_cmd_t::DDI_ATTACH => {}
    }

    xde_dip = dip;

    let u1 = match get_driver_prop_string("underlay1") {
        Some(p) => p,
        None => {
            return DDI_FAILURE;
        }
    };

    let u2 = match get_driver_prop_string("underlay2") {
        Some(p) => p,
        None => {
            return DDI_FAILURE;
        }
    };

    warn!("dld_ioc_add: {:#?}", xde_ioc_list);

    match dld::dld_ioc_register(
        dld::XDE_IOC,
        xde_ioc_list.as_ptr(),
        xde_ioc_list.len() as u32,
    ) {
        0 => {}
        err => {
            warn!("dld_ioc_register failed: {}", err);
            return DDI_FAILURE;
        }
    }

    let mut state = XdeState::new(u1, u2);
    match init_underlay_ingress_handlers(&mut state) {
        ddi::DDI_SUCCESS => {}
        error => {
            dld::dld_ioc_unregister(dld::XDE_IOC);
            return error;
        }
    }

    let state = Box::new(state);
    ddi_set_driver_private(dip, Box::into_raw(state) as *mut c_void);

    return DDI_SUCCESS;
}

#[no_mangle]
unsafe fn init_underlay_ingress_handlers(state: &mut XdeState) -> c_int {
    // null terminated underlay device names

    let u1_devname = match CString::new(state.u1.name.as_str()) {
        Ok(s) => s,
        Err(e) => {
            warn!("bad u1 dev name: {:?}", e);
            return EINVAL;
        }
    };

    let u2_devname = match CString::new(state.u2.name.as_str()) {
        Ok(s) => s,
        Err(e) => {
            warn!("bad u2 dev name: {:?}", e);
            return EINVAL;
        }
    };

    // get mac handles for underlay ports

    match mac::mac_open_by_linkname(
        u1_devname.as_ptr() as *const c_char,
        &mut state.u1.mh,
    ) {
        0 => {}
        err => {
            let p = CStr::from_ptr(u1_devname.as_ptr() as *const c_char);
            warn!("failed to open underlay port 1: {:?}", p);
            return err;
        }
    }

    match mac::mac_open_by_linkname(
        u2_devname.as_ptr() as *const c_char,
        &mut state.u2.mh,
    ) {
        0 => {}
        err => {
            warn!("failed to open underlay port 2");
            return err;
        }
    }

    // get mac clients for underlay ports

    let mac_client_flags = mac::MAC_OPEN_FLAGS_NO_UNICAST_ADDR;

    match mac::mac_client_open(
        state.u1.mh,
        &mut state.u1.mch,
        b"xde\0" as *const u8 as *const c_char,
        mac_client_flags,
    ) {
        0 => {}
        err => {
            warn!("mac client open for u1 failed: {}", err);
            return err;
        }
    }

    match mac::mac_client_open(
        state.u2.mh,
        &mut state.u2.mch,
        b"xde\0" as *const u8 as *const c_char,
        mac_client_flags,
    ) {
        0 => {}
        err => {
            warn!("mac client open for u2 failed: {}", err);
            return err;
        }
    }

    // set up promisc rx handlers for underlay devices

    match mac::mac_promisc_add(
        state.u1.mch,
        mac::mac_client_promisc_type_t::MAC_CLIENT_PROMISC_ALL,
        xde_rx,
        ptr::null_mut(),
        &mut state.u1.mph,
        0,
    ) {
        0 => {}
        err => {
            warn!("mac promisc add u1 failed: {}", err);
            return err;
        }
    }

    /*
     * TODO: this - curently promisc RX is needed to get packets into the xde
     * device. Maybehapps setting something like MAC_OPEN_FLAGS_MULTI_PRIMARY
     * and doing a mac_unicast_add with MAC_UNICAST_PRIMARY would work?.
     *
    mac::mac_rx_set(
        state.u1.mch,
        xde_rx,
        ptr::null_mut(),
    );
     *
     */

    match mac::mac_promisc_add(
        state.u2.mch,
        mac::mac_client_promisc_type_t::MAC_CLIENT_PROMISC_ALL,
        xde_rx,
        ptr::null_mut(),
        &mut state.u2.mph,
        0,
    ) {
        0 => {}
        err => {
            warn!("mac promisc add u2 failed: {}", err);
            return err;
        }
    }
    /*
    mac::mac_rx_set(
        state.u2.mch,
        xde_rx,
        ptr::null_mut(),
    );
    */

    DDI_SUCCESS
}

#[no_mangle]
unsafe fn get_driver_prop_string(pname: &str) -> Option<String> {
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
        xde_dip,
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
    _cmd: ddi_detach_cmd_t,
) -> c_int {
    assert!(!xde_dip.is_null());

    let rstate = ddi_get_driver_private(xde_dip);
    assert!(!rstate.is_null());
    let state = &*(rstate as *mut XdeState);

    // mac rx clear for underlay devices
    mac::mac_rx_clear(state.u1.mch);
    mac::mac_rx_clear(state.u2.mch);
    mac::mac_promisc_remove(state.u1.mph);
    mac::mac_promisc_remove(state.u2.mph);

    // close mac client handle for underlay devices
    mac::mac_client_close(state.u1.mch, 0);
    mac::mac_client_close(state.u2.mch, 0);

    // close mac handle for underlay devices
    mac::mac_close(state.u1.mh);
    mac::mac_close(state.u2.mh);

    let _ = Box::from_raw(rstate as *mut XdeState);

    dld::dld_ioc_unregister(dld::XDE_IOC);
    xde_dip = ptr::null_mut::<c_void>() as *mut dev_info;
    0
}

#[no_mangle]
static mut xde_cb_ops: cb_ops = cb_ops {
    cb_open: nulldev_open,
    cb_close: nulldev_close,
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
    devo_getinfo: nodev_getinfo,
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
    mc_callbacks: (mac::MC_IOCTL
        | mac::MC_GETCAPAB
        | mac::MC_SETPROP
        | mac::MC_GETPROP
        | mac::MC_PROPINFO) as u32,
    mc_reserved: core::ptr::null_mut(),
    mc_getstat: xde_mc_getstat,
    mc_start: xde_mc_start,
    mc_stop: xde_mc_stop,
    mc_setpromisc: xde_mc_setpromisc,
    mc_multicst: xde_mc_multicst,
    mc_unicst: xde_mc_unicst,
    mc_tx: xde_mc_tx,
    mc_ioctl: xde_mc_ioctl,
    mc_getcapab: xde_mc_getcapab,
    mc_open: xde_mc_open,
    mc_close: xde_mc_close,
    mc_getprop: xde_mc_getprop,
    mc_setprop: xde_mc_setprop,
    mc_propinfo: xde_mc_propinfo,
};

#[no_mangle]
unsafe extern "C" fn xde_mc_getstat(
    _arg: *mut c_void,
    _stat: c_uint,
    _val: *mut u64,
) -> c_int {
    ENOTSUP
}

#[no_mangle]
unsafe extern "C" fn xde_mc_start(arg: *mut c_void) -> c_int {
    let dev = arg as *mut XdeDev;
    (*dev).flags |= XdeDeviceFlags::Started as u64;
    0
}

#[no_mangle]
unsafe extern "C" fn xde_mc_stop(arg: *mut c_void) {
    let dev = arg as *mut XdeDev;
    (*dev).flags ^= XdeDeviceFlags::Started as u64;
}

#[no_mangle]
unsafe extern "C" fn xde_mc_setpromisc(
    _arg: *mut c_void,
    _val: boolean_t,
) -> c_int {
    // TODO ... something?
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
        .to_bytes()
        .copy_from_slice(core::slice::from_raw_parts(macaddr, 6));
    0
}

#[no_mangle]
unsafe extern "C" fn xde_mc_tx(
    arg: *mut c_void,
    mp_chain: *mut mblk_t,
) -> *mut mblk_t {
    // The device must be started before we can transmit.
    let dev = arg as *mut XdeDev;
    if ((*dev).flags | XdeDeviceFlags::Started as u64) == 0 {
        // It's okay to call mac_drop_chain() here as we have not yet
        // handed ownership off to Packet.
        mac::mac_drop_chain(
            mp_chain,
            b"xde dev not ready\0".as_ptr() as *const c_char,
        );
        return ptr::null_mut();
    }

    // TODO I haven't dealt with chains, though I'm pretty sure it's
    // always just one.
    assert!((*mp_chain).b_next == ptr::null_mut());

    __dtrace_probe_tx(mp_chain as uintptr_t);

    // TODO Arbitrarily choose u1, later when we integrate with DDM
    // we'll have the information needed to make a real choice.
    let mch = (*dev).u1.mch;
    let hint = 0;
    let flags = mac::MAC_DROP_ON_NO_DESC;
    let ret_mp = ptr::null_mut();

    // Send straight to underlay in passthrough mode.
    if (*dev).passthrough {
        // TODO We need to deal with flow control. This could actually
        // get weird, this is the first provider to use mac_tx(). Is
        // there something we can learn from aggr here? I need to
        // refresh my memory on all of this.
        //
        // TODO Is there way to set mac_tx to must use result?
        //
        // TODO Bring in MacClient safe abstraction from opte-drv.
        mac::mac_tx(mch, mp_chain, hint, flags, ret_mp);
        return ptr::null_mut();
    }

    let port = &(*dev).port;

    // ================================================================
    // IMPORTANT: Packet now takes ownership of mp_chain. When Packet
    // is dropped so is the chain. Be careful with any calls involving
    // mp_chain after this point. They should only be calls that read,
    // nothing that writes or frees. But really you should think of
    // mp_chain as &mut and avoid any reference to it past this point.
    // If needed, owernship can be taken back by calling
    // Packet::unwrap().
    //
    // XXX Make this fool proof by converting the mblk_t pointer to an
    // &mut or some smart pointer type that can be truly owned by the
    // Packet type. This way rustc gives us lifetime enforcement
    // instead of my code comments. But that work is more involved
    // than the immediate fix that needs to happen.
    // ================================================================
    let mut pkt = match Packet::<Initialized>::wrap(mp_chain).parse() {
        Ok(pkt) => pkt,
        Err(e) => {
            // TODO Add bad packet stat.
            //
            // NOTE: We are using mp_chain as read only here to get
            // the pointer value so that the DTrace consumer can
            // examine the packet on failure.
            bad_packet_probe(mp_chain as uintptr_t, &e);
            // Let's be noisy about this for now to catch bugs.
            warn!("failed to parse packet: {:?}", e);
            return core::ptr::null_mut();
        }
    };

    // The port processing code will fire a probe that describes what
    // action was taken -- there should be no need to add probes or
    // prints here.
    let res = port.process(Direction::Out, &mut pkt);
    match res {
        Ok(ProcessResult::Modified) => {
            // Currently the overlay layer leaves the outer frame
            // destination and source zero'd. Ask IRE for the route
            // associated with the underlay destination. Then ask NCE
            // for the mac associated with the IRE nexthop to fill in
            // the outer frame of the packet.
            let (src, dst) = finish_outer_frame(&pkt);
            let mblk = pkt.unwrap();

            // Get a pointer to the beginning of the outer frame and
            // fill in the dst/src addresses before sending out the
            // device.
            let rptr = (*mblk).b_rptr as *mut u8;
            ptr::copy(dst.as_ptr(), rptr, 6);
            ptr::copy(src.as_ptr(), rptr.add(6), 6);
            mac::mac_tx(mch, mblk, hint, flags, ret_mp);
        }

        Ok(ProcessResult::Drop { .. }) => {
            return ptr::null_mut();
        }

        Ok(ProcessResult::Hairpin(hpkt)) => {
            mac::mac_rx(
                (*dev).mh,
                0 as *mut mac::mac_resource_handle,
                hpkt.unwrap(),
            );
        }

        Ok(ProcessResult::Bypass) => {
            mac::mac_tx(mch, pkt.unwrap(), hint, flags, ret_mp);
        }

        Err(_) => {}
    }

    // On return the Packet is dropped and its underlying mblk
    // segments are freed.
    ptr::null_mut()
}

#[no_mangle]
fn finish_outer_frame(pkt: &Packet<Parsed>) -> (EtherAddr, EtherAddr) {
    unsafe {
        let outer = match pkt.headers().outer {
            Some(ref outer) => outer,
            None => {
                warn!("no outer frame");
                return (EtherAddr::zero(), EtherAddr::zero());
            }
        };

        let ip6_hdr = match outer.ip {
            Some(IpHdr::Ip6(ref ip6_hdr)) => ip6_hdr,
            _ => {
                warn!("no outer ip");
                return (EtherAddr::zero(), EtherAddr::zero());
            }
        };

        // assuming global zone
        let netstack = ip::netstack_find_by_zoneid(0);
        assert!(!netstack.is_null());
        let ipst = (*netstack).netstack_u.nu_s.nu_ip;
        assert!(!ipst.is_null());

        let addr = ip::in6_addr_t {
            _S6_un: ip::in6_addr__bindgen_ty_1 {
                _S6_u8: ip6_hdr.dst().to_bytes(),
            },
        };
        let xmit_hint = 0;
        let mut generation_op = 0u32;

        // there are a few ways to go about looking up the mac, one obvious one
        // is ip2mac, however that function assumes we know what interface we
        // want to go out which in this case we do not as we are in a multipath
        // situation.
        let ire = ip::ire_ftable_lookup_simple_v6(
            &addr,
            xmit_hint,
            ipst,
            &mut generation_op as *mut ip::uint_t,
        );
        if ire.is_null() {
            warn!("no ire for {:?}", ip6_hdr.dst());
            return (EtherAddr::zero(), EtherAddr::zero());
        }

        // get the gateway address
        let ireu = (*ire).ire_u;
        // we asked for this from the v6 table so we can assume v6
        let gw = ireu.ire6_u.ire6_gateway_addr;

        // get the gateway ire
        let gw_ire = ip::ire_ftable_lookup_simple_v6(
            &gw,
            xmit_hint,
            ipst,
            &mut generation_op as *mut ip::uint_t,
        );
        if gw_ire.is_null() {
            warn!("no gw ire for {:?}", ip6_hdr.dst());
            return (EtherAddr::zero(), EtherAddr::zero());
        }

        // set the source address of the outer frame from the physical address
        // of the ip lower layer object member or the internet routing entry.
        let ill = (*gw_ire).ire_ill;
        if ill.is_null() {
            warn!("gw ill is null for {:?}", ip6_hdr.dst());
            return (EtherAddr::zero(), EtherAddr::zero());
        }
        let src = (*ill).ill_phys_addr;
        if src.is_null() {
            warn!("gw ill src is null for {:?}", ip6_hdr.dst());
            return (EtherAddr::zero(), EtherAddr::zero());
        }
        let src: [u8; 6] = alloc::slice::from_raw_parts(src, 6)
            .try_into()
            .expect("src mac from pointer");
        let src = EtherAddr::from(src);

        // find an nce entry for the gateway
        let nce = ip::nce_lookup_v6(ill, &gw);
        if nce.is_null() {
            warn!("no nce for {:?}", ip6_hdr.dst());
            return (EtherAddr::zero(), EtherAddr::zero());
        }
        let nce_common = (*nce).nce_common;
        if nce_common.is_null() {
            warn!("no nce common for {:?}", ip6_hdr.dst());
            return (EtherAddr::zero(), EtherAddr::zero());
        }
        let mac = (*nce_common).ncec_lladdr;
        if mac.is_null() {
            warn!("nce mac is null {:?}", ip6_hdr.dst());
            return (EtherAddr::zero(), EtherAddr::zero());
        }
        let maclen = (*nce_common).ncec_lladdr_length;
        assert!(maclen == 6);

        let dst: [u8; 6] = alloc::slice::from_raw_parts(mac, 6)
            .try_into()
            .expect("mac from pointer");
        let dst = EtherAddr::from(dst);

        (src, dst)
    }
}

#[no_mangle]
unsafe extern "C" fn xde_mc_ioctl(
    _arg: *mut c_void,
    _queue: *mut queue_t,
    _mp: *mut mblk_t,
) {
    warn!("call to unimplemented xde_mc_ioctl");
}

#[no_mangle]
unsafe extern "C" fn xde_mc_getcapab(
    _arg: *mut c_void,
    _cap: mac::mac_capab_t,
    _capb_data: *mut c_void,
) -> boolean_t {
    //TODO
    boolean_t::B_FALSE
}

unsafe extern "C" fn xde_mc_open(_arg: *mut c_void) -> c_int {
    0
}
unsafe extern "C" fn xde_mc_close(_arg: *mut c_void) {}

#[no_mangle]
unsafe extern "C" fn xde_mc_setprop(
    _arg: *mut c_void,
    _prop_name: *const c_char,
    _prop_num: mac::mac_prop_id_t,
    _prop_val_size: c_uint,
    _prop_val: *const c_void,
) -> c_int {
    //TODO
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
    //TODO
    ENOTSUP
}

#[no_mangle]
unsafe extern "C" fn xde_mc_propinfo(
    _arg: *mut c_void,
    _prop_name: *const c_char,
    _prop_num: mac::mac_prop_id_t,
    _prh: *mut mac::mac_prop_info_handle,
) {
    //TODO
}

#[no_mangle]
fn new_port(
    xde_dev_name: String,
    private_ip: Ipv4Addr,
    private_mac: EtherAddr,
    gateway_mac: EtherAddr,
    gateway_ip: Ipv4Addr,
    boundary_services_addr: Ipv6Addr,
    boundary_services_vni: Vni,
    src_underlay_addr: Ipv6Addr,
    vpc_vni: Vni,
    ectx: Arc<ExecCtx>,
    snat: Option<SnatCfg>,
) -> Result<(Box<Port<opte_core::port::Active>>, PortCfg), OpteError> {
    //TODO hardcode
    let vpc_subnet = if snat.is_none() {
        "192.168.77.0/24".parse().unwrap()
    } else {
        snat.as_ref().unwrap().vpc_sub4
    };
    let dyn_nat = match snat.as_ref() {
        None => {
            opte_core::oxide_net::DynNat4Cfg {
                //TODO hardcode
                public_ip: "192.168.99.99".parse().unwrap(),
                //TODO hardcode
                ports: Range { start: 999, end: 1000 },
            }
        }

        Some(snat) => opte_core::oxide_net::DynNat4Cfg {
            public_ip: snat.public_ip,
            ports: Range { start: snat.port_start, end: snat.port_end },
        },
    };
    let port_cfg = PortCfg {
        vpc_subnet,
        private_mac,
        private_ip: private_ip,
        gw_mac: gateway_mac,
        gw_ip: gateway_ip,
        dyn_nat,
        overlay: None,
    };
    let mut new_port = Port::new(&xde_dev_name, private_mac, ectx);
    opte_core::oxide_net::firewall::setup(&mut new_port)?;
    opte_core::oxide_net::dhcp4::setup(&mut new_port, &port_cfg)?;
    opte_core::oxide_net::icmp::setup(&mut new_port, &port_cfg)?;
    if snat.is_some() {
        opte_core::oxide_net::dyn_nat4::setup(&mut new_port, &port_cfg)?;
    }
    opte_core::oxide_net::arp::setup(&mut new_port, &port_cfg)?;
    router::setup(&mut new_port)?;

    let oc = overlay::OverlayCfg {
        boundary_services: overlay::PhysNet {
            ether: EtherAddr::from([0; 6]), //XXX this should not be needed
            ip: boundary_services_addr,
            vni: boundary_services_vni,
        },
        phys_ip_src: src_underlay_addr,
        vni: vpc_vni,
    };

    let state = get_xde_state();

    overlay::setup(&new_port, &oc, state.v2p.clone())?;
    let port = Box::new(new_port.activate());
    Ok((port, port_cfg))
}

#[no_mangle]
unsafe extern "C" fn xde_rx(
    _arg: *mut c_void,
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

    // first parse the packet so we can get at the geneve header
    let mut pkt = match Packet::<Initialized>::wrap(mp_chain).parse() {
        Ok(pkt) => pkt,
        Err(e) => {
            // TODO Add bad packet stat.
            //
            // NOTE: We are using mp_chain as read only here to get
            // the pointer value so that the DTrace consumer can
            // examine the packet on failure.
            bad_packet_probe(mp_chain as uintptr_t, &e);
            warn!("failed to parse packet: {:?}", e);
            return;
        }
    };

    let hdrs = pkt.headers();

    // determine where to send packet based on geneve vni
    let outer = match hdrs.outer {
        Some(ref outer) => outer,
        None => {
            // TODO add SDT probe
            // TODO add stat
            warn!("no outer header, dropping");
            return;
        }
    };

    let geneve = match outer.encap {
        Some(ref geneve) => geneve,
        None => {
            // TODO add SDT probe
            // TODO add stat
            warn!("no geneve header, dropping");
            return;
        }
    };

    //TODO create a fast lookup table
    let devs = xde_devs.read();
    let vni = geneve.vni.value();
    let ether_dst = hdrs.inner.ether.dst();
    let dev = match devs
        .iter()
        .find(|x| x.vni == vni && x.port.mac_addr() == ether_dst)
    {
        Some(dev) => dev,
        None => {
            // TODO add SDT probe
            // TODO add stat
            warn!("no device found for vni: {} mac: {}", vni, ether_dst);
            return;
        }
    };

    // just go straight to overlay in passthrough mode
    if (*dev).passthrough {
        mac::mac_rx((*dev).mh, mrh, mp_chain);
    }

    let port = &(*dev).port;
    let res = port.process(Direction::In, &mut pkt);
    match res {
        Ok(ProcessResult::Modified) => {
            warn!("rx accept");
            mac::mac_rx((*dev).mh, mrh, pkt.unwrap());
        }
        Ok(ProcessResult::Drop { reason }) => {
            warn!("rx drop: {:?}", reason);
        }
        Ok(ProcessResult::Hairpin(hppkt)) => {
            warn!("rx hairpin");
            // TODO assuming underlay device 1
            let mch = (*dev).u1.mch;
            let hint = 0;
            let flags = mac::MAC_DROP_ON_NO_DESC;
            let ret_mp = ptr::null_mut();
            mac::mac_tx(mch, hppkt.unwrap(), hint, flags, ret_mp);
        }
        Ok(ProcessResult::Bypass) => {
            warn!("rx bypass");
            mac::mac_rx((*dev).mh, mrh, mp_chain);
        }
        Err(e) => {
            warn!("opte-rx port process error: {:?}", e);
        }
    }
}

#[no_mangle]
fn add_router_entry_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: router::AddRouterEntryIpv4Req = env.copy_in_req()?;
    let devs = unsafe { xde_devs.read() };
    let mut iter = devs.iter();
    let dev = match iter.find(|x| x.devname == req.port_name) {
        Some(dev) => dev,
        None => return Err(OpteError::PortNotFound(req.port_name)),
    };

    router::add_entry_active(&dev.port, IpCidr::Ip4(req.dest), req.target)
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

    api::add_fw_rule(&dev.port, &req)?;
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

    api::rem_fw_rule(&dev.port, &req)?;
    Ok(NoResp::default())
}

#[no_mangle]
fn set_v2p_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: overlay::SetVirt2PhysReq = env.copy_in_req()?;
    let state = get_xde_state();
    state.v2p.set(req.vip, req.phys);
    Ok(NoResp::default())
}

#[no_mangle]
fn list_v2p_hdlr(
    env: &mut IoctlEnvelope,
) -> Result<overlay::DumpVirt2PhysResp, OpteError> {
    let _req: overlay::DumpVirt2PhysReq = env.copy_in_req()?;
    let state = get_xde_state();
    Ok(overlay::DumpVirt2PhysResp {
        ip4: state.v2p.ip4.lock().clone(),
        ip6: state.v2p.ip6.lock().clone(),
    })
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

    Ok(api::dump_uft(&dev.port, &req))
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

    Ok(api::dump_tcp_flows(&dev.port, &req))
}

#[no_mangle]
fn list_ports_hdlr(
    env: &mut IoctlEnvelope,
) -> Result<api::ListPortsResp, OpteError> {
    let _req: api::ListPortsReq = env.copy_in_req()?;
    let mut resp = api::ListPortsResp { ports: vec![] };

    let devs = unsafe { xde_devs.read() };
    for dev in devs.iter() {
        resp.ports.push(api::PortInfo {
            name: dev.port.name().to_string(),
            mac_addr: dev.port.mac_addr(),
            ip4_addr: dev.port_cfg.private_ip,
            in_use: false,
        });
    }

    Ok(resp)
}

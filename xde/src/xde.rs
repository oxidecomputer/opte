//! XDE - A MAC provider for OPTE
//!
//! This is an illumos kernel driver that provides MAC devices hooked up to
//! OPTE. At the time of writing this driver is being developed in a parallel
//! crate to opte-drv. It's expected that this driver will merge into opte-drv.

// TODO
// - ddm integration to choose correct underlay device (currently just using
//   first device)

use crate::{
    dld,
    dls,
    ioctl::{self, IoctlEnvelope, to_errno},
    mac,
    secpolicy,
    warn,
    ip,
};
use alloc::{
    boxed::Box,
    string::String,
    vec::Vec,
    sync::Arc
};
use core::{convert::{TryFrom, TryInto}, ops::Range, ptr};
extern crate opte_core;
use illumos_ddi_dki::*;
use illumos_ddi_dki as ddi;
use opte_core::{
    headers::{IpCidr, IpHdr},
    ether::EtherAddr,
    ioctl::{
        self as api,
        CreateXdeReq, DeleteXdeReq, IoctlCmd, SnatCfg, CmdOk, CmdErr, XdeError
    },
    ip4::Ipv4Addr,
    ip6::Ipv6Addr,
    oxide_net::{router, PortCfg, firewall::FwAddRuleReq, overlay},
    packet::{Initialized, Packet, Parsed},
    port::{Port, ProcessResult},
    geneve::{Vni},
    sync::{KRwLock, KRwLockType},
    CStr, CString, Direction, ExecCtx,
};

use serde::Serialize;

/// The name of this driver.
const XDE_STR: *const c_char = b"xde\0".as_ptr() as *const c_char;

/// A list of xde devices instantiated through xde_ioc_create.
static mut xde_devs: KRwLock<Vec<Box<XdeDev>>> = KRwLock::new(Vec::new());

/// DDI dev info pointer to the attached xde device.
static mut xde_dip: *mut dev_info = 0 as *mut dev_info;

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
    muh: *mut mac::mac_unicast_handle,
    mph: *mut mac::mac_promisc_handle,
}

#[derive(Debug, Serialize)]
enum HdlrError {
    System(i32),
}

impl From<self::ioctl::Error> for HdlrError {
    fn from(e: self::ioctl::Error) -> Self {
        match e {
            self::ioctl::Error::DeserError(_) => Self::System(EINVAL),
            self::ioctl::Error::FailedCopyin => Self::System(EFAULT),
            self::ioctl::Error::FailedCopyout => Self::System(EFAULT),
            self::ioctl::Error::RespTooLong => Self::System(ENOBUFS),
        }
    }
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
    unsafe {
        &*(ddi_get_driver_private(xde_dip) as *mut XdeState)
    }
}

impl XdeState {
    fn new(underlay1: String, underlay2: String) -> Self {
        let ectx = Arc::new(ExecCtx {
            log: Box::new(opte_core::KernelLog {})
        });
        XdeState {
            u1: xde_underlay_port {
                name: underlay1,
                mh: 0 as *mut mac::mac_handle,
                mch: 0 as *mut mac::mac_client_handle,
                muh: 0 as *mut mac::mac_unicast_handle,
                mph: 0 as *mut mac::mac_promisc_handle,
            },
            u2: xde_underlay_port {
                name: underlay2,
                mh: 0 as *mut mac::mac_handle,
                mch: 0 as *mut mac::mac_client_handle,
                muh: 0 as *mut mac::mac_unicast_handle,
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

    // mac handle client/handle for this device
    mh: *mut mac::mac_handle,
    mch: *mut mac::mac_client_handle,

    flags: u64,
    mac_addr: EtherAddr,
    link_state: mac::link_state_t,

    // opte port associated with this xde device
    port: Option<Box<Port<opte_core::port::Active>>>,

    // simply pass the packets through to the underlay devices, skipping
    // opte-core processing.
    passthrough: bool,

    // For the moment we assume a VNI uniquely identifies a port within a host.
    // This may be changed later such that a VNI plus something like an inner
    // packet destination IP is needed.
    vni: u32,

    // these are clones of the underlay ports initialized by the driver
    u1: xde_underlay_port,
    u2: xde_underlay_port,
}

impl Default for XdeDev {
    fn default() -> Self {
        XdeDev {
            devname: "".into(),
            linkid: 0,
            mh: 0 as *mut mac::mac_handle,
            mch: 0 as *mut mac::mac_client_handle,
            flags: 0,
            mac_addr: EtherAddr::from([0u8; 6]),
            port: None,
            link_state: mac::link_state_t::Unknown,
            passthrough: false,
            vni: 0,
            u1: xde_underlay_port {
                name: "".into(),
                mh: 0 as *mut mac::mac_handle,
                mch: 0 as *mut mac::mac_client_handle,
                muh: 0 as *mut mac::mac_unicast_handle,
                mph: 0 as *mut mac::mac_promisc_handle,
            },
            u2: xde_underlay_port {
                name: "".into(),
                mh: 0 as *mut mac::mac_handle,
                mch: 0 as *mut mac::mac_client_handle,
                muh: 0 as *mut mac::mac_unicast_handle,
                mph: 0 as *mut mac::mac_promisc_handle,
            },
        }
    }
}

#[no_mangle]
unsafe extern "C" fn _init() -> c_int {
    xde_devs.init(KRwLockType::Driver);
    mac::mac_init_ops(ptr::null_mut(), XDE_STR);
    match mod_install(&xde_linkage) {
        0 => 0,
        err => {
            warn!("mod install failed: {}", err);
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
        0 => 0,
        err => {
            warn!("mod remove failed: {}", err);
            err
        }
    }
}

#[no_mangle]
unsafe extern "C" fn xde_open(
    _devp: *mut dev_t,
    _flags: c_int,
    _otype: c_int,
    _credp: *mut cred_t,
) -> c_int {
    0
}

#[no_mangle]
unsafe extern "C" fn xde_close(
    _dev: dev_t,
    _flags: c_int,
    _otype: c_int,
    _credp: *mut cred_t,
) -> c_int {
    0
}

#[no_mangle]
unsafe extern "C" fn xde_ioctl(
    _dev: dev_t,
    cmd: c_int,
    arg: intptr_t,
    mode: c_int,
    _credp: *mut cred_t,
    _rvalp: *mut c_int,
) -> c_int {
    let cmd = match IoctlCmd::try_from(cmd) {
        Ok(c) => c,
        Err(_) => {
            warn!("ioctl cmd try from failed");
            return EINVAL;
        }
    };

    let mut ioctlenv =
        match ioctl::IoctlEnvelope::new(arg as *const c_void, mode) {
            Ok(val) => val,
            Err(e) => {
                warn!("ioctl envelope failed: {:?}", e);
                return EFAULT;
            }
        };

    match cmd {
        IoctlCmd::XdeCreate => {
            let mut req: CreateXdeReq = match ioctlenv.copy_in_req() {
                Ok(x) => x,
                Err(e @ crate::ioctl::Error::DeserError(_)) => {
                    warn!("dser xde_ioc_create failed: {:?}", e);
                    return EINVAL;
                }
                Err(e) => {
                    warn!("ioctl envelope copy in failed: {:?}", e);
                    return EFAULT;
                }
            };
            match xde_ioc_create(&mut req) {
                0 => {
                    hdlr_resp::<(), XdeError>(&mut ioctlenv, Ok(Ok(())))
                }
                err => {
                    warn!("xde_ioc_create failed: {}", err);
                    hdlr_resp::<(), XdeError>(
                        &mut ioctlenv, Err(HdlrError::System(err)))
                }
            }
        }
        IoctlCmd::XdeDelete => {
            let mut req: DeleteXdeReq = match ioctlenv.copy_in_req() {
                Ok(x) => x,
                Err(e @ crate::ioctl::Error::DeserError(_)) => {
                    warn!("dser xde_ioc_delete failed: {:?}", e);
                    return EINVAL;
                }
                Err(e) => {
                    warn!("ioctl envelope copy in failed: {:?}", e);
                    return EFAULT;
                }
            };
            match xde_ioc_delete(&mut req) {
                0 => {
                    hdlr_resp::<(), XdeError>(&mut ioctlenv, Ok(Ok(())))
                }
                err => {
                    warn!("xde_ioc_delete failed: {}", err);
                    hdlr_resp::<(), XdeError>(
                        &mut ioctlenv, Err(HdlrError::System(err)))
                }
            }
        }
        IoctlCmd::AddRouterEntryIpv4 => {
            let resp = add_router_entry_hdlr(&ioctlenv);
            hdlr_resp(&mut ioctlenv, resp)
        }
        IoctlCmd::FwAddRule => {
            let resp = add_fw_rule_hdlr(&ioctlenv);
            hdlr_resp(&mut ioctlenv, resp)
        }
        IoctlCmd::SetVirt2Phys => {
            let resp = set_v2p_hdlr(&ioctlenv);
            hdlr_resp(&mut ioctlenv, resp)
        }
        IoctlCmd::GetVirt2Phys => {
            let resp = get_v2p_hdlr(&ioctlenv);
            hdlr_resp(&mut ioctlenv, resp)
        }
        IoctlCmd::ListLayers => {
            let resp = list_layers_hdlr(&ioctlenv);
            hdlr_resp(&mut ioctlenv, resp)
        }
        IoctlCmd::DumpUft => {
            let resp = dump_uft_hdlr(&ioctlenv);
            hdlr_resp(&mut ioctlenv, resp)
        }
        IoctlCmd::DumpLayer => {
            let resp = dump_layer_hdlr(&ioctlenv);
            hdlr_resp(&mut ioctlenv, resp)
        }
        _ => ENOTSUP,
    }
}

fn hdlr_resp<T, E>(
    ioctlenv: &mut IoctlEnvelope,
    resp: Result<Result<T, E>, HdlrError>
) -> c_int
where
    T: CmdOk,
    E: CmdErr,
{
    //TODO
    //dtrace_probe_hdlr_resp(&resp);

    match resp {
        Ok(resp) => {
            match ioctlenv.copy_out_resp(&resp) {
                Ok(()) => 0,
                Err(e) => to_errno(e),
            }
        }

        Err(HdlrError::System(ret)) => ret,
    }
}

#[no_mangle]
unsafe extern "C" fn xde_dld_ioc_create(
    _karg: *mut c_void,
    _arg: intptr_t,
    _mode: c_int,
    _cred: *mut cred_t,
    _rvalp: *mut c_int,
) -> c_int {
    0
}

#[no_mangle]
unsafe extern "C" fn xde_ioc_create(req: &CreateXdeReq) -> c_int {
    // TODO name validation
    // TODO check if xde is already in list before proceeding

    let mut xde = Box::new(XdeDev::default());
    xde.devname = req.xde_devname.clone();
    xde.passthrough = req.passthrough;
    xde.linkid = req.linkid;
    xde.vni = req.vpc_vni.value();

    let xde_devname = match CString::new(req.xde_devname.as_str()) {
        Ok(s) => s,
        Err(e) => {
            warn!("bad xde dev name: {:?}", e);
            return EINVAL;
        }
    };

    // set up upper mac
    let mreg = match mac::mac_alloc(MAC_VERSION as u32).as_mut() {
        Some(x) => x,
        None => return EINVAL,
    };
    mreg.m_type_ident = MAC_PLUGIN_IDENT_ETHER;
    mreg.m_driver = xde.as_mut() as *mut XdeDev as *mut c_void;
    mreg.m_dip = xde_dip;
    mreg.m_dst_addr = core::ptr::null_mut();
    mreg.m_pdata = core::ptr::null_mut();
    mreg.m_pdata_size = 0;
    mreg.m_priv_props = core::ptr::null_mut();
    mreg.m_instance = c_uint::MAX; // let mac handle this
    mreg.m_min_sdu = 1;
    mreg.m_max_sdu = 1500; // TODO hardcode
    mreg.m_multicast_sdu = 0;
    mreg.m_margin = 0;
    mreg.m_v12n = MacVirt::None as u32;

    mreg.m_callbacks = &mut xde_mac_callbacks;

    let mut src = req.private_mac.to_bytes();
    mreg.m_src_addr = src.as_mut_ptr();

    match mac::mac_register(mreg as *mut mac::mac_register_t, &mut xde.mh) {
        0 => {}
        err => {
            warn!("mac register failed: {}", err);
            return err;
        }
    }
    mac::mac_free(mreg);

    let mac_client_flags = 0;

    match mac::mac_client_open(
        xde.mh,
        &mut xde.mch,
        xde_devname.as_ptr() as *const c_char,
        mac_client_flags,
    ) {
        0 => {}
        err => {
            warn!("mac client open failed: {}", err);
            return err;
        }
    }

    // setup dls
    match dls::dls_devnet_create(xde.mh, req.linkid, 0) {
        0 => {}
        err => {
            warn!("dls devnet createa failed: {}", err);
            return err;
        }
    }

    let state = get_xde_state();
    xde.u1 = state.u1.clone();
    xde.u2 = state.u2.clone();

    // create an OPTE port for this xde
    match new_port(
        req.xde_devname.clone(),
        xde.mh,
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
    ) {
        Ok(p) => xde.port = Some(p),
        Err(()) => {
            warn!("creating opte port failed");
            return EFAULT;
        }
    }

    xde.link_state = mac::link_state_t::Up;
    mac::mac_link_update(xde.mh, xde.link_state);
    mac::mac_tx_update(xde.mh);

    let mut devs = xde_devs.write();
    devs.push(xde);
    0
}

#[no_mangle]
unsafe extern "C" fn xde_ioc_delete(req: &DeleteXdeReq) -> c_int {
    let mut devs = xde_devs.write();
    let index = match devs.iter().position(|x| x.devname == req.xde_devname)
    {
        Some(index) => index,
        None => return EINVAL,
    };
    let xde = &mut devs[index];

    // captures any errors encountered for return. If there are multiple errors,
    // represents the last error encountered. Intermediate errors codes will be
    // recoreded in log.
    let mut ret = 0;

    //// clean up the xde instance being deleted and remove from list

    // destroy dls devnet device
    match dls::dls_devnet_destroy(xde.mh, &mut xde.linkid, boolean_t::B_TRUE) {
        0 => {}
        err => {
            warn!("dls devnet destroy failed: {}", err);
            ret = err
        }
    }

    // unregister xde mac handle
    match mac::mac_unregister(xde.mh) {
        0 => {}
        err => {
            warn!("mac unregister failed: {}", err);
            ret = err;
        }
    }

    // remove xde
    devs.remove(index);

    ret
}

unsafe extern "C" fn xde_dld_ioc_delete(
    _karg: *mut c_void,
    _arg: intptr_t,
    _mode: c_int,
    _cred: *mut cred_t,
    _rvalp: *mut c_int,
) -> c_int {
    ENOTSUP
}

#[no_mangle]
unsafe extern "C" fn xde_read(
    _dev: dev_t,
    _uiop: *mut uio,
    _credp: *mut cred_t,
) -> c_int {
    0
}

#[no_mangle]
unsafe extern "C" fn xde_write(
    _dev: dev_t,
    _uiop: *mut uio,
    _credp: *mut cred_t,
) -> c_int {
    0
}

static xde_ioc_list: [dld::dld_ioc_info_t; 2] = [
    dld::dld_ioc_info_t {
        di_cmd: IoctlCmd::XdeCreate as u32,
        di_flags: 0,
        di_argsize: core::mem::size_of::<CreateXdeReq>(),
        di_func: xde_dld_ioc_create,
        di_priv_func: secpolicy::secpolicy_dl_config,
    },
    dld::dld_ioc_info_t {
        di_cmd: IoctlCmd::XdeDelete as u32,
        di_flags: 0,
        di_argsize: core::mem::size_of::<DeleteXdeReq>(),
        di_func: xde_dld_ioc_delete,
        di_priv_func: secpolicy::secpolicy_dl_config,
    },
];

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

    // create a minor node so /devices/xde is a thing, this acts as an entry
    // point for ioctls.
    match ddi_create_minor_node(
        dip,
        b"xde\0".as_ptr() as *const c_char,
        S_IFCHR,
        ddi_get_instance(dip) as u32,
        DDI_PSEUDO,
        0,
    ) {
        0 => {}
        err => {
            warn!("ddi_create_minor_node failed: {}", err);
            return DDI_FAILURE;
        }
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
        ddi::DDI_SUCCESS => {},
        error => {
            //TODO tear down
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

    // we listen in promisc mode and set up all L2 framing ourselves
    // TODO understand why the following does not work in liu of mac_unicast add
    // see comment below for more details
    //let mac_client_flags = mac::MCIS_NO_UNICAST_ADDR;
    let mac_client_flags = 0;

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

    // XXX should not be needed as we're using the underlying phy mac. i tried
    // this with the MCIS_NO_UNICAST_ADDR which I expected to set up a minimal
    // tx path based on my reading of the code, however, tx'd packets just fell
    // on the floor.
    // set up unicast address for tx on mac client handles
    let xxx = EtherAddr::from([0xa8, 0x40, 0x25, 0xff, 0x00, 0x01]);
    let mut diag = mac::mac_diag::MAC_DIAG_NONE;
    let mut ether = xxx.to_bytes();
    match mac::mac_unicast_add(
        state.u1.mch,
        ether.as_mut_ptr(),
        0,
        &mut state.u1.muh,
        0,
        &mut diag,
    ) {
        0 => {}
        err => {
            warn!("mac unicast add u1 failed: {} {:?}", err, diag);
            return err;
        }
    }

    match mac::mac_unicast_add(
        state.u2.mch,
        ether.as_mut_ptr(),
        0,
        &mut state.u2.muh,
        0,
        &mut diag,
    ) {
        0 => {}
        err => {
            warn!("mac unicast add u2 failed: {} {:?}", err, diag);
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
        0
    ) {
        0 => {}
        err => {
            warn!("mac promisc add u1 failed: {}", err);
            return err;
        }
    }

    match mac::mac_promisc_add(
        state.u2.mch,
        mac::mac_client_promisc_type_t::MAC_CLIENT_PROMISC_ALL,
        xde_rx,
        ptr::null_mut(),
        &mut state.u2.mph,
        0
    ) {
        0 => {}
        err => {
            warn!("mac promisc add u2 failed: {}", err);
            return err;
        }
    }

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
            warn!("failed to create string from property value for {}: {:?}", 
                pname, e);
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

    let mut ret = 0;

    // mac unicast remove for underlay devices
    match mac::mac_unicast_remove(state.u1.mch, state.u1.muh) {
        0 => {}
        err => {
            warn!("mac_unicast remove failed for u1: {}", err);
            ret = err;
        }
    }
    match mac::mac_unicast_remove(state.u2.mch, state.u2.muh) {
        0 => {}
        err => {
            warn!("mac_unicast remove failed for u2: {}", err);
            ret = err;
        }
    }

    // close mac client handle for underlay devices
    mac::mac_client_close(state.u1.mch, 0);
    mac::mac_client_close(state.u2.mch, 0);

    // close mac handle for underlay devices
    mac::mac_close(state.u1.mh);
    mac::mac_close(state.u2.mh);

    let _ = Box::from_raw(rstate as *mut XdeState);

    ddi_remove_minor_node(xde_dip, ptr::null());
    xde_dip = ptr::null_mut::<c_void>() as *mut dev_info;
    ret
}

#[no_mangle]
static xde_cb_ops: cb_ops = cb_ops {
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
    devo_cb_ops: &xde_cb_ops,
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
    // TODO ... something
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
        .mac_addr
        .to_bytes()
        .copy_from_slice(core::slice::from_raw_parts(macaddr, 6));
    0
}

#[no_mangle]
unsafe extern "C" fn xde_mc_tx(
    arg: *mut c_void,
    mp_chain: *mut mblk_t,
) -> *mut mblk_t {
    // make sure we have started
    let dev = arg as *mut XdeDev;
    if ((*dev).flags | XdeDeviceFlags::Started as u64) == 0 {
        mac::mac_drop_chain(
            mp_chain,
            b"xde dev not ready\0".as_ptr() as *const c_char,
        );
        return ptr::null_mut();
    }

    assert!((*mp_chain).b_next == ptr::null_mut());

    // arbitrarily choose u1, later when we integrate with DDM we'll have the
    // information needed to make a real choice.
    let mch = (*dev).u1.mch;
    let hint = 0;
    let flags = mac::MAC_DROP_ON_NO_DESC;
    let ret_mp = ptr::null_mut();

    // just go straight to underlay in passthrough mode
    if (*dev).passthrough {
        mac::mac_tx(mch, mp_chain, hint, flags, ret_mp);
        return ptr::null_mut();
    }

    let mut pkt = match Packet::<Initialized>::wrap(mp_chain).parse() {
        Ok(pkt) => pkt,
        Err(e) => {
            warn!("failed to parse packet: {:?}", e);
            return core::ptr::null_mut();
        }
    };

    let port = match (*dev).port {
        Some(ref port) => port,
        None => {
            mac::mac_drop_chain(
                mp_chain,
                b"no opte port avail\0".as_ptr() as *const c_char,
            );
            return ptr::null_mut();
        }
    };

    let res = port.process(Direction::Out, &mut pkt);
    match res {
        Ok(ProcessResult::Modified) => {
            //  Ask IRE for the route associated with the underlay destination.
            //  Then ask NCE for the mac associated with the IRE nexthop to fill
            //  in the outer frame of the packet
            let (src, dst) = finish_outer_frame(&pkt);
            //let len = pkt.len();
            let mblk = pkt.unwrap();

            // get a pointer to the beginning of the outer frame
            let datap = (*mblk).b_datap as *mut dblk_t;
            let basep = (*datap).db_base as *mut u8;

            // set L2 source and destination
            ptr::copy(dst.as_ptr(), basep, 6);
            ptr::copy(src.as_ptr(), basep.add(6), 6);

            // NOTE assuming L2 checksum is going to be computed in hardware on
            // the way out the door.

            mac::mac_tx(mch, mblk, hint, flags, ret_mp);
        }

        Ok(ProcessResult::Drop { .. }) => {
            // NOTE(ry) so uncommenting this probe causes segfaults in the
            // Packet::wrap() call above?
            //opte_core::port::drop_packet_probe();
            mac::mac_drop_chain(mp_chain, b"drop\0".as_ptr() as *const c_char);
            return ptr::null_mut();
        }

        Ok(ProcessResult::Hairpin(hpkt)) => {
            mac::mac_rx(
                (*dev).mh,
                0 as *mut mac::mac_resource_handle,
                hpkt.unwrap()
            );
        }

        Ok(ProcessResult::Bypass) => {
            mac::mac_tx(mch, pkt.unwrap(), hint, flags, ret_mp);
        }

        Err(e) => {
            warn!("opte-tx port process error: {:?}", e);
            mac::mac_drop_chain(
                mp_chain,
                b"packet processing error\0".as_ptr() as *const c_char,
            );
            return ptr::null_mut();
        }
    }

    ptr::null_mut()
}

#[no_mangle]
fn finish_outer_frame(pkt: &Packet<Parsed>) 
-> (EtherAddr, EtherAddr) {

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
            _S6_un: ip::in6_addr__bindgen_ty_1{
                _S6_u8: ip6_hdr.dst().to_bytes(),
            }
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
        let src: [u8;6] = alloc::slice::from_raw_parts(src, 6)
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

        let dst: [u8;6] = alloc::slice::from_raw_parts(mac, 6)
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
    //TODO
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
    mh: *mut mac::mac_handle,
    private_ip: Ipv4Addr,
    _private_mac: EtherAddr,
    gateway_mac: EtherAddr,
    gateway_ip: Ipv4Addr,
    boundary_services_addr: Ipv6Addr,
    boundary_services_vni: Vni,
    src_underlay_addr: Ipv6Addr,
    vpc_vni: Vni,
    ectx: Arc<ExecCtx>,
    snat: Option<SnatCfg>,
) -> Result<Box<Port<opte_core::port::Active>>, ()> {
    let mut private_mac = [0u8; 6];
    unsafe { mac::mac_unicast_primary_get(mh, &mut private_mac) };
    let private_mac = EtherAddr::from(private_mac);

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
                public_mac: EtherAddr::from([0x99; 6]),
                //TODO hardcode
                public_ip: "192.168.99.99".parse().unwrap(),
                //TODO hardcode
                ports: Range { start: 999, end: 1000 },
            }
        }

        Some(snat) => opte_core::oxide_net::DynNat4Cfg {
            public_mac: snat.public_mac.clone(),
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
    let mut new_port = Port::new(
        &xde_dev_name,
        private_mac,
        ectx,
    );
    opte_core::oxide_net::firewall::setup(&mut new_port).unwrap();
    if snat.is_some() {
        opte_core::oxide_net::dyn_nat4::setup(&mut new_port, &port_cfg)
            .unwrap();
    }
    opte_core::oxide_net::arp::setup(&mut new_port, &port_cfg).unwrap();
    router::setup(&mut new_port).unwrap();

    let oc = overlay::OverlayCfg {
        boundary_services: overlay::PhysNet{
            ether: EtherAddr::from([0;6]), //XXX this should not be needed
            ip: boundary_services_addr,
            vni: boundary_services_vni,
        },
        phys_ip_src: src_underlay_addr,
        vni: vpc_vni,
    };

    let state = get_xde_state();

    overlay::setup(&new_port, &oc, state.v2p.clone());
    let port = Box::new(new_port.activate());
    Ok(port)
}

#[no_mangle]
unsafe extern "C" fn xde_rx(
    _arg: *mut c_void,
    mrh: *mut mac::mac_resource_handle,
    mp_chain: *mut mblk_t,
    _is_loopback: boolean_t,
) {

    // first parse the packet so we can get at the geneve header
    let mut pkt = match Packet::<Initialized>::wrap(mp_chain).parse() {
        Ok(pkt) => pkt,
        Err(e) => {
            warn!("failed to parse packet: {:?}", e);
            return;
        }
    };

    // determine where to send packet based on geneve vni
    let outer = match pkt.headers().outer {
        Some(ref outer) => outer,
        None => {
            warn!("no outer header, dropping");
            return;
        }
    };
    let geneve = match outer.encap {
        Some(ref geneve) => geneve,
        None => {
            warn!("no geneve header, dropping");
            return;
        }
    };

    let devs = xde_devs.read();

    //TODO create a fast lookup table
    let vni = geneve.vni.value();
    let dev = match devs.iter().find(|x| x.vni == vni){
        Some(dev) => dev,
        None => {
            warn!("no device for vni = {}, dropping", vni);
            return;
        }
    };

    // just go straight to overlay in passthrough mode
    if (*dev).passthrough {
        mac::mac_rx((*dev).mh, mrh, mp_chain);
    }


    let port = match (*dev).port {
        Some(ref port) => port,
        None => {
            warn!("port not available");
            return;
        }
    };

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

fn add_router_entry_hdlr(
    ioctlenv: &IoctlEnvelope
) -> Result<Result<(), router::AddEntryError>, HdlrError> {

    let req: router::AddRouterEntryIpv4Req = ioctlenv.copy_in_req()?;

    let devs = unsafe { xde_devs.read() };
    let mut iter = devs.iter();
    let dev = match iter.find(|x| x.devname == req.port_name)
    {
        Some(dev) => dev,
        None => {
            return Err(HdlrError::System(ENOENT));
        }
    };

    match dev.port {
        None => {
            Err(HdlrError::System(EAGAIN))
        }
        Some(ref port) => {
            Ok(router::add_entry_active(
                port,
                IpCidr::Ip4(req.dest),
                req.target
            ))

        }
    }
}

fn add_fw_rule_hdlr(
    ioctlenv: &IoctlEnvelope
) -> Result<Result<(), api::AddFwRuleError>, HdlrError> {

    let req: FwAddRuleReq = ioctlenv.copy_in_req()?;

    let devs = unsafe { xde_devs.read() };
    let mut iter = devs.iter();
    let dev = match iter.find(|x| x.devname == req.port_name)
    {
        Some(dev) => dev,
        None => {
            return Err(HdlrError::System(ENOENT));
        }
    };

    match dev.port {
        None => {
            Err(HdlrError::System(EAGAIN))
        }
        Some(ref port) => {
            Ok(api::add_fw_rule(port, &req))
        }
    }
}

fn set_v2p_hdlr(ioctlenv: &IoctlEnvelope) -> Result<Result<(), ()>, HdlrError> {
    let req: overlay::SetVirt2PhysReq = ioctlenv.copy_in_req()?;
    let state = get_xde_state();
    state.v2p.set(req.vip, req.phys);
    Ok(Ok(()))
}

fn get_v2p_hdlr(
    ioctlenv: &IoctlEnvelope,
) -> Result<Result<overlay::GetVirt2PhysResp, ()>, HdlrError> {
    let _req: overlay::GetVirt2PhysReq = ioctlenv.copy_in_req()?;
    let state = get_xde_state();
    Ok(Ok(overlay::GetVirt2PhysResp{
        ip4: state.v2p.ip4.lock().clone(),
        ip6: state.v2p.ip6.lock().clone(),
    }))
}

fn list_layers_hdlr(
    ioctlenv: &IoctlEnvelope
)-> Result<Result<api::ListLayersResp, api::ListLayersError>, HdlrError> {
    let req: api::ListLayersReq = ioctlenv.copy_in_req()?;

    let devs = unsafe { xde_devs.read() };
    let mut iter = devs.iter();
    let dev = match iter.find(|x| x.devname == req.port_name)
    {
        Some(dev) => dev,
        None => {
            return Err(HdlrError::System(ENOENT));
        }
    };

    match dev.port {
        None => {
            Err(HdlrError::System(EAGAIN))
        }
        Some(ref port) => {
            Ok(Ok(port.list_layers()))
        }
    }

}

fn dump_uft_hdlr(
    ioctlenv: &IoctlEnvelope,
) -> Result<Result<api::DumpUftResp, api::DumpUftError>, HdlrError> {
    let req: api::DumpUftReq = ioctlenv.copy_in_req()?;

    let devs = unsafe { xde_devs.read() };
    let mut iter = devs.iter();
    let dev = match iter.find(|x| x.devname == req.port_name)
    {
        Some(dev) => dev,
        None => {
            return Err(HdlrError::System(ENOENT));
        }
    };

    match dev.port {
        None => {
            Err(HdlrError::System(EAGAIN))
        }
        Some(ref port) => {
            Ok(Ok(api::dump_uft(port, &req)))
        }
    }
}

fn dump_layer_hdlr(
    ioctlenv: &IoctlEnvelope
) -> Result<Result<api::DumpLayerResp, api::DumpLayerError>, HdlrError> {
    let req: api::DumpLayerReq = ioctlenv.copy_in_req()?;

    let devs = unsafe { xde_devs.read() };
    let mut iter =  devs.iter();
    let dev = match iter.find(|x| x.devname == req.port_name)
    {
        Some(dev) => dev,
        None => {
            return Err(HdlrError::System(ENOENT));
        }
    };

    match dev.port {
        None => {
            Err(HdlrError::System(EAGAIN))
        }
        Some(ref port) => {
            Ok(api::dump_layer(port, &req))
        }
    }

}

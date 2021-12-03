//! OPTE - Oxide Packet Transformation Engine
//!
//! This driver is used as a way to interface the OPTE implementation
//! (opte-core) with the bhyve virtual interface device (viona). It
//! allows us to perform inbound and outbound packet filtering and
//! modification between the guest instance and the network. In it's
//! current form it achieves this by mimicking the mac client APIs. We
//! then use a modified viona device which replaces the calls to the
//! mac client API with calls to this module's API.
//!
//! This module also presents itself as a character device under
//! `/dev/opte`. This allows users to control and inspect the state of
//! opte as it is running (via opteadm). Requests are sent by way of
//! ioctl, interpreted by this driver, and then routed to the
//! corresponding opte-core APIs. In the future opte will probably
//! present more of a virtual-switch-like abstraction, where each
//! guest interface is a port on the switch, and the two physical NICs
//! have ports on the same virtual switch.
//!
//! When loaded, this driver effectively limits to the system to a
//! single bhyve/viona instance. This limit can be lifted with some
//! work, but for the purposes of prototyping that work was postponed.
#![feature(extern_types)]
#![feature(lang_items)]
#![feature(panic_info_message)]
#![no_std]
#![allow(non_camel_case_types)]
#![feature(str_split_once)]
#![feature(alloc_error_handler)]
#![feature(rustc_private)]

mod ioctl;

#[macro_use]
extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::btree_map::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::ops::Range;
use core::panic::PanicInfo;
use core::ptr;

use crate::ioctl::{to_errno, IoctlEnvelope};

extern crate opte_core;
use opte_core::ether::{EtherAddr, ETHER_TYPE_ARP};
use opte_core::oxide_net::firewall::{FwAddRuleReq, FwRemRuleReq};
use opte_core::ioctl::{
    CmdResp, IoctlCmd, ListPortsReq, ListPortsResp, PortInfo, RegisterPortReq,
    UnregisterPortReq
};
use opte_core::layer::LayerDumpReq;
use opte_core::oxide_net::PortConfig;
use opte_core::packet::{Initialized, Packet};
use opte_core::port::{Port, ProcessResult, TcpFlowsDumpReq, UftDumpReq};
use opte_core::rule::Rule;
use opte_core::sync::{KMutex, KMutexType};
use opte_core::{CStr, CString, Direction};

// For now I glob import all of DDI/DKI until I have a better idea of
// how I would want to organize it. Also, for the time being, if it's
// in defined in the DDI/DKI crate, then opte-drv probably needs it.
//
// TODO: Now that I'm a bit more familiar with Rust I'm not wild about
// glob imports. I think I'd rather just import the DDI types I need
// and then also bind the module to `ddi` so I can call functions like
// `ddi::msgsize()`, making it apparent where they come from.
extern crate illumos_ddi_dki;
use ddi_attach_cmd_t::*;
use ddi_detach_cmd_t::*;
use illumos_ddi_dki::*;

// TODO To `_t` or not to `_t`, that is the question.
//
// In general, we should prefer to name the types identical to the way
// they are in the illumos kernel, namely using the `_t` suffix when
// the corresponding illumos code does. However, there are some
// unforunate typedefs in the illumos code that make implicit
// pointers. For example:
//
// ```
// typedef struct __mac_resource_handle *mac_resource_handle_t;
// ```
//
// And you'll see this type used by the mac rx callback type:
//
// typedef void (*mac_rx_t)(void *, mac_resource_handle_t, mblk_t *,
//    boolean_t);
//
// In the rust code I'd like to continue to name the type
// mac_resource_handle_t, however, I don't think there is a way to
// declare an extern type name as a pointer, implicitly. Rather, when
// using the extern type, we must declare the argument/variable as a
// pointer to the extern type, to avoid unsized issues. However,
// something like `*mut mac_resource_handle_t` might give someone the
// impression this is a pointer to a pointer. So, in cases like this
// we drop the `_t`, and instead fallback to the underlying struct name.

// The following are "C type" aliases for native Rust types so that
// the native illumos structures may be defined almost verbatim to the
// source. These definitions assume AMD64 arch/LP64.
pub type c_void = core::ffi::c_void;
pub type c_schar = i8;
pub type c_uchar = u8;
pub type c_char = c_schar;
pub type c_ushort = u16;
pub type c_int = i32;
pub type c_ulong = u64;
pub type c_longlong = i64;

pub type size_t = usize;
pub type intptr_t = isize;
pub type uintptr_t = usize;
pub type ssize_t = isize;

const OPTE_STR: *const c_char = b"OPTE\0".as_ptr() as *const c_char;
const OPTE_CTL_MINOR: minor_t = 0;

#[no_mangle]
static mut opte_dip: *mut dev_info = ptr::null_mut::<c_void>() as *mut dev_info;

// This block is purely for SDT probes.
extern "C" {
    fn __dtrace_probe_copy__msg(
        src: uintptr_t,
        dst: uintptr_t,
        len: uintptr_t,
        idx: uintptr_t,
    );
    fn __dtrace_probe_read__buf(count: uintptr_t);
    fn __dtrace_probe_rx(mp: uintptr_t);
    fn __dtrace_probe_tx(mp: uintptr_t);
}

#[allow(dead_code)]
#[repr(C)]
pub enum mac_client_promisc_type_t {
    MAC_CLIENT_PROMISC_ALL,
    MAC_CLIENT_PROMISC_FILTERED,
    MAC_CLIENT_PROMISC_MULTI,
}

#[allow(unused_imports)]
use mac_client_promisc_type_t::*;

type mac_tx_cookie_t = uintptr_t;
type mac_rx_fn = unsafe extern "C" fn(
    *mut c_void,
    *mut mac_resource_handle,
    *mut mblk_t,
    boolean_t,
);

// The mac APIs.
extern "C" {
    pub type mac_handle;
    type mac_client_handle;
    type mac_promisc_handle;
    pub type mac_resource_handle;

    fn mac_client_open(
        mh: *const mac_handle,
        mch: *mut *mut mac_client_handle,
        name: *const c_char,
        flags: u16,
    ) -> c_int;

    fn mac_client_close(mch: *const mac_client_handle, flags: u16);
    fn mac_client_name(mch: *const mac_client_handle) -> *const c_char;
    fn mac_close(mh: *mut mac_handle);
    fn mac_open_by_linkname(
        link: *const c_char,
        mhp: *mut *mut mac_handle
    ) -> c_int;
    fn mac_promisc_add(
        mch: *const mac_client_handle,
        ptype: mac_client_promisc_type_t,
        pfn: mac_rx_fn,
        arg: *mut c_void,
        // I've been going back and forth on using
        // const/mut for a lot of the illumos function
        // pointer arguments. Part of me wants to be
        // faithful to the C API which declares very
        // few things `const` (most just strings), but
        // another part of me recognizes that in many
        // cases a) the kernel will not modify these
        // objects after they are allocated or/and b)
        // the Rust code is treating them as opaque
        // blobs and certainly won't touch them. For
        // example, the mac_promisc_handle:
        //
        //     o Rust won't mess with it.
        //
        //     o Perhaps illumos messes with it but I
        //       doubt it?
        //
        // In terms of the Rust compiler I'm guessing
        // it doesn't make too much difference as I
        // don't believe unsafe/raw pointers can assume
        // any of the strict aliasing rules that
        // shared/unique references do.
        mphp: *mut *const mac_promisc_handle,
        flags: u16,
    ) -> c_int;
    fn mac_promisc_remove(mph: *const mac_promisc_handle);
    fn mac_rx_barrier(mch: *const mac_client_handle);
    fn mac_rx_set(
        mch: *const mac_client_handle,
        rx_fn: mac_rx_fn,
        arg: *mut c_void,
    );
    fn mac_rx_clear(mch: *const mac_client_handle);
    fn mac_tx(
        mch: *const mac_client_handle,
        mp_chain: *const mblk_t,
        hint: uintptr_t,
        flag: u16,
        ret_mp: *mut *const mblk_t,
    ) -> mac_tx_cookie_t;
    fn mac_unicast_primary_get(mh: *const mac_handle, addr: *mut [u8; 6]);
}

#[no_mangle]
unsafe extern "C" fn opte_open(
    _devp: *mut dev_t,
    _flags: c_int,
    _otype: c_int,
    _credp: *mut cred_t,
) -> c_int {
    0
}

#[no_mangle]
unsafe extern "C" fn opte_close(
    _dev: dev_t,
    _flags: c_int,
    _otype: c_int,
    _credp: *mut cred_t,
) -> c_int {
    0
}

struct OpteState {
    clients: KMutex<BTreeMap<String, *mut OpteClientState>>,
}

impl OpteState {
    fn new() -> Self {
        OpteState {
            clients: KMutex::new(BTreeMap::new(), KMutexType::Driver),
        }
    }
}

fn register_port(req: &RegisterPortReq) -> CmdResp<()> {
    // Safety: The opte_dip pointer is write-once and is a valid
    // pointer passed to attach(9E). The returned pointer is valid as
    // it was derived from Box::into_raw() during attach(9E).
    let state = unsafe {
        &*(ddi_get_driver_private(opte_dip) as *mut OpteState)
    };

    if let Some(_) = state.clients.lock().unwrap().get(&req.link_name) {
        return Err(format!("port already exists"))
    }

    let mut mh: *mut mac_handle = ptr::null_mut::<c_void>() as *mut mac_handle;
    let link_name_c = CString::new(req.link_name.clone()).unwrap();
    let ret = unsafe { mac_open_by_linkname(link_name_c.as_ptr(), &mut mh) };

    if ret != 0 {
        return Err(format!("failed to open mac: {}", ret));
    }

    let mut private_mac = [0u8; 6];
    unsafe { mac_unicast_primary_get(mh, &mut private_mac) };
    let private_mac = EtherAddr::from(private_mac);

    let vpc_subnet = if req.ip_cfg.snat.is_none() {
        "192.168.77.0/24".parse().unwrap()
    } else {
        req.ip_cfg.snat.as_ref().unwrap().vpc_sub4
    };

    let dyn_nat = match req.ip_cfg.snat.as_ref() {
        None => {
            opte_core::oxide_net::DynNat4Config {
                public_mac: EtherAddr::from([0x99; 6]),
                public_ip: "192.168.99.99".parse().unwrap(),
                ports: Range {
                    start: 999,
                    end: 1000,
                }
            }
        },

        Some(snat) => {
            opte_core::oxide_net::DynNat4Config {
                public_mac: snat.public_mac.clone(),
                public_ip: snat.public_ip,
                ports: Range {
                    start: snat.port_start,
                    end: snat.port_end
                }
            }
        }
    };

    let port_cfg = PortConfig {
        vpc_subnet,
        private_mac,
        private_ip: req.ip_cfg.private_ip,
        gw_mac: req.ip_cfg.gw_mac,
        gw_ip: req.ip_cfg.gw_ip,
        dyn_nat,
    };

    let mut port = Box::new(Port::new(
        req.link_name.clone(),
        private_mac
    ));

    opte_core::oxide_net::firewall::setup(&mut port);

    // TODO: In order to demo this in the lab environment we currently
    // allow SNAT to be optional.
    if req.ip_cfg.snat.is_some() {
        opte_core::oxide_net::dyn_nat4::setup(&mut port, &port_cfg);
    }

    opte_core::oxide_net::arp::setup(&mut port, &port_cfg);

    let port_periodic = unsafe {
        ddi_periodic_add(
            opte_port_periodic,
            port.as_ref() as *const Port as *const c_void,
            ONE_SECOND,
            DDI_IPL_0,
        )
    };

    let ocs = Box::new(OpteClientState {
        in_use: KMutex::new(false, KMutexType::Driver),
        mh,
        mch: ptr::null_mut::<c_void> as *mut mac_client_handle,
        name: req.link_name.clone(),
        rx_state: None,
        mph: 0 as *mut mac_promisc_handle,
        promisc_state: None,
        port,
        port_cfg,
        port_periodic,
        private_mac,
        hairpin_queue: KMutex::new(Vec::with_capacity(4), KMutexType::Driver),
    });

    // We need to pull the raw pointer out of the box and give it to
    // the client (viona). It will pass this pointer back to us during
    // every invocation. To viona, the pointer points to an opaque type.
    //
    // ```
    // typedef struct __opte_client_state opte_client_state_t;
    // ```
    //
    // The "owner" of `ocs` is now viona. When the guest instance is
    // tore down, and viona is closing, it will give ownership back to
    // opte via `opte_client_close()`.
    //
    // There is no concern over shared ownership or data races from
    // viona as `ocs` is simply a top-level state structure with
    // pointers to other MT-safe types (aka interior mutability).
    state.clients.lock().unwrap().insert(
        req.link_name.clone(),
        Box::into_raw(ocs)
    );

    Ok(())
}

fn unregister_port(req: UnregisterPortReq) -> CmdResp<()> {
    unsafe {
        let state = &*(ddi_get_driver_private(opte_dip) as *mut OpteState);
        let ocsp = match state.clients.lock().unwrap().get(&req.name) {
            Some(ocspp) => *ocspp,
            None =>  return Err(format!("port not found: {}", req.name)),
        };

        if *(*ocsp).in_use.lock().unwrap() {
            return Err(format!("port is in use"));
        }

        let ocsp = state.clients.lock().unwrap().remove(&req.name).unwrap();

        // The ownership of `ocs` is being given back to opte. We need
        // to put it back in the box so that the value and its owned
        // resources are properly dropped.
        let ocs = Box::from_raw(ocsp);

        // Release the mac handle.
        mac_close(ocs.mh);

        // Stop the periodic before dropping everything.
        ddi_periodic_delete(ocs.port_periodic);
    }

    // Resources dropped with `ocs`.
    Ok(())
}

#[no_mangle]
unsafe extern "C" fn opte_ioctl(
    _dev: dev_t,
    cmd: c_int,
    arg: intptr_t,
    mode: c_int,
    _credp: *mut cred_t,
    _rvalp: *mut c_int,
) -> c_int {
    let cmd = match IoctlCmd::try_from(cmd) {
        Ok(v) => v,
        Err(_) => {
            opte_core::err(format!("invalid ioctl cmd: {}", cmd));
            return EINVAL;
        }
    };

    let mut ioctlenv = match IoctlEnvelope::new(arg as *const c_void, mode) {
            Ok(val) => val,
            _ => return EFAULT,
    };

    match cmd {
        IoctlCmd::RegisterPort => {
            let req: RegisterPortReq = match ioctlenv.copy_in_req() {
                Ok(val) => val,
                Err(e @ ioctl::Error::DeserError(_)) => {
                    opte_core::err(
                        format!("failed to deser RegisterPortReq: {:?}", e)
                    );
                    return EINVAL;
                }
                _ => return EFAULT,
            };

            to_errno(ioctlenv.copy_out_resp(&register_port(&req)))
        }

        IoctlCmd::UnregisterPort => {
            let req: UnregisterPortReq = match ioctlenv.copy_in_req() {
                Ok(val) => val,
                Err(e @ ioctl::Error::DeserError(_)) => {
                    opte_core::err(
                        format!("failed to deser UnegisterPortReq: {:?}", e)
                    );
                    return EINVAL;
                }
                _ => return EFAULT,
            };

            to_errno(ioctlenv.copy_out_resp(&unregister_port(req)))
        }

        IoctlCmd::ListPorts => {
            let _req: ListPortsReq = match ioctlenv.copy_in_req() {
                Ok(val) => val,
                Err(e @ ioctl::Error::DeserError(_)) => {
                    opte_core::err(
                        format!("failed to deser ListPortsReq: {:?}", e)
                    );
                    return EINVAL;
                }
                _ => return EFAULT,
            };

            let mut resp = ListPortsResp { ports: vec![] };
            let state = &*(ddi_get_driver_private(opte_dip) as *mut OpteState);
            for (_k, v) in state.clients.lock().unwrap().iter() {
                let ocs = &(**v);
                resp.ports.push(PortInfo {
                    name: ocs.name.clone(),
                    mac_addr: ocs.private_mac,
                    ip4_addr: ocs.port_cfg.private_ip,
                    in_use: *ocs.in_use.lock().unwrap()
                });
            }

            to_errno(ioctlenv.copy_out_resp(&Ok(resp)))
        }

        IoctlCmd::FwAddRule => {
            let req: FwAddRuleReq = match ioctlenv.copy_in_req() {
                Ok(val) => val,
                Err(ioctl::Error::DeserError(_)) => return EINVAL,
                _ => return EFAULT,
            };

            let state = &*(ddi_get_driver_private(opte_dip) as *mut OpteState);
            let ocs = match state.clients.lock().unwrap().get(&req.port_name) {
                None => {
                    return ENOENT;
                }

                Some(v) => &mut *(*v),
            };

            let dir = req.rule.direction;
            let rule = Rule::from(req.rule);
            let resp = ocs.port.add_rule("firewall", dir, rule);
            to_errno(ioctlenv.copy_out_resp(&resp))
        }

        IoctlCmd::FwRemRule => {
            // This step validates that the bytes were able to be
            // derserialized, but that doesn't mean we should consider
            // this a valid, legal, or safe request. Before adding a
            // new rule to the firewall we must make sure it meets all
            // requirements. To make sure that the programmer cannot
            // forget to make these checks, they are done as part of
            // the `add_rule()` method.
            //
            // TODO For example, we need to make sure that a default
            // rule cannot be deleted (assuming they should not be
            // deleted), or that a given target is something that
            // actually exists.
            let req: FwRemRuleReq = match ioctlenv.copy_in_req() {
                Ok(val) => val,
                Err(ioctl::Error::DeserError(_)) => return EINVAL,
                _ => return EFAULT,
            };

            let state = &*(ddi_get_driver_private(opte_dip) as *mut OpteState);
            let ocs = match state.clients.lock().unwrap().get(&req.port_name) {
                None => {
                    return ENOENT;
                }

                Some(v) => &mut *(*v),
            };

            let resp = ocs.port.remove_rule("firewall", req.dir, req.id);
            to_errno(ioctlenv.copy_out_resp(&resp))
        }

        IoctlCmd::TcpFlowsDump => {
            let req: TcpFlowsDumpReq = match ioctlenv.copy_in_req() {
                Ok(val) => val,
                Err(ioctl::Error::DeserError(_)) => return EINVAL,
                _ => return EFAULT,
            };
            let state = &*(ddi_get_driver_private(opte_dip) as *mut OpteState);
            let ocs = match state.clients.lock().unwrap().get(&req.port_name) {
                None => {
                    return ENOENT;
                }

                Some(v) => &mut *(*v),
            };

            let resp = Ok(ocs.port.dump_tcp_flows());
            to_errno(ioctlenv.copy_out_resp(&resp))
        }

        IoctlCmd::LayerDump => {
            let req: LayerDumpReq = match ioctlenv.copy_in_req() {
                Ok(val) => val,
                Err(ioctl::Error::DeserError(_)) => return EINVAL,
                _ => return EFAULT,
            };

            let state = &*(ddi_get_driver_private(opte_dip) as *mut OpteState);
            let ocs = match state.clients.lock().unwrap().get(&req.port_name) {
                None => {
                    return ENOENT;
                }

                Some(v) => &mut *(*v),
            };

            let resp = ocs.port.dump_layer(&req.name);
            to_errno(ioctlenv.copy_out_resp(&resp))
        }

        IoctlCmd::UftDump => {
            let req: UftDumpReq = match ioctlenv.copy_in_req() {
                Ok(val) => val,
                Err(ioctl::Error::DeserError(_)) => return EINVAL,
                _ => return EFAULT,
            };

            let state = &*(ddi_get_driver_private(opte_dip) as *mut OpteState);
            let ocs = match state.clients.lock().unwrap().get(&req.port_name) {
                None => {
                    return ENOENT;
                }

                Some(v) => &mut *(*v),
            };

            let resp = Ok(ocs.port.dump_uft());
            to_errno(ioctlenv.copy_out_resp(&resp))
        }
    }
}

#[no_mangle]
unsafe extern "C" fn opte_read(
    _dev: dev_t,
    _uiop: *mut uio,
    _credp: *mut cred_t,
) -> c_int {
    0
}

#[no_mangle]
unsafe extern "C" fn opte_write(
    _dev: dev_t,
    _uiop: *mut uio,
    _credp: *mut cred_t,
) -> c_int {
    0
}

#[no_mangle]
static opte_cb_ops: cb_ops = cb_ops {
    cb_open: opte_open,
    cb_close: opte_close,
    cb_strategy: nodev,
    cb_print: nodev,
    cb_dump: nodev,
    cb_read: opte_read,
    cb_write: opte_write,
    cb_ioctl: opte_ioctl,
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
static opte_devops: dev_ops = dev_ops {
    devo_rev: DEVO_REV,
    devo_refcnt: 0,
    devo_getinfo: nodev_getinfo,
    devo_identify: nulldev_identify,
    devo_probe: nulldev_probe,
    devo_attach: opte_attach,
    devo_detach: opte_detach,
    devo_reset: nodev_reset,
    devo_cb_ops: &opte_cb_ops,
    devo_bus_ops: 0 as *const bus_ops, // ptr::null()
    devo_power: nodev_power,
    devo_quiesce: ddi_quiesce_not_needed,
};

#[no_mangle]
static opte_modldrv: modldrv = unsafe {
    modldrv {
        drv_modops: &mod_driverops,
        drv_linkinfo: OPTE_STR,
        drv_dev_ops: &opte_devops,
    }
};

// NOTE We don't need the `no_magle` here, but it's nice to keep the
// symbol clean to keep with the C modules (it also makes it easier to
// grab from MDB). I'm also using lowercase to be consistent with
// other kernel modules.
//
// TODO There's probably a slightly better way to initialize
// `ml_linkage` to NULL instead of explicitly filling in each slot.
#[no_mangle]
static opte_linkage: modlinkage = modlinkage {
    ml_rev: MODREV_1,
    ml_linkage: [
        (&opte_modldrv as *const modldrv).cast(),
        ptr::null(),
        ptr::null(),
        ptr::null(),
        ptr::null(),
        ptr::null(),
        ptr::null(),
    ],
};

#[no_mangle]
unsafe extern "C" fn opte_attach(
    dip: *mut dev_info,
    cmd: ddi_attach_cmd_t,
) -> c_int {
    match cmd {
        DDI_RESUME => return DDI_SUCCESS,
        cmd if cmd != DDI_ATTACH => return DDI_FAILURE,
        _ => (),
    }

    // We create a minor node to use as entry for opteadm ioctls.
    let ret = ddi_create_minor_node(
        dip,
        b"opte\0".as_ptr() as *const c_char,
        S_IFCHR,
        OPTE_CTL_MINOR,
        DDI_PSEUDO,
        0,
    );

    if ret != DDI_SUCCESS {
        cmn_err(
            CE_WARN,
            b"failed to create minor node\0".as_ptr() as *const c_char,
        );
        return DDI_FAILURE;
    }

    let state = Box::new(OpteState::new());
    // We consume the box and place it's raw pointer in the
    // per-instance device state. On detach we place this pointer back
    // into the box so it can be dropped. All other uses of the
    // pointer will simply convert to a reference, as we know the
    // pointer is non-NULL and aligned properly.
    ddi_set_driver_private(dip, Box::into_raw(state) as *mut c_void);
    opte_dip = dip;
    ddi_report_dev(dip);
    DDI_SUCCESS
}

#[no_mangle]
unsafe extern "C" fn opte_detach(
    _dip: *mut dev_info,
    cmd: ddi_detach_cmd_t,
) -> c_int {
    match cmd {
        DDI_SUSPEND => return DDI_SUCCESS,
        cmd if cmd != DDI_DETACH => return DDI_FAILURE,
        _ => (),
    }

    // We should never be in detach if attach has not run.
    // Furthermore, if we have a dip, we have non-NULL state.
    assert!(!opte_dip.is_null());
    let rstate = ddi_get_driver_private(opte_dip);
    assert!(!rstate.is_null());

    // Put the state back in the box so Rust can drop it.
    let _ = Box::from_raw(rstate as *mut OpteState);
    ddi_remove_minor_node(opte_dip, ptr::null());
    opte_dip = ptr::null_mut::<c_void>() as *mut dev_info;
    DDI_SUCCESS
}

#[no_mangle]
unsafe extern "C" fn _init() -> c_int {
    mod_install(&opte_linkage)
}

#[no_mangle]
unsafe extern "C" fn _info(modinfop: *mut modinfo) -> c_int {
    mod_info(&opte_linkage, modinfop)
}

#[no_mangle]
unsafe extern "C" fn _fini() -> c_int {
    let ret = mod_remove(&opte_linkage);
    if ret != 0 {
        return ret;
    }

    0
}

#[lang = "eh_personality"]
extern "C" fn eh_personality() {}

// The symbol name gets rewritten to `rust_being_unwind` (don't ask me
// why), so we use `panic_hdlr` to avoid clashing with the kernel's
// panic symbol.
#[panic_handler]
fn panic_hdlr(info: &PanicInfo) -> ! {
    let msg = CString::new(format!("{}", info)).unwrap();
    unsafe {
        cmn_err(CE_WARN, msg.as_ptr());
        panic(msg.as_ptr());
    }
}

// ================================================================
// mac client intercept APIs
//
// Thes APIs are meant to mimic the mac client APIs, allowing opte to
// act as an intermediary between viona and mac.
// ================================================================

// TODO The port configuration and client state are conflated here. It
// would be good to tease them apart into separate types to better
// demarcate things. E.g., the client state might be the rx_state and
// promisc_state, along with a pointer to something like `PortState`.
// And the `PortState` might be what OpteClientState is right now.
// Though you might tease this out a bit more and separate the static
// port configuration handed down during port registration from actual
// state like the hairpin queue.
pub struct OpteClientState {
    in_use: KMutex<bool>,
    mh: *mut mac_handle,
    mch: *mut mac_client_handle,
    rx_state: Option<OpteRxState>,
    mph: *const mac_promisc_handle,
    name: String,
    promisc_state: Option<OptePromiscState>,
    port: Box<Port>,
    port_cfg: PortConfig,
    port_periodic: *const ddi_periodic,
    private_mac: EtherAddr,
    // Packets generated by OPTE on the guest's/network's behalf, to
    // be returned to the source (aka a "hairpin" packet).
    hairpin_queue: KMutex<Vec<Packet<Initialized>>>,
}

const ONE_SECOND: hrtime_t = 1_000_000_000;

#[no_mangle]
pub unsafe extern "C" fn opte_port_periodic(arg: *mut c_void) {
    // The `arg` is a raw pointer to a `Port`, as guaranteed by
    // opte_client_open().
    let port = &*(arg as *const Port);
    port.expire_flows(gethrtime());
}

#[no_mangle]
pub unsafe extern "C" fn opte_client_open(
    mh: *const mac_handle,
    ocspo: *mut *const OpteClientState,
    _name: *const c_char,
    flags: u16,
) -> c_int {
    *ocspo = ptr::null_mut();
    let mut mch = ptr::null_mut::<c_void> as *mut mac_client_handle;
    let ret = mac_client_open(mh, &mut mch, ptr::null(), flags);

    if ret != 0 {
        return ret;
    }

    let link_name = CStr::from_ptr(mac_client_name(mch))
        .to_str()
        .unwrap()
        .to_string();

    let state = &mut *(ddi_get_driver_private(opte_dip) as *mut OpteState);
    let ocsp = match state.clients.lock().unwrap().get(&link_name) {
        Some(ocspp) => *ocspp,
        None => return ENOENT,
    };
    let ocs = &mut (*ocsp);
    let mut in_use = ocs.in_use.lock().unwrap();

    if *in_use {
        mac_client_close(ocs.mch, 0);
        return EBUSY;
    }

    ocs.mch = mch;
    *ocspo = ocsp;
    *in_use = true;
    0
}

#[no_mangle]
pub unsafe extern "C" fn opte_client_close(
    ocsp: *mut OpteClientState,
    _flags: u16,
) {
    let ocs = &mut *ocsp;

    // The client is closing its handle to this port. We need to
    // effectively "reset" the port by wiping all of its current state
    // and returning it to its original state in preparation for the
    // next client open. This is best done by dropping the entire Port
    // and replacing it with a new one with the identical
    // configuration.
    ddi_periodic_delete(ocs.port_periodic);
    ocs.port_periodic = 0 as *const c_void as *const ddi_periodic;

    let new_port = Port::new(
        ocs.name.clone(),
        ocs.private_mac
    );

    let _ = core::mem::replace(&mut *ocs.port, new_port);
    opte_core::oxide_net::firewall::setup(&mut ocs.port);
    opte_core::oxide_net::dyn_nat4::setup(&mut ocs.port, &ocs.port_cfg);
    opte_core::oxide_net::arp::setup(&mut ocs.port, &ocs.port_cfg);

    let port_periodic = ddi_periodic_add(
        opte_port_periodic,
        ocs.port.as_ref() as *const Port as *const c_void,
        ONE_SECOND,
        DDI_IPL_0,
    );

    ocs.port_periodic = port_periodic;
    *ocs.in_use.lock().unwrap() = false;
}

#[no_mangle]
pub unsafe extern "C" fn opte_rx_barrier(ocsp: *const OpteClientState) {
    let ocs = &*ocsp;
    mac_rx_barrier(ocs.mch);
}

struct OpteRxState {
    rx_fn: mac_rx_fn,
    arg: *mut c_void,
}

#[no_mangle]
pub unsafe extern "C" fn opte_rx_set(
    ocsp: *mut OpteClientState,
    rx_fn: mac_rx_fn,
    arg: *mut c_void,
) {
    let ocs = &mut *ocsp;
    ocs.rx_state = Some(OpteRxState { rx_fn, arg });
    mac_rx_set(ocs.mch, opte_rx, ocsp as *mut c_void);
}

#[no_mangle]
pub unsafe extern "C" fn opte_rx_clear(ocsp: *mut OpteClientState) {
    let ocs = &mut *ocsp;
    // Need to take the state out so it is dropped.
    let _ = ocs.rx_state.take();
    mac_rx_clear(ocs.mch);
}

struct OptePromiscState {
    promisc_fn: mac_rx_fn,
    arg: *mut c_void,
}

#[no_mangle]
pub unsafe extern "C" fn opte_promisc_add(
    ocsp: *mut OpteClientState,
    ptype: mac_client_promisc_type_t,
    promisc_fn: mac_rx_fn,
    arg: *mut c_void,
    flags: u16,
) -> c_int {
    let mut ocs = &mut *ocsp;
    ocs.promisc_state = Some(OptePromiscState { promisc_fn, arg });
    let mut mph = 0 as *const mac_promisc_handle;
    let ret = mac_promisc_add(
        ocs.mch,
        ptype,
        opte_rx_mcast,
        ocsp as *mut c_void,
        &mut mph,
        flags,
    );

    if ret != 0 {
        let _ = ocs.promisc_state.take();
        return ret;
    }

    ocs.mph = mph;
    0
}

#[no_mangle]
pub unsafe extern "C" fn opte_promisc_remove(ocsp: *mut OpteClientState) {
    let mut ocs = &mut *ocsp;
    mac_promisc_remove(ocs.mph);
    ocs.mph = 0 as *const mac_promisc_handle;
    let _ = ocs.promisc_state.take();
}

#[no_mangle]
pub unsafe extern "C" fn opte_tx(
    ocsp: *mut OpteClientState,
    mp_chain: *mut mblk_t,
    hint: uintptr_t,
    flag: u16,
    ret_mp: *mut *const mblk_t,
) {
    // TODO: I haven't dealt with chains, though I'm pretty sure it's
    // always just one.
    assert!((*mp_chain).b_next == ptr::null_mut());
    __dtrace_probe_tx(mp_chain as uintptr_t);

    let mut pkt = match Packet::<Initialized>::wrap(mp_chain).parse() {
        Ok(pkt) => pkt,
        Err(e) => {
            // TODO SDT probe
            // TODO stat
            opte_core::dbg(format!("failed to parse packet: {:?}", e));
            return;
        }
    };
    let ocs = &*ocsp;
    // TODO This `mp_chain` arg was for debug purposes; now that we
    // have Packet we can probably get rid of it?
    let res = ocs.port.process(Direction::Out, &mut pkt, mp_chain as uintptr_t);

    match res {
        ProcessResult::Modify(meta) => {
            if pkt.set_headers(&meta).is_err() {
                todo!("implement set_headers err stat + SDT probe");
            }

            // It's vital to get the raw `mblk_t` back out of the
            // `pkt` here, otherwise the mblk_t would be dropped
            // at the end of this function along with `pkt`.
            mac_tx(ocs.mch, pkt.unwrap(), hint, flag, ret_mp);
        }

        // TODO Probably want a state + a probe along with a reason
        // carried up via `ProcessResult::Drop(String)` so that a
        // reason can be given as part of the probe.
        ProcessResult::Drop => {
            return;
        }

        ProcessResult::Hairpin(hppkt) => {
            let rx_state = ocs.rx_state.as_ref().unwrap();
            (rx_state.rx_fn)(
                rx_state.arg,
                // TODO: IIRC we can just set the mrh (mac
                // resource handle) to NULL and it will
                // deliver via the default ring. If this
                // doesn't work we can create some type of
                // hairpin queue.
                0 as *mut c_void as *mut mac_resource_handle,
                hppkt.unwrap(),
                boolean_t::B_FALSE,
            );
            return;
        }

        // In this case the packet is bypassing processing. This
        // result type will probably go away eventually. For now we
        // use it for protocols/traffic we aren't ready to deal with
        // yet.
        ProcessResult::Bypass(_meta) => {
            mac_tx(ocs.mch, pkt.unwrap(), hint, flag, ret_mp);
        }
    }

    // Deal with any pending hairpin packets.
    while let Some(p) = ocs.hairpin_queue.lock().unwrap().pop() {
        mac_tx(ocs.mch, p.unwrap(), hint, flag, ret_mp);
    }
}

// This doesn't need to be no_mangle, but I like keeping callbacks
// demangled.
#[no_mangle]
pub unsafe extern "C" fn opte_rx(
    arg: *mut c_void,
    mrh: *mut mac_resource_handle,
    mp_chain: *mut mblk_t,
    loopback: boolean_t,
) {
    // TODO: I haven't dealt with chains yet.
    assert!((*mp_chain).b_next == ptr::null_mut());
    __dtrace_probe_rx(mp_chain as uintptr_t);

    let mut pkt = match Packet::<Initialized>::wrap(mp_chain).parse() {
        Ok(pkt) => pkt,
        Err(e) => {
            // TODO SDT probe
            // TODO stat
            opte_core::dbg(format!("failed to parse packet: {:?}", e));
            return;
        }
    };
    let ocs = &*(arg as *const OpteClientState);
    let rx_state = ocs.rx_state.as_ref().unwrap();
    let res = ocs.port.process(Direction::In, &mut pkt, mp_chain as uintptr_t);
    match res {
        ProcessResult::Modify(meta) => {
            let etype = match meta.inner_ether.as_ref() {
                Some(ether) => ether.ether_type,
                _ => panic!("no inner ether"),
            };

            // We should never see ARP here. The only outbound ARP
            // should be for the gateway, and that should be handled
            // by a hairpin action in opte_tx(). Any inbound should be
            // the gateway ARPing for the private or public IP and
            // should be handled by the hairpin below, all other
            // inbound ARP should be denied.
            //
            // TODO This check will eventually go away. Just want it
            // here for now to verify no ARP is getting thru to the
            // guest.
            if etype == ETHER_TYPE_ARP {
                panic!("Should never see ARP here");
            }

            if pkt.set_headers(&meta).is_err() {
                todo!("implement set_headers err stat + SDT probe");
            }

            (rx_state.rx_fn)(rx_state.arg, mrh, pkt.unwrap(), loopback);
        }

        // TODO Probably want a state + a probe along with a reason
        // carried up via `ProcessResult::Drop(String)` so that a
        // reason can be given as part of the probe.
        ProcessResult::Drop => {
            return;
        }

        ProcessResult::Hairpin(hppkt) => {
            ocs.hairpin_queue.lock().unwrap().push(hppkt);
            return;
        }

        // In this case the packet is bypassing processing. This
        // result type will probably go away eventually. For now we
        // use it for protocols/traffic we aren't ready to deal with
        // yet.
        ProcessResult::Bypass(meta) => {
            let etype = match meta.inner_ether.as_ref() {
                Some(ether) => ether.ether_type,
                _ => panic!("no inner ether"),
            };

            // See comment above.
            if etype == ETHER_TYPE_ARP {
                panic!("Should never see ARP here");
            }

            (rx_state.rx_fn)(rx_state.arg, mrh, pkt.unwrap(), loopback);
        }
    }
}

// This doesn't need to be no_mangle, but I like keeping callbacks
// demangled.
#[no_mangle]
pub unsafe extern "C" fn opte_rx_mcast(
    arg: *mut c_void,
    mrh: *mut mac_resource_handle,
    mp: *mut mblk_t,
    loopback: boolean_t,
) {
    let ocs = &*(arg as *const OpteClientState);
    let pstate = ocs.promisc_state.as_ref().unwrap();
    (pstate.promisc_fn)(pstate.arg, mrh, mp, loopback);
}

// On alignment, `kmem_alloc(9F)` has this of offer:
//
// > The allocated memory is at least double-word aligned, so it can
// > hold any C data structure. No greater alignment can be assumed.
//
// I really hate when documentation uses "word", because that seems to
// mean different things in different contexts, in this case I have to
// assume it means native integer size, or 32-bit in the case our our
// AMD64 kernel. So this means all allocations are at least 8-byte
// aligned, but could be more. However, the last sentence is saying
// that you cannot assume alignment is ever greater than 8 bytes.
// Therefore, it seems best to just assume it's 8 bytes. So, for the
// purposes of implementing GlobalAlloc, I believe this means that I
// should return NULL for any Layout which requests more than 8-byte
// alignment (or probably just panic since I never expect this).
// Furthermore, things that could have smaller alignment will just
// have to live with the larger alignment.

use core::alloc::{GlobalAlloc, Layout};

struct KmemAlloc;

unsafe impl GlobalAlloc for KmemAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() > 8 {
            panic!("kernel alloc greater than 8-byte alignment");
        }

        kmem_alloc(layout.size(), KM_SLEEP) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        kmem_free(ptr as *mut c_void, layout.size() as size_t)
    }
}

#[global_allocator]
static A: KmemAlloc = KmemAlloc;

// In reality, if the GlobalAlloc is using KM_SLEEP, then we can never
// hit this. But the compiler wants us to define it, so we do.
#[alloc_error_handler]
fn alloc_error(_: Layout) -> ! {
    panic!("allocation error");
}

// This is a hack to get around the fact that liballoc includes
// calls to _Unwind_Resume, supposedly because it is not compiled
// with `panic=abort`. This is all a little bit beyond me but I just
// want to satisfy the symbol resolution so I can load this module.
//
// https://github.com/rust-lang/rust/issues/47493
#[allow(non_snake_case)]
#[no_mangle]
fn _Unwind_Resume() -> ! {
    panic!("_Unwind_Resume called");
}

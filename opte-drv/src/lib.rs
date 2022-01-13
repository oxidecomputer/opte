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
#![feature(alloc_error_handler)]
#![feature(rustc_private)]
#![deny(unused_must_use)]

mod ioctl;

#[macro_use]
extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::collections::btree_map::BTreeMap;
// TODO Is Arc okay for illumos-kernel use? I.e., it uses atomics
// underneath, is the code generated okay for the illumos kernel?
use alloc::sync::Arc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::fmt::Debug;
use core::ops::Range;
use core::panic::PanicInfo;
use core::ptr;
use core::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ioctl::{to_errno, IoctlEnvelope};

extern crate opte_core;
use opte_core::ether::{EtherAddr, ETHER_TYPE_ARP};
use opte_core::oxide_net::firewall::{FwAddRuleReq, FwRemRuleReq};
use opte_core::ioctl::{
    self as api, CmdResp, IoctlCmd, ListPortsReq, ListPortsResp, PortInfo, AddPortReq,
    DeletePortReq
};
use opte_core::ip4::Ipv4Addr;
use opte_core::layer;
use opte_core::oxide_net::overlay;
use opte_core::oxide_net::PortCfg;
use opte_core::packet::{Initialized, Packet};
use opte_core::port::{self, Port, ProcessResult};
use opte_core::rule::Rule;
use opte_core::sync::{KMutex, KMutexGuard, KMutexType};
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
    fn mac_close(mh: *const mac_handle);
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

fn get_gw_mac(dip: *mut dev_info) -> EtherAddr {
    let mut gw_mac_c: *const c_char = ptr::null();

    let ret = unsafe {
        ddi_prop_lookup_string(
            DDI_DEV_T_ANY,
            dip,
            DDI_PROP_DONTPASS,
            b"gateway_mac\0".as_ptr() as *const c_char,
            &mut gw_mac_c,
        )
    };

    if ret != DDI_PROP_SUCCESS {
        let err = format!("failed to get gateway_mac: {}", ret);
        unsafe { cmn_err(CE_WARN, CString::new(err).unwrap().as_ptr()) };
        return EtherAddr::from([0; 6]);
    }

    let gw_mac = unsafe { CStr::from_ptr(gw_mac_c).to_owned() };
    unsafe { ddi_prop_free(gw_mac_c as *mut c_void) };

    EtherAddr::from_str(gw_mac.to_str().unwrap()).unwrap_or_else(|err| {
        let msg = format!("failed to parse gateway_mac property: {}", err);
        unsafe { cmn_err(CE_WARN, CString::new(msg).unwrap().as_ptr()) };
        EtherAddr::from([0; 6])
    })
}

fn get_gw_ip(dip: *mut dev_info) -> Ipv4Addr {
    let mut gw_ip_c: *const c_char = ptr::null();

    let ret = unsafe {
        ddi_prop_lookup_string(
            DDI_DEV_T_ANY,
            dip,
            DDI_PROP_DONTPASS,
            b"gateway_ipv4\0".as_ptr() as *const c_char,
            &mut gw_ip_c,
        )
    };

    if ret != DDI_PROP_SUCCESS {
        let err = format!("failed to get gateway_ipv4: {}", ret);
        unsafe { cmn_err(CE_WARN, CString::new(err).unwrap().as_ptr()) };
        return Ipv4Addr::from_str("0.0.0.0").unwrap();
    }

    let gw_ip = unsafe { CStr::from_ptr(gw_ip_c).to_owned() };
    unsafe { ddi_prop_free(gw_ip_c as *mut c_void) };

    Ipv4Addr::from_str(gw_ip.to_str().unwrap()).unwrap_or_else(|err| {
        let msg = format!("failed to parse gateway_ipv4 property: {}", err);
        unsafe { cmn_err(CE_WARN, CString::new(msg).unwrap().as_ptr()) };
        Ipv4Addr::from_str("0.0.0.0").unwrap()
    })
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

type LinkName = String;


// struct InactivePort {
//     port: Port<port::Inactive>,
//     cfg: PortCfg,
// }

// struct ActivePort {
//     client: OpteClientState,
//     cfg: PortCfg,
// }

enum PortState {
    Inactive(Port<port::Inactive>, PortCfg),
    Active(*mut OpteClientState),
}

struct OpteState {
    gateway_mac: EtherAddr,
    gateway_ip: Ipv4Addr,
    v2p: Arc<overlay::Virt2Phys>,
    ports: KMutex<BTreeMap<LinkName, PortState>>,
}

impl OpteState {
    fn new(gateway_mac: EtherAddr, gateway_ip: Ipv4Addr,) -> Self {
        OpteState {
            gateway_mac,
            gateway_ip,
            v2p: Arc::new(overlay::Virt2Phys::new()),
            ports: KMutex::new(BTreeMap::new(), KMutexType::Driver),
        }
    }
}

fn get_opte_state() -> &'static OpteState {
    // Safety: The opte_dip pointer is write-once and is a valid
    // pointer passed to attach(9E). The returned pointer is valid as
    // it was derived from Box::into_raw() during attach(9E).
    unsafe {
        &*(ddi_get_driver_private(opte_dip) as *mut OpteState)
    }
}

fn add_port(
    req: &AddPortReq
) -> Result<(), api::AddPortError> {
    let state = get_opte_state();

    // We must hold this lock until we have inserted the new port into
    // the map; otherwise, multiple threads could race to add the same
    // port.
    let mut ports_lock = state.ports.lock();

    if let Some(_) = ports_lock.get(&req.link_name) {
        return Err(api::AddPortError::Exists);
    }

    let mut mh: *mut mac_handle = ptr::null_mut::<c_void>() as *mut mac_handle;
    let link_name_c = CString::new(req.link_name.clone()).unwrap();
    let ret = unsafe { mac_open_by_linkname(link_name_c.as_ptr(), &mut mh) };

    if ret != 0 {
        return Err(api::AddPortError::MacOpenFailed(ret));
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
            opte_core::oxide_net::DynNat4Cfg {
                public_mac: EtherAddr::from([0x99; 6]),
                public_ip: "192.168.99.99".parse().unwrap(),
                ports: Range {
                    start: 999,
                    end: 1000,
                }
            }
        },

        Some(snat) => {
            opte_core::oxide_net::DynNat4Cfg {
                public_mac: snat.public_mac.clone(),
                public_ip: snat.public_ip,
                ports: Range {
                    start: snat.port_start,
                    end: snat.port_end
                }
            }
        }
    };

    let port_cfg = PortCfg {
        vpc_subnet,
        private_mac,
        private_ip: req.ip_cfg.private_ip,
        gw_mac: state.gateway_mac,
        gw_ip: state.gateway_ip,
        dyn_nat,
        overlay: None,
    };

    let mut new_port = Port::new(req.link_name.clone(), private_mac);
    opte_core::oxide_net::firewall::setup(&mut new_port).unwrap();
    // TODO: In order to demo this in the lab environment we currently
    // allow SNAT to be optional.
    if req.ip_cfg.snat.is_some() {
        opte_core::oxide_net::dyn_nat4::setup(&mut new_port, &port_cfg)
            .unwrap();
    }
    opte_core::oxide_net::arp::setup(&mut new_port, &port_cfg).unwrap();

    ports_lock.insert(
        req.link_name.clone(),
        PortState::Inactive(new_port, port_cfg),
    );
    Ok(())
}

fn delete_port(req: &DeletePortReq) -> Result<(), api::DeletePortError> {
    let state = unsafe {
        &*(ddi_get_driver_private(opte_dip) as *mut OpteState)
    };

    let mut ports_lock = state.ports.lock();

    let _ = match ports_lock.get(&req.name) {
        Some(PortState::Inactive(inactive_port, _)) => inactive_port,
        Some(PortState::Active(_)) => return Err(api::DeletePortError::InUse),
        None => return Err(api::DeletePortError::NotFound),
    };

    let _ = ports_lock.remove(&req.name);
    Ok(())
}

// TODO I think T need Serialize too
// struct IoctlResponse<T: Debug> {
//     ret: c_int,
//     resp: T,
// }

// TODO This should probably be renamed get_client_mut()
fn get_active_port_mut<'a, 'b>(
    state: &'a OpteState,
    name: &'b str
) -> Result<*mut OpteClientState, api::PortError> {
    match state.ports.lock().get_mut(name) {
        None => Err(api::PortError::NotFound),
        Some(PortState::Inactive(_, _)) => {
            Err(api::PortError::Inactive)
        }
        Some(PortState::Active(ocspp)) => Ok(*ocspp),
    }
}

// TODO This should probably be renamed get_port()
//
// We need to pass this function a lock because the caller is likely
// performing several actions on a given Port and thus must hold the
// lock the entire time to prevent another thread from deleting the
// same Port.
fn get_inactive_port<'a, 'b>(
    ports_lock: &'a KMutexGuard<BTreeMap<LinkName, PortState>>,
    name: &'b str,
) -> Result<&'a Port<port::Inactive>, api::PortError> {
    match ports_lock.get(name) {
        None => Err(api::PortError::NotFound),
        Some(PortState::Inactive(port, _)) => Ok(&port),
        Some(PortState::Active(_)) => Err(api::PortError::Active),
    }
}

// enum UberError<A: serde::de::DeserializeOwned + Serialize> {
//     Api(A),
//     // Api(Vec,u8>),
//     Ioctl(ioctl::Error),
//     // AddFwRule(AddFwRuleError),
// }

// impl<E: serde::de::DeserializeOwned + Serialize> From<E> for UberError<E> {
//     fn from(err: E) -> Self {
//         // let bytes = postcard::to_allocvec(e).unwrap();
//         // Self::Api(bytes)
//         Self::Api(err)
//     }
// }

// impl From<ioctl::Error> for UberError<ioctl::Error> {
//     fn from(e: ioctl::Error) -> Self {
//         Self::Ioctl(e)
//     }
// }

// fn do_ioctl<G, E>(
//     cmd: IoctlCmd,
//     ioctlenv: &IoctlEnvelope,
// ) -> Result<G, UberError<E>>
// where
//     G: Serialize,
//     E: serde::de::DeserializeOwned + Serialize
// {
//     match cmd {
//         IoctlCmd::FwAddRule => {
//             let req: FwAddRuleReq = ioctlenv.copy_in_req()?;
//             let state = &*(ddi_get_driver_private(opte_dip) as *mut OpteState);
//             let ocs = get_port_mut(state, &req.port_name)?;
//             api::add_fw_rule(ocs.port.active()?, req)

//             // let dir = req.rule.direction;
//             // let rule = Rule::from(req.rule);

//             // ocs.port.active()?.add_rule("firewall", dir, rule)
//         }

//         _ => todo!("other stuff"),
//     }

// }

#[derive(Debug, Serialize)]
enum HdlrError2<E: Serialize> {
    Api(E),
    Port(api::PortError),
    System(i32),
}

// impl<E: Serialize> From<> for HdlrError2<E> {
//     fn from(e: E) -> Self {
//         Self::Api(e)
//     }
// }

impl<E: Serialize> From<api::PortError> for HdlrError2<E> {
    fn from(e: api::PortError) -> Self {
        Self::Port(e)
    }
}

impl<E: Serialize> From<self::ioctl::Error> for HdlrError2<E> {
    fn from(e: self::ioctl::Error) -> Self {
        match e {
            self::ioctl::Error::DeserError(_) => Self::System(EINVAL),
            self::ioctl::Error::FailedCopyin => Self::System(EFAULT),
            self::ioctl::Error::FailedCopyout => Self::System(EFAULT),
            self::ioctl::Error::RespTooLong => Self::System(ENOBUFS),
        }
    }
}

impl From<api::AddPortError> for HdlrError2<api::AddPortError> {
    fn from(e: api::AddPortError) -> Self {
        Self::Api(e)
    }
}

impl From<api::DeletePortError> for HdlrError2<api::DeletePortError> {
    fn from(e: api::DeletePortError) -> Self {
        Self::Api(e)
    }
}

impl From<api::AddFwRuleError> for HdlrError2<api::AddFwRuleError> {
    fn from(e: api::AddFwRuleError) -> Self {
        Self::Api(e)
    }
}

impl From<api::RemFwRuleError> for HdlrError2<api::RemFwRuleError> {
    fn from(e: api::RemFwRuleError) -> Self {
        Self::Api(e)
    }
}

impl From<api::DumpLayerError> for HdlrError2<api::DumpLayerError> {
    fn from(e: api::DumpLayerError) -> Self {
        Self::Api(e)
    }
}

// TODO Would match against this in opte_ioctl and then convert to
// type that lives in API-land that can map to either the particular
// API response or to the more generic PortNotFound PortInactive
// errors.
enum HdlrError<E> {
    Api(E),
    Ioctl(self::ioctl::Error),
    Port(opte_core::ioctl::PortError),
}

impl<E> From<self::ioctl::Error> for HdlrError<E> {
    fn from(e: self::ioctl::Error) -> Self {
        Self::Ioctl(e)
    }
}

impl<E> From<opte_core::ioctl::PortError> for HdlrError<E> {
    fn from(e: opte_core::ioctl::PortError) -> Self {
        Self::Port(e)
    }
}

impl From<opte_core::ioctl::AddFwRuleError> for HdlrError<opte_core::ioctl::AddFwRuleError> {
    fn from(e: opte_core::ioctl::AddFwRuleError) -> Self {
        Self::Api(e)
    }
}

fn add_port_hdlr(
    ioctlenv: &IoctlEnvelope
) -> Result<(), HdlrError2<api::AddPortError>> {
    let req: AddPortReq = ioctlenv.copy_in_req()?;
    add_port(&req).map_err(HdlrError2::from)
}

fn delete_port_hdlr(
    ioctlenv: &IoctlEnvelope
) -> Result<(), HdlrError2<api::DeletePortError>> {
    let req: DeletePortReq = ioctlenv.copy_in_req()?;
    delete_port(&req).map_err(HdlrError2::from)
}

fn list_ports_hdlr(
    ioctlenv: &IoctlEnvelope
) -> Result<ListPortsResp, HdlrError2<()>> {
    let _req: ListPortsReq = ioctlenv.copy_in_req()?;
    let mut resp = ListPortsResp { ports: vec![] };
    let state = get_opte_state();
    for (_k, ps) in state.ports.lock().iter() {
        match ps {
            PortState::Inactive(port, cfg) => {
                resp.ports.push(PortInfo {
                    name: port.name().to_string(),
                    mac_addr: port.mac_addr(),
                    ip4_addr: cfg.private_ip,
                    in_use: false,
                });
            }

            PortState::Active(ocspp) => {
                let ocs = unsafe { &*(*ocspp) };
                resp.ports.push(PortInfo {
                    name: ocs.name.clone(),
                    mac_addr: ocs.private_mac,
                    ip4_addr: ocs.port_cfg.private_ip,
                    in_use: true,
                });
            }
        }
    }

    Ok(resp)
}

fn add_fw_rule_hdlr(
    ioctlenv: &IoctlEnvelope
) -> Result<(), HdlrError2<api::AddFwRuleError>> {
    let req: FwAddRuleReq = ioctlenv.copy_in_req()?;
    let ocs = unsafe {
        let state = &*(ddi_get_driver_private(opte_dip) as *mut OpteState);
        &mut *get_active_port_mut(state, &req.port_name)?
    };
    api::add_fw_rule(&ocs.port, &req).map_err(HdlrError2::from)
}

fn rem_fw_rule_hdlr(
    ioctlenv: &IoctlEnvelope
) -> Result<(), HdlrError2<api::RemFwRuleError>> {
    let req: FwRemRuleReq = ioctlenv.copy_in_req()?;
    let state = get_opte_state();
    let ocs = unsafe { &mut *get_active_port_mut(state, &req.port_name)? };
    api::rem_fw_rule(&ocs.port, &req).map_err(HdlrError2::from)
}

fn dump_tcp_flows_hdlr(
    ioctlenv: &IoctlEnvelope
) -> Result<port::DumpTcpFlowsResp, HdlrError2<()>> {
    let req: port::DumpTcpFlowsReq = ioctlenv.copy_in_req()?;
    let state = get_opte_state();
    let ocs = unsafe { &mut *get_active_port_mut(state, &req.port_name)? };
    Ok(api::dump_tcp_flows(&ocs.port, &req))
}

fn dump_layer_hdlr(
    ioctlenv: &IoctlEnvelope
) -> Result<layer::DumpLayerResp, HdlrError2<api::DumpLayerError>> {
    let req: layer::DumpLayerReq = ioctlenv.copy_in_req()?;
    let state = get_opte_state();
    let ocs = unsafe { &mut *get_active_port_mut(state, &req.port_name)? };
    api::dump_layer(&ocs.port, &req).map_err(HdlrError2::from)
}

fn dump_uft_hdlr(
    ioctlenv: &IoctlEnvelope,
) -> Result<port::DumpUftResp, HdlrError2<()>> {
    let req: port::DumpUftReq = ioctlenv.copy_in_req()?;
    let state = get_opte_state();
    let ocs = unsafe { &mut *get_active_port_mut(state, &req.port_name)? };
    Ok(api::dump_uft(&ocs.port, &req))
}

fn set_overlay_hdlr(
    ioctlenv: &IoctlEnvelope,
) -> Result<(), HdlrError2<()>> {
    let req: overlay::SetOverlayReq = ioctlenv.copy_in_req()?;
    let state = get_opte_state();
    let ports_lock = state.ports.lock();
    let port = get_inactive_port(&ports_lock, &req.port_name)?;
    Ok(api::set_overlay(&port, &req, state.v2p.clone()))
}

fn hdlr_resp<E, R>(
    ioctlenv: &mut IoctlEnvelope,
    resp: Result<R, HdlrError2<E>>
) -> c_int
where
    E: Debug + Serialize,
    R: Debug + Serialize,
{
    match resp {
        Ok(resp) => {
            match ioctlenv.copy_out_resp(&resp) {
                Ok(()) => 0,
                Err(e) => to_errno(e),
            }
        }

        Err(HdlrError2::Api(eresp)) => {
            match ioctlenv.copy_out_resp(&eresp) {
                // We use EPROTO as a sentinel value to tell an ioctl
                // consumer that there was an error and there is
                // additional information about the error in the
                // user-supplied buffer.
                Ok(()) => EPROTO,
                Err(e) => to_errno(e),
            }
        }

        // TODO Actually implement the rest of this
        Err(_) => EFAULT,
    }
}

// TODO opte_ioctl must return c_int, but want something that
// automatically writes a user response when things fail, by having
// do_ioctl return an IoctlResponse we should be able to generically
// handle ok vs. error in opte_ioctl.
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
            // TODO Replace this with a stat.
            opte_core::err(format!("invalid ioctl cmd: {}", cmd));
            return EINVAL;
        }
    };

    let mut ioctlenv = match IoctlEnvelope::new(arg as *const c_void, mode) {
            Ok(val) => val,
            _ => return EFAULT,
    };

    match cmd {
        IoctlCmd::AddPort => {
            let resp = add_port_hdlr(&ioctlenv);
            hdlr_resp(&mut ioctlenv, resp)
        }

        IoctlCmd::DeletePort => {
            let resp = delete_port_hdlr(&ioctlenv);
            hdlr_resp(&mut ioctlenv, resp)
        }

        // XXX Eventually this information (or some subset of it)
        // comes from Omicron/SA, but for now we require manual config
        // between the window of creating an instance (which creates
        // an OPTE Port) and starting it.
        IoctlCmd::SetOverlay => {
            let resp = set_overlay_hdlr(&ioctlenv);
            hdlr_resp(&mut ioctlenv, resp)
        }

        IoctlCmd::ListPorts => {
            let resp = list_ports_hdlr(&ioctlenv);
            hdlr_resp(&mut ioctlenv, resp)
        }

        IoctlCmd::FwAddRule => {
            let resp = add_fw_rule_hdlr(&ioctlenv);
            hdlr_resp(&mut ioctlenv, resp)
        }

        IoctlCmd::FwRemRule => {
            // XXX At the moment a default rule can be removed. That's
            // something we may want to prevent at the OPTE layer
            // moving forward. Or we may want to allow complete
            // freedom at this level and place that enforcement at the
            // control plane level.
            let resp = rem_fw_rule_hdlr(&ioctlenv);
            hdlr_resp(&mut ioctlenv, resp)
        }

        IoctlCmd::DumpTcpFlows => {
            let resp = dump_tcp_flows_hdlr(&ioctlenv);
            hdlr_resp(&mut ioctlenv, resp)
        }

        IoctlCmd::DumpLayer => {
            let resp = dump_layer_hdlr(&ioctlenv);
            hdlr_resp(&mut ioctlenv, resp)
        }

        IoctlCmd::DumpUft => {
            let resp = dump_uft_hdlr(&ioctlenv);
            hdlr_resp(&mut ioctlenv, resp)
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

    let gateway_mac = get_gw_mac(dip);
    let gateway_ip = get_gw_ip(dip);
    cmn_err(
        CE_NOTE,
        CString::new(
            format!("gateway_mac: {}, gateway_ip: {}", gateway_mac, gateway_ip)
        ).unwrap().as_ptr()
    );
    let state = Box::new(OpteState::new(gateway_mac, gateway_ip));

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

// trait ClientState {}

// struct Inactive {
//     port: Box<Port<opte_core::port::Inactive>>,
// }

// struct Active {
//     // Packets generated by OPTE on the guest's/network's behalf, to
//     // be returned to the source (aka a "hairpin" packet).
//     hairpin_queue: KMutex<Vec<Packet<Initialized>>>,
//     mch: *mut mac_client_handle,
//     port: Box<Port<opte_core::port::Active>>,
//     // TODO Should this use NonNull?
//     port_periodic: *const ddi_periodic,
//     promisc_state: Option<OptePromiscState>,
//     rx_state: Option<OpteRxState>,
// }

// TODO A hack for now to differentiate between active/inactive port.
// enum PortState {
//     Active(Box<Port<port::Active>>),
//     Inactive(Box<Port<port::Inactive>>),
// }

// impl PortState {
//     fn active(&self) -> Result<&Port<port::Active>, self::ioctl::Error> {
//         match self {
//             Self::Active(p) => Ok(p),
//             Self::Inactive(_) => Err(self::ioctl::Error::PortInactive),
//         }
//     }

//     fn activate(&mut self) {
//         match self {
//             Self::Inactive(p) => {
//                 let p1 = p.activate();
//                 core::mem::replace(self, PortState::Active(Box::new(p1)));
//             }

//             Self::Active(_) => panic!("already active"),
//         }
//     }

//     fn inactive(self) -> Box<Port<port::Inactive>> {
//         match self {
//             Self::Active(_) => panic!("port should not be active"),
//             Self::Inactive(p) => p,
//         }
//     }
// }

// TODO The port configuration and client state are conflated here. It
// would be good to tease them apart into separate types to better
// demarcate things. E.g., the client state might be the rx_state and
// promisc_state, along with a pointer to something like `PortState`.
// And the `PortState` might be what OpteClientState is right now.
// Though you might tease this out a bit more and separate the static
// port configuration handed down during port registration from actual
// state like the hairpin queue.
pub struct OpteClientState {
    mh: *const mac_handle,
    mch: *mut mac_client_handle,
    rx_state: Option<OpteRxState>,
    mph: *const mac_promisc_handle,
    name: String,
    promisc_state: Option<OptePromiscState>,
    port: Port<port::Active>,
    port_cfg: PortCfg,
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
    let port = &*(arg as *const Port<opte_core::port::Active>);
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

    // We must hold the ports's lock for the duration of this call to ensure
    // that transition from inactive to active is atomic.
    let mut ports_lock = state.ports.lock();

    let (port, port_cfg) = match ports_lock.remove(&link_name) {
        Some(PortState::Inactive(p,c)) => (p, c),
        Some(PortState::Active(_)) => return EBUSY,
        None => return ENOENT,
    };

    let active_port = port.activate();
    let mac_addr = active_port.mac_addr();

    let port_periodic =  ddi_periodic_add(
            opte_port_periodic,
            &active_port as *const Port<_> as *const c_void,
            ONE_SECOND,
            DDI_IPL_0,
    );

    let ocs = Box::new(OpteClientState {
        mh,
        mch,
        name: link_name.clone(),
        rx_state: None,
        mph: 0 as *mut mac_promisc_handle,
        promisc_state: None,
        port: active_port,
        port_cfg,
        port_periodic,
        private_mac: mac_addr,
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
    //
    // TODO Move or delete this comment?
    //
    // TODO Do I really need to have ocs in a Box? Wouldn't the act of
    // moving it into the map put it on the heap? Furthermore, when I
    // need to hand out a raw pointer to the client I think I could
    // just cast the reference I get back from lookup?
    ports_lock.insert(link_name.clone(), PortState::Active(Box::into_raw(ocs)));
    0
}

#[no_mangle]
pub unsafe extern "C" fn opte_client_close(
    ocsp: *mut OpteClientState,
    _flags: u16,
) {
    let link_name = &((*ocsp).name);
    let state = &mut *(ddi_get_driver_private(opte_dip) as *mut OpteState);
    // This should NEVER happen. It would mean we have an active OPTE
    // client but are not tracking it at all in our clients list.
    let _ = state.ports.lock().remove(link_name).expect("something is amiss");

    // The ownership of `ocs` is being given back to opte. We need
    // to put it back in the box so that the value and its owned
    // resources are properly dropped.
    let ocs = Box::from_raw(ocsp);

    // The client is closing its handle to this port. We need to
    // effectively "reset" the port by wiping all of its current state
    // and returning it to its original state in preparation for the
    // next client open. This is best done by dropping the entire Port
    // and replacing it with a new one with the identical
    // configuration.
    ddi_periodic_delete(ocs.port_periodic);

    let mut new_port = Port::new(
        ocs.name.clone(),
        ocs.private_mac
    );

    let port_cfg = ocs.port_cfg;

    opte_core::oxide_net::firewall::setup(&mut new_port).unwrap();
    opte_core::oxide_net::dyn_nat4::setup(&mut new_port, &port_cfg)
        .unwrap();
    opte_core::oxide_net::arp::setup(&mut new_port, &port_cfg).unwrap();

    // TODO This line made me realize that once a port has a client
    // someone could come along an add the port again now that there
    // is no longer an entry in the ports map. It might be a better
    // idea to put these back into one map but have an enum type like:
    //
    // enum {
    //   Port(Port<Inavtive>),
    //   Client(*const OpteClientState),
    // }
    state.ports.lock().insert(
        link_name.to_string(),
        PortState::Inactive(new_port, port_cfg)
    );
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
        Ok(ProcessResult::Modified) => {
            // It's vital to get the raw `mblk_t` back out of the
            // `pkt` here, otherwise the mblk_t would be dropped
            // at the end of this function along with `pkt`.
            mac_tx(ocs.mch, pkt.unwrap(), hint, flag, ret_mp);
        }

        // TODO Probably want a state + a probe along with a reason
        // carried up via `ProcessResult::Drop(String)` so that a
        // reason can be given as part of the probe.
        Ok(ProcessResult::Drop) => {
            return;
        }

        Ok(ProcessResult::Hairpin(hppkt)) => {
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
        Ok(ProcessResult::Bypass) => {
            mac_tx(ocs.mch, pkt.unwrap(), hint, flag, ret_mp);
        }

        // TODO Want something better here eventually:
        //
        // 1. Not sure we really want to log every error to the system log.
        //
        // 2. Though we should probably fire a probe for every error.
        //
        // 3. Certainly we want stats around errors, perhaps both in
        // OPTE itself as well as this driver.
        Err(e) => {
            cmn_err(
                CE_WARN,
                CString::new(format!("{:?}", e)).unwrap().as_ptr()
            );
            return;
        }
    }

    // Deal with any pending outbound hairpin packets.
    //
    // XXX This should be done by a task queue. Otherwise, we only
    // clear the hairpin queue when the guest is actively trying to
    // send packets.
    while let Some(p) = ocs.hairpin_queue.lock().pop() {
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
        Ok(ProcessResult::Modified) => {
            let meta = pkt.meta();
            let etype = match meta.inner.ether.as_ref() {
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

            (rx_state.rx_fn)(rx_state.arg, mrh, pkt.unwrap(), loopback);
        }

        // TODO Probably want a state + a probe along with a reason
        // carried up via `ProcessResult::Drop(String)` so that a
        // reason can be given as part of the probe.
        Ok(ProcessResult::Drop) => {
            return;
        }

        Ok(ProcessResult::Hairpin(hppkt)) => {
            ocs.hairpin_queue.lock().push(hppkt);
            return;
        }

        // In this case the packet is bypassing processing. This
        // result type will probably go away eventually. For now we
        // use it for protocols/traffic we aren't ready to deal with
        // yet.
        Ok(ProcessResult::Bypass) => {
            let meta = pkt.meta();
            let etype = match meta.inner.ether.as_ref() {
                Some(ether) => ether.ether_type,
                _ => panic!("no inner ether"),
            };

            // See comment above.
            if etype == ETHER_TYPE_ARP {
                panic!("Should never see ARP here");
            }

            (rx_state.rx_fn)(rx_state.arg, mrh, pkt.unwrap(), loopback);
        }

        // TODO Want something better here eventually:
        //
        // 1. Not sure we really want to log every error to the system log.
        //
        // 2. Though we should probably fire a probe for every error.
        //
        // 3. Certainly we want stats around errors, perhaps both in
        // OPTE itself as well as this driver.
        Err(e) => {
            cmn_err(
                CE_WARN,
                CString::new(format!("{:?}", e)).unwrap().as_ptr()
            );
            return;
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

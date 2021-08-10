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
#![feature(alloc_prelude)]
#![feature(alloc_error_handler)]
#![feature(rustc_private)]

mod ioctl;

#[macro_use]
extern crate alloc;

use alloc::prelude::v1::*;
use core::convert::TryFrom;
use core::mem;
use core::ops::Range;
use core::panic::PanicInfo;
use core::ptr;
use core::slice;

use crate::ioctl::IoctlEnvelope;

extern crate opte_core;
use opte_core::arp::{
    ArpHardware, ArpHdrRaw, ArpOp, ArpProtocol, ARP_HTYPE_ETHERNET,
};
use opte_core::ether::{
    EtherAddr, EtherHdrRaw, ETHER_TYPE_ARP, ETHER_TYPE_IPV4,
};
use opte_core::firewallng::{
    Firewall, FwAddRuleReq, FwAddRuleResp, FwRemRuleReq, FwRemRuleResp,
};
use opte_core::headers::{csum_incremental, IpMeta, UlpMeta};
use opte_core::input::{self, Packet, PacketMetaOld, PacketReader, ReadErr};
use opte_core::ioctl::{IoctlCmd, SetIpConfigReq, SetIpConfigResp};
use opte_core::ip4::{Ipv4Addr, Ipv4HdrRaw, Protocol};
use opte_core::layer::{Layer, LayerDumpReq};
use opte_core::nat::{DynNat4, NatPool};
use opte_core::parse::PacketMeta;
use opte_core::port::{Port, Pos, TcpFlowsDumpReq, UftDumpReq};
use opte_core::rule::{
    Action, IpProtoMatch, Ipv4AddrMatch, Predicate, Rule, RuleAction,
};
use opte_core::sync::{KMutex, KMutexType};
use opte_core::tcp::TcpHdrRaw;
use opte_core::udp::UdpHdrRaw;
use opte_core::vpc::{SetVpcSubnet4Req, SetVpcSubnet4Resp, VpcSubnet4};
use opte_core::{dbg, CStr, CString, Direction};

// For now I glob import all of DDI/DKI until I have a better idea of
// how I would want to organize it. Also, for the time being, if it's
// in defined in the DDI/DKI crate, then opte-drv probably needs it.
extern crate illumos_ddi_dki;
use ddi_attach_cmd_t::*;
use ddi_detach_cmd_t::*;
use illumos_ddi_dki::*;

extern crate zerocopy;
use zerocopy::AsBytes;

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

extern "C" {
    // Unfortunately this seems to be a private API. Should this be in
    // the DDI/DKI?
    fn freemsgchain(mp: *mut mblk_t);
}

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
    // There can only be one client for the moment.
    client: Option<*mut OpteClientState>,
}

impl OpteState {
    fn new() -> Self {
        OpteState { client: None }
    }
}

fn set_ip_config(
    req: SetIpConfigReq,
    ocs: &mut OpteClientState,
) -> Result<(), (c_int, String)> {
    ocs.vpc_sub4 = match req.vpc_sub4.parse() {
        Ok(v) => Some(v),
        Err(e) => return Err((EINVAL, format!("vpc_sub4: {:?}", e))),
    };

    let private_ip = match req.private_ip.parse() {
        Ok(v) => v,
        Err(e) => return Err((EINVAL, format!("private_ip: {:?}", e))),
    };
    ocs.private_ip = Some(private_ip);

    let public_ip = match req.public_ip.parse() {
        Ok(v) => v,
        Err(e) => return Err((EINVAL, format!("public_ip: {:?}", e))),
    };
    ocs.public_ip = Some(public_ip);

    let start = match req.port_start.parse() {
        Ok(v) => v,
        Err(e) => return Err((EINVAL, format!("port_start: {:?}", e))),
    };

    let end = match req.port_end.parse() {
        Ok(v) => v,
        Err(e) => return Err((EINVAL, format!("port_end: {:?}", e))),
    };

    let mut pool = NatPool::new();
    pool.add(private_ip, public_ip, Range { start, end });
    ocs.port.set_nat_pool(pool);

    let ip_bytes = ocs.public_ip.unwrap().to_be_bytes();
    ocs.public_mac =
        Some([0xa8, 0x40, 0x25, ip_bytes[1], ip_bytes[2], ip_bytes[3]]);

    let nat = DynNat4::new(
        "dyn-nat4".to_string(),
        ocs.private_ip.unwrap(),
        ocs.guest_mac,
        ocs.public_mac.unwrap(),
    );
    let layer = Layer::new("dyn-nat4", Action::Stateful(Box::new(nat)));

    let mut rule = Rule::new(1, RuleAction::Allow);
    rule.add_predicate(Predicate::InnerIpProto(vec![
        IpProtoMatch::Exact(Protocol::TCP),
        IpProtoMatch::Exact(Protocol::UDP),
    ]));

    // RFD 21 §2.10.4 (Primary and Multiple Interfaces) dictates that
    // there may be more than one interface, but one is primary.
    //
    //  * A given guest may only ever be a part of one VPC, i.e. every
    //    interface in a guest sits in the same VPC.
    //
    //  * However, each interface may be on a different subnet within
    //    the VPC.
    //
    //  * Only the primary interface participates in DNS, ephemeral &
    //    floating public IP, and is specified as the default route to
    //    the guest via DHCP
    //
    // All this means that I can determine if a address needs NAT
    // translation by checking to see if the destination IP belongs to
    // the interface's subnet. As each interface, for now, has its own
    // opte instance, it should be whatever IP + CIDR it was assigned
    // (as opposed to some table mapping src L2 src address to
    // IP+CIDR).
    rule.add_predicate(Predicate::Not(Box::new(Predicate::InnerDstIp4(vec![
        Ipv4AddrMatch::Prefix(ocs.vpc_sub4.unwrap().get_cidr()),
    ]))));
    layer.add_rule(Direction::Out, rule);
    ocs.port.add_layer(layer, Pos::After("firewall"));
    Ok(())
}

// TODO: Implement safe wrapper around arg/ddi_copyin() + mode that
// provides ability to read Rust structure from provided arg. Use
// rust-for-linux `UserSlicePtr` as inspiration. However, ours will be
// different because we have to consider layered drivers and the
// `mode` argument.
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
        Err(_) => return EINVAL,
    };

    match cmd {
        // TODO While this is fine for now we probably want something
        // much more controlled in the future. Setting the guest IP +
        // VPC subnet should be done at (Port) creation and should
        // probably never change (without destroying/recreating the
        // interface). If this is something that can change, it
        // probably requires a quiescence and barrier for all traffic.
        // We need to do it this way for now because it's actually
        // viona creating the opte instance at the moment, when really
        // opte should probably be a vnic-like thing and be created by
        // the control plane and assigned to a guest's interface.
        //
        // You'll also notice there is no mutex around the subnet
        // value...once again, this is temporary.
        IoctlCmd::SetVpcSubnet4 => {
            let mut ioctlenv =
                match IoctlEnvelope::new(arg as *const c_void, mode) {
                    Ok(val) => val,
                    _ => return EFAULT,
                };

            let req: SetVpcSubnet4Req = match ioctlenv.copy_in_req() {
                Ok(val) => val,
                Err(ioctl::Error::DeserError(_)) => return EINVAL,
                _ => return EFAULT,
            };

            let state = &*(ddi_get_driver_private(opte_dip) as *mut OpteState);
            let ocs = &mut *state.client.unwrap();
            ocs.vpc_sub4 = match VpcSubnet4::from_req(req) {
                Ok(v) => Some(v),

                // TODO There is no reason to limit ourselves to
                // errno.h. Allow all responses to include error
                // reason + message to pass back up to userland.
                Err(_) => {
                    return EINVAL;
                }
            };

            let resp = SetVpcSubnet4Resp { resp: Ok(()) };
            match ioctlenv.copy_out_resp(&resp) {
                Ok(()) => return 0,
                Err(ioctl::Error::RespTooLong) => return ENOBUFS,
                Err(_) => return EFAULT,
            }
        }

        IoctlCmd::SetIpConfig => {
            let mut ioctlenv =
                match IoctlEnvelope::new(arg as *const c_void, mode) {
                    Ok(val) => val,
                    _ => return EFAULT,
                };

            let req: SetIpConfigReq = match ioctlenv.copy_in_req() {
                Ok(val) => val,
                Err(ioctl::Error::DeserError(_)) => return EINVAL,
                _ => return EFAULT,
            };

            let state = &*(ddi_get_driver_private(opte_dip) as *mut OpteState);
            let ocs = &mut *state.client.unwrap();

            let (code, val) = match set_ip_config(req, ocs) {
                Ok(_) => (0, Ok(())),
                Err((code, msg)) => (code, Err(msg)),
            };

            let resp = SetIpConfigResp { resp: val };
            match ioctlenv.copy_out_resp(&resp) {
                Ok(()) => return code,
                Err(ioctl::Error::RespTooLong) => return ENOBUFS,
                Err(_) => return EFAULT,
            }
        }

        IoctlCmd::FwAddRule => {
            let mut ioctlenv =
                match IoctlEnvelope::new(arg as *const c_void, mode) {
                    Ok(val) => val,
                    _ => return EFAULT,
                };

            let req: FwAddRuleReq = match ioctlenv.copy_in_req() {
                Ok(val) => val,
                Err(ioctl::Error::DeserError(_)) => return EINVAL,
                _ => return EFAULT,
            };

            let state = &*(ddi_get_driver_private(opte_dip) as *mut OpteState);
            let ocs = &*state.client.unwrap();
            // TODO actually check response.
            let dir = req.rule.direction;
            let rule = Rule::from(req.rule);
            // let res = firewallng::add_fw_rule(&ocs.port, req.rule);
            let res = ocs.port.add_rule("firewall", dir, rule);
            let resp = FwAddRuleResp { resp: res };

            match ioctlenv.copy_out_resp(&resp) {
                Ok(()) => return 0,
                Err(ioctl::Error::RespTooLong) => return ENOBUFS,
                Err(_) => return EFAULT,
            }
        }

        IoctlCmd::FwRemRule => {
            let mut ioctlenv =
                match IoctlEnvelope::new(arg as *const c_void, mode) {
                    Ok(val) => val,
                    _ => return EFAULT,
                };

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
            let ocs = &*state.client.unwrap();
            let res = ocs.port.remove_rule("firewall", req.dir, req.id);
            let resp = FwRemRuleResp { resp: res };

            match ioctlenv.copy_out_resp(&resp) {
                Ok(()) => return 0,
                Err(ioctl::Error::RespTooLong) => return ENOBUFS,
                Err(_) => return EFAULT,
            }
        }

        IoctlCmd::TcpFlowsDump => {
            let mut ioctlenv =
                match IoctlEnvelope::new(arg as *const c_void, mode) {
                    Ok(val) => val,
                    _ => return EFAULT,
                };

            let _req: TcpFlowsDumpReq = match ioctlenv.copy_in_req() {
                Ok(val) => val,
                Err(ioctl::Error::DeserError(_)) => return EINVAL,
                _ => return EFAULT,
            };
            let state = &*(ddi_get_driver_private(opte_dip) as *mut OpteState);
            let ocs = &*state.client.unwrap();
            let resp = ocs.port.dump_tcp_flows();
            match ioctlenv.copy_out_resp(&resp) {
                Ok(()) => return 0,
                Err(ioctl::Error::RespTooLong) => return ENOBUFS,
                Err(_) => return EFAULT,
            }
        }

        IoctlCmd::LayerDump => {
            let mut ioctlenv =
                match IoctlEnvelope::new(arg as *const c_void, mode) {
                    Ok(val) => val,
                    _ => return EFAULT,
                };

            let req: LayerDumpReq = match ioctlenv.copy_in_req() {
                Ok(val) => val,
                Err(ioctl::Error::DeserError(_)) => return EINVAL,
                _ => return EFAULT,
            };

            let state = &*(ddi_get_driver_private(opte_dip) as *mut OpteState);
            let ocs = &*state.client.unwrap();
            let resp = ocs.port.dump_layer(&req.name);

            if resp.is_none() {
                return ENOENT;
            }

            match ioctlenv.copy_out_resp(&resp.unwrap()) {
                Ok(()) => return 0,
                Err(ioctl::Error::RespTooLong) => return ENOBUFS,
                Err(_) => return EFAULT,
            }
        }

        IoctlCmd::UftDump => {
            let mut ioctlenv =
                match IoctlEnvelope::new(arg as *const c_void, mode) {
                    Ok(val) => val,
                    _ => return EFAULT,
                };

            let _req: UftDumpReq = match ioctlenv.copy_in_req() {
                Ok(val) => val,
                Err(ioctl::Error::DeserError(_)) => return EINVAL,
                _ => return EFAULT,
            };

            let state = &*(ddi_get_driver_private(opte_dip) as *mut OpteState);
            let ocs = &*state.client.unwrap();
            let resp = ocs.port.dump_uft();

            match ioctlenv.copy_out_resp(&resp) {
                Ok(()) => return 0,
                Err(ioctl::Error::RespTooLong) => return ENOBUFS,
                Err(_) => return EFAULT,
            }
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

    // We create one minor node to act as the control port for
    // modifying/querying the firewall of the single viona client.
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
    // We could use id_space_create(9F) and ddi_soft_state_init(9F) to
    // support multiple viona links (and thus bhyve instances), but
    // for now the prototype is limited to a single instance/link.
    let ret = mod_install(&opte_linkage);
    if ret != 0 {
        return ret;
    }

    0
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
// mblk + header parsing below
//
// This is a big disorganized heap for now. This is basically a copy
// pasta of my opte-src-and-parsing experiment.
// ================================================================
#[derive(Clone, Copy)]
struct MblkPacket {
    // TODO The more I think about it the more I think I should just
    // convert into a slice via slice::from_raw_parts(). Let's go over
    // the safety requirements of this interface and see how the
    // illumos mblk meets them (I'm going to reference the points in
    // turn and not repeat them verbatim here):
    //
    // I realized as I'm typing this I'm really talking about turning
    // the b_rptr into a slice (`&[u8]`). I should update this struct
    // to instead have `cur_buf: &mut [u8]` along with a raw pointer
    // (or perhaps also a reference for that) to the raw mblk.
    //
    // https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html
    //
    //    o The mblk itself is a single object (allocation) and its
    //      data buffer consist of a single object. Of course, the
    //      real packet may span multiple mblks, but that's when we
    //      walk to the next mblk and update the slice reference (e.g.
    //      when using MblkPacketReader).
    //
    //    o The mblk is non-null, we could also just add a check of
    //      the raw pointer before the call to be extra sure.
    //
    //    o The allocation for the mblk is aligned, as is the data
    //      buffer (which is easy since it's just `char *`).
    //
    //    o The `b_rptr` points to exactly `cur_len` bytes, "properly
    //      initialized", which isn't defined here. I guess it just
    //      means that the mblk's data buffer didn't just come filled
    //      with whatever bytes were left from a previous allocation?
    //      I think we do zero them explicitly before use, but not
    //      really sure how it matters given any string of bits will
    //      make a valid u8. And in fact, the entire reason we are
    //      parsing this buffer stream is to a) check that the stream
    //      of bytes actually makes valid headers, and b) to
    //      initialize header structs from these bytes.
    //
    //    o OPTE is basically an extension of mac, and as with mac it
    //      can and should assume that no other entity is
    //      reading/writing to the buffer as its working with it.
    //      Could a nefarious actor try to break this contract, sure,
    //      and that's why viona's first action in the Tx path is to
    //      copy all header bytes into a fresh, host-owned mblk to
    //      pass to the rest of the system, to prevent TOCTOU attack.
    //      If other part of illumos are violating this contract, then
    //      they would not just be breaking OPTE, but all of mac and
    //      probably other parts of the system. Basically, when an
    //      mblk pointer is passed to a module, that module "owns" it
    //      (really the kmem allocator owns the memory, which
    //      effecitvely makes everyone else a `&mut [u8]` like
    //      consumer). That's all a long way of saying that Rust's
    //      aliasing rules for a unique reference (`&mut`) are upheld
    //      by illumos re mblks.
    //
    //    o The largest mblk buffer is 64K. Perhaps one day that will
    //      increase but it should never touch the realm of
    //      `isize::MAX`, otherwise we have many other harder problems
    //      than this one.
    source_mp: *mut mblk_t,
    cur_len: usize,
}

impl MblkPacket {
    fn alloc(size: usize) -> Self {
        // TODO Could replace `usize` with a type like MblkSize.
        assert!(size <= u16::MAX as usize);

        // Safety: We know this is safe because allocb should be safe
        // for any size. Furthermore, we restrict size to the typical
        // max IP packet, which is definitely safe.
        let mp = unsafe { allocb(size, 0) };
        MblkPacket::wrap(mp)
    }

    fn copy_bytes(&mut self, src: &[u8]) {
        // TODO check len against avail and return error.

        // Safety: This is actually unsafe right now until I check
        // that src.len() fits inside the space available between
        // b_wptr and the limit of the dblk.
        unsafe {
            bcopy(
                src.as_ptr() as *const c_void,
                (*self.source_mp).b_wptr as *mut c_void,
                src.len(),
            );

            // TODO Add "safety" annotation here.
            (*self.source_mp).b_wptr = (*self.source_mp).b_wptr.add(src.len());
        }
    }

    /// Get the length of the entire packet.
    ///
    /// TODO In the future we might want to perform memoization, but
    /// we'd have to be careful if we're modifying the underlying
    /// bytes. For now the caller can choose to cache the result if
    /// they want.
    ///
    /// TODO We might want a mblk_lengths() that gives the length of
    /// each fragment (mblk) that makes up the packet.
    ///
    /// ```
    /// fn mblk_lengths(&self) -> Vec<usize>
    /// ```
    #[allow(dead_code)]
    fn len(&self) -> usize {
        // Safety: If we have an instance of MblkPacket, which can
        // only be created via `new`, then we know there is a valid
        // `mblk_t` pointer in `source_mp`.
        unsafe { msgsize(self.source_mp) }
    }

    fn unwrap(self) -> *mut mblk_t {
        self.source_mp
    }

    fn wrap(mp: *mut mblk_t) -> Self {
        let cur_len;
        unsafe {
            cur_len = (*mp).b_wptr.offset_from((*mp).b_rptr) as usize;
        }
        MblkPacket { source_mp: mp, cur_len }
    }
}

impl Packet for MblkPacket {}

struct MblkPacketReader {
    pkt: MblkPacket,
    cur_pos: usize,
    total_pos: usize,
}

impl MblkPacketReader {
    fn new(pkt: MblkPacket) -> MblkPacketReader {
        MblkPacketReader { pkt, cur_pos: 0, total_pos: 0 }
    }

    fn follow_cont(&mut self) {
        assert!(self.cur_pos <= self.pkt.cur_len);

        unsafe {
            if self.cur_pos == self.pkt.cur_len
                && !(*self.pkt.source_mp).b_cont.is_null()
            {
                self.pkt = MblkPacket::wrap((*self.pkt.source_mp).b_cont);
                self.cur_pos = 0;
            }
        }
    }

    // Any given read should _never_ cross a `b_cont` boundary. In
    // fact, a given header should always be contained in one mblk,
    // because when you think about it any given header should be
    // contained in the same allocation. Therefore, I think it is
    // reasonable to reject any packets which have a header crossing a
    // `b_cont` boundary.
    fn check_buf(&mut self, len: usize) -> input::Result<()> {
        self.follow_cont();

        if self.cur_pos + len > self.pkt.cur_len {
            unsafe {
                if !(*self.pkt.source_mp).b_cont.is_null() {
                    return Err(ReadErr::StraddledHeader);
                }
            }

            return Err(ReadErr::NotEnoughBytes);
        }

        Ok(())
    }
}

impl PacketReader for MblkPacketReader {
    fn get_slice(
        &mut self,
        len: usize,
    ) -> core::result::Result<&[u8], ReadErr> {
        self.check_buf(len)?;
        let start = unsafe { (*self.pkt.source_mp).b_rptr.add(self.cur_pos) };
        let ret = unsafe { slice::from_raw_parts(start, len) };
        self.cur_pos += len;
        self.total_pos += len;
        Ok(ret)
    }

    fn get_slice_mut(
        &mut self,
        len: usize,
    ) -> core::result::Result<&mut [u8], ReadErr> {
        self.check_buf(len)?;
        let start = unsafe { (*self.pkt.source_mp).b_rptr.add(self.cur_pos) };
        let ret = unsafe { slice::from_raw_parts_mut(start, len) };
        self.cur_pos += len;
        self.total_pos += len;
        Ok(ret)
    }

    fn read_bytes(&mut self, dst: &mut [u8]) -> input::Result<()> {
        self.check_buf(dst.len())?;

        unsafe {
            let start = (*self.pkt.source_mp).b_rptr.add(self.cur_pos);
            start.copy_to_nonoverlapping(dst.as_mut_ptr(), dst.len());
        }

        self.cur_pos += dst.len();
        self.total_pos += dst.len();
        Ok(())
    }

    fn read_u8(&mut self, dst: &mut u8) -> input::Result<()> {
        self.check_buf(1)?;

        unsafe {
            let mut tmp = [0u8; 1];
            let start = (*self.pkt.source_mp).b_rptr.add(self.cur_pos);
            start.copy_to_nonoverlapping(tmp.as_mut_ptr(), tmp.len());
            *dst = u8::from_be_bytes(tmp);
        }

        self.cur_pos += 1;
        self.total_pos += 1;
        Ok(())
    }

    fn read_u16(&mut self, dst: &mut u16) -> input::Result<()> {
        self.check_buf(2)?;

        unsafe {
            let mut tmp = [0u8; 2];
            let start = (*self.pkt.source_mp).b_rptr.add(self.cur_pos);
            start.copy_to_nonoverlapping(tmp.as_mut_ptr(), tmp.len());
            *dst = u16::from_be_bytes(tmp);
        }

        self.cur_pos += 2;
        self.total_pos += 2;
        Ok(())
    }

    fn read_u32(&mut self, dst: &mut u32) -> input::Result<()> {
        self.check_buf(4)?;

        unsafe {
            let mut tmp = [0u8; 4];
            let start = (*self.pkt.source_mp).b_rptr.add(self.cur_pos);
            start.copy_to_nonoverlapping(tmp.as_mut_ptr(), tmp.len());
            *dst = u32::from_be_bytes(tmp);
        }

        self.cur_pos += 4;
        self.total_pos += 4;
        Ok(())
    }

    // We only allow to seek backwards to the beginning of the current
    // mblk, which should be enough in all situations this is needed.
    fn seek_back(&mut self, offset: usize) -> input::Result<()> {
        if offset > self.cur_pos {
            return Err(ReadErr::NotEnoughBytes);
        }

        self.cur_pos -= offset;
        Ok(())
    }

    fn seek(&mut self, offset: usize) -> input::Result<()> {
        self.check_buf(offset)?;
        self.cur_pos += offset;
        self.total_pos += offset;
        Ok(())
    }
}

// ================================================================
// mac client intercept APIs
//
// Thes APIs are meant to mimic the mac client APIs, allowing opte to
// act as an intermediary between viona and mac.
// ================================================================
pub struct OpteClientState {
    mch: *mut mac_client_handle,
    rx_state: Option<OpteRxState>,
    mph: *const mac_promisc_handle,
    promisc_state: Option<OptePromiscState>,
    port: Box<Port>,
    port_periodic: *const ddi_periodic,
    guest_mac: EtherAddr,
    // TODO: Technically the following four fields should be protected
    // by a KMutex, but ideally opte shouldn't be hard-coded into
    // viona and these values would be setup as part of Port creation.
    vpc_sub4: Option<VpcSubnet4>,
    private_ip: Option<Ipv4Addr>,
    public_ip: Option<Ipv4Addr>,
    public_mac: Option<[u8; 6]>,
    // Mock ARP queue (for faking out NAT until we have a real Oxide
    // physical network).
    marp_queue: KMutex<Vec<MblkPacket>>,
}

const ONE_SECOND: hrtime_t = 1_000_000_000;

#[no_mangle]
pub unsafe extern "C" fn opte_port_periodic(arg: *mut c_void) {
    // The `arg` is a raw pointer to an `Port`, as guaranteed by
    // opte_client_open().
    let port = &*(arg as *const Port);
    port.expire_flows(gethrtime());
}

#[no_mangle]
pub unsafe extern "C" fn opte_client_open(
    mh: *const mac_handle,
    ocspo: *mut *const OpteClientState,
    name: *const c_char,
    flags: u16,
) -> c_int {
    let mut mch = 0 as *mut mac_client_handle;
    let ret = mac_client_open(mh, &mut mch, name, flags);
    if ret != 0 {
        return ret;
    }

    let mut guest_mac: EtherAddr = [0; 6];
    mac_unicast_primary_get(mh, &mut guest_mac);
    let port = Box::new(Port::new(
        CStr::from_ptr(name).to_str().unwrap().to_string(),
        guest_mac,
    ));

    let fw_layer = Firewall::create_layer();
    port.add_layer(fw_layer, Pos::First);

    let port_periodic = ddi_periodic_add(
        opte_port_periodic,
        port.as_ref() as *const Port as *const c_void,
        ONE_SECOND,
        DDI_IPL_0,
    );

    let ocs = Box::new(OpteClientState {
        mch,
        rx_state: None,
        mph: 0 as *mut mac_promisc_handle,
        promisc_state: None,
        port,
        port_periodic,
        guest_mac,
        vpc_sub4: None,
        private_ip: None,
        public_ip: None,
        public_mac: None,
        marp_queue: KMutex::new(Vec::with_capacity(4), KMutexType::Driver),
    });

    let state = &mut *(ddi_get_driver_private(opte_dip) as *mut OpteState);
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
    let ocsp = Box::into_raw(ocs);
    *ocspo = ocsp;
    state.client = Some(ocsp);
    0
}

#[no_mangle]
pub unsafe extern "C" fn opte_client_close(
    ocsp: *mut OpteClientState,
    flags: u16,
) {
    // The ownership of `ocs` is being given back to opte. We need to
    // put it back in the box so that the value and its owned
    // resources are properly dropped.
    let ocs = Box::from_raw(ocsp);
    let state = &mut *(ddi_get_driver_private(opte_dip) as *mut OpteState);
    let _ = state.client.take();

    // First, tell mac we no longer want to be a client.
    mac_client_close(ocs.mch, flags);

    // Stop the periodic before dropping everything.
    ddi_periodic_delete(ocs.port_periodic);

    // Resources dropped with `ocs`.
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

// It's easy to become confused by endianess and networking code when
// looking at code that deals with checksums; it's worth making clear
// what is going on.
//
// Any logical value stored in a network header (or application data
// for that matter) needs to consider endianess. That is, a multi-byte
// value like an IP header's "total length" or TCP's "port", which has
// a logical value like "total length = 60" or "port = 443", needs to
// make sure its value is interpreted correctly no matter which byte
// order the underlying hardware uses. To this effect, all logical
// values sent across the network are sent in "network order" (big
// endian) and then adjusted accordingly on the host. In an AMD64 arch
// you will see network code which calls `hton{s,l}()` in order to
// convert the logical value in memory to the correct byte order for
// the network. However, not all values have a logical, numerial
// meaning. For example, a mac address is made up of 6 consecutive
// bytes, for which the order is important, but this string of bytes
// is never interpreted as an integer. Thus, there is no conversion to
// be made: the bytes are in the same order in the network as they are
// in memory (because they are just that, a sequence of bytes). The
// same goes for the various checksums. The internet checksum is just
// a sequence of two bytes. However, in order to implement the
// checksum (one's complement sum), we happen to treat these two bytes
// as a 16-bit integer, and the sequence of bytes to be summed as a
// set of 16-bit integers. Because of this it's easy to think of the
// checksum as a logical value when it's really not. This brings us to
// the point: you never perform byte-order conversion on the checksum
// field. You treat each pair of bytes (both the checksum field
// itself, and the bytes you are summing) as if it's a native 16-bit
// integer. Yes, this means that on a little-endian architecture you
// are logically flipping the bytes, but as the bytes being summed are
// all in network-order, you are also storing them in network-order
// when you write the final sum to memory.
//
// While said a slightly different way, this is also covered in RFC
// 1071 §1.B.
//
// > Therefore, the sum may be calculated in exactly the same way
// > regardless of the byte order ("big-endian" or "little-endian")
// > of the underlaying hardware.  For example, assume a "little-
// > endian" machine summing data that is stored in memory in network
// > ("big-endian") order.  Fetching each 16-bit word will swap
// > bytes, resulting in the sum [4]; however, storing the result
// > back into memory will swap the sum back into network byte order.
fn set_headers(
    _ocs: &OpteClientState,
    meta: &PacketMeta,
    mut rdr: MblkPacketReader,
) {
    let mut ether = match EtherHdrRaw::parse_mut::<MblkPacketReader>(&mut rdr) {
        Ok(v) => v,
        Err(err) => {
            dbg(format!("error reading ether header: {:?}", err));
            return;
        }
    };

    ether.src = meta.inner_ether.as_ref().unwrap().src;
    ether.dst = meta.inner_ether.as_ref().unwrap().dst;
    drop(ether);

    let mut ip4 = match Ipv4HdrRaw::parse_mut::<MblkPacketReader>(&mut rdr) {
        Ok(v) => v,
        Err(e) => {
            dbg(format!("error reading IPv4 header: {:?}", e));
            return;
        }
    };

    // We stash these here because we need them for the pseudo-header
    // checksum update for the ULP.
    let old_ip_src = ip4.src;
    let old_ip_dst = ip4.dst;
    let (new_ip_src, new_ip_dst, proto) = match meta.inner_ip.as_ref().unwrap()
    {
        IpMeta::Ip4(v) => (v.src.to_be_bytes(), v.dst.to_be_bytes(), v.proto),
        _ => panic!("unexpected IPv6 in set_headers"),
    };

    let mut csum: u32 = (!u16::from_ne_bytes(ip4.csum)) as u32;
    csum_incremental(
        &mut csum,
        u16::from_ne_bytes([ip4.src[0], ip4.src[1]]),
        u16::from_ne_bytes([new_ip_src[0], new_ip_src[1]]),
    );
    csum_incremental(
        &mut csum,
        u16::from_ne_bytes([ip4.src[2], ip4.src[3]]),
        u16::from_ne_bytes([new_ip_src[2], new_ip_src[3]]),
    );
    csum_incremental(
        &mut csum,
        u16::from_ne_bytes([ip4.dst[0], ip4.dst[1]]),
        u16::from_ne_bytes([new_ip_dst[0], new_ip_dst[1]]),
    );
    csum_incremental(
        &mut csum,
        u16::from_ne_bytes([ip4.dst[2], ip4.dst[3]]),
        u16::from_ne_bytes([new_ip_dst[2], new_ip_dst[3]]),
    );
    assert_eq!(csum & 0xFFFF_0000, 0);

    ip4.src = new_ip_src;
    ip4.dst = new_ip_dst;
    // Note: We do not convert the endianess of the checksum because
    // the sum was computed in network order. If you change this to
    // `to_be_bytes()`, you will break the checksum.
    ip4.csum = (!(csum as u16)).to_ne_bytes();

    drop(ip4);

    match proto {
        Protocol::UDP => {
            let mut udp =
                match UdpHdrRaw::parse_mut::<MblkPacketReader>(&mut rdr) {
                    Ok(udp) => udp,
                    Err(err) => {
                        dbg(format!("error parsing UDP header: {:?}", err));
                        return;
                    }
                };

            let (new_sport, new_dport) = match meta.ulp.as_ref().unwrap() {
                UlpMeta::Udp(v) => (v.src.to_be_bytes(), v.dst.to_be_bytes()),
                _ => panic!("ULP data doesn't match IP protocol"),
            };
            let mut csum: u32 = (!u16::from_ne_bytes(udp.csum)) as u32;

            // Update pseudo-header checksum.
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([old_ip_src[0], old_ip_src[1]]),
                u16::from_ne_bytes([new_ip_src[0], new_ip_src[1]]),
            );
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([old_ip_src[2], old_ip_src[3]]),
                u16::from_ne_bytes([new_ip_src[2], new_ip_src[3]]),
            );
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([old_ip_dst[0], old_ip_dst[1]]),
                u16::from_ne_bytes([new_ip_dst[0], new_ip_dst[1]]),
            );
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([old_ip_dst[2], old_ip_dst[3]]),
                u16::from_ne_bytes([new_ip_dst[2], new_ip_dst[3]]),
            );

            // Update UDP checksum.
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([udp.src_port[0], udp.src_port[1]]),
                u16::from_ne_bytes([new_sport[0], new_sport[1]]),
            );
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([udp.dst_port[0], udp.dst_port[1]]),
                u16::from_ne_bytes([new_dport[0], new_dport[1]]),
            );
            assert_eq!(csum & 0xFFFF_0000, 0);

            udp.src_port = new_sport;
            udp.dst_port = new_dport;
            udp.csum = (!(csum as u16)).to_ne_bytes();
        }

        Protocol::TCP => {
            let mut tcp =
                match TcpHdrRaw::parse_mut::<MblkPacketReader>(&mut rdr) {
                    Ok(tcp) => tcp,
                    Err(err) => {
                        dbg(format!("error parsing TCP header: {:?}", err));
                        return;
                    }
                };

            let (new_sport, new_dport) = match meta.ulp.as_ref().unwrap() {
                UlpMeta::Tcp(v) => (v.src.to_be_bytes(), v.dst.to_be_bytes()),
                _ => panic!("ULP data doesn't match IP protocol"),
            };
            let mut csum: u32 = (!u16::from_ne_bytes(tcp.csum)) as u32;

            // Update pseudo-header checksum.
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([old_ip_src[0], old_ip_src[1]]),
                u16::from_ne_bytes([new_ip_src[0], new_ip_src[1]]),
            );
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([old_ip_src[2], old_ip_src[3]]),
                u16::from_ne_bytes([new_ip_src[2], new_ip_src[3]]),
            );
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([old_ip_dst[0], old_ip_dst[1]]),
                u16::from_ne_bytes([new_ip_dst[0], new_ip_dst[1]]),
            );
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([old_ip_dst[2], old_ip_dst[3]]),
                u16::from_ne_bytes([new_ip_dst[2], new_ip_dst[3]]),
            );

            // Update TCP checksum.
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([tcp.src_port[0], tcp.src_port[1]]),
                u16::from_ne_bytes([new_sport[0], new_sport[1]]),
            );
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([tcp.dst_port[0], tcp.dst_port[1]]),
                u16::from_ne_bytes([new_dport[0], new_dport[1]]),
            );
            assert_eq!(csum & 0xFFFF_0000, 0);

            tcp.src_port = new_sport;
            tcp.dst_port = new_dport;
            tcp.csum = (!(csum as u16)).to_ne_bytes();
        }

        _ => (),
    }
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

    let pkt = MblkPacket::wrap(mp_chain);
    let mut rdr = MblkPacketReader::new(pkt);
    // TODO probably don't need ocs/ocsp to be mut?
    let ocs = &mut *ocsp;
    let mut meta_old = PacketMetaOld::new(Direction::Out);
    let ether = match EtherHdrRaw::parse::<MblkPacketReader>(&mut rdr) {
        Ok(ehdr_raw) => ehdr_raw,
        Err(err) => {
            dbg(format!("error reading raw ether header: {:?}", err));
            freemsgchain(mp_chain);
            return;
        }
    };

    meta_old.ether_src = ether.src;
    meta_old.ether_dst = ether.dst;
    let etype = u16::from_be_bytes(ether.ether_type);

    // TODO: Deal with non-IPv4.
    if etype != 0x800 {
        mac_tx(ocs.mch, mp_chain, hint, flag, ret_mp);
        return;
    }
    drop(ether);

    let mut rdr = MblkPacketReader::new(pkt);
    let meta =
        match ocs.port.process(Direction::Out, &mut rdr, mp_chain as uintptr_t)
        {
            Some(val) => val,
            None => {
                freemsgchain(mp_chain);
                return;
            }
        };

    set_headers(ocs, &meta, MblkPacketReader::new(pkt));
    mac_tx(ocs.mch, mp_chain, hint, flag, ret_mp);

    // Send out any fake ARP replies. The underlying `mblk_t` is now
    // owned (and later freed) by `mac_tx()`.
    let mut marp_queue = ocs.marp_queue.lock().unwrap();
    while let Some(mp) = marp_queue.pop() {
        mac_tx(ocs.mch, mp.unwrap(), hint, flag, ret_mp);
    }
}

// This doesn't need to be no_mangle, but I like keeping callbacks
// demangled.
//
// TODO arg should change to *const OpteClientState, that way we don't
// have to stash circular ref/pointers between OpteClientState and
// OpteRxState.
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

    let pkt = MblkPacket::wrap(mp_chain);
    let mut rdr = MblkPacketReader::new(pkt);
    let ocs = &*(arg as *const OpteClientState);
    let mut meta_old = PacketMetaOld::new(Direction::In);
    let ehdr = match EtherHdrRaw::parse::<MblkPacketReader>(&mut rdr) {
        Ok(v) => v,
        Err(err) => {
            dbg(format!("error reading ether header: {:?}", err));
            freemsgchain(mp_chain);
            return;
        }
    };
    meta_old.ether_src = ehdr.src;
    meta_old.ether_dst = ehdr.dst;
    let etype = u16::from_be_bytes(ehdr.ether_type);
    let rx_state = ocs.rx_state.as_ref().unwrap();

    // TODO: Deal with non-IPv4
    if etype != ETHER_TYPE_IPV4 && etype != ETHER_TYPE_ARP {
        (rx_state.rx_fn)(rx_state.arg, mrh, mp_chain, loopback);
        return;
    }

    if etype == ETHER_TYPE_ARP {
        let arp_raw = match ArpHdrRaw::parse::<MblkPacketReader>(&mut rdr) {
            Ok(v) => v,
            Err(err) => {
                dbg(format!("error reading ARP header: {:?}", err));
                freemsgchain(mp_chain);
                return;
            }
        };

        let htype = u16::from_be_bytes(arp_raw.htype);

        if htype != ARP_HTYPE_ETHERNET {
            dbg(format!("unexpected ARP hardware type: {}", htype));
            freemsgchain(mp_chain);
            return;
        }

        let _arp_hw = ArpHardware::Ethernet(arp_raw.hlen);
        let _arp_proto = match u16::from_be_bytes(arp_raw.ptype) {
            ETHER_TYPE_IPV4 => ArpProtocol::Ip4(arp_raw.plen),
            proto_type => {
                dbg(format!("unexpected ARP protocol type: {}", proto_type));
                freemsgchain(mp_chain);
                return;
            }
        };

        let arp_op = ArpOp::try_from(u16::from_be_bytes(arp_raw.op)).unwrap();

        let mut sender_hw = [0u8; 6];
        rdr.read_bytes(&mut sender_hw).unwrap();
        let mut sender_proto = [0u8; 4];
        rdr.read_bytes(&mut sender_proto).unwrap();
        let mut target_hw = [0u8; 6];
        rdr.read_bytes(&mut target_hw).unwrap();
        let mut target_proto = [0u8; 4];
        rdr.read_bytes(&mut target_proto).unwrap();
        let target_ip = Ipv4Addr::from(u32::from_be_bytes(target_proto));

        // We have an ARP request for the instances public IP. In this
        // case opte is acting as the public interface and needs to
        // fool the gateway. All other ARP requests/replies should
        // flow through to the guest untouched.
        //
        // TODO Yes, this is greasy, but it's here temporarily to
        // serve a useful purpose until we have something closer to
        // the real Oxide Physical Network.
        if ArpOp::Req == arp_op
            && ocs.public_ip.is_some()
            && target_ip == ocs.public_ip.unwrap()
        {
            const SZ: usize = mem::size_of::<EtherHdrRaw>()
                + mem::size_of::<ArpHdrRaw>()
                + (6 * 2)
                + (4 * 2);
            let mut reply = Box::new([0u8; SZ]);
            let mut pos = 0;

            let ether = EtherHdrRaw {
                dst: sender_hw,
                src: ocs.public_mac.unwrap(),
                ether_type: ETHER_TYPE_ARP.to_be_bytes(),
            };

            let ether_size = mem::size_of::<EtherHdrRaw>();
            &reply[pos..pos + ether_size].copy_from_slice(ether.as_bytes());
            pos += ether_size;

            let arp = ArpHdrRaw {
                htype: 1u16.to_be_bytes(),
                ptype: ETHER_TYPE_IPV4.to_be_bytes(),
                hlen: 6,
                plen: 4,
                op: 2u16.to_be_bytes(),
            };

            let arp_size = mem::size_of::<ArpHdrRaw>();
            &reply[pos..pos + arp_size].copy_from_slice(arp.as_bytes());
            pos += arp_size;

            // ARP reply body
            &reply[pos..pos + 6].copy_from_slice(&ocs.public_mac.unwrap());
            pos += 6;
            &reply[pos..pos + 4].copy_from_slice(&target_proto);
            pos += 4;
            &reply[pos..pos + 6].copy_from_slice(&sender_hw);
            pos += 6;
            &reply[pos..pos + 4].copy_from_slice(&sender_proto);
            pos += 4;
            assert_eq!(pos, SZ);

            let mut mp = MblkPacket::alloc(SZ);
            mp.copy_bytes(&*reply);
            ocs.marp_queue.lock().unwrap().push(mp);
            freemsgchain(mp_chain);
            return;
        }

        // This is an ARP packet the guest should handle.
        (rx_state.rx_fn)(rx_state.arg, mrh, mp_chain, loopback);
        return;
    }

    drop(ehdr);

    let mut rdr = MblkPacketReader::new(pkt);
    let meta = match ocs.port.process(
        Direction::In,
        &mut rdr,
        mp_chain as uintptr_t,
    ) {
        Some(val) => val,
        None => {
            freemsgchain(mp_chain);
            return;
        }
    };

    set_headers(ocs, &meta, MblkPacketReader::new(pkt));
    (rx_state.rx_fn)(rx_state.arg, mrh, mp_chain, loopback);
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

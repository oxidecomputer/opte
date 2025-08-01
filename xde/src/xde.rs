// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! xde - A mac provider for OPTE.
//!
//! An illumos kernel driver that implements the mac provider
//! interface, allowing one to run network implementations written in
//! the OPTE framework.
//!
//! The XDE driver registers a single minor as a central control device.
//! Ports are created and administrated through ioctls made on this device,
//! referencing the target port by name,
//!
//! ## Locking Constraints
//! Locks in XDE are managed quite delicately, given that we have a central
//! set of ports which all need to be accessed from various contexts.
//! Practically, this means that we can be called into at various priorities,
//! varying degrees of preemptability, and with or without affinity to a given
//! CPU core:
//!  * The datapath. Packets can arrive in XDE from several contexts, at which
//!    point we're responsible for determining which port(s) are responsible
//!    for processing a packet:
//!     1. Packet transmit.
//!       - Occurs from an arbitrary kthread (viona_tx, or IP stack of a zone).
//!       - The port responsible for packet processing is well-known, and
//!         is provided as the argument for `xde_mc_tx`.
//!       - If any processed packet has an outer IPV6 destination belonging to
//!         this system, then we perform loopback processing here rather than
//!         going through MAC. This requires that we lookup a matching port, as
//!         in packet receive.
//!     2. Packet receive.
//!       - Occurs from various places tied to the Rx queue that a packet arrived
//!         on. This can be its interrupt context, its poll thread, a softring
//!         worker, or one of its fanout threads. These are all bound to a CPU,
//!         but we do not know *which*. They can generally assumed to be separate
//!         CPUs on gimlet etc., but may overlap on machines with few cores.
//!       - *May* occur from an arbitrary kthread via MAC loopback, but this is
//!         not a pathway expected in the product. I.e., we should handle this
//!         case *soundly* but not necessarily quickly.
//!       - Packets may arrive for any arbitrary combination of ports. For each
//!         packet, we must lookup a matching `XdeDev` based on its Geneve VNI
//!         and inner MAC address using a `DevMap`.
//!  * Administration ioctls (port add/delete, update of port rules).
//!  * Cleanup tasks via `ddi_periodic`. Various entries in individual ports
//!    and in XDE itself have a finite lifetime, and for these we need to walk
//!    the set of *all ports*.
//!
//! XDE works within this context by maintaining a central canonical `DevMap`
//! within `XdeState` (the DDI private info struct), and providing datapath
//! entrypoints with copies derived from it. Most ioctls (and the cleanup task)
//! use read access to the ground-truth `DevMap`, and those which perform
//! structural/administrative changes (port removal/addition, underlay) use a
//! `TokenLock` to control write access.
//!
//! Once we have a port, things become fairly simple. Today, each port has a
//! central RWLock -- reads/writes are only held for the duration of packet
//! processing, or as long as is required to insert new rules.
//!
//! ### `DevMap` views
//! Ideally, we want the above interactions to have minimal impact on one another
//! (e.g., insertion of a port should not lock out all use of the datapath).
//! For this reason, we provide the datapath entrypoints with read-only shared
//! copies of the central `DevMap`.
//!  * For Rx entrypoints, we allocate a `Vec<KMutex<Arc<DevMap>>>`. Each CPU
//!    on the system has its own slot within this `Vec`, such that there should
//!    never be lock contention unless a port is being added/removed. The CPU ID
//!    is then used as an index into this table, and the lock is held until all
//!    packets are delivered (as all packet deliveries require a live `XdeDev`).
//!  * For Tx entrypoints, each `XdeDev` holds an RWLock around its copy of the
//!    `DevMap`. When needed for delivery, the Rx pathway acquires the read lock.
//!    We prefer an RwLock here over a Mutex[] given that we can be called from
//!    multiple threads, and our callers are not expected to bound to a given CPU.
//!    Most packet deliveries should go via the underlay.
//!
//! Holding the lock in both cases (rather than cloning out the `Arc`) has an
//! inherent risk associated, but this is necessary to ensure that no Rx/Tx
//! contexts will attempt to send a packet to a port which has been (or is being!)
//! removed. Holding a read/lock on the `DevMap` in use ensures that any found
//! port remains alive until any in-progress packet processing is complete.
//!
//! In the Rx case, loopback delivery or MAC->CPU oversubscription present some
//! risk of contention. These are not expected paths in the product, but using
//! them does not impact correctness.
//!
//! The remaining locking risks are double-locking a given Rx Mutex by the same
//! thread, and re-entrant reads on a Tx RwLock without readers-starve-writers
//! configured. The first such case results in a panic, but can only happen if
//! we transit the NIC's Rx path twice in the same stack (i.e. Rx on NIC ->
//! mac_rx on the OPTE port -> ... -> loopback delivery to underlay device).
//! This should be impossible, given that any packet sent upstack by XDE must
//! have a MAC address belonging to the OPTE port.
//!
//! The second exposes us to a deadlock if the ordering `read[xde_mc_tx] ->
//! write[ioctl] -> read[xde_mc_tx]` occurs on one lock -- the latter read
//! acquisition will block indefinitely. This is a possibility we need to
//! consciously work around. Hairpin exchanges (e.g., ARP -> ICMP ping, DHCP)
//! can lead to fairly deep stacks of the form `(ip) -> xde_mc_tx -> (ip) ->
//! xde_mc_tx -> ...` when used with zones (this is not an issue with viona,
//! which returns once packets are communicated to the guest). Thus, we *must*
//! drop the read before delivering any hairpin packets.
//!
//! ### `TokenLock` and `DevMap` updates
//! The `TokenLock` primitive provides us with logical mutual exclusion around
//! the underlay and the ability to modify the canonical `DevMap` -- without
//! holding a `KMutex`. Management operations made by OPTE *will* upcall -- we
//! must resolve link names to IDs, and add/remove link information from DLS.
//! Doing so makes an ioctl thread vulnerable to receiving signals, so other
//! threads trying to take the management lock must be able to take, e.g.,
//! a SIGSTOP.
//!
//! Whenever the central `DevMap` is modified, we iterate through each reachable
//! `XdeDev` and underlay port, and for every instance of the cloned `DevMap` we
//! write()/lock() that entry, replace it with the new contents, and drop the
//! lock. This ensures that port removal cannot fully proceed until the port is
//! no longer usable from any Tx/Rx context.

use crate::dev_map::DevMap;
use crate::dev_map::ReadOnlyDevMap;
use crate::dev_map::VniMac;
use crate::dls;
use crate::dls::DlsStream;
use crate::dls::LinkId;
use crate::ioctl::IoctlEnvelope;
use crate::mac;
use crate::mac::ChecksumOffloadCapabs;
use crate::mac::MacClient;
use crate::mac::MacEmul;
use crate::mac::MacHandle;
use crate::mac::MacSiphon;
use crate::mac::MacTxFlags;
use crate::mac::OffloadInfo;
use crate::mac::TcpLsoFlags;
use crate::mac::TxHint;
use crate::mac::lso_basic_tcp_ipv4_t;
use crate::mac::lso_basic_tcp_ipv6_t;
use crate::mac::mac_capab_cso_t;
use crate::mac::mac_capab_lso_t;
use crate::mac::mac_getinfo;
use crate::mac::mac_hw_emul;
use crate::mac::mac_private_minor;
use crate::postbox::Postbox;
use crate::postbox::TxPostbox;
use crate::route::Route;
use crate::route::RouteCache;
use crate::route::RouteKey;
use crate::secpolicy;
use crate::stats::XdeStats;
use crate::sys::current_cpu;
use crate::sys::ncpus;
use crate::warn;
use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::num::NonZeroU32;
use core::ptr;
use core::ptr::NonNull;
use core::ptr::addr_of;
use core::ptr::addr_of_mut;
use core::time::Duration;
use illumos_sys_hdrs::mac::MacEtherOffloadFlags;
use illumos_sys_hdrs::mac::MacTunType;
use illumos_sys_hdrs::mac::MblkOffloadFlags;
use illumos_sys_hdrs::mac::mac_ether_offload_info_t;
use illumos_sys_hdrs::*;
use ingot::ethernet::Ethertype;
use ingot::geneve::Geneve;
use ingot::geneve::GeneveRef;
use ingot::ip::IpProtocol;
use ingot::types::HeaderLen;
use ingot::udp::Udp;
use opte::ExecCtx;
use opte::api::ClearLftReq;
use opte::api::ClearUftReq;
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
use opte::api::OpteError;
use opte::api::SetXdeUnderlayReq;
use opte::api::XDE_IOC_OPTE_CMD;
use opte::d_error::LabelBlock;
use opte::ddi::kstat::KStatNamed;
use opte::ddi::kstat::KStatProvider;
use opte::ddi::mblk::AsMblk;
use opte::ddi::mblk::MsgBlk;
use opte::ddi::mblk::MsgBlkChain;
use opte::ddi::sync::KMutex;
use opte::ddi::sync::KRwLock;
use opte::ddi::sync::KRwLockReadGuard;
use opte::ddi::sync::KRwLockWriteGuard;
use opte::ddi::sync::TokenGuard;
use opte::ddi::sync::TokenLock;
use opte::ddi::time::Interval;
use opte::ddi::time::Periodic;
use opte::engine::NetworkImpl;
use opte::engine::ether::Ethernet;
use opte::engine::ether::EthernetRef;
use opte::engine::geneve::Vni;
use opte::engine::headers::IpAddr;
use opte::engine::ip::v6::Ipv6;
use opte::engine::ip::v6::Ipv6Addr;
use opte::engine::packet::InnerFlowId;
use opte::engine::packet::Packet;
use opte::engine::packet::ParseError;
use opte::engine::parse::ValidUlp;
use opte::engine::port::Port;
use opte::engine::port::PortBuilder;
use opte::engine::port::ProcessResult;
use oxide_vpc::api::AddFwRuleReq;
use oxide_vpc::api::AddRouterEntryReq;
use oxide_vpc::api::ClearVirt2BoundaryReq;
use oxide_vpc::api::ClearVirt2PhysReq;
use oxide_vpc::api::CreateXdeReq;
use oxide_vpc::api::DelRouterEntryReq;
use oxide_vpc::api::DelRouterEntryResp;
use oxide_vpc::api::DeleteXdeReq;
use oxide_vpc::api::DhcpCfg;
use oxide_vpc::api::DumpVirt2BoundaryResp;
use oxide_vpc::api::DumpVirt2PhysResp;
use oxide_vpc::api::ListPortsResp;
use oxide_vpc::api::PhysNet;
use oxide_vpc::api::PortInfo;
use oxide_vpc::api::RemFwRuleReq;
use oxide_vpc::api::RemoveCidrResp;
use oxide_vpc::api::SetFwRulesReq;
use oxide_vpc::api::SetVirt2BoundaryReq;
use oxide_vpc::api::SetVirt2PhysReq;
use oxide_vpc::cfg::IpCfg;
use oxide_vpc::cfg::VpcCfg;
use oxide_vpc::engine::VpcNetwork;
use oxide_vpc::engine::VpcParser;
use oxide_vpc::engine::firewall;
use oxide_vpc::engine::gateway;
use oxide_vpc::engine::nat;
use oxide_vpc::engine::overlay;
use oxide_vpc::engine::router;

const ETHERNET_MTU: u16 = 1500;

// Entry limits for the various flow tables.
const FW_FT_LIMIT: NonZeroU32 = NonZeroU32::new(8096).unwrap();
const FT_LIMIT_ONE: NonZeroU32 = NonZeroU32::new(1).unwrap();

/// The name of this driver.
const XDE_STR: *const c_char = c"xde".as_ptr();

/// Name of the control device.
const XDE_CTL_STR: *const c_char = c"ctl".as_ptr();

/// Minor number for the control device.
// Set once in `xde_attach`.
static mut XDE_CTL_MINOR: minor_t = 0;

/// DDI dev info pointer to the attached xde device.
static mut xde_dip: *mut dev_info = ptr::null_mut();

// This block is purely for SDT probes.
unsafe extern "C" {
    pub safe fn __dtrace_probe_bad__packet(
        port: uintptr_t,
        dir: uintptr_t,
        mp: uintptr_t,
        err_b: *const LabelBlock<8>,
        data_len: uintptr_t,
    );
    pub safe fn __dtrace_probe_guest__loopback(
        mp: uintptr_t,
        flow: *const InnerFlowId,
        src_port: uintptr_t,
        dst_port: uintptr_t,
    );
    pub safe fn __dtrace_probe_hdlr__resp(resp_str: uintptr_t);
}

fn bad_packet_parse_probe(
    port: Option<&CString>,
    dir: Direction,
    mp: uintptr_t,
    err: &ParseError,
) {
    let port_str = match port {
        None => c"unknown",
        Some(name) => name.as_c_str(),
    };

    // Truncation is captured *in* the LabelBlock.
    let block = match LabelBlock::<8>::from_nested(err) {
        Ok(block) => block,
        Err(block) => block,
    };

    __dtrace_probe_bad__packet(
        port_str.as_ptr() as uintptr_t,
        dir as uintptr_t,
        mp,
        block.as_ptr(),
        4,
    );
}

fn bad_packet_probe(
    port: Option<&CString>,
    dir: Direction,
    mp: uintptr_t,
    msg: &CStr,
) {
    let port_str = match port {
        None => c"unknown",
        Some(name) => name.as_c_str(),
    };
    let mut eb = LabelBlock::<8>::new();

    unsafe {
        let _ = eb.append_name_raw(msg);
    }
    __dtrace_probe_bad__packet(
        port_str.as_ptr() as uintptr_t,
        dir as uintptr_t,
        mp,
        eb.as_ptr(),
        8,
    );
}

/// Underlay port state.
#[derive(Debug)]
pub struct XdeUnderlayPort {
    /// Name of the link being used for this underlay port.
    pub name: String,

    /// The MAC address associated with this underlay port.
    pub mac: [u8; 6],

    /// The MTU of this link.
    pub mtu: u32,

    /// MAC promiscuous handle for receiving packets on the underlay link.
    siphon: MacSiphon<UnderlayDev>,

    /// DLS-level handle on a device for promiscuous registration and
    /// packet Tx.
    stream: Arc<UnderlayDev>,
}

struct XdeState {
    management_lock: TokenLock<XdeMgmt>,
    ectx: Arc<ExecCtx>,
    vpc_map: Arc<overlay::VpcMappings>,
    v2b: Arc<overlay::Virt2Boundary>,
    devs: ReadOnlyDevMap,
    stats: KStatNamed<XdeStats>,
    #[allow(unused)]
    cleanup: Periodic<()>,
}

/// Resource sets which require ioctl-level mutual exclusion to modify. Not all
/// ioctls in XDE require this -- only those which modify the port map or need
/// to interface with DLS/MAC directly.
///
/// **None of the contained locks may be held during calls to DLS,
/// lookup/resolution of link state, etc. which could possibly upcall.**
struct XdeMgmt {
    devs: Arc<KRwLock<DevMap>>,
    underlay: Option<UnderlayState>,
}

#[derive(Clone)]
struct UnderlayState {
    // each xde driver has a handle to two underlay ports that are used for I/O
    // onto the underlay network
    u1: Arc<XdeUnderlayPort>,
    u2: Arc<XdeUnderlayPort>,
    shared_props: OffloadInfo,
}

fn get_xde_state() -> &'static XdeState {
    // Safety: The opte_dip pointer is write-once and is a valid
    // pointer passed to attach(9E). The returned pointer is valid as
    // it was derived from Box::into_raw() during `xde_attach`.
    unsafe {
        let p = ddi_get_driver_private(xde_dip);
        &*(p as *mut XdeState)
    }
}

impl XdeState {
    fn new() -> Self {
        let ectx = Arc::new(ExecCtx { log: Box::new(opte::KernelLog {}) });
        let dev_map = Arc::new(KRwLock::new(DevMap::default()));
        let devs = ReadOnlyDevMap::new(dev_map.clone());

        XdeState {
            management_lock: TokenLock::new(XdeMgmt {
                devs: dev_map,
                underlay: None,
            }),
            devs,
            ectx,
            vpc_map: Arc::new(overlay::VpcMappings::new()),
            v2b: Arc::new(overlay::Virt2Boundary::new()),
            stats: KStatNamed::new("xde", "xde", XdeStats::new())
                .expect("Name is well-constructed (len, no NUL bytes)"),
            cleanup: Periodic::new(
                c"XDE flow/cache expiry".to_owned(),
                shared_periodic_expire,
                Box::new(()),
                ONE_SECOND,
            ),
        }
    }
}

fn stat_parse_error(dir: Direction, err: &ParseError) {
    let xde = get_xde_state();
    xde.stats.vals.parse_error(dir, err);
}

#[repr(C)]
pub struct XdeDev {
    pub devname: String,
    linkid: datalink_id_t,
    mh: *mut mac::mac_handle,
    link_state: mac::link_state_t,

    // The OPTE port associated with this xde device.
    //
    // XXX Ideally the xde driver would be a generic driver which
    // could setup ports for any number of network implementations.
    // However, that's not where things are today.
    pub port: Arc<Port<VpcNetwork>>,
    vpc_cfg: VpcCfg,
    port_v2p: Arc<overlay::Virt2Phys>,

    // Pass the packets through to the underlay devices, skipping
    // opte-core processing.
    passthrough: bool,

    pub vni: Vni,

    // These are clones of the underlay ports initialized by the
    // driver.
    pub u1: Arc<XdeUnderlayPort>,
    pub u2: Arc<XdeUnderlayPort>,
    underlay_capab: OffloadInfo,

    // We make this a per-port cache rather than sharing between all
    // ports to theoretically reduce contention around route expiry
    // and reinsertion.
    routes: RouteCache,

    // Each port has its own copy of the `DevMap` held by `XdeState`.
    // This is kept under an RwLock because we need to deliver
    // from potentially one or more threads unbound to a particular CPU.
    port_map: KRwLock<Arc<DevMap>>,
}

impl XdeDev {
    #[inline]
    pub fn deliver(&self, pkt: impl AsMblk) {
        if let Some(pkt) = pkt.unwrap_mblk() {
            unsafe { mac::mac_rx(self.mh, ptr::null_mut(), pkt.as_ptr()) }
        }
    }
}

// SAFETY: The sole pointer member (the mac handle) safely supports
// multiple threads calling e.g. `mac_rx`. Management operations which
// would invalidate this require either `&mut` or use of an owned `XdeDev`.
unsafe impl Send for XdeDev {}
unsafe impl Sync for XdeDev {}

/// Index to one of the two underlay devices.
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum UnderlayIndex {
    U1 = 0,
    U2 = 1,
}

/// Padded `Arc<DevMap>`.
///
/// When retrieving a `DevMap` from an `UnderlayDev`, the per-CPU slots are
/// stored as a contiguous block. We want to be sure that both the mutex and
/// contained data have no synchronisation with another CPU (save for
/// infrequent port adds/removals from an ioctl).
#[repr(C)]
struct PerEntryState {
    devs: KMutex<Arc<DevMap>>,
    _pad: [u8; 48],
}

const _: () = assert!(
    size_of::<PerEntryState>().is_multiple_of(64),
    "PerEntryState must be cache-line-sized.",
);

impl Default for PerEntryState {
    fn default() -> Self {
        Self { devs: KMutex::new(Arc::new(DevMap::new())), _pad: [0u8; 48] }
    }
}

#[repr(C)]
struct UnderlayDev {
    stream: DlsStream,
    ports_map: Vec<PerEntryState>,
}

impl core::fmt::Debug for UnderlayDev {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnderlayDev").finish_non_exhaustive()
    }
}

impl MacClient for UnderlayDev {
    fn mac_client_handle(&self) -> Result<*mut mac::mac_client_handle, c_int> {
        self.stream.mac_client_handle()
    }
}

#[cfg(not(test))]
#[unsafe(no_mangle)]
unsafe extern "C" fn _init() -> c_int {
    unsafe {
        mac::mac_init_ops(addr_of_mut!(xde_devops), XDE_STR);

        match mod_install(&xde_linkage) {
            0 => 0,
            err => {
                warn!("mod_install failed: {}", err);
                mac::mac_fini_ops(addr_of_mut!(xde_devops));
                err
            }
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn _info(modinfop: *mut modinfo) -> c_int {
    unsafe { mod_info(&xde_linkage, modinfop) }
}

#[cfg(not(test))]
#[unsafe(no_mangle)]
unsafe extern "C" fn _fini() -> c_int {
    unsafe {
        match mod_remove(&xde_linkage) {
            0 => {
                mac::mac_fini_ops(addr_of_mut!(xde_devops));
                0
            }
            err => {
                warn!("mod remove failed: {}", err);
                err
            }
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
#[unsafe(no_mangle)]
unsafe extern "C" fn xde_open(
    devp: *mut dev_t,
    flags: c_int,
    otyp: c_int,
    credp: *mut cred_t,
) -> c_int {
    unsafe {
        assert!(!xde_dip.is_null());
    }

    if otyp != OTYP_CHR {
        return EINVAL;
    }

    unsafe {
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
    }

    if (flags & (FEXCL | FNDELAY | FNONBLOCK)) != 0 {
        return EINVAL;
    }

    0
}

#[unsafe(no_mangle)]
unsafe extern "C" fn xde_close(
    dev: dev_t,
    _flag: c_int,
    otyp: c_int,
    _credp: *mut cred_t,
) -> c_int {
    unsafe {
        assert!(!xde_dip.is_null());
    }

    if otyp != OTYP_CHR {
        return EINVAL;
    }

    unsafe {
        let minor = getminor(dev);
        if minor != XDE_CTL_MINOR {
            return ENXIO;
        }
    }

    0
}

#[unsafe(no_mangle)]
unsafe extern "C" fn xde_ioctl(
    dev: dev_t,
    cmd: c_int,
    arg: intptr_t,
    mode: c_int,
    _credp: *mut cred_t,
    _rvalp: *mut c_int,
) -> c_int {
    unsafe {
        assert!(!xde_dip.is_null());

        let minor = getminor(dev);
        if minor != XDE_CTL_MINOR {
            return ENXIO;
        }
    }

    if cmd != XDE_IOC_OPTE_CMD {
        return ENOTTY;
    }

    // TODO: this is using KM_SLEEP, is that ok?
    let mut buf = Vec::<u8>::with_capacity(IOCTL_SZ);
    unsafe {
        if ddi_copyin(arg as _, buf.as_mut_ptr() as _, IOCTL_SZ, mode) != 0 {
            return EFAULT;
        }
    }

    unsafe {
        let err = xde_ioc_opte_cmd(buf.as_mut_ptr() as _, mode);

        if ddi_copyout(buf.as_ptr() as _, arg as _, IOCTL_SZ, mode) != 0
            && err == 0
        {
            return EFAULT;
        }

        err
    }
}

fn dtrace_probe_hdlr_resp<T>(resp: &Result<T, OpteError>)
where
    T: CmdOk,
{
    let resp_arg = CString::new(format!("{resp:?}")).unwrap();
    __dtrace_probe_hdlr__resp(resp_arg.as_ptr() as uintptr_t);
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

fn clear_xde_underlay_hdlr() -> Result<NoResp, OpteError> {
    clear_xde_underlay()
}

// This is the entry point for all OPTE commands. It verifies the API
// version and then multiplexes the command to its appropriate handler.
#[unsafe(no_mangle)]
unsafe extern "C" fn xde_ioc_opte_cmd(karg: *mut c_void, mode: c_int) -> c_int {
    let mut env = unsafe {
        let ioctl: &mut OpteCmdIoctl = &mut *(karg as *mut OpteCmdIoctl);
        match IoctlEnvelope::wrap(ioctl, mode) {
            Ok(v) => v,
            Err(errno) => return errno,
        }
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

        OpteCmd::ClearXdeUnderlay => {
            let resp = clear_xde_underlay_hdlr();
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

        OpteCmd::ClearLft => {
            let resp = clear_lft_hdlr(&mut env);
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
            let resp = dump_v2p_hdlr();
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::SetVirt2Phys => {
            let resp = set_v2p_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::ClearVirt2Phys => {
            let resp = clear_v2p_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::DumpVirt2Boundary => {
            let resp = dump_v2b_hdlr();
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::SetVirt2Boundary => {
            let resp = set_v2b_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::ClearVirt2Boundary => {
            let resp = clear_v2b_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::AddRouterEntry => {
            let resp = add_router_entry_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::DelRouterEntry => {
            let resp = del_router_entry_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::DumpTcpFlows => {
            let resp = dump_tcp_flows_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::SetExternalIps => {
            let resp = set_external_ips_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::AllowCidr => {
            let resp = allow_cidr_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::RemoveCidr => {
            let resp = remove_cidr_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }
    }
}

const ONE_SECOND: Interval = Interval::from_duration(Duration::new(1, 0));

#[unsafe(no_mangle)]
fn shared_periodic_expire(_: &mut ()) {
    let state = get_xde_state();
    let devs = state.devs.read();
    for dev in devs.iter() {
        let _ = dev.port.expire_flows();
        dev.routes.remove_routes();
    }
}

#[unsafe(no_mangle)]
fn create_xde(req: &CreateXdeReq) -> Result<NoResp, OpteError> {
    // TODO name validation
    let state = get_xde_state();

    // Taking the management lock allows us to create XDE ports atomically
    // with respect to other threads (and enforces a lockout on, e.g., the
    // underlay).
    let token = state.management_lock.lock();

    let UnderlayState { u1, u2, shared_props: underlay_capab } = {
        token
            .underlay
            .as_ref()
            .ok_or_else(|| OpteError::System {
                errno: EINVAL,
                msg: "underlay not initialized".to_string(),
            })?
            .clone()
    };

    let cfg = VpcCfg::from(req.cfg.clone());

    // Because we hold the token, no one else will add to/remove from
    // the XdeDev map in parallel. Quickly check that there is no
    // collision on name or MAC address -- take a read lock so as not
    // to block the Rx datapath (yet).
    {
        let devs = token.devs.read();
        if devs.get_by_name(&req.xde_devname).is_some() {
            return Err(OpteError::PortExists(req.xde_devname.clone()));
        }
        if devs.get_by_key(VniMac::new(cfg.vni, cfg.guest_mac)).is_some() {
            return Err(OpteError::MacExists {
                port: req.xde_devname.clone(),
                vni: cfg.vni,
                mac: cfg.guest_mac,
            });
        }
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

    let mut guest_addr = cfg.guest_mac.bytes();

    let mut xde = Arc::new(XdeDev {
        devname: req.xde_devname.clone(),
        linkid: req.linkid,
        mh: ptr::null_mut(),
        link_state: mac::link_state_t::Down,
        port: new_port(
            req.xde_devname.clone(),
            &cfg,
            state.vpc_map.clone(),
            port_v2p.clone(),
            state.v2b.clone(),
            state.ectx.clone(),
            &req.dhcp,
        )?,
        port_v2p,
        vni: cfg.vni,
        vpc_cfg: cfg,
        passthrough: req.passthrough,
        u1,
        u2,
        underlay_capab,
        routes: RouteCache::default(),
        port_map: KRwLock::new(Default::default()),
    });
    let xde_ref =
        Arc::get_mut(&mut xde).expect("only one instance of XDE exists");

    // set up upper mac
    let Some(mreg) = (unsafe { mac::mac_alloc(MAC_VERSION as u32).as_mut() })
    else {
        return Err(OpteError::System {
            errno: ENOMEM,
            msg: "failed to alloc mac".to_string(),
        });
    };

    mreg.m_type_ident = MAC_PLUGIN_IDENT_ETHER;
    mreg.m_driver = xde_ref as *mut XdeDev as *mut c_void;
    mreg.m_dst_addr = core::ptr::null_mut();
    mreg.m_pdata = core::ptr::null_mut();
    mreg.m_pdata_size = 0;
    mreg.m_priv_props = core::ptr::null_mut();
    mreg.m_instance = c_uint::MAX; // let mac handle this
    mreg.m_min_sdu = 1;
    mreg.m_max_sdu = u32::from(ETHERNET_MTU); // TODO hardcode
    mreg.m_multicast_sdu = 0;
    mreg.m_margin = crate::sys::VLAN_TAGSZ;
    mreg.m_v12n = mac::MAC_VIRT_NONE as u32;

    unsafe {
        mreg.m_dip = xde_dip;
        mreg.m_callbacks = addr_of_mut!(xde_mac_callbacks);
    }

    mreg.m_src_addr = guest_addr.as_mut_ptr();

    let reg_res = unsafe {
        mac::mac_register(mreg as *mut mac::mac_register_t, &mut xde_ref.mh)
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

    // Setup DLS.
    // Any DLS operations are liable to upcall, so we *must* be certain
    // that *no locks are actively held at this moment*.
    match unsafe { dls::dls_devnet_create(xde_ref.mh, req.linkid, 0) } {
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

    xde_ref.link_state = mac::link_state_t::Up;
    unsafe {
        mac::mac_link_update(xde.mh, xde.link_state);
        mac::mac_tx_update(xde.mh);
    }

    // Finally, insert our fully established port.
    // This temporarily blocks the Rx pathway.
    {
        let mut devs = token.devs.write();
        _ = devs.insert(xde);
        refresh_maps(
            devs,
            token.underlay.as_ref().expect(
                "bailed out above if no underlay, and protected by token",
            ),
        );
    }

    Ok(NoResp::default())
}

#[unsafe(no_mangle)]
fn delete_xde(req: &DeleteXdeReq) -> Result<NoResp, OpteError> {
    let state = get_xde_state();

    let token = state.management_lock.lock();

    // First -- does the device exist?
    // Remove it, knowing that we may need to reinsert on a rollback.
    let xde = {
        let mut devs = token.devs.write();
        let xde = devs
            .remove(&req.xde_devname)
            .ok_or_else(|| OpteError::PortNotFound(req.xde_devname.clone()))?;

        refresh_maps(
            devs,
            token
                .underlay
                .as_ref()
                .expect("underlay must exist while ports exist"),
        );

        xde
    };

    // Clear the port's devmap to break any cycles.
    {
        let mut pmap = xde.port_map.write();
        *pmap = Default::default();
    }

    let return_port = |token: &TokenGuard<'_, XdeMgmt>, port| {
        let mut devs = token.devs.write();
        _ = devs.insert(port);
        refresh_maps(
            devs,
            token
                .underlay
                .as_ref()
                .expect("underlay must exist while ports exist"),
        );
    };

    // Destroy DLS devnet device.
    // Any DLS operations are liable to upcall, so we *must* be certain
    // that *no locks are actively held at this moment*.
    let ret = unsafe {
        let mut tmpid = xde.linkid;
        dls::dls_devnet_destroy(xde.mh, &mut tmpid, boolean_t::B_TRUE)
    };

    match ret {
        0 => {}
        err => {
            return_port(&token, xde);
            return Err(OpteError::System {
                errno: err,
                msg: format!("failed to destroy DLS devnet: {err}"),
            });
        }
    }

    // Unregister this xde's mac handle.
    // We have the same lock constraints as above, given that we could
    // have to rebind the DLS devnet on rollback.
    match unsafe { mac::mac_unregister(xde.mh) } {
        0 => {}
        err => {
            match unsafe { dls::dls_devnet_create(xde.mh, xde.linkid, 0) } {
                0 => {}
                err => {
                    warn!("failed to recreate DLS devnet entry: {}", err);
                }
            };
            return_port(&token, xde);
            return Err(OpteError::System {
                errno: err,
                msg: format!("failed to unregister mac: {err}"),
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

    Ok(NoResp::default())
}

/// Rebuild each entrypoint's view of the central `DevMap`.
fn refresh_maps(devs: KRwLockWriteGuard<DevMap>, underlay: &UnderlayState) {
    let new_map = Arc::new(devs.clone());

    // Update all ports' maps.
    for port in devs.iter() {
        let mut map = port.port_map.write();
        *map = Arc::clone(&new_map);
    }

    // Update all underlays' maps.
    let ports = [&underlay.u1.stream.ports_map, &underlay.u2.stream.ports_map];
    for port in ports {
        for map in port {
            let mut map = map.devs.lock();
            *map = Arc::clone(&new_map);
        }
    }
}

struct ResolvedLink<'a>(&'a str, LinkId);
impl<'a> ResolvedLink<'a> {
    fn new(name: &'a str) -> Result<Self, OpteError> {
        let link_cstr = CString::new(name).unwrap();

        let link_id =
            LinkId::from_name(link_cstr).map_err(|err| OpteError::System {
                errno: EFAULT,
                msg: format!("failed to get linkid for {name}: {err}"),
            })?;

        Ok(Self(name, link_id))
    }
}

#[unsafe(no_mangle)]
fn set_xde_underlay(req: &SetXdeUnderlayReq) -> Result<NoResp, OpteError> {
    let state = get_xde_state();

    // Resolve `LinkId`s outside of any locks -- these require upcalls,
    // but we don't need to perform these from within the management lock.
    let link1 = ResolvedLink::new(req.u1.as_str())?;
    let link2 = ResolvedLink::new(req.u2.as_str())?;

    let mut token = state.management_lock.lock();

    if token.underlay.is_some() {
        return Err(OpteError::System {
            errno: EEXIST,
            msg: "underlay already initialized".into(),
        });
    }

    // `init_underlay_ingress_handlers` contains no upcalls today.
    let new_underlay = init_underlay_ingress_handlers(link1, link2, &token)?;
    token.underlay = Some(new_underlay);

    Ok(NoResp::default())
}

#[unsafe(no_mangle)]
fn clear_xde_underlay() -> Result<NoResp, OpteError> {
    let state = get_xde_state();
    let mut token = state.management_lock.lock();
    if token.underlay.is_none() {
        return Err(OpteError::System {
            errno: ENOENT,
            msg: "underlay not yet initialized".into(),
        });
    }
    if !token.devs.read().is_empty() {
        return Err(OpteError::System {
            errno: EBUSY,
            msg: "underlay in use by attached ports".into(),
        });
    }

    if let Some(underlay) = token.underlay.take() {
        // If the underlay references have leaked/spread beyond `XdeDev`s and not
        // been cleaned up, we committed have a fatal programming error.
        // We aren't using `Weak` references to these types either, so no strong
        // references could be created.
        //
        // We know these must succeed given that the only holders of an
        // `Arc<XdeUnderlayPort>` are `XdeState` (whose ref we have exclusively locked)
        // and `XdeDev` (of which none remain).
        let name = underlay.u1.name.clone();
        let u1 = Arc::into_inner(underlay.u1).unwrap_or_else(|| {
            panic!("underlay u1 ({name}) must have one ref during teardown",)
        });

        let name = underlay.u2.name.clone();
        let u2 = Arc::into_inner(underlay.u2).unwrap_or_else(|| {
            panic!("underlay u2 ({name}) must have one ref during teardown",)
        });

        for u in [u1, u2] {
            // We have a chain of refs here: `MacSiphon` holds a ref to
            // `DlsStream`. We explicitly drop them in order here to ensure
            // there are no outstanding refs.

            // 1. Remove packet rx callback.
            drop(u.siphon);

            // Although `xde_rx` can be called into without any running ports
            // via the siphon handle, illumos guarantees that this callback won't
            // be running here. `mac_siphon_clear` performs the moral equivalent of
            // `mac_rx_barrier` -- the client's SRS is quiesced, and then restarted
            // after the callback is removed.
            // Because there are no ports and we hold the write/management lock, no
            // one else will have or try to clone the Stream handle.

            // 2. Close the open stream handle.
            // The only other hold on this `DlsStream` is via `u.siphon`, which
            // we just dropped. The `expect` asserts that we have consumed them
            // in the correct order.
            Arc::into_inner(u.stream).unwrap_or_else(|| {
                panic!(
                    "underlay ({}) must have no external refs to its DlsStream",
                    u.name
                )
            });
        }
    }

    Ok(NoResp::default())
}

const IOCTL_SZ: usize = core::mem::size_of::<OpteCmdIoctl>();

#[unsafe(no_mangle)]
unsafe extern "C" fn xde_getinfo(
    dip: *mut dev_info,
    cmd: ddi_info_cmd_t,
    arg: *mut c_void,
    resultp: *mut *mut c_void,
) -> c_int {
    unsafe {
        if xde_dip.is_null() {
            return DDI_FAILURE;
        }
    }

    let minor = match cmd {
        ddi_info_cmd_t::DDI_INFO_DEVT2DEVINFO
        | ddi_info_cmd_t::DDI_INFO_DEVT2INSTANCE => unsafe {
            getminor(arg as dev_t)
        },
        // We call into `mac_getinfo` here rather than just fail
        // with `DDI_FAILURE` to let it handle if ever there's a new
        // `ddi_info_cmd_t` variant.
        _ => return unsafe { mac_getinfo(dip, cmd, arg, resultp) },
    };

    unsafe {
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
    }

    match cmd {
        ddi_info_cmd_t::DDI_INFO_DEVT2DEVINFO => unsafe {
            *resultp = xde_dip.cast();
            DDI_SUCCESS
        },
        ddi_info_cmd_t::DDI_INFO_DEVT2INSTANCE => unsafe {
            *resultp = ddi_get_instance(xde_dip) as _;
            DDI_SUCCESS
        },
        _ => DDI_FAILURE,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn xde_attach(
    dip: *mut dev_info,
    cmd: ddi_attach_cmd_t,
) -> c_int {
    match cmd {
        ddi_attach_cmd_t::DDI_RESUME => return DDI_SUCCESS,
        ddi_attach_cmd_t::DDI_ATTACH => {}
        _ => return DDI_FAILURE,
    }

    unsafe {
        assert!(xde_dip.is_null());
    }

    // Create xde control device
    let res = unsafe {
        // We need to share the minor number space with the GLDv3 framework.
        // We'll use the first private minor number for our control device.
        XDE_CTL_MINOR = mac_private_minor();

        ddi_create_minor_node(
            dip,
            XDE_CTL_STR,
            S_IFCHR,
            XDE_CTL_MINOR,
            DDI_PSEUDO,
            0,
        )
    };
    match res {
        0 => {}
        err => {
            warn!("failed to create xde control device: {err}");
            return DDI_FAILURE;
        }
    }

    let state = Box::new(XdeState::new());
    unsafe {
        xde_dip = dip;
        ddi_set_driver_private(xde_dip, Box::into_raw(state) as *mut c_void);
        ddi_report_dev(xde_dip);
    }

    DDI_SUCCESS
}

/// Setup underlay port atop the given link.
fn create_underlay_port(
    resolved: ResolvedLink<'_>,
) -> Result<(XdeUnderlayPort, OffloadInfo), OpteError> {
    let ResolvedLink(link_name, link_id) = resolved;
    let stream = DlsStream::open(link_id).map_err(|e| OpteError::System {
        errno: EFAULT,
        msg: format!("failed to grab open stream for {link_name}: {e}"),
    })?;

    let cpus = ncpus();
    let mut ports_map = Vec::with_capacity(cpus);
    for _ in 0..cpus {
        ports_map.push(PerEntryState::default());
    }

    let stream = Arc::new(UnderlayDev { stream, ports_map });

    // Bind a packet handler to the MAC client underlying `stream`.
    let siphon = MacSiphon::new(stream.clone(), xde_rx).map_err(|e| {
        OpteError::System {
            errno: EFAULT,
            msg: format!("failed to set MAC siphon on {link_name}: {e}"),
        }
    })?;

    // Grab mac handle for underlying link, to retrieve its MAC address.
    let mh =
        MacHandle::open_by_link_id(link_id).map(Arc::new).map_err(|e| {
            OpteError::System {
                errno: EFAULT,
                msg: format!(
                    "failed to open link {link_name} for underlay: {e}"
                ),
            }
        })?;

    let mtu = *mh.get_valid_mtus().end();
    let cso_state = mh.get_cso_capabs();
    let lso_state = mh.get_lso_capabs();

    Ok((
        XdeUnderlayPort {
            name: link_name.to_string(),
            mac: mh.get_mac_addr(),
            mtu,
            siphon,
            stream,
        },
        OffloadInfo { lso_state, cso_state, mtu },
    ))
}

#[unsafe(no_mangle)]
fn init_underlay_ingress_handlers(
    u1: ResolvedLink<'_>,
    u2: ResolvedLink<'_>,
    _token: &XdeMgmt,
) -> Result<UnderlayState, OpteError> {
    let (u1, i1) = create_underlay_port(u1)?;
    let (u2, i2) = create_underlay_port(u2)?;
    Ok(UnderlayState {
        u1: u1.into(),
        u2: u2.into(),
        shared_props: i1.mutual_capabs(&i2),
    })
}

#[unsafe(no_mangle)]
unsafe fn driver_prop_exists(dip: *mut dev_info, pname: &str) -> bool {
    let name = match CString::new(pname) {
        Ok(s) => s,
        Err(e) => {
            warn!("bad driver prop string name: {}: {:?}", pname, e);
            return false;
        }
    };

    let ret = unsafe {
        ddi_prop_exists(
            DDI_DEV_T_ANY,
            dip,
            DDI_PROP_DONTPASS,
            name.as_ptr() as *const c_char,
        )
    };

    ret == 1
}

#[unsafe(no_mangle)]
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

    let ret = unsafe {
        ddi_prop_get_int(
            DDI_DEV_T_ANY,
            dip,
            DDI_PROP_DONTPASS,
            name.as_ptr() as *const c_char,
            99,
        )
    };

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

#[unsafe(no_mangle)]
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
    let s = unsafe {
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
        CStr::from_ptr(value)
    };
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

#[unsafe(no_mangle)]
unsafe extern "C" fn xde_detach(
    _dip: *mut dev_info,
    cmd: ddi_detach_cmd_t,
) -> c_int {
    unsafe {
        assert!(!xde_dip.is_null());
    }

    match cmd {
        ddi_detach_cmd_t::DDI_DETACH => {}
        _ => return DDI_FAILURE,
    }

    {
        let state = get_xde_state();
        if !state.devs.read().is_empty() {
            warn!("failed to detach: outstanding ports");
            return DDI_FAILURE;
        }
    }

    let state = unsafe { ddi_get_driver_private(xde_dip) as *mut XdeState };
    assert!(!state.is_null());

    // Lock a *reference* to the XdeState, and ensure we are ready
    // to detach and cleanup.
    {
        let state_ref = unsafe { &*(state) };
        let token = state_ref.management_lock.lock();

        if token.underlay.is_some() {
            warn!("failed to detach: underlay is set");
            return DDI_FAILURE;
        }
    }
    // Drop the lock, and ensure we only have the raw ptr (and not
    // a `&'static XdeState`) again.

    unsafe {
        // Reattach the XdeState to a Box, which takes ownership and will
        // free it on drop.
        drop(Box::from_raw(state));

        // Remove control device
        ddi_remove_minor_node(xde_dip, XDE_STR);
        xde_dip = ptr::null_mut();
    }

    DDI_SUCCESS
}

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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
    devo_cb_ops: addr_of!(xde_cb_ops),
    devo_bus_ops: 0 as *const bus_ops,
    devo_power: nodev_power,
    devo_quiesce: ddi_quiesce_not_needed,
};

#[unsafe(no_mangle)]
static xde_modldrv: modldrv = modldrv {
    drv_modops: addr_of!(mod_driverops),
    drv_linkinfo: XDE_STR,
    drv_dev_ops: addr_of!(xde_devops),
};

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
unsafe extern "C" fn xde_mc_start(arg: *mut c_void) -> c_int {
    let dev = arg as *mut XdeDev;
    unsafe {
        (*dev).port.start();
    }
    0
}

// The mac framework calls this when the last client closes its handle
// to the device. At this point we know the port is no longer in use.
#[unsafe(no_mangle)]
unsafe extern "C" fn xde_mc_stop(arg: *mut c_void) {
    let dev = arg as *mut XdeDev;
    unsafe {
        (*dev).port.reset();
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn xde_mc_setpromisc(
    _arg: *mut c_void,
    _val: boolean_t,
) -> c_int {
    0
}

#[unsafe(no_mangle)]
unsafe extern "C" fn xde_mc_multicst(
    _arg: *mut c_void,
    _add: boolean_t,
    _addrp: *const u8,
) -> c_int {
    ENOTSUP
}

#[unsafe(no_mangle)]
unsafe extern "C" fn xde_mc_unicst(
    arg: *mut c_void,
    macaddr: *const u8,
) -> c_int {
    let dev = arg as *mut XdeDev;
    unsafe {
        (*dev)
            .port
            .mac_addr()
            .bytes()
            .copy_from_slice(core::slice::from_raw_parts(macaddr, 6));
    }
    0
}

fn guest_loopback_probe(
    mblk_addr: uintptr_t,
    flow: &InnerFlowId,
    src: &XdeDev,
    dst: &XdeDev,
) {
    __dtrace_probe_guest__loopback(
        mblk_addr,
        flow,
        src.port.name_cstr().as_ptr() as uintptr_t,
        dst.port.name_cstr().as_ptr() as uintptr_t,
    );
}

fn guest_loopback(
    src_dev: &XdeDev,
    entry_state: &DevMap,
    mut pkt: MsgBlk,
    vni: Vni,
    postbox: &mut TxPostbox,
) {
    use Direction::*;

    let mblk_addr = pkt.mblk_addr();

    // Loopback now requires a reparse on loopback to account for UFT fastpath.
    // When viona serves us larger packets, we needn't worry about allocing
    // the encap on.
    // We might be able to do better in the interim, but that costs us time.

    let parsed_pkt = match Packet::parse_inbound(pkt.iter_mut(), VpcParser {}) {
        Ok(pkt) => pkt,
        Err(e) => {
            stat_parse_error(Direction::In, &e);
            opte::engine::dbg!("Loopback bad packet: {:?}", e);
            bad_packet_parse_probe(None, Direction::In, mblk_addr, &e);

            return;
        }
    };

    let meta = parsed_pkt.meta();
    let old_len = parsed_pkt.len();

    let ulp_meoi = match meta.ulp_meoi(old_len) {
        Ok(ulp_meoi) => ulp_meoi,
        Err(e) => {
            opte::engine::dbg!("{}", e);
            return;
        }
    };

    let flow = parsed_pkt.flow();

    let ether_dst = parsed_pkt.meta().inner_eth.destination();
    let port_key = VniMac::new(vni, ether_dst);
    let maybe_dest_dev = entry_state.get_by_key(port_key);

    match maybe_dest_dev {
        Some(dest_dev) => {
            guest_loopback_probe(mblk_addr, &flow, src_dev, dest_dev);

            // We have found a matching Port on this host; "loop back"
            // the packet into the inbound processing path of the
            // destination Port.
            match dest_dev.port.process(In, parsed_pkt) {
                Ok(ProcessResult::Modified(emit_spec)) => {
                    let mut pkt = emit_spec.apply(pkt);
                    if let Err(e) = pkt.fill_parse_info(&ulp_meoi, None) {
                        opte::engine::err!("failed to set offload info: {}", e);
                    }

                    // Having advertised offloads to our guest, looped back
                    // packets are liable to have zero-checksums. Fill these
                    // if necessary.
                    let pkt = if pkt
                        .offload_flags()
                        .flags
                        .intersects(MblkOffloadFlags::HCK_TX_FLAGS)
                    {
                        // We have only asked for cksum emulation, so we
                        // will either have:
                        //  * 0 pkts (checksum could not be emulated,
                        //            packet dropped)
                        //  * 1 pkt.
                        mac_hw_emul(pkt, MacEmul::HWCKSUM_EMUL)
                            .and_then(|mut v| v.pop_front())
                    } else {
                        Some(pkt)
                    };

                    if let Some(pkt) = pkt {
                        postbox.post_local(port_key, pkt);
                    }
                }

                Ok(ProcessResult::Drop { reason }) => {
                    opte::engine::dbg!("loopback rx drop: {:?}", reason);
                }

                Ok(ProcessResult::Hairpin(_hppkt)) => {
                    // There should be no reason for an loopback
                    // inbound packet to generate a hairpin response
                    // from the destination port.
                    opte::engine::dbg!("unexpected loopback rx hairpin");
                }

                Err(e) => {
                    opte::engine::dbg!(
                        "loopback port process error: {} -> {} {:?}",
                        src_dev.port.name(),
                        dest_dev.port.name(),
                        e
                    );
                }
            }
        }

        None => {
            opte::engine::dbg!(
                "underlay dest is same as src but the Port was not found \
                 vni = {}, mac = {}",
                vni.as_u32(),
                ether_dst
            );
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn xde_mc_tx(
    arg: *mut c_void,
    mp_chain: *mut mblk_t,
) -> *mut mblk_t {
    // The device must be started before we can transmit.
    let src_dev = unsafe { &*(arg as *mut XdeDev) };

    // ================================================================
    // IMPORTANT: PacketChain now takes ownership of mp_chain, and each
    // Packet takes ownership of an mblk_t from mp_chain. When these
    // structs are dropped, so are any contained packets at those pointers.
    // Be careful with any calls involving mblk_t pointers (or their
    // uintptr_t numeric forms) after this point. They should only be calls
    // that read (i.e., SDT arguments), nothing that writes or frees. But
    // really you should think of mp_chain as &mut and avoid any reference
    // to it past this point. Ownership is taken back by calling
    // Packet/PacketChain::unwrap_mblk().
    //
    // XXX We may use Packet types with non-'static lifetimes in future.
    //     We *will* still need to remain careful here and `xde_rx` as
    //     pointers are `Copy`.
    // ================================================================
    let Ok(mut chain) = (unsafe { MsgBlkChain::new(mp_chain) }) else {
        bad_packet_probe(
            Some(src_dev.port.name_cstr()),
            Direction::Out,
            mp_chain as uintptr_t,
            c"rx'd packet chain from guest was null",
        );
        return ptr::null_mut();
    };

    let mut hairpin_chain = MsgBlkChain::empty();
    let mut tx_postbox = TxPostbox::new();

    // We don't need to read-lock the port map unless we have local
    // delivery to perform.
    //
    // TODO: really think this one through. This might expose us to the
    // risk of double read-locking at the same time as the tokenlock
    // wants to make some globally mutable operation happen.
    //
    // Maybe we should clone out the `DevMap` at this instant.
    let mut entry_state = None;

    while let Some(pkt) = chain.pop_front() {
        xde_mc_tx_one(
            src_dev,
            pkt,
            &mut tx_postbox,
            &mut entry_state,
            &mut hairpin_chain,
        );
    }

    let (local_pkts, [u1_pkts, u2_pkts]) = tx_postbox.deconstruct();

    if let Some(entry_state) = entry_state {
        entry_state.deliver_all(local_pkts);
    }

    // `entry_state` has been moved, making it safe to deliver hairpin
    // packets (which may cause us to re-enter XDE in the same stack).
    // All deliver/tx calls will NO-OP if the sent chain is empty.
    src_dev.deliver(hairpin_chain);

    src_dev.u1.stream.stream.tx_drop_on_no_desc(
        u1_pkts.msgs,
        u1_pkts.last_hint,
        MacTxFlags::empty(),
    );

    src_dev.u2.stream.stream.tx_drop_on_no_desc(
        u2_pkts.msgs,
        u2_pkts.last_hint,
        MacTxFlags::empty(),
    );

    ptr::null_mut()
}

#[inline]
fn xde_mc_tx_one<'a>(
    src_dev: &'a XdeDev,
    mut pkt: MsgBlk,
    postbox: &mut TxPostbox,
    entry_state: &mut Option<KRwLockReadGuard<'a, Arc<DevMap>>>,
    hairpin_chain: &mut MsgBlkChain,
) {
    let parser = src_dev.port.network().parser();
    let mblk_addr = pkt.mblk_addr();
    let offload_req = pkt.offload_flags();
    let parsed_pkt = match Packet::parse_outbound(pkt.iter_mut(), parser) {
        Ok(pkt) => pkt,
        Err(e) => {
            stat_parse_error(Direction::Out, &e);

            // NOTE: We are using the individual mblk_t as read only
            // here to get the pointer value so that the DTrace consumer
            // can examine the packet on failure.
            opte::engine::dbg!("Rx bad packet: {:?}", e);
            bad_packet_parse_probe(
                Some(src_dev.port.name_cstr()),
                Direction::Out,
                mblk_addr,
                &e,
            );
            return;
        }
    };
    let old_len = parsed_pkt.len();

    let meta = parsed_pkt.meta();
    let Ok(non_eth_payl_bytes) =
        u32::try_from((&meta.inner_l3, &meta.inner_ulp).packet_length())
    else {
        opte::engine::dbg!("sum of packet L3/L4 exceeds u32::MAX");
        return;
    };

    let ulp_meoi = match meta.ulp_meoi(old_len) {
        Ok(ulp_meoi) => ulp_meoi,
        Err(e) => {
            opte::engine::dbg!("{}", e);
            return;
        }
    };

    // Send straight to underlay in passthrough mode.
    if src_dev.passthrough {
        // TODO We need to deal with flow control. This could actually
        // get weird, this is the first provider to use mac_tx(). Is
        // there something we can learn from aggr here? I need to
        // refresh my memory on all of this.
        //
        // TODO Is there way to set mac_tx to must use result?
        drop(parsed_pkt);
        postbox.post_underlay(UnderlayIndex::U1, TxHint::NoneOrMixed, pkt);
        return;
    }

    let port = &src_dev.port;

    // The port processing code will fire a probe that describes what
    // action was taken -- there should be no need to add probes or
    // prints here.
    let res = port.process(Direction::Out, parsed_pkt);

    match res {
        Ok(ProcessResult::Modified(emit_spec)) => {
            // If the outer IPv6 destination is the same as the
            // source, then we need to loop the packet inbound to the
            // guest on this same host.
            let (ip6_src, ip6_dst) = match emit_spec.outer_ip6_addrs() {
                Some(v) => v,
                None => {
                    // XXX add SDT probe
                    // XXX add stat
                    opte::engine::dbg!("no outer IPv6 header, dropping");
                    return;
                }
            };

            let vni = match emit_spec.outer_encap_vni() {
                Some(vni) => vni,
                None => {
                    // XXX add SDT probe
                    // XXX add stat
                    opte::engine::dbg!("no geneve header, dropping");
                    return;
                }
            };

            let mtu_unrestricted = emit_spec.mtu_unrestricted();
            let l4_hash = emit_spec.l4_hash();
            let mut out_pkt = emit_spec.apply(pkt);
            let new_len = out_pkt.byte_len();

            if ip6_src == ip6_dst {
                let entry_state =
                    entry_state.get_or_insert_with(|| src_dev.port_map.read());
                guest_loopback(src_dev, entry_state, out_pkt, vni, postbox);
                return;
            }

            let Ok(encap_len) = u32::try_from(new_len.saturating_sub(old_len))
            else {
                opte::engine::err!(
                    "tried to push encap_len greater than u32::MAX"
                );
                return;
            };

            // Boost MSS to use full jumbo frames if we know our path
            // can be served purely on internal links.
            // Recall that SDU does not include L2 size, hence 'non_eth_payl'
            let mut flags = offload_req.flags;
            let mss = if mtu_unrestricted {
                src_dev.underlay_capab.mtu - encap_len - non_eth_payl_bytes
            } else {
                offload_req.mss
            };

            // As underlay devices may need to emulate tunnelled LSO, then we
            // need to strip the flag to prevent a drop, in cases where we'd
            // ask to split a packet back into... 1 segment.
            // Hardware tends to handle this without issue.
            if ulp_meoi.meoi_len.saturating_sub(
                non_eth_payl_bytes
                    + u32::try_from(Ethernet::MINIMUM_LENGTH)
                        .expect("14B < u32::MAX"),
            ) <= mss
            {
                flags.remove(MblkOffloadFlags::HW_LSO);
            }

            out_pkt.request_offload(flags.shift_in(), mss);

            let tun_meoi = mac_ether_offload_info_t {
                meoi_flags: MacEtherOffloadFlags::L2INFO_SET
                    | MacEtherOffloadFlags::L3INFO_SET
                    | MacEtherOffloadFlags::L4INFO_SET
                    | MacEtherOffloadFlags::TUNINFO_SET,
                meoi_l2hlen: u8::try_from(Ethernet::MINIMUM_LENGTH)
                    .expect("14B < u8::MAX"),
                meoi_l3proto: Ethertype::IPV6.0,
                meoi_l3hlen: u16::try_from(Ipv6::MINIMUM_LENGTH)
                    .expect("40B < u16::MAX"),
                meoi_l4proto: IpProtocol::UDP.0,
                meoi_l4hlen: u8::try_from(Udp::MINIMUM_LENGTH)
                    .expect("8B < u8::MAX"),
                meoi_tuntype: MacTunType::GENEVE,
                meoi_tunhlen: u16::try_from(Geneve::MINIMUM_LENGTH)
                    .expect("8B < u16::MAX"),
                // meoi_len will be recomputed by consumers.
                meoi_len: u32::try_from(new_len).unwrap_or(u32::MAX),
            };

            if let Err(e) = out_pkt.fill_parse_info(&tun_meoi, Some(&ulp_meoi))
            {
                opte::engine::err!("failed to set offload info: {}", e);
            }

            // Currently the overlay layer leaves the outer frame
            // destination and source zero'd. Ask IRE for the route
            // associated with the underlay destination. Then ask NCE
            // for the mac associated with the IRE nexthop to fill in
            // the outer frame of the packet. Also return the underlay
            // device associated with the nexthop
            //
            // As route lookups are fairly expensive, we can cache their
            // results for a given dst + entropy. These have a fairly tight
            // expiry so that we can actually react to new reachability/load
            // info from DDM.
            let my_key = RouteKey { dst: ip6_dst, l4_hash: Some(l4_hash) };
            let Route { src, dst, underlay_idx } =
                src_dev.routes.next_hop(my_key, src_dev);

            // Get a pointer to the beginning of the outer frame and
            // fill in the dst/src addresses before sending out the
            // device.
            let new_pkt = unsafe {
                let mblk = out_pkt.unwrap_mblk().as_ptr();
                let rptr = (*mblk).b_rptr;
                ptr::copy(dst.as_ptr(), rptr, 6);
                ptr::copy(src.as_ptr(), rptr.add(6), 6);
                // Unwrap: We know the packet is good because we just
                // unwrapped it above.
                MsgBlk::wrap_mblk(mblk).unwrap()
            };

            postbox.post_underlay(
                underlay_idx,
                TxHint::from_crc32(l4_hash),
                new_pkt,
            );
        }

        Ok(ProcessResult::Drop { .. }) => {}

        Ok(ProcessResult::Hairpin(hpkt)) => {
            // From the theory statement, if we have a packet chain
            // from above which contains a mixture of hairpin and local
            // deliveries (`guest_loopback`) we can only deliver hairpin
            // packets once `entry_state` is explicitly dropped.
            hairpin_chain.append(hpkt);
        }

        Err(_) => {}
    }
}

/// This is a generic wrapper for references that should be dropped once not in
/// use.
pub(crate) struct DropRef<DropFn, Arg>
where
    DropFn: Fn(*mut Arg),
{
    /// A function to drop the reference.
    func: DropFn,
    /// The reference pointer.
    arg: *mut Arg,
}

impl<DropFn, Arg> DropRef<DropFn, Arg>
where
    DropFn: Fn(*mut Arg),
{
    /// Create a new `DropRef` for the provided reference argument. When this
    /// object is dropped, the provided `func` will be called.
    pub(crate) fn new(func: DropFn, arg: *mut Arg) -> Self {
        Self { func, arg }
    }

    /// Return a pointer to the underlying reference.
    pub(crate) fn inner(&self) -> *mut Arg {
        self.arg
    }
}

impl<DropFn, Arg> Drop for DropRef<DropFn, Arg>
where
    DropFn: Fn(*mut Arg),
{
    /// Call the cleanup function on the reference argument when we are dropped.
    fn drop(&mut self) {
        if !self.arg.is_null() {
            (self.func)(self.arg);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn xde_mc_getcapab(
    arg: *mut c_void,
    cap: mac::mac_capab_t,
    capb_data: *mut c_void,
) -> boolean_t {
    let dev = arg as *mut XdeDev;

    let shared_underlay_caps = unsafe { (*dev).underlay_capab };

    // XDE's approach to the capabilities we advertise is to always say
    // that we support LSO/CSO, using tunnelled LSO/CSO if the underlay
    // supports it or having MAC emulate offloads when it does not.
    // We know in actuality what the intersection of our two underlay ports'
    // capabilities is, which we use to limit the `lso_max` when tunnelled
    // LSO hardware support over Geneve is present.
    match cap {
        // TODO: work out a safer interface for this.
        mac::mac_capab_t::MAC_CAPAB_HCKSUM => {
            let capab = capb_data as *mut mac_capab_cso_t;

            unsafe {
                (*capab).cso_flags = ChecksumOffloadCapabs::NON_TUN_CAPABS
                    .difference(ChecksumOffloadCapabs::INET_PARTIAL);
            }

            boolean_t::B_TRUE
        }
        mac::mac_capab_t::MAC_CAPAB_LSO => {
            let capab = capb_data as *mut mac_capab_lso_t;
            let upstream_lso = shared_underlay_caps.upstream_lso();

            // Geneve TSO support in the underlay has been converted to basic TSO
            // in `upstream_lso`, use the values there if possible.
            let (v4_lso_max, v6_lso_max) = if upstream_lso
                .lso_flags
                .contains(TcpLsoFlags::BASIC_IPV4 | TcpLsoFlags::BASIC_IPV6)
            {
                (
                    upstream_lso.lso_basic_tcp_ipv4.lso_max,
                    upstream_lso.lso_basic_tcp_ipv6.lso_max,
                )
            } else {
                (u32::from(u16::MAX), u32::from(u16::MAX))
            };

            unsafe {
                (*capab).lso_flags =
                    TcpLsoFlags::BASIC_IPV4 | TcpLsoFlags::BASIC_IPV6;
                (*capab).lso_basic_tcp_ipv4 =
                    lso_basic_tcp_ipv4_t { lso_max: v4_lso_max };
                (*capab).lso_basic_tcp_ipv6 =
                    lso_basic_tcp_ipv6_t { lso_max: v6_lso_max };
            }

            boolean_t::B_TRUE
        }
        _ => boolean_t::B_FALSE,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn xde_mc_setprop(
    _arg: *mut c_void,
    _prop_name: *const c_char,
    _prop_num: mac::mac_prop_id_t,
    _prop_val_size: c_uint,
    _prop_val: *const c_void,
) -> c_int {
    ENOTSUP
}

#[unsafe(no_mangle)]
unsafe extern "C" fn xde_mc_getprop(
    _arg: *mut c_void,
    _prop_name: *const c_char,
    _prop_num: mac::mac_prop_id_t,
    _prop_val_size: c_uint,
    _prop_val: *mut c_void,
) -> c_int {
    ENOTSUP
}

#[unsafe(no_mangle)]
unsafe extern "C" fn xde_mc_propinfo(
    _arg: *mut c_void,
    _prop_name: *const c_char,
    _prop_num: mac::mac_prop_id_t,
    _prh: *mut mac::mac_prop_info_handle,
) {
}

#[unsafe(no_mangle)]
fn new_port(
    name: String,
    cfg: &VpcCfg,
    vpc_map: Arc<overlay::VpcMappings>,
    v2p: Arc<overlay::Virt2Phys>,
    v2b: Arc<overlay::Virt2Boundary>,
    ectx: Arc<ExecCtx>,
    dhcp_cfg: &DhcpCfg,
) -> Result<Arc<Port<VpcNetwork>>, OpteError> {
    let cfg = cfg.clone();
    let name_cstr = match CString::new(name.as_str()) {
        Ok(v) => v,
        Err(_) => return Err(OpteError::BadName),
    };

    let mut pb = PortBuilder::new(&name, name_cstr, cfg.guest_mac, ectx);
    firewall::setup(&mut pb, FW_FT_LIMIT)?;

    // Unwrap safety: we always have at least one FT entry, because we always
    // have at least one IP stack (v4 and/or v6).
    let nat_ft_limit = NonZeroU32::new(cfg.required_nat_space()).unwrap();

    // XXX some layers have no need for LFT, perhaps have two types
    // of Layer: one with, one without?
    gateway::setup(&pb, &cfg, vpc_map, FT_LIMIT_ONE, dhcp_cfg)?;
    router::setup(&pb, &cfg, FT_LIMIT_ONE)?;
    nat::setup(&mut pb, &cfg, nat_ft_limit)?;
    overlay::setup(&pb, &cfg, v2p, v2b, FT_LIMIT_ONE)?;

    // Set the overall unified flow and TCP flow table limits based on the total
    // configuration above, by taking the maximum of size of the individual
    // layer tables. Only the firewall and NAT layers are relevant here, since
    // the others have a size of at most 1 now.
    //
    // Safety: We're extracting the contained value in a `NonZeroU32` to
    // construct a new one, so the unwrap is safe.
    let limit =
        NonZeroU32::new(FW_FT_LIMIT.get().max(nat_ft_limit.get())).unwrap();
    let net = VpcNetwork { cfg };
    Ok(Arc::new(pb.create(net, limit, limit)?))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn xde_rx(
    arg: *mut c_void,
    mp_chain: *mut mblk_t,
    out_mp_tail: *mut *mut mblk_t,
    out_count: *mut c_uint,
    out_len: *mut usize,
) -> *mut mblk_t {
    // Safety: This arg comes from `Arc::from_ptr()` on the `MacClientHandle`
    // corresponding to the underlay port we're receiving on (derived from
    // `DlsStream`). Being here in the callback means the `MacSiphon` hasn't
    // been dropped yet, and thus our `MacClientHandle` is also still valid.
    let stream = unsafe {
        (arg as *const UnderlayDev)
            .as_ref()
            .expect("packet was received from siphon with a NULL argument")
    };

    let mut chain = if let Ok(chain) = unsafe { MsgBlkChain::new(mp_chain) } {
        chain
    } else {
        bad_packet_probe(
            None,
            Direction::In,
            mp_chain as uintptr_t,
            c"rx'd packet chain was null",
        );

        // Continue processing on an empty chain to uphold the contract with
        // MAC for the three `out_` pointer values.
        MsgBlkChain::empty()
    };

    let mut out_chain = MsgBlkChain::empty();
    let mut count = 0;
    let mut len = 0;

    // Acquire our own dev map -- this gives us access to prebuilt postboxes
    // for all active ports. We don't worry about this changing for rx -- caller
    // threads here (interrupt contexts, poll threads, fanout, worker threads)
    // are all bound to a given CPU each by MAC.
    let cpu_index = current_cpu().seq_id;
    let cpu_state = stream.ports_map[cpu_index].devs.lock();
    let mut postbox = Postbox::new();

    while let Some(pkt) = chain.pop_front() {
        if let Some(pkt) =
            xde_rx_one(&stream.stream, pkt, &cpu_state, &mut postbox)
        {
            count += 1;
            len += pkt.byte_len();
            out_chain.append(pkt);
        }
    }

    cpu_state.deliver_all(postbox);

    let (head, tail) = out_chain
        .unwrap_head_and_tail()
        .map(|v| (v.0.as_ptr(), v.1.as_ptr()))
        .unwrap_or((ptr::null_mut(), ptr::null_mut()));

    if let Some(ptr) = NonNull::new(out_len) {
        unsafe {
            ptr.write(len);
        }
    }

    if let Some(ptr) = NonNull::new(out_count) {
        unsafe {
            ptr.write(count);
        }
    }

    if let Some(ptr) = NonNull::new(out_mp_tail) {
        unsafe {
            ptr.write(tail);
        }
    }

    head
}

/// Processes an individual packet receiver on the underlay device `stream`.
///
/// This function returns any input `pkt` which is not of interest to XDE (e.g.,
/// the packet is not Geneve over v6, or no matching OPTE port could be found).
#[inline]
fn xde_rx_one(
    stream: &DlsStream,
    mut pkt: MsgBlk,
    devs: &DevMap,
    postbox: &mut Postbox,
) -> Option<MsgBlk> {
    let mblk_addr = pkt.mblk_addr();

    // We must first parse the packet in order to determine where it
    // is to be delivered.
    let parser = VpcParser {};
    let parsed_pkt = match Packet::parse_inbound(pkt.iter_mut(), parser) {
        Ok(pkt) => pkt,
        Err(e) => {
            stat_parse_error(Direction::In, &e);

            // NOTE: We are using the individual mblk_t as read only
            // here to get the pointer value so that the DTrace consumer
            // can examine the packet on failure.
            //
            // We don't know the port yet, thus the None.
            opte::engine::dbg!("Rx bad packet: {:?}", e);
            bad_packet_parse_probe(None, Direction::In, mblk_addr, &e);

            return Some(pkt);
        }
    };

    let meta = parsed_pkt.meta();
    let old_len = parsed_pkt.len();

    let ulp_meoi = match meta.ulp_meoi(old_len) {
        Ok(ulp_meoi) => ulp_meoi,
        Err(e) => {
            opte::engine::dbg!("{}", e);
            return None;
        }
    };

    // Determine where to send packet based on Geneve VNI and
    // destination MAC address.
    let vni = meta.outer_encap.vni();

    let ether_dst = meta.inner_eth.destination();

    let port_key = VniMac::new(vni, ether_dst);
    let Some(dev) = devs.get_by_key(port_key) else {
        // TODO add SDT probe
        // TODO add stat
        opte::engine::dbg!(
            "[encap] no device found for vni: {} mac: {}",
            vni,
            ether_dst
        );
        return Some(pkt);
    };

    let is_tcp = matches!(meta.inner_ulp, ValidUlp::Tcp(_));
    let mss_estimate = usize::from(ETHERNET_MTU)
        - (&meta.inner_l3, &meta.inner_ulp).packet_length();

    // We are in passthrough mode, skip OPTE processing.
    if dev.passthrough {
        drop(parsed_pkt);
        postbox.post(port_key, pkt);
        return None;
    }

    let port = &dev.port;

    let res = port.process(Direction::In, parsed_pkt);

    match res {
        Ok(ProcessResult::Modified(emit_spec)) => {
            let mut npkt = emit_spec.apply(pkt);
            let len = npkt.byte_len();

            // Due to possible pseudo-GRO, we need to inform mac/viona on how
            // it can split up this packet, if the guest cannot receive it
            // (e.g., no GRO/large frame support).
            // HW_LSO will cause viona to treat this packet as though it were
            // a locally delivered segment making use of LSO.
            if is_tcp
                && len > usize::from(ETHERNET_MTU) + Ethernet::MINIMUM_LENGTH
            {
                npkt.request_offload(
                    MblkOffloadFlags::HW_LSO,
                    mss_estimate as u32,
                );
            }

            if let Err(e) = npkt.fill_parse_info(&ulp_meoi, None) {
                opte::engine::err!("failed to set offload info: {}", e);
            }

            postbox.post(port_key, npkt);
        }
        Ok(ProcessResult::Hairpin(hppkt)) => {
            stream.tx_drop_on_no_desc(
                hppkt,
                TxHint::NoneOrMixed,
                MacTxFlags::empty(),
            );
        }
        _ => {}
    }

    None
}

#[unsafe(no_mangle)]
fn add_router_entry_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: AddRouterEntryReq = env.copy_in_req()?;
    let state = get_xde_state();
    let devs = state.devs.read();
    let dev = devs
        .get_by_name(&req.port_name)
        .ok_or_else(|| OpteError::PortNotFound(req.port_name.clone()))?;

    router::add_entry(&dev.port, req.dest, req.target, req.class)
}

#[unsafe(no_mangle)]
fn del_router_entry_hdlr(
    env: &mut IoctlEnvelope,
) -> Result<DelRouterEntryResp, OpteError> {
    let req: DelRouterEntryReq = env.copy_in_req()?;
    let state = get_xde_state();
    let devs = state.devs.read();
    let dev = devs
        .get_by_name(&req.port_name)
        .ok_or_else(|| OpteError::PortNotFound(req.port_name.clone()))?;

    router::del_entry(&dev.port, req.dest, req.target, req.class)
}

#[unsafe(no_mangle)]
fn add_fw_rule_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: AddFwRuleReq = env.copy_in_req()?;
    let state = get_xde_state();
    let devs = state.devs.read();
    let dev = devs
        .get_by_name(&req.port_name)
        .ok_or_else(|| OpteError::PortNotFound(req.port_name.clone()))?;

    firewall::add_fw_rule(&dev.port, &req)?;
    Ok(NoResp::default())
}

#[unsafe(no_mangle)]
fn rem_fw_rule_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: RemFwRuleReq = env.copy_in_req()?;
    let state = get_xde_state();
    let devs = state.devs.read();
    let dev = devs
        .get_by_name(&req.port_name)
        .ok_or_else(|| OpteError::PortNotFound(req.port_name.clone()))?;

    firewall::rem_fw_rule(&dev.port, &req)?;
    Ok(NoResp::default())
}

#[unsafe(no_mangle)]
fn set_fw_rules_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: SetFwRulesReq = env.copy_in_req()?;
    let state = get_xde_state();
    let devs = state.devs.read();
    let dev = devs
        .get_by_name(&req.port_name)
        .ok_or_else(|| OpteError::PortNotFound(req.port_name.clone()))?;

    firewall::set_fw_rules(&dev.port, &req)?;
    Ok(NoResp::default())
}

#[unsafe(no_mangle)]
fn set_v2p_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: SetVirt2PhysReq = env.copy_in_req()?;
    let state = get_xde_state();
    state.vpc_map.add(req.vip, req.phys);
    Ok(NoResp::default())
}

#[unsafe(no_mangle)]
fn clear_v2p_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: ClearVirt2PhysReq = env.copy_in_req()?;
    let state = get_xde_state();
    state.vpc_map.del(&req.vip, &req.phys);
    Ok(NoResp::default())
}

#[unsafe(no_mangle)]
fn dump_v2p_hdlr() -> Result<DumpVirt2PhysResp, OpteError> {
    let state = get_xde_state();
    Ok(state.vpc_map.dump())
}

#[unsafe(no_mangle)]
fn set_v2b_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: SetVirt2BoundaryReq = env.copy_in_req()?;
    let state = get_xde_state();
    state.v2b.set(req.vip, req.tep);
    Ok(NoResp::default())
}

#[unsafe(no_mangle)]
fn clear_v2b_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: ClearVirt2BoundaryReq = env.copy_in_req()?;
    let state = get_xde_state();
    state.v2b.remove(req.vip, req.tep);
    Ok(NoResp::default())
}

#[unsafe(no_mangle)]
fn dump_v2b_hdlr() -> Result<DumpVirt2BoundaryResp, OpteError> {
    let state = get_xde_state();
    Ok(state.v2b.dump())
}

#[unsafe(no_mangle)]
fn list_layers_hdlr(
    env: &mut IoctlEnvelope,
) -> Result<ListLayersResp, OpteError> {
    let req: ListLayersReq = env.copy_in_req()?;
    let state = get_xde_state();
    let devs = state.devs.read();
    let dev = devs
        .get_by_name(&req.port_name)
        .ok_or_else(|| OpteError::PortNotFound(req.port_name.clone()))?;

    Ok(dev.port.list_layers())
}

#[unsafe(no_mangle)]
fn clear_uft_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: ClearUftReq = env.copy_in_req()?;
    let state = get_xde_state();
    let devs = state.devs.read();
    let dev = devs
        .get_by_name(&req.port_name)
        .ok_or_else(|| OpteError::PortNotFound(req.port_name.clone()))?;

    dev.port.clear_uft()?;
    Ok(NoResp::default())
}

#[unsafe(no_mangle)]
fn clear_lft_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: ClearLftReq = env.copy_in_req()?;
    let state = get_xde_state();
    let devs = state.devs.read();
    let dev = devs
        .get_by_name(&req.port_name)
        .ok_or_else(|| OpteError::PortNotFound(req.port_name.clone()))?;

    dev.port.clear_lft(&req.layer_name)?;
    Ok(NoResp::default())
}

#[unsafe(no_mangle)]
fn dump_uft_hdlr(env: &mut IoctlEnvelope) -> Result<DumpUftResp, OpteError> {
    let req: DumpUftReq = env.copy_in_req()?;
    let state = get_xde_state();
    let devs = state.devs.read();
    let dev = devs
        .get_by_name(&req.port_name)
        .ok_or_else(|| OpteError::PortNotFound(req.port_name.clone()))?;

    dev.port.dump_uft()
}

#[unsafe(no_mangle)]
fn dump_layer_hdlr(
    env: &mut IoctlEnvelope,
) -> Result<DumpLayerResp, OpteError> {
    let req: DumpLayerReq = env.copy_in_req()?;
    let state = get_xde_state();
    let devs = state.devs.read();
    let dev = devs
        .get_by_name(&req.port_name)
        .ok_or_else(|| OpteError::PortNotFound(req.port_name.clone()))?;

    dev.port.dump_layer(&req.name)
}

#[unsafe(no_mangle)]
fn dump_tcp_flows_hdlr(
    env: &mut IoctlEnvelope,
) -> Result<DumpTcpFlowsResp, OpteError> {
    let req: DumpTcpFlowsReq = env.copy_in_req()?;
    let state = get_xde_state();
    let devs = state.devs.read();
    let dev = devs
        .get_by_name(&req.port_name)
        .ok_or_else(|| OpteError::PortNotFound(req.port_name.clone()))?;

    dev.port.dump_tcp_flows()
}

#[unsafe(no_mangle)]
fn set_external_ips_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: oxide_vpc::api::SetExternalIpsReq = env.copy_in_req()?;
    let state = get_xde_state();
    let devs = state.devs.read();
    let dev = devs
        .get_by_name(&req.port_name)
        .ok_or_else(|| OpteError::PortNotFound(req.port_name.clone()))?;

    nat::set_nat_rules(&dev.vpc_cfg, &dev.port, req)?;
    Ok(NoResp::default())
}

#[unsafe(no_mangle)]
fn allow_cidr_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: oxide_vpc::api::AllowCidrReq = env.copy_in_req()?;
    let state = get_xde_state();
    let devs = state.devs.read();
    let dev = devs
        .get_by_name(&req.port_name)
        .ok_or_else(|| OpteError::PortNotFound(req.port_name.clone()))?;

    gateway::allow_cidr(&dev.port, req.cidr, req.dir, state.vpc_map.clone())?;
    Ok(NoResp::default())
}

#[unsafe(no_mangle)]
fn remove_cidr_hdlr(
    env: &mut IoctlEnvelope,
) -> Result<RemoveCidrResp, OpteError> {
    let req: oxide_vpc::api::RemoveCidrReq = env.copy_in_req()?;
    let state = get_xde_state();
    let devs = state.devs.read();
    let dev = devs
        .get_by_name(&req.port_name)
        .ok_or_else(|| OpteError::PortNotFound(req.port_name.clone()))?;

    gateway::remove_cidr(&dev.port, req.cidr, req.dir, state.vpc_map.clone())
}

#[unsafe(no_mangle)]
fn list_ports_hdlr() -> Result<ListPortsResp, OpteError> {
    let mut resp = ListPortsResp { ports: vec![] };
    let state = get_xde_state();
    let devs = state.devs.read();
    for dev in devs.iter() {
        let ipv4_state =
            dev.vpc_cfg.ipv4_cfg().map(|cfg| cfg.external_ips.load());
        let ipv6_state =
            dev.vpc_cfg.ipv6_cfg().map(|cfg| cfg.external_ips.load());
        resp.ports.push(PortInfo {
            name: dev.port.name().to_string(),
            mac_addr: dev.port.mac_addr(),
            ip4_addr: dev.vpc_cfg.ipv4_cfg().map(|cfg| cfg.private_ip),
            ephemeral_ip4_addr: ipv4_state
                .as_ref()
                .and_then(|cfg| cfg.ephemeral_ip),
            floating_ip4_addrs: ipv4_state
                .as_ref()
                .map(|cfg| cfg.floating_ips.clone()),
            ip6_addr: dev.vpc_cfg.ipv6_cfg().map(|cfg| cfg.private_ip),
            ephemeral_ip6_addr: ipv6_state
                .as_ref()
                .and_then(|cfg| cfg.ephemeral_ip),
            floating_ip6_addrs: ipv6_state
                .as_ref()
                .map(|cfg| cfg.floating_ips.clone()),
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

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
//! central RWLock, as reads/writes are only held for the duration of packet
//! processing, or as long as is required to insert new rules.
//!
//! ### [`DevMap`] views
//! Ideally, we want the above interactions to have minimal impact on one another
//! (e.g., insertion of a port should not lock out all use of the datapath).
//! For this reason, we provide the datapath entrypoints with read-only shared
//! copies of the central [`DevMap`].
//!  * For Rx entrypoints, we allocate a `Vec<KMutex<Arc<DevMap>>>`. Each CPU
//!    on the system has its own slot within this `Vec`, such that lock
//!    contention only occurs when a port is being added/removed. The CPU ID is
//!    used as an index into this table, the lock is acquired, and held for the
//!    duration of packet processing (including delivery via
//!    [`deliver_all()`](DevMap::deliver_all)), as all packet deliveries require
//!    a live `XdeDev`. This prevents port removal from completing while any Rx
//!    handler is active.
//!  * For Tx entrypoints, each `XdeDev` holds a per-port `KRwLock<Arc<DevMap>>`.
//!    - Unicast to remote host: No `DevMap` needed, packets go directly to
//!      underlay.
//!    - Hairpin (same-host unicast): Hold per-port `DevMap` read lock for
//!      local delivery.
//!    - Multicast: Hold per-port `mcast_fwd` and `DevMap` read locks for the
//!      duration of Tx processing (replication + local delivery).
//!    We prefer an RwLock here over a Mutex given that we can be called from
//!    multiple threads, and our callers are not expected to bound to a given
//!    CPU.
//!
//! Read locks and mutexes are held for the duration of packet processing to
//! prevent use-after-free of the illumos datapath of any port. Management
//! operations attempting to remove a port will block when acquiring a
//! write/exclusive lock to update the map, ensuring no Rx/Tx context can hold
//! references to a port while its DLS/MAC datapath is being torn down.
//! Each lock's wait time for a management task is bounded to the packet
//! processing duration, and any block on the datapath is limited to one or two
//! `Arc` swaps depending on the work being done.
//!
//! In the Rx case, loopback delivery or MAC->CPU oversubscription present some
//! risk of contention. These are not expected paths in the product, but using
//! them does not impact correctness.
//!
//! The remaining locking risk is double-locking a given Rx Mutex by the same
//! thread during packet processing. This results in a panic, but can only
//! happen if we transit the NIC's Rx path twice in the same stack (i.e. Rx on
//! NIC -> mac_rx on the OPTE port -> ... -> loopback delivery to underlay
//! device). This should be impossible, given that any packet sent upstack by
//! XDE must have a MAC address belonging to the OPTE port.
//!
//! For Tx, re-entrant read lock acquisition exposes us to a deadlock if the
//! ordering `read[xde_mc_tx] -> write[ioctl] -> read[xde_mc_tx]` occurs on one
//! lock -- the latter read acquisition will block indefinitely. This is a
//! possibility we need to consciously work around. Hairpin exchanges
//! (e.g., ARP -> ICMP ping, DHCP) can lead to fairly deep stacks of the form
//! `(ip) -> xde_mc_tx -> (ip) -> xde_mc_tx -> ...` when used with zones (this
//! is not an issue with viona, which returns once packets are communicated to
//! the guest). Thus, we *must* drop the read lock before delivering any
//! hairpin packets.
//!
//! Note:
//!  - We cannot afford to take the management lock ([`TokenLock`]) during any
//!    dataplane operation. If a dataplane path ever needs to consult the
//!    central source of truth directly, the minimally acceptable pattern is a
//!    read of `state.devs.read()` (never the management token itself). In
//!    practice, to further reduce contention on reader counters we avoid even
//!    this by using per-CPU cached `Arc<DevMap>` snapshots for Rx and per-port
//!    `Arc<DevMap>` snapshots for Tx. Both are updated by `refresh_maps()`
//!    whenever the canonical map changes.
//!  - Multicast forwarding state (`mcast_fwd`) follows the same model: a copy
//!    is kept per-port, updated by `refresh_maps()` whenever the canonical
//!    forwarding table changes.
//!
//! ### [`TokenLock`] and [`DevMap`] updates
//! The `TokenLock` primitive provides us with logical mutual exclusion around
//! the underlay and the ability to modify the canonical [`DevMap`] -- without
//! holding a `KMutex`. Management operations made by OPTE *will* upcall -- we
//! must resolve link names to IDs, and add/remove link information from DLS.
//! Doing so makes an ioctl thread vulnerable to receiving signals, so other
//! threads trying to take the management lock must be able to take, e.g.,
//! a SIGSTOP.
//!
//! Whenever the central [`DevMap`] is modified, we call [`refresh_maps()`]
//! which iterates through each reachable [`XdeDev`] and underlay port. For
//! every instance of the [`DevMap`] Arc, we acquire the write lock (blocking if
//! Tx/Rx holds a read lock), swap the Arc, and release the write lock. This
//! ensures that port removal cannot fully proceed until no Tx/Rx context holds
//! references to the port.
//!
//! ### Teardown
//! When `clear_xde_underlay()` is called (after all ports have been removed),
//! all per-CPU and per-port [`DevMap`] snapshots contain no ports (updated by
//! the final `refresh_maps()` calls during port deletion). The management lock
//! ensures no concurrent modifications, allowing underlay port Arcs to be
//! safely unwrapped.

use crate::dev_map::DevMap;
use crate::dev_map::ReadOnlyDevMap;
use crate::dev_map::VniMac;
use crate::dls;
use crate::dls::DlsStream;
use crate::dls::LinkId;
use crate::ioctl::IoctlEnvelope;
use crate::ip::AF_INET;
use crate::ip::AF_INET6;
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
use alloc::collections::BTreeMap;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::num::NonZeroU32;
use core::num::NonZeroUsize;
use core::ptr;
use core::ptr::NonNull;
use core::ptr::addr_of;
use core::ptr::addr_of_mut;
use core::time::Duration;
use illumos_sys_hdrs::mac::MacEtherOffloadFlags;
use illumos_sys_hdrs::mac::MblkOffloadFlags;
use illumos_sys_hdrs::*;
use ingot::geneve::Geneve;
use ingot::geneve::GeneveMut;
use ingot::geneve::GeneveOpt;
use ingot::geneve::GeneveRef;
use ingot::geneve::ValidGeneve;
use ingot::types::HeaderLen;
use ingot::types::HeaderParse;
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
use opte::api::MacAddr;
use opte::api::MulticastUnderlay;
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
use opte::engine::ether::EtherAddr;
use opte::engine::ether::Ethernet;
use opte::engine::ether::EthernetRef;
use opte::engine::geneve::Vni;
use opte::engine::geneve::WalkOptions;
use opte::engine::headers::IpAddr;
use opte::engine::ip::ValidL3;
use opte::engine::ip::v4::Ipv4Ref;
use opte::engine::ip::v6::Ipv6Addr;
use opte::engine::ip::v6::Ipv6Ref;
use opte::engine::packet::InnerFlowId;
use opte::engine::packet::Packet;
use opte::engine::packet::ParseError;
use opte::engine::parse::ValidUlp;
use opte::engine::port::Port;
use opte::engine::port::PortBuilder;
use opte::engine::port::ProcessResult;
use opte::engine::rule::MappingResource;
use oxide_vpc::api::AddFwRuleReq;
use oxide_vpc::api::AddRouterEntryReq;
use oxide_vpc::api::ClearMcast2PhysReq;
use oxide_vpc::api::ClearMcastForwardingReq;
use oxide_vpc::api::ClearVirt2BoundaryReq;
use oxide_vpc::api::ClearVirt2PhysReq;
use oxide_vpc::api::CreateXdeReq;
use oxide_vpc::api::DEFAULT_MULTICAST_VNI;
use oxide_vpc::api::DelRouterEntryReq;
use oxide_vpc::api::DelRouterEntryResp;
use oxide_vpc::api::DeleteXdeReq;
use oxide_vpc::api::DhcpCfg;
use oxide_vpc::api::DumpMcastForwardingResp;
use oxide_vpc::api::DumpMcastSubscriptionsResp;
use oxide_vpc::api::DumpVirt2BoundaryResp;
use oxide_vpc::api::DumpVirt2PhysResp;
use oxide_vpc::api::ListPortsResp;
use oxide_vpc::api::McastForwardingEntry;
use oxide_vpc::api::McastSubscribeReq;
use oxide_vpc::api::McastSubscriptionEntry;
use oxide_vpc::api::McastUnsubscribeAllReq;
use oxide_vpc::api::McastUnsubscribeReq;
use oxide_vpc::api::NextHopV6;
use oxide_vpc::api::PhysNet;
use oxide_vpc::api::PortInfo;
use oxide_vpc::api::RemFwRuleReq;
use oxide_vpc::api::RemoveCidrResp;
use oxide_vpc::api::Replication;
use oxide_vpc::api::SetFwRulesReq;
use oxide_vpc::api::SetMcast2PhysReq;
use oxide_vpc::api::SetMcastForwardingReq;
use oxide_vpc::api::SetVirt2BoundaryReq;
use oxide_vpc::api::SetVirt2PhysReq;
use oxide_vpc::cfg::IpCfg;
use oxide_vpc::cfg::VpcCfg;
use oxide_vpc::engine::VpcNetwork;
use oxide_vpc::engine::VpcParser;
use oxide_vpc::engine::firewall;
use oxide_vpc::engine::gateway;
use oxide_vpc::engine::geneve::MssInfoRef;
use oxide_vpc::engine::geneve::OxideOptions;
use oxide_vpc::engine::geneve::ValidOxideOption;
use oxide_vpc::engine::nat;
use oxide_vpc::engine::overlay;
use oxide_vpc::engine::router;

const ETHERNET_MTU: u16 = 1500;

// Type alias for multicast forwarding table:
// Maps IPv6 destination addresses to their next hop replication entries.
type McastForwardingTable =
    BTreeMap<MulticastUnderlay, BTreeMap<NextHopV6, Replication>>;

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
    pub safe fn __dtrace_probe_mcast__tx(
        af: uintptr_t,        // AF_INET or AF_INET6
        inner_dst: uintptr_t, // *const Ipv4Addr or *const Ipv6Addr
        vni: uintptr_t,
    );
    pub safe fn __dtrace_probe_mcast__rx(
        af: uintptr_t,
        inner_dst: uintptr_t,
        vni: uintptr_t,
    );
    pub safe fn __dtrace_probe_mcast__local__delivery(
        af: uintptr_t,
        inner_dst: uintptr_t,
        vni: uintptr_t,
        port: uintptr_t,
    );
    pub safe fn __dtrace_probe_mcast__underlay__fwd(
        af: uintptr_t,
        inner_dst: uintptr_t,
        vni: uintptr_t,
        next_hop: *const oxide_vpc::api::Ipv6Addr,
    );
    pub safe fn __dtrace_probe_mcast__external__fwd(
        af: uintptr_t,
        inner_dst: uintptr_t,
        vni: uintptr_t,
        next_hop: *const oxide_vpc::api::Ipv6Addr,
    );

    // Multicast control-plane probes
    pub safe fn __dtrace_probe_mcast__map__set(
        af: uintptr_t,
        group: uintptr_t,
        underlay: *const oxide_vpc::api::Ipv6Addr,
        vni: uintptr_t,
    );
    pub safe fn __dtrace_probe_mcast__map__clear(
        af: uintptr_t,
        group: uintptr_t,
        underlay: *const oxide_vpc::api::Ipv6Addr,
        vni: uintptr_t,
    );
    pub safe fn __dtrace_probe_mcast__fwd__set(
        underlay: *const oxide_vpc::api::Ipv6Addr,
        count: uintptr_t,
        vni: uintptr_t,
    );
    pub safe fn __dtrace_probe_mcast__fwd__clear(
        underlay: *const oxide_vpc::api::Ipv6Addr,
        vni: uintptr_t,
    );
    pub safe fn __dtrace_probe_mcast__subscribe(
        port: uintptr_t,
        af: uintptr_t,
        group: uintptr_t,
        vni: uintptr_t,
    );
    pub safe fn __dtrace_probe_mcast__unsubscribe(
        port: uintptr_t,
        af: uintptr_t,
        group: uintptr_t,
        vni: uintptr_t,
    );
    pub safe fn __dtrace_probe_mcast__unsubscribe__all(
        af: uintptr_t,
        group: uintptr_t,
        vni: uintptr_t,
    );

    // Multicast dataplane problem probes
    pub safe fn __dtrace_probe_mcast__tx__pullup__fail(len: uintptr_t);
    pub safe fn __dtrace_probe_mcast__rx__pullup__fail(len: uintptr_t);
    pub safe fn __dtrace_probe_mcast__no__fwd__entry(
        underlay: *const oxide_vpc::api::Ipv6Addr,
        vni: uintptr_t,
    );
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
    m2p: Arc<overlay::Mcast2Phys>,
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
    /// XDE-wide multicast forwarding table mapping underlay multicast addresses
    /// to their physical next hops with replication information.
    /// Maps: Ipv6Addr (underlay multicast address) -> BTreeMap<NextHopV6 (next hops), Replication>
    mcast_fwd: Arc<KRwLock<McastForwardingTable>>,
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
                mcast_fwd: Arc::new(KRwLock::new(BTreeMap::new())),
            }),
            devs,
            ectx,
            vpc_map: Arc::new(overlay::VpcMappings::new()),
            m2p: Arc::new(overlay::Mcast2Phys::new()),
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

    // Each port has its own copy of the multicast forwarding table.
    // Used in Tx path (which is not CPU-pinned), so stored per-port rather
    // than per-CPU.
    mcast_fwd: KRwLock<Arc<McastForwardingTable>>,
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

        OpteCmd::SetMcastForwarding => {
            let resp = set_mcast_forwarding_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::ClearMcastForwarding => {
            let resp = clear_mcast_forwarding_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::DumpMcastForwarding => {
            let resp = dump_mcast_forwarding_hdlr();
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::DumpMcastSubscriptions => {
            let resp = dump_mcast_subscriptions_hdlr();
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::McastSubscribe => {
            let resp = mcast_subscribe_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::McastUnsubscribe => {
            let resp = mcast_unsubscribe_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::McastUnsubscribeAll => {
            let resp = mcast_unsubscribe_all_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::SetMcast2Phys => {
            let resp = set_m2p_hdlr(&mut env);
            hdlr_resp(&mut env, resp)
        }

        OpteCmd::ClearMcast2Phys => {
            let resp = clear_m2p_hdlr(&mut env);
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
            state.m2p.clone(),
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
        mcast_fwd: KRwLock::new(Arc::new(token.mcast_fwd.read().clone())),
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
            &token.mcast_fwd,
            RefreshScope::Ports,
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
            &token.mcast_fwd,
            RefreshScope::Ports,
        );

        xde
    };

    // Break potential self-reference cycles before dropping this `XdeDev` by
    // resetting its per-port `DevMap` snapshot to an empty map. Otherwise, the
    // `Arc<DevMap>` inside `port_map` may still contain an Arc back to this
    // same XdeDev, keeping it (and its underlay Arc clones) alive beyond
    // deletion.
    {
        let mut port_map = xde.port_map.write();
        *port_map = Arc::new(DevMap::new());
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
            &token.mcast_fwd,
            RefreshScope::Ports,
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

/// Which state was modified, dictating which caches need refresh.
#[derive(Copy, Clone)]
enum RefreshScope {
    /// Port was added or removed; [`DevMap`] needs refresh everywhere.
    Ports,
    /// Multicast forwarding table changed; only `mcast_fwd` needs refresh.
    Multicast,
}

/// Rebuild each entrypoint's view of the central [`DevMap`] and/or multicast
/// forwarding table `McastForwardingTable`, depending on what changed.
///
/// This selective refresh avoids unnecessary locking. For example, multicast
/// subscription changes don't need to lock out unicast-only Rx processing.
fn refresh_maps(
    devs: KRwLockWriteGuard<DevMap>,
    underlay: &UnderlayState,
    mcast_fwd: &Arc<KRwLock<McastForwardingTable>>,
    scope: RefreshScope,
) {
    let new_map = Arc::new(devs.clone());

    match scope {
        RefreshScope::Ports => {
            // Port topology changed: update `DevMap` everywhere.
            // Also update `mcast_fwd` since ports need current forwarding state.
            let new_mcast_fwd = Arc::new(mcast_fwd.read().clone());

            // Update both underlay ports' per-CPU caches (u1 and u2).
            // Each underlay port has a Vec<PerEntryState> with one entry per CPU.
            let underlay_ports =
                [&underlay.u1.stream.ports_map, &underlay.u2.stream.ports_map];
            for per_cpu_map in underlay_ports {
                for entry in per_cpu_map {
                    let mut map = entry.devs.lock();
                    *map = Arc::clone(&new_map);
                }
            }

            // Update all ports' per-port maps and multicast state.
            for port in new_map.iter() {
                {
                    let mut map = port.port_map.write();
                    *map = Arc::clone(&new_map);
                }
                {
                    let mut mcast = port.mcast_fwd.write();
                    *mcast = Arc::clone(&new_mcast_fwd);
                }
            }
        }
        RefreshScope::Multicast => {
            // Only multicast forwarding changed: update mcast_fwd on each port.
            // Don't touch per-CPU DevMap mutexes (avoids blocking unicast Rx).
            let new_mcast_fwd = Arc::new(mcast_fwd.read().clone());

            for port in new_map.iter() {
                let mut mcast = port.mcast_fwd.write();
                *mcast = Arc::clone(&new_mcast_fwd);
            }
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

    // Clear multicast forwarding table
    token.mcast_fwd.write().clear();

    if let Some(underlay) = token.underlay.take() {
        // If the underlay references have leaked/spread beyond `XdeDev`s and not
        // been cleaned up, we have committed a fatal programming error.
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
            // we just dropped. The `unwrap_or_else` asserts that we have consumed them
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
    devo_bus_ops: core::ptr::null::<bus_ops>(),
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
    dst_dev: &XdeDev,
    port_key: VniMac,
    mut pkt: MsgBlk,
    postbox: &mut TxPostbox,
) {
    use Direction::*;

    let mblk_addr = pkt.mblk_addr();

    // Loopback requires a reparse to account for UFT fastpath.
    // We might be able to do better, but the logistics in passing around
    // the emitspec in lieu of "full" metadata might be a little troublesome.
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

    guest_loopback_probe(mblk_addr, &flow, src_dev, dst_dev);

    match dst_dev.port.process(In, parsed_pkt) {
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
                dst_dev.port.name(),
                e
            );
        }
    }
}

/// Locate the Oxide Multicast Geneve option and return the offset to its body.
///
/// Walks through Geneve options starting at `geneve_offset + 8` to find the
/// Oxide Multicast option (class=0x0129, type=0x01). Returns the offset to the
/// option body (after the 4-byte option header) if found.
///
/// Safety: This function validates option headers as it walks to avoid reading
/// beyond packet boundaries. Returns `None` if the option is not found or if
/// validation fails.
///
/// # Geneve Option Format
/// Each option consists of:
/// - 2 bytes: Option class
/// - 1 byte: Flags (bit 7=critical) + Type (bits 0-6)
/// - 1 byte: Reserved (3 bits) + Length in 4-byte words (5 bits)
/// - N bytes: Option data (N = length field * 4)
fn find_mcast_option_offset(
    pkt: &MsgBlk,
    geneve_offset: usize,
) -> Option<usize> {
    let geneve_slice = pkt.get(geneve_offset..)?;
    let (geneve_hdr, ..) = ValidGeneve::parse(geneve_slice).ok()?;

    let mut cursor = geneve_offset + Geneve::MINIMUM_LENGTH;

    for opt in OxideOptions::from_raw(&geneve_hdr) {
        let Ok(opt) = opt else { break };
        if let Some(ValidOxideOption::Multicast(_)) = opt.option.known() {
            return Some(cursor + GeneveOpt::MINIMUM_LENGTH);
        }
        cursor += opt.packet_length();
    }

    None
}

/// Update the Oxide Multicast Geneve option's Tx-only replication field.
///
/// Locates the multicast option and rewrites the Tx-only replication instruction
/// in the first byte of the option body (top 2 bits encode the replication mode).
///
/// Returns `true` if the option was found and updated, `false` otherwise.
///
/// # Replication Encoding (Tx-only)
/// The replication field uses the top 2 bits of the first byte:
/// - `External` (0): 0x00
/// - `Underlay` (1): 0x40
/// - `All` (2): 0x80
/// - `Reserved` (3): 0xC0
#[inline]
fn update_mcast_replication(
    pkt: &mut MsgBlk,
    geneve_offset: usize,
    replication: Replication,
) -> bool {
    let Some(mcast_body_off) = find_mcast_option_offset(pkt, geneve_offset)
    else {
        return false;
    };

    let Some(rep_byte) = pkt.get_mut(mcast_body_off..mcast_body_off + 1) else {
        return false;
    };

    // Encode replication in top 2 bits, preserve bottom 6 bits
    let repl_bits = (replication as u8) << 6;
    rep_byte[0] = (rep_byte[0] & 0x3F) | repl_bits;
    true
}

struct MulticastTxContext<'a> {
    inner_dst: oxide_vpc::api::IpAddr, // Inner/overlay destination IP (for subscriptions)
    underlay_dst: Ipv6Addr, // Outer/underlay destination IP (for forwarding lookup)
    vni: Vni,
    out_pkt: &'a MsgBlk,
    encap_len: u32,
    inner_eth_len: usize,
    non_eth_payl_bytes: u32,
    tun_meoi: &'a illumos_sys_hdrs::mac::mac_ether_offload_info_t,
    l4_hash: u32,
}

struct MulticastRxContext<'a> {
    inner_dst: oxide_vpc::api::IpAddr, // Inner/overlay destination IP (for subscriptions)
    underlay_dst: Ipv6Addr, // Outer/underlay destination IP (for forwarding lookup)
    vni: Vni,
    pkt: &'a MsgBlk,
    pullup_len: usize,
    // Byte offset of the inner Ethernet header from the start of the packet.
    inner_eth_off: usize,
}

/// Handle multicast packet forwarding for same-sled delivery and underlay
/// replication based on the XDE-wide multicast forwarding table.
///
/// Always delivers to local same-sled subscribers regardless of replication mode.
/// Routes to next hop unicast addresses for ALL replication modes to determine
/// reachability and underlay port/MAC. Packet destination is always the multicast
/// address with multicast MAC. The [`Replication`] type is a Tx-only instruction
/// telling the switch which port groups to replicate to: External (front panel),
/// Underlay (other sleds), or Both.
///
/// [`Replication`]: oxide_vpc::api::Replication
fn handle_mcast_tx<'a>(
    ctx: MulticastTxContext,
    src_dev: &'a XdeDev,
    postbox: &mut TxPostbox,
    devs: &'a DevMap,
    cpu_mcast_fwd: &'a McastForwardingTable,
) {
    // DTrace probe: multicast Tx entry
    let (af, addr_ptr) = match &ctx.inner_dst {
        oxide_vpc::api::IpAddr::Ip4(v4) => {
            (AF_INET as usize, AsRef::<[u8]>::as_ref(v4).as_ptr() as uintptr_t)
        }
        oxide_vpc::api::IpAddr::Ip6(v6) => {
            (AF_INET6 as usize, AsRef::<[u8]>::as_ref(v6).as_ptr() as uintptr_t)
        }
    };
    __dtrace_probe_mcast__tx(af, addr_ptr, ctx.vni.as_u32() as uintptr_t);

    // Compute packet offsets once (used for both local delivery and next hop forwarding)
    let pullup_len = (ctx.encap_len as usize)
        + (ctx.non_eth_payl_bytes as usize)
        + ctx.inner_eth_len;
    let geneve_offset = usize::from(ctx.tun_meoi.meoi_l2hlen)
        + usize::from(ctx.tun_meoi.meoi_l3hlen)
        + usize::from(ctx.tun_meoi.meoi_l4hlen);

    // Local same-sled delivery: always deliver to subscribers on this sled,
    // independent of the Tx-only Replication instruction (not an access control mechanism).
    // The Replication type only affects how switches handle the packet on Tx.
    // Subscription is keyed by underlay (outer) IPv6 multicast address.
    let underlay_addr =
        oxide_vpc::api::Ipv6Addr::from(ctx.underlay_dst.bytes());
    let group_key = MulticastUnderlay::new_unchecked(underlay_addr);

    if let Some(listeners) = devs.mcast_listeners(&group_key) {
        let my_key = VniMac::new(ctx.vni, src_dev.port.mac_addr());
        for el in listeners {
            // Skip delivering to self
            if my_key == *el {
                continue;
            }
            // Note: The inner destination MAC is already set to the multicast MAC by
            // OPTE's `EncapAction` transformation. No manual rewrite needed for Tx path.
            let Ok(my_pkt) = ctx.out_pkt.pullup(NonZeroUsize::new(pullup_len))
            else {
                opte::engine::dbg!(
                    "mcast Tx pullup failed: requested {} bytes",
                    pullup_len
                );
                let xde = get_xde_state();
                xde.stats.vals.mcast_tx_pullup_fail().incr(1);
                __dtrace_probe_mcast__tx__pullup__fail(pullup_len as uintptr_t);
                continue;
            };

            match devs.get_by_key(*el) {
                Some(dev) => {
                    // DTrace probe: local delivery
                    let (af, addr_ptr) = match &ctx.inner_dst {
                        oxide_vpc::api::IpAddr::Ip4(v4) => (
                            AF_INET as usize,
                            AsRef::<[u8]>::as_ref(v4).as_ptr() as uintptr_t,
                        ),
                        oxide_vpc::api::IpAddr::Ip6(v6) => (
                            AF_INET6 as usize,
                            AsRef::<[u8]>::as_ref(v6).as_ptr() as uintptr_t,
                        ),
                    };
                    __dtrace_probe_mcast__local__delivery(
                        af,
                        addr_ptr,
                        ctx.vni.as_u32() as uintptr_t,
                        dev.port.name_cstr().as_ptr() as uintptr_t,
                    );
                    guest_loopback(src_dev, dev, *el, my_pkt, postbox);
                    let xde = get_xde_state();
                    xde.stats.vals.mcast_tx_local().incr(1);
                }
                None => {
                    let xde = get_xde_state();
                    xde.stats.vals.mcast_tx_stale_local().incr(1);
                }
            }
        }
    }

    // Next hop forwarding: send packets to configured next hops.
    //
    // At the leaf level, we process all next hops in the forwarding table.
    // Each next hop's `Replication` is a Tx-only instruction telling the switch
    // which ports to replicate to:
    // - External: ports set for external multicast traffic (egress to external networks)
    // - Underlay: replicate to other sleds (using multicast outer dst)
    // - Both: both external and underlay replication
    //
    // We already have the Arc from the per-CPU cache, no need to clone.
    let underlay_key = MulticastUnderlay::new_unchecked(ctx.underlay_dst);
    if cpu_mcast_fwd.get(&underlay_key).is_none() {
        __dtrace_probe_mcast__no__fwd__entry(
            &ctx.underlay_dst,
            ctx.vni.as_u32() as uintptr_t,
        );
        let xde = get_xde_state();
        xde.stats.vals.mcast_tx_no_fwd_entry().incr(1);
    }

    if let Some(next_hops) = cpu_mcast_fwd.get(&underlay_key) {
        // We found forwarding entries, replicate to each next hop
        for (next_hop, replication) in next_hops.iter() {
            // Clone packet with headers using pullup
            let Ok(mut fwd_pkt) =
                ctx.out_pkt.pullup(NonZeroUsize::new(pullup_len))
            else {
                opte::engine::dbg!(
                    "mcast Tx next hop pullup failed: requested {} bytes",
                    pullup_len
                );
                let xde = get_xde_state();
                xde.stats.vals.mcast_tx_pullup_fail().incr(1);
                __dtrace_probe_mcast__tx__pullup__fail(pullup_len as uintptr_t);
                continue; // Skip this destination on allocation failure
            };

            // Route to next hop unicast address to determine which underlay
            // port/MAC to use. Packet destination is the multicast address with
            // multicast MAC (RFC 2464).
            //
            // NextHopV6.addr = unicast switch address (for routing)
            // Outer dst IP = ctx.underlay_dst (multicast address from M2P)
            // Geneve Replication is a Tx-only instruction telling the switch
            // which port groups to use.
            let routing_dst = next_hop.addr;
            let actual_outer_dst = ctx.underlay_dst;

            // Update VNI for this next hop's destination VPC using ingot.
            //
            // Parse the Geneve header mutably and use the GeneveMut trait to set VNI.
            // This avoids manual offset calculations and benefits from ingot's
            // bounds checking.
            if let Ok((mut pkt, _, _)) =
                ValidGeneve::parse(&mut fwd_pkt[geneve_offset..])
            {
                pkt.set_vni(next_hop.vni);
            }
            // Update Geneve multicast option with the Tx-only replication
            // instruction for the switch.
            update_mcast_replication(&mut fwd_pkt, geneve_offset, *replication);

            // Route to switch unicast address to determine which underlay
            // port/MAC to use. Packet destination is multicast address with
            // multicast MAC.
            let route_key =
                RouteKey { dst: routing_dst, l4_hash: Some(ctx.l4_hash) };
            let Route { src: mac_src, dst: _mac_dst, underlay_idx } =
                src_dev.routes.next_hop(route_key, src_dev);

            // Derive destination MAC from IPv6 multicast address per RFC 2464:
            // IPv6 multicast MAC = 33:33 + last 4 bytes of IPv6 address
            let ipv6_bytes = actual_outer_dst.bytes();
            let dst_mac = EtherAddr::from([
                0x33,
                0x33,
                ipv6_bytes[12],
                ipv6_bytes[13],
                ipv6_bytes[14],
                ipv6_bytes[15],
            ]);

            // Fill in outer MAC addresses
            let final_pkt = unsafe {
                let mblk = fwd_pkt.unwrap_mblk().as_ptr();
                let rptr = (*mblk).b_rptr;
                ptr::copy(dst_mac.as_ptr(), rptr, 6);
                ptr::copy(mac_src.as_ptr(), rptr.add(6), 6);

                MsgBlk::wrap_mblk(mblk).unwrap()
            };

            // Replication is a Tx-only instruction telling the switch which
            // port groups to replicate to. Local same-sled delivery always
            // occurs regardless of this setting.
            //
            // Packet is sent once to the underlay. The switch reads the Geneve
            // Replication field and performs the actual bifurcation.

            // Prepare common data for DTrace probes
            let outer_ip6 =
                oxide_vpc::api::Ipv6Addr::from(actual_outer_dst.bytes());
            let (af, addr_ptr) =
                (AF_INET6 as usize, &outer_ip6 as *const _ as uintptr_t);

            // Fire DTrace probes and increment stats based on replication mode
            match replication {
                oxide_vpc::api::Replication::Underlay => {
                    __dtrace_probe_mcast__underlay__fwd(
                        af,
                        addr_ptr,
                        ctx.vni.as_u32() as uintptr_t,
                        &next_hop.addr,
                    );
                    let xde = get_xde_state();
                    xde.stats.vals.mcast_tx_underlay().incr(1);
                }
                oxide_vpc::api::Replication::Both => {
                    __dtrace_probe_mcast__underlay__fwd(
                        af,
                        addr_ptr,
                        ctx.vni.as_u32() as uintptr_t,
                        &next_hop.addr,
                    );
                    __dtrace_probe_mcast__external__fwd(
                        af,
                        addr_ptr,
                        ctx.vni.as_u32() as uintptr_t,
                        &next_hop.addr,
                    );
                    let xde = get_xde_state();
                    xde.stats.vals.mcast_tx_underlay().incr(1);
                    xde.stats.vals.mcast_tx_external().incr(1);
                }
                oxide_vpc::api::Replication::External => {
                    __dtrace_probe_mcast__external__fwd(
                        af,
                        addr_ptr,
                        ctx.vni.as_u32() as uintptr_t,
                        &next_hop.addr,
                    );
                    let xde = get_xde_state();
                    xde.stats.vals.mcast_tx_external().incr(1);
                }
                oxide_vpc::api::Replication::Reserved => {
                    // Reserved: drop packet
                    continue;
                }
            }

            // Send to underlay (common for all valid replication modes)
            postbox.post_underlay(
                underlay_idx,
                TxHint::from_crc32(ctx.l4_hash),
                final_pkt,
            );
        }
    }
}

/// Handle multicast packet reception from the underlay.
///
/// OPTE is always a leaf node in the multicast replication tree.
/// This function only delivers packets to local subscribers.
///
/// The Replication type is Tx-only (instructions to the switch), so the
/// replication field is ignored on Rx. Local delivery is based purely on
/// subscriptions.
fn handle_mcast_rx(
    ctx: MulticastRxContext,
    stream: &DlsStream,
    devs: &DevMap,
    postbox: &mut Postbox,
) {
    // DTrace probe: multicast Rx entry
    let (af, addr_ptr) = match &ctx.inner_dst {
        oxide_vpc::api::IpAddr::Ip4(v4) => {
            (AF_INET as usize, v4 as *const _ as uintptr_t)
        }
        oxide_vpc::api::IpAddr::Ip6(v6) => {
            (AF_INET6 as usize, v6 as *const _ as uintptr_t)
        }
    };
    __dtrace_probe_mcast__rx(af, addr_ptr, ctx.vni.as_u32() as uintptr_t);

    // Subscription is keyed by underlay (outer) IPv6 multicast address.
    // This uniquely identifies the multicast group across the fleet.
    let underlay_addr =
        oxide_vpc::api::Ipv6Addr::from(ctx.underlay_dst.bytes());
    let group_key = MulticastUnderlay::new_unchecked(underlay_addr);

    // Validate packet and derive the multicast MAC before attempting delivery.
    // The inner destination MAC will be rewritten to the proper multicast MAC
    // derived from the inner IP address (RFC 1112 for IPv4, RFC 2464 for IPv6).
    // This ensures guests receive packets with standard multicast MACs rather
    // than broadcast or other MAC addresses that may have been used during
    // encapsulation.
    let Some(expected_mac) = ctx.inner_dst.multicast_mac() else {
        // Inner IP is not multicast despite outer being multicast.
        // This is malformed - drop the packet.
        opte::engine::dbg!(
            "mcast Rx: inner dst {} is not multicast",
            ctx.inner_dst
        );
        let xde = get_xde_state();
        xde.stats.vals.mcast_rx_bad_inner_dst().incr(1);
        return;
    };

    // Deliver to all local subscribers. VNI validation and VPC isolation
    // are handled by OPTE's inbound overlay layer.
    if let Some(ports) = devs.mcast_listeners(&group_key) {
        for el in ports {
            let Ok(my_pkt) = ctx.pkt.pullup(NonZeroUsize::new(ctx.pullup_len))
            else {
                opte::engine::dbg!(
                    "mcast Rx pullup failed: requested {} bytes",
                    ctx.pullup_len
                );
                let xde = get_xde_state();
                xde.stats.vals.mcast_rx_pullup_fail().incr(1);
                __dtrace_probe_mcast__rx__pullup__fail(
                    ctx.pullup_len as uintptr_t,
                );
                continue;
            };

            // Rewrite the inner destination MAC to the multicast MAC.
            //
            // Unlike Tx path (where `EncapAction` sets the MAC during transformation),
            // Rx packets arrive from the underlay with arbitrary inner MACs set by
            // the originating host. `DecapAction` only pops outer headers, so XDE must
            // normalize the inner MAC here before local delivery.
            //
            // This cannot be done in OPTE because the multicast routing decision
            // (which packets need normalization) requires XDE's subscription tables.
            let my_pkt = unsafe {
                let mblk = my_pkt.unwrap_mblk().as_ptr();
                let rptr = (*mblk).b_rptr;
                let dst_mac_ptr = rptr.add(ctx.inner_eth_off);

                // Write the correct multicast MAC
                ptr::copy(expected_mac.as_ptr(), dst_mac_ptr, 6);

                MsgBlk::wrap_mblk(mblk).unwrap()
            };

            match devs.get_by_key(*el) {
                Some(dev) => {
                    // DTrace probe: Rx local delivery
                    let (af, addr_ptr) = match &ctx.inner_dst {
                        oxide_vpc::api::IpAddr::Ip4(v4) => {
                            (AF_INET as usize, v4 as *const _ as uintptr_t)
                        }
                        oxide_vpc::api::IpAddr::Ip6(v6) => {
                            (AF_INET6 as usize, v6 as *const _ as uintptr_t)
                        }
                    };
                    __dtrace_probe_mcast__local__delivery(
                        af,
                        addr_ptr,
                        ctx.vni.as_u32() as uintptr_t,
                        dev.port.name_cstr().as_ptr() as uintptr_t,
                    );
                    xde_rx_one_direct(stream, dev, *el, my_pkt, postbox);
                    let xde = get_xde_state();
                    xde.stats.vals.mcast_rx_local().incr(1);
                }
                None => {
                    let xde = get_xde_state();
                    xde.stats.vals.mcast_rx_stale_local().incr(1);
                }
            }
        }
    } else {
        // No subscription entry found for this multicast group
        let underlay_ip6 =
            oxide_vpc::api::Ipv6Addr::from(ctx.underlay_dst.bytes());
        __dtrace_probe_mcast__no__fwd__entry(
            &underlay_ip6,
            ctx.vni.as_u32() as uintptr_t,
        );
        let xde = get_xde_state();
        xde.stats.vals.mcast_rx_no_subscribers().incr(1);
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

    // We don't need to read-lock port_map or mcast_fwd unless we actually need them.
    // Locks are acquired lazily on first use and then held for the duration of
    // packet processing. This prevents port removal from completing while any Tx
    // handler holds references (management operations block on the write lock).
    let mut port_map = None;
    let mut mcast_fwd = None;

    while let Some(pkt) = chain.pop_front() {
        xde_mc_tx_one(
            src_dev,
            pkt,
            &mut tx_postbox,
            &mut port_map,
            &mut mcast_fwd,
            &mut hairpin_chain,
        );
    }

    let (local_pkts, [u1_pkts, u2_pkts]) = tx_postbox.deconstruct();

    // Local same-sled delivery (via mac_rx to guest ports).
    if let Some(port_map) = port_map {
        port_map.deliver_all(local_pkts);
    }

    // `port_map` has been moved, making it safe to deliver hairpin
    // packets (which may cause us to re-enter XDE in the same stack).
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
    port_map: &mut Option<KRwLockReadGuard<'a, Arc<DevMap>>>,
    mcast_fwd: &mut Option<KRwLockReadGuard<'a, Arc<McastForwardingTable>>>,
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

    // Extract inner destination IP for potential multicast processing
    let inner_dst_ip = match &meta.inner_l3 {
        Some(ValidL3::Ipv4(v4)) => {
            Some(oxide_vpc::api::IpAddr::from(v4.destination()))
        }
        Some(ValidL3::Ipv6(v6)) => {
            Some(oxide_vpc::api::IpAddr::from(v6.destination()))
        }
        None => None,
    };

    let Ok(non_eth_payl_bytes) =
        u32::try_from((&meta.inner_l3, &meta.inner_ulp).packet_length())
    else {
        opte::engine::dbg!("sum of packet L3/L4 exceeds u32::MAX");
        return;
    };

    let inner_eth_len = meta.inner_eth.packet_length();

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
    // action was taken.
    let res = port.process(Direction::Out, parsed_pkt);

    match res {
        Ok(ProcessResult::Modified(emit_spec)) => {
            // If the outer IPv6 destination is the same as the
            // source, then we need to loop the packet inbound to the
            // guest on this same host.
            let Some((ip6_src, ip6_dst)) = emit_spec.outer_ip6_addrs() else {
                // XXX add SDT probe
                // XXX add stat
                opte::engine::dbg!("no outer IPv6 header, dropping");
                return;
            };

            // EmitSpec applies pushes/pops, but modifications will have occurred
            // by this point. Pull destination MAC to allow us to reuse code
            // between unicast & multicast loopback.
            //
            // Ingot will have asserted that Ethernet came first, and that it was
            // contiguous.
            let Some(ether_dst) = pkt
                .get(..size_of::<MacAddr>())
                .map(|v| MacAddr::from_const(v.try_into().unwrap()))
            else {
                // XXX add SDT probe
                // XXX add stat
                opte::engine::dbg!("couldn't re-read inner MAC, dropping");
                return;
            };

            let Some(vni) = emit_spec.outer_encap_vni() else {
                // XXX add SDT probe
                // XXX add stat
                opte::engine::dbg!("no geneve header, dropping");
                return;
            };

            let Some(tun_meoi) = emit_spec.encap_meoi() else {
                opte::engine::dbg!(
                    "tried to emit packet without encapsulation"
                );
                return;
            };

            let mtu_unrestricted = emit_spec.mtu_unrestricted();
            let l4_hash = emit_spec.l4_hash();
            let mut out_pkt = emit_spec.apply(pkt);
            let new_len = out_pkt.byte_len();

            if ip6_src == ip6_dst {
                // Loopback: same-host delivery
                let key = VniMac::new(vni, ether_dst);
                let devs =
                    port_map.get_or_insert_with(|| src_dev.port_map.read());
                if let Some(dst_dev) = devs.get_by_key(key) {
                    // We have found a matching Port on this host; "loop back"
                    // the packet into the inbound processing path of the
                    // destination Port.
                    guest_loopback(src_dev, dst_dev, key, out_pkt, postbox);
                } else {
                    opte::engine::dbg!(
                        "underlay dest is same as src but the Port was not found \
                         vni = {}, mac = {}",
                        vni.as_u32(),
                        ether_dst
                    );
                }
                return;
            }

            let Ok(encap_len) = u32::try_from(new_len.saturating_sub(old_len))
            else {
                opte::engine::err!(
                    "tried to push encap_len greater than u32::MAX"
                );
                return;
            };

            // Multicast interception: All packets (unicast and multicast) go
            // through normal `port.process()` which applies router/firewall
            // rules and uses M2P for multicast encapsulation. Here, we
            // intercept multicast packets for replication to multiple next hops
            // and local delivery to subscribers.
            //
            // Check if this is a multicast packet by examining the outer IPv6
            // destination. For multicast, OPTE should have set it to an
            // ff0x:: address (via M2P table).
            if ip6_dst.is_multicast() {
                // This is a multicast packet, so we determine the inner
                // destination from the packet contents or use a fallback
                let inner_dst = inner_dst_ip.unwrap_or_else(|| {
                    // Fallback: derive from outer IPv6 multicast address
                    // For IPv4 multicast mapped to IPv6, the last 4 bytes
                    // contain the IPv4 address
                    if ip6_dst.bytes()[0] == 0xff && ip6_dst.bytes()[1] == 0x04
                    {
                        // Admin-scoped IPv6 multicast, likely mapped from IPv4
                        let bytes = ip6_dst.bytes();
                        oxide_vpc::api::IpAddr::Ip4(
                            oxide_vpc::api::Ipv4Addr::from([
                                bytes[12], bytes[13], bytes[14], bytes[15],
                            ]),
                        )
                    } else {
                        // Use the IPv6 multicast address directly
                        oxide_vpc::api::IpAddr::Ip6(ip6_dst)
                    }
                });

                // Acquire locks lazily on first multicast packet.
                // Once acquired, locks are held for the duration of Tx processing.
                let devs =
                    port_map.get_or_insert_with(|| src_dev.port_map.read());
                let fwd_table =
                    mcast_fwd.get_or_insert_with(|| src_dev.mcast_fwd.read());
                handle_mcast_tx(
                    MulticastTxContext {
                        inner_dst,
                        underlay_dst: ip6_dst,
                        vni,
                        out_pkt: &out_pkt,
                        encap_len,
                        inner_eth_len,
                        non_eth_payl_bytes,
                        tun_meoi: &tun_meoi,
                        l4_hash,
                    },
                    src_dev,
                    postbox,
                    devs,
                    fwd_table,
                );
                return;
            }

            // 'MSS boosting' is performed here -- we set a 9k (minus overheads)
            // MSS for compatible TCP traffic. This is a kind of 'pseudo-GRO',
            // sending larger frames internally rather than having the NIC/OS
            // reassemble them. However, guests may reject carried packets if
            // the embedded MSS value / `gso_size` is larger than the agreed-
            // upon MSS for the connection itself.
            //
            // The Oxide VPC reserves a Geneve option to carry this signal.
            let mut flags = offload_req.flags;
            let mss = if mtu_unrestricted {
                if flags.intersects(MblkOffloadFlags::HW_LSO_FLAGS)
                    && let Some(my_mss) =
                        NonZeroU32::try_from(offload_req.mss).ok()
                    && tun_meoi
                        .meoi_flags
                        .contains(MacEtherOffloadFlags::FULL_TUN)
                {
                    // OPTE pushes encap in one contiguous block. We know that the
                    // output format is currently the first geneve option.
                    let mss_idx = usize::from(tun_meoi.meoi_l2hlen)
                        + usize::from(tun_meoi.meoi_l3hlen)
                        + usize::from(tun_meoi.meoi_l4hlen)
                        + Geneve::MINIMUM_LENGTH
                        + GeneveOpt::MINIMUM_LENGTH;

                    if let Some(slot) =
                        out_pkt.get_mut(mss_idx..mss_idx + size_of::<u32>())
                    {
                        let slot =
                            <&mut [u8; size_of::<u32>()]>::try_from(slot)
                                .expect("size proven above");
                        *slot = my_mss.get().to_be_bytes();
                    }
                }

                // Recall that SDU does not include L2 size, hence 'non_eth_payl'
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

            if let Err(e) = out_pkt.fill_parse_info(&tun_meoi, Some(&ulp_meoi))
            {
                opte::engine::err!("failed to set offload info: {}", e);
            }

            // Currently the overlay layer leaves the outer frame
            // destination and source zero'd. Ask IRE for the route
            // associated with the underlay destination. Then ask NCE
            // for the mac associated with the IRE next hop to fill in
            // the outer frame of the packet. Also return the underlay
            // device associated with the next hop
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
            // Hairpin packets are queued for later delivery. If we have a
            // packet chain containing both hairpin and local deliveries
            // (via `guest_loopback`), we defer hairpin delivery until after
            // local delivery completes to avoid potential re-entrancy issues.
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
    m2p: Arc<overlay::Mcast2Phys>,
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
    gateway::setup(&pb, &cfg, vpc_map.clone(), FT_LIMIT_ONE, dhcp_cfg)?;
    router::setup(&pb, &cfg, FT_LIMIT_ONE)?;
    nat::setup(&mut pb, &cfg, nat_ft_limit)?;
    overlay::setup(&pb, &cfg, v2p, m2p, v2b, FT_LIMIT_ONE)?;

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
    let port = Arc::new(pb.create(net, limit, limit)?);
    Ok(port)
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

    // Hold the per-CPU DevMap mutex for the duration of Rx processing.
    // This prevents port removal from completing until no Rx handler holds
    // references. Management operations will block briefly during lock hold,
    // but the critical section is bounded to packet processing time
    // (swap Arc during refresh).
    //
    // Caller threads here (interrupt contexts, poll threads, softring workers,
    // fanout threads) are all bound to a CPU by MAC. We don't worry about this
    // changing for Rx -- each thread stays on its CPU, avoiding contention
    // except during port add/remove.
    let cpu_index = current_cpu().seq_id;
    let devmap = stream.ports_map[cpu_index].devs.lock();
    let mut postbox = Postbox::new();

    while let Some(pkt) = chain.pop_front() {
        if let Some(pkt) =
            xde_rx_one(&stream.stream, pkt, &devmap, &mut postbox)
        {
            count += 1;
            len += pkt.byte_len();
            out_chain.append(pkt);
        }
    }

    devmap.deliver_all(postbox);

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

/// Processes an individual packet received on the underlay device `stream`.
///
/// This function returns any input `pkt` which is not of interest to XDE (e.g.,
/// the packet is not Geneve over v6, or no matching OPTE port could be found).
///
/// `xde_rx_one_direct` largely replicates this function due to lifetime issues
/// around parsing, so changes here may need to be made there too. We could do this
/// with a single function using an `enum` control parameter (e.g.,
/// `DoMcastCheck(&DevMap)`, `DeliverDirect(&XdeDev, VniMac)`) but we'd be
/// really reliant on rustc interpreting these as static choices and inlining
/// accordingly.
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

    let ip6_dst = meta.outer_v6.destination();
    if ip6_dst.is_multicast() {
        // Early exit: if no multicast subscribers exist on this sled, drop immediately
        // to avoid unnecessary packet processing (pullup, parsing, subscription lookups).
        if !devs.has_mcast_subscribers() {
            return None;
        }

        let pullup_len = (
            &meta.outer_eth,
            &meta.outer_v6,
            &meta.outer_udp,
            &meta.outer_encap,
            &meta.inner_eth,
            &meta.inner_l3,
            &meta.inner_ulp,
        )
            .packet_length();
        debug_assert!(
            pullup_len > 0,
            "pullup_len should be non-zero for valid multicast packet"
        );
        let vni = meta.outer_encap.vni();

        // Compute inner Ethernet offset and extract inner destination IP for multicast processing
        let inner_eth_off = (
            &meta.outer_eth,
            &meta.outer_v6,
            &meta.outer_udp,
            &meta.outer_encap,
        )
            .packet_length();
        let inner_dst = match &meta.inner_l3 {
            ValidL3::Ipv4(v4) => oxide_vpc::api::IpAddr::from(v4.destination()),
            ValidL3::Ipv6(v6) => oxide_vpc::api::IpAddr::from(v6.destination()),
        };

        // Drop the parsed packet before calling handle_mcast_rx
        drop(parsed_pkt);

        // Handle multicast packets, delivering to local subscribers only
        // (leaf node)
        handle_mcast_rx(
            MulticastRxContext {
                inner_dst,
                underlay_dst: ip6_dst,
                vni,
                pkt: &pkt,
                pullup_len,
                inner_eth_off,
            },
            stream,
            devs,
            postbox,
        );
        return None;
    }

    let ulp_meoi = match meta.ulp_meoi(old_len) {
        Ok(ulp_meoi) => ulp_meoi,
        Err(e) => {
            opte::engine::dbg!("{}", e);
            return None;
        }
    };

    let non_payl_bytes = u32::from(ulp_meoi.meoi_l2hlen)
        + u32::from(ulp_meoi.meoi_l3hlen)
        + u32::from(ulp_meoi.meoi_l4hlen);

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

    // Large TCP frames include their MSS in-band, as recipients can require
    // this to correctly process frames which have been given split into
    // larger chunks.
    //
    // This will be set to a nonzero value when TSO has been asked of the
    // source packet.
    let is_tcp = matches!(meta.inner_ulp, ValidUlp::Tcp(_));
    let recovered_mss = if is_tcp {
        let mut out = None;
        for opt in WalkOptions::from_raw(&meta.outer_encap) {
            let Ok(opt) = opt else { break };
            if let Some(ValidOxideOption::Mss(el)) = opt.option.known() {
                out = NonZeroU32::new(el.mss());
                break;
            }
        }
        out
    } else {
        None
    };

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
            let pay_len = len
                - usize::try_from(non_payl_bytes)
                    .expect("usize > 32b on x86_64");

            // Due to possible pseudo-GRO, we need to inform mac/viona on how
            // it can split up this packet, if the guest cannot receive it
            // (e.g., no GRO/large frame support).
            // HW_LSO will cause viona to treat this packet as though it were
            // a locally delivered segment making use of LSO.
            if let Some(mss) = recovered_mss
                // This packet could be the last segment of a split frame at
                // which point it could be smaller than the original MSS.
                // Don't re-tag the MSS if so, as guests may be confused and
                // MAC emulation will reject the packet if the guest does not
                // support GRO.
                && pay_len > usize::try_from(mss.get()).expect("usize > 32b on x86_64")
            {
                npkt.request_offload(MblkOffloadFlags::HW_LSO, mss.get());
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

/// Processes an individual packet after multicast replication has taken place.
/// This primarily duplicates `xde_rx_one`.
///
/// Lifetimes (arond Packet<LiteParsed> etc.) will make this difficult to simplify
/// the expression of both this and its original implementation. We could insert
/// the body using macros, but then we really lose a lot (line numbers on crash,
/// subpar rust-analyzer integration)...
#[inline]
fn xde_rx_one_direct(
    stream: &DlsStream,
    dev: &XdeDev,
    port_key: VniMac,
    mut pkt: MsgBlk,
    postbox: &mut Postbox,
) {
    // TODO: it would be great if we could tell Ingot 'here are all the
    // layer lengths/types, please believe that they are correct'. And then
    // to plumb that through `NetworkParser`. I can't say that I *like*
    // doing this reparse here post-replication.
    let parser = VpcParser {};
    let parsed_pkt = Packet::parse_inbound(pkt.iter_mut(), parser)
        .expect("this is a reparse of a known-valid packet");

    let meta = parsed_pkt.meta();
    let old_len = parsed_pkt.len();

    let ulp_meoi = match meta.ulp_meoi(old_len) {
        Ok(ulp_meoi) => ulp_meoi,
        Err(e) => {
            opte::engine::dbg!("{}", e);
            return;
        }
    };

    let non_payl_bytes = u32::from(ulp_meoi.meoi_l2hlen)
        + u32::from(ulp_meoi.meoi_l3hlen)
        + u32::from(ulp_meoi.meoi_l4hlen);

    // Large TCP frames include their MSS in-band, as recipients can require
    // this to correctly process frames which have been given split into
    // larger chunks.
    //
    // This will be set to a nonzero value when TSO has been asked of the
    // source packet.
    let is_tcp = matches!(meta.inner_ulp, ValidUlp::Tcp(_));
    let recovered_mss = if is_tcp {
        let mut out = None;
        for opt in WalkOptions::from_raw(&meta.outer_encap) {
            let Ok(opt) = opt else { break };
            if let Some(ValidOxideOption::Mss(el)) = opt.option.known() {
                out = NonZeroU32::new(el.mss());
                break;
            }
        }
        out
    } else {
        None
    };

    // We are in passthrough mode, skip OPTE processing.
    if dev.passthrough {
        drop(parsed_pkt);
        postbox.post(port_key, pkt);
        return;
    }

    let port = &dev.port;

    let res = port.process(Direction::In, parsed_pkt);

    match res {
        Ok(ProcessResult::Modified(emit_spec)) => {
            let mut npkt = emit_spec.apply(pkt);
            let len = npkt.byte_len();
            let pay_len = len
                - usize::try_from(non_payl_bytes)
                    .expect("usize > 32b on x86_64");

            // Due to possible pseudo-GRO, we need to inform mac/viona on how
            // it can split up this packet, if the guest cannot receive it
            // (e.g., no GRO/large frame support).
            // HW_LSO will cause viona to treat this packet as though it were
            // a locally delivered segment making use of LSO.
            if let Some(mss) = recovered_mss
                // This packet could be the last segment of a split frame at
                // which point it could be smaller than the original MSS.
                // Don't re-tag the MSS if so, as guests may be confused and
                // MAC emulation will reject the packet if the guest does not
                // support GRO.
                && pay_len > usize::try_from(mss.get()).expect("usize > 32b on x86_64")
            {
                npkt.request_offload(MblkOffloadFlags::HW_LSO, mss.get());
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
fn set_m2p_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: SetMcast2PhysReq = env.copy_in_req()?;

    // Validation of admin-local IPv6 (ff04::/16) happens at deserialization
    let underlay = req.underlay;

    // All multicast uses fleet-wide DEFAULT_MULTICAST_VNI (77)
    let vni = Vni::new(DEFAULT_MULTICAST_VNI).unwrap();
    let state = get_xde_state();
    state.m2p.set(req.group, underlay);

    // DTrace: multicast map set
    let (af, group_ptr): (usize, uintptr_t) = match req.group {
        oxide_vpc::api::IpAddr::Ip4(v4) => {
            (AF_INET as usize, AsRef::<[u8]>::as_ref(&v4).as_ptr() as uintptr_t)
        }
        oxide_vpc::api::IpAddr::Ip6(v6) => (
            AF_INET6 as usize,
            AsRef::<[u8]>::as_ref(&v6).as_ptr() as uintptr_t,
        ),
    };
    __dtrace_probe_mcast__map__set(
        af as uintptr_t,
        group_ptr,
        &underlay.addr(),
        vni.as_u32() as uintptr_t,
    );
    Ok(NoResp::default())
}

#[unsafe(no_mangle)]
fn clear_m2p_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: ClearMcast2PhysReq = env.copy_in_req()?;

    // Validation of admin-local IPv6 (ff04::/16) happens at deserialization
    let underlay = req.underlay;

    // All multicast uses fleet-wide DEFAULT_MULTICAST_VNI (77)
    let vni = Vni::new(DEFAULT_MULTICAST_VNI).unwrap();
    let state = get_xde_state();
    state.m2p.remove(&req.group);

    // DTrace: multicast map clear
    let (af, group_ptr): (usize, uintptr_t) = match req.group {
        oxide_vpc::api::IpAddr::Ip4(v4) => {
            (AF_INET as usize, AsRef::<[u8]>::as_ref(&v4).as_ptr() as uintptr_t)
        }
        oxide_vpc::api::IpAddr::Ip6(v6) => (
            AF_INET6 as usize,
            AsRef::<[u8]>::as_ref(&v6).as_ptr() as uintptr_t,
        ),
    };
    __dtrace_probe_mcast__map__clear(
        af as uintptr_t,
        group_ptr,
        &underlay.addr(),
        vni.as_u32() as uintptr_t,
    );
    Ok(NoResp::default())
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
fn set_mcast_forwarding_hdlr(
    env: &mut IoctlEnvelope,
) -> Result<NoResp, OpteError> {
    let req: SetMcastForwardingReq = env.copy_in_req()?;
    let state = get_xde_state();

    // Validation of admin-local IPv6 (ff04::/16) happens at deserialization
    let underlay = req.underlay;

    // Fleet-level multicast: enforce DEFAULT_MULTICAST_VNI for all replication modes.
    // NextHopV6.addr must be unicast (switch address for routing).
    // The packet will be sent to the multicast address (req.underlay).
    for (next_hop, _rep) in &req.next_hops {
        if next_hop.vni.as_u32() != DEFAULT_MULTICAST_VNI {
            return Err(OpteError::System {
                errno: EINVAL,
                msg: format!(
                    "multicast next hop VNI must be DEFAULT_MULTICAST_VNI ({DEFAULT_MULTICAST_VNI}), got: {}",
                    next_hop.vni.as_u32()
                ),
            });
        }

        // NextHopV6.addr must be unicast (the switch endpoint for routing).
        // The actual packet destination is the multicast address (req.underlay).
        if next_hop.addr.is_multicast() {
            return Err(OpteError::System {
                errno: EINVAL,
                msg: format!(
                    "NextHopV6.addr must be unicast (switch address), got multicast: {}",
                    next_hop.addr
                ),
            });
        }
    }

    // Record next hop count before consuming the vector
    let next_hop_count = req.next_hops.len();

    let token = state.management_lock.lock();
    {
        let mut mcast_fwd = token.mcast_fwd.write();

        // Get or create the next hop map for this underlay address
        let next_hop_map =
            mcast_fwd.entry(underlay).or_insert_with(BTreeMap::new);

        // Insert/update next hops: same next hop addr → replace replication mode,
        // different next hop addr → add new entry (like `swadm route add`)
        for (next_hop, rep) in req.next_hops {
            next_hop_map.insert(next_hop, rep);
        }
    }

    // Refresh cached copies in all ports and underlay devices
    {
        let devs = token.devs.write();
        if let Some(underlay) = token.underlay.as_ref() {
            refresh_maps(
                devs,
                underlay,
                &token.mcast_fwd,
                RefreshScope::Multicast,
            );
        }
    }

    // DTrace: forwarding set
    __dtrace_probe_mcast__fwd__set(
        &underlay.addr(),
        next_hop_count as uintptr_t,
        DEFAULT_MULTICAST_VNI as uintptr_t,
    );

    Ok(NoResp::default())
}

#[unsafe(no_mangle)]
fn clear_mcast_forwarding_hdlr(
    env: &mut IoctlEnvelope,
) -> Result<NoResp, OpteError> {
    let req: ClearMcastForwardingReq = env.copy_in_req()?;
    let state = get_xde_state();

    // Validation of admin-local IPv6 (ff04::/16) happens at deserialization
    let underlay = req.underlay;

    let token = state.management_lock.lock();
    {
        let mut mcast_fwd = token.mcast_fwd.write();
        mcast_fwd.remove(&underlay);
    }

    // Refresh cached copies in all ports and underlay devices
    {
        let devs = token.devs.write();
        if let Some(underlay) = token.underlay.as_ref() {
            refresh_maps(
                devs,
                underlay,
                &token.mcast_fwd,
                RefreshScope::Multicast,
            );
        }
    }

    // DTrace: forwarding clear
    __dtrace_probe_mcast__fwd__clear(
        &underlay.addr(),
        DEFAULT_MULTICAST_VNI as uintptr_t,
    );

    Ok(NoResp::default())
}

#[unsafe(no_mangle)]
fn dump_mcast_forwarding_hdlr() -> Result<DumpMcastForwardingResp, OpteError> {
    let state = get_xde_state();

    let token = state.management_lock.lock();
    let mcast_fwd = token.mcast_fwd.read();

    let entries: Vec<McastForwardingEntry> = mcast_fwd
        .iter()
        .map(|(underlay, next_hops)| McastForwardingEntry {
            underlay: *underlay,
            next_hops: next_hops
                .iter()
                .map(|(next_hop, rep)| (*next_hop, *rep))
                .collect(),
        })
        .collect();

    Ok(DumpMcastForwardingResp { entries })
}

fn dump_mcast_subscriptions_hdlr()
-> Result<DumpMcastSubscriptionsResp, OpteError> {
    let state = get_xde_state();
    let token = state.management_lock.lock();
    let devs = token.devs.read();

    let mut entries: alloc::vec::Vec<McastSubscriptionEntry> =
        alloc::vec::Vec::new();
    for (underlay, ports) in devs.dump_mcast_subscriptions().into_iter() {
        entries.push(McastSubscriptionEntry { underlay, ports });
    }

    Ok(DumpMcastSubscriptionsResp { entries })
}

#[unsafe(no_mangle)]
fn mcast_subscribe_hdlr(env: &mut IoctlEnvelope) -> Result<NoResp, OpteError> {
    let req: McastSubscribeReq = env.copy_in_req()?;
    let state = get_xde_state();

    // Update under management lock so we can refresh DevMap views used by Tx/Rx
    let token = state.management_lock.lock();
    {
        let mut devs = token.devs.write();
        // Subscriptions are keyed on the underlay (outer) IPv6 multicast address.
        // If the caller supplied an overlay group, translate it via the M2P table.
        // First, reject non-multicast inputs to preserve DevMap error semantics.
        if !req.group.is_multicast() {
            return Err(OpteError::BadState(format!(
                "IP address {} is not a multicast address",
                req.group
            )));
        }
        let group_key = match req.group {
            oxide_vpc::api::IpAddr::Ip6(ip6) => {
                // If an overlay->underlay mapping exists, use it; otherwise, if the
                // provided address is already an admin-scoped multicast (ff04::/16),
                // accept it as-is. Otherwise, reject.
                if let Some(underlay_group) =
                    state.m2p.get(&oxide_vpc::api::IpAddr::Ip6(ip6))
                {
                    underlay_group
                } else if let Ok(underlay_group) = MulticastUnderlay::new(ip6) {
                    underlay_group
                } else {
                    return Err(OpteError::BadState(
                        "no underlay mapping for IPv6 multicast group".into(),
                    ));
                }
            }
            oxide_vpc::api::IpAddr::Ip4(_v4) => {
                // IPv4 overlay groups must have an M2P mapping; the subscription key
                // is the underlay IPv6 multicast. Without a mapping, reject with
                // a clear message (callers may rely on this distinction).
                if let Some(underlay_group) = state.m2p.get(&req.group) {
                    underlay_group
                } else {
                    return Err(OpteError::BadState(
                        "no underlay mapping for IPv4 multicast group".into(),
                    ));
                }
            }
        };

        devs.mcast_subscribe(&req.port_name, group_key)?;

        // DTrace: subscribe
        let (af, group_ptr): (usize, uintptr_t) = (
            AF_INET6 as usize,
            AsRef::<[u8]>::as_ref(&group_key.addr()).as_ptr() as uintptr_t,
        );
        if let Ok(port_cstr) = CString::new(req.port_name.clone()) {
            __dtrace_probe_mcast__subscribe(
                port_cstr.as_ptr() as uintptr_t,
                af as uintptr_t,
                group_ptr,
                DEFAULT_MULTICAST_VNI as uintptr_t,
            );
        }
        refresh_maps(
            devs,
            token
                .underlay
                .as_ref()
                .expect("underlay must exist while ports exist"),
            &token.mcast_fwd,
            RefreshScope::Ports,
        );
    }

    Ok(NoResp::default())
}

#[unsafe(no_mangle)]
fn mcast_unsubscribe_hdlr(
    env: &mut IoctlEnvelope,
) -> Result<NoResp, OpteError> {
    let req: McastUnsubscribeReq = env.copy_in_req()?;
    let state = get_xde_state();

    // Update under management lock so we can refresh DevMap views used by Tx/Rx
    let token = state.management_lock.lock();
    {
        let mut devs = token.devs.write();

        // Verify the port exists, maintaining consistency with other operations
        // and ensures we're not silently accepting operations on non-existent
        // ports. This check happens before M2P translation to provide clear
        // error semantics.
        if devs.get_by_name(&req.port_name).is_none() {
            return Err(OpteError::PortNotFound(req.port_name.clone()));
        }

        // Reject non-multicast input to preserve API use and match subscribe
        // semantics.
        if !req.group.is_multicast() {
            return Err(OpteError::BadState(format!(
                "IP address {} is not a multicast address",
                req.group
            )));
        }

        // Translate overlay group to underlay IPv6 if M2P mapping exists.
        // For unsubscribe, if no M2P mapping exists, we return success (no-op).
        // This makes unsubscribe idempotent and handles cleanup race conditions
        // where M2P mappings may be removed before unsubscribe is called.
        let Some(group_key) = state.m2p.get(&req.group) else {
            refresh_maps(
                devs,
                token
                    .underlay
                    .as_ref()
                    .expect("underlay must exist while ports exist"),
                &token.mcast_fwd,
                RefreshScope::Multicast,
            );
            return Ok(NoResp::default());
        };

        devs.mcast_unsubscribe(&req.port_name, group_key)?;
        // DTrace: unsubscribe
        let (af, group_ptr): (usize, uintptr_t) = (
            AF_INET6 as usize,
            AsRef::<[u8]>::as_ref(&group_key.addr()).as_ptr() as uintptr_t,
        );
        if let Ok(port_cstr) = CString::new(req.port_name.clone()) {
            __dtrace_probe_mcast__unsubscribe(
                port_cstr.as_ptr() as uintptr_t,
                af as uintptr_t,
                group_ptr,
                DEFAULT_MULTICAST_VNI as uintptr_t,
            );
        }
        refresh_maps(
            devs,
            token
                .underlay
                .as_ref()
                .expect("underlay must exist while ports exist"),
            &token.mcast_fwd,
            RefreshScope::Ports,
        );
    }

    Ok(NoResp::default())
}

#[unsafe(no_mangle)]
fn mcast_unsubscribe_all_hdlr(
    env: &mut IoctlEnvelope,
) -> Result<NoResp, OpteError> {
    let req: McastUnsubscribeAllReq = env.copy_in_req()?;
    let state = get_xde_state();

    // Update under management lock so we can refresh DevMap views used by Tx/Rx
    let token = state.management_lock.lock();
    {
        let mut devs = token.devs.write();

        // Reject non-multicast input
        if !req.group.is_multicast() {
            return Err(OpteError::BadState(format!(
                "IP address {} is not a multicast address",
                req.group
            )));
        }

        // Translate overlay group to underlay IPv6 if M2P mapping exists.
        // For unsubscribe-all, if no M2P mapping exists, we return success (no-op).
        let Some(group_key) = state.m2p.get(&req.group) else {
            refresh_maps(
                devs,
                token
                    .underlay
                    .as_ref()
                    .expect("underlay must exist while ports exist"),
                &token.mcast_fwd,
                RefreshScope::Multicast,
            );
            return Ok(NoResp::default());
        };

        devs.mcast_unsubscribe_all(group_key);
        // DTrace: unsubscribe-all
        let (af, group_ptr): (usize, uintptr_t) = (
            AF_INET6 as usize,
            AsRef::<[u8]>::as_ref(&group_key.addr()).as_ptr() as uintptr_t,
        );
        __dtrace_probe_mcast__unsubscribe__all(
            af as uintptr_t,
            group_ptr,
            DEFAULT_MULTICAST_VNI as uintptr_t,
        );
        refresh_maps(
            devs,
            token
                .underlay
                .as_ref()
                .expect("underlay must exist while ports exist"),
            &token.mcast_fwd,
            RefreshScope::Ports,
        );
    }

    Ok(NoResp::default())
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

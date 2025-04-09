// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Safe abstractions for the mac client API.
//!
//! NOTE: This module is re-exporting all of the sys definitions at
//! the moment out of laziness.
pub mod sys;

use crate::dls::LinkId;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use bitflags::bitflags;
use core::ffi::CStr;
use core::fmt;
use core::mem;
use core::mem::MaybeUninit;
use core::ops::RangeInclusive;
use core::ptr;
use illumos_sys_hdrs::*;
use ingot::ip::IpProtocol;
use opte::ddi::mblk::AsMblk;
use opte::ddi::mblk::MsgBlk;
use opte::ddi::mblk::MsgBlkChain;
use opte::engine::ether::EtherAddr;
pub use sys::*;

/// Errors while opening a MAC handle.
#[derive(Debug)]
pub enum MacOpenError<'a> {
    InvalidLinkName(&'a str),
    OpenFailed(&'a str, i32),
}

impl fmt::Display for MacOpenError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MacOpenError::InvalidLinkName(link) => {
                write!(f, "invalid link name: {link}")
            }
            MacOpenError::OpenFailed(link, err) => {
                write!(f, "mac_open_by_linkname failed for {link}: {err}")
            }
        }
    }
}

/// Safe wrapper around a `mac_handle_t`.
#[derive(Debug)]
pub struct MacHandle(*mut mac_handle);

impl MacHandle {
    /// Grab a handle to the mac provider for the given link.
    pub fn open_by_link_name(link: &str) -> Result<Self, MacOpenError> {
        let name = CString::new(link)
            .map_err(|_| MacOpenError::InvalidLinkName(link))?;

        let mut mh = ptr::null_mut();
        let ret = unsafe { mac_open_by_linkname(name.as_ptr(), &mut mh) };
        if ret != 0 {
            return Err(MacOpenError::OpenFailed(link, ret));
        }

        Ok(Self(mh))
    }

    /// Get the primary MAC address associated with this device.
    pub fn get_mac_addr(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        unsafe {
            mac_unicast_primary_get(self.0, &mut mac);
        }
        mac
    }

    /// Get the range of valid MTUs supported by this device.
    pub fn get_valid_mtus(&self) -> RangeInclusive<u32> {
        let (mut min, mut max) = (0, 0);

        unsafe {
            mac_sdu_get(self.0, &raw mut min, &raw mut max);
        }

        min..=max
    }

    /// Query this device's supported checksum offload capabilities.
    pub fn get_cso_capabs(&self) -> mac_capab_cso_t {
        let mut cso = mac_capab_cso_t::default();
        unsafe {
            mac_capab_get(
                self.0,
                mac_capab_t::MAC_CAPAB_HCKSUM,
                (&raw mut cso) as *mut _,
            );
        }
        cso
    }

    /// Query this device's supported large send offload capabilities.
    pub fn get_lso_capabs(&self) -> mac_capab_lso_t {
        let mut lso = MaybeUninit::<mac_capab_lso_t>::zeroed();
        unsafe {
            mac_capab_get(
                self.0,
                mac_capab_t::MAC_CAPAB_LSO,
                (&raw mut lso) as *mut _,
            );

            lso.assume_init()
        }
    }
}

impl Drop for MacHandle {
    fn drop(&mut self) {
        // Safety: We know that a `MacHandle` can only exist if a mac
        // handle was successfully obtained.
        unsafe { mac_close(self.0) };
    }
}

/// Safe wrapper around a `mac_client_handle_t`.
#[derive(Debug)]
pub struct MacClientHandle {
    /// Flags to pass to `mac_client_close()`.
    close_flags: u16,

    /// The client handle.
    mch: *mut mac_client_handle,

    /// Reference to the underlying MAC handle for this client.
    _mh: Arc<MacHandle>,
}

bitflags! {
    pub struct MacTxFlags: u16 {
        const NO_ENQUEUE = MAC_TX_NO_ENQUEUE;
        const NO_HOLD = MAC_TX_NO_HOLD;
    }
}

bitflags! {
    // See uts/common/sys/mac_client.h.
    //
    // For now we only include flags currently used by consumers.
    pub struct MacOpenFlags: u16 {
        const NONE = 0;
        const IS_VNIC = MAC_OPEN_FLAGS_IS_VNIC;
        const EXCLUSIVE = MAC_OPEN_FLAGS_EXCLUSIVE;
        const IS_AGGR_PORT = MAC_OPEN_FLAGS_IS_AGGR_PORT;
        const SHARES_DESIRED = MAC_OPEN_FLAGS_SHARES_DESIRED;
        const USE_DATALINK_NAME = MAC_OPEN_FLAGS_USE_DATALINK_NAME;
        const MULTI_PRIMARY = MAC_OPEN_FLAGS_MULTI_PRIMARY;
        const NO_UNICAST_ADDR = MAC_OPEN_FLAGS_NO_UNICAST_ADDR;
    }
}

impl MacClientHandle {
    /// Open a new client for the given MAC, `mh`.
    pub fn open(
        mh: &Arc<MacHandle>,
        name: Option<&str>,
        open_flags: MacOpenFlags,
        close_flags: u16,
    ) -> Result<Self, c_int> {
        let mut raw_oflags = open_flags.bits();
        let mut mch = ptr::null_mut::<c_void> as *mut mac_client_handle;
        let ret = match name {
            Some(name_str) => {
                // It's imperative to declare name_cstr here and not
                // call as_ptr(); otherwise the CString value is
                // dropped before mac_client_open() and we are left
                // with a pointer to freed memory.
                let name_cstr = CString::new(name_str).unwrap();
                unsafe {
                    mac_client_open(
                        mh.0,
                        &mut mch,
                        name_cstr.as_ptr(),
                        raw_oflags,
                    )
                }
            }

            None => {
                let name_cstr = ptr::null_mut();
                raw_oflags |= MAC_OPEN_FLAGS_USE_DATALINK_NAME;
                unsafe {
                    mac_client_open(mh.0, &mut mch, name_cstr, raw_oflags)
                }
            }
        };

        if ret != 0 {
            return Err(ret);
        }

        Ok(Self { close_flags, mch, _mh: mh.clone() })
    }

    /// Get the name of the client.
    pub fn name(&self) -> String {
        unsafe {
            CStr::from_ptr(mac_client_name(self.mch))
                .to_str()
                .unwrap()
                .to_string()
        }
    }

    pub fn rx_barrier(&self) {
        unsafe { mac_rx_barrier(self.mch) };
    }

    /// Clear the Rx callback handler; resetting it to the default.
    ///
    /// Future packets destined for this client are dropped by mac.
    pub fn clear_rx(&self) {
        unsafe { mac_rx_clear(self.mch) };
    }

    /// Calls `mac_unicast_add` on the underlying system.
    pub fn add_unicast(
        self: &Arc<Self>,
        mac: EtherAddr,
    ) -> Result<MacUnicastHandle, c_int> {
        let mut diag = mac_diag::MAC_DIAG_NONE;
        let mut ether = mac.to_bytes();
        let mut muh = ptr::null_mut();
        unsafe {
            match mac_unicast_add(
                self.mch,
                ether.as_mut_ptr(),
                0,
                // MAC_UNICAST_PRIMARY | MAC_UNICAST_NODUPCHECK,
                &mut muh,
                0,
                &mut diag,
            ) {
                0 => Ok(MacUnicastHandle { muh, mch: self.clone() }),
                err => Err(err),
            }
        }
    }

    /// Send the [`Packet`] on this client.
    ///
    /// If the packet cannot be sent, return it. If you want to drop
    /// the packet when no descriptors are available, then use
    /// [`MacClient::tx_drop_on_no_desc()`].
    ///
    /// XXX The underlying mac_tx() function accepts a packet chain,
    /// but for now we pass only a single packet at a time.
    pub fn tx(
        &self,
        pkt: impl AsMblk,
        hint: uintptr_t,
        flags: MacTxFlags,
    ) -> Option<MsgBlk> {
        // We must unwrap the raw `mblk_t` out of the `pkt` here,
        // otherwise the mblk_t would be dropped at the end of this
        // function along with `pkt`.
        let mut ret_mp = ptr::null_mut();
        let mblk = pkt.unwrap_mblk()?;
        unsafe {
            mac_tx(self.mch, mblk.as_ptr(), hint, flags.bits(), &mut ret_mp)
        };
        if !ret_mp.is_null() {
            // Unwrap: We know the ret_mp is valid because we gave
            // mac_tx() a valid mp_chain; and mac_tx() will give us
            // either that exact pointer back (via ret_mp) or the
            // portion of the packet chain it could not queue.
            //
            // XXX Technically we are still only passing single
            // packets, but eventually we will pass packet chains and
            // the sentence above will hold.
            Some(unsafe { MsgBlk::wrap_mblk(ret_mp).unwrap() })
        } else {
            None
        }
    }

    /// Send the [`Packet`] on this client, dropping if there is no
    /// descriptor available
    ///
    /// This function always consumes the [`Packet`].
    ///
    /// XXX The underlying mac_tx() function accepts a packet chain,
    /// but for now we pass only a single packet at a time.
    pub fn tx_drop_on_no_desc(
        &self,
        pkt: impl AsMblk,
        hint: uintptr_t,
        flags: MacTxFlags,
    ) {
        // We must unwrap the raw `mblk_t` out of the `pkt` here,
        // otherwise the mblk_t would be dropped at the end of this
        // function along with `pkt`.
        let mut raw_flags = flags.bits();
        raw_flags |= MAC_DROP_ON_NO_DESC;
        let mut ret_mp = ptr::null_mut();

        let Some(mblk) = pkt.unwrap_mblk() else {
            return;
        };

        unsafe {
            mac_tx(self.mch, mblk.as_ptr(), hint, raw_flags, &mut ret_mp)
        };
        debug_assert_eq!(ret_mp, ptr::null_mut());
    }

    /// TODO: document what's happening here.
    /// TODO: error conditions?
    pub fn rx_set(self: &Arc<Self>, promisc_fn: mac_rx_fn) {
        let mch = self.clone();
        let arg = Arc::as_ptr(&mch) as *mut c_void;
        unsafe { mac_rx_set(self.mch, Some(promisc_fn), arg) }
        // unsafe { mac_rx_set(self.mch, None, arg) }
    }

    pub fn set_flow_cb(self: &Arc<Self>, promisc_fn: mac_rx_fn) {
        let mch = self.clone();
        let arg = Arc::as_ptr(&mch) as *mut c_void;
        unsafe { mac_client_set_flow_cb(self.mch, Some(promisc_fn), arg) }
        // unsafe { mac_client_set_flow_cb(self.mch, None, arg) }
    }

    /// TODO: document what's happening here.
    /// TODO: error conditions?
    pub fn rx_bypass_disable(&self) {
        unsafe { mac_rx_bypass_disable(self.mch) }
    }

    /// TODO: document what's happening here.
    /// TODO: error conditions?
    pub fn rx_bypass_enable(&self) {
        unsafe { mac_rx_bypass_enable(self.mch) }
    }
}

impl Drop for MacClientHandle {
    fn drop(&mut self) {
        // Safety: We know that a `MacClientHandle` can only exist if a mac
        // client handle was successfully obtained, and thus mch is
        // valid.
        unsafe { mac_client_close(self.mch, self.close_flags) };
    }
}

/// Structs which are (or contain) a usable MAC client.
///
/// Currently, this is only used to enable promiscuous handler
/// registration.
pub trait MacClient {
    fn mac_client_handle(&self) -> Result<*mut mac_client_handle, c_int>;
}

impl MacClient for MacClientHandle {
    fn mac_client_handle(&self) -> Result<*mut mac_client_handle, c_int> {
        Ok(self.mch)
    }
}

/// Safe wrapper around a `mac_promisc_handle_t`.
#[derive(Debug)]
pub struct MacPromiscHandle<P> {
    /// The underlying `mac_promisc_handle_t`.
    mph: *mut mac_promisc_handle,

    /// The parent used to create this promiscuous callback.
    parent: *const P,
}

impl<P: MacClient> MacPromiscHandle<P> {
    /// Register a promiscuous callback to receive packets on the underlying MAC.
    pub fn new(
        parent: Arc<P>,
        ptype: mac_client_promisc_type_t,
        promisc_fn: mac_rx_fn,
        flags: u16,
    ) -> Result<MacPromiscHandle<P>, c_int> {
        let mut mph = ptr::null_mut();
        let mch = parent.mac_client_handle()?;
        let parent = Arc::into_raw(parent);
        let arg = parent as *mut c_void;

        // SAFETY: `MacPromiscHandle` keeps a reference to this `P`
        // until it is removed and so we can safely access it from the
        // callback via the `arg` pointer.
        let ret = unsafe {
            mac_promisc_add(mch, ptype, promisc_fn, arg, &mut mph, flags)
        };

        if ret == 0 { Ok(Self { mph, parent }) } else { Err(ret) }
    }
}

impl<P> Drop for MacPromiscHandle<P> {
    fn drop(&mut self) {
        // Safety: We know that a `MacPromiscHandle` can only exist if a
        // mac promisc handle was successfully obtained, and thus `mph`
        // is valid.
        unsafe {
            mac_promisc_remove(self.mph);
            Arc::from_raw(self.parent); // dropped immediately
        };
    }
}

/// Safe wrapper around a `mac_unicast_handle_t`.
#[derive(Debug)]
pub struct MacUnicastHandle {
    /// The underlying `mac_unicast_handle_t`.
    muh: *mut mac_unicast_handle,

    /// The `MacClientHandle` used to create this unicast callback.
    mch: Arc<MacClientHandle>,
}

impl Drop for MacUnicastHandle {
    fn drop(&mut self) {
        // Safety: We know that a `MacUnicastHandle` can only exist if a
        // mac unicast handle was successfully obtained, and thus `muh`
        // is valid.
        unsafe { mac_unicast_remove(self.mch.mch, self.muh) };
    }
}

/// Safe wrapper around a `mac_perim_handle_t`.
pub struct MacPerimeterHandle {
    mph: mac_perim_handle,
    link: LinkId,
}

impl MacPerimeterHandle {
    /// Attempt to acquire the MAC perimeter for a given link.
    pub fn from_linkid(link: LinkId) -> Result<Self, c_int> {
        let mut mph = 0;
        let res = unsafe { mac_perim_enter_by_linkid(link.into(), &mut mph) };
        if res == 0 { Ok(Self { mph, link }) } else { Err(res) }
    }

    /// Returns the ID of the link whose MAC perimeter is held.
    pub fn link_id(&self) -> LinkId {
        self.link
    }
}

impl Drop for MacPerimeterHandle {
    fn drop(&mut self) {
        unsafe {
            mac_perim_exit(self.mph);
        }
    }
}

bitflags! {
/// Flagset for requesting emulation on any packets marked
/// with the given offloads.
///
/// Derived from `mac_emul_t` (mac.h).
pub struct MacEmul: u32 {
    /// Calculate the L3/L4 checksums.
    const HWCKSUM_EMUL = MAC_HWCKSUM_EMUL;
    /// Calculate the IPv4 checksum, ignoring L4.
    const IPCKSUM_EMUL = MAC_IPCKSUM_EMUL;
    /// Segment TCP packets into MSS-sized chunks.
    const LSO_EMUL = MAC_LSO_EMUL;
}
}

/// Emulates various offloads (checksum, LSO) for packets on loopback paths.
///
/// Specific offloads within `flags` must be requested using
/// [`MsgBlk::request_offload`].
pub fn mac_hw_emul(msg: impl AsMblk, flags: MacEmul) -> Option<MsgBlkChain> {
    let mut chain = msg.unwrap_mblk()?.as_ptr();
    unsafe {
        sys::mac_hw_emul(
            &raw mut chain,
            ptr::null_mut(),
            ptr::null_mut(),
            flags.bits(),
        );
    }

    (!chain.is_null()).then(|| unsafe { MsgBlkChain::new(chain).unwrap() })
}

#[derive(Copy, Clone, Debug)]
pub struct OffloadInfo {
    pub cso_state: mac_capab_cso_t,
    pub lso_state: mac_capab_lso_t,
    pub mtu: u32,
}

impl OffloadInfo {
    /// Forwards the underlay's tunnel checksum offload capabilities into
    /// standard capabilities.
    pub fn upstream_csum(&self) -> mac_capab_cso_t {
        let base_capabs = self.cso_state.cso_flags;
        let mut out = mac_capab_cso_t::default();

        if base_capabs.contains(ChecksumOffloadCapabs::TUNNEL_VALID)
            && self.cso_state.cso_tunnel.ct_types.contains(TunnelType::GENEVE)
        {
            let tsco_flags = self.cso_state.cso_tunnel.ct_flags;
            if tsco_flags.contains(TunnelCsoFlags::INNER_IPHDR) {
                out.cso_flags |= ChecksumOffloadCapabs::INET_HDRCKSUM;
            }
            if tsco_flags.contains(
                TunnelCsoFlags::INNER_TCP_PARTIAL
                    | TunnelCsoFlags::INNER_UDP_PARTIAL,
            ) {
                out.cso_flags |= ChecksumOffloadCapabs::INET_PARTIAL;
            }
            if tsco_flags.contains(
                TunnelCsoFlags::INNER_TCP_FULL | TunnelCsoFlags::INNER_UDP_FULL,
            ) {
                out.cso_flags |= ChecksumOffloadCapabs::INET_FULL_V4
                    | ChecksumOffloadCapabs::INET_FULL_V6;
            }
        }

        out
    }

    /// Forwards the underlay's tunnel TCP LSO capabilities into
    /// standard LSO capabilities.
    pub fn upstream_lso(&self) -> mac_capab_lso_t {
        let mut out = mac_capab_lso_t::default();

        if self.lso_state.lso_flags.contains(TcpLsoFlags::TUNNEL_TCP)
            && self
                .lso_state
                .lso_tunnel_tcp
                .tun_types
                .contains(TunnelType::GENEVE)
        {
            out.lso_flags |= TcpLsoFlags::BASIC_IPV4 | TcpLsoFlags::BASIC_IPV6;
            out.lso_basic_tcp_ipv4 = lso_basic_tcp_ipv4_t {
                lso_max: self.lso_state.lso_tunnel_tcp.tun_pay_max,
            };
            out.lso_basic_tcp_ipv6 = lso_basic_tcp_ipv6_t {
                lso_max: self.lso_state.lso_tunnel_tcp.tun_pay_max,
            };
        }

        out
    }

    /// Return the set of capabilities and MTUs compatible across one or more
    /// underlay devices.
    pub fn mutual_capabs(&self, other: &Self) -> Self {
        Self {
            cso_state: mac_capab_cso_t {
                cso_flags: self.cso_state.cso_flags & other.cso_state.cso_flags,
                cso_tunnel: cso_tunnel_t {
                    ct_flags: self.cso_state.cso_tunnel.ct_flags
                        & other.cso_state.cso_tunnel.ct_flags,
                    ct_encap_max: self
                        .cso_state
                        .cso_tunnel
                        .ct_encap_max
                        .min(other.cso_state.cso_tunnel.ct_encap_max),
                    ct_types: self.cso_state.cso_tunnel.ct_types
                        & other.cso_state.cso_tunnel.ct_types,
                },
            },
            lso_state: mac_capab_lso_t {
                lso_flags: self.lso_state.lso_flags & other.lso_state.lso_flags,
                lso_basic_tcp_ipv4: lso_basic_tcp_ipv4_t {
                    lso_max: self
                        .lso_state
                        .lso_basic_tcp_ipv4
                        .lso_max
                        .min(other.lso_state.lso_basic_tcp_ipv4.lso_max),
                },
                lso_basic_tcp_ipv6: lso_basic_tcp_ipv6_t {
                    lso_max: self
                        .lso_state
                        .lso_basic_tcp_ipv6
                        .lso_max
                        .min(other.lso_state.lso_basic_tcp_ipv6.lso_max),
                },
                lso_tunnel_tcp: lso_tunnel_tcp_t {
                    tun_pay_max: self
                        .lso_state
                        .lso_tunnel_tcp
                        .tun_pay_max
                        .min(other.lso_state.lso_tunnel_tcp.tun_pay_max),
                    tun_encap_max: self
                        .lso_state
                        .lso_tunnel_tcp
                        .tun_encap_max
                        .min(other.lso_state.lso_tunnel_tcp.tun_encap_max),
                    tun_flags: self.lso_state.lso_tunnel_tcp.tun_flags
                        & other.lso_state.lso_tunnel_tcp.tun_flags,
                    tun_types: self.lso_state.lso_tunnel_tcp.tun_types
                        & other.lso_state.lso_tunnel_tcp.tun_types,
                    tun_pad: [0; 2],
                },
            },
            mtu: self.mtu.min(other.mtu),
        }
    }
}

#[derive(Clone, Default)]
pub struct MacFlowDesc {
    mask: flow_mask_t,
    ip_ver: Option<u8>,
    proto: Option<IpProtocol>,
    local_port: Option<u16>,
}

// TODO At the moment the flow system only allows six different
// combinations of attributes:
//
//   local_ip=address[/prefixlen]
//   remote_ip=address[/prefixlen]
//   transport={tcp|udp|sctp|icmp|icmpv6}
//   transport={tcp|udp|sctp},local_port=port
//   transport={tcp|udp|sctp},remote_port=port
//   dsfield=val[:dsfield_mask]
//
// Update this type to enforce the above.
//
// For now my best bet is to use
// transport={tcp|udp|sctp},local_port=port to classify on Geneve
// packets.
impl MacFlowDesc {
    pub fn new() -> Self {
        Default::default()
    }

    /// TODO create an IpVersion type to avoid invalid descriptors.
    pub fn set_ipver(&mut self, ver: u8) -> &mut Self {
        self.mask |= FLOW_IP_VERSION;
        self.ip_ver = Some(ver);
        self
    }

    pub fn set_proto(&mut self, proto: IpProtocol) -> &mut Self {
        self.mask |= FLOW_IP_PROTOCOL;
        self.proto = Some(proto);
        self
    }

    pub fn set_local_port(&mut self, port: u16) -> &mut Self {
        self.mask |= FLOW_ULP_PORT_LOCAL;
        self.local_port = Some(port);
        self
    }

    pub fn to_desc(&self) -> flow_desc_t {
        flow_desc_t::from(self.clone())
    }

    pub fn new_flow<'a, P>(
        &'a self,
        flow_name: &'a str,
        link_id: LinkId,
    ) -> Result<MacFlow<P>, FlowCreateError<'a>> {
        let name = CString::new(flow_name)
            .map_err(|_| FlowCreateError::InvalidFlowName(flow_name))?;
        let desc = self.to_desc();

        match unsafe {
            mac_link_flow_add(
                link_id.into(),
                name.as_ptr(),
                &desc,
                &MAC_RESOURCE_PROPS_DEF,
            )
        } {
            0 => {}
            err => return Err(FlowCreateError::CreateFailed(flow_name, err)),
        }

        let mut flent = ptr::null_mut();
        match unsafe { mac_flow_lookup_byname(name.as_ptr(), &mut flent) } {
            0 => Ok(MacFlow { name, flent, parent: None }),
            err => Err(FlowCreateError::CreateFailed(flow_name, err)),
        }
    }
}

impl From<MacFlowDesc> for flow_desc_t {
    fn from(mf: MacFlowDesc) -> Self {
        let no_addr = IP_NO_ADDR;
        let fd_ipversion = mf.ip_ver.unwrap_or(0);

        // The mac flow subsystem uses 0 as sentinel to indicate no
        // filtering on protocol.
        let fd_protocol = match mf.proto {
            Some(p) => p.0,
            None => 0,
        };

        // Apparently mac flow wants this in network order.
        let fd_local_port = mf.local_port.unwrap_or(0).to_be();

        Self {
            // The mask controls options like priority and bandwidth,
            // which we are not using at the moment.
            fd_mask: mf.mask,
            fd_mac_len: 0,
            fd_dst_mac: [0u8; MAXMACADDR],
            fd_src_mac: [0u8; MAXMACADDR],
            fd_vid: 0,
            // XXX Typically I would saw the SAP is the EtherType
            // (when talking about Ethernet, but this stuff always
            // confuses me. This doesn't seem to be used to filter
            // anything.
            fd_sap: 0,
            fd_ipversion,
            fd_protocol,
            fd_local_addr: no_addr,
            fd_local_netmask: no_addr,
            fd_remote_addr: no_addr,
            fd_remote_netmask: no_addr,
            fd_local_port,
            fd_remote_port: 0,
            fd_dsfield: 0,
            fd_dsfield_mask: 0,
        }
    }
}

/// Errors while opening a MAC handle.
#[derive(Debug)]
pub enum FlowCreateError<'a> {
    InvalidFlowName(&'a str),
    CreateFailed(&'a str, i32),
    LookupFailed(&'a str, i32),
}

impl fmt::Display for FlowCreateError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowCreateError::InvalidFlowName(flow) => {
                write!(f, "invalid flow name: {flow}")
            }
            FlowCreateError::CreateFailed(flow, err) => {
                write!(f, "mac_link_flow_add failed for {flow}: {err}")
            }
            FlowCreateError::LookupFailed(flow, err) => {
                write!(f, "mac_flow_lookup_byname failed for {flow}: {err}")
            }
        }
    }
}

/// Resource handle for a created Mac flow.
#[derive(Debug)]
pub struct MacFlow<P> {
    name: CString,
    flent: *mut flow_entry_t,
    parent: Option<*const P>,
}

impl<P> MacFlow<P> {
    /// Forcibly wrench this flow from the clutches of DLS.
    pub fn set_flow_cb(&mut self, new_fn: mac_rx_fn, parent: Arc<P>) {
        let parent = Arc::into_raw(parent);
        let arg = parent as *mut c_void;

        unsafe {
            crate::warn!(
                "Some potential offsets {:x} {:x} {:x} {:x} {:x} {:x}",
                mem::offset_of!(flow_entry_t, fe_next),
                mem::offset_of!(flow_entry_t, fe_link_id),
                mem::offset_of!(flow_entry_t, fe_resource_props),
                mem::offset_of!(flow_entry_t, fe_effective_props),
                mem::offset_of!(flow_entry_t, fe_lock),
                mem::offset_of!(flow_entry_t, fe_rx_srs)
            );

            // flow_cb_pre_srs(self.flent, new_fn);
            flow_cb_post_srs(self.flent, new_fn, arg);
        }
        self.parent = Some(parent);
    }
}

/// Insert a flow callback which replaces `mac_rx_srs_subflow_process`.
#[unsafe(no_mangle)]
pub unsafe fn flow_cb_pre_srs(flent: *mut flow_entry_t, new_fn: mac_rx_fn) {
    // TODO: locks, negative handling, ...
    unsafe {
        (*flent).fe_cb_fn = new_fn;
    }
}

/// Insert a flow callback accessed via `mac_rx_srs_subflow_process`.
///
/// This will usually replace `mac_rx_deliver`, which will call into the mac_rx
/// callback on the *parent device* (i.e., i_dls_link_rx).
#[unsafe(no_mangle)]
pub unsafe fn flow_cb_post_srs(
    flent: *mut flow_entry_t,
    new_fn: mac_rx_fn,
    arg: *mut c_void,
) {
    // TODO: locks, negative handling, ...
    unsafe {
        let n_srs = (*flent).fe_rx_srs_cnt;
        for srs in (*flent).fe_rx_srs.iter().take(n_srs as usize) {
            mutex_enter(&mut (**srs).srs_lock);
            (**srs).srs_rx.sr_func = new_fn;
            (**srs).srs_rx.sr_arg1 = arg;
            mutex_exit(&mut (**srs).srs_lock);
        }
    }
}

unsafe fn flow_user_refrele(flent: *mut flow_entry_t) {
    unsafe {
        // TODO: use the existing KMutex code...
        mutex_enter(&mut (*flent).fe_lock);
        // ASSERT((flent)->fe_user_refcnt != 0);       \
        (*flent).fe_user_refcnt -= 1;
        if (*flent).fe_user_refcnt == 0 && (*flent).fe_flags & FE_WAITER != 0 {
            crate::ip::cv_signal((&mut (*flent).fe_cv) as *mut _);
        }

        mutex_exit(&mut (*flent).fe_lock);
    }
}

impl<P> Drop for MacFlow<P> {
    fn drop(&mut self) {
        unsafe {
            // TODO: need to reimplement FLOW_USER_REFRELE in here...
            flow_user_refrele(self.flent);
            mac_link_flow_remove(self.name.as_ptr());
            if let Some(parent) = self.parent {
                Arc::from_raw(parent); // dropped immediately
            }
        }
    }
}

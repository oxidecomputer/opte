// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Safe abstractions for the mac client API.
//!
//! NOTE: This module is re-exporting all of the sys definitions at
//! the moment out of laziness.
use crate::ip::datalink_id_t;

pub use super::mac_sys::*;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use bitflags::bitflags;
use core::ffi::CStr;
use core::fmt;
use core::ptr;
use illumos_sys_hdrs::*;
use opte::engine::ether::EtherAddr;
use opte::engine::packet::Initialized;
use opte::engine::packet::Packet;
use opte::engine::packet::PacketState;

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

    pub fn get_mac_addr(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        unsafe {
            mac_unicast_primary_get(self.0, &mut mac);
        }
        mac
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
                &mut muh,
                0,
                &mut diag,
            ) {
                0 => Ok(MacUnicastHandle { muh, mch: self.clone() }),
                err => Err(err),
            }
        }
    }

    /// Register promiscuous callback to receive packets on the underlying MAC.
    pub fn add_promisc(
        self: &Arc<Self>,
        ptype: mac_client_promisc_type_t,
        promisc_fn: mac_rx_fn,
        flags: u16,
    ) -> Result<MacPromiscHandle, c_int> {
        let mut mph = ptr::null_mut();

        // `MacPromiscHandle` keeps a reference to this `MacClientHandle`
        // until it is removed and so we can safely access it from the
        // callback via the `arg` pointer.
        let mch = self.clone();
        let arg = Arc::as_ptr(&mch) as *mut c_void;
        let ret = unsafe {
            mac_promisc_add(self.mch, ptype, promisc_fn, arg, &mut mph, flags)
        };

        if ret == 0 {
            Ok(MacPromiscHandle { mph, _mch: mch })
        } else {
            Err(ret)
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
        pkt: Packet<impl PacketState>,
        hint: uintptr_t,
        flags: MacTxFlags,
    ) -> Option<Packet<Initialized>> {
        // We must unwrap the raw `mblk_t` out of the `pkt` here,
        // otherwise the mblk_t would be dropped at the end of this
        // function along with `pkt`.
        let mut ret_mp = ptr::null_mut();
        unsafe {
            mac_tx(self.mch, pkt.unwrap_mblk(), hint, flags.bits(), &mut ret_mp)
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
            Some(unsafe { Packet::wrap_mblk(ret_mp).unwrap() })
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
        pkt: Packet<impl PacketState>,
        hint: uintptr_t,
        flags: MacTxFlags,
    ) {
        // We must unwrap the raw `mblk_t` out of the `pkt` here,
        // otherwise the mblk_t would be dropped at the end of this
        // function along with `pkt`.
        let mut raw_flags = flags.bits();
        raw_flags |= MAC_DROP_ON_NO_DESC;
        let mut ret_mp = ptr::null_mut();
        unsafe {
            mac_tx(self.mch, pkt.unwrap_mblk(), hint, raw_flags, &mut ret_mp)
        };
        debug_assert_eq!(ret_mp, ptr::null_mut());
    }

    /// TODO: document what's happening here.
    /// TODO: error conditions?
    pub fn rx_set(&self, promisc_fn: mac_rx_fn) {
        unsafe { mac_rx_set(self.mch, promisc_fn, ptr::null_mut()) }
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

/// Safe wrapper around a `mac_promisc_handle_t`.
#[derive(Debug)]
pub struct MacPromiscHandle {
    /// The underlying `mac_promisc_handle_t`.
    mph: *mut mac_promisc_handle,

    /// The `MacClientHandle` used to create this promiscuous callback.
    _mch: Arc<MacClientHandle>,
}

impl Drop for MacPromiscHandle {
    fn drop(&mut self) {
        // Safety: We know that a `MacPromiscHandle` can only exist if a
        // mac promisc handle was successfully obtained, and thus `mph`
        // is valid.
        unsafe { mac_promisc_remove(self.mph) };
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

// TODO Move this somewhere else?
#[derive(Clone, Default)]
pub struct MacFlowDesc {
    mask: flow_mask_t,
    ip_ver: Option<u8>,
    proto: Option<opte::api::ip::Protocol>,
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

    pub fn set_proto(&mut self, proto: opte::api::ip::Protocol) -> &mut Self {
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

    pub fn new_flow<'a>(
        &'a self,
        flow_name: &'a str,
        link_id: datalink_id_t,
    ) -> Result<MacFlow, FlowCreateError> {
        let name = CString::new(flow_name)
            .map_err(|_| FlowCreateError::InvalidFlowName(flow_name))?;
        let desc = self.to_desc();

        match unsafe {
            mac_link_flow_add(
                link_id,
                name.as_ptr(),
                &desc,
                &MAC_RESOURCE_PROPS_DEF,
            )
        } {
            0 => Ok(MacFlow { name }),
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
            Some(p) => u8::from(p),
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
        }
    }
}

/// Resource handle for a created Mac flow.
#[derive(Debug)]
pub struct MacFlow {
    name: CString,
}

impl Drop for MacFlow {
    fn drop(&mut self) {
        unsafe {
            mac_link_flow_remove(self.name.as_ptr());
        }
    }
}

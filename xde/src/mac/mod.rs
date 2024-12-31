// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

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
use core::mem::MaybeUninit;
use core::ptr;
use illumos_sys_hdrs::*;
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

    pub fn get_mac_addr(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        unsafe {
            mac_unicast_primary_get(self.0, &mut mac);
        }
        mac
    }

    pub fn get_min_max_sdu(&self) -> (u32, u32) {
        let (mut min, mut max) = (0, 0);

        unsafe {
            mac_sdu_get(self.0, &raw mut min, &raw mut max);
        }

        (min, max)
    }

    pub fn get_cso_capabs(&self) -> u32 {
        let mut flags = 0u32;
        unsafe {
            mac_capab_get(
                self.0,
                mac_capab_t::MAC_CAPAB_HCKSUM,
                (&raw mut flags) as *mut _,
            );
        }
        flags
    }

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
        let Some(mblk) = pkt.unwrap_mblk() else {
            return None;
        };
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

        if ret == 0 {
            Ok(Self { mph, parent })
        } else {
            Err(ret)
        }
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
        if res == 0 {
            Ok(Self { mph, link })
        } else {
            Err(res)
        }
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
/// Classes of TCP segmentation offload supported by a MAC provider.
pub struct TcpLsoFlags: u32 {
    /// The device supports TCP LSO over IPv4.
    const BASIC_IPV4 = LSO_TX_BASIC_TCP_IPV4;
    /// The device supports TCP LSO over IPv6.
    const BASIC_IPV6 = LSO_TX_BASIC_TCP_IPV6;
    /// The device supports LSO of TCP packets within IPv4-based tunnels.
    const TUN_IPV4 = LSO_TX_TUNNEL_TCP_IPV4;
    /// The device supports LSO of TCP packets within IPv6-based tunnels.
    const TUN_IPV6 = LSO_TX_TUNNEL_TCP_IPV6;
}

/// Supported LSO use specific to [`TcpLsoFlags::TUN_IPV4`] or
/// [`TcpLsoFlags::TUN_IPV6`].
pub struct TunnelTcpLsoFlags: u32 {
    /// The device can fill the outer L4 (e.g., UDP) checksum
    /// on generated tunnel packets.
    const FILL_OUTER_CSUM = LSO_TX_TUNNEL_OUTER_CSUM;
    /// The device supports *inner* TCP LSO over IPv4.
    const INNER_IPV4 = LSO_TX_TUNNEL_INNER_IP4;
    /// The device supports *inner* TCP LSO over IPv6.
    const INNER_IPV6 = LSO_TX_TUNNEL_INNER_IP6;
    /// LSO is supported with a Geneve outer transport.
    const GENEVE = LSO_TX_TUNNEL_GENEVE;
    /// LSO is supported with a VXLAN outer transport.
    const VXLAN = LSO_TX_TUNNEL_VXLAN;
}

/// Classes of checksum offload suppported by a MAC provider.
pub struct ChecksumOffloadCapabs: u32 {
    /// CSO is enabled on the device.
    const ENABLE = 1 << 0;

    /// Device can finalize packet checksum when provided with a partial
    /// (pseudoheader) checksum.
    const INET_PARTIAL = 1 << 1;
    /// Device can compute full (L3+L4) checksum of TCP/UDP over IPv4.
    const INET_FULL_V4 = 1 << 2;
    /// Device can compute full (L4) checksum of TCP/UDP over IPv6.
    const INET_FULL_V6 = 1 << 3;
    /// Device can compute IPv4 header checksum.
    const INET_HDRCKSUM = 1 << 4;

    const NON_TUN_CAPABS =
        Self::ENABLE.bits() | Self::INET_PARTIAL.bits() |
        Self::INET_FULL_V4.bits() | Self::INET_FULL_V6.bits() |
        Self::INET_HDRCKSUM.bits();

    /// Device can fill outer (UDP) checksum on tunnelled packets.
    const TUN_OUTER_CSUM = 1 << 5;
    /// Device can fill inner checksums (`NON_TUN_CAPABS`) for Geneve packets.
    const TUN_GENEVE = 1 << 6;
}
}

bitflags! {
/// Flagset for requesting emulation on any packets marked
/// with the given offloads.
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

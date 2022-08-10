// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Safe abstractions for the mac client API.
//!
//! NOTE: This module is re-exporting all of the sys definitions at
//! the moment out of laziness.
pub use super::mac_sys::*;
use alloc::string::{String, ToString};
use bitflags::bitflags;
use core::ptr;
use cstr_core::{CStr, CString};
use illumos_ddi_dki::*;
use opte::engine::packet::{Initialized, Packet, PacketState};

/// A mac client
#[derive(Clone, Debug)]
pub struct MacClient {
    close_flags: u16,
    mch: *mut mac_client_handle,
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
        const NO_UNICAST_ADDR = MAC_OPEN_FLAGS_NO_UNICAST_ADDR;
    }
}

impl MacClient {
    /// Open a new client on top of the provider specified by `mh`.
    pub fn open(
        mh: *const mac_handle,
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
                        mh,
                        &mut mch,
                        name_cstr.as_ptr(),
                        raw_oflags,
                    )
                }
            }

            None => {
                let name_cstr = ptr::null_mut();
                raw_oflags |= MAC_OPEN_FLAGS_USE_DATALINK_NAME;
                unsafe { mac_client_open(mh, &mut mch, name_cstr, raw_oflags) }
            }
        };

        if ret != 0 {
            return Err(ret);
        }

        Ok(Self { close_flags, mch })
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

    /// Set the Rx callback handler.
    pub fn set_rx(&self, rx_fn: mac_rx_fn, arg: *mut c_void) {
        unsafe { mac_rx_set(self.mch, rx_fn, arg) };
    }

    pub fn add_promisc(
        &self,
        ptype: mac_client_promisc_type_t,
        promisc_fn: mac_rx_fn,
        arg: *mut c_void,
        flags: u16,
    ) -> Result<*mut mac_promisc_handle, c_int> {
        let mut mph = 0 as *mut mac_promisc_handle;

        let ret = unsafe {
            mac_promisc_add(self.mch, ptype, promisc_fn, arg, &mut mph, flags)
        };

        if ret == 0 {
            Ok(mph)
        } else {
            return Err(ret);
        }
    }

    pub fn rem_promisc(&self, mph: *mut mac_promisc_handle) {
        unsafe { mac_promisc_remove(mph) };
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
            mac_tx(self.mch, pkt.unwrap(), hint, flags.bits(), &mut ret_mp)
        };
        if ret_mp != ptr::null_mut() {
            // Safety: We know the ret_mp is valid because we gave
            // mac_tx() a valid mp_chain (pkt.unwrap()); and mac_tx()
            // will give us either that exact pointer back (via
            // ret_mp) or the portion of the packet chain it could not
            // queue.
            //
            // XXX Technically we are still only passing single
            // packets, but eventually we will pass packet chains and
            // the sentence above will hold.
            Some(unsafe { Packet::<Initialized>::wrap(ret_mp) })
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
        unsafe { mac_tx(self.mch, pkt.unwrap(), hint, raw_flags, &mut ret_mp) };
        debug_assert_eq!(ret_mp, ptr::null_mut());
    }
}

impl Drop for MacClient {
    fn drop(&mut self) {
        // Safety: We know that a MacClient can only exist if a mac
        // client handle was successfully obtained, and thus mch is
        // valid.
        unsafe { mac_client_close(self.mch, self.close_flags) };
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Safe abstractions around DLS public and private functions.

pub mod sys;

use crate::mac::mac_client_handle;
use crate::mac::MacClient;
use crate::mac::MacPerimeterHandle;
use crate::mac::MacTxFlags;
use crate::mac::MAC_DROP_ON_NO_DESC;
use alloc::sync::Arc;
use core::ffi::CStr;
use core::fmt::Display;
use core::mem::MaybeUninit;
use core::ptr;
use illumos_sys_hdrs::c_int;
use illumos_sys_hdrs::datalink_id_t;
use illumos_sys_hdrs::uintptr_t;
use illumos_sys_hdrs::ENOENT;
use opte::engine::packet::Packet;
use opte::engine::packet::PacketState;
pub use sys::*;

/// An integer ID used by DLS to refer to a given link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkId(u32);

impl LinkId {
    /// Request the link ID for a device using its name.
    pub fn from_name(name: impl AsRef<CStr>) -> Result<Self, LinkError> {
        let mut link_id = 0;

        unsafe {
            match dls_mgmt_get_linkid(name.as_ref().as_ptr(), &mut link_id) {
                0 => Ok(LinkId(link_id)),
                ENOENT => Err(LinkError::NotFound),
                err => Err(LinkError::Other(err)),
            }
        }
    }
}

impl From<LinkId> for datalink_id_t {
    fn from(val: LinkId) -> Self {
        val.0
    }
}

/// Errors encountered while querying DLS for a `LinkId`.
pub enum LinkError {
    NotFound,
    Other(i32),
}

impl Display for LinkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LinkError::NotFound => write!(f, "link not found"),
            LinkError::Other(e) => write!(f, "unknown error ({e})"),
        }
    }
}

/// A hold on an existing link managed by DLS.
#[derive(Debug)]
struct DlsLink {
    inner: Option<DlsLinkInner>,
    link: LinkId,
}

#[derive(Debug)]
struct DlsLinkInner {
    dlp: *mut dls_link,
    dlh: dls_dl_handle,
}

impl DlsLink {
    /// Place a hold on an existing link.
    fn hold(mph: &MacPerimeterHandle) -> Result<Self, c_int> {
        let mut dlp = ptr::null_mut();
        let mut dlh = ptr::null_mut();
        let link = mph.link_id();

        let res = unsafe { dls_devnet_hold(link.into(), &mut dlh) };
        if res != 0 {
            return Err(res);
        }

        let res = unsafe { dls_link_hold(dls_devnet_mac(dlh), &mut dlp) };
        if res == 0 {
            Ok(Self { inner: Some(DlsLinkInner { dlp, dlh }), link })
        } else {
            unsafe { dls_devnet_rele(dlh) };
            Err(res)
        }
    }

    /// Release a hold on a given link.
    ///
    /// This operation requires that you acquire the MAC perimeter
    /// for the target device.
    fn release(mut self, mph: &MacPerimeterHandle) {
        if let Some(inner) = self.inner.take() {
            if mph.link_id() != self.link {
                panic!("Tried to free link hold with the wrong MAC perimeter: saw {:?}, wanted {:?}",
                    mph.link_id(), self.link);
            }
            unsafe {
                dls_devnet_rele_link(inner.dlh, inner.dlp);
            }
        }
    }

    /// Convert a hold into a `DlsStream` for packet Rx/Tx.
    fn open_stream(
        mut self,
        mph: &MacPerimeterHandle,
    ) -> Result<Arc<DlsStream>, c_int> {
        let Some(inner) = self.inner.as_ref() else {
            return Err(-1);
        };

        if mph.link_id() != self.link {
            panic!("Tried to open stream with the wrong MAC perimeter: saw {:?}, wanted {:?}",
                mph.link_id(), self.link);
        }

        let mut stream = MaybeUninit::zeroed();
        let res =
            unsafe { dls_open(inner.dlp, inner.dlh, stream.as_mut_ptr()) };
        if res == 0 {
            // DLP is held/consumed by dls_open.
            _ = self.inner.take();
            let dld_str = unsafe { stream.assume_init() };
            Ok(DlsStream {
                inner: Some(DlsStreamInner { dld_str }),
                link: mph.link_id(),
            }
            .into())
        } else {
            self.release(mph);
            Err(res)
        }
    }
}

impl Drop for DlsLink {
    fn drop(&mut self) {
        if self.inner.take().is_some() {
            opte::engine::err!(
                "dropped hold on link {:?} without releasing!!",
                self.link
            );
        }
    }
}

/// A DLS message stream on a target link, allowing packet
/// Rx and Tx.
#[derive(Debug)]
pub struct DlsStream {
    inner: Option<DlsStreamInner>,
    link: LinkId,
}

#[derive(Debug)]
struct DlsStreamInner {
    dld_str: dld_str_s,
}

impl DlsStream {
    pub fn open(link_id: LinkId) -> Result<Arc<Self>, c_int> {
        let perim = MacPerimeterHandle::from_linkid(link_id)?;
        let link_handle = DlsLink::hold(&perim)?;
        link_handle.open_stream(&perim)
    }

    /// Returns the ID of the link this stream belongs to.
    pub fn link_id(&self) -> LinkId {
        self.link
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
        let Some(inner) = self.inner.as_ref() else {
            // XXX: probably handle or signal an error here.
            return;
        };
        // We must unwrap the raw `mblk_t` out of the `pkt` here,
        // otherwise the mblk_t would be dropped at the end of this
        // function along with `pkt`.
        let mut raw_flags = flags.bits();
        raw_flags |= MAC_DROP_ON_NO_DESC;
        unsafe {
            str_mdata_fastpath_put(
                &inner.dld_str,
                pkt.unwrap_mblk(),
                hint,
                raw_flags,
            )
        };
    }
}

impl MacClient for DlsStream {
    fn mac_client_handle(&self) -> Result<*mut mac_client_handle, c_int> {
        let Some(inner) = self.inner.as_ref() else {
            return Err(-1);
        };

        Ok(inner.dld_str.ds_mch)
    }
}

impl Drop for DlsStream {
    fn drop(&mut self) {
        if let Some(mut inner) = self.inner.take() {
            match MacPerimeterHandle::from_linkid(self.link) {
                Ok(_perim) => unsafe {
                    // NOTE: this is reimplementing dld_str_detach
                    // but we're avoiding capab negotiation/disable and
                    // mac notify callbacks. Should we just come in through
                    // dld_open/dld_close/dld_wput? That would make it a bit
                    // weirder to set the promisc handle, and I don't know how
                    // this would interact with
                    dls_close(&mut inner.dld_str);
                    dls_devnet_rele(inner.dld_str.ds_ddh)
                },
                Err(e) => opte::engine::err!(
                    "couldn't acquire MAC perimeter (err {}): \
                    dropped stream on link {:?} without releasing",
                    e,
                    self.link,
                ),
            }
        }
    }
}

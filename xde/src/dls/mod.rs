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
pub struct DlsLink {
    inner: Option<DlsLinkInner>,
    link: LinkId,
}

#[derive(Debug)]
struct DlsLinkInner {
    dlp: *mut dls_link,
    dlh: dls_dl_handle,
}

impl DlsLink {
    /// Place a hold on an existing link,
    pub fn hold(mph: &MacPerimeterHandle) -> Result<Self, c_int> {
        let mut dlp = ptr::null_mut();
        let mut dlh = ptr::null_mut();
        let link = mph.link_id();

        let res =
            unsafe { dls_devnet_hold_link(link.into(), &mut dlh, &mut dlp) };
        if res == 0 {
            Ok(Self { inner: Some(DlsLinkInner { dlp, dlh }), link })
        } else {
            Err(res)
        }
    }

    pub fn link_id(&self) -> LinkId {
        self.link
    }

    // XXX: cleanup REQUIRES that we hold the MAC perimeter handle.
    pub fn release(mut self, mph: &MacPerimeterHandle) {
        if let Some(inner) = self.inner.take() {
            if mph.link_id() != self.link {
                panic!("Tried to free link hold with the wrong MAC perimeter: saw {:?}, wanted {:?}",
                    mph.link_id(),self.link);
            }
            unsafe {
                dls_devnet_rele_link(inner.dlh, inner.dlp);
            }
        }
    }

    pub fn open_stream(
        mut self,
        mph: &MacPerimeterHandle,
    ) -> Result<Arc<DldStream>, c_int> {
        let Some(inner) = self.inner.as_ref() else {
            return Err(-1);
        };

        if mph.link_id() != self.link {
            panic!("Tried to open stream with the wrong MAC perimeter: saw {:?}, wanted {:?}",
                mph.link_id(),self.link);
        }

        let mut stream = MaybeUninit::zeroed();
        let res =
            unsafe { dls_open(inner.dlp, inner.dlh, stream.as_mut_ptr()) };
        if res == 0 {
            // DLP is held/consumed by dls_open.
            _ = self.inner.take();
            let dld_str = unsafe { stream.assume_init() };
            Ok(DldStream {
                inner: Some(DldStreamInner { dld_str }),
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

/// A DLS message stream derived from a
#[derive(Debug)]
pub struct DldStream {
    inner: Option<DldStreamInner>,
    link: LinkId,
}

#[derive(Debug)]
struct DldStreamInner {
    dld_str: dld_str_s,
}

impl DldStream {
    pub fn link_id(&self) -> LinkId {
        self.link
    }

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

    // XXX: cleanup REQUIRES that we hold the MAC perimeter handle.
    pub fn release(mut self, mph: &MacPerimeterHandle) {
        if let Some(mut inner) = self.inner.take() {
            if mph.link_id() != self.link {
                opte::engine::err!("Tried to free link hold with the wrong MAC perimeter: saw {:?}, wanted {:?}",
                    mph.link_id(), self.link);
            }
            unsafe {
                dls_close(&mut inner.dld_str);
            }
        }
    }
}

impl MacClient for DldStream {
    fn mac_client_handle(&self) -> Result<*mut mac_client_handle, c_int> {
        let Some(inner) = self.inner.as_ref() else {
            return Err(-1);
        };

        Ok(inner.dld_str.ds_mch)
    }
}

impl Drop for DldStream {
    fn drop(&mut self) {
        if self.inner.take().is_some() {
            opte::engine::err!(
                "dropped stream on link {:?} without releasing!!",
                self.link,
            );
        }
    }
}

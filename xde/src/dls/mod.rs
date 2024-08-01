// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Safe abstractions around DLS public and private functions.

pub mod sys;

use crate::kmem::sys::kmem_cache_alloc;
use crate::kmem::sys::kmem_cache_free;
use crate::mac::mac_client_handle;
use crate::mac::MacClient;
use crate::mac::MacPerimeterHandle;
use crate::mac::MacTxFlags;
use crate::mac::MAC_DROP_ON_NO_DESC;
use crate::warn;
use alloc::string::String;
use core::ffi::CStr;
use core::fmt::Display;
use core::ptr;
use core::ptr::NonNull;
use illumos_sys_hdrs::c_int;
use illumos_sys_hdrs::datalink_id_t;
use illumos_sys_hdrs::uintptr_t;
use illumos_sys_hdrs::ENOENT;
use illumos_sys_hdrs::KM_SLEEP;
use opte::api::StructDef;
use opte::engine::packet::Packet;
use opte::engine::packet::PacketState;
pub use sys::*;

/// An integer ID used by DLS to refer to a given link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkId(datalink_id_t);

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
                dls_link_rele(inner.dlp);
                dls_devnet_rele(inner.dlh);
            }
        }
    }

    /// Convert a hold into a `DlsStream` for packet Rx/Tx.
    fn open_stream(
        mut self,
        mph: &MacPerimeterHandle,
    ) -> Result<DlsStream, c_int> {
        let Some(inner) = self.inner.as_ref() else {
            panic!("attempted to open a DlsStream on freed link")
        };

        if mph.link_id() != self.link {
            panic!("Tried to open stream with the wrong MAC perimeter: saw {:?}, wanted {:?}",
                mph.link_id(), self.link);
        }

        let dld_str = NonNull::new(unsafe {
            kmem_cache_alloc(dld_str_cachep, KM_SLEEP) as *mut dld_str_s
        });
        let Some(dld_str) = dld_str else {
            self.release(mph);
            return Err(-1);
        };

        let res = unsafe { dls_open(inner.dlp, inner.dlh, dld_str.as_ptr()) };
        if res == 0 {
            // DLP is held/consumed by dls_open.
            _ = self.inner.take();
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
    dld_str: NonNull<dld_str_s>,
}

impl DlsStream {
    pub fn verify_bindings(bindings: &StructDef) -> Result<(), String> {
        let expt = [
            ("ds_ddh", core::mem::offset_of!(dld_str_s, ds_ddh)),
            ("ds_mch", core::mem::offset_of!(dld_str_s, ds_mch)),
            ("ds_mh", core::mem::offset_of!(dld_str_s, ds_mh)),
            ("ds_mip", core::mem::offset_of!(dld_str_s, ds_mip)),
        ];

        let mut errs = vec![];
        for (field_name, byte_offset) in expt {
            let bit_offset = 8 * byte_offset;
            let Some(field) = bindings.fields.get(field_name) else {
                errs.push(format!("missing field {field_name}"));
                continue;
            };

            if field.bit_offset != bit_offset as u64 {
                errs.push(format!(
                    "field {field_name} at bit {} (wanted {})",
                    field.bit_offset, bit_offset,
                ));
            }
        }

        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join(", "))
        }
    }

    pub fn open(link_id: LinkId) -> Result<Self, c_int> {
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
                inner.dld_str.as_ptr(),
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

        Ok(unsafe { (*inner.dld_str.as_ptr()).ds_mch })
    }
}

impl Drop for DlsStream {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            match MacPerimeterHandle::from_linkid(self.link) {
                Ok(_perim) => unsafe {
                    // NOTE: this is reimplementing dld_str_detach
                    // but we're avoiding capab negotiation/disable and
                    // mac notify callbacks. Should we just come in through
                    // dld_open/dld_close/dld_wput? That would make it a bit
                    // weirder to set the promisc handle, and I don't know how
                    // this would interact with the existing (logical)
                    // STREAMS up to ip.
                    dls_close(inner.dld_str.as_ptr());
                    dls_devnet_rele((*inner.dld_str.as_ptr()).ds_ddh);

                    (*inner.dld_str.as_ptr()).ds_mh = ptr::null_mut();
                    (*inner.dld_str.as_ptr()).ds_mch = ptr::null_mut();
                    // ddh NULL not checked by destroy fn or cleared by ddh
                    // but it probably should be.
                    (*inner.dld_str.as_ptr()).ds_ddh = ptr::null_mut();
                    (*inner.dld_str.as_ptr()).ds_mip = ptr::null();

                    // already the case:
                    // dsp->ds_dlstate = DL_UNATTACHED;
                    // dsp->ds_sap = 0;

                    kmem_cache_free(
                        dld_str_cachep,
                        inner.dld_str.as_ptr() as *mut _,
                    );
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

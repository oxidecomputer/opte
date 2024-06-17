// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Safe abstractions around DLS public and private functions.

pub mod sys;

use crate::mac::mac_client_promisc_type_t;
use crate::mac::mac_promisc_add;
use crate::mac::mac_rx_fn;
use crate::mac::MacPerimeterHandle;
use crate::mac::MacPromiscHandle;
use crate::mac::MacTxFlags;
use crate::mac::MAC_DROP_ON_NO_DESC;
use alloc::sync::Arc;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr;
use illumos_sys_hdrs::c_int;
use illumos_sys_hdrs::datalink_id_t;
use illumos_sys_hdrs::uintptr_t;
use opte::engine::packet::Packet;
use opte::engine::packet::PacketState;
pub use sys::*;

#[derive(Debug)]
pub struct DlsLink {
    inner: Option<DlsLinkInner>,
}

#[derive(Debug)]
pub struct DlsLinkInner {
    dlp: *mut dls_link,
    dlh: dls_dl_handle,
    link: datalink_id_t,
}

impl DlsLink {
    pub fn hold(mph: &MacPerimeterHandle) -> Result<Self, c_int> {
        let mut dlp = ptr::null_mut();
        let mut dlh = ptr::null_mut();
        let link = mph.linkid();

        let res = unsafe { dls_devnet_hold_link(link, &mut dlh, &mut dlp) };
        if res == 0 {
            Ok(Self { inner: Some(DlsLinkInner { dlp, dlh, link }) })
        } else {
            Err(res)
        }
    }

    // XXX: cleanup REQUIRES that we hold the MAC perimeter handle.
    pub fn release(mut self, mph: &MacPerimeterHandle) {
        if let Some(inner) = self.inner.take() {
            if mph.linkid() != inner.link {
                panic!("Tried to free link hold with the wrong MAC perimeter: saw {}, wanted {}",
                    mph.linkid(), inner.link);
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

        if mph.linkid() != inner.link {
            panic!("Tried to open stream with the wrong MAC perimeter: saw {}, wanted {}",
                mph.linkid(), inner.link);
        }

        let mut stream = MaybeUninit::zeroed();
        let res =
            unsafe { dls_open(inner.dlp, inner.dlh, stream.as_mut_ptr()) };
        if res == 0 {
            // DLP is held/consumed by dls_open.
            _ = self.inner.take();
            let dld_str = unsafe { stream.assume_init() };
            Ok(DldStream {
                inner: Some(DldStreamInner { dld_str, link: mph.linkid() }),
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
        if let Some(inner) = self.inner.take() {
            opte::engine::err!(
                "dropped hold on link {} without releasing!!",
                inner.link
            );
        }
    }
}

#[derive(Debug)]
pub struct DldStream {
    inner: Option<DldStreamInner>,
}

#[derive(Debug)]
pub struct DldStreamInner {
    dld_str: dld_str_s,
    link: datalink_id_t,
}

impl DldStream {
    /// Register promiscuous callback to receive packets on the underlying MAC.
    pub fn add_promisc(
        self: &Arc<Self>,
        ptype: mac_client_promisc_type_t,
        promisc_fn: mac_rx_fn,
        flags: u16,
    ) -> Result<MacPromiscHandle<Self>, c_int> {
        let Some(inner) = self.inner.as_ref() else {
            return Err(-1);
        };

        let mut mph = ptr::null_mut();

        // `MacPromiscHandle` keeps a reference to this `MacClientHandle`
        // until it is removed and so we can safely access it from the
        // callback via the `arg` pointer.
        let _parent = self.clone();
        let parent = Arc::into_raw(_parent) as *mut _;
        let arg = parent as *mut c_void;
        let mch = inner.dld_str.ds_mch;
        let ret = unsafe {
            // NOTE: arg is reinterpreted as `mac_resource_handle` -> `mac_ring`
            // in `mac_rx_common`. Is what we've been doing here and before even safe?
            mac_promisc_add(mch, ptype, promisc_fn, arg, &mut mph, flags)
        };

        if ret == 0 {
            Ok(MacPromiscHandle { mph, parent })
        } else {
            Err(ret)
        }
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
            if mph.linkid() != inner.link {
                opte::engine::err!("Tried to free link hold with the wrong MAC perimeter: saw {}, wanted {}",
                    mph.linkid(), inner.link);
            }
            unsafe {
                dls_close(&mut inner.dld_str);
            }
        }
    }
}

impl Drop for DldStream {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            opte::engine::err!(
                "dropped stream on link {} without releasing!!",
                inner.link
            );
        }
    }
}

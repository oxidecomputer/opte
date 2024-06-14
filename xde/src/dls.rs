// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

// stuff we need from dls

use crate::ip::kcondvar_t;
use crate::ip::krwlock_t;
use crate::ip::list_node_t;
use crate::ip::major_t;
use crate::ip::minor_t;
use crate::ip::queue_t;
use crate::ip::t_uscalar_t;
use crate::mac;
use crate::mac::mac_client_handle;
use crate::mac::mac_client_promisc_type_t;
use crate::mac::mac_handle;
use crate::mac::mac_promisc_add;
use crate::mac::mac_promisc_handle;
use crate::mac::mac_rx_fn;
use crate::mac::MacPerimeterHandle;
use crate::mac::MacPromiscHandle;
use crate::mac::MacTxFlags;
use crate::mac_sys::mac_tx_cookie_t;
use crate::mac_sys::MAC_DROP_ON_NO_DESC;
use alloc::sync::Arc;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr;
use illumos_sys_hdrs::boolean_t;
use illumos_sys_hdrs::c_char;
use illumos_sys_hdrs::c_int;
use illumos_sys_hdrs::c_uint;
use illumos_sys_hdrs::datalink_id_t;
use illumos_sys_hdrs::kmutex_t;
use illumos_sys_hdrs::mblk_t;
use illumos_sys_hdrs::uintptr_t;
use illumos_sys_hdrs::zoneid_t;
use opte::engine::packet::Packet;
use opte::engine::packet::PacketState;

extern "C" {
    pub fn dls_devnet_create(
        mh: *mut mac::mac_handle,
        linkid: datalink_id_t,
        zoneid: zoneid_t,
    ) -> c_int;

    pub fn dls_devnet_destroy(
        mh: *mut mac::mac_handle,
        linkid: *mut datalink_id_t,
        wait: boolean_t,
    ) -> c_int;

    pub fn dls_mgmt_get_linkid(
        name: *const c_char,
        linkid: *mut datalink_id_t,
    ) -> c_int;
}

// Private DLS functions needed to get us a Tx path.
extern "C" {
    pub type dls_devnet_s;
    pub type dls_link;

    // ALL OF THESE REQUIRE THE MAC PERIMETER.
    pub fn dls_devnet_hold_link(
        link: datalink_id_t,
        ddhp: *mut dls_dl_handle,
        dlpp: *mut *mut dls_link,
    ) -> c_int;
    pub fn dls_devnet_rele_link(dlh: dls_dl_handle, dlp: *mut dls_link);
    pub fn dls_open(
        dlp: *mut dls_link,
        ddh: dls_dl_handle,
        dsp: *mut dld_str_s,
    ) -> c_int;
    pub fn dls_close(dsp: *mut dld_str_s);

    // THIS DOES NOT.
    pub fn str_mdata_fastpath_put(
        dsp: *const dld_str_s,
        mp: *mut mblk_t,
        f_hint: uintptr_t,
        flag: u16,
    ) -> mac_tx_cookie_t;
}

// struct dld_str_s {                  /* Protected by */
//     /*
//      * Major number of the device
//      */
//     major_t         ds_major;       /* WO */
//     /*
//      * Ephemeral minor number for the object.
//      */
//     minor_t         ds_minor;       /* WO */
//     /*
//      * PPA number this stream is attached to.
//      */
//     t_uscalar_t     ds_ppa;         /* SL */
//     /*
//      * Read/write queues for the stream which the object represents.
//      */
//     queue_t         *ds_rq;         /* WO */
//     queue_t         *ds_wq;         /* WO */
//     /*
//      * Stream is open to DLD_CONTROL (control node) or
//      * DLD_DLPI (DLS provider) node.
//      */
//     uint_t          ds_type;        /* WO */
//     /*
//      * The following fields are only used for DLD_DLPI type objects.
//      */
//     /*
//      * Current DLPI state.
//      */
//     t_uscalar_t     ds_dlstate;     /* SL */
//     /*
//      * DLPI style
//      */
//     t_uscalar_t     ds_style;       /* WO */
//     /*
//      * Currently bound DLSAP.
//      */
//     uint16_t        ds_sap;         /* SL */
//     /*
//      * Handle of the MAC that is used by the data-link interface.
//      */
//     mac_handle_t        ds_mh;          /* SL */
//     mac_client_handle_t ds_mch;         /* SL */
//     /*
//      * Promiscuity level information.
//      */
//     uint32_t        ds_promisc;     /* SL */
//     mac_promisc_handle_t    ds_mph;
//     mac_promisc_handle_t    ds_vlan_mph;

//     /*
//      * Immutable information of the MAC which the channel is using.
//      */
//     const mac_info_t    *ds_mip;        /* SL */
//     /*
//      * Current packet priority.
//      */
//     uint_t          ds_pri;         /* SL */
//     /*
//      * Handle of our MAC notification callback.
//      */
//     mac_notify_handle_t ds_mnh;         /* SL */
//     /*
//      * Set of enabled DL_NOTE... notifications. (See dlpi.h).
//      */
//     uint32_t        ds_notifications;   /* SL */
//     /*
//      * Mode: unitdata, fast-path or raw.
//      */
//     dld_str_mode_t      ds_mode;        /* SL */
//     /*
//      * Native mode state.
//      */
//     boolean_t       ds_native;      /* SL */
//     /*
//      * IP polling is operational if this flag is set.
//      */
//     boolean_t       ds_polling;     /* SL */
//     boolean_t       ds_direct;      /* SL */
//     /*
//      * LSO is enabled if ds_lso is set.
//      */
//     boolean_t       ds_lso;         /* SL */
//     uint64_t        ds_lso_max;     /* SL */
//     /*
//      * State of DLPI user: may be active (regular network layer),
//      * passive (snoop-like monitoring), or unknown (not yet
//      * determined).
//      */
//     dld_passivestate_t  ds_passivestate;    /* SL */
//     /*
//      * Dummy mblk used for flow-control.
//      */
//     mblk_t          *ds_tx_flow_mp;     /* ds_lock */
//     /*
//      * List of queued DLPI requests. These will be processed
//      * by a taskq thread. This block is protected by ds_lock
//      */
//     kmutex_t        ds_lock;
//     krwlock_t       ds_rw_lock;
//     kcondvar_t      ds_datathr_cv;      /* ds_lock */
//     uint_t          ds_datathr_cnt;     /* ds_lock */
//     mblk_t          *ds_pending_head;   /* ds_lock */
//     mblk_t          *ds_pending_tail;   /* ds_lock */
//     kcondvar_t      ds_dlpi_pending_cv; /* ds_lock */
//     uint32_t
//                 ds_dlpi_pending : 1,    /* ds_lock */
//                 ds_local    : 1,
//                 ds_pad      : 30;   /* ds_lock */
//     dls_link_t      *ds_dlp;        /* SL */
//     dls_multicst_addr_t *ds_dmap;       /* ds_rw_lock */
//     dls_rx_t        ds_rx;          /* ds_lock */
//     void            *ds_rx_arg;     /* ds_lock */
//     uint_t          ds_nactive;     /* SL */
//     dld_str_t       *ds_next;       /* SL */
//     dls_head_t      *ds_head;
//     dls_dl_handle_t     ds_ddh;
//     list_node_t     ds_tqlist;

//     /*
//      * driver private data set by the driver when calling dld_str_open().
//      */
//     void            *ds_private;

//     boolean_t       ds_lowlink;     /* SL */
//     boolean_t       ds_nonip;       /* SL */
// };

#[repr(C)]
pub enum dld_str_mode_t {
    DLD_UNITDATA,
    DLD_FASTPATH,
    DLD_RAW,
}

#[repr(C)]
pub enum dld_passivestate_t {
    DLD_UNINITIALIZED,
    DLD_PASSIVE,
    DLD_ACTIVE,
}

#[repr(C)]
pub struct dld_str_s {
    ds_major: major_t,
    ds_minor: minor_t,

    ds_ppa: t_uscalar_t,

    ds_rq: *mut queue_t,
    ds_wq: *mut queue_t,

    ds_type: c_uint,

    ds_dlstate: t_uscalar_t,
    ds_style: t_uscalar_t,
    ds_sap: u16,

    ds_mh: *mut mac_handle,
    ds_mch: *mut mac_client_handle,

    ds_promisc: u32,
    ds_mph: *mut mac_promisc_handle,
    ds_vlan_mph: *mut mac_promisc_handle,

    ds_mip: *const c_void, // mac_info_t

    ds_pri: c_uint,

    ds_mnh: *mut c_void, // mac_notify_handle_t

    ds_notifications: u32,

    ds_mode: dld_str_mode_t,

    ds_native: boolean_t,

    ds_polling: boolean_t,
    ds_direct: boolean_t,

    ds_lso: boolean_t,
    ds_lso_max: u64,

    ds_passivestate: dld_passivestate_t,

    ds_tx_flow_mp: *mut mblk_t,

    /*
     * List of queued DLPI requests. These will be processed
     * by a taskq thread. This block is protected by ds_lock
     */
    ds_lock: kmutex_t,
    ds_rw_lock: krwlock_t,
    ds_datathr_cv: kcondvar_t,
    ds_datathr_cnt: c_uint,
    ds_pending_head: *mut mblk_t,
    ds_pending_tail: *mut mblk_t,
    ds_dlpi_pending_cv: kcondvar_t,
    // bitset: ds_dlpi_pending + ds_local + ds_pad
    dl_dlpi_pend_local: u32,

    ds_dlp: *mut dls_link,
    ds_dmap: *mut c_void, // dls_multicst_addr_t
    ds_rx: *mut c_void,   // dls_rx_t
    ds_rx_arg: *mut c_void,
    ds_nactive: c_uint,
    ds_next: *mut dld_str_s,
    ds_head: *mut c_void, // dls_head_t
    ds_ddh: dls_dl_handle,
    ds_tqlist: list_node_t,

    ds_private: *mut c_void,

    ds_lowlink: boolean_t,
    ds_nonip: boolean_t,
}

impl core::fmt::Debug for dld_str_s {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "<dld_str_s>")
    }
}

pub type dls_dl_handle = *mut dls_devnet_s;

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
        &self,
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
            let dld_str = unsafe { stream.assume_init() };
            Ok(DldStream {
                inner: Some(DldStreamInner { dld_str, link: mph.linkid() }),
            }
            .into())
        } else {
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

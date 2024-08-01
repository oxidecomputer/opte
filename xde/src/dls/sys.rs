// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

// stuff we need from dls

use crate::ip::kcondvar_t;
use crate::ip::kmem_cache_t;
use crate::ip::krwlock_t;
use crate::ip::list_node_t;
use crate::ip::major_t;
use crate::ip::minor_t;
use crate::ip::queue_t;
use crate::ip::t_uscalar_t;
use crate::mac;
use crate::mac::mac_client_handle;
use crate::mac::mac_handle;
use crate::mac::mac_promisc_handle;
use crate::mac::mac_tx_cookie_t;
use core::ffi::c_void;
use illumos_sys_hdrs::boolean_t;
use illumos_sys_hdrs::c_char;
use illumos_sys_hdrs::c_int;
use illumos_sys_hdrs::c_uint;
use illumos_sys_hdrs::datalink_id_t;
use illumos_sys_hdrs::kmutex_t;
use illumos_sys_hdrs::mblk_t;
use illumos_sys_hdrs::uintptr_t;
use illumos_sys_hdrs::zoneid_t;

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

// Private DLS functions needed to have a Tx path on top of
// an existing link while circumventing `ip`.
extern "C" {
    pub type dls_devnet_s;
    pub type dls_link;

    /// Transmit a packet chain on a given link.
    /// This is effectively one layer above mac_tx.
    pub fn str_mdata_fastpath_put(
        dsp: *mut dld_str_s,
        mp: *mut mblk_t,
        f_hint: uintptr_t,
        flag: u16,
    ) -> mac_tx_cookie_t;

    // NOTE: ALL BELOW FUNCTIONS REQUIRE THE MAC PERIMETER TO BE HELD.
    pub fn dls_devnet_hold(
        link: datalink_id_t,
        ddhp: *mut dls_dl_handle,
    ) -> c_int;

    pub fn dls_devnet_rele(dlh: dls_dl_handle);

    pub fn dls_link_hold(
        name: *const c_char,
        dlpp: *mut *mut dls_link,
    ) -> c_int;

    pub fn dls_link_rele(dlp: *mut dls_link);

    pub fn dls_devnet_mac(dlh: dls_dl_handle) -> *const c_char;

    pub fn dls_open(
        dlp: *mut dls_link,
        ddh: dls_dl_handle,
        dsp: *mut dld_str_s,
    ) -> c_int;

    pub fn dls_close(dsp: *mut dld_str_s);

    pub static dld_str_cachep: *mut kmem_cache_t;
}

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

// Direct translation of the illumos type, with some
// pointer fields left as opaque void*s for simplicity.
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

    pub ds_mh: *mut mac_handle,
    pub ds_mch: *mut mac_client_handle,

    ds_promisc: u32,
    ds_mph: *mut mac_promisc_handle,
    ds_vlan_mph: *mut mac_promisc_handle,

    pub ds_mip: *const c_void, // mac_info_t

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
    pub ds_ddh: dls_dl_handle,
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

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

// stuff we need from dls

use crate::mac;
use crate::mac::mac_client_handle;
use crate::mac::mac_tx_cookie_t;
use illumos_sys_hdrs::boolean_t;
use illumos_sys_hdrs::c_char;
use illumos_sys_hdrs::c_int;
use illumos_sys_hdrs::datalink_id_t;
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
    pub type dld_str_s;
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

    // These are stlouis-only methods used to enable the
    // approach we're using here to get a Tx pathway via the
    // existing primary MAC client on the underlay devices.
    pub fn dld_str_create_detached() -> *mut dld_str_s;
    pub fn dld_str_destroy_detached(val: *mut dld_str_s);
    pub fn dld_str_mac_client_handle(
        val: *mut dld_str_s,
    ) -> *mut mac_client_handle;
}

pub type dls_dl_handle = *mut dls_devnet_s;

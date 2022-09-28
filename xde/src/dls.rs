// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

// stuff we need from dls

use crate::mac;
use illumos_sys_hdrs::boolean_t;
use illumos_sys_hdrs::c_int;
use illumos_sys_hdrs::datalink_id_t;
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
}

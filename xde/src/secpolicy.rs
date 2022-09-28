// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

// stuff we need from secpolicy

use illumos_sys_hdrs::c_int;
use illumos_sys_hdrs::cred_t;

extern "C" {
    pub fn secpolicy_dl_config(cr: *const cred_t) -> c_int;
}

// stuff we need from secpolicy

use illumos_ddi_dki::{c_int, cred_t};

extern "C" {
    pub fn secpolicy_dl_config(cr: *const cred_t) -> c_int;
}

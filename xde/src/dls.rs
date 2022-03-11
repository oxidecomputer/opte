// stuff we need from dls

use crate::mac;
use illumos_ddi_dki::{boolean_t, c_int, datalink_id_t, zoneid_t};

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

// DLS APIs that we need.
use crate::mac;
use illumos_ddi_dki::*;

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
        link: *const c_char,
        linkid: *mut datalink_id_t,
    ) -> c_int;
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

// stuff we need from mac

use illumos_sys_hdrs::boolean_t;
use illumos_sys_hdrs::c_char;
use illumos_sys_hdrs::c_int;
use illumos_sys_hdrs::c_uint;
use illumos_sys_hdrs::c_void;
use illumos_sys_hdrs::dev_info;
use illumos_sys_hdrs::dev_ops;
use illumos_sys_hdrs::mblk_t;
use illumos_sys_hdrs::minor_t;
use illumos_sys_hdrs::queue_t;
use illumos_sys_hdrs::size_t;
use illumos_sys_hdrs::uintptr_t;

pub const MAC_DROP_ON_NO_DESC: u16 = 0x01;
pub const MAC_TX_NO_ENQUEUE: u16 = 0x02;
pub const MAC_TX_NO_HOLD: u16 = 0x04;
pub const MCIS_NO_UNICAST_ADDR: u16 = 0x2000;

pub const MAC_VIRT_NONE: c_int = 0x0;
pub const MAC_VIRT_LEVEL1: c_int = 0x0;
pub const MAC_VIRT_HIO: c_int = 0x0;

pub const MAC_UNICAST_NODUPCHECK: u16 = 0x0001;
pub const MAC_UNICAST_PRIMARY: u16 = 0x0002;
pub const MAC_UNICAST_HW: u16 = 0x0004;
pub const MAC_UNICAST_VNIC_PRIMARY: u16 = 0x0008;
pub const MAC_UNICAST_TAG_DISABLE: u16 = 0x0010;
pub const MAC_UNICAST_STRIP_DISABLE: u16 = 0x0020;
pub const MAC_UNICAST_DISABLE_TX_VID_CHECK: u16 = 0x0040;

pub const MAC_OPEN_FLAGS_IS_VNIC: u16 = 0x0001;
pub const MAC_OPEN_FLAGS_EXCLUSIVE: u16 = 0x0002;
pub const MAC_OPEN_FLAGS_IS_AGGR_PORT: u16 = 0x0004;
pub const MAC_OPEN_FLAGS_SHARES_DESIRED: u16 = 0x0008;
pub const MAC_OPEN_FLAGS_USE_DATALINK_NAME: u16 = 0x0010;
pub const MAC_OPEN_FLAGS_MULTI_PRIMARY: u16 = 0x0020;
pub const MAC_OPEN_FLAGS_NO_UNICAST_ADDR: u16 = 0x0040;

#[allow(dead_code)]
#[repr(C)]
pub enum mac_client_promisc_type_t {
    MAC_CLIENT_PROMISC_ALL,
    MAC_CLIENT_PROMISC_FILTERED,
    MAC_CLIENT_PROMISC_MULTI,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub enum link_state_t {
    Unknown = -1,
    Down,
    Up,
}

#[allow(unused_imports)]
use mac_client_promisc_type_t::*;

pub type mac_tx_cookie_t = uintptr_t;
pub type mac_rx_fn = unsafe extern "C" fn(
    *mut c_void,
    *mut mac_resource_handle,
    *mut mblk_t,
    boolean_t,
);

extern "C" {
    pub type mac_handle;
    pub type mac_client_handle;
    pub type mac_unicast_handle;
    pub type mac_promisc_handle;
    pub type mac_resource_handle;
    pub type mac_prop_info_handle;

    pub fn mac_client_open(
        mh: *const mac_handle,
        mch: *mut *mut mac_client_handle,
        name: *const c_char,
        flags: u16,
    ) -> c_int;

    pub fn mac_alloc(mac_version: c_uint) -> *mut mac_register_t;
    pub fn mac_free(mregp: *mut mac_register_t);
    pub fn mac_init_ops(ops: *mut dev_ops, name: *const c_char);
    pub fn mac_fini_ops(ops: *mut dev_ops);
    pub fn mac_drop_chain(chain: *mut mblk_t, fmt: *const c_char, ...);
    pub fn mac_register(
        mregp: *mut mac_register_t,
        mhp: *mut *mut mac_handle,
    ) -> c_int;
    pub fn mac_unregister(mh: *const mac_handle) -> c_int;

    pub fn mac_client_close(mch: *const mac_client_handle, flags: u16);
    pub fn mac_client_name(mch: *const mac_client_handle) -> *const c_char;
    pub fn mac_close(mh: *mut mac_handle);
    pub fn mac_open_by_linkname(
        link: *const c_char,
        mhp: *mut *mut mac_handle,
    ) -> c_int;
    pub fn mac_promisc_add(
        mch: *const mac_client_handle,
        ptype: mac_client_promisc_type_t,
        pfn: mac_rx_fn,
        arg: *mut c_void,
        mphp: *mut *mut mac_promisc_handle,
        flags: u16,
    ) -> c_int;
    pub fn mac_promisc_remove(mph: *const mac_promisc_handle);
    pub fn mac_rx_barrier(mch: *const mac_client_handle);
    pub fn mac_rx_set(
        mch: *const mac_client_handle,
        rx_fn: mac_rx_fn,
        arg: *mut c_void,
    );
    pub fn mac_rx_clear(mch: *const mac_client_handle);
    pub fn mac_tx(
        mch: *const mac_client_handle,
        mp_chain: *mut mblk_t,
        hint: uintptr_t,
        flag: u16,
        ret_mp: *mut *mut mblk_t,
    ) -> mac_tx_cookie_t;
    pub fn mac_unicast_primary_get(mh: *const mac_handle, addr: *mut [u8; 6]);
    pub fn mac_link_update(mh: *const mac_handle, link: link_state_t);
    pub fn mac_tx_update(mh: *const mac_handle);
    pub fn mac_unicast_add(
        mch: *mut mac_client_handle,
        mac_addr: *mut u8,
        flags: u16,
        mah: *mut *mut mac_unicast_handle,
        vid: u16,
        diag: *mut mac_diag,
    ) -> c_int;
    pub fn mac_unicast_remove(
        mch: *mut mac_client_handle,
        mah: *mut mac_unicast_handle,
    ) -> c_int;
    pub fn mac_rx(
        mh: *mut mac_handle,
        mrh: *mut mac_resource_handle,
        mp_chain: *mut mblk_t,
    );
    pub fn mac_private_minor() -> minor_t;
}

#[repr(C)]
#[derive(Debug)]
pub enum mac_diag {
    MAC_DIAG_NONE,
    MAC_DIAG_MACADDR_NIC,
    MAC_DIAG_MACADDR_INUSE,
    MAC_DIAG_MACADDR_INVALID,
    MAC_DIAG_MACADDRLEN_INVALID,
    MAC_DIAG_MACFACTORYSLOTINVALID,
    MAC_DIAG_MACFACTORYSLOTUSED,
    MAC_DIAG_MACFACTORYSLOTALLUSED,
    MAC_DIAG_MACFACTORYNOTSUP,
    MAC_DIAG_MACPREFIX_INVALID,
    MAC_DIAG_MACPREFIXLEN_INVALID,
    MAC_DIAG_MACNO_HWRINGS,
}

// See mac_callbacks(9S) for more information on mac callbacks
#[repr(C)]
pub struct mac_callbacks_t {
    pub mc_callbacks: c_uint,
    pub mc_getstat:
        unsafe extern "C" fn(*mut c_void, c_uint, *mut u64) -> c_int,
    pub mc_start: unsafe extern "C" fn(*mut c_void) -> c_int,
    pub mc_stop: unsafe extern "C" fn(*mut c_void),
    pub mc_setpromisc: unsafe extern "C" fn(*mut c_void, boolean_t) -> c_int,
    pub mc_multicst:
        unsafe extern "C" fn(*mut c_void, boolean_t, *const u8) -> c_int,
    pub mc_unicst: unsafe extern "C" fn(*mut c_void, *const u8) -> c_int,
    pub mc_tx: unsafe extern "C" fn(*mut c_void, *mut mblk_t) -> *mut mblk_t,
    pub mc_reserved: *mut c_void,
    pub mc_ioctl: unsafe extern "C" fn(*mut c_void, *mut queue_t, *mut mblk_t),

    pub mc_getcapab: unsafe extern "C" fn(
        *mut c_void,
        mac_capab_t,
        *mut c_void,
    ) -> boolean_t,

    pub mc_open: unsafe extern "C" fn(*mut c_void) -> c_int,
    pub mc_close: unsafe extern "C" fn(*mut c_void),
    pub mc_setprop: unsafe extern "C" fn(
        *mut c_void,
        *const c_char,
        mac_prop_id_t,
        c_uint,
        *const c_void,
    ) -> c_int,

    pub mc_getprop: unsafe extern "C" fn(
        *mut c_void,
        *const c_char,
        mac_prop_id_t,
        c_uint,
        *mut c_void,
    ) -> c_int,

    pub mc_propinfo: unsafe extern "C" fn(
        *mut c_void,
        *const c_char,
        mac_prop_id_t,
        *mut mac_prop_info_handle,
    ),
}
unsafe impl Sync for mac_callbacks_t {}

pub const MC_RESERVED: c_int = 0x0001;
pub const MC_IOCTL: c_int = 0x0002;
pub const MC_GETCAPAB: c_int = 0x0004;
pub const MC_OPEN: c_int = 0x0008;
pub const MC_CLOSE: c_int = 0x0010;
pub const MC_SETPROP: c_int = 0x0020;
pub const MC_GETPROP: c_int = 0x0040;
pub const MC_PROPINFO: c_int = 0x0080;
pub const MC_PROPERTIES: c_int = MC_SETPROP | MC_GETPROP | MC_PROPINFO;

#[repr(C)]
pub enum mac_prop_id_t {
    MAC_PROP_PRIVATE = -1,
    MAC_PROP_DUPLEX = 0x00000001,
    MAC_PROP_SPEED,
    MAC_PROP_STATUS,
    MAC_PROP_AUTONEG,
    MAC_PROP_EN_AUTONEG,
    MAC_PROP_MTU,
    MAC_PROP_ZONE,
    MAC_PROP_AUTOPUSH,
    MAC_PROP_FLOWCTRL,
    MAC_PROP_ADV_1000FDX_CAP,
    MAC_PROP_EN_1000FDX_CAP,
    MAC_PROP_ADV_1000HDX_CAP,
    MAC_PROP_EN_1000HDX_CAP,
    MAC_PROP_ADV_100FDX_CAP,
    MAC_PROP_EN_100FDX_CAP,
    MAC_PROP_ADV_100HDX_CAP,
    MAC_PROP_EN_100HDX_CAP,
    MAC_PROP_ADV_10FDX_CAP,
    MAC_PROP_EN_10FDX_CAP,
    MAC_PROP_ADV_10HDX_CAP,
    MAC_PROP_EN_10HDX_CAP,
    MAC_PROP_ADV_100T4_CAP,
    MAC_PROP_EN_100T4_CAP,
    MAC_PROP_IPTUN_HOPLIMIT,
    MAC_PROP_IPTUN_ENCAPLIMIT,
    MAC_PROP_WL_ESSID,
    MAC_PROP_WL_BSSID,
    MAC_PROP_WL_BSSTYPE,
    MAC_PROP_WL_LINKSTATUS,
    MAC_PROP_WL_DESIRED_RATES,
    MAC_PROP_WL_SUPPORTED_RATES,
    MAC_PROP_WL_AUTH_MODE,
    MAC_PROP_WL_ENCRYPTION,
    MAC_PROP_WL_RSSI,
    MAC_PROP_WL_PHY_CONFIG,
    MAC_PROP_WL_CAPABILITY,
    MAC_PROP_WL_WPA,
    MAC_PROP_WL_SCANRESULTS,
    MAC_PROP_WL_POWER_MODE,
    MAC_PROP_WL_RADIO,
    MAC_PROP_WL_ESS_LIST,
    MAC_PROP_WL_KEY_TAB,
    MAC_PROP_WL_CREATE_IBSS,
    MAC_PROP_WL_SETOPTIE,
    MAC_PROP_WL_DELKEY,
    MAC_PROP_WL_KEY,
    MAC_PROP_WL_MLME,
    MAC_PROP_TAGMODE,
    MAC_PROP_ADV_10GFDX_CAP,
    MAC_PROP_EN_10GFDX_CAP,
    MAC_PROP_PVID,
    MAC_PROP_LLIMIT,
    MAC_PROP_LDECAY,
    MAC_PROP_RESOURCE,
    MAC_PROP_RESOURCE_EFF,
    MAC_PROP_RXRINGSRANGE,
    MAC_PROP_TXRINGSRANGE,
    MAC_PROP_MAX_TX_RINGS_AVAIL,
    MAC_PROP_MAX_RX_RINGS_AVAIL,
    MAC_PROP_MAX_RXHWCLNT_AVAIL,
    MAC_PROP_MAX_TXHWCLNT_AVAIL,
    MAC_PROP_IB_LINKMODE,
    MAC_PROP_VN_PROMISC_FILTERED,
    MAC_PROP_SECONDARY_ADDRS,
    MAC_PROP_ADV_40GFDX_CAP,
    MAC_PROP_EN_40GFDX_CAP,
    MAC_PROP_ADV_100GFDX_CAP,
    MAC_PROP_EN_100GFDX_CAP,
    MAC_PROP_ADV_2500FDX_CAP,
    MAC_PROP_EN_2500FDX_CAP,
    MAC_PROP_ADV_5000FDX_CAP,
    MAC_PROP_EN_5000FDX_CAP,
    MAC_PROP_ADV_25GFDX_CAP,
    MAC_PROP_EN_25GFDX_CAP,
    MAC_PROP_ADV_50GFDX_CAP,
    MAC_PROP_EN_50GFDX_CAP,
    MAC_PROP_EN_FEC_CAP,
    MAC_PROP_ADV_FEC_CAP,
}

#[repr(C)]
pub enum mac_capab_t {
    /*
     * Public Capabilities (MAC_VERSION_V1)
     */
    MAC_CAPAB_HCKSUM = 0x00000001, /* data is a uint32_t */
    MAC_CAPAB_LSO = 0x00000008,    /* data is mac_capab_lso_t */

    /*
     * Reserved capabilities, do not use
     */
    MAC_CAPAB_RESERVED1 = 0x00000002,
    MAC_CAPAB_RESERVED2 = 0x00000004,

    /*
     * Private driver capabilities
     */
    MAC_CAPAB_RINGS = 0x00000010, /* data is mac_capab_rings_t */
    MAC_CAPAB_SHARES = 0x00000020, /* data is mac_capab_share_t */
    MAC_CAPAB_MULTIFACTADDR = 0x00000040, /* mac_data_multifactaddr_t */

    /*
     * Private driver capabilities for use by the GLDv3 framework only
     */
    MAC_CAPAB_VNIC = 0x00010000, /* data is mac_capab_vnic_t */
    MAC_CAPAB_ANCHOR_VNIC = 0x00020000, /* boolean only, no data */
    MAC_CAPAB_AGGR = 0x00040000, /* data is mac_capab_aggr_t */
    MAC_CAPAB_NO_NATIVEVLAN = 0x00080000, /* boolean only, no data */
    MAC_CAPAB_NO_ZCOPY = 0x00100000, /* boolean only, no data */
    MAC_CAPAB_LEGACY = 0x00200000, /* data is mac_capab_legacy_t */
    MAC_CAPAB_VRRP = 0x00400000, /* data is mac_capab_vrrp_t */
    MAC_CAPAB_TRANSCEIVER = 0x01000000, /* mac_capab_transciever_t */
    MAC_CAPAB_LED = 0x02000000,  /* data is mac_capab_led_t */
}

#[repr(C)]
pub struct mac_register_t {
    pub m_version: c_uint,
    pub m_type_ident: *const c_char,
    pub m_driver: *mut c_void,
    pub m_dip: *mut dev_info,
    pub m_instance: c_uint,
    pub m_src_addr: *mut u8,
    pub m_dst_addr: *mut u8,
    pub m_callbacks: *mut mac_callbacks_t,
    pub m_min_sdu: c_uint,
    pub m_max_sdu: c_uint,
    pub m_pdata: *mut c_void,
    pub m_pdata_size: size_t,
    pub m_priv_props: *mut *mut c_char,
    pub m_margin: u32,
    pub m_v12n: u32,
    pub m_multicast_sdu: c_uint,
}

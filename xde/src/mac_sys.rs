// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

// stuff we need from mac

use crate::ip::in6_addr__bindgen_ty_1;
use crate::ip::in6_addr_t;
use illumos_sys_hdrs::boolean_t;
use illumos_sys_hdrs::c_char;
use illumos_sys_hdrs::c_int;
use illumos_sys_hdrs::c_uchar;
use illumos_sys_hdrs::c_uint;
use illumos_sys_hdrs::c_void;
use illumos_sys_hdrs::datalink_id_t;
use illumos_sys_hdrs::ddi_info_cmd_t;
use illumos_sys_hdrs::dev_info;
use illumos_sys_hdrs::dev_ops;
use illumos_sys_hdrs::mblk_t;
use illumos_sys_hdrs::minor_t;
use illumos_sys_hdrs::queue_t;
use illumos_sys_hdrs::size_t;
use illumos_sys_hdrs::uintptr_t;
use illumos_sys_hdrs::MAXPATHLEN;

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

pub const MAC_PROMISC_FLAGS_NO_TX_LOOP: u16 = 0x0001;

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

    pub fn mac_getinfo(
        dip: *mut dev_info,
        cmd: ddi_info_cmd_t,
        arg: *mut c_void,
        result: *mut *mut c_void,
    ) -> c_int;

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
    pub fn mac_link_flow_add(
        linkid: datalink_id_t,
        flow_name: *const c_char,
        flow_desc: *const flow_desc_t,
        mrp: *const mac_resource_props_t,
    ) -> c_int;
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

/// Networking device driver callbacks.
///
/// See `mac_callbacks(9S)`.
#[repr(C)]
pub struct mac_callbacks_t {
    /// Indicates which optional callbacks are supported by the driver.
    pub mc_callbacks: c_uint,

    /// Used to return statistics about the device.
    ///
    /// See `mac(9E)` & `mc_getstat(9E)`.
    pub mc_getstat:
        unsafe extern "C" fn(*mut c_void, c_uint, *mut u64) -> c_int,

    /// Entry point used to start a device.
    ///
    /// See `mc_start(9E)`.
    pub mc_start: unsafe extern "C" fn(*mut c_void) -> c_int,

    /// Entry point used to stop a device.
    ///
    /// See `mc_stop(9E)`.
    pub mc_stop: unsafe extern "C" fn(*mut c_void),

    /// Entry point used to enable and disable promiscuous mode.
    ///
    /// See `mc_setpromisc(9E)`.
    pub mc_setpromisc: unsafe extern "C" fn(*mut c_void, boolean_t) -> c_int,

    /// Entry point used to enable and disable filtering multicast addresses.
    ///
    /// See `mc_multicst(9E)`.
    pub mc_multicst:
        unsafe extern "C" fn(*mut c_void, boolean_t, *const u8) -> c_int,

    /// Entry point used to update the primary unicast MAC address.
    ///
    /// Must not be set if the `MAC_CAPAB_RINGS` capability is set for
    /// receive rings. See `mc_unicst(9E)`.
    pub mc_unicst:
        Option<unsafe extern "C" fn(*mut c_void, *const u8) -> c_int>,

    /// Entry point used to transmit a single message.
    ///
    /// Must not be set if the `MAC_CAPAB_RINGS` capability is set for
    /// transmit rings. See `mc_tx(9E)`.
    pub mc_tx:
        Option<unsafe extern "C" fn(*mut c_void, *mut mblk_t) -> *mut mblk_t>,

    pub mc_reserved: *mut c_void,

    /// Entry point to process device specific ioctls.
    ///
    /// Must set `MC_IOCTL` on `mc_callbacks` if non-NULL. See `mc_ioctl(9E)`.
    pub mc_ioctl:
        Option<unsafe extern "C" fn(*mut c_void, *mut queue_t, *mut mblk_t)>,

    /// Entry point used to determine device capabilities.
    ///
    /// Must set `MC_GETCAPAB` on `mc_callbacks` if non-NULL. See `mc_getcapab(9E)`.
    pub mc_getcapab: Option<
        unsafe extern "C" fn(
            *mut c_void,
            mac_capab_t,
            *mut c_void,
        ) -> boolean_t,
    >,

    /// Entry point for actions to take when a device is opened.
    ///
    /// Must set `MC_OPEN` on `mc_callbacks` if non-NULL. See `mc_open(9E)`.
    pub mc_open: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,

    /// Entry point for actions to take when a device is closed.
    ///
    /// Must set `MC_CLOSE` on `mc_callbacks` if non-NULL. See `mc_close(9E)`.
    pub mc_close: Option<unsafe extern "C" fn(*mut c_void)>,

    /// Entry point used to set a device property.
    ///
    /// Must set `MC_SETPROP` on `mc_callbacks` if non-NULL. See `mc_setprop(9E)`.
    pub mc_setprop: Option<
        unsafe extern "C" fn(
            *mut c_void,
            *const c_char,
            mac_prop_id_t,
            c_uint,
            *const c_void,
        ) -> c_int,
    >,

    /// Entry point used to get current value of a device property.
    ///
    /// Must set `MC_GETPROP` on `mc_callbacks` if non-NULL. See `mc_getprop(9E)`.
    pub mc_getprop: Option<
        unsafe extern "C" fn(
            *mut c_void,
            *const c_char,
            mac_prop_id_t,
            c_uint,
            *mut c_void,
        ) -> c_int,
    >,

    /// Entry point used to get information about a device property.
    ///
    /// Must set `MC_PROPINFO` on `mc_callbacks` if non-NULL. See `mc_propinfo(9E)`.
    pub mc_propinfo: Option<
        unsafe extern "C" fn(
            *mut c_void,
            *const c_char,
            mac_prop_id_t,
            *mut mac_prop_info_handle,
        ),
    >,
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

pub type flow_mask_t = u64;
pub const MAXMACADDR: usize = 20;

#[repr(C)]
pub struct flow_desc_t {
    pub fd_mask: flow_mask_t,
    pub fd_mac_len: u32,
    pub fd_dst_mac: [u8; MAXMACADDR],
    pub fd_src_mac: [u8; MAXMACADDR],
    pub fd_vid: u16,
    pub fd_sap: u32,
    pub fd_ipversion: u8,
    pub fd_protocol: u8,
    pub fd_local_addr: crate::ip::in6_addr_t,
    pub fd_local_netmask: crate::ip::in6_addr_t,
    pub fd_remote_addr: crate::ip::in6_addr_t,
    pub fd_remote_netmask: crate::ip::in6_addr_t,
    pub fd_local_port: crate::ip::in_port_t,
    pub fd_remote_port: crate::ip::in_port_t,
    pub fd_dsfield: u8,
    pub fd_dsfield_mask: u8,
}

#[repr(C)]
pub struct mac_resource_props_t {
    mrp_mask: u32,
    mrp_maxbw: u64,
    mrp_priority: mac_priority_level_t,
    mrp_cpus: mac_cpus_t,
    mrp_protect: mac_protect_t,
    mrp_nrxings: u32,
    mrp_ntxrings: u32,
    mrp_pool: [c_char; MAXPATHLEN],
}

pub const FLOW_LINK_DST: u64 = 0x00000001;
pub const FLOW_LINK_SRC: u64 = 0x00000002;
pub const FLOW_LINK_VID: u64 = 0x00000004;
pub const FLOW_LINK_SAP: u64 = 0x00000008;

pub const FLOW_IP_VERSION: u64 = 0x00000010;
pub const FLOW_IP_PROTOCOL: u64 = 0x00000020;
pub const FLOW_IP_LOCAL: u64 = 0x00000040;
pub const FLOW_IP_REMOTE: u64 = 0x00000080;
pub const FLOW_IP_DSFIELD: u64 = 0x00000100;

pub const FLOW_ULP_PORT_LOCAL: u64 = 0x00001000;
pub const FLOW_ULP_PORT_REMOTE: u64 = 0x00002000;

pub const MPT_MACNOSPOOF: c_int = 0x00000001;
pub const MPT_RESTRICTED: c_int = 0x00000002;
pub const MPT_IPNOSPOOF: c_int = 0x00000004;
pub const MPT_DHCPNOSPOOF: c_int = 0x00000008;
pub const MPT_ALL: c_int = 0x0000000f;
pub const MPT_RESET: c_int = -1;
pub const MPT_MAXCNT: usize = 32;
pub const MPT_MAXIPADDR: usize = MPT_MAXCNT;
pub const MPT_MAXCID: usize = MPT_MAXCNT;
pub const MPT_MAXCIDLEN: usize = 256;

pub const MRP_MAXBW: c_int = 0x00000001;
pub const MRP_CPUS: c_int = 0x00000002;
pub const MRP_CPUS_USERSPEC: c_int = 0x00000004;
pub const MRP_PRIORITY: c_int = 0x00000008;
pub const MRP_PROTECT: c_int = 0x00000010;
pub const MRP_RX_RINGS: c_int = 0x00000020;
pub const MRP_TX_RINGS: c_int = 0x00000040;
pub const MRP_RXRINGS_UNSPEC: c_int = 0x00000080;
pub const MRP_TXRINGS_UNSPEC: c_int = 0x00000100;
pub const MRP_RINGS_RESET: c_int = 0x00000200;
pub const MRP_POOL: c_int = 0x00000400;

pub const MRP_NCPUS: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub enum mac_priority_level_t {
    MPL_LOW,
    MPL_MEDIUM,
    MPL_HIGH,
    MPL_RESET,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub enum mac_cpu_mode_t {
    MCM_FANOUT = 1,
    MCM_CPUS,
}

pub const MAC_RESOURCE_PROPS_DEF: mac_resource_props_t = mac_resource_props_t {
    mrp_mask: 0,
    mrp_maxbw: 0,
    mrp_priority: mac_priority_level_t::MPL_HIGH,
    mrp_cpus: MAC_CPUS_DEF,
    mrp_protect: MAC_PROTECT_DEF,
    mrp_nrxings: 0,
    mrp_ntxrings: 0,
    mrp_pool: [0; MAXPATHLEN],
};

pub const MAC_CPUS_DEF: mac_cpus_t = mac_cpus_t {
    mc_ncpus: 0,
    mc_cpus: [0; MRP_NCPUS],
    mc_rx_fanout_cnt: 0,
    mc_rx_fanout_cpus: [0; MRP_NCPUS],
    mc_rx_pollid: 0,
    mc_rx_workerid: 0,
    mc_rx_intr_cpu: 0,
    mc_tx_fanout_cpus: [0; MRP_NCPUS],
    mc_tx_intr_cpus: mac_tx_intr_cpu_t {
        mtc_intr_cpu: [0; MRP_NCPUS],
        mtc_retargeted_cpu: [0; MRP_NCPUS],
    },
    mc_fanout_mode: mac_cpu_mode_t::MCM_FANOUT,
};

#[repr(C)]
pub struct mac_cpus_t {
    mc_ncpus: u32,
    mc_cpus: [u32; MRP_NCPUS],
    mc_rx_fanout_cnt: u32,
    mc_rx_fanout_cpus: [u32; MRP_NCPUS],
    mc_rx_pollid: u32,
    mc_rx_workerid: u32,
    mc_rx_intr_cpu: i32,
    mc_tx_fanout_cpus: [i32; MRP_NCPUS],
    mc_tx_intr_cpus: mac_tx_intr_cpu_t,
    mc_fanout_mode: mac_cpu_mode_t,
}

#[repr(C)]
pub struct mac_tx_intr_cpu_t {
    mtc_intr_cpu: [i32; MRP_NCPUS],
    mtc_retargeted_cpu: [i32; MRP_NCPUS],
}

#[repr(C)]
pub struct mac_protect_t {
    mp_types: u32,
    mp_ipaddrcnt: u32,
    mp_ipaddrs: [mac_ipaddr_t; MPT_MAXIPADDR as usize],
    mp_cidcnt: u32,
    mp_cids: [mac_dhcpcid_t; MPT_MAXCID as usize],
}

pub const MAC_PROTECT_DEF: mac_protect_t = mac_protect_t {
    mp_types: 0,
    mp_ipaddrcnt: 0,
    mp_ipaddrs: [MAC_IPADDR_DEF; MPT_MAXIPADDR],
    mp_cidcnt: 0,
    mp_cids: [MAC_DHCPCID_DEF; MPT_MAXCID],
};

#[repr(C)]
pub struct mac_ipaddr_t {
    ip_version: u32,
    ip_addr: in6_addr_t,
    ip_netmask: u8,
}

pub const MAC_IPADDR_DEF: mac_ipaddr_t =
    mac_ipaddr_t { ip_version: 0, ip_addr: IP_NO_ADDR, ip_netmask: 0 };

#[repr(C)]
pub struct mac_dhcpcid_t {
    dc_id: [c_uchar; MPT_MAXCIDLEN as usize],
    dc_len: u32,
    dc_form: mac_dhcpcid_form_t,
}

pub const MAC_DHCPCID_DEF: mac_dhcpcid_t = mac_dhcpcid_t {
    dc_id: [0; MPT_MAXCIDLEN],
    dc_len: 0,
    dc_form: mac_dhcpcid_form_t::CIDFORM_TYPED,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub enum mac_dhcpcid_form_t {
    CIDFORM_TYPED = 1,
    CIDFORM_HEX,
    CIDFORM_STR,
}

pub const IP_NO_ADDR: in6_addr_t =
    in6_addr_t { _S6_un: in6_addr__bindgen_ty_1 { _S6_u16: [0u16; 8] } };

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use core::ffi::c_int;

#[cfg(feature = "kernel")]
use crate::mblk_t;
use bitflags::bitflags;

// ======================================================================
// uts/common/sys/mac_provider.h
// ======================================================================

bitflags! {
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
/// Flags which denote the valid fields of a `mac_ether_offload_info_t`
/// or `mac_ether_tun_info_t`.
pub struct MacEtherOffloadFlags: u32 {
    /// `l2hlen` and `l3proto` are set.
    const L2INFO_SET     = 1 << 0;
    /// `l3hlen` and `l4proto` are set.
    const L3INFO_SET     = 1 << 1;
    /// `l4hlen` is set.
    const L4INFO_SET     = 1 << 2;
    /// `tunhlen` is set.
    const TUNINFO_SET    = 1 << 3;
    /// The ethernet header contains a VLAN tag.
    const VLAN_TAGGED    = 1 << 4;
    /// The packet is fragmented at L3.
    const L3_FRAGMENT    = 1 << 5;
}
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct MacTunType(u32);

impl MacTunType {
    pub const NONE: Self = Self(0);
    pub const GENEVE: Self = Self(1);
    pub const VXLAN: Self = Self(2);
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct mac_ether_offload_info_t {
    pub meoi_flags: MacEtherOffloadFlags,
    pub meoi_tuntype: MacTunType,
    pub meoi_len: u32,
    pub meoi_l2hlen: u8,
    pub meoi_l3proto: u16,
    pub meoi_l3hlen: u16,
    pub meoi_l4proto: u8,
    pub meoi_l4hlen: u8,
    pub meoi_tunhlen: u16,
}

#[cfg(feature = "kernel")]
extern "C" {
    pub fn lso_info_set(mp: *mut mblk_t, mss: u32, flags: u32);
    pub fn lso_info_cleanup(mp: *mut mblk_t);
    pub fn mac_hcksum_set(
        mp: *mut mblk_t,
        start: u32,
        stuff: u32,
        end: u32,
        value: u32,
        flags: u32,
    );
    pub fn mac_hcksum_get(
        mp: *mut mblk_t,
        start: *mut u32,
        stuff: *mut u32,
        end: *mut u32,
        value: *mut u32,
        flags: *mut u32,
    );
    pub fn mac_lso_get(mp: *mut mblk_t, mss: *mut u32, flags: *mut u32);
    pub fn mac_ether_set_pktinfo(
        mp: *mut mblk_t,
        outer_info: *const mac_ether_offload_info_t,
        inner_info: *const mac_ether_offload_info_t,
    ) -> c_int;
}

// ======================================================================
// uts/common/sys/pattr.h
// ======================================================================

bitflags! {
/// Flags which denote checksum and LSO state for an `mblk_t`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MblkOffloadFlags: u16 {
    /// Tx: IPv4 header checksum must be computer by hardware.
    const HCK_IPV4_HDRCKSUM = 1 << 0;
    /// Rx: IPv4 header checksum was verified correct by hardware.
    const HCK_IPV4_HDRCKSUM_OK = Self::HCK_IPV4_HDRCKSUM.bits();
    /// * Tx: Compute partial checksum based on start/stuff/end offsets.
    /// * Rx: Partial checksum computed and attached.
    const HCK_PARTIALCKSUM = 1 << 1;
    /// * Tx: Compute full (pseudo + l4 + payload) cksum for this packet.
    /// * Rx: Full checksum was computed in hardware, and is attached.
    const HCK_FULLCKSUM = 1 << 2;
    /// Rx: Hardware has verified that L3/L4 checksums are correct.
    const HCK_FULLCKSUM_OK = 1 << 3;
    /// Tx: Hardware must perform LSO.
    const HW_LSO = 1 << 4;

    const HCK_INNER_V4CKSUM = 1 << 5;

    const HCK_INNER_V4CKSUM_OK = 1 << 6;

    const HCK_INNER_PARTIAL = 1 << 7;

    const HCK_INNER_FULL = 1 << 8;

    const HCK_INNER_FULL_OK = 1 << 9;

    const HCK_FLAGS = Self::HCK_IPV4_HDRCKSUM.bits() |
        Self::HCK_PARTIALCKSUM.bits() | Self::HCK_FULLCKSUM.bits() |
        Self::HCK_FULLCKSUM_OK.bits() | Self::HCK_INNER_V4CKSUM.bits() |
        Self::HCK_INNER_V4CKSUM_OK.bits() | Self::HCK_INNER_PARTIAL.bits() |
        Self::HCK_INNER_FULL.bits() | Self::HCK_INNER_FULL_OK.bits();

    const HCK_TX_FLAGS = Self::HCK_IPV4_HDRCKSUM.bits() |
        Self::HCK_PARTIALCKSUM.bits() | Self::HCK_FULLCKSUM.bits() |
        Self::HCK_INNER_V4CKSUM.bits() | Self::HCK_INNER_PARTIAL.bits() |
        Self::HCK_INNER_FULL.bits();

    const HCK_OUTER_TX_FLAGS = Self::HCK_IPV4_HDRCKSUM.bits() |
        Self::HCK_PARTIALCKSUM.bits() | Self::HCK_FULLCKSUM.bits();

    const HCK_OUTER_FLAGS = Self::HCK_OUTER_TX_FLAGS.bits() |
        Self::HCK_IPV4_HDRCKSUM_OK.bits() | Self::HCK_FULLCKSUM_OK.bits();

    const HCK_INNER_TX_FLAGS = Self::HCK_INNER_V4CKSUM.bits() |
        Self::HCK_INNER_PARTIAL.bits() | Self::HCK_INNER_FULL.bits();

    const HCK_INNER_FLAGS = Self::HCK_INNER_TX_FLAGS.bits() |
        Self::HCK_INNER_V4CKSUM_OK.bits() | Self::HCK_INNER_FULL_OK.bits();

    const HW_LSO_FLAGS = Self::HW_LSO.bits();
}
}

impl MblkOffloadFlags {
    /// Move any outer offload flags to the inner layer, as part of
    /// encapsulation.
    pub fn shift_in(self) -> Self {
        let mut out =
            self.difference(Self::HCK_INNER_FLAGS.union(Self::HCK_OUTER_FLAGS));

        if self.contains(Self::HCK_IPV4_HDRCKSUM) {
            out |= Self::HCK_INNER_V4CKSUM;
        }

        if self.contains(Self::HCK_PARTIALCKSUM) {
            out |= Self::HCK_INNER_PARTIAL;
        }

        if self.contains(Self::HCK_FULLCKSUM) {
            out |= Self::HCK_INNER_FULL;
        }

        if self.contains(Self::HCK_FULLCKSUM_OK) {
            out |= Self::HCK_INNER_FULL_OK;
        }

        out
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use bitflags::bitflags;

// ======================================================================
// uts/common/sys/mac_provider.h
// ======================================================================

bitflags! {
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
/// Flags which denote the valid fields of a `mac_ether_offload_info_t`
/// or `mac_ether_tun_info_t`.
pub struct MacEtherOffloadFlags: u8 {
    /// `l2hlen` and `l3proto` are set.
    const L2INFO_SET     = 1 << 0;
    /// The ethernet header contains a VLAN tag.
    const VLAN_TAGGED    = 1 << 1;
    /// `l3hlen` and `l4proto` are set.
    const L3INFO_SET     = 1 << 2;
    /// `l4hlen` is set.
    const L4INFO_SET     = 1 << 3;
    /// `tuntype` is set.
    const TUNINFO_SET    = 1 << 4;
}
}

// ======================================================================
// uts/common/sys/pattr.h
// ======================================================================

bitflags! {
/// Flags which denote checksum and LSO state for an `mblk_t`.
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
    /// Tx: Hardware must compute all checksum for the outer tunnel
    /// encapsulation of this packet.
    const HCK_FULLOUTERCKSUM = 1 << 5;

    const HCK_FLAGS = Self::HCK_IPV4_HDRCKSUM.bits() |
        Self::HCK_PARTIALCKSUM.bits() | Self::HCK_FULLCKSUM.bits() |
        Self::HCK_FULLCKSUM_OK.bits() | Self::HCK_FULLOUTERCKSUM.bits();

    const HCK_TX_FLAGS = Self::HCK_IPV4_HDRCKSUM.bits() |
        Self::HCK_PARTIALCKSUM.bits() | Self::HCK_FULLCKSUM.bits() |
        Self::HCK_FULLOUTERCKSUM.bits();

    const HW_LSO_FLAGS = Self::HW_LSO.bits();
}
}

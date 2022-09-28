// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Types for working with the IPv6 Neighbor Discovery Protocol

use super::Ipv6Addr;
use super::MacAddr;
use core::fmt;
use core::fmt::Debug;
use core::fmt::Display;

/// A Neighbor Discovery Protocol Router Advertisement, generated in response to
/// a Router Solicitation.
#[derive(Clone, Copy, Debug)]
pub struct RouterAdvertisement {
    /// The expected MAC address of the client whose Router Solicitations we
    /// respond to.
    pub src_mac: MacAddr,

    /// The MAC address advertised by the router.
    pub mac: MacAddr,

    // The IPv6 address advertised by the router, which is the EUI-64 transform
    // of the router MAC address.
    ip: Ipv6Addr,

    /// Managed address configuration, indicating that the peer can use DHCPv6
    /// to acquire an IPv6 address.
    pub managed_cfg: bool,
}

impl RouterAdvertisement {
    /// Create new `RouterAdvertisement`.
    ///
    /// The `src_mac` is the expected source MAC address a Router Solicitation
    /// should come from. There are no restrictions on the source IP address,
    /// other than that it be link-local, in `fe80::/10`.
    ///
    /// `mac` is the MAC address of the router, to which Solicitations are
    /// expected to be addressed, and from which Advertisements are sent. The
    /// source IPv6 address of the Advertisement is derived from this, using the
    /// EUI-64 transform.
    ///
    /// `managed_cfg` is set to `true` to indicate that the host can get further
    /// configuration from a DHCPv6 server running on the network.
    pub fn new(src_mac: MacAddr, mac: MacAddr, managed_cfg: bool) -> Self {
        let ip = Ipv6Addr::from_eui64(&mac);
        Self { src_mac, mac, ip, managed_cfg }
    }

    /// Return the IPv6 address the router sends advertisements from.
    pub fn ip(&self) -> &Ipv6Addr {
        &self.ip
    }
}

impl Display for RouterAdvertisement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NDP RA IPv6={} MAC={}", self.ip, self.mac)
    }
}

/// A Neighbor Discovery Protocol Neighbor Advertisement, generated in response to
/// a Neighbor Solicitation.
#[derive(Clone, Copy, Debug)]
pub struct NeighborAdvertisement {
    /// The expected MAC address of the client whose Neighbor Solicitations we
    /// respond to.
    pub src_mac: MacAddr,

    /// The MAC address advertised by the neighbor.
    pub mac: MacAddr,

    // The advertised IPv6 address of the neighbor, which is the EUI-64
    // transform of the source MAC address, in `mac`.
    ip: Ipv6Addr,

    /// If true, advertise that this neighbor is a router.
    pub is_router: bool,

    /// If true, respond to Neighbor Solicitations sent from the unspecified
    /// address `::`, in addition to those from a link-local address
    /// `fe80::/10`.
    pub allow_unspec: bool,
}

impl NeighborAdvertisement {
    /// Create new `NeighborAdvertisement`.
    ///
    /// The `src_mac` is the expected source MAC address a Neighbor Solicitation
    /// should come from. There are no restrictions on the source IP address,
    /// other than that it be link-local, in `fe80::/10`.
    ///
    /// `mac` is the MAC address of the neighbor, to which Solicitations are
    /// expected to be addressed, and from which Advertisements are sent. The
    /// source IPv6 address of the Advertisement is derived from this, using the
    /// EUI-64 transform.
    ///
    /// `is_router` is `true` if the advert should be marked as coming from a
    /// router.
    ///
    /// `allow_unspec` is `true` if the advertisement is generated in response
    /// to Neigbor Solicitations from the unspecified address.
    pub fn new(
        src_mac: MacAddr,
        mac: MacAddr,
        is_router: bool,
        allow_unspec: bool,
    ) -> Self {
        let ip = Ipv6Addr::from_eui64(&mac);
        Self { src_mac, mac, ip, is_router, allow_unspec }
    }

    /// Return the IPv6 address the neighbor sends advertisements from.
    pub fn ip(&self) -> &Ipv6Addr {
        &self.ip
    }
}

impl Display for NeighborAdvertisement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NDP NA IPv6={} MAC={}", self.ip, self.mac)
    }
}

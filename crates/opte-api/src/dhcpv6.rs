// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Types for working with the DHCPv6

use crate::DomainName;
use crate::Ipv6Addr;
use crate::MacAddr;
use core::fmt;
use core::fmt::Display;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::vec::Vec;
        use alloc::string::String;
    } else {
        use std::vec::Vec;
        use std::string::String;
    }
}

/// An action for acting as a DHCPv6 server, leasing IPv6 addresses.
#[derive(Clone, Debug)]
pub struct Dhcpv6Action {
    /// Expected MAC address of the client.
    pub client_mac: MacAddr,

    /// MAC address we advertise as the DHCP server.
    pub server_mac: MacAddr,

    /// IPv6 addresses leased to the client.
    pub addrs: AddressInfo,

    /// DNS servers the client should use.
    pub dns_servers: Vec<Ipv6Addr>,

    /// SNTP servers the client should use.
    pub sntp_servers: Vec<Ipv6Addr>,

    /// A list of domain names used during DNS resolution.
    pub domain_list: Vec<DomainName>,
}

impl Dhcpv6Action {
    /// Return an iterator over the actual leased IPv6 addresses.
    pub fn addresses(&self) -> impl Iterator<Item = Ipv6Addr> + '_ {
        self.addrs.addrs.iter().map(|lease| lease.addr)
    }
}

impl Display for Dhcpv6Action {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let addr_list = self
            .addresses()
            .map(|addr| format!("{}", addr))
            .collect::<Vec<_>>()
            .join(",");
        write!(f, "DHCPv6 IA Addrs: [{}]", addr_list)
    }
}

/// A single leased IPv6 address, with associated lifetime.
#[derive(Clone, Copy, Debug)]
pub struct LeasedAddress {
    /// The leased address.
    pub addr: Ipv6Addr,

    // The preferred lifetime for this address.
    preferred: u32,

    // The maximum valid lifetime for this address.
    valid: u32,
}

impl LeasedAddress {
    /// Construct an address lease with infinite lifetime.
    pub fn infinite_lease(addr: Ipv6Addr) -> Self {
        Self { addr, preferred: u32::MAX, valid: u32::MAX }
    }

    /// Construct a new leased address with checked lifetimes, in seconds.
    ///
    /// The preferred lifetime must be no longer than the valid lifetime.
    pub fn new(
        addr: Ipv6Addr,
        preferred: u32,
        valid: u32,
    ) -> Result<Self, String> {
        if valid < preferred {
            return Err(String::from(
                "Preferred lifetime must be <= valid lifetime",
            ));
        }
        Ok(Self { addr, preferred, valid })
    }

    /// Return the valid lifetime, in seconds.
    pub fn valid(&self) -> u32 {
        self.valid
    }

    /// Return the preferred lifetime, in seconds.
    pub fn preferred(&self) -> u32 {
        self.preferred
    }
}

/// Information about IPv6 addresses leased by OPTE.
#[derive(Clone, Debug)]
pub struct AddressInfo {
    /// The set of addresses OPTE will lease.
    pub addrs: Vec<LeasedAddress>,
    /// The time (in seconds) after which the client should renew the lease.
    ///
    /// NOTE: This is used as both T1 and T2 in a Non-Temporary Address
    /// Assignment.
    pub renew: u32,
}

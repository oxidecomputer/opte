// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! The Oxide VPC Network.
//!
//! This module contains configuration that is specific to the "Oxide
//! VPC Network"; the guest overlay network that we implement on an
//! Oxide Rack. OPTE itself is a generic engine for performing packet
//! transformations in a flow-centric manner. While it does provide
//! primitve building blocks for implementing network functions, like
//! rules and header transpositions, it does not dictate a specific
//! network configuration. This module configures OPTE in a manner
//! consistent with the definition of The Oxide VPC Network [^rfd21]
//! [^rfd63].
//!
//! This should probably be in its own crate, separate from OPTE
//! itself. For now keeping it here is convenient.
//!
//! [rfd21]: [RFD 21 User Networking
//! API](https://rfd.shared.oxide.computer/rfd/0063)
//!
//! [rfd63]: [RFD 63 Network
//! Architecture](https://rfd.shared.oxide.computer/rfd/0063)
#![no_std]

// NOTE: Things get weird if you move the extern crate into cfg_if!.
#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[cfg(all(not(feature = "std"), not(test)))]
#[macro_use]
extern crate alloc;

#[macro_use]
extern crate cfg_if;

#[cfg(any(feature = "api", test))]
pub mod api;

cfg_if! {
    if #[cfg(any(feature = "engine", test))] {
        use opte::api::{Ipv4Addr, Ipv4Cidr, Ipv6Addr, MacAddr, Vni};
        use crate::api::{PhysNet, SNatCfg};

        pub mod engine;

        // TODO Tease out generic PortCfg.
        #[derive(Clone, Debug)]
        pub struct VpcCfg {
            pub vpc_subnet: Ipv4Cidr,
            pub private_mac: MacAddr,
            pub private_ip: Ipv4Addr,
            pub gw_mac: MacAddr,
            pub gw_ip: Ipv4Addr,
            // XXX For now we limit to one external IP.
            pub external_ips_v4: Option<Ipv4Addr>,
            pub snat: Option<SNatCfg>,
            pub vni: Vni,
            pub phys_ip: Ipv6Addr,
            pub bsvc_addr: PhysNet,
            // XXX-EXT-IP the follow two fields are for the external IP hack.
            pub proxy_arp_enable: bool,
            pub phys_gw_mac: Option<MacAddr>,
        }
    }
}

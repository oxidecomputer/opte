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
#[cfg(any(feature = "api", test))]
pub mod api;

cfg_if! {
    if #[cfg(any(feature = "engine", test))] {
        use core::ops::Range;
        use crate::api::{Ipv4Addr, Ipv6Addr, MacAddr, Vni};
        use crate::engine::vpc::VpcSubnet4;
        use crate::oxide_vpc::api::PhysNet;

        pub mod engine;

        #[derive(Clone, Debug)]
        pub struct DynNat4Cfg {
            pub public_ip: Ipv4Addr,
            pub ports: Range<u16>,
        }

        // TODO Rename to VpcCfg, tease out generic PortCfg.
        #[derive(Clone, Debug)]
        pub struct PortCfg {
            pub vpc_subnet: VpcSubnet4,
            pub private_mac: MacAddr,
            pub private_ip: Ipv4Addr,
            pub gw_mac: MacAddr,
            pub gw_ip: Ipv4Addr,
            pub dyn_nat: DynNat4Cfg,
            pub vni: Vni,
            pub phys_ip: Ipv6Addr,
            pub bsvc_addr: PhysNet,
        }
    }
}

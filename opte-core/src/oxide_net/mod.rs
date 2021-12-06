//! The Oxide Network configuration.
//!
//! This module contains configuration that is specific to the "Oxide
//! Network" -- i.e., the underlay/overlay that we implement on an
//! Oxide Rack. OPTE itself is a generic engine for performing packet
//! transformations in a flow-centric manner. While it does provide
//! primitve building blocks for implementing network functions, like
//! rules and header transpositions, it does not dictate a specific
//! network configuration. This module configures OPTE in a manner
//! consistent with the definition of The Oxide Network [^rfd63].
//!
//! This should probably be in its own crate, separate from OPTE
//! itself. For now keeping it here is convenient.
//!
//! [rfd63]: [RFD 63 Network
//! Architecture](https://rfd.shared.oxide.computer/rfd/0063)
use std::ops::Range;

use crate::ether::EtherAddr;
use crate::ip4::Ipv4Addr;
use crate::vpc::VpcSubnet4;

pub mod arp;
pub mod dyn_nat4;
pub mod firewall;

#[derive(Clone, Debug)]
pub struct DynNat4Config {
    pub public_mac: EtherAddr,
    pub public_ip: Ipv4Addr,
    pub ports: Range<u16>,
}

#[derive(Clone, Debug)]
pub struct PortConfig {
    pub vpc_subnet: VpcSubnet4,
    pub private_mac: EtherAddr,
    pub private_ip: Ipv4Addr,
    pub gw_mac: EtherAddr,
    pub gw_ip: Ipv4Addr,
    pub dyn_nat: DynNat4Config,
}
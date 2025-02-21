// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! ARP headers and data.

use super::ether::Ethernet;
use crate::ddi::mblk::MsgBlk;
use core::fmt;
use core::fmt::Display;
use ingot::Ingot;
use ingot::ethernet::Ethertype;
use ingot::types::NetworkRepr;
use ingot::types::primitives::u16be;
use opte_api::Ipv4Addr;
use opte_api::MacAddr;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::ByteSlice;

pub const ARP_HTYPE_ETHERNET: u16 = 1;

#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    Hash,
)]
pub struct ArpOp(u16);

impl ArpOp {
    pub const REQUEST: Self = Self(1);
    pub const REPLY: Self = Self(2);
}

impl Default for ArpOp {
    fn default() -> Self {
        Self::REQUEST
    }
}

impl Display for ArpOp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match *self {
            ArpOp::REQUEST => "Request",
            ArpOp::REPLY => "Reply",
            _ => "Unknown",
        };
        write!(f, "{}", s)
    }
}

impl NetworkRepr<zerocopy::U16<zerocopy::BigEndian>> for ArpOp {
    fn to_network(self) -> zerocopy::U16<zerocopy::BigEndian> {
        self.0.into()
    }

    fn from_network(val: zerocopy::U16<zerocopy::BigEndian>) -> Self {
        Self(val.into())
    }
}

/// Generate an ARP reply from SHA/SPA to THA/TPA.
pub fn gen_arp_reply(
    sha: MacAddr,
    spa: Ipv4Addr,
    tha: MacAddr,
    tpa: Ipv4Addr,
) -> MsgBlk {
    MsgBlk::new_ethernet_pkt((
        Ethernet { destination: tha, source: sha, ethertype: Ethertype::ARP },
        ArpEthIpv4 {
            op: ArpOp::REPLY,
            sha,
            spa,
            tha,
            tpa,
            ..Default::default()
        },
    ))
}

/// An ARP packet containing Ethernet (MAC) to IPv4 address mappings.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct ArpEthIpv4 {
    #[ingot(default = ARP_HTYPE_ETHERNET)]
    pub htype: u16be,
    #[ingot(default = Ethertype::IPV4, is = "u16be")]
    pub ptype: Ethertype,
    #[ingot(default = size_of::<MacAddr>() as u8)]
    pub hlen: u8,
    #[ingot(default = size_of::<Ipv4Addr>() as u8)]
    pub plen: u8,

    #[ingot(is = "u16be")]
    pub op: ArpOp,

    #[ingot(is = "[u8; 6]")]
    pub sha: MacAddr,
    #[ingot(is = "[u8; 4]")]
    pub spa: Ipv4Addr,

    #[ingot(is = "[u8; 6]")]
    pub tha: MacAddr,
    #[ingot(is = "[u8; 4]")]
    pub tpa: Ipv4Addr,
}

impl<V: ByteSlice> ValidArpEthIpv4<V> {
    pub fn values_valid(&self) -> bool {
        self.htype() == ARP_HTYPE_ETHERNET
            && self.ptype() == Ethertype::IPV4
            && self.hlen() == (size_of::<MacAddr>() as u8)
            && self.plen() == (size_of::<Ipv4Addr>() as u8)
            && (self.op() == ArpOp::REQUEST || self.op() == ArpOp::REPLY)
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

pub use opte_api::*;

use core::fmt::Display;
use core::fmt::{self};
#[cfg(feature = "engine")]
use core::hash::Hash;
#[cfg(feature = "engine")]
use crc32fast::Hasher;
use ingot::icmp::IcmpV4Type;
use ingot::icmp::IcmpV6Type;
use ingot::ip::IpProtocol;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

const AF_INET: i32 = 2;
const AF_INET6: i32 = 26;

pub static FLOW_ID_DEFAULT: InnerFlowId = InnerFlowId {
    proto: 255,
    addrs: AddrPair::V4 { src: Ipv4Addr::ANY_ADDR, dst: Ipv4Addr::ANY_ADDR },
    proto_info: [0u16; 2],
};

/// The flow identifier.
///
/// In this case the flow identifier is the 5-tuple of the inner IP
/// packet.
///
/// NOTE: This should not be defined in `opte`. Rather, the engine
/// should be generic in regards to the flow identifier, and it should
/// be up to the `NetworkImpl` to define it.
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[repr(C, align(4))]
pub struct InnerFlowId {
    // Using a `u8` here for `proto` hides the enum repr from SDTs.
    pub proto: u8,
    // We could also theoretically get to a 38B packing if we reduce
    // AddrPair's repr from `u16` to `u8`. However, on the dtrace/illumos
    // side `union addrs` is 4B aligned -- in6_addr_t has a 4B alignment.
    // So, this layout has to match that constraint -- placing addrs at
    // offset 0x2 with `u16` discriminant sets up 4B alignment for the
    // enum variant data (and this struct itself is 4B aligned).
    pub addrs: AddrPair,
    pub proto_info: [u16; 2],
}

impl Default for InnerFlowId {
    fn default() -> Self {
        FLOW_ID_DEFAULT
    }
}

pub enum L4Info<'a> {
    Ports(&'a PortInfo),
    Icmpv4(&'a Icmpv4Info),
    Icmpv6(&'a Icmpv6Info),
}

pub enum L4InfoMut<'a> {
    Ports(&'a mut PortInfo),
    Icmpv4(&'a mut Icmpv4Info),
    Icmpv6(&'a mut Icmpv6Info),
}

#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    FromBytes,
    Hash,
    Immutable,
    IntoBytes,
    KnownLayout,
    Ord,
    PartialEq,
    PartialOrd,
)]
#[repr(C)]
pub struct PortInfo {
    pub src_port: u16,
    pub dst_port: u16,
}

impl Into<[u16; 2]> for PortInfo {
    fn into(self) -> [u16; 2] {
        zerocopy::transmute!(self)
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    FromBytes,
    Hash,
    Immutable,
    IntoBytes,
    KnownLayout,
    Ord,
    PartialEq,
    PartialOrd,
)]
#[repr(C)]
pub struct IcmpInfo {
    // TODO: it seems *very* hard to convince the zerocopy derives
    // that this can safely be anrbitrary `Type`, when we know that is
    // either IcmpV4Type or IcmpV6Type without making this `packed`.
    pub ty: u8,
    pub code: u8,
    pub id: u16,
}

pub type Icmpv4Info = IcmpInfo; //<IcmpV4Type>;
pub type Icmpv6Info = IcmpInfo; //<IcmpV6Type>;

// impl Icmpv4Info {
//     pub fn echo_id(&self) -> Option<u16> {
//         match self.ty {
//             IcmpV4Type::ECHO_REQUEST | IcmpV4Type::ECHO_REPLY => Some(self.id),
//             _ => None,
//         }
//     }
// }

impl Into<[u16; 2]> for Icmpv4Info {
    fn into(self) -> [u16; 2] {
        zerocopy::transmute!(self)
    }
}

// impl Icmpv6Info {
//     pub fn echo_id(&self) -> Option<u16> {
//         match self.ty {
//             IcmpV6Type::ECHO_REQUEST | IcmpV6Type::ECHO_REPLY => Some(self.id),
//             _ => None,
//         }
//     }
// }

// impl Into<[u16; 2]> for Icmpv6Info {
//     fn into(self) -> [u16; 2] {
//         zerocopy::transmute!(self)
//     }
// }

/// Tagged union of a source-dest IP address pair, used to avoid
/// duplicating the discriminator.
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[repr(C, u16)]
pub enum AddrPair {
    V4 { src: Ipv4Addr, dst: Ipv4Addr } = AF_INET as u16,
    V6 { src: Ipv6Addr, dst: Ipv6Addr } = AF_INET6 as u16,
}

impl AddrPair {
    pub fn mirror(self) -> Self {
        match self {
            Self::V4 { src, dst } => Self::V4 { src: dst, dst: src },
            Self::V6 { src, dst } => Self::V6 { src: dst, dst: src },
        }
    }
}

impl InnerFlowId {
    /// Swap IP source and destination as well as ULP port source and
    /// destination.
    pub fn mirror(self) -> Self {
        let proto_info = match self.l4_info() {
            Some(L4Info::Ports(p)) => {
                PortInfo { src_port: p.dst_port, dst_port: p.src_port }.into()
            }
            Some(L4Info::Icmpv4(v4)) if v4.code == 0 => Icmpv4Info {
                ty: match IcmpV4Type(v4.ty) {
                    IcmpV4Type::ECHO_REQUEST => IcmpV4Type::ECHO_REPLY,
                    IcmpV4Type::ECHO_REPLY => IcmpV4Type::ECHO_REQUEST,
                    a => a,
                }
                .0,
                ..*v4
            }
            .into(),
            Some(L4Info::Icmpv6(v6)) if v6.code == 0 => Icmpv6Info {
                ty: match IcmpV6Type(v6.ty) {
                    IcmpV6Type::ECHO_REQUEST => IcmpV6Type::ECHO_REPLY,
                    IcmpV6Type::ECHO_REPLY => IcmpV6Type::ECHO_REQUEST,
                    a => a,
                }
                .0,
                ..*v6
            }
            .into(),
            _ => self.proto_info,
        };

        Self { proto: self.proto, addrs: self.addrs.mirror(), proto_info }
    }

    pub fn src_ip(&self) -> IpAddr {
        match self.addrs {
            AddrPair::V4 { src, .. } => src.into(),
            AddrPair::V6 { src, .. } => src.into(),
        }
    }

    pub fn dst_ip(&self) -> IpAddr {
        match self.addrs {
            AddrPair::V4 { dst, .. } => dst.into(),
            AddrPair::V6 { dst, .. } => dst.into(),
        }
    }

    pub fn protocol(&self) -> Protocol {
        Protocol::from(self.proto)
    }

    pub fn l4_info(&self) -> Option<L4Info<'_>> {
        match IpProtocol(self.proto) {
            IpProtocol::ICMP => {
                Some(L4Info::Icmpv4(zerocopy::transmute_ref!(&self.proto_info)))
            }
            IpProtocol::ICMP_V6 => {
                Some(L4Info::Icmpv6(zerocopy::transmute_ref!(&self.proto_info)))
            }
            IpProtocol::TCP | IpProtocol::UDP => {
                Some(L4Info::Ports(zerocopy::transmute_ref!(&self.proto_info)))
            }
            _ => None,
        }
    }

    pub fn l4_info_mut(&mut self) -> Option<L4InfoMut<'_>> {
        match IpProtocol(self.proto) {
            IpProtocol::ICMP => Some(L4InfoMut::Icmpv4(
                zerocopy::transmute_mut!(&mut self.proto_info),
            )),
            IpProtocol::ICMP_V6 => Some(L4InfoMut::Icmpv6(
                zerocopy::transmute_mut!(&mut self.proto_info),
            )),
            IpProtocol::TCP | IpProtocol::UDP => Some(L4InfoMut::Ports(
                zerocopy::transmute_mut!(&mut self.proto_info),
            )),
            _ => None,
        }
    }

    #[cfg(feature = "engine")]
    pub fn crc32(&self) -> u32 {
        let mut hasher = Hasher::new();
        self.hash(&mut hasher);
        hasher.finalize()
    }
}

impl Display for InnerFlowId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO: different presentation for different kinds?
        write!(
            f,
            "{}:{}:{}:{}:{}",
            self.protocol(),
            self.src_ip(),
            self.proto_info[0],
            self.dst_ip(),
            self.proto_info[1],
        )
    }
}

// Convenience `Dump` types while `InnerFlowId` is the only flowkey allowed.
pub type DumpLayerResp = opte_api::DumpLayerResp<InnerFlowId>;
pub type DumpUftResp = opte_api::DumpUftResp<InnerFlowId>;
pub type DumpTcpFlowsResp = opte_api::DumpTcpFlowsResp<InnerFlowId>;
pub type TcpFlowEntryDump = opte_api::TcpFlowEntryDump<InnerFlowId>;

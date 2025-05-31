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
    Icmpv4(&'a IcmpInfo),
    Icmpv6(&'a IcmpInfo),
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

impl From<PortInfo> for [u16; 2] {
    fn from(val: PortInfo) -> [u16; 2] {
        zerocopy::transmute!(val)
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
    // This is an untyped `u8`, because it seems *very* hard to convince the
    // zerocopy derives that this can safely be an arbitrary `Type`, when we know
    // that is fundamentally a `u8` (either IcmpV4Type or IcmpV6Type) without
    // making the struct `packed`. That then makes us unable to pull `id` out
    // from a `&IcmpInfo`. `PhantomData<Ty>` fails similarly.
    // Expressing this would make it easier to constrain the validity of echo_id.
    pub ty: u8,
    pub code: u8,
    pub id: u16,
}

impl From<IcmpInfo> for [u16; 2] {
    fn from(val: IcmpInfo) -> [u16; 2] {
        zerocopy::transmute!(val)
    }
}

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
            Some(L4Info::Icmpv4(v4)) if v4.code == 0 => IcmpInfo {
                ty: match IcmpV4Type(v4.ty) {
                    IcmpV4Type::ECHO_REQUEST => IcmpV4Type::ECHO_REPLY,
                    IcmpV4Type::ECHO_REPLY => IcmpV4Type::ECHO_REQUEST,
                    a => a,
                }
                .0,
                ..*v4
            }
            .into(),
            Some(L4Info::Icmpv6(v6)) if v6.code == 0 => IcmpInfo {
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

    #[cfg(feature = "engine")]
    pub fn crc32(&self) -> u32 {
        let mut hasher = Hasher::new();
        self.hash(&mut hasher);
        hasher.finalize()
    }
}

impl Display for InnerFlowId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let proto = self.protocol();
        let sip = self.src_ip();
        let dip = self.dst_ip();

        match self.l4_info() {
            Some(L4Info::Ports(info)) => write!(
                f,
                "{proto}:{sip}:{}:{dip}:{}",
                info.src_port, info.dst_port
            ),
            Some(L4Info::Icmpv4(info)) => write!(
                f,
                "{proto}/{}/{}:{sip}:{dip}:{}",
                info.ty, info.code, info.id
            ),
            Some(L4Info::Icmpv6(info)) => write!(
                f,
                "{proto}/{}/{}:{sip}:{dip}:{}",
                info.ty, info.code, info.id
            ),
            None => write!(f, "{proto}:{sip}:{dip}"),
        }
    }
}

// Convenience `Dump` types while `InnerFlowId` is the only flowkey allowed.
pub type DumpLayerResp = opte_api::DumpLayerResp<InnerFlowId>;
pub type DumpUftResp = opte_api::DumpUftResp<InnerFlowId>;
pub type DumpTcpFlowsResp = opte_api::DumpTcpFlowsResp<InnerFlowId>;
pub type TcpFlowEntryDump = opte_api::TcpFlowEntryDump<InnerFlowId>;

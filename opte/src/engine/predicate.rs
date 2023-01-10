// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Predicates used for `Rule` matching.

use super::dhcp::MessageType as DhcpMessageType;
use super::dhcpv6::MessageType as Dhcpv6MessageType;
use super::ether::EtherType;
use super::headers::IpMeta;
use super::headers::UlpMeta;
use super::icmp::MessageType as IcmpMessageType;
use super::icmpv6::MessageType as Icmpv6MessageType;
use super::ip4::Ipv4Addr;
use super::ip4::Ipv4Cidr;
use super::ip4::Ipv4Meta;
use super::ip4::Protocol;
use super::ip6::Ipv6Addr;
use super::ip6::Ipv6Cidr;
use super::ip6::Ipv6Meta;
use super::packet::PacketMeta;
use super::packet::PacketRead;
use super::port::meta::ActionMeta;
use super::tcp::TcpMeta;
use super::udp::UdpMeta;
use core::fmt;
use core::fmt::Display;
use opte_api::MacAddr;
use serde::Deserialize;
use serde::Serialize;
use smoltcp::phy::ChecksumCapabilities as Csum;
use smoltcp::wire;
use smoltcp::wire::DhcpPacket;
use smoltcp::wire::DhcpRepr;
use smoltcp::wire::Icmpv4Packet;
use smoltcp::wire::Icmpv4Repr;
use smoltcp::wire::Icmpv6Packet;
use smoltcp::wire::Icmpv6Repr;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::boxed::Box;
        use alloc::string::{String, ToString};
        use alloc::vec::Vec;
    } else {
        use std::boxed::Box;
        use std::string::{String, ToString};
        use std::vec::Vec;
    }
}

/// A marker trait for types that can be matched exactly, usually by direct
/// equality comparison.
pub trait MatchExactVal {}

/// Trait support matching a value exactly, usually by direct equality
/// comparison.
pub trait MatchExact<M: MatchExactVal + Eq + PartialEq> {
    fn match_exact(&self, val: &M) -> bool;
}

/// A marker trait for types that can be match by prefix.
pub trait MatchPrefixVal {}

/// A trait describing how to match data by prefix.
pub trait MatchPrefix<M: MatchPrefixVal> {
    fn match_prefix(&self, prefix: &M) -> bool;
}

/// A marker trait for types that can match a range of values.
pub trait MatchRangeVal {}

/// A trait describing how to match data over a range of values.
pub trait MatchRange<M: MatchRangeVal> {
    fn match_range(&self, start: &M, end: &M) -> bool;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EtherTypeMatch {
    Exact(u16),
}

impl EtherTypeMatch {
    fn matches(&self, flow_et: EtherType) -> bool {
        match self {
            EtherTypeMatch::Exact(et) => u16::from(flow_et) == *et,
        }
    }
}

impl Display for EtherTypeMatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use crate::engine::ether::*;
        use EtherTypeMatch::*;

        match self {
            // Print known EtherTypes by name
            Exact(et) if *et == ETHER_TYPE_ARP => write!(f, "ARP"),
            Exact(et) if *et == ETHER_TYPE_ETHER => write!(f, "ETHER"),
            Exact(et) if *et == ETHER_TYPE_IPV4 => write!(f, "IPv4"),
            Exact(et) if *et == ETHER_TYPE_IPV6 => write!(f, "IPv6"),

            Exact(et) => write!(f, "0x{:X}", et),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EtherAddrMatch {
    Exact(MacAddr),
}

impl EtherAddrMatch {
    fn matches(&self, flow_addr: MacAddr) -> bool {
        match self {
            EtherAddrMatch::Exact(addr) => flow_addr == *addr,
        }
    }
}

impl Display for EtherAddrMatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use EtherAddrMatch::*;

        match self {
            Exact(addr) => write!(f, "{}", addr),
        }
    }
}

/// Describe how to match an IPv4 address
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Ipv4AddrMatch {
    /// Match an exact address
    Exact(Ipv4Addr),
    /// Match an address in the same CIDR block
    Prefix(Ipv4Cidr),
}

impl Ipv4AddrMatch {
    fn matches(&self, flow_ip: Ipv4Addr) -> bool {
        match self {
            Self::Exact(ip) => flow_ip.match_exact(ip),
            Self::Prefix(cidr) => flow_ip.match_prefix(cidr),
        }
    }
}

impl Display for Ipv4AddrMatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Ipv4AddrMatch::*;

        match self {
            Exact(ip) => write!(f, "{}", ip),
            Prefix(cidr) => write!(f, "{}", cidr),
        }
    }
}

/// Describe how to match an IPv6 address
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Ipv6AddrMatch {
    /// Match an exact address
    Exact(Ipv6Addr),
    /// Match an address in the same CIDR block
    Prefix(Ipv6Cidr),
}

impl Ipv6AddrMatch {
    fn matches(&self, flow_ip: Ipv6Addr) -> bool {
        match self {
            Self::Exact(ip) => flow_ip.match_exact(ip),
            Self::Prefix(cidr) => flow_ip.match_prefix(cidr),
        }
    }
}

impl Display for Ipv6AddrMatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Ipv6AddrMatch::*;

        match self {
            Exact(ip) => write!(f, "{}", ip),
            Prefix(cidr) => write!(f, "{}", cidr),
        }
    }
}

#[derive(Clone, Debug, Eq, Deserialize, PartialEq, Serialize)]
pub enum IpProtoMatch {
    Exact(Protocol),
}

impl IpProtoMatch {
    fn matches(&self, flow_proto: Protocol) -> bool {
        match self {
            Self::Exact(proto) => flow_proto == *proto,
        }
    }
}

impl Display for IpProtoMatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use IpProtoMatch::*;

        match self {
            Exact(proto) => write!(f, "{}", proto),
        }
    }
}

impl MatchExactVal for u16 {}

impl MatchExact<u16> for u16 {
    fn match_exact(&self, val: &u16) -> bool {
        *self == *val
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PortMatch {
    Exact(u16),
}

impl PortMatch {
    fn matches(&self, flow_port: u16) -> bool {
        match self {
            Self::Exact(port) => flow_port.match_exact(port),
        }
    }
}

impl Display for PortMatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use PortMatch::*;

        match self {
            Exact(port) => write!(f, "{}", port),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Predicate {
    InnerEtherType(Vec<EtherTypeMatch>),
    InnerEtherDst(Vec<EtherAddrMatch>),
    InnerEtherSrc(Vec<EtherAddrMatch>),
    InnerSrcIp4(Vec<Ipv4AddrMatch>),
    InnerDstIp4(Vec<Ipv4AddrMatch>),
    InnerSrcIp6(Vec<Ipv6AddrMatch>),
    InnerDstIp6(Vec<Ipv6AddrMatch>),
    InnerIpProto(Vec<IpProtoMatch>),
    InnerSrcPort(Vec<PortMatch>),
    InnerDstPort(Vec<PortMatch>),
    Not(Box<Predicate>),
    Meta(String, String),
}

impl Display for Predicate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Predicate::*;

        match self {
            InnerEtherType(list) => {
                let s = list
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                write!(f, "inner.ether.ether_type={}", s)
            }

            InnerEtherDst(list) => {
                let s = list
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                write!(f, "inner.ether.dst={}", s)
            }

            InnerEtherSrc(list) => {
                let s = list
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                write!(f, "inner.ether.src={}", s)
            }

            InnerIpProto(list) => {
                let s = list
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                write!(f, "inner.ip.proto={}", s)
            }

            InnerSrcIp4(list) => {
                let s = list
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                write!(f, "inner.ip.src={}", s)
            }

            InnerDstIp4(list) => {
                let s = list
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                write!(f, "inner.ip.dst={}", s)
            }

            InnerSrcIp6(list) => {
                let s = list
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                write!(f, "inner.ip6.src={}", s)
            }

            InnerDstIp6(list) => {
                let s = list
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                write!(f, "inner.ip6.dst={}", s)
            }

            InnerSrcPort(list) => {
                let s = list
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                write!(f, "inner.ulp.src={}", s)
            }

            InnerDstPort(list) => {
                let s = list
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                write!(f, "inner.ulp.dst={}", s)
            }

            Meta(key, val) => {
                write!(f, "meta: {}={}", key, val)
            }

            Not(pred) => {
                write!(f, "!")?;
                Display::fmt(&pred, f)
            }
        }
    }
}

impl Predicate {
    pub(crate) fn is_match(
        &self,
        meta: &PacketMeta,
        action_meta: &ActionMeta,
    ) -> bool {
        match self {
            Self::Meta(key, pred_val) => {
                if let Some(meta_val) = action_meta.get(key) {
                    return pred_val == meta_val;
                }

                return false;
            }

            Self::Not(pred) => return !pred.is_match(meta, action_meta),

            Self::InnerEtherType(list) => {
                for m in list {
                    if m.matches(meta.inner.ether.ether_type) {
                        return true;
                    }
                }
            }

            Self::InnerEtherDst(list) => {
                for m in list {
                    if m.matches(meta.inner.ether.dst) {
                        return true;
                    }
                }
            }

            Self::InnerEtherSrc(list) => {
                for m in list {
                    if m.matches(meta.inner.ether.src) {
                        return true;
                    }
                }
            }

            Self::InnerIpProto(list) => match meta.inner.ip {
                None => return false,

                Some(IpMeta::Ip4(Ipv4Meta { proto, .. })) => {
                    for m in list {
                        if m.matches(proto) {
                            return true;
                        }
                    }
                }

                Some(IpMeta::Ip6(Ipv6Meta { proto, .. })) => {
                    for m in list {
                        if m.matches(proto) {
                            return true;
                        }
                    }
                }
            },

            Self::InnerSrcIp4(list) => match meta.inner.ip {
                Some(IpMeta::Ip4(Ipv4Meta { src: ip, .. })) => {
                    for m in list {
                        if m.matches(ip) {
                            return true;
                        }
                    }
                }

                // Either there is no Inner IP metadata or this is an
                // IPv6 packet.
                _ => return false,
            },

            Self::InnerDstIp4(list) => match meta.inner.ip {
                Some(IpMeta::Ip4(Ipv4Meta { dst: ip, .. })) => {
                    for m in list {
                        if m.matches(ip) {
                            return true;
                        }
                    }
                }

                // Either there is no Inner IP metadata or this is an
                // IPv6 packet.
                _ => return false,
            },

            Self::InnerSrcIp6(list) => match meta.inner.ip {
                Some(IpMeta::Ip6(Ipv6Meta { src: ip, .. })) => {
                    for m in list {
                        if m.matches(ip) {
                            return true;
                        }
                    }
                }
                _ => return false,
            },

            Self::InnerDstIp6(list) => match meta.inner.ip {
                Some(IpMeta::Ip6(Ipv6Meta { dst: ip, .. })) => {
                    for m in list {
                        if m.matches(ip) {
                            return true;
                        }
                    }
                }
                _ => return false,
            },

            Self::InnerSrcPort(list) => match meta.inner.ulp {
                None => return false,

                Some(UlpMeta::Tcp(TcpMeta { src: port, .. })) => {
                    for m in list {
                        if m.matches(port) {
                            return true;
                        }
                    }
                }

                Some(UlpMeta::Udp(UdpMeta { src: port, .. })) => {
                    for m in list {
                        if m.matches(port) {
                            return true;
                        }
                    }
                }
            },

            Self::InnerDstPort(list) => match meta.inner.ulp {
                None => return false,

                Some(UlpMeta::Tcp(TcpMeta { dst: port, .. })) => {
                    for m in list {
                        if m.matches(port) {
                            return true;
                        }
                    }
                }

                Some(UlpMeta::Udp(UdpMeta { dst: port, .. })) => {
                    for m in list {
                        if m.matches(port) {
                            return true;
                        }
                    }
                }
            },
        }

        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DataPredicate {
    DhcpMsgType(DhcpMessageType),
    IcmpMsgType(IcmpMessageType),
    Icmpv6MsgType(Icmpv6MessageType),
    Dhcpv6MsgType(Dhcpv6MessageType),
    Not(Box<DataPredicate>),
}

impl Display for DataPredicate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DataPredicate::*;

        match self {
            DhcpMsgType(mt) => {
                write!(f, "dhcp.msg_type={}", mt)
            }

            IcmpMsgType(mt) => {
                write!(f, "icmp.msg_type={}", mt)
            }

            Icmpv6MsgType(mt) => {
                write!(f, "icmpv6.msg_type={}", mt)
            }

            Dhcpv6MsgType(mt) => {
                write!(f, "dhcpv6.msg_type={}", mt)
            }

            Not(pred) => {
                write!(f, "!")?;
                Display::fmt(&pred, f)
            }
        }
    }
}

impl DataPredicate {
    // Determine if the given `DataPredicate` matches the payload. We
    // use `PacketMeta` to determine if there is a suitable payload to
    // be inspected. That is, if there is no metadata for a given
    // header, there is certainly no payload.
    pub(crate) fn is_match<'a, 'b, R>(
        &self,
        meta: &PacketMeta,
        rdr: &'b mut R,
    ) -> bool
    where
        R: PacketRead<'a>,
    {
        match self {
            Self::Not(pred) => return !pred.is_match(meta, rdr),

            Self::DhcpMsgType(mt) => {
                let bytes = rdr.copy_remaining();
                let pkt = match DhcpPacket::new_checked(&bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        super::err(format!(
                            "DhcpPacket::new_checked() failed: {:?}",
                            e
                        ));
                        return false;
                    }
                };
                let dhcp = match DhcpRepr::parse(&pkt) {
                    Ok(v) => v,
                    Err(e) => {
                        super::err(format!(
                            "DhcpRepr::parse() failed: {:?}",
                            e
                        ));

                        return false;
                    }
                };

                let res = DhcpMessageType::from(dhcp.message_type) == *mt;
                return res;
            }

            Self::IcmpMsgType(mt) => {
                let bytes = rdr.copy_remaining();
                let pkt = match Icmpv4Packet::new_checked(&bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        super::err(format!(
                            "Icmpv4Packet::new_checked() failed: {:?}",
                            e
                        ));
                        return false;
                    }
                };
                let _icmp = match Icmpv4Repr::parse(&pkt, &Csum::ignored()) {
                    Ok(v) => v,
                    Err(e) => {
                        super::err(format!(
                            "Icmpv4Repr::parse() failed: {:?}",
                            e
                        ));
                        return false;
                    }
                };

                return IcmpMessageType::from(pkt.msg_type()) == *mt;
            }

            Self::Icmpv6MsgType(mt) => {
                // Pull out the IPv6 source / destination addresses. This checks
                // that this is actually an IPv6 packet, and these are needed
                // for the `smoltcp` packet parsing / validation.
                let (src, dst) = if let Some(metadata) = meta.inner_ip6() {
                    (
                        wire::IpAddress::Ipv6(wire::Ipv6Address(
                            metadata.src.bytes(),
                        )),
                        wire::IpAddress::Ipv6(wire::Ipv6Address(
                            metadata.dst.bytes(),
                        )),
                    )
                } else {
                    // This isn't an IPv6 packet at all
                    return false;
                };

                let bytes = rdr.copy_remaining();
                let pkt = match Icmpv6Packet::new_checked(&bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        super::err(format!(
                            "Icmpv6Packet::new_checked() failed: {:?}",
                            e
                        ));
                        return false;
                    }
                };
                if let Err(e) =
                    Icmpv6Repr::parse(&src, &dst, &pkt, &Csum::ignored())
                {
                    super::err(format!("Icmpv6Repr::parse() failed: {:?}", e,));
                    return false;
                }
                return Icmpv6MessageType::from(pkt.msg_type()) == *mt;
            }

            Self::Dhcpv6MsgType(mt) => {
                if let Ok(buf) = rdr.slice(1) {
                    rdr.seek_back(1).expect("Failed to seek back");
                    return buf[0] == u8::from(*mt);
                } else {
                    super::err(String::from(
                        "Failed to read DHCPv6 message type from packet",
                    ));
                    return false;
                }
            }
        }
    }
}

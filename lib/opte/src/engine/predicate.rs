// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Predicates used for `Rule` matching.

use super::dhcp::MessageType as DhcpMessageType;
use super::dhcpv6::MessageType as Dhcpv6MessageType;
use super::ether::EtherType;
use super::icmp::v4::MessageType as IcmpMessageType;
use super::icmp::v6::MessageType as Icmpv6MessageType;
use super::ingot_base::EthernetRef;
use super::ingot_base::Ipv4Ref;
use super::ingot_base::Ipv6Ref;
use super::ingot_base::L3;
use super::ingot_packet::ulp_dst_port;
use super::ingot_packet::ulp_src_port;
use super::ingot_packet::PacketHeaders2;
use super::ip4::Ipv4Addr;
use super::ip4::Ipv4Cidr;
use super::ip4::Protocol;
use super::ip6::Ipv6Addr;
use super::ip6::Ipv6Cidr;
use super::port::meta::ActionMeta;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Display;
use core::ops::RangeInclusive;
use ingot::icmp::IcmpV4Ref;
use ingot::icmp::IcmpV6Ref;
use opte_api::MacAddr;
use serde::Deserialize;
use serde::Serialize;
use smoltcp::wire::DhcpPacket;
use smoltcp::wire::DhcpRepr;

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
        meta: &PacketHeaders2,
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
                    if m.matches(EtherType::from(
                        meta.inner_ether().ethertype().0,
                    )) {
                        return true;
                    }
                }
            }

            Self::InnerEtherDst(list) => {
                for m in list {
                    if m.matches(meta.inner_ether().destination()) {
                        return true;
                    }
                }
            }

            Self::InnerEtherSrc(list) => {
                for m in list {
                    if m.matches(meta.inner_ether().source()) {
                        return true;
                    }
                }
            }

            Self::InnerIpProto(list) => match meta.inner_l3() {
                None => return false,

                Some(L3::Ipv4(ipv4)) => {
                    let proto = Protocol::from(ipv4.protocol().0);

                    for m in list {
                        if m.matches(proto) {
                            return true;
                        }
                    }
                }

                Some(L3::Ipv6(ipv6)) => {
                    // NOTE: I know this is bugged on EHs.
                    let proto = Protocol::from(ipv6.next_header().0);

                    for m in list {
                        if m.matches(proto) {
                            return true;
                        }
                    }
                }
            },

            Self::InnerSrcIp4(list) => match meta.inner_ip4() {
                Some(v4) => {
                    let ip = v4.source().into();
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

            Self::InnerDstIp4(list) => match meta.inner_ip4() {
                Some(v4) => {
                    let ip = v4.destination().into();
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

            Self::InnerSrcIp6(list) => match meta.inner_ip6() {
                Some(v6) => {
                    let ip = v6.source().into();
                    for m in list {
                        if m.matches(ip) {
                            return true;
                        }
                    }
                }
                _ => return false,
            },

            Self::InnerDstIp6(list) => match meta.inner_ip6() {
                Some(v6) => {
                    let ip = v6.destination().into();
                    for m in list {
                        if m.matches(ip) {
                            return true;
                        }
                    }
                }
                _ => return false,
            },

            Self::InnerSrcPort(list) => {
                match meta.inner_ulp().map(ulp_src_port).flatten() {
                    // No ULP metadata or no source port (e.g. ICMPv6).
                    None => return false,

                    Some(port) => {
                        for m in list {
                            if m.matches(port) {
                                return true;
                            }
                        }
                    }
                }
            }

            Self::InnerDstPort(list) => {
                match meta.inner_ulp().map(ulp_dst_port).flatten() {
                    // No ULP metadata or no destination port (e.g. ICMPv6).
                    None => return false,

                    Some(port) => {
                        for m in list {
                            if m.matches(port) {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Match<T> {
    Exact(T),
    Range(RangeInclusive<T>),
}

impl<T> Match<T>
where
    T: PartialEq + PartialOrd,
{
    pub(crate) fn is_match(&self, val: &T) -> bool {
        match self {
            Self::Exact(target) => val == target,
            Self::Range(range) => range.contains(val),
        }
    }
}

impl<T: Display> Display for Match<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(target) => write!(f, "={target}"),
            Self::Range(range) => {
                write!(f, "∈({}..={})", range.start(), range.end())
            }
        }
    }
}

impl<T> From<T> for Match<T> {
    fn from(value: T) -> Self {
        Match::Exact(value)
    }
}

impl<T> From<RangeInclusive<T>> for Match<T> {
    fn from(value: RangeInclusive<T>) -> Self {
        Match::Range(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DataPredicate {
    DhcpMsgType(Match<DhcpMessageType>),
    IcmpMsgType(Match<IcmpMessageType>),
    Icmpv6MsgType(Match<Icmpv6MessageType>),
    Dhcpv6MsgType(Match<Dhcpv6MessageType>),
    Not(Box<DataPredicate>),
}

impl Display for DataPredicate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DataPredicate::*;

        match self {
            DhcpMsgType(mt) => {
                write!(f, "dhcp.msg_type{mt}")
            }

            IcmpMsgType(mt) => {
                write!(f, "icmp.msg_type{mt}")
            }

            Icmpv6MsgType(mt) => {
                write!(f, "icmpv6.msg_type{mt}")
            }

            Dhcpv6MsgType(mt) => {
                write!(f, "dhcpv6.msg_type{mt}")
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
    pub(crate) fn is_match<'a>(&self, meta: &PacketHeaders2) -> bool {
        match self {
            Self::Not(pred) => !pred.is_match(meta),

            Self::DhcpMsgType(mt) => {
                // Not sure that I like that this is a complete clone/parse...
                let body;

                let bytes = if meta.body_segs().len() > 1 {
                    body = meta.copy_remaining();
                    &body
                } else {
                    meta.body_segs()[0]
                };

                let pkt = match DhcpPacket::new_checked(&bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        super::err!(
                            "DhcpPacket::new_checked() failed: {:?}",
                            e
                        );
                        return false;
                    }
                };

                let dhcp = match DhcpRepr::parse(&pkt) {
                    Ok(v) => v,
                    Err(e) => {
                        super::err!("DhcpRepr::parse() failed: {:?}", e);

                        return false;
                    }
                };

                mt.is_match(&DhcpMessageType::from(dhcp.message_type))
            }

            Self::IcmpMsgType(mt) => {
                let Some(icmp) = meta.inner_icmp() else {
                    // This isn't an ICMPv4 packet at all
                    return false;
                };

                mt.is_match(&IcmpMessageType::from(icmp.ty()))
            }

            Self::Icmpv6MsgType(mt) => {
                let Some(icmp6) = meta.inner_icmp6() else {
                    // This isn't an ICMPv6 packet at all
                    return false;
                };

                mt.is_match(&Icmpv6MessageType::from(icmp6.ty()))
            }

            Self::Dhcpv6MsgType(mt) => {
                let body = meta.body_segs();
                if body.len() == 0 || body[0].len() == 0 {
                    super::err!(
                        "Failed to read DHCPv6 message type from packet"
                    );
                    false
                } else {
                    mt.is_match(&body[0][0].into())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::DhcpMessageType as SmolDhcpType;
    use smoltcp::wire::Icmpv4Message;
    use smoltcp::wire::Icmpv6Message;

    // Some 'enum with unknown' ways of encoding message types
    // can have some unexpected behaviour with PartialOrd -- we
    // need to sort on the underlying representation for range
    // matches to be sensible.
    #[test]
    fn data_predicate_ranges_handle_unknown() {
        let dhcp_range: Match<DhcpMessageType> = (SmolDhcpType::Discover.into()
            ..=SmolDhcpType::Decline.into())
            .into();
        let icmp_range: Match<IcmpMessageType> =
            (Icmpv4Message::EchoReply.into()..=Icmpv4Message::Redirect.into())
                .into();
        let dhcp6_range: Match<Dhcpv6MessageType> =
            (Dhcpv6MessageType::Renew..=Dhcpv6MessageType::Reply).into();

        let icmp6_range: Match<Icmpv6MessageType> =
            (Icmpv6Message::RouterSolicit.into()
                ..=Icmpv6Message::Redirect.into())
                .into();

        // The `Unknown` cases here are artificial (i.e., the opcode is understood)
        // in case the underlying repr adds support for a test opcode.
        assert!(dhcp_range.is_match(&SmolDhcpType::Unknown(2).into()));
        assert!(icmp_range.is_match(&Icmpv4Message::Unknown(3).into()));
        assert!(dhcp6_range.is_match(&Dhcpv6MessageType::Other(6)));
        assert!(icmp6_range.is_match(&Icmpv6Message::Unknown(0x86).into()));
    }
}

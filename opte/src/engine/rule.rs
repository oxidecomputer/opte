// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use super::arp::{
    ArpEth4Payload, ArpEth4PayloadRaw, ArpMeta, ArpOp, ARP_HTYPE_ETHERNET,
};
use super::dhcp::MessageType as DhcpMessageType;
use super::ether::{EtherMeta, EtherMetaOpt, ETHER_TYPE_IPV4};
use super::flow_table::StateSummary;
use super::geneve::{GeneveMeta, GeneveMetaOpt};
use super::headers::{
    self, HeaderAction, IpAddr, IpMeta, IpMetaOpt, UlpHeaderAction, UlpMeta,
    UlpMetaOpt,
};
use super::icmp::MessageType as Icmp4MessageType;
use super::ip4::{Ipv4Addr, Ipv4Cidr, Ipv4Meta, Protocol};
use super::ip6::Ipv6Meta;
use super::layer::InnerFlowId;
use super::packet::{
    Initialized, Packet, PacketMeta, PacketRead, PacketReader, Parsed,
};
use super::port::meta::Meta;
use super::tcp::TcpMeta;
use super::udp::UdpMeta;
use crate::api::{Direction, MacAddr};
use core::fmt::{self, Debug, Display};
use cstr_core::CString;
use illumos_ddi_dki::c_char;
use serde::{Deserialize, Serialize};
use smoltcp::phy::ChecksumCapabilities as Csum;
use smoltcp::wire::{DhcpPacket, DhcpRepr, Icmpv4Packet, Icmpv4Repr};

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::boxed::Box;
        use alloc::string::{String, ToString};
        use alloc::sync::Arc;
        use alloc::vec::Vec;
        use illumos_ddi_dki::uintptr_t;
    } else {
        use std::boxed::Box;
        use std::string::{String, ToString};
        use std::sync::Arc;
        use std::vec::Vec;
    }
}

// A marker trait for types which represent packet payloads. Examples
// of payloads include an ARP request, ICMP body, or TCP body.
pub trait Payload {}

pub trait MatchExactVal {}

pub trait MatchExact<M: MatchExactVal + Eq + PartialEq> {
    fn match_exact(&self, val: &M) -> bool;
}

pub trait MatchPrefixVal {}

pub trait MatchPrefix<M: MatchPrefixVal> {
    fn match_prefix(&self, prefix: &M) -> bool;
}

pub trait MatchRangeVal {}

pub trait MatchRange<M: MatchRangeVal> {
    fn match_range(&self, start: &M, end: &M) -> bool;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EtherTypeMatch {
    Exact(u16),
}

impl EtherTypeMatch {
    fn matches(&self, flow_et: u16) -> bool {
        match self {
            EtherTypeMatch::Exact(et) => flow_et == *et,
        }
    }
}

impl Display for EtherTypeMatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use EtherTypeMatch::*;

        match self {
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ArpHtypeMatch {
    Exact(u16),
}

impl ArpHtypeMatch {
    fn matches(&self, flow_htype: u16) -> bool {
        match self {
            ArpHtypeMatch::Exact(htype) => flow_htype == *htype,
        }
    }
}

impl Display for ArpHtypeMatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ArpHtypeMatch::*;

        match self {
            Exact(htype) => write!(f, "{}", htype),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ArpPtypeMatch {
    Exact(u16),
}

impl ArpPtypeMatch {
    fn matches(&self, flow_ptype: u16) -> bool {
        match self {
            ArpPtypeMatch::Exact(ptype) => flow_ptype == *ptype,
        }
    }
}

impl Display for ArpPtypeMatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ArpPtypeMatch::*;

        match self {
            Exact(ptype) => write!(f, "0x{:4X}", ptype),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ArpOpMatch {
    Exact(ArpOp),
}

impl ArpOpMatch {
    fn matches(&self, flow_op: ArpOp) -> bool {
        match self {
            ArpOpMatch::Exact(op) => flow_op == *op,
        }
    }
}

impl Display for ArpOpMatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ArpOpMatch::*;

        match self {
            Exact(op) => write!(f, "{}", op),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Ipv4AddrMatch {
    Exact(Ipv4Addr),
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

#[derive(Debug)]
pub enum Predicate {
    InnerEtherType(Vec<EtherTypeMatch>),
    InnerEtherDst(Vec<EtherAddrMatch>),
    InnerEtherSrc(Vec<EtherAddrMatch>),
    InnerArpHtype(ArpHtypeMatch),
    InnerArpPtype(ArpPtypeMatch),
    InnerArpOp(ArpOpMatch),
    InnerSrcIp4(Vec<Ipv4AddrMatch>),
    InnerDstIp4(Vec<Ipv4AddrMatch>),
    InnerIpProto(Vec<IpProtoMatch>),
    InnerSrcPort(Vec<PortMatch>),
    InnerDstPort(Vec<PortMatch>),
    Not(Box<Predicate>),
    Meta(Box<dyn MetaPredicate>),
}

impl PartialEq for Predicate {
    fn eq(&self, other: &Self) -> bool {
        use Predicate::*;

        match (self, other) {
            (InnerEtherType(s), InnerEtherType(o)) => s == o,
            (InnerEtherDst(s), InnerEtherDst(o)) => s == o,
            (InnerEtherSrc(s), InnerEtherSrc(o)) => s == o,
            (InnerArpHtype(s), InnerArpHtype(o)) => s == o,
            (InnerArpPtype(s), InnerArpPtype(o)) => s == o,
            (InnerArpOp(s), InnerArpOp(o)) => s == o,
            (InnerSrcIp4(s), InnerSrcIp4(o)) => s == o,
            (InnerDstIp4(s), InnerDstIp4(o)) => s == o,
            (InnerIpProto(s), InnerIpProto(o)) => s == o,
            (InnerSrcPort(s), InnerSrcPort(o)) => s == o,
            (InnerDstPort(s), InnerDstPort(o)) => s == o,
            (Not(s), Not(o)) => s == o,
            (Meta(s), Self::Meta(o)) => {
                // Avert your eyes!
                s.to_string() == o.to_string()
            }
            _ => false,
        }
    }
}

impl Eq for Predicate {}

pub trait MetaPredicate: Debug + Display {
    fn is_match(&self, meta: &Meta) -> bool;
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

            InnerArpHtype(ArpHtypeMatch::Exact(htype)) => {
                write!(f, "inner.arp.htype={}", htype)
            }

            InnerArpPtype(ArpPtypeMatch::Exact(ptype)) => {
                write!(f, "inner.arp.ptype={}", ptype)
            }

            InnerArpOp(ArpOpMatch::Exact(op)) => {
                write!(f, "inner.arp.op={}", op)
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

            Meta(pred) => {
                write!(f, "meta={}", pred)
            }

            Not(pred) => {
                write!(f, "!")?;
                Display::fmt(&pred, f)
            }
        }
    }
}

impl Predicate {
    fn is_match(&self, meta: &PacketMeta, layer_meta: &Meta) -> bool {
        match self {
            Self::Meta(pred) => return pred.is_match(layer_meta),

            Self::Not(pred) => return !pred.is_match(meta, layer_meta),

            Self::InnerEtherType(list) => match meta.inner.ether {
                None => return false,

                Some(EtherMeta { ether_type, .. }) => {
                    for m in list {
                        if m.matches(ether_type) {
                            return true;
                        }
                    }
                }
            },

            Self::InnerEtherDst(list) => match meta.inner.ether {
                None => return false,

                Some(EtherMeta { dst, .. }) => {
                    for m in list {
                        if m.matches(dst) {
                            return true;
                        }
                    }
                }
            },

            Self::InnerEtherSrc(list) => match meta.inner.ether {
                None => return false,

                Some(EtherMeta { src, .. }) => {
                    for m in list {
                        if m.matches(src) {
                            return true;
                        }
                    }
                }
            },

            Self::InnerArpHtype(m) => match meta.inner.arp {
                None => return false,

                Some(ArpMeta { htype, .. }) => {
                    if m.matches(htype) {
                        return true;
                    }
                }
            },

            Self::InnerArpPtype(m) => match meta.inner.arp {
                None => return false,

                Some(ArpMeta { ptype, .. }) => {
                    if m.matches(ptype) {
                        return true;
                    }
                }
            },

            Self::InnerArpOp(m) => match meta.inner.arp {
                None => return false,

                Some(ArpMeta { op, .. }) => {
                    if m.matches(op) {
                        return true;
                    }
                }
            },

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
    Dhcp4MsgType(DhcpMessageType),
    Icmp4MsgType(Icmp4MessageType),
    InnerArpTpa(Vec<Ipv4AddrMatch>),
    Not(Box<DataPredicate>),
}

impl Display for DataPredicate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DataPredicate::*;

        match self {
            Dhcp4MsgType(mt) => {
                write!(f, "dhcp4.msg_type={}", mt)
            }

            Icmp4MsgType(mt) => {
                write!(f, "icmp.msg_type={}", mt)
            }

            InnerArpTpa(list) => {
                let s = list
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                write!(f, "inner.arp.data.tpa={}", s)
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
    fn is_match<'a, 'b, R>(&self, meta: &PacketMeta, rdr: &'b mut R) -> bool
    where
        R: PacketRead<'a>,
    {
        match self {
            Self::Not(pred) => return !pred.is_match(meta, rdr),

            Self::Dhcp4MsgType(mt) => {
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

            Self::Icmp4MsgType(mt) => {
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

                return Icmp4MessageType::from(pkt.msg_type()) == *mt;
            }

            Self::InnerArpTpa(list) => match meta.inner.arp {
                None => return false,

                Some(ArpMeta { htype, ptype, .. }) => {
                    if htype != ARP_HTYPE_ETHERNET || ptype != ETHER_TYPE_IPV4 {
                        return false;
                    }

                    let raw = match ArpEth4PayloadRaw::parse(rdr) {
                        Ok(raw) => raw,
                        Err(_) => return false,
                    };

                    let arp = ArpEth4Payload::from(&raw);
                    // TODO It would be nice to add some type of undo
                    // method to the reader interface, allowing you to
                    // track back to the cursor position before the
                    // last read. Or, even better, have the ability to
                    // get a new type from the PacketReader, like
                    // TempPacketRead (or something) that undoes the
                    // most recent read in its Drop implementation.
                    // That way there is no chance to forget to undo
                    // the read.
                    rdr.seek_back(super::arp::ARP_ETH4_PAYLOAD_SZ)
                        .expect("failed to seek back");

                    for m in list {
                        if m.matches(arp.tpa) {
                            return true;
                        }
                    }
                }
            },
        }

        false
    }
}

/// A marker trait indicating a type is an entry acuired from a [`Resource`].
pub trait ResourceEntry {}

/// A marker trait indicating a type is a resource.
pub trait Resource {}

/// A mapping resource represents a shared map from a key to a shared
/// [`ResourceEntry`].
///
/// The idea being that multiple consumers can "own" the entry at once.
pub trait MappingResource: Resource {
    type Key: Clone;
    type Entry: ResourceEntry;

    /// Get the [`ResourceEntry`] with the given key, if one exists.
    fn get(&self, key: &Self::Key) -> Option<Self::Entry>;

    /// Remove the [`ResourceEntry`] with the given key, if one exists.
    fn remove(&self, key: &Self::Key) -> Option<Self::Entry>;

    /// Set the [`ResoruceEntry`] with the given key. Return the
    /// current entry, if one exists.
    fn set(&self, key: Self::Key, entry: Self::Entry) -> Option<Self::Entry>;
}

/// A finite resource represents a shared map from a key to an
/// exclusively owned [`ResourceEntry`].
///
/// The idea being that a single consumer takes ownership of the
/// [`ResourceEntry`] for some amount of time; and while that consumer
/// owns the entry no other consumer may have access to it. The
/// resource represents a finite collection of entries, and thus may
/// be exhausted at any given moment.
pub trait FiniteResource: Resource {
    type Key: Clone;
    type Entry: ResourceEntry;

    /// Obtain a new [`ResourceEntry`] given the key.
    ///
    /// # Errors
    ///
    /// Return an error if no entry can be mapped to this key or if
    /// the resource is exhausted.
    fn obtain(&self, key: &Self::Key) -> Result<Self::Entry, ResourceError>;

    /// Release the [`ResourceEntry`] back to the available resources.
    fn release(&self, key: &Self::Key, br: Self::Entry);
}

/// An Action Descriptor holds the information needed to create the HT
/// which implements the desired action. An ActionDesc is created by
/// an [`StatefulAction`] implementation.
pub trait ActionDesc {
    /// Generate the [`HT`] which implements this descriptor.
    fn gen_ht(&self, dir: Direction) -> HT;

    fn name(&self) -> &str;
}

impl fmt::Debug for dyn ActionDesc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "dyn ActionDesc")
    }
}

impl StateSummary for Arc<dyn ActionDesc> {
    fn summary(&self) -> String {
        self.name().to_string()
    }
}

#[derive(Debug)]
pub enum ActionInitError {
    ExhaustedResources,
    ResourceError(ResourceError),
}

impl fmt::Debug for dyn StaticAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "dyn StaticAction")
    }
}

pub trait ActionContext {
    // The `payload` is the mutable bytes of the packet payload (after
    // the headers parsed for FlowId).
    fn exec(&self, meta: &PacketMeta, payload: &mut [u8])
        -> Result<(), String>;
}

impl fmt::Debug for dyn StatefulAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "dyn StatefulAction")
    }
}

pub trait ActionSummary {
    fn summary(&self) -> String;
}

#[derive(Clone)]
pub struct IdentityDesc {
    name: String,
}

impl IdentityDesc {
    pub fn new(name: String) -> Self {
        IdentityDesc { name }
    }
}

impl ActionDesc for IdentityDesc {
    fn gen_ht(&self, _dir: Direction) -> HT {
        Default::default()
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug)]
pub struct Identity {
    name: String,
}

impl Identity {
    pub fn new(name: &str) -> Self {
        Identity { name: name.to_string() }
    }
}

impl Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Identity")
    }
}

impl StaticAction for Identity {
    fn gen_ht(
        &self,
        _dir: Direction,
        _flow_id: &InnerFlowId,
        _meta: &mut Meta,
    ) -> GenHtResult {
        Ok(AllowOrDeny::Allow(HT::identity(&self.name)))
    }

    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        (vec![], vec![])
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HT {
    pub name: String,
    pub outer_ether: HeaderAction<EtherMeta, EtherMetaOpt>,
    pub outer_ip: HeaderAction<IpMeta, IpMetaOpt>,
    pub outer_ulp: HeaderAction<UlpMeta, UlpMetaOpt>,
    pub outer_encap: HeaderAction<GeneveMeta, GeneveMetaOpt>,
    pub inner_ether: HeaderAction<EtherMeta, EtherMetaOpt>,
    pub inner_ip: HeaderAction<IpMeta, IpMetaOpt>,
    // We don't support push/pop for inner_ulp.
    pub inner_ulp: UlpHeaderAction<super::headers::UlpMetaModify>,
}

impl StateSummary for Vec<HT> {
    fn summary(&self) -> String {
        self.iter().map(|ht| ht.to_string()).collect::<Vec<String>>().join(",")
    }
}

impl Display for HT {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
extern "C" {
    pub fn __dtrace_probe_ht__run(arg: uintptr_t);
}

#[repr(C)]
pub struct flow_id_sdt_arg {
    af: i32,
    src_ip4: u32,
    dst_ip4: u32,
    src_ip6: [u8; 16],
    dst_ip6: [u8; 16],
    src_port: u16,
    dst_port: u16,
    proto: u8,
}

impl From<&InnerFlowId> for flow_id_sdt_arg {
    fn from(ifid: &InnerFlowId) -> Self {
        // Consumers expect all data to be presented as it would be
        // traveling across the network.
        let (af, src_ip4, src_ip6) = match ifid.src_ip {
            IpAddr::Ip4(ip4) => (headers::AF_INET, ip4.to_be(), [0; 16]),
            IpAddr::Ip6(ip6) => (headers::AF_INET6, 0, ip6.bytes()),
        };

        let (dst_ip4, dst_ip6) = match ifid.dst_ip {
            IpAddr::Ip4(ip4) => (ip4.to_be(), [0; 16]),
            IpAddr::Ip6(ip6) => (0, ip6.bytes()),
        };

        flow_id_sdt_arg {
            af,
            src_ip4,
            dst_ip4,
            src_ip6,
            dst_ip6,
            src_port: ifid.src_port.to_be(),
            dst_port: ifid.dst_port.to_be(),
            proto: ifid.proto as u8,
        }
    }
}

#[repr(C)]
pub struct ht_run_sdt_arg {
    pub port: *const c_char,
    pub loc: *const c_char,
    pub dir: *const c_char,
    pub flow_id_before: *const flow_id_sdt_arg,
    pub flow_id_after: *const flow_id_sdt_arg,
}

pub fn ht_probe(
    port: &CString,
    loc: &str,
    dir: Direction,
    before: &InnerFlowId,
    after: &InnerFlowId,
) {
    cfg_if! {
        if #[cfg(all(not(feature = "std"), not(test)))] {
            let loc_c = CString::new(loc).unwrap();
            let flow_id_before = flow_id_sdt_arg::from(before);
            let flow_id_after = flow_id_sdt_arg::from(after);

            let arg = ht_run_sdt_arg {
                port: port.as_ptr(),
                loc: loc_c.as_ptr(),
                dir: dir.cstr_raw(),
                flow_id_before: &flow_id_before,
                flow_id_after: &flow_id_after,
            };

            unsafe {
                __dtrace_probe_ht__run(
                    &arg as *const ht_run_sdt_arg as uintptr_t
                );
            }
        } else if #[cfg(feature = "usdt")] {
            let port_s = port.to_str().unwrap();
            let before_s = before.to_string();
            let after_s = after.to_string();

            crate::opte_provider::ht__run!(
                || (port_s, loc, dir, before_s, after_s)
            );
        } else {
            let (_, _, _, _, _) = (port, loc, dir, before, after);
        }
    }
}

impl HT {
    /// The "identity" header transformation; one which leaves the
    /// header as-isl
    pub fn identity(name: &str) -> Self {
        Self {
            name: name.to_string(),
            outer_ether: HeaderAction::Ignore,
            outer_ip: HeaderAction::Ignore,
            outer_ulp: HeaderAction::Ignore,
            outer_encap: HeaderAction::Ignore,
            inner_ether: HeaderAction::Ignore,
            inner_ip: HeaderAction::Ignore,
            inner_ulp: UlpHeaderAction::Ignore,
        }
    }

    pub fn run(&self, meta: &mut PacketMeta) {
        self.outer_ether.run(&mut meta.outer.ether);
        self.outer_ip.run(&mut meta.outer.ip);
        self.outer_ulp.run(&mut meta.outer.ulp);
        self.outer_encap.run(&mut meta.outer.encap);
        self.inner_ether.run(&mut meta.inner.ether);
        self.inner_ip.run(&mut meta.inner.ip);
        self.inner_ulp.run(&mut meta.inner.ulp);
    }
}

#[derive(Debug)]
pub enum ResourceError {
    Exhausted,
    NoMatch(String),
}

#[derive(Clone, Debug)]
pub enum GenDescError {
    ResourceExhausted { name: String },

    Unexpected { msg: String },
}

pub type GenDescResult = ActionResult<Arc<dyn ActionDesc>, GenDescError>;

pub trait StatefulAction: Display {
    /// Generate a an [`ActionDesc`] based on the [`InnerFlowId`] and
    /// [`Meta`]. This action may also add, remove, or modify metadata
    /// to communicate data to downstream actions.
    ///
    /// # Errors
    ///
    /// * [`GenDescError::ResourceExhausted`]: This action relies on a
    /// dynamic resource which has been exhausted.
    ///
    /// * [`GenDescError::Unexpected`]: This action encountered an
    /// unexpected error while trying to generate a descriptor.
    fn gen_desc(&self, flow_id: &InnerFlowId, meta: &mut Meta)
        -> GenDescResult;

    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>);
}

#[derive(Clone, Debug)]
pub enum GenHtError {
    ResourceExhausted { name: String },
    Unexpected { msg: String },
}

pub type GenHtResult = ActionResult<HT, GenHtError>;

pub trait StaticAction: Display {
    fn gen_ht(
        &self,
        dir: Direction,
        flow_id: &InnerFlowId,
        meta: &mut Meta,
    ) -> GenHtResult;

    /// Return the predicates implicit to this action.
    ///
    /// Return both the header [`Predicate`] list and
    /// [`DataPredicate`] list implicit to this action. An empty list
    /// implies there are no implicit predicates of that type.
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>);
}

pub type ModMetaResult = ActionResult<(), String>;

/// A meta action is one that's only goal is to modify the processing
/// metadata in some way. That is, it has no transformation to make on
/// the packet, only add/modify/remove metadata for use by later
/// layers.
pub trait MetaAction: Display {
    /// Return the predicates implicit to this action.
    ///
    /// Return both the header [`Predicate`] list and
    /// [`DataPredicate`] list implicit to this action. An empty list
    /// implies there are no implicit predicates of that type.
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>);

    fn mod_meta(&self, flow_id: &InnerFlowId, meta: &mut Meta)
        -> ModMetaResult;
}

#[derive(Debug)]
pub enum GenErr {
    BadPayload(super::packet::ReadErr),
    Malformed,
    MissingMeta,
    Truncated,
    Unexpected(String),
}

impl From<super::packet::ReadErr> for GenErr {
    fn from(err: super::packet::ReadErr) -> Self {
        Self::BadPayload(err)
    }
}

impl From<smoltcp::Error> for GenErr {
    fn from(err: smoltcp::Error) -> Self {
        use smoltcp::Error::*;

        match err {
            Malformed => Self::Malformed,
            Truncated => Self::Truncated,
            _ => Self::Unexpected(format!("smoltcp error {}", err)),
        }
    }
}

pub type GenPacketResult = ActionResult<Packet<Initialized>, GenErr>;

/// A hairpin action is one that generates a new packet based on the
/// current inbound/outbound packet, and then "hairpins" that new
/// packet back to the source of the original packet. For example, you
/// could use this to hairpin an ARP Reply in response to a guest's
/// ARP request.
pub trait HairpinAction: Display {
    /// Generate a [`Packet`] to hairpin back to the source. The
    /// `meta` argument holds the packet metadata, inlucding any
    /// modifications made by previous layers up to this point. The
    /// `rdr` argument provides a [`PacketReader`] against
    /// [`Packet<Parsed>`], with its starting position set to the
    /// beginning of the packet's payload.
    fn gen_packet(
        &self,
        meta: &PacketMeta,
        rdr: &mut PacketReader<Parsed, ()>,
    ) -> GenPacketResult;

    /// Return the predicates implicit to this action.
    ///
    /// Return both the header [`Predicate`] list and
    /// [`DataPredicate`] list implicit to this action. An empty list
    /// implies there are no implicit predicates of that type.
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>);
}

#[derive(Debug)]
pub enum AllowOrDeny<T> {
    Allow(T),
    Deny,
}

pub type ActionResult<T, E> = Result<AllowOrDeny<T>, E>;

#[derive(Clone)]
pub enum Action {
    Deny,
    Meta(Arc<dyn MetaAction>),
    Static(Arc<dyn StaticAction>),
    Stateful(Arc<dyn StatefulAction>),
    Hairpin(Arc<dyn HairpinAction>),
}

impl Action {
    pub fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        match self {
            // The entire point of a Deny action is for the consumer
            // to specify which types of packets it wants to deny,
            // which means the predicates are always purely explicit.
            Self::Deny => (vec![], vec![]),
            Self::Meta(act) => act.implicit_preds(),
            Self::Static(act) => act.implicit_preds(),
            Self::Stateful(act) => act.implicit_preds(),
            Self::Hairpin(act) => act.implicit_preds(),
        }
    }

    pub fn is_deny(&self) -> bool {
        match self {
            Self::Deny => true,
            _ => false,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub enum ActionDump {
    Deny,
    Meta(String),
    Static(String),
    Stateful(String),
    Hairpin(String),
}

impl From<&Action> for ActionDump {
    fn from(action: &Action) -> Self {
        match action {
            Action::Deny => Self::Deny,
            Action::Meta(ma) => Self::Meta(ma.to_string()),
            Action::Static(sa) => Self::Static(sa.to_string()),
            Action::Stateful(sa) => Self::Stateful(sa.to_string()),
            Action::Hairpin(ha) => Self::Hairpin(ha.to_string()),
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Deny => write!(f, "DENY"),
            Self::Meta(a) => write!(f, "META: {}", a),
            Self::Static(a) => write!(f, "STATIC: {}", a),
            Self::Stateful(a) => write!(f, "STATEFUL: {}", a),
            Self::Hairpin(a) => write!(f, "HAIRPIN: {}", a),
        }
    }
}

impl fmt::Debug for Action {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "todo: implement Debug for Action")
    }
}

// TODO Use const generics to make this array?
#[derive(Debug)]
pub struct RulePredicates {
    hdr_preds: Vec<Predicate>,
    data_preds: Vec<DataPredicate>,
}

impl PartialEq for RulePredicates {
    /// Rule predicates are equal when both contain identical sets of
    /// header and data predicates.
    fn eq(&self, other: &Self) -> bool {
        if self.hdr_preds.len() != other.hdr_preds.len() {
            return false;
        }

        if self.data_preds.len() != other.data_preds.len() {
            return false;
        }

        for hp in &self.hdr_preds {
            if !other.hdr_preds.contains(hp) {
                return false;
            }
        }

        for dp in &self.data_preds {
            if !other.data_preds.contains(dp) {
                return false;
            }
        }

        true
    }
}

impl Eq for RulePredicates {}

pub trait RuleState {}

#[derive(Debug)]
pub struct Ready {
    hdr_preds: Vec<Predicate>,
    data_preds: Vec<DataPredicate>,
}
impl RuleState for Ready {}

#[derive(Debug, Eq, PartialEq)]
pub struct Finalized {
    preds: Option<RulePredicates>,
}
impl RuleState for Finalized {}

#[derive(Clone, Debug)]
pub struct Rule<S: RuleState> {
    state: S,
    action: Action,
    priority: u16,
}

impl PartialEq for Rule<Finalized> {
    fn eq(&self, other: &Self) -> bool {
        self.state.preds == other.state.preds
    }
}

impl Eq for Rule<Finalized> {}

impl<S: RuleState> Rule<S> {
    pub fn action(&self) -> &Action {
        &self.action
    }
}

impl Rule<Ready> {
    /// Create a new rule.
    ///
    /// Create a new rule with the given priority and [`Action`]. Add
    /// any implicit predicates dictated by the action. Additional
    /// predicates may be added along with the action's implicit ones.
    pub fn new(priority: u16, action: Action) -> Self {
        let (hdr_preds, data_preds) = action.implicit_preds();

        Rule { state: Ready { hdr_preds, data_preds }, action, priority }
    }

    /// Create a new rule that matches anything.
    ///
    /// The same as [`Rule::new()`] + [`Rule::clear_preds()`] with the
    /// additional effect of moving directly to the [`Finalized`]
    /// state; preventing any chance for adding a predicate. This is
    /// useful for making intentions clear that this rule is to match
    /// anything.
    pub fn match_any(priority: u16, action: Action) -> Rule<Finalized> {
        Rule { state: Finalized { preds: None }, action, priority }
    }

    /// Add a single [`Predicate`] to the end of the list.
    pub fn add_predicate(&mut self, pred: Predicate) {
        self.state.hdr_preds.push(pred);
    }

    /// Append a list of [`Predicate`]s to the existing list.
    pub fn add_predicates(&mut self, preds: Vec<Predicate>) {
        for p in preds {
            self.state.hdr_preds.push(p);
        }
    }

    /// Add a single [`DataPredicate`] to the end of the list.
    pub fn add_data_predicate(&mut self, pred: DataPredicate) {
        self.state.data_preds.push(pred)
    }

    /// Clear all header and data predicates.
    ///
    /// For the rare occasion that you want to disregard an [`Action`]'s
    /// implicit predicates.
    pub fn clear_preds(&mut self) {
        self.state.hdr_preds.clear();
        self.state.data_preds.clear();
    }

    /// Finalize the rule; locking all predicates in stone.
    pub fn finalize(self) -> Rule<Finalized> {
        let preds = if self.state.hdr_preds.len() == 0
            && self.state.data_preds.len() == 0
        {
            None
        } else {
            Some(RulePredicates {
                hdr_preds: self.state.hdr_preds,
                data_preds: self.state.data_preds,
            })
        };

        Rule {
            state: Finalized { preds },
            priority: self.priority,
            action: self.action,
        }
    }
}

impl<'a> Rule<Finalized> {
    pub fn is_match<'b, R>(
        &self,
        meta: &PacketMeta,
        layer_meta: &Meta,
        rdr: &'b mut R,
    ) -> bool
    where
        R: PacketRead<'a>,
    {
        #[cfg(debug_assert)]
        {
            if let Some(preds) = &self.state.preds {
                if preds.hdr_preds.len() == 0 && preds.data_preds.len() == 0 {
                    panic!(
                        "bug: RulePredicates must have at least one \
                            predicate"
                    );
                }
            }
        }

        match &self.state.preds {
            // A rule with no predicates always matches.
            None => true,

            Some(preds) => {
                for p in &preds.hdr_preds {
                    if !p.is_match(meta, layer_meta) {
                        return false;
                    }
                }

                for p in &preds.data_preds {
                    if !p.is_match(meta, rdr) {
                        return false;
                    }
                }

                true
            }
        }
    }

    pub fn priority(&self) -> u16 {
        self.priority
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RuleDump {
    pub priority: u16,
    pub predicates: Vec<String>,
    pub data_predicates: Vec<DataPredicate>,
    pub action: String,
}

impl From<&Rule<Finalized>> for RuleDump {
    fn from(rule: &Rule<Finalized>) -> Self {
        let predicates = rule.state.preds.as_ref().map_or(vec![], |rp| {
            rp.hdr_preds.iter().map(ToString::to_string).collect()
        });
        let data_predicates = rule
            .state
            .preds
            .as_ref()
            .map_or(vec![], |rp| rp.data_preds.clone());

        RuleDump {
            priority: rule.priority,
            predicates,
            data_predicates,
            action: rule.action.to_string(),
        }
    }
}

#[test]
fn rule_matching() {
    use crate::engine::packet::MetaGroup;

    let action = Identity::new("rule_matching");
    let mut r1 = Rule::new(1, Action::Static(Arc::new(action)));
    let src_ip = "10.11.11.100".parse().unwrap();
    let src_port = "1026".parse().unwrap();
    let dst_ip = "52.10.128.69".parse().unwrap();
    let dst_port = "443".parse().unwrap();
    // There is no DataPredicate usage in this test, so this pkt/rdr
    // can be bogus.
    let pkt = Packet::copy(&[0xA]);
    let mut rdr = PacketReader::new(&pkt, ());

    let ip = IpMeta::from(Ipv4Meta {
        src: src_ip,
        dst: dst_ip,
        proto: Protocol::TCP,
    });
    let ulp = UlpMeta::from(TcpMeta {
        src: src_port,
        dst: dst_port,
        flags: 0,
        seq: 0,
        ack: 0,
    });

    let meta = PacketMeta {
        outer: Default::default(),
        inner: MetaGroup { ip: Some(ip), ulp: Some(ulp), ..Default::default() },
    };

    r1.add_predicate(Predicate::InnerSrcIp4(vec![Ipv4AddrMatch::Exact(
        src_ip,
    )]));
    let r1 = r1.finalize();

    let port_meta = Meta::new();
    assert!(r1.is_match(&meta, &port_meta, &mut rdr));

    let new_src_ip = "10.11.11.99".parse().unwrap();

    let ip = IpMeta::from(Ipv4Meta {
        src: new_src_ip,
        dst: dst_ip,
        proto: Protocol::TCP,
    });
    let ulp = UlpMeta::from(TcpMeta {
        src: src_port,
        dst: dst_port,
        flags: 0,
        seq: 0,
        ack: 0,
    });

    let meta = PacketMeta {
        outer: Default::default(),
        inner: MetaGroup { ip: Some(ip), ulp: Some(ulp), ..Default::default() },
    };

    assert!(!r1.is_match(&meta, &port_meta, &mut rdr));
}

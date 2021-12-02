use core::fmt::{self, Display};

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::boxed::Box;
#[cfg(any(feature = "std", test))]
use std::boxed::Box;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::sync::Arc;
#[cfg(any(feature = "std", test))]
use std::sync::Arc;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::string::{String, ToString};
#[cfg(any(feature = "std", test))]
use std::string::{String, ToString};
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::vec::Vec;
#[cfg(any(feature = "std", test))]
use std::vec::Vec;

use crate::arp::{
    ArpEth4Payload, ArpEth4PayloadRaw, ArpMeta, ArpOp, ARP_HTYPE_ETHERNET,
};
use crate::ether::{EtherAddr, EtherMeta, EtherMetaOpt, ETHER_TYPE_IPV4};
use crate::flow_table::StateSummary;
use crate::headers::{
    GeneveMeta, GeneveMetaOpt, HeaderAction, HeaderActionModify, IcmpDuMeta,
    IcmpDuMetaOpt, IcmpEchoMeta, IcmpEchoMetaOpt, IpMeta, IpMetaOpt, Ipv4Meta,
    TcpMeta, TcpMetaOpt, UdpMeta, UdpMetaOpt, UlpMeta,
};
use crate::ip4::{Ipv4Addr, Ipv4Cidr, Protocol};
use crate::layer::{InnerFlowId, IpAddr};
use crate::nat::NatPool;
use crate::packet::{
    Initialized, Packet, PacketMeta, PacketRead, PacketReader, Parsed,
};
use crate::sync::{KMutex, KMutexType};
use crate::{CString, Direction};

use illumos_ddi_dki::{c_char, uintptr_t};

use serde::{Deserialize, Serialize};

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

#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum EtherAddrMatch {
    Exact(EtherAddr),
}

impl EtherAddrMatch {
    fn matches(&self, flow_addr: EtherAddr) -> bool {
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

#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Ipv4AddrMatch {
    Exact(Ipv4Addr),
    Prefix(Ipv4Cidr),
    // Range(Ipv4Addr, Ipv4Addr),
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

#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
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
    InnerDstPort(Vec<PortMatch>),
    Not(Box<Predicate>),
    // Match on metadata stored by previous layers.
    //
    // TODO Use more structured types than string -> string.
    // Meta(&'static str, &'static str),
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

            InnerDstPort(list) => {
                let s = list
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                write!(f, "inner.ulp.dst={}", s)
            }

            Not(pred) => {
                write!(f, "!")?;
                pred.fmt(f)
            }
        }
    }
}

impl Predicate {
    fn is_match(&self, meta: &PacketMeta) -> bool {
        match self {
            Self::Not(pred) => return !pred.is_match(meta),

            Self::InnerEtherType(list) => match meta.inner_ether {
                None => return false,

                Some(EtherMeta { ether_type, .. }) => {
                    for m in list {
                        if m.matches(ether_type) {
                            return true;
                        }
                    }
                }
            },

            Self::InnerEtherDst(list) => match meta.inner_ether {
                None => return false,

                Some(EtherMeta { dst, .. }) => {
                    for m in list {
                        if m.matches(dst) {
                            return true;
                        }
                    }
                }
            },

            Self::InnerEtherSrc(list) => match meta.inner_ether {
                None => return false,

                Some(EtherMeta { src, .. }) => {
                    for m in list {
                        if m.matches(src) {
                            return true;
                        }
                    }
                }
            },

            Self::InnerArpHtype(m) => match meta.inner_arp {
                None => return false,

                Some(ArpMeta { htype, .. }) => {
                    if m.matches(htype) {
                        return true;
                    }
                }
            },

            Self::InnerArpPtype(m) => match meta.inner_arp {
                None => return false,

                Some(ArpMeta { ptype, .. }) => {
                    if m.matches(ptype) {
                        return true;
                    }
                }
            },

            Self::InnerArpOp(m) => match meta.inner_arp {
                None => return false,

                Some(ArpMeta { op, .. }) => {
                    if m.matches(op) {
                        return true;
                    }
                }
            },

            Self::InnerIpProto(list) => match meta.inner_ip {
                None => return false,

                Some(IpMeta::Ip4(Ipv4Meta { proto, .. })) => {
                    for m in list {
                        if m.matches(proto) {
                            return true;
                        }
                    }
                }

                _ => todo!("implement IPv6 for InnerIpProto"),
            },

            Self::InnerSrcIp4(list) => match meta.inner_ip {
                None => return false,

                Some(IpMeta::Ip4(Ipv4Meta { src: ip, .. })) => {
                    for m in list {
                        if m.matches(ip) {
                            return true;
                        }
                    }
                }

                _ => todo!("implement Ip6 meta for InnerSrcIp4"),
            },

            Self::InnerDstIp4(list) => match meta.inner_ip {
                None => return false,

                Some(IpMeta::Ip4(Ipv4Meta { dst: ip, .. })) => {
                    for m in list {
                        if m.matches(ip) {
                            return true;
                        }
                    }
                }

                _ => todo!("implement Ip6 meta for InnerDstIp4"),
            },

            Self::InnerDstPort(list) => match meta.ulp {
                None => return false,

                Some(UlpMeta::IcmpEcho(IcmpEchoMeta { id: port })) => {
                    for m in list {
                        if m.matches(port) {
                            return true;
                        }
                    }
                }

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

                _ => todo!("implement InnerDstPort for {:?}", meta.ulp),
            },
        }

        false
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum DataPredicate {
    InnerArpTpa(Vec<Ipv4AddrMatch>),
    Not(Box<DataPredicate>),
}

impl Display for DataPredicate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DataPredicate::*;

        match self {
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
                pred.fmt(f)
            }
        }
    }
}

impl DataPredicate {
    // Determine if the given `DataPredicate` matches the payload. We
    // use `PacketMeta` to determine if there is a suitable payload to
    // be inspected. That is, if there is no metadata for a given
    // header, there is certainly no payload.
    fn is_match<R>(&self, meta: &PacketMeta, rdr: &mut R) -> bool
    where
        R: PacketRead,
    {
        match self {
            Self::Not(pred) => return !pred.is_match(meta, rdr),

            Self::InnerArpTpa(list) => match meta.inner_arp {
                None => return false,

                Some(ArpMeta { htype, ptype, .. }) => {
                    if htype != ARP_HTYPE_ETHERNET || ptype != ETHER_TYPE_IPV4 {
                        return false;
                    }

                    // let raw = match LayoutVerified::new(payload) {
                    //     Some(raw) => raw,
                    //     None => return false,
                    // };

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
                    rdr.seek_back(crate::arp::ARP_ETH4_PAYLOAD_SZ)
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

/// An Action Descriptor type holds the information needed to create
/// an HT which implements the desired action. An ActionDesc is
/// created by an Action implementation.
pub trait ActionDesc {
    /// Perform any finalization needed. For a stateful action this
    /// will typically release ownership of a resource.
    fn fini(&self);

    /// Generate the `HT` which implements this descriptor.
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
    fn exec(
        &self,
        meta: &PacketMeta,
        resources: &Resources,
        payload: &mut [u8],
    ) -> Result<(), String>;
}

impl fmt::Debug for dyn StatefulAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "dyn StatefulAction")
    }
}

pub trait ActionSummary {
    fn summary(&self) -> String;
}

#[derive(Debug)]
pub struct StatefulIdentity {
    layer: String,
}

impl StatefulIdentity {
    pub fn new(layer: String) -> Self {
        StatefulIdentity { layer }
    }
}

pub struct IdentityDesc {
    name: String,
}

impl IdentityDesc {
    pub fn new(name: String) -> Self {
        IdentityDesc { name }
    }
}

impl ActionDesc for IdentityDesc {
    fn fini(&self) {
        return;
    }

    fn gen_ht(&self, _dir: Direction) -> HT {
        HT {
            name: self.name.clone(),
            outer_ether: HeaderAction::Ignore,
            outer_ip: HeaderAction::Ignore,
            outer_udp: HeaderAction::Ignore,
            geneve: HeaderAction::Ignore,
            inner_ether: HeaderAction::Ignore,
            inner_ip: HeaderAction::Ignore,
            ulp: UlpHdrAction {
                icmp_du: HeaderAction::Ignore,
                icmp_echo: HeaderAction::Ignore,
                tcp: HeaderAction::Ignore,
                udp: HeaderAction::Ignore,
            },
        }
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
    pub fn new(name: String) -> Self {
        Identity { name }
    }
}

impl StaticAction for Identity {
    fn gen_ht(&self, _dir: Direction, _flow_id: InnerFlowId) -> HT {
        HT {
            name: self.name.clone(),
            outer_ether: HeaderAction::Ignore,
            outer_ip: HeaderAction::Ignore,
            outer_udp: HeaderAction::Ignore,
            geneve: HeaderAction::Ignore,
            inner_ether: HeaderAction::Ignore,
            inner_ip: HeaderAction::Ignore,
            ulp: UlpHdrAction {
                icmp_du: HeaderAction::Ignore,
                icmp_echo: HeaderAction::Ignore,
                tcp: HeaderAction::Ignore,
                udp: HeaderAction::Ignore,
            },
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UlpHdrAction {
    pub icmp_du: HeaderAction<IcmpDuMeta, IcmpDuMetaOpt>,
    pub icmp_echo: HeaderAction<IcmpEchoMeta, IcmpEchoMetaOpt>,
    pub tcp: HeaderAction<TcpMeta, TcpMetaOpt>,
    pub udp: HeaderAction<UdpMeta, UdpMetaOpt>,
}

impl UlpHdrAction {
    pub fn run(&self, meta: &mut PacketMeta) {
        match &mut meta.ulp {
            Some(ulp) => match ulp {
                UlpMeta::IcmpDu(_icmp_meta) => match &self.icmp_du {
                    HeaderAction::Ignore => (),

                    // TODO For now we only implement Ignore for ICMP DU.
                    action => {
                        todo!(
                            "action {:?} not implemented for ICMP DU",
                            action
                        );
                    }
                },

                UlpMeta::IcmpEcho(icmp_meta) => match &self.icmp_echo {
                    HeaderAction::Modify(arg) => {
                        icmp_meta.run_modify(&arg);
                    }

                    HeaderAction::Ignore => (),

                    // TODO: We really need to either a) return a
                    // runtime error when a user tries to create an
                    // action type (push, pop, modify, etc) for a
                    // header type which doesn't support it or b) make
                    // it a compile time error. Or all header types
                    // need to support all action types.
                    action => {
                        todo!(
                            "action {:?} not implemented for ICMP Echo",
                            action
                        );
                    }
                },

                UlpMeta::IcmpRedirect(_icmp_meta) => match &self.icmp_du {
                    HeaderAction::Ignore => (),

                    // TODO For now we only implement Ignore for ICMP Redirect.
                    action => {
                        todo!(
                            "action {:?} not implemented for ICMP Redirect",
                            action
                        );
                    }
                },

                UlpMeta::Tcp(tcp_meta) => match &self.tcp {
                    HeaderAction::Modify(arg) => {
                        tcp_meta.run_modify(&arg);
                    }

                    HeaderAction::Ignore => (),

                    action => {
                        todo!("implement run() for action {:?}", action);
                    }
                },

                UlpMeta::Udp(udp_meta) => match &self.udp {
                    HeaderAction::Modify(arg) => {
                        udp_meta.run_modify(&arg);
                    }

                    HeaderAction::Ignore => (),

                    action => {
                        todo!("implement run() for action {:?}", action);
                    }
                },
            },

            None => (),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HT {
    pub name: String,
    pub outer_ether: HeaderAction<EtherMeta, EtherMetaOpt>,
    pub outer_ip: HeaderAction<IpMeta, IpMetaOpt>,
    pub outer_udp: HeaderAction<UdpMeta, UdpMetaOpt>,
    pub geneve: HeaderAction<GeneveMeta, GeneveMetaOpt>,
    pub inner_ether: HeaderAction<EtherMeta, EtherMetaOpt>,
    pub inner_ip: HeaderAction<IpMeta, IpMetaOpt>,
    pub ulp: UlpHdrAction,
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

// We mark all the std-built probes as `unsafe`, not because they are,
// but in order to stay consistent with the externs, which are
// implicitly unsafe. This also keeps the compiler from throwing up a
// warning for every probe callsite when compiling with std.
//
// TODO In the future we could have these std versions of the probes
// modify some global state so that unit/functional tests can verify
// that they fire when expected. We could also wire them up as USDTs,
// allowing someone to inspect a test with DTrace.
#[cfg(any(feature = "std", test))]
pub unsafe fn __dtrace_probe_ht__run(_arg: uintptr_t) {
    ()
}

#[repr(C)]
pub struct flow_id_sdt_arg {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
}

impl From<&InnerFlowId> for flow_id_sdt_arg {
    fn from(ifid: &InnerFlowId) -> Self {
        let src_ip = match ifid.src_ip {
            IpAddr::Ip4(v) => v,
            _ => panic!("add IPv6 support for flow_id_sdt_arg"),
        };

        let dst_ip = match ifid.dst_ip {
            IpAddr::Ip4(v) => v,
            _ => panic!("add IPv6 support for flow_id_sdt_arg"),
        };

        flow_id_sdt_arg {
            // Consumers expect all data to be presented as it would
            // be traveling across the network.
            src_ip: src_ip.to_be(),
            dst_ip: dst_ip.to_be(),
            src_port: ifid.src_port.to_be(),
            dst_port: ifid.dst_port.to_be(),
            proto: ifid.proto as u8,
        }
    }
}

#[repr(C)]
pub struct ht_run_sdt_arg {
    pub loc: *const c_char,
    pub dir: *const c_char,
    pub flow_id_before: *const flow_id_sdt_arg,
    pub flow_id_after: *const flow_id_sdt_arg,
}

pub fn ht_fire_probe(
    loc: &str,
    dir: Direction,
    before: &InnerFlowId,
    after: &InnerFlowId,
) {
    let loc_c = CString::new(loc).unwrap();
    let dir_c = match dir {
        Direction::In => CString::new("in").unwrap(),
        Direction::Out => CString::new("out").unwrap(),
    };
    let flow_id_before = flow_id_sdt_arg::from(before);
    let flow_id_after = flow_id_sdt_arg::from(after);

    let arg = ht_run_sdt_arg {
        // TODO: Sigh, I'm only doing this because some
        // platforms define c_char as u8, and I want to be
        // able to run unit tests on those other platforms.
        #[cfg(all(not(feature = "std"), not(test)))]
        loc: loc_c.as_ptr(),
        #[cfg(any(feature = "std", test))]
        loc: loc_c.as_ptr() as *const u8 as *const c_char,
        #[cfg(all(not(feature = "std"), not(test)))]
        dir: dir_c.as_ptr(),
        #[cfg(any(feature = "std", test))]
        dir: dir_c.as_ptr() as *const u8 as *const c_char,
        flow_id_before: &flow_id_before,
        flow_id_after: &flow_id_after,
    };

    unsafe {
        __dtrace_probe_ht__run(&arg as *const ht_run_sdt_arg as uintptr_t);
    }
}

impl HT {
    pub fn run(&self, meta: &mut PacketMeta) {
        // TODO eventually we expect the inner_ether to always be
        // present, this is just here for now because in some testing
        // cases it's not always set.
        if meta.inner_ether.is_some() {
            self.inner_ether.run(&mut meta.inner_ether);
        }
        self.inner_ip.run(&mut meta.inner_ip);
        self.ulp.run(meta);
    }
}

#[derive(Debug)]
pub enum ResourceError {
    Exhausted,
    NoMatch(String),
}

pub struct Resources {
    pub nat_pool: KMutex<Option<NatPool>>,
}

impl Resources {
    pub fn new() -> Self {
        Resources { nat_pool: KMutex::new(None, KMutexType::Driver) }
    }

    pub fn set_nat_pool(&self, pool: NatPool) {
        if self.nat_pool.lock().unwrap().is_some() {
            // TODO: This is temporary, just want to avoid overwriting
            // the NAT Pool which could lead to very hard-to-debug
            // issues.
            panic!("attempt to overwrite NAT Pool");
        }

        self.nat_pool.lock().unwrap().replace(pool);
    }
}

pub trait StatefulAction {
    // TODO: Need to change to Result<Self::Desc, InitError> in order
    // to account for failures to obtain resources and such.
    fn gen_desc(
        &self,
        flow_id: InnerFlowId,
        resources: &Resources,
    ) -> Arc<dyn ActionDesc>;
}

pub trait StaticAction {
    fn gen_ht(&self, dir: Direction, flow_id: InnerFlowId) -> HT;
}

#[derive(Debug)]
pub enum GenErr {
    BadPayload(crate::packet::ReadErr),
    MissingMeta,
}

pub type GenResult<T> = Result<T, GenErr>;

/// A hairpin action is one that generates a new packet based on the
/// current inbound/outbound packet, and then "hairpins" that new
/// packet back to the source of the original packet. For example, you
/// could use this to hairpin an ARP Reply in response to a guest's
/// ARP request.
pub trait HairpinAction {
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
    ) -> GenResult<Packet<Initialized>>;
}

pub enum Action {
    Static(Box<dyn StaticAction>),
    Stateful(Box<dyn StatefulAction>),
    Hairpin(Box<dyn HairpinAction>),
}

// TODO I should probably name this something else now. It's role is
// to declare whether or not a rule match should execute the layer's
// associated action (Allow), or whether it should deny the packet
// (Deny).
#[derive(Clone, Debug)]
pub enum RuleAction {
    Allow(usize),
    Deny,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum RuleActionDump {
    Allow(usize),
    Deny,
}

impl From<&RuleAction> for RuleActionDump {
    fn from(ra: &RuleAction) -> Self {
        use RuleAction::*;

        match ra {
            Allow(idx) => RuleActionDump::Allow(*idx),
            Deny => RuleActionDump::Deny,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub priority: u16,
    predicates: Vec<Predicate>,
    data_predicates: Vec<DataPredicate>,
    pub action: RuleAction,
}

impl Rule {
    pub fn new(priority: u16, action: RuleAction) -> Self {
        Rule { priority, predicates: vec![], data_predicates: vec![], action }
    }

    pub fn add_predicate(&mut self, pred: Predicate) {
        self.predicates.push(pred);
    }

    pub fn add_data_predicate(&mut self, pred: DataPredicate) {
        self.data_predicates.push(pred);
    }

    pub fn is_match<R>(&self, meta: &PacketMeta, rdr: &mut R) -> bool
    where
        R: PacketRead,
    {
        for p in &self.predicates {
            if !p.is_match(meta) {
                return false;
            }
        }

        for p in &self.data_predicates {
            if !p.is_match(meta, rdr) {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RuleDump {
    pub priority: u16,
    pub predicates: Vec<Predicate>,
    pub action: RuleActionDump,
}

impl From<&Rule> for RuleDump {
    fn from(rule: &Rule) -> Self {
        RuleDump {
            priority: rule.priority,
            predicates: rule.predicates.clone(),
            action: RuleActionDump::from(&rule.action),
        }
    }
}

#[test]
fn rule_matching() {
    let mut r1 = Rule::new(1, RuleAction::Allow(0));
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

    let meta =
        PacketMeta { inner_ip: Some(ip), ulp: Some(ulp), ..Default::default() };

    r1.add_predicate(Predicate::InnerSrcIp4(vec![Ipv4AddrMatch::Exact(
        src_ip,
    )]));

    assert!(r1.is_match(&meta, &mut rdr));

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
        // inner_ether: Some(ether),
        inner_ip: Some(ip),
        ulp: Some(ulp),
        ..Default::default()
    };

    assert!(!r1.is_match(&meta, &mut rdr));
}

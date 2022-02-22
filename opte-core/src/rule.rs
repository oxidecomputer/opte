use core::fmt::{self, Display};

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::string::{String, ToString};
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::sync::Arc;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::vec::Vec;
#[cfg(any(feature = "std", test))]
use std::boxed::Box;
#[cfg(any(feature = "std", test))]
use std::string::{String, ToString};
#[cfg(any(feature = "std", test))]
use std::sync::Arc;
#[cfg(any(feature = "std", test))]
use std::vec::Vec;

use crate::arp::{
    ArpEth4Payload, ArpEth4PayloadRaw, ArpMeta, ArpOp, ARP_HTYPE_ETHERNET,
};
use crate::dhcp::{MessageType as DhcpMessageType};
use crate::ether::{EtherAddr, EtherMeta, EtherMetaOpt, ETHER_TYPE_IPV4};
use crate::flow_table::StateSummary;
use crate::geneve::{GeneveMeta, GeneveMetaOpt};
use crate::headers::{
    self, HeaderAction, IpAddr, IpMeta, IpMetaOpt, UlpHeaderAction, UlpMeta,
    UlpMetaOpt,
};
use crate::ip4::{Ipv4Addr, Ipv4Cidr, Ipv4Meta, Protocol};
use crate::ip6::Ipv6Meta;
use crate::layer::InnerFlowId;
use crate::packet::{
    Initialized, Packet, PacketMeta, PacketRead, PacketReader, Parsed,
};
use crate::port::meta::Meta;
use crate::tcp::TcpMeta;
use crate::udp::UdpMeta;
use crate::{CString, Direction};

use illumos_ddi_dki::{c_char, uintptr_t};

use serde::{Deserialize, Serialize};

use smoltcp::wire::{DhcpPacket, DhcpRepr};

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
    InnerSrcPort(Vec<PortMatch>),
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
            }

            Self::InnerEtherSrc(list) => match meta.inner.ether {
                None => return false,

                Some(EtherMeta { src, .. }) => {
                    for m in list {
                        if m.matches(src) {
                            return true;
                        }
                    }
                }
            }

            Self::InnerArpHtype(m) => match meta.inner.arp {
                None => return false,

                Some(ArpMeta { htype, .. }) => {
                    if m.matches(htype) {
                        return true;
                    }
                }
            }

            Self::InnerArpPtype(m) => match meta.inner.arp {
                None => return false,

                Some(ArpMeta { ptype, .. }) => {
                    if m.matches(ptype) {
                        return true;
                    }
                }
            }

            Self::InnerArpOp(m) => match meta.inner.arp {
                None => return false,

                Some(ArpMeta { op, .. }) => {
                    if m.matches(op) {
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
            }

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
            }

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
            }

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
            }

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
            }
        }

        false
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum DataPredicate {
    InnerDhcp4MsgType(DhcpMessageType),
    InnerArpTpa(Vec<Ipv4AddrMatch>),
    Not(Box<DataPredicate>),
}

impl Display for DataPredicate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DataPredicate::*;

        match self {
            InnerDhcp4MsgType(mt) => {
                write!(f, "inner.dhcp4.msg_type={}", mt)
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
    fn is_match<'a, 'b, R>(&self, meta: &PacketMeta, rdr: &'b mut R) -> bool
    where
        R: PacketRead<'a>,
    {
        match self {
            Self::Not(pred) => return !pred.is_match(meta, rdr),

            Self::InnerDhcp4MsgType(mt) => {
                let bytes = rdr.slice(rdr.seg_left()).unwrap();
                let pkt = match DhcpPacket::new_checked(bytes) {
                    Ok(v) => v,
                    Err(_) => return false,
                };
                let dhcp = match DhcpRepr::parse(&pkt) {
                    Ok(v) => v,
                    Err(_) => return false,
                };

                let res = DhcpMessageType::from(dhcp.message_type) == *mt;
                rdr.seek_back(bytes.len()).unwrap();
                return res;
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
                    rdr.seek_back(crate::arp::ARP_ETH4_PAYLOAD_SZ)
                        .expect("failed to seek back");

                    for m in list {
                        if m.matches(arp.tpa) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }
}

/// An Action Descriptor type holds the information needed to create
/// an HT which implements the desired action. An ActionDesc is
/// created by an [`Action`] implementation.
pub trait ActionDesc {
    /// Perform any finalization needed. For a [`StatefulAction`] this
    /// will typically release ownership of any obtained resource.
    fn fini(&self);

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
        _flow_id: InnerFlowId,
        _meta: &mut Meta,
    ) -> GenHtResult {
        Ok(HT::identity(&self.name))
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
    pub inner_ulp: UlpHeaderAction<crate::headers::UlpMetaModify>,
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
            IpAddr::Ip6(ip6) => (headers::AF_INET6, 0, ip6.to_bytes()),
        };

        let (dst_ip4, dst_ip6) = match ifid.dst_ip {
            IpAddr::Ip4(ip4) => (ip4.to_be(), [0; 16]),
            IpAddr::Ip6(ip6) => (0, ip6.to_bytes()),
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

pub type GenDescResult = Result<Arc<dyn ActionDesc>, GenDescError>;

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
    fn gen_desc(&self, flow_id: InnerFlowId, meta: &mut Meta) -> GenDescResult;
}

#[derive(Clone, Debug)]
pub enum GenHtError {
    ResourceExhausted { name: String },

    Unexpected { msg: String },
}

pub type GenHtResult = Result<HT, GenHtError>;

pub trait StaticAction: Display {
    fn gen_ht(
        &self,
        dir: Direction,
        flow_id: InnerFlowId,
        meta: &mut Meta,
    ) -> GenHtResult;
}

/// A meta action is one that's only goal is to modify the processing
/// metadata in some way. That is, it has no transformation to make on
/// the packet, only add/modify/remove metadata for use by later
/// layers.
pub trait MetaAction: Display {
    fn mod_meta(&self, flow_id: InnerFlowId, meta: &mut Meta);
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
    ) -> GenResult<Packet<Initialized>>;
}

#[derive(Clone)]
pub enum Action {
    Deny,
    Meta(Arc<dyn MetaAction>),
    Static(Arc<dyn StaticAction>),
    Stateful(Arc<dyn StatefulAction>),
    Hairpin(Arc<dyn HairpinAction>),
}

impl Action {
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
#[derive(Clone, Debug)]
pub struct RulePredicates {
    hdr_preds: Vec<Predicate>,
    data_preds: Vec<DataPredicate>,
}

pub trait RuleState {}

#[derive(Clone, Debug)]
pub struct Empty {}
impl RuleState for Empty {}

#[derive(Clone, Debug)]
pub struct Ready {
    hdr_preds: Vec<Predicate>,
    data_preds: Vec<DataPredicate>,
}
impl RuleState for Ready {}

#[derive(Clone, Debug)]
pub struct Finalized {
    preds: Option<RulePredicates>,
}
impl RuleState for Finalized {}

#[derive(Clone, Debug)]
pub struct Rule<S: RuleState> {
    state: S,
    action: Action,
    pub priority: u16,
}

impl<S: RuleState> Rule<S> {
    pub fn action(&self) -> &Action {
        &self.action
    }
}

impl Rule<Empty> {
    pub fn new(priority: u16, action: Action) -> Self {
        Rule { state: Empty {}, action, priority }
    }

    pub fn add_predicate(self, pred: Predicate) -> Rule<Ready> {
        Rule {
            state: Ready { hdr_preds: vec![pred], data_preds: vec![] },
            action: self.action,
            priority: self.priority,
        }
    }

    pub fn add_predicates(self, preds: Vec<Predicate>) -> Rule<Ready> {
        Rule {
            state: Ready { hdr_preds: preds, data_preds: vec![] },
            action: self.action,
            priority: self.priority,
        }
    }

    pub fn add_data_predicate(self, pred: DataPredicate) -> Rule<Ready> {
        Rule {
            state: Ready { hdr_preds: vec![], data_preds: vec![pred] },
            action: self.action,
            priority: self.priority,
        }
    }

    pub fn match_any(self) -> Rule<Finalized> {
        Rule {
            state: Finalized { preds: None },
            action: self.action,
            priority: self.priority,
        }
    }
}

impl Rule<Ready> {
    pub fn add_predicate(&mut self, pred: Predicate) {
        self.state.hdr_preds.push(pred);
    }

    pub fn add_data_predicate(&mut self, pred: DataPredicate) {
        self.state.data_preds.push(pred)
    }

    pub fn finalize(self) -> Rule<Finalized> {
        Rule {
            state: Finalized {
                preds: Some(RulePredicates {
                    hdr_preds: self.state.hdr_preds,
                    data_preds: self.state.data_preds,
                }),
            },
            priority: self.priority,
            action: self.action,
        }
    }
}

impl<'a> Rule<Finalized> {
    pub fn is_match<'b, R>(&self, meta: &PacketMeta, rdr: &'b mut R) -> bool
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
                    if !p.is_match(meta) {
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
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RuleDump {
    pub priority: u16,
    pub predicates: Vec<Predicate>,
    pub action: String,
}

impl From<&Rule<Finalized>> for RuleDump {
    fn from(rule: &Rule<Finalized>) -> Self {
        let predicates =
            rule.state.preds.as_ref().map_or(vec![], |rp| rp.hdr_preds.clone());

        RuleDump {
            priority: rule.priority,
            predicates,
            // XXX What about data predicates?
            action: rule.action.to_string(),
        }
    }
}

#[test]
fn rule_matching() {
    use crate::packet::MetaGroup;

    let action = Identity::new("rule_matching");
    let r1 = Rule::new(1, Action::Static(Arc::new(action)));
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

    let r1 =
        r1.add_predicate(Predicate::InnerSrcIp4(vec![Ipv4AddrMatch::Exact(
            src_ip,
        )]));
    let r1 = r1.finalize();

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
        outer: Default::default(),
        inner: MetaGroup { ip: Some(ip), ulp: Some(ulp), ..Default::default() },
    };

    assert!(!r1.is_match(&meta, &mut rdr));
}

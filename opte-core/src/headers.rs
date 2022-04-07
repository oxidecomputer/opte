use core::fmt;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::vec::Vec;
    } else {
        use std::vec::Vec;
    }
}

use serde::{Deserialize, Serialize};
use zerocopy::LayoutVerified;

use crate::checksum::Checksum;
use crate::ip4::{Ipv4Addr, Ipv4Hdr, Ipv4Meta, Ipv4MetaOpt, IPV4_HDR_SZ};
use crate::ip6::{Ipv6Addr, Ipv6Hdr, Ipv6Meta, Ipv6MetaOpt, IPV6_HDR_SZ};
use crate::packet::{PacketRead, ReadErr, WriteError};
use crate::tcp::{TcpHdr, TcpMeta, TcpMetaOpt};
use crate::udp::{UdpHdr, UdpMeta, UdpMetaOpt};
use opte_api as api;

/// Port 0 is reserved by the sockets layer. It is used by clients to
/// indicate they want the operating system to choose a port on their
/// behalf.
pub const DYNAMIC_PORT: u16 = 0;

pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 26;

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum IpAddr {
    Ip4(Ipv4Addr),
    Ip6(Ipv6Addr),
}

impl From<api::IpAddr> for IpAddr {
    fn from(addr: api::IpAddr) -> Self {
        match addr {
            api::IpAddr::Ip4(ip4) => Self::Ip4(ip4.into()),
            api::IpAddr::Ip6(ip6) => Self::Ip6(ip6.into()),
        }
    }
}

impl Default for IpAddr {
    fn default() -> Self {
        IpAddr::Ip4(Default::default())
    }
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IpAddr::Ip4(ip4) => write!(f, "{}", ip4),
            IpAddr::Ip6(_) => write!(f, "<IPv6 addr>"),
        }
    }
}

/// A raw header.
///
/// A raw header is the most basic and raw representation of a given
/// header type. A raw header value preserves the bytes as they are,
/// in network order. A raw header undergoes no validation of header
/// fields. A raw header represents only the base header, eschewing
/// any options or extensions.
pub trait RawHeader<'a> {
    /// Read a zerocopy version of the raw header from the [`Packet`]
    /// backing `rdr`.
    fn raw_zc<'b, R: PacketRead<'a>>(
        rdr: &'b mut R,
    ) -> Result<LayoutVerified<&'a [u8], Self>, ReadErr>;

    /// Read a mutable, zerocopy version of the raw header from the
    /// passed in mutable slice.
    fn raw_mut_zc(
        src: &mut [u8],
    ) -> Result<LayoutVerified<&mut [u8], Self>, WriteError>;
}

/// A parsed, partially validated header.
///
/// A value of this type represents a header type which has been
/// parsed from a [`RawHeader`]. This parsing includes some amount of
/// intra-header validation along with conversion from a sequence of
/// network-order bytes to native host types. This header value may
/// also include options or extension headers.
///
/// In general, this is the primary type of header value that OPTE
/// code should be dealing with. The idea is to convert [`RawHeader`]
/// to [`Header`] as close to the edges as possible.
///
/// NOTE: OPTE currently performs all header reads as copy-only. This
/// was done as a measure of expedience for development and to cut
/// down on initial complexity. Furthermore, while zerocopy can be
/// important, it's less important at this moment, especially for the
/// header data. There are larger performance wins to be had before we
/// worry too much about header zercopy, such as the Unified Flow
/// Table, checksum offloads, LSO, and LRO.
pub trait Header {
    type Error;

    /// Create a value of `Self` by attempting to parse and validate a
    /// copy of it from the provided [`PacketRead`] argument.
    fn parse<'a, 'b, R>(rdr: &'b mut R) -> Result<Self, Self::Error>
    where
        Self: core::marker::Sized,
        R: PacketRead<'a>;
}

pub trait PushActionArg {}
pub trait ModActionArg {}

#[derive(Clone, Copy, Debug)]
pub enum IpType {
    Ipv4,
    Ipv6,
}

#[derive(Debug)]
pub enum IpHdr {
    Ip4(Ipv4Hdr),
    Ip6(Ipv6Hdr),
}

#[macro_export]
macro_rules! assert_ip {
    ($left:expr, $right:expr) => {
        match ($left, $right) {
            (
                Some($crate::headers::IpHdr::Ip4(ip4_left)),
                Some($crate::headers::IpHdr::Ip4(ip4_right)),
            ) => {
                assert_ip4!(ip4_left, ip4_right);
            }

            (
                Some($crate::headers::IpHdr::Ip6(ip6_left)),
                Some($crate::headers::IpHdr::Ip6(ip6_right)),
            ) => {
                assert_ip6!(ip6_left, ip6_right);
            }

            (left, right) => {
                panic!(
                    "IP headers not same type\nleft: {:?}\nright: {:?}",
                    left, right,
                );
            }
        }
    };
}

impl IpHdr {
    pub fn hdr_len(&self) -> usize {
        match self {
            Self::Ip4(ip4) => ip4.hdr_len(),
            Self::Ip6(ip6) => ip6.hdr_len(),
        }
    }

    pub fn ip4(&self) -> Option<&Ipv4Hdr> {
        match self {
            Self::Ip4(ip4) => Some(ip4),
            _ => None,
        }
    }

    pub fn ip6(&self) -> Option<&Ipv6Hdr> {
        match self {
            Self::Ip6(ip6) => Some(ip6),
            _ => None,
        }
    }

    pub fn pay_len(&self) -> usize {
        match self {
            Self::Ip4(ip4) => ip4.pay_len(),
            Self::Ip6(ip6) => ip6.pay_len(),
        }
    }

    pub fn pseudo_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ip4(ip4) => ip4.pseudo_bytes(),
            Self::Ip6(ip6) => ip6.pseudo_bytes(),
        }
    }

    pub fn pseudo_csum(&self) -> Checksum {
        match self {
            Self::Ip4(ip4) => ip4.pseudo_csum(),
            Self::Ip6(ip6) => ip6.pseudo_csum(),
        }
    }

    pub fn set_total_len(&mut self, len: usize) {
        match self {
            Self::Ip4(ip4) => ip4.set_total_len(len as u16),
            Self::Ip6(ip6) => ip6.set_total_len(len as u16),
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Self::Ip4(_) => IPV4_HDR_SZ,
            Self::Ip6(_) => IPV6_HDR_SZ,
        }
    }

    pub fn total_len(&self) -> u16 {
        match self {
            Self::Ip4(ip4) => ip4.total_len(),
            Self::Ip6(_ip6) => todo!("implement"),
        }
    }
}

impl From<Ipv4Hdr> for IpHdr {
    fn from(ip4: Ipv4Hdr) -> Self {
        IpHdr::Ip4(ip4)
    }
}

impl From<Ipv6Hdr> for IpHdr {
    fn from(ip6: Ipv6Hdr) -> Self {
        IpHdr::Ip6(ip6)
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum IpMeta {
    Ip4(Ipv4Meta),
    Ip6(Ipv6Meta),
}

impl IpMeta {
    pub fn ip4(&self) -> Option<&Ipv4Meta> {
        match self {
            Self::Ip4(meta) => Some(meta),
            _ => None,
        }
    }
}

impl From<Ipv4Meta> for IpMeta {
    fn from(ip4: Ipv4Meta) -> Self {
        IpMeta::Ip4(ip4)
    }
}

impl From<Ipv6Meta> for IpMeta {
    fn from(ip6: Ipv6Meta) -> Self {
        IpMeta::Ip6(ip6)
    }
}

impl From<&IpHdr> for IpMeta {
    fn from(ip: &IpHdr) -> Self {
        match ip {
            IpHdr::Ip4(ip4) => IpMeta::Ip4(Ipv4Meta::from(ip4)),
            IpHdr::Ip6(ip6) => IpMeta::Ip6(Ipv6Meta::from(ip6)),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum IpMetaOpt {
    Ip4(Ipv4MetaOpt),
    Ip6(Ipv6MetaOpt),
}

impl PushActionArg for IpMeta {}
impl ModActionArg for IpMetaOpt {}

impl From<Ipv4MetaOpt> for IpMetaOpt {
    fn from(ip4: Ipv4MetaOpt) -> Self {
        IpMetaOpt::Ip4(ip4)
    }
}

impl HeaderActionModify<IpMetaOpt> for IpMeta {
    fn run_modify(&mut self, spec: &IpMetaOpt) {
        match (self, spec) {
            (IpMeta::Ip4(ip4_meta), IpMetaOpt::Ip4(ip4_spec)) => {
                ip4_meta.run_modify(&ip4_spec);
            }

            (IpMeta::Ip6(_ip6_meta), IpMetaOpt::Ip6(_ip6_spec)) => {
                todo!("implement IPv6 run_modify()");
            }

            (meta, spec) => {
                panic!("differeing IP meta and spec: {:?} {:?}", meta, spec);
            }
        }
    }
}

#[derive(Debug)]
pub enum UlpHdr {
    Tcp(TcpHdr),
    Udp(UdpHdr),
}

#[macro_export]
macro_rules! assert_ulp {
    ($left:expr, $right:expr) => {
        match ($left, $right) {
            (
                Some($crate::headers::UlpHdr::Tcp(tcp_left)),
                Some($crate::headers::UlpHdr::Tcp(tcp_right)),
            ) => {
                assert_tcp!(tcp_left, tcp_right);
            }

            (
                Some($crate::headers::UlpHdr::Udp(udp_left)),
                Some($crate::headers::UlpHdr::Udp(udp_right)),
            ) => {
                assert_udp!(udp_left, udp_right);
            }

            (left, right) => {
                panic!(
                    "ULP headers not same type\nleft: {:?}\nright: {:?}",
                    left, right,
                );
            }
        }
    };
}

impl UlpHdr {
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            Self::Tcp(tcp) => tcp.as_bytes(),
            Self::Udp(udp) => udp.as_bytes(),
        }
    }

    pub fn csum_minus_hdr(&self) -> Checksum {
        match self {
            Self::Tcp(tcp) => tcp.csum_minus_hdr(),
            Self::Udp(udp) => udp.csum_minus_hdr(),
        }
    }

    pub fn hdr_len(&self) -> usize {
        match self {
            Self::Tcp(tcp) => tcp.hdr_len(),
            Self::Udp(udp) => udp.hdr_len(),
        }
    }

    pub fn set_pay_len(&mut self, len: usize) {
        match self {
            // Nothing to do for TCP as it determines payload len from
            // IP header.
            Self::Tcp(_tcp) => (),
            Self::Udp(udp) => udp.set_pay_len(len as u16),
        }
    }

    pub fn set_total_len(&mut self, len: usize) {
        match self {
            // Nothing to do for TCP as it determines payload len from
            // IP header.
            Self::Tcp(_tcp) => (),
            Self::Udp(udp) => udp.set_total_len(len as u16),
        }
    }

    pub fn udp(&self) -> Option<&UdpHdr> {
        match self {
            Self::Udp(udp) => Some(udp),
            _ => None,
        }
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum UlpMeta {
    Tcp(TcpMeta),
    Udp(UdpMeta),
}

impl PushActionArg for UlpMeta {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum UlpMetaOpt {
    Tcp(TcpMetaOpt),
    Udp(UdpMetaOpt),
}

impl ModActionArg for UlpMetaOpt {}

impl HeaderActionModify<UlpMetaOpt> for UlpMeta {
    fn run_modify(&mut self, spec: &UlpMetaOpt) {
        match (self, spec) {
            (UlpMeta::Tcp(tcp_meta), UlpMetaOpt::Tcp(tcp_spec)) => {
                tcp_meta.run_modify(tcp_spec);
            }

            (UlpMeta::Udp(udp_meta), UlpMetaOpt::Udp(udp_spec)) => {
                udp_meta.run_modify(udp_spec);
            }

            (meta, spec) => {
                panic!("differeing IP meta and spec: {:?} {:?}", meta, spec);
            }
        }
    }
}

impl From<TcpMeta> for UlpMeta {
    fn from(tcp: TcpMeta) -> Self {
        UlpMeta::Tcp(tcp)
    }
}

impl From<UdpMeta> for UlpMeta {
    fn from(udp: UdpMeta) -> Self {
        UlpMeta::Udp(udp)
    }
}

impl From<&UlpHdr> for UlpMeta {
    fn from(ulp: &UlpHdr) -> Self {
        match ulp {
            UlpHdr::Tcp(tcp) => UlpMeta::Tcp(TcpMeta::from(tcp)),
            UlpHdr::Udp(udp) => UlpMeta::Udp(UdpMeta::from(udp)),
        }
    }
}

impl HeaderActionModify<UlpMetaModify> for UlpMeta {
    fn run_modify(&mut self, spec: &UlpMetaModify) {
        match self {
            UlpMeta::Tcp(tcp_meta) => tcp_meta.run_modify(spec),

            UlpMeta::Udp(udp_meta) => udp_meta.run_modify(spec),
        }
    }
}

/// The action to take for a particular header transposition.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum HeaderAction<P, M>
where
    P: PushActionArg + fmt::Debug,
    M: ModActionArg + fmt::Debug,
{
    Push(P),
    Pop,
    Modify(M),
    Ignore,
}

impl<P, M> Default for HeaderAction<P, M>
where
    P: PushActionArg + fmt::Debug,
    M: ModActionArg + fmt::Debug,
{
    fn default() -> HeaderAction<P, M> {
        HeaderAction::Ignore
    }
}

// XXX Every time I look at this I ask myself "why must P be
// PushActionArg?". This is just saying that the metadata passed to
// run() must be the actual full header metadata (e.g. `TcpMeta`). But
// because of the way I coded this up originally that's also the same
// type as the argument for a push action. That is, I've conflated the
// header metadata and the action arguments a bit. This is mostly fine
// because the two overlap almost 100% (i.e., the values needed for
// header metadata and the values needed to push a header are
// basically always the same), but it's a bit confusing and it would
// probably be better to place a seam between these two things.
impl<P, M> HeaderAction<P, M>
where
    P: HeaderActionModify<M> + PushActionArg + Clone + fmt::Debug,
    M: ModActionArg + fmt::Debug,
{
    pub fn run(&self, meta: &mut Option<P>) {
        match self {
            Self::Ignore => (),

            Self::Modify(arg) => meta.as_mut().unwrap().run_modify(arg),

            Self::Push(arg) => {
                meta.replace(arg.clone());
            }

            Self::Pop => {
                meta.take();
            }
        }
    }
}

pub trait HeaderActionModify<M: ModActionArg> {
    fn run_modify(&mut self, mod_spec: &M);
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UlpGenericModify {
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UlpMetaModify {
    pub generic: UlpGenericModify,
    pub tcp_flags: Option<u8>,
}

impl ModActionArg for UlpMetaModify {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum UlpHeaderAction<M>
where
    M: ModActionArg + fmt::Debug,
{
    Ignore,
    Modify(M),
}

impl<M> Default for UlpHeaderAction<M>
where
    M: ModActionArg + fmt::Debug,
{
    fn default() -> UlpHeaderAction<M> {
        UlpHeaderAction::Ignore
    }
}

impl<M> UlpHeaderAction<M>
where
    M: ModActionArg + fmt::Debug,
{
    pub fn run<P>(&self, meta: &mut Option<P>)
    where
        P: HeaderActionModify<M> + fmt::Debug,
    {
        match self {
            Self::Ignore => (),
            Self::Modify(arg) => meta.as_mut().unwrap().run_modify(arg),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum IpCidr {
    Ip4(crate::ip4::Ipv4Cidr),
    Ip6(crate::ip6::Ipv6Cidr),
}

impl From<api::IpCidr> for IpCidr {
    fn from(cidr: api::IpCidr) -> Self {
        match cidr {
            api::IpCidr::Ip4(ip4) => Self::Ip4(ip4.into()),
            api::IpCidr::Ip6(ip6) => Self::Ip6(ip6.into()),
        }
    }
}

impl IpCidr {
    pub fn is_default(&self) -> bool {
        match self {
            Self::Ip4(ip4) => ip4.is_default(),
            Self::Ip6(_) => todo!("IPv6 is_default"),
        }
    }

    pub fn prefix(&self) -> usize {
        match self {
            Self::Ip4(ip4) => ip4.prefix() as usize,
            Self::Ip6(_) => todo!("IPv6 prefix"),
        }
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Ip4(ip4) => write!(f, "{}", ip4),
            Self::Ip6(ip6) => write!(f, "{:?}", ip6),
        }
    }
}

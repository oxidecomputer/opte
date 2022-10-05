// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use super::checksum::Checksum;
use super::ip4::Ipv4Hdr;
use super::ip4::Ipv4Meta;
use super::ip4::Ipv4MetaOpt;
use super::ip6::Ipv6Hdr;
use super::ip6::Ipv6Meta;
use super::ip6::Ipv6MetaOpt;
use super::packet::PacketRead;
use super::packet::ReadErr;
use super::packet::WriteError;
use super::tcp::TcpHdr;
use super::tcp::TcpMeta;
use super::tcp::TcpMetaOpt;
use super::udp::UdpHdr;
use super::udp::UdpMeta;
use super::udp::UdpMetaOpt;
use core::fmt;
pub use opte_api::IpAddr;
pub use opte_api::IpCidr;
pub use opte_api::Protocol;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::LayoutVerified;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::vec::Vec;
    } else {
        use std::vec::Vec;
    }
}

pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 26;

/// A raw header.
///
/// A raw header is the most basic and raw representation of a given
/// header type. A raw header value preserves the bytes as they are,
/// in network order. A raw header undergoes no validation of header
/// fields. A raw header represents only the base header, eschewing
/// any options or extensions.
pub trait RawHeader<'a> {
    /// Read a zerocopy version of the raw header from the `Packet`
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

/// A type that is meant to be used as an argument to a
/// [`HeaderActionModify`] implementation.
pub trait ModifyActionArg {}

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
                Some($crate::engine::headers::IpHdr::Ip4(ip4_left)),
                Some($crate::engine::headers::IpHdr::Ip4(ip4_right)),
            ) => {
                assert_ip4!(ip4_left, ip4_right);
            }

            (
                Some($crate::engine::headers::IpHdr::Ip6(ip6_left)),
                Some($crate::engine::headers::IpHdr::Ip6(ip6_right)),
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
    /// Return the total length of the header.
    ///
    /// In the case of IPv6, this includes any extension headers.
    pub fn hdr_len(&self) -> usize {
        match self {
            Self::Ip4(ip4) => ip4.hdr_len(),
            Self::Ip6(ip6) => ip6.hdr_len(),
        }
    }

    /// Return `Some` if this is an IPv4 header, or `None`.
    pub fn ip4(&self) -> Option<&Ipv4Hdr> {
        match self {
            Self::Ip4(ip4) => Some(ip4),
            _ => None,
        }
    }

    /// Return `Some` if this is an IPv6 header, or `None`.
    pub fn ip6(&self) -> Option<&Ipv6Hdr> {
        match self {
            Self::Ip6(ip6) => Some(ip6),
            _ => None,
        }
    }

    /// Return the length of the upper-layer protocol contents.
    pub fn ulp_len(&self) -> usize {
        match self {
            Self::Ip4(ip4) => ip4.ulp_len(),
            Self::Ip6(ip6) => ip6.ulp_len(),
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

    /// Set the total length of the packet, in octets.
    pub fn set_total_len(&mut self, len: usize) {
        match self {
            Self::Ip4(ip4) => ip4.set_total_len(len as u16),
            Self::Ip6(ip6) => ip6.set_total_len(len as u16),
        }
    }

    /// Total length of the packet, including all headers and payload
    pub fn total_len(&self) -> u16 {
        match self {
            Self::Ip4(ip4) => ip4.total_len(),
            Self::Ip6(ip6) => ip6.total_len(),
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
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, Copy,
)]
pub enum IpMeta {
    Ip4(Ipv4Meta),
    Ip6(Ipv6Meta),
}

impl IpMeta {
    /// Get the [`Ipv4Meta`], if this is IPv4.
    pub fn ip4(&self) -> Option<&Ipv4Meta> {
        match self {
            Self::Ip4(meta) => Some(meta),
            _ => None,
        }
    }

    /// Get the [`Ipv6Meta`], if this is IPv6.
    pub fn ip6(&self) -> Option<&Ipv6Meta> {
        match self {
            Self::Ip6(meta) => Some(meta),
            _ => None,
        }
    }

    /// Get the [`Protocol`].
    pub fn proto(&self) -> Protocol {
        match self {
            Self::Ip4(meta) => meta.proto,
            Self::Ip6(meta) => meta.proto,
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
impl ModifyActionArg for IpMetaOpt {}

impl From<Ipv4MetaOpt> for IpMetaOpt {
    fn from(ip4: Ipv4MetaOpt) -> Self {
        IpMetaOpt::Ip4(ip4)
    }
}

impl From<Ipv6MetaOpt> for IpMetaOpt {
    fn from(ip6: Ipv6MetaOpt) -> Self {
        IpMetaOpt::Ip6(ip6)
    }
}

impl HeaderActionModify<IpMetaOpt> for IpMeta {
    fn run_modify(&mut self, spec: &IpMetaOpt) {
        match (self, spec) {
            (IpMeta::Ip4(ip4_meta), IpMetaOpt::Ip4(ip4_spec)) => {
                ip4_meta.run_modify(&ip4_spec);
            }

            (IpMeta::Ip6(ip6_meta), IpMetaOpt::Ip6(ip6_spec)) => {
                ip6_meta.run_modify(&ip6_spec);
            }

            (meta, spec) => {
                panic!(
                    "Different IP versions for meta and spec: {:?} {:?}",
                    meta, spec
                );
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
                Some($crate::engine::headers::UlpHdr::Tcp(tcp_left)),
                Some($crate::engine::headers::UlpHdr::Tcp(tcp_right)),
            ) => {
                assert_tcp!(tcp_left, tcp_right);
            }

            (
                Some($crate::engine::headers::UlpHdr::Udp(udp_left)),
                Some($crate::engine::headers::UlpHdr::Udp(udp_right)),
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

impl ModifyActionArg for UlpMetaOpt {}

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
    M: ModifyActionArg + fmt::Debug,
{
    Push(P),
    Pop,
    Modify(M),
    Ignore,
}

impl<P, M> Default for HeaderAction<P, M>
where
    P: PushActionArg + fmt::Debug,
    M: ModifyActionArg + fmt::Debug,
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
    M: ModifyActionArg + fmt::Debug,
{
    pub fn run(&self, meta: &mut Option<P>) -> Result<(), HeaderActionError> {
        match self {
            Self::Ignore => (),

            Self::Modify(arg) => match meta {
                Some(meta) => meta.run_modify(arg),
                None => return Err(HeaderActionError::MissingHeader),
            },

            Self::Push(arg) => {
                meta.replace(arg.clone());
            }

            // A previous action may have already removed this meta,
            // which is fine.
            Self::Pop => {
                meta.take();
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum HeaderActionError {
    MissingHeader,
}

/// A header type that allows itself to be modified via a
/// [`ModifyActionArg`] specification.
pub trait HeaderActionModify<M: ModifyActionArg> {
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

impl ModifyActionArg for UlpMetaModify {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum UlpHeaderAction<M: ModifyActionArg> {
    Ignore,
    Modify(M),
}

impl<M: ModifyActionArg> Default for UlpHeaderAction<M> {
    fn default() -> UlpHeaderAction<M> {
        UlpHeaderAction::Ignore
    }
}

impl<M: ModifyActionArg> UlpHeaderAction<M> {
    pub fn run<P>(&self, meta: &mut Option<P>) -> Result<(), HeaderActionError>
    where
        P: HeaderActionModify<M>,
    {
        match self {
            Self::Ignore => (),
            Self::Modify(arg) => match meta {
                Some(meta) => meta.run_modify(arg),
                None => return Err(HeaderActionError::MissingHeader),
            },
        }

        Ok(())
    }
}

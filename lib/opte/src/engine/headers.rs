// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Header metadata combinations for IP, ULP, and Encap.

use super::checksum::Checksum;
use super::geneve::GeneveHdr;
use super::geneve::GeneveMeta;
use super::geneve::GeneveMod;
use super::geneve::GenevePush;
use super::icmpv6::Icmpv6Hdr;
use super::icmpv6::Icmpv6Meta;
use super::ip4::Ipv4Hdr;
use super::ip4::Ipv4Meta;
use super::ip4::Ipv4Mod;
use super::ip4::Ipv4Push;
use super::ip6::Ipv6Hdr;
use super::ip6::Ipv6Meta;
use super::ip6::Ipv6Mod;
use super::ip6::Ipv6Push;
use super::packet::ReadErr;
use super::tcp::TcpHdr;
use super::tcp::TcpMeta;
use super::tcp::TcpMod;
use super::tcp::TcpPush;
use super::udp::UdpHdr;
use super::udp::UdpMeta;
use super::udp::UdpMod;
use super::udp::UdpPush;
use core::fmt;
pub use opte_api::IpAddr;
pub use opte_api::IpCidr;
pub use opte_api::Protocol;
pub use opte_api::Vni;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::LayoutVerified;

pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 26;

/// A raw header.
///
/// A raw header is the most basic and raw representation of a given
/// header type. A raw header value preserves the bytes as they are,
/// in network order. A raw header undergoes no validation of header
/// fields. A raw header represents only the base header, eschewing
/// any options or extensions.
pub trait RawHeader<'a>: Sized {
    const SIZE: usize = core::mem::size_of::<Self>();

    /// Create a mutable, zerocopy version of the raw header from the
    /// src.
    fn new_mut(
        src: &mut [u8],
    ) -> Result<LayoutVerified<&mut [u8], Self>, ReadErr>;

    /// Create an immutable, zerocopy version of the raw header from the
    /// src.
    fn new(_src: &[u8]) -> Result<LayoutVerified<&[u8], Self>, ReadErr> {
        Err(ReadErr::NotImplemented)
    }
}

pub trait PushAction<HdrM> {
    fn push(&self) -> HdrM;
}

/// A type that is meant to be used as an argument to a
/// [`HeaderActionModify`] implementation.
pub trait ModifyAction<HdrM> {
    fn modify(&self, meta: &mut HdrM);
}

#[derive(Clone, Copy, Debug)]
pub enum IpType {
    Ipv4,
    Ipv6,
}

#[derive(Debug)]
pub enum IpHdr<'a> {
    Ip4(Ipv4Hdr<'a>),
    Ip6(Ipv6Hdr<'a>),
}

impl<'a> IpHdr<'a> {
    pub fn pseudo_csum(&self) -> Checksum {
        match self {
            Self::Ip4(ip4) => ip4.pseudo_csum(),
            Self::Ip6(ip6) => ip6.pseudo_csum(),
        }
    }
}

impl<'a> From<Ipv4Hdr<'a>> for IpHdr<'a> {
    fn from(ip4: Ipv4Hdr<'a>) -> Self {
        Self::Ip4(ip4)
    }
}

impl<'a> From<Ipv6Hdr<'a>> for IpHdr<'a> {
    fn from(ip6: Ipv6Hdr<'a>) -> Self {
        Self::Ip6(ip6)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Copy)]
pub enum IpMeta {
    Ip4(Ipv4Meta),
    Ip6(Ipv6Meta),
}

impl IpMeta {
    /// Return the checksum value.
    pub fn csum(&self) -> [u8; 2] {
        match self {
            Self::Ip4(ip4) => ip4.csum,
            // IPv6 has no checksum.
            Self::Ip6(_) => [0; 2],
        }
    }

    pub fn has_csum(&self) -> bool {
        match self {
            Self::Ip4(ip4) => ip4.csum != [0; 2],
            // IPv6 has no checksum.
            Self::Ip6(_) => false,
        }
    }

    pub fn emit(&self, dst: &mut [u8]) {
        match self {
            Self::Ip4(ip4) => ip4.emit(dst),
            Self::Ip6(ip6) => ip6.emit(dst),
        }
    }

    pub fn hdr_len(&self) -> usize {
        match self {
            Self::Ip4(ip4) => ip4.hdr_len(),
            Self::Ip6(ip6) => ip6.hdr_len(),
        }
    }

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

    pub fn pseudo_csum(&self) -> Checksum {
        match self {
            Self::Ip4(ip4) => ip4.pseudo_csum(),
            Self::Ip6(ip6) => ip6.pseudo_csum(),
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum IpPush {
    Ip4(Ipv4Push),
    Ip6(Ipv6Push),
}

impl PushAction<IpMeta> for IpPush {
    fn push(&self) -> IpMeta {
        match self {
            Self::Ip4(spec) => IpMeta::from(spec.push()),

            Self::Ip6(spec) => IpMeta::from(spec.push()),
        }
    }
}

impl From<Ipv4Push> for IpPush {
    fn from(ip4: Ipv4Push) -> Self {
        Self::Ip4(ip4)
    }
}

impl From<Ipv6Push> for IpPush {
    fn from(ip6: Ipv6Push) -> Self {
        Self::Ip6(ip6)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum IpMod {
    Ip4(Ipv4Mod),
    Ip6(Ipv6Mod),
}

impl ModifyAction<IpMeta> for IpMod {
    fn modify(&self, meta: &mut IpMeta) {
        match (self, meta) {
            (IpMod::Ip4(spec), IpMeta::Ip4(meta)) => {
                spec.modify(meta);
            }

            (IpMod::Ip6(spec), IpMeta::Ip6(meta)) => {
                spec.modify(meta);
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

impl From<Ipv4Mod> for IpMod {
    fn from(ip4: Ipv4Mod) -> Self {
        Self::Ip4(ip4)
    }
}

impl From<Ipv6Mod> for IpMod {
    fn from(ip6: Ipv6Mod) -> Self {
        Self::Ip6(ip6)
    }
}

pub enum EncapHdr<'a> {
    Geneve(GeneveHdr<'a>),
}

impl<'a> From<GeneveHdr<'a>> for EncapHdr<'a> {
    fn from(hdr: GeneveHdr<'a>) -> Self {
        Self::Geneve(hdr)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EncapMeta {
    Geneve(GeneveMeta),
}

impl From<GeneveMeta> for EncapMeta {
    fn from(meta: GeneveMeta) -> Self {
        Self::Geneve(meta)
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, Copy,
)]
pub enum EncapPush {
    Geneve(GenevePush),
}

impl PushAction<EncapMeta> for EncapPush {
    fn push(&self) -> EncapMeta {
        match self {
            Self::Geneve(gp) => EncapMeta::from(gp.push()),
        }
    }
}

impl From<GenevePush> for EncapPush {
    fn from(gp: GenevePush) -> Self {
        Self::Geneve(gp)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum EncapMod {
    Geneve(GeneveMod),
}

impl ModifyAction<EncapMeta> for EncapMod {
    fn modify(&self, meta: &mut EncapMeta) {
        match (self, meta) {
            (EncapMod::Geneve(g_spec), EncapMeta::Geneve(g_meta)) => {
                g_spec.modify(g_meta);
            }
        }
    }
}

impl EncapMeta {
    pub fn hdr_len(&self) -> usize {
        match self {
            Self::Geneve(geneve) => geneve.hdr_len(),
        }
    }
}

#[derive(Debug)]
pub enum UlpHdr<'a> {
    Icmpv6(Icmpv6Hdr<'a>),
    Tcp(TcpHdr<'a>),
    Udp(UdpHdr<'a>),
}

impl<'a> UlpHdr<'a> {
    pub fn csum_minus_hdr(&self) -> Option<Checksum> {
        match self {
            Self::Icmpv6(icmp6) => icmp6.csum_minus_hdr(),
            Self::Tcp(tcp) => tcp.csum_minus_hdr(),
            Self::Udp(udp) => udp.csum_minus_hdr(),
        }
    }

    pub fn hdr_len(&self) -> usize {
        match self {
            Self::Icmpv6(icmp6) => icmp6.hdr_len(),
            Self::Tcp(tcp) => tcp.hdr_len(),
            Self::Udp(udp) => udp.hdr_len(),
        }
    }

    pub fn set_pay_len(&mut self, len: usize) {
        match self {
            // Nothing to do for ICMPv6 or TCP which determine payload len
            // from IP header.
            Self::Icmpv6(_icmp6) => (),
            Self::Tcp(_tcp) => (),
            Self::Udp(udp) => udp.set_pay_len(len as u16),
        }
    }

    pub fn set_total_len(&mut self, len: usize) {
        match self {
            // Nothing to do for ICMPv6 or TCP which determine payload len
            // from IP header.
            Self::Icmpv6(_icmp6) => (),
            Self::Tcp(_tcp) => (),
            Self::Udp(udp) => udp.set_len(len as u16),
        }
    }

    pub fn udp(&self) -> Option<&UdpHdr> {
        match self {
            Self::Udp(udp) => Some(udp),
            _ => None,
        }
    }
}

impl<'a> From<Icmpv6Hdr<'a>> for UlpHdr<'a> {
    fn from(icmp6: Icmpv6Hdr<'a>) -> Self {
        Self::Icmpv6(icmp6)
    }
}

impl<'a> From<TcpHdr<'a>> for UlpHdr<'a> {
    fn from(tcp: TcpHdr<'a>) -> Self {
        UlpHdr::Tcp(tcp)
    }
}

impl<'a> From<UdpHdr<'a>> for UlpHdr<'a> {
    fn from(udp: UdpHdr<'a>) -> Self {
        Self::Udp(udp)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum UlpMeta {
    Icmpv6(Icmpv6Meta),
    Tcp(TcpMeta),
    Udp(UdpMeta),
}

impl UlpMeta {
    /// Return the checksum value.
    pub fn csum(&self) -> [u8; 2] {
        match self {
            Self::Icmpv6(icmp6) => icmp6.csum,
            Self::Tcp(tcp) => tcp.csum,
            Self::Udp(udp) => udp.csum,
        }
    }

    pub fn has_csum(&self) -> bool {
        match self {
            Self::Icmpv6(icmp6) => icmp6.csum != [0; 2],
            Self::Tcp(tcp) => tcp.csum != [0; 2],
            Self::Udp(udp) => udp.csum != [0; 2],
        }
    }

    /// Return the destination port, if any.
    pub fn dst_port(&self) -> Option<u16> {
        match self {
            Self::Icmpv6(_) => None,
            Self::Tcp(tcp) => Some(tcp.dst),
            Self::Udp(udp) => Some(udp.dst),
        }
    }

    pub fn hdr_len(&self) -> usize {
        match self {
            Self::Icmpv6(icmp) => icmp.hdr_len(),
            Self::Tcp(tcp) => tcp.hdr_len(),
            Self::Udp(udp) => udp.hdr_len(),
        }
    }

    /// Return the source port, if any.
    pub fn src_port(&self) -> Option<u16> {
        match self {
            Self::Icmpv6(_) => None,
            Self::Tcp(tcp) => Some(tcp.src),
            Self::Udp(udp) => Some(udp.src),
        }
    }

    pub fn emit(&self, dst: &mut [u8]) {
        match self {
            Self::Icmpv6(icmp) => icmp.emit(dst),
            Self::Tcp(tcp) => tcp.emit(dst),
            Self::Udp(udp) => udp.emit(dst),
        }
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum UlpPush {
    Tcp(TcpPush),
    Udp(UdpPush),
}

impl PushAction<UlpMeta> for UlpPush {
    fn push(&self) -> UlpMeta {
        match self {
            Self::Tcp(tcp) => UlpMeta::from(tcp.push()),

            Self::Udp(udp) => UlpMeta::from(udp.push()),
        }
    }
}

impl From<TcpPush> for UlpPush {
    fn from(tcp: TcpPush) -> Self {
        UlpPush::Tcp(tcp)
    }
}

impl From<UdpPush> for UlpPush {
    fn from(udp: UdpPush) -> Self {
        UlpPush::Udp(udp)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum UlpMod {
    Tcp(TcpMod),
    Udp(UdpMod),
}

impl ModifyAction<UlpMeta> for UlpMod {
    fn modify(&self, meta: &mut UlpMeta) {
        match (self, meta) {
            (Self::Tcp(spec), UlpMeta::Tcp(meta)) => {
                spec.modify(meta);
            }

            (Self::Udp(spec), UlpMeta::Udp(meta)) => {
                spec.modify(meta);
            }

            (spec, meta) => {
                panic!("differeing ULP meta and spec: {:?} {:?}", meta, spec);
            }
        }
    }
}

impl From<TcpMod> for UlpMod {
    fn from(tcp: TcpMod) -> Self {
        UlpMod::Tcp(tcp)
    }
}

impl From<UdpMod> for UlpMod {
    fn from(udp: UdpMod) -> Self {
        UlpMod::Udp(udp)
    }
}

impl From<Icmpv6Meta> for UlpMeta {
    fn from(icmp6: Icmpv6Meta) -> Self {
        UlpMeta::Icmpv6(icmp6)
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

impl<'a> From<&UlpHdr<'a>> for UlpMeta {
    fn from(ulp: &UlpHdr) -> Self {
        match ulp {
            UlpHdr::Icmpv6(icmp6) => UlpMeta::Icmpv6(Icmpv6Meta::from(icmp6)),
            UlpHdr::Tcp(tcp) => UlpMeta::Tcp(TcpMeta::from(tcp)),
            UlpHdr::Udp(udp) => UlpMeta::Udp(UdpMeta::from(udp)),
        }
    }
}

impl HeaderActionModify<UlpMetaModify> for UlpMeta {
    fn run_modify(&mut self, spec: &UlpMetaModify) {
        match self {
            UlpMeta::Icmpv6(_) => {}
            UlpMeta::Tcp(tcp_meta) => tcp_meta.run_modify(spec),
            UlpMeta::Udp(udp_meta) => udp_meta.run_modify(spec),
        }
    }
}

/// The action to take for a particular header transposition.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum HeaderAction<H, P, M>
where
    P: PushAction<H> + fmt::Debug,
    M: ModifyAction<H> + fmt::Debug,
{
    Push(P, core::marker::PhantomData<H>),
    Pop,
    Modify(M, core::marker::PhantomData<H>),
    #[default]
    Ignore,
}

impl<H, P, M> HeaderAction<H, P, M>
where
    P: PushAction<H> + fmt::Debug,
    M: ModifyAction<H> + fmt::Debug,
{
    pub fn run(&self, meta: &mut Option<H>) -> Result<(), HeaderActionError> {
        match self {
            Self::Ignore => (),

            Self::Modify(action, _) => match meta {
                Some(meta) => action.modify(meta),
                None => return Err(HeaderActionError::MissingHeader),
            },

            Self::Push(action, _) => {
                meta.replace(action.push());
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

pub trait ModifyActionArg {}

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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum UlpHeaderAction<M: ModifyActionArg> {
    #[default]
    Ignore,
    Modify(M),
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

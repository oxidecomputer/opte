// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Header metadata modifications for IP, ULP, and Encap.

use super::geneve::GENEVE_PORT;
use super::geneve::GeneveMeta;
use super::geneve::GeneveMod;
use super::geneve::GenevePush;
use super::geneve::ValidGeneveMeta;
use super::ip::L3Repr;
use super::ip::v4::Ipv4;
use super::ip::v4::Ipv4Mod;
use super::ip::v4::Ipv4Push;
use super::ip::v6::Ipv6;
use super::ip::v6::Ipv6Mod;
use super::ip::v6::Ipv6Push;
use super::rule::GenHtError;
use super::tcp::TcpMod;
use super::tcp::TcpPush;
use super::udp::UdpMod;
use super::udp::UdpPush;
use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::string::ToString;
use core::error::Error;
use core::fmt;
use core::ops::Deref;
use ingot::ethernet::Ethertype;
use ingot::geneve::Geneve;
use ingot::geneve::GeneveMut;
use ingot::ip::IpProtocol;
use ingot::types::Emit;
use ingot::types::Header;
use ingot::types::HeaderLen;
use ingot::types::InlineHeader;
use ingot::types::util::Repeated;
use ingot::udp::Udp;
pub use opte_api::IpAddr;
pub use opte_api::IpCidr;
pub use opte_api::Protocol;
pub use opte_api::Vni;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::ByteSlice;
use zerocopy::ByteSliceMut;

/// A type that is meant to be used as an argument to a [`Transform`]
/// implementation.
pub trait PushAction<HdrP> {
    /// Produce a concrete header specification from a simplified
    /// representation, assuming that `self` has already been validated.
    fn push(&self) -> HdrP;
}

/// A type that is meant to be used as an argument to a
/// [`HeaderActionModify`] implementation.
pub trait ModifyAction<HdrM> {
    fn modify(&self, meta: &mut HdrM);
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum IpPush {
    Ip4(Ipv4Push),
    Ip6(Ipv6Push),
}

impl Validate for IpPush {
    fn validate(&self) -> Result<(), super::headers::ValidateErr> {
        match self {
            Self::Ip4(v) => v.validate(),
            Self::Ip6(v) => v.validate(),
        }
    }
}

impl From<&IpPush> for L3Repr {
    fn from(value: &IpPush) -> Self {
        match value {
            IpPush::Ip4(v4) => L3Repr::Ipv4(Ipv4 {
                protocol: IpProtocol(u8::from(v4.proto)),
                source: v4.src,
                destination: v4.dst,
                flags: v4.flags.into(),
                ..Default::default()
            }),
            IpPush::Ip6(v6) => {
                let ulp = IpProtocol(u8::from(v6.proto));
                let (exts, next_header) = if v6.exts.is_empty() {
                    (vec![], ulp)
                } else {
                    let first = v6.exts.first().unwrap().ip_protocol();
                    let mut out = vec![];
                    for (i, ext) in v6.exts.iter().enumerate() {
                        let next_header = v6
                            .exts
                            .get(i + 1)
                            .map(|v| v.ip_protocol())
                            .unwrap_or(ulp);

                        out.push(ext.as_repr(next_header));
                    }
                    (out, first)
                };

                L3Repr::Ipv6(Ipv6 {
                    next_header,
                    source: v6.src,
                    destination: v6.dst,
                    v6ext: Repeated::new(exts),
                    ..Default::default()
                })
            }
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

impl IpMod {
    pub fn new_src(ip: IpAddr) -> Self {
        match ip {
            IpAddr::Ip4(ip) => {
                Self::Ip4(Ipv4Mod { src: Some(ip), ..Default::default() })
            }
            IpAddr::Ip6(ip) => {
                Self::Ip6(Ipv6Mod { src: Some(ip), ..Default::default() })
            }
        }
    }

    pub fn new_dst(ip: IpAddr) -> Self {
        match ip {
            IpAddr::Ip4(ip) => {
                Self::Ip4(Ipv4Mod { dst: Some(ip), ..Default::default() })
            }
            IpAddr::Ip6(ip) => {
                Self::Ip6(Ipv6Mod { dst: Some(ip), ..Default::default() })
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

#[derive(
    Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
pub enum EncapMeta {
    Geneve(GeneveMeta),
}

impl From<GeneveMeta> for EncapMeta {
    fn from(meta: GeneveMeta) -> Self {
        Self::Geneve(meta)
    }
}

impl EncapMeta {
    #[inline]
    pub fn l4_len(&self) -> usize {
        match self {
            Self::Geneve(_) => Udp::MINIMUM_LENGTH,
        }
    }

    #[inline]
    pub fn tunnel_len(&self) -> usize {
        match self {
            Self::Geneve(_) => self.packet_length() - Udp::MINIMUM_LENGTH,
        }
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
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

impl From<EncapPush> for EncapMeta {
    fn from(push: EncapPush) -> Self {
        match push {
            EncapPush::Geneve(gp) => EncapMeta::Geneve(gp.into()),
        }
    }
}

impl Validate for EncapPush {
    fn validate(&self) -> Result<(), ValidateErr> {
        match self {
            Self::Geneve(g) => g.validate(),
        }
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

impl<T: ByteSliceMut> HeaderActionModify<EncapMod>
    for InlineHeader<EncapMeta, ValidEncapMeta<T>>
{
    #[inline]
    fn run_modify(
        &mut self,
        mod_spec: &EncapMod,
    ) -> Result<(), HeaderActionError> {
        match (self, mod_spec) {
            (
                InlineHeader::Repr(EncapMeta::Geneve(g)),
                EncapMod::Geneve(mod_spec),
            ) => {
                if let Some(vni) = mod_spec.vni {
                    g.vni = vni;
                }
            }
            (
                InlineHeader::Raw(ValidEncapMeta::Geneve(g)),
                EncapMod::Geneve(mod_spec),
            ) => {
                if let Some(vni) = mod_spec.vni {
                    g.1.set_vni(vni);
                }
            }
        }

        Ok(())
    }
}

impl<T: ByteSlice> HasInnerCksum
    for InlineHeader<EncapMeta, ValidEncapMeta<T>>
{
    const HAS_CKSUM: bool = false;
}

impl<T: ByteSlice> From<EncapMeta> for Header<EncapMeta, ValidEncapMeta<T>> {
    #[inline]
    fn from(value: EncapMeta) -> Self {
        Header::Repr(value.into())
    }
}

impl<T: ByteSlice> From<EncapMeta>
    for InlineHeader<EncapMeta, ValidEncapMeta<T>>
{
    #[inline]
    fn from(value: EncapMeta) -> Self {
        InlineHeader::Repr(value)
    }
}

pub enum ValidEncapMeta<B: ByteSlice> {
    Geneve(ValidGeneveMeta<B>),
}

impl Emit for EncapMeta {
    #[inline]
    fn emit_raw<V: ByteSliceMut>(&self, buf: V) -> usize {
        SizeHoldingEncap { encapped_len: 0, meta: self }.emit_raw(buf)
    }

    #[inline]
    fn needs_emit(&self) -> bool {
        true
    }
}

impl<B: ByteSliceMut> Emit for ValidEncapMeta<B> {
    #[inline]
    fn emit_raw<V: ByteSliceMut>(&self, buf: V) -> usize {
        match self {
            ValidEncapMeta::Geneve(g) => g.emit_raw(buf),
        }
    }

    #[inline]
    fn needs_emit(&self) -> bool {
        match self {
            ValidEncapMeta::Geneve(g) => g.needs_emit(),
        }
    }
}

impl HeaderLen for EncapMeta {
    const MINIMUM_LENGTH: usize = GeneveMeta::MINIMUM_LENGTH;

    #[inline]
    fn packet_length(&self) -> usize {
        match self {
            EncapMeta::Geneve(g) => g.packet_length(),
        }
    }
}

impl<B: ByteSlice> HeaderLen for ValidEncapMeta<B> {
    const MINIMUM_LENGTH: usize = GeneveMeta::MINIMUM_LENGTH;

    #[inline]
    fn packet_length(&self) -> usize {
        match self {
            ValidEncapMeta::Geneve(g) => g.packet_length(),
        }
    }
}

pub struct SizeHoldingEncap<'a> {
    pub encapped_len: u16,
    pub meta: &'a EncapMeta,
}

// SAFETY: All Emit writes are done via ingot-generated methods,
// and we don't read any element of `buf` in `SizeHoldingEncap::emit_raw`.
unsafe impl ingot::types::EmitDoesNotRelyOnBufContents
    for SizeHoldingEncap<'_>
{
}

impl HeaderLen for SizeHoldingEncap<'_> {
    const MINIMUM_LENGTH: usize = EncapMeta::MINIMUM_LENGTH;

    #[inline]
    fn packet_length(&self) -> usize {
        self.meta.packet_length()
    }
}

impl Emit for SizeHoldingEncap<'_> {
    #[inline]
    fn emit_raw<V: ByteSliceMut>(&self, mut buf: V) -> usize {
        match self.meta {
            EncapMeta::Geneve(g) => {
                let opt_len = g.options_len();

                let geneve = Geneve {
                    protocol_type: Ethertype::ETHERNET,
                    vni: g.vni,
                    opt_len: u8::try_from(opt_len / 4).unwrap_or(u8::MAX),
                    // Skip options, we rely on the custom `Emit` impl for
                    // ArbitraryGeneveOption so as not to clone them out.
                    ..Default::default()
                };

                let length = self.encapped_len.saturating_add(
                    u16::try_from(
                        Udp::MINIMUM_LENGTH + geneve.packet_length() + opt_len,
                    )
                    .unwrap_or(u16::MAX),
                );

                // It's worth noting that we have a zero UDP checksum here,
                // which holds true even if we're sending out over IPv6.
                // Ordinarily IPv6 requires a full checksum compute for UDP,
                // however RFCs 6935 & 6936 make an optional exception for
                // tunnelled transports (e.g., Geneve) over UDP/v6.
                // Generally OPTE is covered on validity of this:
                // * We preserve cksums on inner messages, so their headers and
                //   payloads are *always* valid.
                // * OPTE ports will only accept inbound packets with correct
                //   Ethernet dest, next headers, L3 dest, and VNI.
                //   Misdelivery on the basis of IPv6 (or other) corruption
                //   will lead to a drop.
                // This is also reflected in RFC 8200 §8.1 (IPv6 2017).
                let limit = buf.len() - opt_len;
                let mut out = (
                    Udp {
                        source: g.entropy,
                        destination: GENEVE_PORT,
                        length,
                        ..Default::default()
                    },
                    &geneve,
                )
                    .emit_raw(&mut buf[..limit]);

                for opt in g.options.as_ref() {
                    // Index safety: `buf` is sized according to Self::packet_length.
                    // This calls GeneveMeta::packet_length, which accounts for
                    // UDP + Geneve (above, initial value `out = 16`) plus the sum
                    // of all opt packet lengths.
                    out += opt.emit_raw(&mut buf[out..][..opt.packet_length()])
                }

                out
            }
        }
    }

    #[inline]
    fn needs_emit(&self) -> bool {
        true
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum UlpPush {
    Tcp(TcpPush),
    Udp(UdpPush),
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

pub trait HasInnerCksum {
    const HAS_CKSUM: bool;
}

/// Transform a header layer using an OPTE action.
pub trait Transform<H, P, M>: HasInnerCksum
where
    P: PushAction<H> + fmt::Debug,
    M: fmt::Debug,
{
    /// Modify/push/pop self, dependent on a given action.
    ///
    /// Returns whether we will need a checksum recompute on the target field
    /// if it is still present.
    fn act_on(
        &mut self,
        action: &HeaderAction<P, M>,
    ) -> Result<bool, HeaderActionError>;
}

impl<T: HasInnerCksum> HasInnerCksum for Option<T> {
    const HAS_CKSUM: bool = T::HAS_CKSUM;
}

impl<H, P, M, X> Transform<H, P, M> for X
where
    P: PushAction<H> + fmt::Debug,
    M: fmt::Debug,
    X: HeaderActionModify<M> + From<H> + HasInnerCksum,
{
    #[inline]
    fn act_on(
        &mut self,
        action: &HeaderAction<P, M>,
    ) -> Result<bool, HeaderActionError> {
        match action {
            HeaderAction::Ignore => Ok(false),
            HeaderAction::Push(p) => {
                *self = p.push().into();
                Ok(Self::HAS_CKSUM)
            }
            HeaderAction::Pop => Err(HeaderActionError::CantPop),
            HeaderAction::Modify(m) => {
                self.run_modify(m)?;
                Ok(Self::HAS_CKSUM)
            }
        }
    }
}

/// The action to take for a particular header transposition.
#[derive(Copy, Clone, Debug, Default, Deserialize, Serialize)]
pub enum HeaderAction<P, M> {
    Push(Valid<P>),
    Pop,
    Modify(M),
    #[default]
    Ignore,
}

impl<P, M> HeaderAction<P, M> {
    pub fn run<H>(&self, meta: &mut Option<H>) -> Result<(), HeaderActionError>
    where
        P: PushAction<H> + fmt::Debug,
        M: ModifyAction<H> + fmt::Debug,
    {
        match self {
            Self::Ignore => (),

            Self::Modify(action) => match meta {
                Some(meta) => action.modify(meta),
                None => return Err(HeaderActionError::MissingHeader),
            },

            Self::Push(action) => {
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

    pub fn act_on_option<H, X>(
        &self,
        target: &mut Option<X>,
    ) -> Result<bool, HeaderActionError>
    where
        P: PushAction<H> + fmt::Debug,
        M: fmt::Debug,
        X: Transform<H, P, M> + From<H>,
        X: HeaderActionModify<M> + HasInnerCksum,
    {
        match (self, target) {
            (HeaderAction::Ignore, _) => Ok(false),
            (HeaderAction::Push(p), a) => {
                *a = Some(p.push().into());
                Ok(X::HAS_CKSUM)
            }
            (HeaderAction::Pop, a) => {
                *a = None;
                Ok(X::HAS_CKSUM)
            }
            (a @ HeaderAction::Modify(..), Some(h)) => h.act_on(a),
            (_, None) => Err(HeaderActionError::MissingHeader),
        }
    }
}

/// Header actions which require sanity checking before they can be used.
pub trait Validate {
    fn validate(&self) -> Result<(), ValidateErr>;
}

/// An error message and location encountered while validating a packet
/// transform.
#[derive(Debug)]
pub struct ValidateErr {
    pub msg: Cow<'static, str>,
    pub location: Cow<'static, str>,
    pub source: Option<Box<dyn Error>>,
}

impl fmt::Display for ValidateErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ValidateErr { msg, location, source: _source } = self;
        write!(f, "invalid {location} ({msg})")
    }
}

impl Error for ValidateErr {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref()
    }
}

impl From<ValidateErr> for GenHtError {
    fn from(value: ValidateErr) -> Self {
        let mut out = value.to_string();
        let mut source = value.source();
        while let Some(inner) = source {
            out = format!("{out}: {inner}");
            source = inner.source();
        }

        GenHtError::Unexpected { msg: out }
    }
}

/// Header actions which have been successfully sanity checked.
#[derive(Copy, Clone, Debug, Default, Deserialize, Serialize)]
pub struct Valid<T>(T);

impl<T: Validate> Valid<T> {
    pub fn validated(value: T) -> Result<Self, ValidateErr> {
        value.validate().map(|_| Self(value))
    }
}

impl<T> Valid<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for Valid<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub enum HeaderActionError {
    MissingHeader,
    CantPop,
    MalformedExtension,
}

pub trait ModifyActionArg {}

/// A header type that allows itself to be modified via a
/// [`ModifyActionArg`] specification.
pub trait HeaderActionModify<M> {
    fn run_modify(&mut self, mod_spec: &M) -> Result<(), HeaderActionError>;
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
    /// Used by a rule to replace ICMP Echo ID values with a new value.
    pub icmp_id: Option<u16>,
}

impl ModifyActionArg for UlpMetaModify {}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum UlpHeaderAction<M: ModifyActionArg> {
    #[default]
    Ignore,
    Modify(M),
}

impl<M: ModifyActionArg> UlpHeaderAction<M> {
    pub fn run<P>(
        &self,
        meta: &mut Option<P>,
    ) -> Result<bool, HeaderActionError>
    where
        P: HeaderActionModify<M>,
    {
        match self {
            Self::Ignore => Ok(false),
            Self::Modify(arg) => match meta {
                Some(meta) => {
                    meta.run_modify(arg)?;
                    Ok(true)
                }
                None => Err(HeaderActionError::MissingHeader),
            },
        }
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Geneve headers and their related actions.
//!
//! RFC 8926 Geneve: Generic Network Virtualization Encapsulation

use super::headers::ModifyAction;
use super::headers::PushAction;
use super::headers::Valid;
use super::headers::Validate;
use super::packet::MismatchError;
use super::packet::ParseError;
use crate::engine::headers::ValidateErr;
use alloc::borrow::Cow;
use core::marker::PhantomData;
use ingot::geneve::Geneve;
use ingot::geneve::GeneveOpt;
use ingot::geneve::GeneveOptRef;
use ingot::geneve::GeneveOptionType;
use ingot::geneve::GeneveRef;
use ingot::geneve::ValidGeneve;
use ingot::geneve::ValidGeneveOpt;
use ingot::types::Emit;
use ingot::types::EmitDoesNotRelyOnBufContents;
use ingot::types::HasView;
use ingot::types::HeaderLen;
use ingot::types::HeaderParse;
use ingot::types::InlineHeader;
use ingot::types::ParseError as IngotParseError;
use ingot::udp::Udp;
use ingot::udp::UdpRef;
use ingot::udp::ValidUdp;
pub use opte_api::Vni;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::ByteSlice;
use zerocopy::ByteSliceMut;

pub const GENEVE_PORT: u16 = 6081;
pub const GENEVE_OPT_CLASS_OXIDE: u16 = 0x0129;

#[inline]
pub fn validate_geneve<V: ByteSlice>(
    pkt: &ValidGeneve<V>,
) -> Result<(), ParseError> {
    if pkt.version() != 0 {
        return Err(ParseError::IllegalValue(MismatchError {
            location: c"Geneve.version",
            expected: 0,
            actual: pkt.version() as u64,
        }));
    }

    Ok(())
}

pub trait GeneveMetaRef {
    fn entropy(&self) -> u16;
    fn vni(&self) -> Vni;
}

impl<O: GeneveMetaRef, B: GeneveMetaRef> GeneveMetaRef
    for InlineHeader<&O, &B>
{
    #[inline]
    fn entropy(&self) -> u16 {
        match self {
            InlineHeader::Repr(v) => v.entropy(),
            InlineHeader::Raw(v) => v.entropy(),
        }
    }

    #[inline]
    fn vni(&self) -> Vni {
        match self {
            InlineHeader::Repr(v) => v.vni(),
            InlineHeader::Raw(v) => v.vni(),
        }
    }
}

#[derive(
    Clone,
    Debug,
    Default,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
)]
pub struct GeneveMeta {
    pub entropy: u16,
    pub vni: Vni,
    pub options: Cow<'static, [ArbitraryGeneveOption]>,
}

impl GeneveMetaRef for GeneveMeta {
    #[inline]
    fn entropy(&self) -> u16 {
        self.entropy
    }

    #[inline]
    fn vni(&self) -> Vni {
        self.vni
    }
}

pub struct ValidGeneveMeta<B: ByteSlice>(pub ValidUdp<B>, pub ValidGeneve<B>);

impl<B: ByteSlice> HasView<B> for GeneveMeta {
    type ViewType = ValidGeneveMeta<B>;
}

impl<B: ByteSlice> GeneveMetaRef for ValidGeneveMeta<B> {
    #[inline]
    fn entropy(&self) -> u16 {
        self.0.source()
    }

    #[inline]
    fn vni(&self) -> Vni {
        self.1.vni()
    }
}

impl<B: ByteSlice> HeaderLen for ValidGeneveMeta<B> {
    const MINIMUM_LENGTH: usize = Udp::MINIMUM_LENGTH + Geneve::MINIMUM_LENGTH;

    fn packet_length(&self) -> usize {
        (&self.0, &self.1).packet_length()
    }
}

impl<B: ByteSlice> Emit for ValidGeneveMeta<B> {
    fn emit_raw<V: ByteSliceMut>(&self, buf: V) -> usize {
        (&self.0, &self.1).emit_raw(buf)
    }

    fn needs_emit(&self) -> bool {
        (&self.0, &self.1).needs_emit()
    }
}

// SAFETY: All Emit writes are done via ingot-generated methods,
// and we don't read any element of `buf` in `SizeHoldingEncap::emit_raw`.
unsafe impl<B: ByteSlice> EmitDoesNotRelyOnBufContents for ValidGeneveMeta<B> {}

#[derive(
    Clone,
    Debug,
    Default,
    Deserialize,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct GenevePush {
    pub entropy: u16,
    pub vni: Vni,
    pub options: Cow<'static, [ArbitraryGeneveOption]>,
}

impl From<GenevePush> for GeneveMeta {
    fn from(v: GenevePush) -> Self {
        Self { entropy: v.entropy, vni: v.vni, options: v.options }
    }
}

impl PushAction<GeneveMeta> for GenevePush {
    fn push(value: &Valid<Self>) -> GeneveMeta {
        GeneveMeta {
            entropy: value.entropy,
            vni: value.vni,
            options: value.options.clone(),
        }
    }
}

impl Validate for GenevePush {
    fn validate(&self) -> Result<(), ValidateErr> {
        // Geneve.opt_len is a `u6`.
        // This is a count of 4-byte blocks, so scale up to the true length.
        const MAX_OPTS_LEN: usize = 0b0011_1111 * 4;

        let mut total_opts_len = 0;
        for (i, opt) in self.options.iter().enumerate() {
            opt.validate().map_err(|e| ValidateErr {
                msg: "illegal option".into(),
                location: format!("geneve.options[{i}]").into(),
                source: Some(e.into()),
            })?;
            total_opts_len += opt.packet_length();
            if total_opts_len > MAX_OPTS_LEN {
                return Err(ValidateErr {
                    msg: "options longer than 252B".into(),
                    location: format!("geneve.options[{i}]").into(),
                    source: None,
                });
            }
        }

        Ok(())
    }
}

/// Simplified representation of an arbitrary Geneve option.
#[derive(
    Clone,
    Debug,
    Default,
    Deserialize,
    Eq,
    PartialEq,
    Serialize,
    Ord,
    PartialOrd,
)]
pub struct ArbitraryGeneveOption {
    pub option_class: u16,
    pub option_type: u8,
    pub data: Cow<'static, [u8]>,
}

impl HeaderLen for ArbitraryGeneveOption {
    const MINIMUM_LENGTH: usize = GeneveOpt::MINIMUM_LENGTH;

    fn packet_length(&self) -> usize {
        // Length is in 4B blocks -- pad to the next boundary.
        Self::MINIMUM_LENGTH + self.data.len().next_multiple_of(4)
    }
}

impl Validate for ArbitraryGeneveOption {
    fn validate(&self) -> Result<(), ValidateErr> {
        // GeneveOpt.length is a `u5`.
        // Again, this is a count of 4-byte blocks, so scale up to the true
        // length.
        const MAX_OPT_DATA_LEN: usize = 0b0001_1111 * 4;

        let opt_len = self.data.len();
        if opt_len > MAX_OPT_DATA_LEN {
            Err(ValidateErr {
                msg: format!("option is too long ({opt_len}B vs. max 124B)")
                    .into(),
                location: "data".into(),
                source: None,
            })
        } else {
            Ok(())
        }
    }
}

impl Emit for ArbitraryGeneveOption {
    #[inline]
    fn emit_raw<V: ByteSliceMut>(&self, mut buf: V) -> usize {
        let len = self.packet_length();
        let opt_len = len - ArbitraryGeneveOption::MINIMUM_LENGTH;
        let pad_start = ArbitraryGeneveOption::MINIMUM_LENGTH + self.data.len();

        buf[pad_start..len].fill(0);

        let serialised = (
            GeneveOpt {
                class: self.option_class,
                option_type: self.option_type.into(),
                length: u8::try_from(opt_len / 4).unwrap_or(u8::MAX),
                ..Default::default()
            },
            self.data.as_ref(),
        )
            .emit_raw(buf);
        assert_eq!(serialised, pad_start);

        len
    }

    #[inline]
    fn needs_emit(&self) -> bool {
        true
    }
}

// SAFETY: the above impl does not read from `Buf`, and fills all bytes
//         up to `<Self as HeaderLen>::packet_length`.
unsafe impl EmitDoesNotRelyOnBufContents for ArbitraryGeneveOption {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneveMod {
    pub vni: Option<Vni>,
}

impl ModifyAction<GeneveMeta> for GeneveMod {
    fn modify(&self, meta: &mut GeneveMeta) {
        if let Some(vni) = self.vni {
            meta.vni = vni;
        }
    }
}

impl GeneveMeta {
    /// Return the length of only the Geneve header and its options.
    #[inline]
    pub fn hdr_len_inner(&self) -> usize {
        Geneve::MINIMUM_LENGTH + self.options_len()
    }

    /// Return the required length (in bytes) needed to store
    /// all Geneve options attached to this packet.
    ///
    /// Options must be padded to the next 4-byte boundary, the length here
    /// accounts for this.
    pub fn options_len(&self) -> usize {
        self.options.iter().map(|v| v.packet_length()).sum()
    }
}

impl HeaderLen for GeneveMeta {
    const MINIMUM_LENGTH: usize = Udp::MINIMUM_LENGTH + Geneve::MINIMUM_LENGTH;

    #[inline]
    fn packet_length(&self) -> usize {
        Self::MINIMUM_LENGTH + self.options_len()
    }
}

/// A dataplane-specific interpretation of a given Geneve option.
pub trait OptionCast<'a>: HeaderLen {
    /// Return the Geneve class associated with `self`.
    fn option_class(&self) -> u16;

    /// Return the Geneve type associated with `self`.
    fn option_type(&self) -> GeneveOptionType;

    /// Convert the raw parts of a Geneve option into a valid instance
    /// of `Self`.
    ///
    /// Implementors should return `Some(_)` when the
    /// `(option_class, option_type)` combination are recognised,
    /// and `None` otherwise. This allows [`GeneveOptionParse`] to
    /// classify the option as `Known::Known` or `Known::Unknown`.
    fn try_cast(
        option_class: u16,
        option_type: GeneveOptionType,
        body: &'a [u8],
    ) -> Result<Option<(Self, &'a [u8])>, IngotParseError>
    where
        Self: Sized;
}

/// A successfully parsed Geneve option, alongside any spare bytes in
/// the payload.
///
/// Carries the option body if the inner `option` is `Known::Unknown`.
pub struct GeneveOptionParse<'a, T: OptionCast<'a>> {
    pub option: Known<T>,
    pub body_remainder: &'a [u8],
}

impl<'a, T: OptionCast<'a>> GeneveOptionParse<'a, T> {
    pub fn parse(
        class: u16,
        ty: GeneveOptionType,
        body: &'a [u8],
    ) -> Result<GeneveOptionParse<'a, T>, IngotParseError> {
        let (option, body_remainder) =
            if let Some((opt, rem)) = T::try_cast(class, ty, body)? {
                (Known::Known(opt), rem)
            } else {
                (Known::Unknown(class, ty), body)
            };

        Ok(Self { option, body_remainder })
    }
}

impl<'a, T: OptionCast<'a>> HeaderLen for GeneveOptionParse<'a, T> {
    const MINIMUM_LENGTH: usize = GeneveOpt::MINIMUM_LENGTH;

    fn packet_length(&self) -> usize {
        // For Known options, use their HeaderLen implementation
        // (e.g., Mss returns 8B).
        // For Unknown options, the header (4B) + body remainder
        // (which includes padding).
        self.option.packet_length() + self.body_remainder.len()
    }
}

/// Marks whether a Geneve option has been successfully interpreted as a known
/// option variant.
pub enum Known<T> {
    Known(T),
    Unknown(u16, GeneveOptionType),
}

impl<'a, T: OptionCast<'a>> HeaderLen for Known<T> {
    const MINIMUM_LENGTH: usize = GeneveOpt::MINIMUM_LENGTH;

    fn packet_length(&self) -> usize {
        match self {
            Known::Known(a) => a.packet_length(),
            // For unknown options, we only have the header (4 bytes).
            // The body is tracked separately in `GeneveOptionParse::body_remainder`.
            // `GeneveOptionParse::packet_length()` adds that remainder to the
            // value returned here, so do not include body bytes in this branch.
            Known::Unknown(..) => GeneveOpt::MINIMUM_LENGTH,
        }
    }
}

impl<'a, T: OptionCast<'a>> Known<T> {
    pub fn option_class(&self) -> u16 {
        match self {
            Known::Known(a) => a.option_class(),
            Known::Unknown(class, ..) => *class,
        }
    }

    pub fn option_type(&self) -> GeneveOptionType {
        match self {
            Known::Known(a) => a.option_type(),
            Known::Unknown(.., ty) => *ty,
        }
    }

    pub fn is_unknown_critical(&self) -> bool {
        match self {
            Known::Known(..) => false,
            Known::Unknown(.., ty) => ty.is_critical(),
        }
    }

    pub fn known(&self) -> Option<&T> {
        match self {
            Known::Known(a) => Some(a),
            Known::Unknown(..) => None,
        }
    }

    pub fn unknown(&self) -> Option<(u16, GeneveOptionType)> {
        match self {
            Known::Known(..) => None,
            Known::Unknown(class, ty) => Some((*class, *ty)),
        }
    }
}

/// Walk all geneve options, attempting to cast them to a T when the class
/// and type are recognised.
pub struct WalkOptions<'a, T: OptionCast<'a>>(Source<'a>, PhantomData<T>);

impl<'a, T: OptionCast<'a>> WalkOptions<'a, T> {
    pub fn from_meta<B: ByteSlice>(
        meta: InlineHeader<&'a GeneveMeta, &'a ValidGeneveMeta<B>>,
    ) -> Self {
        match meta {
            InlineHeader::Repr(r) => {
                Self(Source::Simplified(r.options.as_ref()), PhantomData)
            }
            InlineHeader::Raw(r) => Self::from_raw(&r.1),
        }
    }

    pub fn from_raw<B: ByteSlice>(meta: &'a ValidGeneve<B>) -> Self {
        match &meta.1 {
            ingot::types::BoxedHeader::Repr(r) => {
                Self(Source::Owned(r.as_slice()), PhantomData)
            }
            ingot::types::BoxedHeader::Raw(r) => {
                Self(Source::Raw(r.as_ref()), PhantomData)
            }
        }
    }
}

enum Source<'a> {
    Simplified(&'a [ArbitraryGeneveOption]),
    Owned(&'a [GeneveOpt]),
    Raw(&'a [u8]),
}

impl<'a, T: OptionCast<'a>> Iterator for WalkOptions<'a, T> {
    type Item = Result<GeneveOptionParse<'a, T>, IngotParseError>;

    // This partially reimplements some work from `Repeated/View`, but
    // formalises the case that a freshly parsed Raw cannot have an owned body.
    // This needs some special handling to reborrow the slice without Rust
    // thinking that a new `Header` owns the data instead of the input.
    fn next(&mut self) -> Option<Self::Item> {
        let (class, ty, body) = match self.0 {
            Source::Simplified(ref mut opt_source) => {
                let (el, rest) = opt_source.split_first()?;
                *opt_source = rest;
                (
                    el.option_class,
                    GeneveOptionType(el.option_type),
                    el.data.as_ref(),
                )
            }
            Source::Owned(ref mut opt_source) => {
                let (el, rest) = opt_source.split_first()?;
                *opt_source = rest;
                (el.class, el.option_type, el.data.as_slice())
            }
            Source::Raw(ref mut bytes) => {
                let (class, ty, len) = {
                    let (opt, ..) = match ValidGeneveOpt::parse(*bytes) {
                        Ok(opt) => opt,
                        Err(e) => return Some(Err(e)),
                    };

                    (opt.class(), opt.option_type(), opt.packet_length())
                };
                let (opt, remainder) = bytes.split_at(len);
                *bytes = remainder;
                (class, ty, &opt[GeneveOpt::MINIMUM_LENGTH..])
            }
        };

        Some(GeneveOptionParse::parse(class, ty, body))
    }
}

// Can't impl TryFrom<T: GeneveOptRef>, sadly.
impl<'a, T: OptionCast<'a>> TryFrom<&'a ArbitraryGeneveOption>
    for GeneveOptionParse<'a, T>
{
    type Error = IngotParseError;

    #[inline]
    fn try_from(value: &'a ArbitraryGeneveOption) -> Result<Self, Self::Error> {
        Self::parse(
            value.option_class,
            GeneveOptionType(value.option_type),
            value.data.as_ref(),
        )
    }
}

impl<'a, T: OptionCast<'a>> TryFrom<&'a GeneveOpt>
    for GeneveOptionParse<'a, T>
{
    type Error = IngotParseError;

    #[inline]
    fn try_from(value: &'a GeneveOpt) -> Result<Self, Self::Error> {
        Self::parse(value.class, value.option_type, value.data.as_slice())
    }
}

impl<'a, 'b: 'a, T: OptionCast<'a>> TryFrom<&'a ValidGeneveOpt<&'b [u8]>>
    for GeneveOptionParse<'a, T>
{
    type Error = IngotParseError;

    #[inline]
    fn try_from(
        value: &'a ValidGeneveOpt<&'b [u8]>,
    ) -> Result<Self, Self::Error> {
        let class = value.class();
        let ty = value.option_type();

        let value_data = match &value.1 {
            ingot::types::BoxedHeader::Repr(r) => r.as_slice(),
            ingot::types::BoxedHeader::Raw(r) => &r[..],
        };

        Self::parse(class, ty, value_data)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::engine::headers::EncapMeta;
    use ingot::types::Emit;

    #[test]
    fn emit_no_opts() {
        let geneve = GeneveMeta {
            entropy: 7777,
            vni: Vni::new(1234u32).unwrap(),

            ..Default::default()
        };

        let len = geneve.packet_length();
        let emitted = EncapMeta::Geneve(geneve).to_vec();
        assert_eq!(len, emitted.len());

        #[rustfmt::skip]
        let expected_bytes = vec![
            // source
            0x1E, 0x61,
            // dest
            0x17, 0xC1,
            // length
            0x00, 0x10,
            // csum
            0x00, 0x00,
            // ver + opt len
            0x00,
            // flags
            0x00,
            // proto
            0x65, 0x58,
            // vni + reserved
            0x00, 0x04, 0xD2, 0x00
        ];
        assert_eq!(expected_bytes, emitted);
    }

    #[test]
    fn emit_single_opt() {
        let geneve = GeneveMeta {
            entropy: 7777,
            vni: Vni::new(1234u32).unwrap(),
            options: vec![ArbitraryGeneveOption {
                option_class: GENEVE_OPT_CLASS_OXIDE,
                option_type: 0,
                data: (&[]).into(),
            }]
            .into(),
        };

        let len = geneve.packet_length();
        let emitted = EncapMeta::Geneve(geneve).to_vec();
        assert_eq!(len, emitted.len());

        #[rustfmt::skip]
        let expected_bytes = vec![
            // source
            0x1E, 0x61,
            // dest
            0x17, 0xC1,
            // length
            0x00, 0x14,
            // csum
            0x00, 0x00,
            // ver + opt len
            0x01,
            // flags
            0x00,
            // proto
            0x65, 0x58,
            // vni + reserved
            0x00, 0x04, 0xD2, 0x00,

            // option class
            0x01, 0x29,
            // crt + type
            0x00,
            // rsvd + len
            0x00,
        ];
        assert_eq!(&expected_bytes, &emitted[..]);
    }
}

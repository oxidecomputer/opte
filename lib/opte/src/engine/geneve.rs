// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Geneve headers and their related actions.
//!
//! RFC 8926 Geneve: Generic Network Virtualization Encapsulation

use super::headers::ModifyAction;
use super::headers::PushAction;
use super::headers::Validate;
use super::packet::MismatchError;
use super::packet::ParseError;
use crate::engine::headers::ValidateErr;
use alloc::borrow::Cow;
use ingot::geneve::Geneve;
use ingot::geneve::GeneveFlags;
use ingot::geneve::GeneveOpt;
use ingot::geneve::GeneveOptRef;
use ingot::geneve::GeneveRef;
use ingot::geneve::ValidGeneve;
use ingot::types::Emit;
use ingot::types::EmitDoesNotRelyOnBufContents;
use ingot::types::HasView;
use ingot::types::HeaderLen;
use ingot::types::InlineHeader;
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

    if pkt.flags().contains(GeneveFlags::CRITICAL_OPTS) {
        match pkt.options_ref() {
            ingot::types::FieldRef::Repr(g) => {
                for opt in g.iter() {
                    if !opt.option_type.is_critical() {
                        continue;
                    }

                    GeneveOption::from_code_and_ty(
                        opt.class,
                        opt.option_type.0,
                    )?;
                }
            }
            ingot::types::FieldRef::Raw(g) => {
                for opt in g.iter(None) {
                    let Ok(opt) = opt else {
                        break;
                    };

                    if !opt.option_type().is_critical() {
                        continue;
                    }

                    GeneveOption::from_code_and_ty(
                        opt.class(),
                        opt.option_type().0,
                    )?;
                }
            }
        }
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
    fn push(&self) -> GeneveMeta {
        GeneveMeta {
            entropy: self.entropy,
            vni: self.vni,
            options: self.options.clone(),
        }
    }
}

impl Validate for GenevePush {
    fn validate(&self) -> Result<(), ValidateErr> {
        // Geneve.opt_len is a `u6`.
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
    pub opt_class: u16,
    pub opt_type: u8,
    pub data: Cow<'static, [u8]>,
}

impl HeaderLen for ArbitraryGeneveOption {
    const MINIMUM_LENGTH: usize = GeneveOpt::MINIMUM_LENGTH;

    fn packet_length(&self) -> usize {
        // Length is in 4B blocks -- pad to the next boundary.
        let unpadded = self.data.len();
        let remainder = unpadded % 4;
        Self::MINIMUM_LENGTH
            + if remainder == 0 { unpadded } else { unpadded - remainder + 4 }
    }
}

impl Validate for ArbitraryGeneveOption {
    fn validate(&self) -> Result<(), ValidateErr> {
        // GeneveOpt.length is a `u5`.
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
                class: self.opt_class,
                option_type: self.opt_type.into(),
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
    /// Return the length of headers needed to fully Geneve-encapsulate
    /// a packet, including UDP.
    #[inline]
    pub fn hdr_len(&self) -> usize {
        Udp::MINIMUM_LENGTH + self.hdr_len_inner()
    }

    /// Return the length of only the Geneve header.
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

/// Parsed form of an individual Geneve option TLV.
///
/// These are grouped by the vendor `class`es understood by OPTE.
#[non_exhaustive]
pub enum GeneveOption {
    Oxide(OxideOption),
}

impl GeneveOption {
    #[inline]
    pub fn from_code_and_ty(class: u16, ty: u8) -> Result<Self, ParseError> {
        match (class, ty) {
            (GENEVE_OPT_CLASS_OXIDE, v)
                if OxideOption::External.opt_type() == v =>
            {
                Ok(Self::Oxide(OxideOption::External))
            }
            _ => Err(ParseError::UnrecognisedTunnelOpt { class, ty }),
        }
    }

    /// Return the wire-length of this option in bytes, including headers.
    pub fn len(&self) -> usize {
        4 + match self {
            GeneveOption::Oxide(o) => o.len(),
        }
    }
}

/// Geneve options defined by Oxide, [`GENEVE_OPT_CLASS_OXIDE`].
#[non_exhaustive]
pub enum OxideOption {
    /// A tag indicating that this packet originated from outside the VPC.
    ///
    /// Option Type `0`. Currently includes no body.
    External,
}

impl OxideOption {
    /// Return the wire-length of this option's body in bytes, excluding headers.
    pub fn len(&self) -> usize {
        match self {
            OxideOption::External => 0,
        }
    }

    /// Return the option type number.
    pub const fn opt_type(&self) -> u8 {
        match self {
            OxideOption::External => 0,
        }
    }
}

// We probably want a more general way to retrieve all facts we care about
// from the geneve options -- we only have the one today, however.
#[inline]
pub fn geneve_has_oxide_external(pkt: &Geneve) -> bool {
    let mut out = false;
    for opt in pkt.options.iter() {
        out = matches!(
            GeneveOption::from_code_and_ty(opt.class, opt.option_type.0,),
            Ok(GeneveOption::Oxide(OxideOption::External))
        );
        if out {
            break;
        }
    }

    out
}

#[inline]
pub fn valid_geneve_has_oxide_external<V: ByteSlice>(
    pkt: &ValidGeneve<V>,
) -> bool {
    let mut out = false;

    match pkt.options_ref() {
        ingot::types::FieldRef::Repr(g) => {
            for opt in g.iter() {
                out = matches!(
                    GeneveOption::from_code_and_ty(
                        opt.class,
                        opt.option_type.0,
                    ),
                    Ok(GeneveOption::Oxide(OxideOption::External))
                );
                if out {
                    break;
                }
            }
        }
        ingot::types::FieldRef::Raw(g) => {
            for opt in g.iter(None) {
                let Ok(opt) = opt else {
                    break;
                };

                out = matches!(
                    GeneveOption::from_code_and_ty(
                        opt.class(),
                        opt.option_type().0,
                    ),
                    Ok(GeneveOption::Oxide(OxideOption::External))
                );
                if out {
                    break;
                }
            }
        }
    }

    out
}

#[inline(always)]
pub fn geneve_opt_is_oxide_external<V: ByteSlice>(
    opt: &impl GeneveOptRef<V>,
) -> bool {
    opt.class() == GENEVE_OPT_CLASS_OXIDE
        && opt.option_type().0 == OxideOption::External.opt_type()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::engine::headers::EncapMeta;
    use ingot::types::Emit;
    use ingot::types::HeaderParse;
    use ingot::udp::ValidUdp;

    #[test]
    fn emit_no_opts() {
        let geneve = GeneveMeta {
            entropy: 7777,
            vni: Vni::new(1234u32).unwrap(),

            ..Default::default()
        };

        let len = geneve.hdr_len();
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
    fn emit_external_opt() {
        let geneve = GeneveMeta {
            entropy: 7777,
            vni: Vni::new(1234u32).unwrap(),
            options: vec![ArbitraryGeneveOption {
                opt_class: GENEVE_OPT_CLASS_OXIDE,
                opt_type: 0,
                data: (&[]).into(),
            }]
            .into(),
        };

        let len = geneve.hdr_len();
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

    #[test]
    fn parse_single_opt() {
        // Create a packet with one extension header.
        #[rustfmt::skip]
        let buf = [
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

        let (.., rem) = ValidUdp::parse(&buf[..]).unwrap();
        let (geneve, ..) = ValidGeneve::parse(rem).unwrap();

        validate_geneve(&geneve).unwrap();

        assert!(valid_geneve_has_oxide_external(&geneve));
    }

    #[test]
    fn unknown_crit_option_fails() {
        // Create a packet with one extension header with the critical
        // flag set.
        // We do not unsdertand this extension, so must drop the packet.
        #[rustfmt::skip]
        let buf = [
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
            0b0100_0000,
            // proto
            0x65, 0x58,
            // vni + reserved
            0x00, 0x04, 0xD2, 0x00,

            // experimenter option class
            0xff, 0xff,
            // crt + type
            0x80,
            // rsvd + len
            0x00,
        ];

        let (_udp, _, rem) = ValidUdp::parse(&buf[..]).unwrap();
        let (geneve, ..) = ValidGeneve::parse(rem).unwrap();

        assert!(matches!(
            validate_geneve(&geneve),
            Err(ParseError::UnrecognisedTunnelOpt { class: 0xffff, ty: 0x80 }),
        ));
    }

    #[test]
    fn parse_multi_opt() {
        // Create a packet with three extension headers.
        // None are critical, so the fact that we
        // We shoukld also be able to extract info on the options we *do*
        // care about.
        #[rustfmt::skip]
        let buf = [
            // source
            0x1E, 0x61,
            // dest
            0x17, 0xC1,
            // length
            0x00, 0x1c,
            // csum
            0x00, 0x00,
            // ver + opt len
            0x05,
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

            // experimenter option class
            0xff, 0xff,
            // crt + type
            0x05,
            // rsvd + len
            0x01,
            // body
            0x00, 0x00, 0x00, 0x00,

            // experimenter option class
            0xff, 0xff,
            // crt + type
            0x06,
            // rsvd + len
            0x01,
            // body
            0x00, 0x00, 0x00, 0x00,
        ];

        let (.., rem) = ValidUdp::parse(&buf[..]).unwrap();
        let (geneve, ..) = ValidGeneve::parse(rem).unwrap();

        validate_geneve(&geneve).unwrap();
        assert!(valid_geneve_has_oxide_external(&geneve));
    }
}

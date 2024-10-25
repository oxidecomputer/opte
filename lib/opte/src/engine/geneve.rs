// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Geneve headers and their related actions.
//!
//! RFC 8926 Geneve: Generic Network Virtualization Encapsulation

use super::headers::ModifyAction;
use super::headers::PushAction;
use super::packet::MismatchError;
use super::packet::ParseError;
use ingot::geneve::Geneve;
use ingot::geneve::GeneveFlags;
use ingot::geneve::GeneveOpt;
use ingot::geneve::GeneveOptRef;
use ingot::geneve::GeneveRef;
use ingot::geneve::ValidGeneve;
use ingot::types::Header;
use ingot::types::HeaderLen;
use ingot::udp::Udp;
pub use opte_api::Vni;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::ByteSlice;

pub const GENEVE_VSN: u8 = 0;
pub const GENEVE_VER_MASK: u8 = 0xC0;
pub const GENEVE_VER_SHIFT: u8 = 6;
pub const GENEVE_OPT_LEN_MASK: u8 = 0x3F;
pub const GENEVE_OPT_LEN_SCALE_SHIFT: u8 = 2;
pub const GENEVE_PORT: u16 = 6081;

pub const GENEVE_OPT_CRIT_SHIFT: u8 = 7;
pub const GENEVE_OPT_TYPE_MASK: u8 = (1 << GENEVE_OPT_CRIT_SHIFT) - 1;
pub const GENEVE_OPT_RESERVED_SHIFT: u8 = 5;
pub const GENEVE_OPT_RESERVED_MASK: u8 = (1 << GENEVE_OPT_RESERVED_SHIFT) - 1;
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
            ingot::types::FieldRef::Raw(Header::Repr(g)) => {
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
            ingot::types::FieldRef::Raw(Header::Raw(g)) => {
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

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct GeneveMeta {
    pub entropy: u16,
    pub vni: Vni,
    pub oxide_external_pkt: bool,
}

#[derive(
    Clone,
    Copy,
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
}

impl PushAction<GeneveMeta> for GenevePush {
    fn push(&self) -> GeneveMeta {
        GeneveMeta {
            entropy: self.entropy,
            vni: self.vni,
            ..Default::default()
        }
    }
}

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
    pub fn options_len(&self) -> usize {
        // XXX: This is very special-cased just to enable testing.
        if self.oxide_external_pkt {
            GeneveOpt::MINIMUM_LENGTH
        } else {
            0
        }
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
            _ => {
                Err(ParseError::UnrecognisedTunnelOpt { class: class, ty: ty })
            }
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
        ingot::types::FieldRef::Raw(Header::Repr(g)) => {
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
        ingot::types::FieldRef::Raw(Header::Raw(g)) => {
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
    use core::matches;

    use ingot::ethernet::Ethernet;
    use ingot::ethernet::Ethertype;
    use ingot::ip::IpProtocol;
    use ingot::ip::Ipv6;
    use ingot::types::Emit;
    use ingot::types::HeaderParse;
    use ingot::udp::UdpRef;
    use ingot::udp::ValidUdp;

    use super::*;
    use crate::engine::headers::EncapMeta;
    use crate::engine::ingot_packet::MsgBlk;
    use crate::engine::ingot_packet::Packet;
    use crate::engine::packet::Packet;
    use crate::engine::parse::ValidGeneveOverV6;

    #[test]
    fn emit_no_opts() {
        let geneve = GeneveMeta {
            entropy: 7777,
            vni: Vni::new(1234u32).unwrap(),

            ..Default::default()
        };

        let len = geneve.hdr_len();
        let emitted = EncapMeta::Geneve(geneve).emit_vec();
        assert_eq!(len, pkt.len());

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
            oxide_external_pkt: true,
        };

        let len = geneve.hdr_len();
        let emitted = EncapMeta::Geneve(geneve).emit_vec();
        assert_eq!(len, pkt.len());

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
        assert_eq!(&expected_bytes, emitted);
    }

    #[test]
    fn parse_single_opt() {
        // Create a packet with one extension header.
        #[rustfmt::skip]
        let buf = vec![
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

        assert!(geneve_opt_is_oxide_external(&geneve));
    }

    #[test]
    fn unknown_crit_option_fails() {
        // Create a packet with one extension header with the critical
        // flag set.
        // We do not unsdertand this extension, so must drop the packet.
        #[rustfmt::skip]
        let buf = vec![
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
        let buf = vec![
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
        assert!(geneve_opt_is_oxide_external(&geneve));
    }
}

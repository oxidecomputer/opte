// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Geneve option types specific to the Oxide VPC dataplane.

use ingot::geneve::GeneveFlags;
use ingot::geneve::GeneveOpt;
use ingot::geneve::GeneveOptRef;
use ingot::geneve::GeneveRef;
use ingot::geneve::ValidGeneve;
use ingot::geneve::ValidGeneveOpt;
use ingot::types::HeaderParse;
use ingot::types::NetworkRepr;
use ingot::types::ParseError;
use opte::engine::geneve::ArbitraryGeneveOption;
use opte::engine::geneve::GENEVE_OPT_CLASS_OXIDE;
use opte::engine::packet::ParseError as PktParseError;
use opte::ingot::Ingot;
use opte::ingot::geneve::GeneveOptionType;
use opte::ingot::types::primitives::*;
use zerocopy::ByteSlice;

pub struct GeneveOptionParse<T, B: ByteSlice> {
    pub option: T,
    pub body_remainder: B,
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum OxideOptionType {
    External = 0x00,
    Multicast,
    Mss,
}

impl From<OxideOptionType> for GeneveOptionType {
    fn from(value: OxideOptionType) -> Self {
        GeneveOptionType(value as u8)
    }
}

pub enum ValidOxideOption<B: ByteSlice> {
    External,
    Multicast(ValidMulticastInfo<B>),
    Mss(ValidMssInfo<B>),
    Unknown(GeneveOptionType),
}

impl<B: ByteSlice> ValidOxideOption<B> {
    pub fn option_type(&self) -> GeneveOptionType {
        match self {
            Self::External => OxideOptionType::External.into(),
            Self::Multicast(_) => OxideOptionType::Multicast.into(),
            Self::Mss(_) => OxideOptionType::Mss.into(),
            Self::Unknown(v) => *v,
        }
    }
}

impl<'a> ValidOxideOption<&'a [u8]> {
    #[inline]
    pub fn from_parts(
        option_type: GeneveOptionType,
        body: &'a [u8],
    ) -> Result<GeneveOptionParse<Self, &'a [u8]>, ParseError> {
        let (option, body_remainder) = match option_type.0 {
            n if n == (OxideOptionType::External as u8) => {
                (ValidOxideOption::External, body)
            }
            n if n == (OxideOptionType::Multicast as u8) => {
                let (mc, _, tail) = ValidMulticastInfo::parse(body)?;
                (ValidOxideOption::Multicast(mc), tail)
            }
            n if n == (OxideOptionType::Mss as u8) => {
                let (mss, _, tail) = ValidMssInfo::parse(body)?;
                (ValidOxideOption::Mss(mss), tail)
            }
            _ => (ValidOxideOption::Unknown(option_type), body),
        };

        Ok(GeneveOptionParse { option, body_remainder })
    }
}

// Can't impl TryFrom<T: GeneveOptRef>, sadly.
impl<'a> TryFrom<&'a ArbitraryGeneveOption>
    for GeneveOptionParse<ValidOxideOption<&'a [u8]>, &'a [u8]>
{
    type Error = ParseError;

    #[inline]
    fn try_from(value: &'a ArbitraryGeneveOption) -> Result<Self, Self::Error> {
        if value.opt_class != GENEVE_OPT_CLASS_OXIDE {
            return Err(ParseError::Unwanted);
        }

        ValidOxideOption::from_parts(
            GeneveOptionType(value.opt_type),
            value.data.as_ref(),
        )
    }
}

impl<'a> TryFrom<&'a GeneveOpt>
    for GeneveOptionParse<ValidOxideOption<&'a [u8]>, &'a [u8]>
{
    type Error = ParseError;

    #[inline]
    fn try_from(value: &'a GeneveOpt) -> Result<Self, Self::Error> {
        if value.class != GENEVE_OPT_CLASS_OXIDE {
            return Err(ParseError::Unwanted);
        }

        ValidOxideOption::from_parts(value.option_type, value.data.as_slice())
    }
}

impl<'a, 'b: 'a> TryFrom<&'a ValidGeneveOpt<&'b [u8]>>
    for GeneveOptionParse<ValidOxideOption<&'a [u8]>, &'a [u8]>
{
    type Error = ParseError;

    #[inline]
    fn try_from(
        value: &'a ValidGeneveOpt<&'b [u8]>,
    ) -> Result<Self, Self::Error> {
        if value.class() != GENEVE_OPT_CLASS_OXIDE {
            return Err(ParseError::Unwanted);
        }

        let value_data = match &value.1 {
            ingot::types::BoxedHeader::Repr(r) => r.as_slice(),
            ingot::types::BoxedHeader::Raw(r) => &r[..],
        };

        ValidOxideOption::from_parts(value.option_type(), value_data)
    }
}

#[derive(Debug, Clone, Ingot, Eq, PartialEq)]
#[ingot(impl_default)]
pub struct MulticastInfo {
    #[ingot(is = "u2")]
    pub version: Replication,
    rsvd: u30be,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum Replication {
    /// Replicate packets to ports set for external multicast traffic.
    #[default]
    External = 0x00,
    /// Replicate packets to ports set for underlay multicast traffic.
    Underlay,
    /// Replicate packets to ports set for underlay and external multicast
    /// traffic (bifurcated).
    All,
    Reserved,
}

impl NetworkRepr<u2> for Replication {
    fn to_network(self) -> u2 {
        self as u8
    }

    #[inline]
    fn from_network(val: u8) -> Self {
        match val {
            0 => Replication::External,
            1 => Replication::Underlay,
            2 => Replication::All,
            3 => Replication::Reserved,
            _ => panic!("outside bounds of u2"),
        }
    }
}

#[derive(Debug, Clone, Ingot, Eq, PartialEq)]
#[ingot(impl_default)]
pub struct MssInfo {
    pub mss: u32be,
}

/// Assert that any critical options attached to a packet are understood
/// in this version of the Oxide VPC dataplane.
#[inline]
pub fn validate_options<V: ByteSlice>(
    pkt: &ValidGeneve<V>,
) -> Result<(), PktParseError> {
    if pkt.flags().contains(GeneveFlags::CRITICAL_OPTS) {
        match pkt.options_ref() {
            ingot::types::FieldRef::Repr(g) => {
                for opt in g.iter() {
                    if !opt.option_type.is_critical() {
                        continue;
                    }

                    GeneveOptionParse::try_from(opt)
                        .map_err(|_| ())
                        .and_then(|v| match v.option {
                            ValidOxideOption::Unknown(a) if a.is_critical() => {
                                Err(())
                            }
                            _ => Ok(()),
                        })
                        .map_err(|_| PktParseError::UnrecognisedTunnelOpt {
                            class: opt.class,
                            ty: opt.option_type.0,
                        })?;
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

                    GeneveOptionParse::try_from(&opt)
                        .map_err(|_| ())
                        .and_then(|v| match v.option {
                            ValidOxideOption::Unknown(a) if a.is_critical() => {
                                Err(())
                            }
                            _ => Ok(()),
                        })
                        .map_err(|_| PktParseError::UnrecognisedTunnelOpt {
                            class: opt.class(),
                            ty: opt.option_type().0,
                        })?;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
pub fn valid_geneve_has_oxide_external<V: ByteSlice>(
    pkt: &ValidGeneve<V>,
) -> bool {
    let mut out = false;

    match pkt.options_ref() {
        ingot::types::FieldRef::Repr(g) => {
            for opt in g.iter() {
                out = matches!(
                    GeneveOptionParse::try_from(opt),
                    Ok(GeneveOptionParse {
                        option: ValidOxideOption::External,
                        ..
                    })
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
                    GeneveOptionParse::try_from(&opt),
                    Ok(GeneveOptionParse {
                        option: ValidOxideOption::External,
                        ..
                    })
                );
                if out {
                    break;
                }
            }
        }
    }

    out
}

#[cfg(test)]
mod test {
    use super::*;
    use ingot::types::HeaderParse;
    use ingot::udp::ValidUdp;

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

        opte::engine::geneve::validate_geneve(&geneve).unwrap();
        validate_options(&geneve).unwrap();

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
            validate_options(&geneve),
            Err(PktParseError::UnrecognisedTunnelOpt {
                class: 0xffff,
                ty: 0x80
            }),
        ));

        // This should also apply on classes we *do* know.
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
            0x01, 0x29,
            // crt + type
            0x80,
            // rsvd + len
            0x00,
        ];

        let (_udp, _, rem) = ValidUdp::parse(&buf[..]).unwrap();
        let (geneve, ..) = ValidGeneve::parse(rem).unwrap();

        assert!(matches!(
            validate_options(&geneve),
            Err(PktParseError::UnrecognisedTunnelOpt {
                class: GENEVE_OPT_CLASS_OXIDE,
                ty: 0x80
            }),
        ));
    }

    #[test]
    fn parse_multi_opt() {
        // Create a packet with three extension headers.
        // None are critical, so the fact that we
        // We should also be able to extract info on the options we *do*
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

        opte::engine::geneve::validate_geneve(&geneve).unwrap();
        validate_options(&geneve).unwrap();
        assert!(valid_geneve_has_oxide_external(&geneve));

        assert_eq!(geneve.1.raw().unwrap().iter(None).count(), 3);
    }
}

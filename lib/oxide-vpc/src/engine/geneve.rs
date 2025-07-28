// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Geneve option types specific to the Oxide VPC dataplane.

use ingot::geneve::GeneveOpt;
use ingot::geneve::GeneveOptRef;
use ingot::geneve::ValidGeneveOpt;
use ingot::types::HeaderParse;
use ingot::types::NetworkRepr;
use ingot::types::ParseError;
use opte::engine::geneve::ArbitraryGeneveOption;
use opte::engine::geneve::GENEVE_OPT_CLASS_OXIDE;
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

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum Replication {
    #[default]
    None = 0,
    Internal,
    External,
    All,
}

impl NetworkRepr<u2> for Replication {
    fn to_network(self) -> u2 {
        self as u8
    }

    #[inline]
    fn from_network(val: u8) -> Self {
        match val {
            0 => Replication::None,
            1 => Replication::Internal,
            2 => Replication::External,
            3 => Replication::All,
            _ => panic!("outside bounds of u2"),
        }
    }
}

#[derive(Debug, Clone, Ingot, Eq, PartialEq)]
#[ingot(impl_default)]
pub struct MssInfo {
    pub mss: u32be,
}

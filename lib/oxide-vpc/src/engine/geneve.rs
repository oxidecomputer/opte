// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Geneve option types specific to the Oxide VPC dataplane.
//!
//! # Oxide Geneve Options
//!
//! This module defines Geneve options used in the Oxide rack network to carry
//! VPC-specific metadata during packet encapsulation. All options use the Oxide
//! option class (`GENEVE_OPT_CLASS_OXIDE` = 0x0129).
//!
//! ## Option Types
//!
//! - **External** (0x00): Indicates a packet originated from outside the rack
//!   and was encapsulated by the switch NAT ingress path with Geneve wrapping.
//! - **Multicast** (0x01): Carries multicast replication strategy as a 2-bit
//!   field for coordinating delivery between OPTE and sidecar switch logic.
//! - **Mss** (0x02): Carries original TCP MSS for MSS clamping/boosting to
//!   prevent MTU issues during underlay encapsulation.
//!
//! ## Multicast Option Encoding
//!
//! The multicast option uses a compact 2-bit encoding aligned with sidecar.p4's
//! processing constraints:
//!
//! ```text
//! Option body (4 bytes):
//! ┌──────────┬────────────────────────────┐
//! │ Bits 7-6 │ Bits 5-0 + remaining bytes │
//! │ (u2)     │ (reserved, must be 0)      │
//! └──────────┴────────────────────────────┘
//!    │
//!    └─> Replication mode:
//!        00 = External (front panel/customer ports, traffic leaving rack)
//!        01 = Underlay (infrastructure forwarding to other sleds)
//!        10 = Both (both External and Underlay)
//!        11 = Reserved
//! ```
//!
//! ### Replication Semantics (Tx-only instruction)
//!
//! The [`Replication`] type is a Tx-only instruction telling the switch which
//! port groups to replicate outbound multicast packets to. On Rx, OPTE ignores
//! the replication field and performs local same-sled delivery based purely on
//! subscriptions.
//!
//! OPTE routes to next hop unicast address (for ALL modes) to determine
//! reachability and underlay port/MAC. Packet destination is multicast
//! ff04::/16 with multicast MAC.
//!
//! - **External**: Switch decaps and replicates to external-facing ports (front panel)
//! - **Underlay**: Switch replicates to underlay ports (other sleds)
//! - **Both**: Switch replicates to both external and underlay port groups (bifurcated)
//! - **Local same-sled delivery**: Always happens regardless of the replication setting.
//!   Not an access control mechanism - local delivery is independent of replication mode.
//!
//! All multicast packets are encapsulated with fleet VNI 77 (`DEFAULT_MULTICAST_VNI`)
//! regardless of replication mode. The replication mode determines delivery behavior,
//! not VNI selection.
//!
//! The 2-bit encoding allows extraction in P4 programs and aligns with the
//! sidecar pipeline's tag-based routing decisions.
//!
//! [`Replication`]: crate::api::Replication
//!
//! ## Option Length Encoding
//!
//! Geneve has two length fields to consider (both measured in 4-byte words):
//! - Geneve header `opt_len` (6 bits): total size of the options area
//!   (sums each option's 4-byte header + body).
//! - Option header `len` (5 bits): size of that option's body only.
//!
//! For Oxide options used here:
//! - External: geneve opt_len += 1; option len = 0
//! - Multicast: geneve opt_len += 2; option len = 1
//! - MSS: geneve opt_len += 2; option len = 1

use crate::api::Replication;
use ingot::geneve::GeneveFlags;
use ingot::geneve::GeneveRef;
use ingot::geneve::ValidGeneve;
use ingot::types::CRStr;
use ingot::types::HeaderParse;
use ingot::types::NetworkRepr;
use ingot::types::ParseError;
use opte::engine::geneve::GENEVE_OPT_CLASS_OXIDE;
use opte::engine::geneve::OptionCast;
use opte::engine::geneve::WalkOptions;
use opte::engine::packet::ParseError as PktParseError;
use opte::ingot::Ingot;
use opte::ingot::geneve::GeneveOptionType;
use opte::ingot::types::primitives::*;
use zerocopy::ByteSlice;

pub type OxideOptions<'a> = WalkOptions<'a, ValidOxideOption<'a>>;

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

pub enum ValidOxideOption<'a> {
    External,
    Multicast(ValidMulticastInfo<&'a [u8]>),
    Mss(ValidMssInfo<&'a [u8]>),
}

impl<'a> OptionCast<'a> for ValidOxideOption<'a> {
    fn option_class(&self) -> u16 {
        GENEVE_OPT_CLASS_OXIDE
    }

    fn option_type(&self) -> GeneveOptionType {
        match self {
            Self::External => OxideOptionType::External,
            Self::Multicast(_) => OxideOptionType::Multicast,
            Self::Mss(_) => OxideOptionType::Mss,
        }
        .into()
    }

    fn try_cast(
        class: u16,
        ty: GeneveOptionType,
        body: &'a [u8],
    ) -> Result<Option<(Self, &'a [u8])>, ParseError>
    where
        Self: Sized + 'a,
    {
        Ok(match (class, ty.0) {
            (class, _) if class != GENEVE_OPT_CLASS_OXIDE => None,
            (_, n) if n == (OxideOptionType::External as u8) => {
                Some((ValidOxideOption::External, body))
            }
            (_, n) if n == (OxideOptionType::Multicast as u8) => {
                let (mc, _, tail) = ValidMulticastInfo::parse(body)?;
                Some((ValidOxideOption::Multicast(mc), tail))
            }
            (_, n) if n == (OxideOptionType::Mss as u8) => {
                let (mss, _, tail) = ValidMssInfo::parse(body)?;
                Some((ValidOxideOption::Mss(mss), tail))
            }
            _ => None,
        })
    }
}

/// Geneve multicast option body carrying replication information.
#[derive(Debug, Clone, Ingot, Eq, PartialEq)]
#[ingot(impl_default)]
pub struct MulticastInfo {
    #[ingot(is = "u2")]
    pub version: Replication,
    rsvd: u30be,
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
            2 => Replication::Both,
            3 => Replication::Reserved,
            _ => unreachable!("u2 value out of range: {val}"),
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
    static LABEL: CRStr = CRStr::new_unchecked("geneve_option\0");
    if pkt.flags().contains(GeneveFlags::CRITICAL_OPTS) {
        for opt in OxideOptions::from_raw(pkt) {
            let opt = opt
                .map_err(|e| {
                    PktParseError::IngotError(
                        ingot::types::PacketParseError::new(e, &LABEL),
                    )
                })?
                .option;
            if opt.is_unknown_critical() {
                return Err(PktParseError::UnrecognisedTunnelOpt {
                    class: opt.option_class(),
                    ty: opt.option_type().0,
                });
            }
        }
    }

    Ok(())
}

/// Extract multicast replication info from Geneve options.
///
/// Treats Reserved (value 3) as invalid and returns None, implementing
/// fail-closed behavior.
///
/// This function silently skips options with parse errors (e.g., `TooSmall`).
/// Call `validate_options()` first if you want parse errors surfaced and
/// RFC 8926 critical option semantics enforced. This function assumes
/// validation has already been performed.
pub fn extract_multicast_replication<V: ByteSlice>(
    pkt: &ValidGeneve<V>,
) -> Option<Replication> {
    // In debug builds, verify validate_options() was called first if critical options present
    debug_assert!(
        !pkt.flags().contains(GeneveFlags::CRITICAL_OPTS)
            || validate_options(pkt).is_ok(),
        "extract_multicast_replication() called without prior validation when critical options present"
    );

    for opt in OxideOptions::from_raw(pkt) {
        let Ok(opt) = opt else { continue };
        if let Some(ValidOxideOption::Multicast(mc_info)) = opt.option.known() {
            let repl = mc_info.version();
            // Filter out Reserved (u2=3). This value exists in the 2-bit space
            // but is not used by sidecar P4; treat as invalid.
            if matches!(repl, Replication::Reserved) {
                return None;
            }
            return Some(repl);
        }
    }
    None
}

#[cfg(test)]
pub fn valid_geneve_has_oxide_external<V: ByteSlice>(
    pkt: &ValidGeneve<V>,
) -> bool {
    let mut out = false;

    for opt in OxideOptions::from_raw(pkt) {
        let Ok(opt) = opt else { panic!("malformed extension!") };
        if let Some(ValidOxideOption::External) = opt.option.known() {
            out = true;
            break;
        }
    }

    out
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec::Vec;
    use ingot::types::HeaderParse;
    use ingot::udp::ValidUdp;

    /// Critical bit mask for Geneve option type field (bit 7).
    /// Per RFC 8926, unknown options with this bit set must cause packet drop.
    const GENEVE_OPT_TYPE_CRITICAL: u8 = 0x80;

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
    fn parse_multicast_replication_values() {
        // Build a minimal UDP+Geneve packet with one Oxide multicast option
        // Body's first byte top-2 bits carry Replication.
        fn build_buf(rep: Replication) -> Vec<u8> {
            #[rustfmt::skip]
            let mut buf = vec![
                // UDP source
                0x1E, 0x61,
                // UDP dest
                0x17, 0xC1,
                // UDP length (8 UDP hdr + 8 Geneve hdr + 4 opt hdr + 4 opt body = 24 = 0x18)
                0x00, 0x18,
                // UDP csum
                0x00, 0x00,
                // Geneve: ver + opt len (2 words = 8 bytes: 4 opt hdr + 4 opt body)
                0x02,
                // Geneve flags
                0x00,
                // Geneve proto
                0x65, 0x58,
                // Geneve vni + reserved
                0x00, 0x00, 0x00, 0x00,
                // Geneve option: class 0x0129 (Oxide)
                0x01, 0x29,
                // Geneve option: flags+type (non-critical, Multicast = 0x01)
                0x01,
                // Geneve option: rsvd + len (1 word = 4 bytes body)
                0x01,
            ];
            // Geneve option body: 4-byte body with replication in top 2 bits
            buf.push((rep as u8) << 6);
            buf.extend_from_slice(&[0x00, 0x00, 0x00]);
            buf
        }

        for (rep, expect) in [
            (Replication::External, Replication::External),
            (Replication::Underlay, Replication::Underlay),
            (Replication::Both, Replication::Both),
        ] {
            let buf = build_buf(rep);
            let (.., rem) = ValidUdp::parse(&buf[..]).unwrap();
            let (geneve, ..) = ValidGeneve::parse(rem).unwrap();
            validate_options(&geneve).unwrap();

            let got = extract_multicast_replication(&geneve).unwrap();
            assert_eq!(got, expect);
        }
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
            GENEVE_OPT_TYPE_CRITICAL,
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
            GENEVE_OPT_TYPE_CRITICAL,
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
            // length (8 UDP hdr + 8 Geneve hdr + 20 options = 36 = 0x24)
            0x00, 0x24,
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

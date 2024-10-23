// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

pub mod v4;
pub mod v6;

use super::checksum::Checksum;
use super::packet::ParseError;
use ingot::choice;
use ingot::ethernet::Ethertype;
use ingot::types::ByteSlice;
use ingot::types::Header;
use ingot::types::NextLayer;
use ingot::Ingot;
use opte_api::MacAddr;
use v4::*;
use v6::*;
use zerocopy::ByteSliceMut;
use zerocopy::IntoBytes;

// Redefine Ethernet and v4/v6 because we have our own, internal,
// address types already.

#[choice(on = Ethertype)]
pub enum L3 {
    Ipv4 = Ethertype::IPV4,
    Ipv6 = Ethertype::IPV6,
}

impl<V: ByteSlice> L3<V> {
    pub fn pseudo_header(&self) -> Checksum {
        match self {
            L3::Ipv4(v4) => {
                let mut pseudo_hdr_bytes = [0u8; 12];
                pseudo_hdr_bytes[0..4].copy_from_slice(v4.source().as_ref());
                pseudo_hdr_bytes[4..8]
                    .copy_from_slice(v4.destination().as_ref());
                pseudo_hdr_bytes[9] = v4.protocol().0;
                let ulp_len = v4.total_len() - 4 * (v4.ihl() as u16);
                pseudo_hdr_bytes[10..].copy_from_slice(&ulp_len.to_be_bytes());

                Checksum::compute(&pseudo_hdr_bytes)
            }
            L3::Ipv6(v6) => {
                let mut pseudo_hdr_bytes = [0u8; 40];
                pseudo_hdr_bytes[0..16].copy_from_slice(&v6.source().as_ref());
                pseudo_hdr_bytes[16..32]
                    .copy_from_slice(&v6.destination().as_ref());
                pseudo_hdr_bytes[39] = v6.next_layer().unwrap_or_default().0;
                let ulp_len = v6.payload_len() as u32;
                pseudo_hdr_bytes[32..36]
                    .copy_from_slice(&ulp_len.to_be_bytes());
                Checksum::compute(&pseudo_hdr_bytes)
            }
        }
    }
}

impl<V: ByteSliceMut> L3<V> {
    #[inline]
    pub fn compute_checksum(&mut self) {
        if let L3::Ipv4(ip) = self {
            match ip {
                Header::Repr(ip) => ip.compute_checksum(),
                Header::Raw(ip) => ip.compute_checksum(),
            }
        }
    }
}

impl<V: ByteSlice> ValidL3<V> {
    pub fn pseudo_header(&self) -> Checksum {
        match self {
            ValidL3::Ipv4(v4) => {
                let mut pseudo_hdr_bytes = [0u8; 12];
                pseudo_hdr_bytes[0..4].copy_from_slice(v4.source().as_ref());
                pseudo_hdr_bytes[4..8]
                    .copy_from_slice(v4.destination().as_ref());
                // pseudo_hdr_bytes[8] reserved
                pseudo_hdr_bytes[9] = v4.protocol().0;
                let ulp_len = v4.total_len() - 4 * (v4.ihl() as u16);
                pseudo_hdr_bytes[10..].copy_from_slice(&ulp_len.to_be_bytes());

                Checksum::compute(&pseudo_hdr_bytes)
            }
            ValidL3::Ipv6(v6) => {
                let mut pseudo_hdr_bytes = [0u8; 40];
                pseudo_hdr_bytes[0..16].copy_from_slice(&v6.source().as_ref());
                pseudo_hdr_bytes[16..32]
                    .copy_from_slice(&v6.destination().as_ref());
                pseudo_hdr_bytes[39] = v6.next_layer().unwrap_or_default().0;
                let ulp_len = v6.payload_len() as u32;
                pseudo_hdr_bytes[32..36]
                    .copy_from_slice(&ulp_len.to_be_bytes());

                Checksum::compute(&pseudo_hdr_bytes)
            }
        }
    }

    pub fn csum(&self) -> [u8; 2] {
        match self {
            ValidL3::Ipv4(i4) => i4.checksum(),
            ValidL3::Ipv6(_) => 0,
        }
        .to_be_bytes()
    }

    #[inline]
    pub fn validate(&self, bytes_after: usize) -> Result<(), ParseError> {
        match self {
            ValidL3::Ipv4(i4) => i4.validate(bytes_after),
            ValidL3::Ipv6(i6) => i6.validate(bytes_after),
        }
    }
}

impl<V: ByteSliceMut> ValidL3<V> {
    #[inline]
    pub fn compute_checksum(&mut self) {
        if let ValidL3::Ipv4(ip) = self {
            ip.set_checksum(0);

            let mut csum = Checksum::new();
            csum.add_bytes(ip.0.as_bytes());
            match &ip.1 {
                Header::Repr(opts) => {
                    csum.add_bytes(&*opts);
                }
                Header::Raw(opts) => {
                    csum.add_bytes(&*opts);
                }
            }

            ip.set_checksum(csum.finalize_for_ingot());
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct Ethernet {
    #[ingot(is = "[u8; 6]")]
    pub destination: MacAddr,
    #[ingot(is = "[u8; 6]")]
    pub source: MacAddr,
    #[ingot(is = "u16be", next_layer)]
    pub ethertype: Ethertype,
}

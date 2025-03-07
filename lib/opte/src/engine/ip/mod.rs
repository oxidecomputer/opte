// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

pub mod v4;
pub mod v6;

use super::checksum::Checksum;
use super::headers::HasInnerCksum;
use super::headers::HeaderActionError;
use super::headers::HeaderActionModify;
use super::headers::IpMod;
use super::headers::IpPush;
use super::headers::PushAction;
use super::packet::ParseError;
use ingot::choice;
use ingot::ethernet::Ethertype;
use ingot::ip::IpProtocol;
use ingot::ip::Ipv4Flags;
use ingot::types::ByteSlice;
use ingot::types::Header;
use ingot::types::InlineHeader;
use ingot::types::NextLayer;
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
                // pseudo_hdr_bytes[8] reserved
                pseudo_hdr_bytes[9] = v4.protocol().0;
                let ulp_len = v4.total_len() - 4 * (v4.ihl() as u16);
                pseudo_hdr_bytes[10..].copy_from_slice(&ulp_len.to_be_bytes());

                Checksum::compute(&pseudo_hdr_bytes)
            }
            L3::Ipv6(v6) => {
                let mut pseudo_hdr_bytes = [0u8; 40];
                pseudo_hdr_bytes[0..16].copy_from_slice(v6.source().as_ref());
                pseudo_hdr_bytes[16..32]
                    .copy_from_slice(v6.destination().as_ref());
                let ulp_len = v6.payload_len() as u32;
                pseudo_hdr_bytes[32..36]
                    .copy_from_slice(&ulp_len.to_be_bytes());
                pseudo_hdr_bytes[39] = v6.next_layer().unwrap_or_default().0;

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
    #[inline]
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
                pseudo_hdr_bytes[0..16].copy_from_slice(v6.source().as_ref());
                pseudo_hdr_bytes[16..32]
                    .copy_from_slice(v6.destination().as_ref());
                let ulp_len = v6.payload_len() as u32;
                pseudo_hdr_bytes[32..36]
                    .copy_from_slice(&ulp_len.to_be_bytes());
                pseudo_hdr_bytes[39] = v6.next_layer().unwrap_or_default().0;

                Checksum::compute(&pseudo_hdr_bytes)
            }
        }
    }

    #[inline]
    pub fn csum(&self) -> [u8; 2] {
        match self {
            ValidL3::Ipv4(i4) => i4.checksum(),
            ValidL3::Ipv6(_) => 0,
        }
        .to_be_bytes()
    }

    /// Return whether the IP layer has a checksum both structurally
    /// and that it is non-zero (i.e., not offloaded).
    #[inline]
    pub fn has_ip_csum(&self) -> bool {
        match self {
            ValidL3::Ipv4(i4) => i4.checksum() != 0,
            _ => false,
        }
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
                    csum.add_bytes(opts);
                }
                Header::Raw(opts) => {
                    csum.add_bytes(opts);
                }
            }

            ip.set_checksum(csum.finalize_for_ingot());
        }
    }
}

impl<T: ByteSliceMut> HeaderActionModify<IpMod>
    for InlineHeader<L3Repr, ValidL3<T>>
{
    #[inline]
    fn run_modify(
        &mut self,
        mod_spec: &IpMod,
    ) -> Result<(), HeaderActionError> {
        match mod_spec {
            IpMod::Ip4(mods) => match self {
                InlineHeader::Repr(L3Repr::Ipv4(v4)) => {
                    if let Some(src) = mods.src {
                        v4.source = src;
                    }
                    if let Some(dst) = mods.dst {
                        v4.destination = dst;
                    }
                    if let Some(p) = mods.proto {
                        v4.protocol = IpProtocol(u8::from(p));
                    }
                }
                InlineHeader::Raw(ValidL3::Ipv4(v4)) => {
                    if let Some(src) = mods.src {
                        v4.set_source(src);
                    }
                    if let Some(dst) = mods.dst {
                        v4.set_destination(dst);
                    }
                    if let Some(p) = mods.proto {
                        v4.set_protocol(IpProtocol(u8::from(p)));
                    }
                }
                _ => return Err(HeaderActionError::MissingHeader),
            },
            IpMod::Ip6(mods) => match self {
                InlineHeader::Repr(L3Repr::Ipv6(v6)) => {
                    if let Some(src) = mods.src {
                        v6.source = src;
                    }
                    if let Some(dst) = mods.dst {
                        v6.destination = dst;
                    }
                    if let Some(p) = mods.proto {
                        let ipp = IpProtocol(u8::from(p));

                        v6_set_next_header::<&mut [u8]>(ipp, v6)?;
                    }
                }
                InlineHeader::Raw(ValidL3::Ipv6(v6)) => {
                    if let Some(src) = mods.src {
                        v6.set_source(src);
                    }
                    if let Some(dst) = mods.dst {
                        v6.set_destination(dst);
                    }
                    if let Some(p) = mods.proto {
                        let ipp = IpProtocol(u8::from(p));
                        v6_set_next_header(ipp, v6)?;
                    }
                }
                _ => return Err(HeaderActionError::MissingHeader),
            },
        }

        Ok(())
    }
}

impl<T: ByteSliceMut> HeaderActionModify<IpMod> for L3<T> {
    #[inline]
    fn run_modify(
        &mut self,
        mod_spec: &IpMod,
    ) -> Result<(), HeaderActionError> {
        match (self, mod_spec) {
            (L3::Ipv4(v4), IpMod::Ip4(mods)) => {
                if let Some(src) = mods.src {
                    v4.set_source(src);
                }
                if let Some(dst) = mods.dst {
                    v4.set_destination(dst);
                }
                if let Some(p) = mods.proto {
                    v4.set_protocol(IpProtocol(u8::from(p)));
                }
                Ok(())
            }
            (L3::Ipv6(v6), IpMod::Ip6(mods)) => {
                if let Some(src) = mods.src {
                    v6.set_source(src);
                }
                if let Some(dst) = mods.dst {
                    v6.set_destination(dst);
                }
                if let Some(p) = mods.proto {
                    let ipp = IpProtocol(u8::from(p));
                    v6_set_next_header(ipp, v6)?;
                }
                Ok(())
            }
            _ => Err(HeaderActionError::MissingHeader),
        }
    }
}

impl<T: ByteSlice> HasInnerCksum for InlineHeader<L3Repr, ValidL3<T>> {
    const HAS_CKSUM: bool = true;
}

impl<T: ByteSlice> HasInnerCksum for L3<T> {
    const HAS_CKSUM: bool = true;
}

impl<T: ByteSlice> PushAction<L3<T>> for IpPush {
    fn push(&self) -> L3<T> {
        match self {
            IpPush::Ip4(v4) => L3::Ipv4(
                Ipv4 {
                    protocol: IpProtocol(u8::from(v4.proto)),
                    source: v4.src,
                    destination: v4.dst,
                    flags: Ipv4Flags::DONT_FRAGMENT,
                    ..Default::default()
                }
                .into(),
            ),
            IpPush::Ip6(v6) => L3::Ipv6(
                Ipv6 {
                    next_header: IpProtocol(u8::from(v6.proto)),
                    source: v6.src,
                    destination: v6.dst,
                    ..Default::default()
                }
                .into(),
            ),
        }
    }
}

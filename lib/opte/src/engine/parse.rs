// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Constructs used in packet parsing, such as choices over protocol
//! and complete packet definitions.

use super::LightweightMeta;
use super::checksum::Checksum;
use super::checksum::HeaderChecksum;
use super::ether::EthernetPacket;
use super::ether::EthernetRef;
use super::ether::ValidEthernet;
use super::geneve::GENEVE_PORT;
use super::geneve::validate_geneve;
use super::headers::HasInnerCksum;
use super::headers::HeaderActionError;
use super::headers::HeaderActionModify;
use super::headers::UlpMetaModify;
use super::headers::ValidEncapMeta;
use super::icmp::IcmpEchoMut;
use super::icmp::QueryEcho;
use super::icmp::ValidIcmpEcho;
use super::ip::L3;
use super::ip::ValidL3;
use super::ip::v4::Ipv4Ref;
use super::ip::v6::Ipv6Packet;
use super::ip::v6::Ipv6Ref;
use super::packet::AddrPair;
use super::packet::FLOW_ID_DEFAULT;
use super::packet::InnerFlowId;
use super::packet::MismatchError;
use super::packet::OpteMeta;
use super::packet::ParseError;
use super::rule::CompiledTransform;
use core::fmt;
use illumos_sys_hdrs::mac::MacEtherOffloadFlags;
use illumos_sys_hdrs::mac::mac_ether_offload_info_t;
use ingot::Parse;
use ingot::choice;
use ingot::ethernet::Ethertype;
use ingot::geneve::GenevePacket;
use ingot::icmp::IcmpV4;
use ingot::icmp::IcmpV4Mut;
use ingot::icmp::IcmpV4Ref;
use ingot::icmp::IcmpV6;
use ingot::icmp::IcmpV6Mut;
use ingot::icmp::IcmpV6Ref;
use ingot::icmp::ValidIcmpV4;
use ingot::icmp::ValidIcmpV6;
use ingot::ip::IpProtocol;
use ingot::tcp::Tcp;
use ingot::tcp::TcpFlags;
use ingot::tcp::TcpMut;
use ingot::tcp::TcpRef;
use ingot::tcp::ValidTcp;
use ingot::types::ByteSlice;
use ingot::types::Header;
use ingot::types::HeaderLen;
use ingot::types::HeaderParse;
use ingot::types::InlineHeader;
use ingot::types::NextLayer;
use ingot::types::ParseControl;
use ingot::types::ToOwnedPacket;
use ingot::udp::Udp;
use ingot::udp::UdpMut;
use ingot::udp::UdpPacket;
use ingot::udp::UdpRef;
use ingot::udp::ValidUdp;
use zerocopy::ByteSliceMut;
use zerocopy::IntoBytes;
use zerocopy::SplitByteSlice;

#[choice(on = IpProtocol)]
pub enum L4 {
    Tcp = IpProtocol::TCP,
    Udp = IpProtocol::UDP,
}

#[choice(on = IpProtocol)]
pub enum Ulp {
    Tcp = IpProtocol::TCP,
    Udp = IpProtocol::UDP,
    IcmpV4 = IpProtocol::ICMP,
    IcmpV6 = IpProtocol::ICMP_V6,
}

impl<B: ByteSlice + SplitByteSlice> Ulp<B> {
    #[inline]
    pub fn repr(&self) -> UlpRepr {
        // Unwrap safety: to_owned is infallible on all these types
        // (no inner reparsing is required).
        match self {
            Ulp::Tcp(t) => t.to_owned(None).unwrap().into(),
            Ulp::Udp(t) => t.to_owned(None).unwrap().into(),
            Ulp::IcmpV4(t) => t.to_owned(None).unwrap().into(),
            Ulp::IcmpV6(t) => t.to_owned(None).unwrap().into(),
        }
    }
}

impl<B: ByteSlice> ValidUlp<B> {
    #[inline]
    pub fn csum(&self) -> [u8; 2] {
        match self {
            ValidUlp::Tcp(t) => t.checksum(),
            ValidUlp::Udp(u) => u.checksum(),
            ValidUlp::IcmpV4(i4) => i4.checksum(),
            ValidUlp::IcmpV6(i6) => i6.checksum(),
        }
        .to_be_bytes()
    }

    /// Return whether the ULP layer has a checksum both structurally
    /// and that it is non-zero (i.e., not offloaded).
    #[inline]
    pub fn has_ulp_csum(&self) -> bool {
        let csum = match self {
            ValidUlp::Tcp(t) => t.checksum(),
            ValidUlp::Udp(u) => u.checksum(),
            ValidUlp::IcmpV4(i4) => i4.checksum(),
            ValidUlp::IcmpV6(i6) => i6.checksum(),
        };

        csum != 0
    }

    #[inline]
    pub fn ip_protocol(&self) -> IpProtocol {
        match self {
            ValidUlp::Tcp(_) => IpProtocol::TCP,
            ValidUlp::Udp(_) => IpProtocol::UDP,
            ValidUlp::IcmpV4(_) => IpProtocol::ICMP,
            ValidUlp::IcmpV6(_) => IpProtocol::ICMP_V6,
        }
    }
}

impl<B: ByteSliceMut> ValidUlp<B> {
    #[inline]
    pub fn compute_checksum(
        &mut self,
        mut body_csum: Checksum,
        l3: &ValidL3<B>,
    ) {
        match self {
            // ICMP4 requires the body_csum *without*
            // the pseudoheader added back in.
            ValidUlp::IcmpV4(i4) => {
                i4.set_checksum(0);
                body_csum.add_bytes(i4.0.as_bytes());
                i4.set_checksum(body_csum.finalize_for_ingot());
            }
            ValidUlp::IcmpV6(i6) => {
                body_csum += l3.pseudo_header();

                i6.set_checksum(0);
                body_csum.add_bytes(i6.0.as_bytes());
                i6.set_checksum(body_csum.finalize_for_ingot());
            }
            ValidUlp::Tcp(tcp) => {
                body_csum += l3.pseudo_header();

                tcp.set_checksum(0);
                body_csum.add_bytes(tcp.0.as_bytes());
                match &tcp.1 {
                    Header::Repr(opts) => {
                        body_csum.add_bytes(opts);
                    }
                    Header::Raw(opts) => {
                        body_csum.add_bytes(opts);
                    }
                }
                tcp.set_checksum(body_csum.finalize_for_ingot());
            }
            ValidUlp::Udp(udp) => {
                body_csum += l3.pseudo_header();

                udp.set_checksum(0);
                body_csum.add_bytes(udp.0.as_bytes());
                udp.set_checksum(body_csum.finalize_for_ingot());
            }
        }
    }
}

impl<B: ByteSlice> Ulp<B> {
    pub fn src_port(&self) -> Option<u16> {
        match self {
            Ulp::Tcp(t) => Some(t.source()),
            Ulp::Udp(u) => Some(u.source()),
            _ => None,
        }
    }

    pub fn dst_port(&self) -> Option<u16> {
        match self {
            Ulp::Tcp(t) => Some(t.destination()),
            Ulp::Udp(t) => Some(t.destination()),
            _ => None,
        }
    }
}

#[derive(Parse)]
pub struct GeneveOverV6<Q: ByteSlice> {
    pub outer_eth: EthernetPacket<Q>,
    #[ingot(from = "L3<Q>")]
    pub outer_v6: Ipv6Packet<Q>,
    #[ingot(from = "L4<Q>", control = geneve_dst_port)]
    pub outer_udp: UdpPacket<Q>,
    pub outer_encap: GenevePacket<Q>,

    pub inner_eth: EthernetPacket<Q>,
    pub inner_l3: L3<Q>,
    pub inner_ulp: Ulp<Q>,
}

impl<Q: ByteSlice> ValidGeneveOverV6<Q> {
    /// Return packet info about the inner frame.
    #[inline]
    pub fn ulp_meoi(
        &self,
        pkt_len: usize,
    ) -> Result<mac_ether_offload_info_t, MeoiError> {
        let adj_len = pkt_len
            .checked_sub(
                (
                    &self.outer_eth,
                    &self.outer_v6,
                    &self.outer_udp,
                    &self.outer_encap,
                )
                    .packet_length(),
            )
            .ok_or(MeoiError::PacketTooShort)?;
        let meoi_len =
            u32::try_from(adj_len).expect("packet length exceeds u32::MAX");
        let meoi_l3hlen = u16::try_from(self.inner_l3.packet_length())
            .map_err(|_| MeoiError::L3TooLong)?;

        Ok(mac_ether_offload_info_t {
            meoi_flags: MacEtherOffloadFlags::L2INFO_SET
                | MacEtherOffloadFlags::L3INFO_SET
                | MacEtherOffloadFlags::L4INFO_SET,
            meoi_l2hlen: u8::try_from(self.inner_eth.packet_length())
                .expect("L2 should never exceed ~22B (QinQ)"),
            meoi_l3proto: self.inner_eth.ethertype().0,
            meoi_l3hlen,
            meoi_l4proto: self.inner_ulp.ip_protocol().0,
            meoi_l4hlen: u8::try_from(self.inner_ulp.packet_length())
                .expect("L4 should never exceed 60B (max TCP options)"),
            meoi_len,
            ..Default::default()
        })
    }
}

/// Errors encountered when constructing a [`mac_ether_offload_info_t`].
#[derive(Copy, Clone, Debug)]
pub enum MeoiError {
    L3TooLong,
    PacketTooShort,
}

impl fmt::Display for MeoiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("meoi construction failed: ")?;
        match self {
            MeoiError::L3TooLong => f.write_str("packet L3 exceeds u16::MAX"),
            MeoiError::PacketTooShort => {
                f.write_str("packet length reported as shorter than encap")
            }
        }
    }
}

#[inline]
fn geneve_dst_port<V: ByteSlice>(l4: &ValidL4<V>) -> ParseControl {
    match l4 {
        ValidL4::Udp(u) if u.destination() == GENEVE_PORT => {
            ParseControl::Continue
        }
        _ => ParseControl::Reject,
    }
}

#[inline]
fn exit_on_arp<V: ByteSlice>(eth: &ValidEthernet<V>) -> ParseControl {
    if eth.ethertype() == Ethertype::ARP {
        ParseControl::Accept
    } else {
        ParseControl::Continue
    }
}

#[inline(always)]
fn flow_id<V: ByteSlice>(
    l3: Option<&ValidL3<V>>,
    ulp: Option<&ValidUlp<V>>,
) -> InnerFlowId {
    let (proto, addrs) = match l3 {
        Some(ValidL3::Ipv4(pkt)) => (
            pkt.protocol().0,
            AddrPair::V4 { src: pkt.source(), dst: pkt.destination() },
        ),
        Some(ValidL3::Ipv6(pkt)) => (
            pkt.next_layer().unwrap_or_default().0,
            AddrPair::V6 { src: pkt.source(), dst: pkt.destination() },
        ),
        None => (255, FLOW_ID_DEFAULT.addrs),
    };

    let (src_port, dst_port) = ulp
        .map(|ulp| {
            (
                ulp.true_src_port().or_else(|| ulp.pseudo_port()).unwrap_or(0),
                ulp.true_dst_port().or_else(|| ulp.pseudo_port()).unwrap_or(0),
            )
        })
        .unwrap_or((0, 0));

    InnerFlowId { proto, addrs, src_port, dst_port }
}

#[derive(Parse)]
pub struct NoEncap<Q: ByteSlice> {
    #[ingot(control = exit_on_arp)]
    pub inner_eth: EthernetPacket<Q>,
    pub inner_l3: Option<L3<Q>>,
    pub inner_ulp: Option<Ulp<Q>>,
}

impl<Q: ByteSlice> ValidNoEncap<Q> {
    /// Return packet info about the inner frame.
    #[inline]
    pub fn ulp_meoi(
        &self,
        pkt_len: usize,
    ) -> Result<mac_ether_offload_info_t, MeoiError> {
        // TCP, UDP, and the ICMPs are all understood by illumos's MEOI
        // framework.
        let l4_flag = if self.inner_ulp.is_some() {
            MacEtherOffloadFlags::L4INFO_SET
        } else {
            MacEtherOffloadFlags::empty()
        };
        let meoi_len =
            u32::try_from(pkt_len).expect("packet length exceeds u32::MAX");
        let meoi_l3hlen = u16::try_from(self.inner_l3.packet_length())
            .map_err(|_| MeoiError::L3TooLong)?;

        Ok(mac_ether_offload_info_t {
            meoi_flags: MacEtherOffloadFlags::L2INFO_SET
                | MacEtherOffloadFlags::L3INFO_SET
                | l4_flag,
            meoi_l2hlen: u8::try_from(self.inner_eth.packet_length())
                .expect("L2 should never exceed ~22B (QinQ)"),
            meoi_l3proto: self.inner_eth.ethertype().0,
            meoi_l3hlen,
            meoi_l4proto: self
                .inner_ulp
                .as_ref()
                .map(|v| v.ip_protocol().0)
                .unwrap_or_default(),
            meoi_l4hlen: u8::try_from(self.inner_ulp.packet_length())
                .expect("L4 should never exceed 60B (max TCP options)"),
            meoi_len,
            ..Default::default()
        })
    }
}

impl<T: ByteSlice> From<ValidNoEncap<T>> for OpteMeta<T> {
    #[inline]
    fn from(value: ValidNoEncap<T>) -> Self {
        NoEncap::from(value).into()
    }
}

impl<V: ByteSliceMut> LightweightMeta<V> for ValidNoEncap<V> {
    #[inline]
    fn flow(&self) -> InnerFlowId {
        flow_id(self.inner_l3.as_ref(), self.inner_ulp.as_ref())
    }

    #[inline]
    fn run_compiled_transform(&mut self, transform: &CompiledTransform)
    where
        V: ByteSliceMut,
    {
        transform.transform_ether(&mut self.inner_eth);
        if let Some(l3) = self.inner_l3.as_mut() {
            transform.transform_l3(l3);
        }
        if let Some(ulp) = self.inner_ulp.as_mut() {
            transform.transform_ulp(ulp);
        }
    }

    #[inline]
    fn compute_body_csum(&self) -> Option<Checksum> {
        let use_pseudo = if let Some(v) = &self.inner_ulp {
            !matches!(v, ValidUlp::IcmpV4(_))
        } else {
            false
        };

        let pseudo_csum = match self.inner_eth.ethertype() {
            Ethertype::IPV4 | Ethertype::IPV6 => {
                self.inner_l3.as_ref().map(|v| v.pseudo_header())
            }
            // Includes ARP.
            _ => return None,
        };

        let pseudo_csum = pseudo_csum?;

        self.inner_ulp.as_ref().and_then(csum_minus_hdr).map(|mut v| {
            if use_pseudo {
                v -= pseudo_csum;
            }
            v
        })
    }

    #[inline]
    fn encap_len(&self) -> u16 {
        0
    }

    #[inline]
    fn update_inner_checksums(&mut self, body_csum: Option<Checksum>) {
        if let Some(l3) = self.inner_l3.as_mut() {
            if let (Some(ulp), Some(body_csum)) =
                (self.inner_ulp.as_mut(), body_csum)
            {
                if ulp.has_ulp_csum() {
                    ulp.compute_checksum(body_csum, l3);
                }
            }
            if l3.has_ip_csum() {
                l3.compute_checksum();
            }
        }
    }

    #[inline]
    fn inner_tcp(&self) -> Option<&impl TcpRef<V>> {
        match self.inner_ulp.as_ref() {
            Some(ValidUlp::Tcp(t)) => Some(t),
            _ => None,
        }
    }

    #[inline]
    fn validate(&self, pkt_len: usize) -> Result<(), ParseError> {
        if let Some(l3) = &self.inner_l3 {
            let rem_len = pkt_len - (&self.inner_eth, l3).packet_length();
            l3.validate(rem_len)?;
            if let Some(ulp) = &self.inner_ulp {
                let rem_len = rem_len - ulp.packet_length();
                ulp.validate(rem_len)?;
            }
        }

        Ok(())
    }
}

#[inline]
fn validate_udp<V: ByteSlice>(
    pkt: &ValidUdp<V>,
    bytes_after: usize,
) -> Result<(), ParseError> {
    // Packets can have arbitrary zero-padding at the end so
    // our length *could* be larger than the packet reports.
    // Unlikely in practice as Encap headers push us past the 64B
    // minimum packet size.
    let wanted_len = bytes_after + pkt.packet_length();
    if pkt.length() as usize <= wanted_len {
        Ok(())
    } else {
        Err(ParseError::BadLength(MismatchError {
            location: c"Udp.length",
            expected: wanted_len as u64,
            actual: pkt.length() as u64,
        }))
    }
}

impl<V: ByteSlice> ValidUlp<V> {
    #[inline]
    fn validate(&self, bytes_after: usize) -> Result<(), ParseError> {
        match self {
            ValidUlp::Udp(u) => validate_udp(u, bytes_after),
            _ => Ok(()),
        }
    }
}

impl<T: ByteSlice> From<ValidGeneveOverV6<T>> for OpteMeta<T> {
    #[inline]
    fn from(value: ValidGeneveOverV6<T>) -> Self {
        OpteMeta {
            outer_eth: Some(value.outer_eth.into()),
            outer_l3: Some(L3::Ipv6(value.outer_v6.into())),
            outer_encap: Some(InlineHeader::Raw(ValidEncapMeta::Geneve(
                value.outer_udp,
                value.outer_encap,
            ))),
            inner_eth: value.inner_eth.into(),
            inner_l3: Some(value.inner_l3.into()),
            inner_ulp: Some(value.inner_ulp.into()),
        }
    }
}

impl<V: ByteSliceMut> LightweightMeta<V> for ValidGeneveOverV6<V> {
    #[inline]
    fn flow(&self) -> InnerFlowId {
        flow_id(Some(&self.inner_l3), Some(&self.inner_ulp))
    }

    #[inline]
    fn run_compiled_transform(&mut self, transform: &CompiledTransform)
    where
        V: ByteSliceMut,
    {
        transform.transform_ether(&mut self.inner_eth);
        transform.transform_l3(&mut self.inner_l3);
        transform.transform_ulp(&mut self.inner_ulp);
    }

    #[inline]
    fn compute_body_csum(&self) -> Option<Checksum> {
        let use_pseudo = !matches!(self.inner_ulp, ValidUlp::IcmpV4(_));

        let pseudo_csum = match self.inner_eth.ethertype() {
            Ethertype::IPV4 | Ethertype::IPV6 => {
                Some(self.inner_l3.pseudo_header())
            }
            // Includes ARP.
            _ => return None,
        };

        let pseudo_csum = pseudo_csum?;

        csum_minus_hdr(&self.inner_ulp).map(|mut v| {
            if use_pseudo {
                v -= pseudo_csum;
            }
            v
        })
    }

    #[inline]
    fn encap_len(&self) -> u16 {
        (self.outer_eth.packet_length()
            + self.outer_v6.packet_length()
            + self.outer_udp.packet_length()
            + self.outer_encap.packet_length()) as u16
    }

    #[inline]
    fn update_inner_checksums(&mut self, body_csum: Option<Checksum>) {
        if let Some(body_csum) = body_csum {
            if self.inner_ulp.has_ulp_csum() {
                self.inner_ulp.compute_checksum(body_csum, &self.inner_l3);
            }
        }
        if self.inner_l3.has_ip_csum() {
            self.inner_l3.compute_checksum();
        }
    }

    #[inline]
    fn inner_tcp(&self) -> Option<&impl TcpRef<V>> {
        match &self.inner_ulp {
            ValidUlp::Tcp(t) => Some(t),
            _ => None,
        }
    }

    #[inline]
    fn validate(&self, pkt_len: usize) -> Result<(), ParseError> {
        // Outer layers.
        let rem_len =
            pkt_len - (&self.outer_eth, &self.outer_v6).packet_length();
        self.outer_v6.validate(rem_len)?;

        let rem_len = rem_len - self.outer_udp.packet_length();
        validate_udp(&self.outer_udp, rem_len)?;

        validate_geneve(&self.outer_encap)?;

        // Inner layers.
        let rem_len = rem_len
            - (&self.outer_encap, &self.outer_eth, &self.inner_l3)
                .packet_length();
        self.inner_l3.validate(rem_len)?;

        let rem_len = rem_len - self.inner_ulp.packet_length();
        self.inner_ulp.validate(rem_len)?;

        Ok(())
    }
}

#[inline]
fn csum_minus_hdr<V: ByteSlice>(ulp: &ValidUlp<V>) -> Option<Checksum> {
    match ulp {
        ValidUlp::IcmpV4(icmp) => {
            if icmp.checksum() == 0 {
                return None;
            }

            let mut csum = Checksum::from(HeaderChecksum::wrap(
                icmp.checksum().to_be_bytes(),
            ));

            csum.sub_bytes(&[icmp.ty().0, icmp.code()]);
            csum.sub_bytes(icmp.rest_of_hdr_ref());

            Some(csum)
        }
        ValidUlp::IcmpV6(icmp) => {
            if icmp.checksum() == 0 {
                return None;
            }

            let mut csum = Checksum::from(HeaderChecksum::wrap(
                icmp.checksum().to_be_bytes(),
            ));

            csum.sub_bytes(&[icmp.ty().0, icmp.code()]);
            csum.sub_bytes(icmp.rest_of_hdr_ref());

            Some(csum)
        }
        ValidUlp::Tcp(tcp) => {
            if tcp.checksum() == 0 {
                return None;
            }

            let mut csum = Checksum::from(HeaderChecksum::wrap(
                tcp.checksum().to_be_bytes(),
            ));

            let b = tcp.0.as_bytes();

            csum.sub_bytes(&b[0..16]);
            csum.sub_bytes(&b[18..]);

            csum.sub_bytes(match &tcp.1 {
                ingot::types::Header::Repr(v) => &v[..],
                ingot::types::Header::Raw(v) => &v[..],
            });

            Some(csum)
        }
        ValidUlp::Udp(udp) => {
            if udp.checksum() == 0 {
                return None;
            }

            let mut csum = Checksum::from(HeaderChecksum::wrap(
                udp.checksum().to_be_bytes(),
            ));

            let b = udp.0.as_bytes();
            csum.sub_bytes(&b[0..6]);

            Some(csum)
        }
    }
}

impl<V: ByteSlice> Ulp<V> {
    #[inline]
    pub fn true_src_port(&self) -> Option<u16> {
        match self {
            Ulp::Tcp(pkt) => Some(pkt.source()),
            Ulp::Udp(pkt) => Some(pkt.source()),
            _ => None,
        }
    }

    #[inline]
    pub fn true_dst_port(&self) -> Option<u16> {
        match self {
            Ulp::Tcp(pkt) => Some(pkt.destination()),
            Ulp::Udp(pkt) => Some(pkt.destination()),
            _ => None,
        }
    }

    #[inline]
    pub fn pseudo_port(&self) -> Option<u16> {
        match self {
            Ulp::IcmpV4(pkt) => pkt.echo_id(),
            Ulp::IcmpV6(pkt) => pkt.echo_id(),
            _ => None,
        }
    }
}

impl<V: ByteSlice> ValidUlp<V> {
    #[inline]
    pub fn true_src_port(&self) -> Option<u16> {
        match self {
            ValidUlp::Tcp(pkt) => Some(pkt.source()),
            ValidUlp::Udp(pkt) => Some(pkt.source()),
            _ => None,
        }
    }

    #[inline]
    pub fn true_dst_port(&self) -> Option<u16> {
        match self {
            ValidUlp::Tcp(pkt) => Some(pkt.destination()),
            ValidUlp::Udp(pkt) => Some(pkt.destination()),
            _ => None,
        }
    }

    #[inline]
    pub fn pseudo_port(&self) -> Option<u16> {
        match self {
            ValidUlp::IcmpV4(pkt) => pkt.echo_id(),
            ValidUlp::IcmpV6(pkt) => pkt.echo_id(),
            _ => None,
        }
    }
}

impl<T: ByteSlice> HasInnerCksum for Ulp<T> {
    const HAS_CKSUM: bool = true;
}

impl<T: ByteSliceMut> HeaderActionModify<UlpMetaModify> for Ulp<T> {
    #[inline]
    fn run_modify(
        &mut self,
        mod_spec: &UlpMetaModify,
    ) -> Result<(), HeaderActionError> {
        match self {
            Ulp::Tcp(t) => {
                if let Some(src) = mod_spec.generic.src_port {
                    t.set_source(src);
                }
                if let Some(dst) = mod_spec.generic.dst_port {
                    t.set_destination(dst);
                }
                if let Some(flags) = mod_spec.tcp_flags {
                    t.set_flags(TcpFlags::from_bits_retain(flags));
                }
            }
            Ulp::Udp(u) => {
                if let Some(src) = mod_spec.generic.src_port {
                    u.set_source(src);
                }
                if let Some(dst) = mod_spec.generic.dst_port {
                    u.set_destination(dst);
                }
            }
            Ulp::IcmpV4(i4) => {
                if let Some(id) = mod_spec.icmp_id {
                    if i4.echo_id().is_some() {
                        let roh = i4.rest_of_hdr_mut();
                        ValidIcmpEcho::parse(&mut roh[..])
                            .expect(
                                "ICMP ROH is exactly as large as ValidIcmpEcho",
                            )
                            .0
                            .set_id(id);
                    }
                }
            }
            Ulp::IcmpV6(i6) => {
                if let Some(id) = mod_spec.icmp_id {
                    if i6.echo_id().is_some() {
                        let roh = i6.rest_of_hdr_mut();
                        ValidIcmpEcho::parse(&mut roh[..])
                            .expect(
                                "ICMP ROH is exactly as large as ValidIcmpEcho",
                            )
                            .0
                            .set_id(id);
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::engine::checksum::Checksum as OpteCsum;
    use ingot::types::HeaderParse;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::Icmpv4Packet;
    use smoltcp::wire::Icmpv4Repr;

    use super::*;

    #[test]
    fn icmp4_body_csum_equals_body() {
        let data = b"reunion\0";
        let mut body_csum = OpteCsum::default();
        body_csum.add_bytes(data);

        let mut cksum_cfg = ChecksumCapabilities::ignored();
        cksum_cfg.icmpv4 = smoltcp::phy::Checksum::Both;

        let test_pkt = Icmpv4Repr::EchoRequest { ident: 7, seq_no: 7777, data };
        let mut out = vec![0u8; test_pkt.buffer_len()];
        let mut packet = Icmpv4Packet::new_unchecked(&mut out);
        test_pkt.emit(&mut packet, &cksum_cfg);

        let src = &mut out[..IcmpV4::MINIMUM_LENGTH];
        let (ulp, ..) =
            ValidUlp::parse_choice(src, Some(IpProtocol::ICMP)).unwrap();

        assert_eq!(
            Some(body_csum.finalize()),
            csum_minus_hdr(&ulp).map(|mut v| v.finalize()),
        );
    }
}

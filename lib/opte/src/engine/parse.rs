// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Constructs used in packet parsing, such as choices over protocol
//! and complete packet definitions.

use super::checksum::Checksum;
use super::checksum::HeaderChecksum;
use super::ether::EthernetMut;
use super::ether::EthernetPacket;
use super::ether::EthernetRef;
use super::ether::ValidEthernet;
use super::geneve::GENEVE_PORT;
use super::headers::IpMod;
use super::ingot_packet::OpteMeta;
use super::ingot_packet::ValidEncapMeta;
use super::ip::v4::Ipv4Mut;
use super::ip::v4::Ipv4Ref;
use super::ip::v6::Ipv6Mut;
use super::ip::v6::Ipv6Packet;
use super::ip::v6::Ipv6Ref;
use super::ip::ValidL3;
use super::ip::L3;
use super::packet::AddrPair;
use super::packet::InnerFlowId;
use super::packet::MismatchError;
use super::packet::ParseError;
use super::packet::FLOW_ID_DEFAULT;
use super::rule::CompiledTransform;
use super::LightweightMeta;
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
use ingot::types::InlineHeader;
use ingot::types::NextLayer;
use ingot::types::ParseControl;
use ingot::udp::Udp;
use ingot::udp::UdpMut;
use ingot::udp::UdpPacket;
use ingot::udp::UdpRef;
use ingot::udp::ValidUdp;
use ingot::Parse;
use zerocopy::ByteSliceMut;
use zerocopy::IntoBytes;

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

impl<B: ByteSlice> ValidUlp<B> {
    pub fn csum(&self) -> [u8; 2] {
        match self {
            ValidUlp::Tcp(t) => t.checksum(),
            ValidUlp::Udp(u) => u.checksum(),
            ValidUlp::IcmpV4(i4) => i4.checksum(),
            ValidUlp::IcmpV6(i6) => i6.checksum(),
        }
        .to_be_bytes()
    }
}

impl<B: ByteSliceMut> ValidUlp<B> {
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
                        body_csum.add_bytes(&*opts);
                    }
                    Header::Raw(opts) => {
                        body_csum.add_bytes(&*opts);
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

#[derive(Parse)]
pub struct NoEncap<Q: ByteSlice> {
    #[ingot(control = exit_on_arp)]
    pub inner_eth: EthernetPacket<Q>,
    pub inner_l3: Option<L3<Q>>,
    pub inner_ulp: Option<Ulp<Q>>,
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
        let (proto, addrs) = match &self.inner_l3 {
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

        let (src_port, dst_port) = self
            .inner_ulp
            .as_ref()
            .map(|ulp| {
                (
                    ulp.true_src_port()
                        .or_else(|| ulp.pseudo_port())
                        .unwrap_or(0),
                    ulp.true_dst_port()
                        .or_else(|| ulp.pseudo_port())
                        .unwrap_or(0),
                )
            })
            .unwrap_or((0, 0));

        InnerFlowId { proto: proto.into(), addrs, src_port, dst_port }
    }

    #[inline]
    fn run_compiled_transform(&mut self, transform: &CompiledTransform)
    where
        V: ByteSliceMut,
    {
        // TODO: break out commonalities for this and geneve.
        if let Some(ether_tx) = &transform.inner_ether {
            if let Some(new_src) = &ether_tx.src {
                self.inner_eth.set_source(*new_src);
            }
            if let Some(new_dst) = &ether_tx.dst {
                self.inner_eth.set_destination(*new_dst);
            }
        }
        match (&mut self.inner_l3, &transform.inner_ip) {
            (Some(ValidL3::Ipv4(pkt)), Some(IpMod::Ip4(tx))) => {
                if let Some(new_src) = &tx.src {
                    pkt.set_source(*new_src);
                }
                if let Some(new_dst) = &tx.dst {
                    pkt.set_destination(*new_dst);
                }
                if let Some(new_proto) = &tx.proto {
                    pkt.set_protocol(IpProtocol(u8::from(*new_proto)));
                }
            }
            (Some(ValidL3::Ipv6(pkt)), Some(IpMod::Ip6(tx))) => {
                if let Some(new_src) = &tx.src {
                    pkt.set_source(*new_src);
                }
                if let Some(new_dst) = &tx.dst {
                    pkt.set_destination(*new_dst);
                }
                if let Some(new_proto) = &tx.proto {
                    // TODO: wrong in the face of EHs...
                    // For now, we never use this on our dataplane.
                    pkt.set_next_header(IpProtocol(u8::from(*new_proto)));
                }
            }
            _ => {}
        }

        match (&mut self.inner_ulp, &transform.inner_ulp) {
            (Some(ValidUlp::Tcp(pkt)), Some(tx)) => {
                if let Some(flags) = tx.tcp_flags {
                    pkt.set_flags(TcpFlags::from_bits_retain(flags));
                }

                if let Some(new_src) = &tx.generic.src_port {
                    pkt.set_source(*new_src);
                }

                if let Some(new_dst) = &tx.generic.dst_port {
                    pkt.set_destination(*new_dst);
                }
            }
            (Some(ValidUlp::Udp(pkt)), Some(tx)) => {
                if let Some(new_src) = &tx.generic.src_port {
                    pkt.set_source(*new_src);
                }

                if let Some(new_dst) = &tx.generic.dst_port {
                    pkt.set_destination(*new_dst);
                }
            }
            (Some(ValidUlp::IcmpV4(pkt)), Some(tx))
                if pkt.ty() == 0 || pkt.ty() == 8 =>
            {
                if let Some(new_id) = tx.icmp_id {
                    pkt.rest_of_hdr_mut()[..2]
                        .copy_from_slice(&new_id.to_be_bytes())
                }
            }
            (Some(ValidUlp::IcmpV6(pkt)), Some(tx))
                if pkt.ty() == 128 || pkt.ty() == 129 =>
            {
                if let Some(new_id) = tx.icmp_id {
                    pkt.rest_of_hdr_mut()[..2]
                        .copy_from_slice(&new_id.to_be_bytes())
                }
            }
            _ => {}
        }
    }

    // FIXME: identical to Geneve.
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

        let Some(pseudo_csum) = pseudo_csum else {
            return None;
        };

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
    fn update_inner_checksums(&mut self, body_csum: Checksum) {
        if let Some(l3) = self.inner_l3.as_mut() {
            if let Some(ulp) = self.inner_ulp.as_mut() {
                ulp.compute_checksum(body_csum, l3);
            }
            l3.compute_checksum();
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
            let rem_len = pkt_len - &(&self.inner_eth, l3).packet_length();
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
    let wanted_len = bytes_after + pkt.packet_length();
    if pkt.length() as usize == wanted_len {
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
        let (proto, addrs) = match &self.inner_l3 {
            ValidL3::Ipv4(pkt) => (
                pkt.protocol().0,
                AddrPair::V4 { src: pkt.source(), dst: pkt.destination() },
            ),
            ValidL3::Ipv6(pkt) => (
                pkt.next_layer().unwrap_or_default().0,
                AddrPair::V6 { src: pkt.source(), dst: pkt.destination() },
            ),
        };

        let src_port = self
            .inner_ulp
            .true_src_port()
            .or_else(|| self.inner_ulp.pseudo_port())
            .unwrap_or(0);

        let dst_port = self
            .inner_ulp
            .true_dst_port()
            .or_else(|| self.inner_ulp.pseudo_port())
            .unwrap_or(0);

        InnerFlowId { proto: proto.into(), addrs, src_port, dst_port }
    }

    #[inline]
    fn run_compiled_transform(&mut self, transform: &CompiledTransform)
    where
        V: ByteSliceMut,
    {
        // TODO: break out commonalities for this and geneve.
        if let Some(ether_tx) = &transform.inner_ether {
            if let Some(new_src) = &ether_tx.src {
                self.inner_eth.set_source(*new_src);
            }
            if let Some(new_dst) = &ether_tx.dst {
                self.inner_eth.set_destination(*new_dst);
            }
        }
        match (&mut self.inner_l3, &transform.inner_ip) {
            (ValidL3::Ipv4(pkt), Some(IpMod::Ip4(tx))) => {
                if let Some(new_src) = &tx.src {
                    pkt.set_source(*new_src);
                }
                if let Some(new_dst) = &tx.dst {
                    pkt.set_destination(*new_dst);
                }
                if let Some(new_proto) = &tx.proto {
                    pkt.set_protocol(IpProtocol(u8::from(*new_proto)));
                }
            }
            (ValidL3::Ipv6(pkt), Some(IpMod::Ip6(tx))) => {
                if let Some(new_src) = &tx.src {
                    pkt.set_source(*new_src);
                }
                if let Some(new_dst) = &tx.dst {
                    pkt.set_destination(*new_dst);
                }
                if let Some(new_proto) = &tx.proto {
                    // TODO: wrong in the face of EHs...
                    // For now, we never use this on our dataplane.
                    pkt.set_next_header(IpProtocol(u8::from(*new_proto)));
                }
            }
            _ => {}
        }

        match (&mut self.inner_ulp, &transform.inner_ulp) {
            (ValidUlp::Tcp(pkt), Some(tx)) => {
                if let Some(flags) = tx.tcp_flags {
                    pkt.set_flags(TcpFlags::from_bits_retain(flags));
                }

                if let Some(new_src) = &tx.generic.src_port {
                    pkt.set_source(*new_src);
                }

                if let Some(new_dst) = &tx.generic.dst_port {
                    pkt.set_destination(*new_dst);
                }
            }
            (ValidUlp::Udp(pkt), Some(tx)) => {
                if let Some(new_src) = &tx.generic.src_port {
                    pkt.set_source(*new_src);
                }

                if let Some(new_dst) = &tx.generic.dst_port {
                    pkt.set_destination(*new_dst);
                }
            }
            (ValidUlp::IcmpV4(pkt), Some(tx))
                if pkt.ty() == 0 || pkt.ty() == 8 =>
            {
                if let Some(new_id) = tx.icmp_id {
                    pkt.rest_of_hdr_mut()[..2]
                        .copy_from_slice(&new_id.to_be_bytes())
                }
            }
            (ValidUlp::IcmpV6(pkt), Some(tx))
                if pkt.ty() == 128 || pkt.ty() == 129 =>
            {
                if let Some(new_id) = tx.icmp_id {
                    pkt.rest_of_hdr_mut()[..2]
                        .copy_from_slice(&new_id.to_be_bytes())
                }
            }
            _ => {}
        }
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

        let Some(pseudo_csum) = pseudo_csum else {
            return None;
        };

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
    fn update_inner_checksums(&mut self, body_csum: Checksum) {
        self.inner_ulp.compute_checksum(body_csum, &self.inner_l3);
        self.inner_l3.compute_checksum();
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
        let rem_len =
            pkt_len - (&self.outer_eth, &self.outer_v6).packet_length();
        self.outer_v6.validate(rem_len)?;

        let rem_len = rem_len - self.outer_udp.packet_length();
        validate_udp(&self.outer_udp, rem_len)?;

        let rem_len = rem_len
            - &(&self.outer_encap, &self.outer_eth, &self.inner_l3)
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

            csum.sub_bytes(&[icmp.ty(), icmp.code()]);
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

            csum.sub_bytes(&[icmp.ty(), icmp.code()]);
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
            Ulp::IcmpV4(pkt)
                if pkt.code() == 0 && (pkt.ty() == 0 || pkt.ty() == 8) =>
            {
                Some(u16::from_be_bytes(
                    pkt.rest_of_hdr()[..2].try_into().unwrap(),
                ))
            }
            Ulp::IcmpV6(pkt)
                if pkt.code() == 0 && (pkt.ty() == 128 || pkt.ty() == 129) =>
            {
                Some(u16::from_be_bytes(
                    pkt.rest_of_hdr()[..2].try_into().unwrap(),
                ))
            }
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
            ValidUlp::IcmpV4(pkt)
                if pkt.code() == 0 && (pkt.ty() == 0 || pkt.ty() == 8) =>
            {
                Some(u16::from_be_bytes(
                    pkt.rest_of_hdr()[..2].try_into().unwrap(),
                ))
            }
            ValidUlp::IcmpV6(pkt)
                if pkt.code() == 0 && (pkt.ty() == 128 || pkt.ty() == 129) =>
            {
                Some(u16::from_be_bytes(
                    pkt.rest_of_hdr()[..2].try_into().unwrap(),
                ))
            }
            _ => None,
        }
    }
}

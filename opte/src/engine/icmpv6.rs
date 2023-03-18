// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Internet Control Message Protocol version 6

use super::checksum::Checksum;
use super::checksum::HeaderChecksum;
use super::ether::EtherHdr;
use super::ether::EtherMeta;
use super::ether::EtherType;
use super::headers::RawHeader;
use super::ip6::Ipv6Hdr;
use super::ip6::Ipv6Meta;
use super::packet::Packet;
use super::packet::PacketMeta;
use super::packet::PacketRead;
use super::packet::PacketReadMut;
use super::packet::PacketReader;
use super::packet::ReadErr;
use super::predicate::DataPredicate;
use super::predicate::EtherAddrMatch;
use super::predicate::IpProtoMatch;
use super::predicate::Ipv6AddrMatch;
use super::predicate::Predicate;
use super::rule::AllowOrDeny;
use super::rule::GenErr;
use super::rule::GenPacketResult;
use super::rule::HairpinAction;
use core::fmt;
use core::fmt::Display;
pub use opte_api::ip::Icmpv6EchoReply;
pub use opte_api::ip::Ipv6Addr;
pub use opte_api::ip::Ipv6Cidr;
pub use opte_api::ip::Protocol;
use opte_api::mac::MacAddr;
pub use opte_api::ndp::NeighborAdvertisement;
pub use opte_api::ndp::RouterAdvertisement;
use serde::Deserialize;
use serde::Serialize;
use smoltcp::phy::ChecksumCapabilities as Csum;
use smoltcp::wire::Icmpv6Message;
use smoltcp::wire::Icmpv6Packet;
use smoltcp::wire::Icmpv6Repr;
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv6Address;
use smoltcp::wire::NdiscNeighborFlags;
use smoltcp::wire::NdiscRepr;
use smoltcp::wire::RawHardwareAddress;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::LayoutVerified;
use zerocopy::Unaligned;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::vec::Vec;
        use alloc::string::String;
    } else {
        use std::vec::Vec;
        use std::string::String;
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Icmpv6Meta {
    pub msg_type: u8,
    pub msg_code: u8,
    pub csum: [u8; 2],
}

impl Icmpv6Meta {
    // This assumes the dst is large enough.
    #[inline]
    pub fn emit(&self, dst: &mut [u8]) {
        debug_assert!(dst.len() >= Icmpv6Hdr::SIZE);
        dst[0] = self.msg_type;
        dst[1] = self.msg_code;
        dst[2..4].copy_from_slice(&self.csum);
    }

    #[inline]
    pub fn hdr_len(&self) -> usize {
        Icmpv6Hdr::SIZE
    }
}

impl<'a> From<&Icmpv6Hdr<'a>> for Icmpv6Meta {
    fn from(hdr: &Icmpv6Hdr<'a>) -> Self {
        Self {
            msg_type: hdr.base.msg_type,
            msg_code: hdr.base.msg_code,
            csum: hdr.base.csum,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Icmpv6HdrError {
    ReadError { error: ReadErr },
}

impl From<ReadErr> for Icmpv6HdrError {
    fn from(error: ReadErr) -> Self {
        Icmpv6HdrError::ReadError { error }
    }
}

#[derive(Debug)]
pub struct Icmpv6Hdr<'a> {
    base: LayoutVerified<&'a mut [u8], Icmpv6HdrRaw>,
}

impl<'a> Icmpv6Hdr<'a> {
    pub const SIZE: usize = Icmpv6HdrRaw::SIZE;

    /// Offset to the start of the ICMPv6 checksum field.
    pub const CSUM_BEGIN_OFFSET: usize = 2;

    /// Offset to the end of the ICMPv6 checksum field.
    pub const CSUM_END_OFFSET: usize = 4;

    pub fn csum_minus_hdr(&self) -> Option<Checksum> {
        if self.base.csum != [0; 2] {
            let mut csum = Checksum::from(HeaderChecksum::wrap(self.base.csum));
            csum.sub_bytes(&self.base.bytes()[0..Self::CSUM_BEGIN_OFFSET]);
            Some(csum)
        } else {
            None
        }
    }

    /// Return the header length, in bytes.
    pub fn hdr_len(&self) -> usize {
        Self::SIZE
    }

    pub fn parse<'b>(
        rdr: &'b mut impl PacketReadMut<'a>,
    ) -> Result<Self, Icmpv6HdrError> {
        let src = rdr.slice_mut(Icmpv6Hdr::SIZE)?;
        let icmp6 = Self { base: Icmpv6HdrRaw::new_mut(src)? };
        Ok(icmp6)
    }
}

/// Note: For now we keep this unaligned to be safe.
#[repr(C)]
#[derive(Clone, Debug, FromBytes, AsBytes, Unaligned)]
pub struct Icmpv6HdrRaw {
    pub msg_type: u8,
    pub msg_code: u8,
    pub csum: [u8; 2],
}

impl Icmpv6HdrRaw {
    /// An ICMPv6 header is always 4 bytes.
    pub const SIZE: usize = 4;
}

impl<'a> RawHeader<'a> for Icmpv6HdrRaw {
    #[inline]
    fn new_mut(
        src: &mut [u8],
    ) -> Result<LayoutVerified<&mut [u8], Self>, ReadErr> {
        debug_assert_eq!(src.len(), Self::SIZE);
        let hdr = match LayoutVerified::new(src) {
            Some(hdr) => hdr,
            None => return Err(ReadErr::BadLayout),
        };
        Ok(hdr)
    }
}

/// An ICMPv6 message type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(from = "u8", into = "u8")]
pub struct MessageType {
    inner: Icmpv6Message,
}

impl From<Icmpv6Message> for MessageType {
    fn from(inner: Icmpv6Message) -> MessageType {
        MessageType { inner }
    }
}

impl From<MessageType> for Icmpv6Message {
    fn from(mt: MessageType) -> Self {
        mt.inner
    }
}

impl From<MessageType> for u8 {
    fn from(mt: MessageType) -> u8 {
        u8::from(mt.inner)
    }
}

impl From<u8> for MessageType {
    fn from(val: u8) -> Self {
        Self { inner: Icmpv6Message::from(val) }
    }
}

impl Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl HairpinAction for Icmpv6EchoReply {
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        let hdr_preds = vec![
            Predicate::InnerEtherSrc(vec![EtherAddrMatch::Exact(
                self.src_mac.into(),
            )]),
            Predicate::InnerEtherDst(vec![EtherAddrMatch::Exact(
                self.dst_mac.into(),
            )]),
            Predicate::InnerSrcIp6(vec![Ipv6AddrMatch::Exact(self.src_ip)]),
            Predicate::InnerDstIp6(vec![Ipv6AddrMatch::Exact(self.dst_ip)]),
            Predicate::InnerIpProto(vec![IpProtoMatch::Exact(
                Protocol::ICMPv6,
            )]),
        ];

        let data_preds = vec![DataPredicate::Icmpv6MsgType(MessageType::from(
            Icmpv6Message::EchoRequest,
        ))];

        (hdr_preds, data_preds)
    }

    fn gen_packet(
        &self,
        meta: &PacketMeta,
        rdr: &mut PacketReader,
    ) -> GenPacketResult {
        use smoltcp::phy::Checksum;

        // Collect the src / dst IP addresses, which are needed to emit the
        // resulting ICMPv6 echo reply.
        let (src_ip, dst_ip) = if let Some(metadata) = meta.inner_ip6() {
            (
                IpAddress::Ipv6(Ipv6Address(metadata.src.bytes())),
                IpAddress::Ipv6(Ipv6Address(metadata.dst.bytes())),
            )
        } else {
            // Getting here implies the predicate matched, but that the
            // extracted metadata indicates this isn't an IPv6 packet. That
            // should be impossible, but we avoid panicking given the kernel
            // context.
            return Err(GenErr::Unexpected(format!(
                "Expected IPv6 packet metadata, but found: {:?}",
                meta
            )));
        };
        let body = rdr.copy_remaining();
        let src_pkt = Icmpv6Packet::new_checked(&body)?;
        let src_icmp =
            Icmpv6Repr::parse(&src_ip, &dst_ip, &src_pkt, &Csum::ignored())?;

        let (src_ident, src_seq_no, src_data) = match src_icmp {
            Icmpv6Repr::EchoRequest { ident, seq_no, data } => {
                (ident, seq_no, data)
            }

            _ => {
                // We should never hit this case because the predicate
                // should have verified that we are dealing with an
                // Echo Request. However, programming error could
                // cause this to happen -- let's not take any chances.
                return Err(GenErr::Unexpected(format!(
                    "expected an ICMPv6 Echo Request, got {} {}",
                    src_pkt.msg_type(),
                    src_pkt.msg_code()
                )));
            }
        };

        let reply = Icmpv6Repr::EchoReply {
            ident: src_ident,
            seq_no: src_seq_no,
            data: src_data,
        };

        let reply_len = reply.buffer_len();
        let mut ulp_body = vec![0u8; reply_len];
        let mut icmp_reply = Icmpv6Packet::new_unchecked(&mut ulp_body);
        let mut csum = Csum::ignored();
        csum.icmpv6 = Checksum::Tx;
        reply.emit(&dst_ip, &src_ip, &mut icmp_reply, &csum);

        let ip = Ipv6Meta {
            src: self.dst_ip,
            dst: self.src_ip,
            proto: Protocol::ICMPv6,
            next_hdr: IpProtocol::Icmpv6,
            // There are no extension headers. The ULP is the only
            // content.
            pay_len: reply_len as u16,
            ..Default::default()
        };

        let eth = EtherMeta {
            ether_type: EtherType::Ipv6,
            dst: self.src_mac,
            src: self.dst_mac,
        };

        let total_len = EtherHdr::SIZE + Ipv6Hdr::BASE_SIZE + reply_len;
        let mut pkt = Packet::alloc_and_expand(total_len);
        let mut wtr = pkt.seg0_wtr();
        eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
        ip.emit(wtr.slice_mut(ip.hdr_len()).unwrap());
        wtr.write(&ulp_body).unwrap();
        Ok(AllowOrDeny::Allow(pkt))
    }
}

impl HairpinAction for RouterAdvertisement {
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        const ALL_ROUTERS_MAC: MacAddr =
            Ipv6Addr::ALL_ROUTERS.unchecked_multicast_mac();
        let hdr_preds = vec![
            // We expect that the source MAC is the MAC provided to the client.
            Predicate::InnerEtherSrc(vec![EtherAddrMatch::Exact(
                self.src_mac.into(),
            )]),
            // It's directed to the multicast MAC address derived from the
            // All-Routers multicast IPv6 address.
            Predicate::InnerEtherDst(vec![EtherAddrMatch::Exact(
                ALL_ROUTERS_MAC,
            )]),
            // The source IP must be a link-local IPv6 address. We make no
            // assumptions about its format otherwise.
            Predicate::InnerSrcIp6(vec![Ipv6AddrMatch::Prefix(
                Ipv6Cidr::LINK_LOCAL,
            )]),
            // And the packet must be directed to the All-Routers IPv6 multicast
            // address.
            Predicate::InnerDstIp6(vec![Ipv6AddrMatch::Exact(
                Ipv6Addr::ALL_ROUTERS,
            )]),
            // NDP runs over ICMPv6.
            Predicate::InnerIpProto(vec![IpProtoMatch::Exact(
                Protocol::ICMPv6,
            )]),
        ];

        let data_preds = vec![
            // This must be a Router Solicitation message.
            DataPredicate::Icmpv6MsgType(MessageType::from(
                Icmpv6Message::RouterSolicit,
            )),
        ];

        (hdr_preds, data_preds)
    }

    fn gen_packet(
        &self,
        meta: &PacketMeta,
        rdr: &mut PacketReader,
    ) -> GenPacketResult {
        use smoltcp::phy::Checksum;
        use smoltcp::time::Duration;
        use smoltcp::wire::NdiscRouterFlags;

        // Collect the src / dst IP addresses, which are needed to emit the
        // resulting ICMPv6 packet using `smoltcp`.
        let (src_ip, dst_ip) = if let Some(metadata) = meta.inner_ip6() {
            (
                IpAddress::Ipv6(Ipv6Address(metadata.src.bytes())),
                IpAddress::Ipv6(Ipv6Address(metadata.dst.bytes())),
            )
        } else {
            // Getting here implies the predicate matched, but that the
            // extracted metadata indicates this isn't an IPv6 packet. That
            // should be impossible, but we avoid panicking given the kernel
            // context.
            return Err(GenErr::Unexpected(format!(
                "Expected IPv6 packet metadata, but found: {:?}",
                meta
            )));
        };
        let body = rdr.copy_remaining();
        let src_pkt = Icmpv6Packet::new_checked(&body)?;
        let src_ndisc =
            Icmpv6Repr::parse(&src_ip, &dst_ip, &src_pkt, &Csum::ignored())?;

        if !matches!(
            src_ndisc,
            Icmpv6Repr::Ndisc(NdiscRepr::RouterSolicit { .. })
        ) {
            // We should never hit this case because the predicate
            // should have verified that we are dealing with an
            // Router Solicitation. However, programming error could
            // cause this to happen -- let's not take any chances.
            return Err(GenErr::Unexpected(format!(
                "expected a NDP Router Solicitation, got {} {}",
                src_pkt.msg_type(),
                src_pkt.msg_code()
            )));
        }

        // RFC 4861 6.1.1 describes a number of validation steps routers are
        // required to perform.
        if src_pkt.msg_code() != 0 {
            return Ok(AllowOrDeny::Deny);
        }
        if !src_pkt.verify_checksum(&src_ip, &dst_ip) {
            return Ok(AllowOrDeny::Deny);
        }
        // NOTE: The router is required to check that there is no Link-Layer
        // Address Option, if the solicitation is sent from the unspecified
        // address. However, from the associated predicates, we know that this
        // is only called if the source IPv6 address is a link-local address,
        // and thus _not_ UNSPEC, so we skip that checking here.
        //
        // TODO-completeness: Check IP Hop Limit and ICMP length / option length

        let flags = if self.managed_cfg {
            NdiscRouterFlags::MANAGED
        } else {
            NdiscRouterFlags::empty()
        };
        const MAX_ROUTER_ADV_LIFETIME: Duration = Duration::from_secs(9_000);
        const ZERO_DURATION: Duration = Duration::from_millis(0);
        let advert = NdiscRepr::RouterAdvert {
            hop_limit: u8::MAX,
            flags,
            // Use the maximum advertised lifetime as a default router.
            router_lifetime: MAX_ROUTER_ADV_LIFETIME,
            // Do not specify the reachable or retrans time. Clients will decide
            // that for themselves at this point.
            reachable_time: ZERO_DURATION,
            retrans_time: ZERO_DURATION,
            lladdr: Some(RawHardwareAddress::from_bytes(&self.mac)),
            // TODO-completeness: Don't hardcode this.
            //
            // See https://github.com/oxidecomputer/opte/issues/263.
            mtu: Some(1500),
            // Indicate that there are no addresses considered on-link, other
            // than the router's advertised link-local address. This will
            // require all traffic from the client to go through OPTE.
            prefix_info: None,
        };
        let reply = Icmpv6Repr::Ndisc(advert);

        let reply_len = reply.buffer_len();
        let mut ulp_body = vec![0u8; reply_len];
        let mut advert_reply = Icmpv6Packet::new_unchecked(&mut ulp_body);
        let mut csum = Csum::ignored();
        csum.icmpv6 = Checksum::Tx;
        reply.emit(
            &IpAddress::Ipv6((*self.ip()).into()),
            &src_ip,
            &mut advert_reply,
            &mut csum,
        );

        let ip = Ipv6Meta {
            src: *self.ip(),
            // Safety: We match on this being Some(_) above, so unwrap is safe.
            dst: meta.inner_ip6().unwrap().src,
            proto: Protocol::ICMPv6,
            next_hdr: IpProtocol::Icmpv6,
            // RFC 4861 7.1.2 requires that the hop limit be 255 in an RA.
            hop_limit: 255,
            // There are no extension headers; the ULP is the only
            // content.
            pay_len: reply_len as u16,
            ..Default::default()
        };

        // The Ethernet frame should come from OPTE's virtual gateway MAC, and
        // be destined for the client which sent us the packet.
        let eth = EtherMeta {
            ether_type: EtherType::Ipv6,
            dst: self.src_mac,
            src: self.mac,
        };

        let total_len = EtherHdr::SIZE + Ipv6Hdr::BASE_SIZE + reply_len;
        let mut pkt = Packet::alloc_and_expand(total_len);
        let mut wtr = pkt.seg0_wtr();
        eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
        ip.emit(wtr.slice_mut(ip.hdr_len()).unwrap());
        wtr.write(&ulp_body).unwrap();
        Ok(AllowOrDeny::Allow(pkt))
    }
}

// Check if an ICMPv6 message is a valid Neighbor Solicitation
//
// See https://www.rfc-editor.org/rfc/rfc4861.html#section-7.1.1 for details on
// the validations performed.
//
// Return the target address from the Neighbor Solicitation.
fn validate_neighbor_solicitation(
    rdr: &mut PacketReader,
    metadata: &Ipv6Meta,
) -> Result<Ipv6Addr, GenErr> {
    // First, check if this is in fact a NS message.
    let smol_src = IpAddress::Ipv6(metadata.src.into());
    let smol_dst = IpAddress::Ipv6(metadata.dst.into());
    let body = rdr.copy_remaining();
    let src_pkt = Icmpv6Packet::new_checked(&body)?;
    let icmp =
        Icmpv6Repr::parse(&smol_src, &smol_dst, &src_pkt, &Csum::ignored())?;

    let (target_addr, has_ll_option) = match icmp {
        Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
            lladdr,
            target_addr,
        }) => (Ipv6Addr::from(target_addr), lladdr.is_some()),
        _ => {
            // We should never hit this case because the predicate
            // should have verified that we are dealing with a
            // Neighbor Solicitation. However, programming error could
            // cause this to happen -- let's not take any chances.
            return Err(GenErr::Unexpected(format!(
                "expected a NDP Neighbor Solicitation, got {} {}",
                src_pkt.msg_type(),
                src_pkt.msg_code()
            )));
        }
    };

    // The target cannot be a multicast address.
    if target_addr.is_multicast() {
        return Err(GenErr::Unexpected(String::from(
            "Received NS with multicast target address.",
        )));
    }

    // NS is only allowed from the unspecified address if the destination is a
    // solicited-node multicast address.
    if metadata.src == Ipv6Addr::ANY_ADDR
        && !metadata.dst.is_solicited_node_multicast()
    {
        return Err(GenErr::Unexpected(String::from(
            "Received NS from UNSPEC, but destination is not the solicited \
            node multicast address.",
        )));
    }

    // Cannot contain Link-Layer address option if from the unspecified address.
    if metadata.src == Ipv6Addr::ANY_ADDR && has_ll_option {
        return Err(GenErr::Unexpected(String::from(
            "Received NS from UNSPEC, but message contains the \
            Link-Layer Address option.",
        )));
    }

    Ok(target_addr)
}

// Return the destination IP and a Neighbor Advertisement, based on the data
// provided in a Neighbor Solicitation. If we should not generate an NA in
// response to the NS, then `None` is returned.
//
// See https://www.rfc-editor.org/rfc/rfc4861.html#section-7.2.4 for details on
// the validation and construction performed here.
fn construct_neighbor_advert<'a>(
    na: &'a NeighborAdvertisement,
    target_addr: &'a Ipv6Addr,
    src_ip: &'a Ipv6Addr,
) -> Option<(Ipv6Addr, NdiscRepr<'a>)> {
    // Drop the packet if the target address is not actually our own address.
    if target_addr != na.ip() {
        return None;
    }

    // Set the ROUTER flag, if required.
    //
    // Note from RFC 4861 Section 7.2.4 paragraph 2, we start with the OVERRIDE
    // flag set. That says:
    //
    // > If the Target Address is either an anycast address or a unicast
    // > address for which the node is providing proxy service, or the Target
    // > Link-Layer Address option is not included, the Override flag SHOULD
    // > be set to zero.  Otherwise, the Override flag SHOULD be set to one.
    //
    // We're never proxying or supporting anycast addresses, and we're always
    // including the Link-Layer address option in the response. So we set
    // OVERRIDE to 1.
    let mut flags = NdiscNeighborFlags::OVERRIDE;
    flags.set(NdiscNeighborFlags::ROUTER, na.is_router);

    // Even though this is NA is in response to an NS, if the source IP is
    // UNSPEC, we must _not_ set the SOLICITED flag.
    let src_is_unspec = src_ip == &Ipv6Addr::ANY_ADDR;
    flags.set(NdiscNeighborFlags::SOLICITED, !src_is_unspec);

    // The destination IP address also depends on the source IP address.
    //
    // If the source is UNSPEC, we're required to send this to the all-nodes
    // multicast group. Otherwise, we must unicast the NA back to the source.
    let dst_ip = if src_is_unspec { Ipv6Addr::ALL_NODES } else { *src_ip };
    Some((
        dst_ip,
        NdiscRepr::NeighborAdvert {
            flags,
            target_addr: Ipv6Address::from(*target_addr),
            // Always include the Link-Layer address option.
            lladdr: Some(RawHardwareAddress::from_bytes(&na.mac)),
        },
    ))
}

impl HairpinAction for NeighborAdvertisement {
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        // The source IP must be a link-local IPv6 address, or, if
        // `allow_unspec` is true, the unspecified address.
        let source_addrs = if self.allow_unspec {
            vec![
                Ipv6AddrMatch::Prefix(Ipv6Cidr::LINK_LOCAL),
                Ipv6AddrMatch::Exact(Ipv6Addr::ANY_ADDR),
            ]
        } else {
            vec![Ipv6AddrMatch::Prefix(Ipv6Cidr::LINK_LOCAL)]
        };

        // There are a few MAC addresses we need to support:
        // - Unicast directly to us
        // - Multicast to the MAC derived from our solicited-node multicast
        // group
        let dest_macs = vec![
            EtherAddrMatch::Exact(self.mac),
            EtherAddrMatch::Exact(
                self.ip().solicited_node_multicast().multicast_mac().unwrap(),
            ),
        ];

        // The destination IP address must be either our unicast link-local
        // address, or its solicited-node multicast group.
        let dest_addrs = vec![
            Ipv6AddrMatch::Exact(*self.ip()),
            Ipv6AddrMatch::Exact(self.ip().solicited_node_multicast()),
        ];

        let hdr_preds = vec![
            // We expect that the source MAC is the MAC provided to the client.
            Predicate::InnerEtherSrc(vec![EtherAddrMatch::Exact(self.src_mac)]),
            Predicate::InnerEtherDst(dest_macs),
            Predicate::InnerSrcIp6(source_addrs),
            Predicate::InnerDstIp6(dest_addrs),
            // NDP runs over ICMPv6.
            Predicate::InnerIpProto(vec![IpProtoMatch::Exact(
                Protocol::ICMPv6,
            )]),
        ];

        let data_preds = vec![
            // This must be an actual Neighbor Solicitation message
            DataPredicate::Icmpv6MsgType(MessageType::from(
                Icmpv6Message::NeighborSolicit,
            )),
        ];

        (hdr_preds, data_preds)
    }

    fn gen_packet(
        &self,
        meta: &PacketMeta,
        rdr: &mut PacketReader,
    ) -> GenPacketResult {
        use smoltcp::phy::Checksum;

        // Sanity check that this is actually in IPv6 packet.
        let metadata = meta.inner_ip6().ok_or_else(|| {
            // Getting here implies the predicate matched, but that the
            // extracted metadata indicates this isn't an IPv6 packet. That
            // should be impossible, but we avoid panicking given the kernel
            // context.
            GenErr::Unexpected(format!(
                "Expected IPv6 packet metadata, but found: {:?}",
                meta
            ))
        })?;

        // Validate the ICMPv6 packet is actually a Neighbor Solicitation, and
        // that its data is appopriate.
        let target_addr = validate_neighbor_solicitation(rdr, metadata)?;

        // Build the NA, whose data depends on how we received the packet. If
        // `None` is returned, the NS is not destined for us, and will be
        // dropped.
        let (dst_ip, advert) = match construct_neighbor_advert(
            self,
            &target_addr,
            &metadata.src,
        ) {
            Some(data) => data,
            None => return Ok(AllowOrDeny::Deny),
        };

        // Construct the actual bytes of the reply packet, and return it.
        let reply = Icmpv6Repr::Ndisc(advert);
        let reply_len = reply.buffer_len();
        let mut ulp_body = vec![0u8; reply_len];
        let mut advert_reply = Icmpv6Packet::new_unchecked(&mut ulp_body);
        let mut csum = Csum::ignored();
        csum.icmpv6 = Checksum::Tx;
        reply.emit(
            &IpAddress::Ipv6((*self.ip()).into()),
            &IpAddress::Ipv6(dst_ip.into()),
            &mut advert_reply,
            &mut csum,
        );

        let ip = Ipv6Meta {
            src: *self.ip(),
            dst: dst_ip,
            proto: Protocol::ICMPv6,
            next_hdr: IpProtocol::Icmpv6,
            // There are no extension headers; the ULP is the only
            // content.
            pay_len: reply_len as u16,
            ..Default::default()
        };

        // While the frame must always be sent from the gateway, who the frame
        // is addressed to depends on whether we should multicast the packet.
        let dst_mac = dst_ip.multicast_mac().unwrap_or(self.src_mac);

        // The Ethernet frame should come from OPTE's virtual gateway MAC, and
        // be destined for the client which sent us the packet.
        let eth = EtherMeta {
            ether_type: EtherType::Ipv6,
            dst: dst_mac,
            src: self.mac,
        };

        let len = EtherHdr::SIZE + Ipv6Hdr::BASE_SIZE + reply_len;
        let mut pkt = Packet::alloc_and_expand(len);
        let mut wtr = pkt.seg0_wtr();
        eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
        ip.emit(wtr.slice_mut(ip.hdr_len()).unwrap());
        wtr.write(&ulp_body).unwrap();
        Ok(AllowOrDeny::Allow(pkt))
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! ICMPv6 headers and processing.

use super::*;
use crate::engine::ingot_base::Ethernet;
use crate::engine::ingot_base::Ipv6;
use crate::engine::ingot_base::Ipv6Ref;
use crate::engine::ingot_packet::MblkPacketData;
use crate::engine::ingot_packet::MsgBlk;
use crate::engine::predicate::Ipv6AddrMatch;
use alloc::string::String;
use ingot::ethernet::Ethertype;
use ingot::ip::IpProtocol as IngotIpProto;
use ingot::types::Emit;
pub use opte_api::ip::Icmpv6EchoReply;
pub use opte_api::ip::Ipv6Addr;
pub use opte_api::ip::Ipv6Cidr;
pub use opte_api::ip::Protocol;
use opte_api::mac::MacAddr;
pub use opte_api::ndp::NeighborAdvertisement;
pub use opte_api::ndp::RouterAdvertisement;
use smoltcp::wire::Icmpv6Message;
use smoltcp::wire::Icmpv6Packet;
use smoltcp::wire::Icmpv6Repr;
use smoltcp::wire::IpAddress;
use smoltcp::wire::Ipv6Address;
use smoltcp::wire::NdiscNeighborFlags;
use smoltcp::wire::NdiscRepr;
use smoltcp::wire::RawHardwareAddress;

/// An ICMPv6 message type
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(from = "u8", into = "u8")]
pub struct MessageType {
    inner: Icmpv6Message,
}

impl PartialOrd for MessageType {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MessageType {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        u8::from(*self).cmp(&u8::from(*other))
    }
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
            Predicate::InnerEtherSrc(vec![EtherAddrMatch::Exact(self.src_mac)]),
            Predicate::InnerEtherDst(vec![EtherAddrMatch::Exact(self.dst_mac)]),
            Predicate::InnerSrcIp6(vec![Ipv6AddrMatch::Exact(self.src_ip)]),
            Predicate::InnerDstIp6(vec![Ipv6AddrMatch::Exact(self.dst_ip)]),
            Predicate::InnerIpProto(vec![IpProtoMatch::Exact(
                Protocol::ICMPv6,
            )]),
        ];

        let data_preds = vec![DataPredicate::Icmpv6MsgType(
            MessageType::from(Icmpv6Message::EchoRequest).into(),
        )];

        (hdr_preds, data_preds)
    }

    fn gen_packet(&self, meta: &MblkPacketData) -> GenPacketResult {
        // TODO: fold reader access into PacketHeaders2
        let Some(icmp6) = meta.inner_icmp6() else {
            // Getting here implies the predicate matched, but that the
            // extracted metadata indicates this isn't an ICMPv6 packet. That
            // should be impossible, but we avoid panicking given the kernel
            // context.
            return Err(GenErr::Unexpected(format!(
                "Expected ICMPv6 packet metadata, but found: {:?}",
                meta
            )));
        };

        // Collect the src / dst IP addresses, which are needed to emit the
        // resulting ICMPv6 echo reply.
        let (src_ip, dst_ip) = if let Some(metadata) = meta.inner_ip6() {
            (
                IpAddress::Ipv6(Ipv6Address(metadata.source().bytes())),
                IpAddress::Ipv6(Ipv6Address(metadata.destination().bytes())),
            )
        } else {
            // We got the ICMPv6 metadata above but no IPv6 somehow?
            return Err(GenErr::Unexpected(format!(
                "Expected IPv6 packet metadata, but found: {:?}",
                meta
            )));
        };

        // `Icmpv6Packet` requires the ICMPv6 header and not just the message payload.
        // Given we successfully got the ICMPv6 metadata, rewinding here is fine.
        let mut body = icmp6.emit_vec();
        meta.append_remaining(&mut body);

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

        // TODO: less Vec

        let reply_len = reply.buffer_len();
        let mut ulp_body = vec![0u8; reply_len];
        let mut icmp_reply = Icmpv6Packet::new_unchecked(&mut ulp_body);
        let mut csum = Csum::ignored();
        csum.icmpv6 = Checksum::Tx;
        reply.emit(&dst_ip, &src_ip, &mut icmp_reply, &csum);

        let ip6 = Ipv6 {
            source: self.dst_ip,
            destination: self.src_ip,
            next_header: IngotIpProto::ICMP_V6,
            payload_len: reply_len as u16,
            ..Default::default()
        };

        let eth = Ethernet {
            destination: self.src_mac,
            source: self.dst_mac,
            ethertype: Ethertype::IPV6,
        };

        Ok(AllowOrDeny::Allow(MsgBlk::new_ethernet_pkt((
            &eth, &ip6, &ulp_body,
        ))))
    }
}

impl HairpinAction for RouterAdvertisement {
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        const ALL_ROUTERS_MAC: MacAddr =
            Ipv6Addr::ALL_ROUTERS.unchecked_multicast_mac();
        let hdr_preds = vec![
            // We expect that the source MAC is the MAC provided to the client.
            Predicate::InnerEtherSrc(vec![EtherAddrMatch::Exact(self.src_mac)]),
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
            DataPredicate::Icmpv6MsgType(
                MessageType::from(Icmpv6Message::RouterSolicit).into(),
            ),
        ];

        (hdr_preds, data_preds)
    }

    fn gen_packet(&self, meta: &MblkPacketData) -> GenPacketResult {
        // TODO: fold reader access into PacketHeaders2
        use smoltcp::time::Duration;
        use smoltcp::wire::NdiscRouterFlags;

        let Some(icmp6) = meta.inner_icmp6() else {
            // Getting here implies the predicate matched, but that the
            // extracted metadata indicates this isn't an ICMPv6 packet. That
            // should be impossible, but we avoid panicking given the kernel
            // context.
            return Err(GenErr::Unexpected(format!(
                "Expected ICMPv6 packet metadata, but found: {:?}",
                meta
            )));
        };

        // Collect the src / dst IP addresses, which are needed to emit the
        // resulting ICMPv6 packet using `smoltcp`.
        let Some(ip6) = meta.inner_ip6() else {
            // We got the ICMPv6 metadata above but no IPv6 somehow?
            return Err(GenErr::Unexpected(format!(
                "Expected IPv6 packet metadata, but found: {:?}",
                meta
            )));
        };
        let src_ip = IpAddress::Ipv6(Ipv6Address(ip6.source().bytes()));
        let dst_ip = IpAddress::Ipv6(Ipv6Address(ip6.destination().bytes()));

        // `Icmpv6Packet` requires the ICMPv6 header and not just the message payload.
        // Given we successfully got the ICMPv6 metadata, rewinding here is fine.
        let mut body = icmp6.emit_vec();
        meta.append_remaining(&mut body);

        let src_pkt = Icmpv6Packet::new_checked(&body)?;
        let mut csum = Csum::ignored();
        csum.icmpv6 = Checksum::Rx;
        let src_ndisc = Icmpv6Repr::parse(&src_ip, &dst_ip, &src_pkt, &csum)?;

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
        //
        // `Icmpv6Packet::new_checked` and `Icmpv6Repr::parse` above guarantee:
        //  - Checksum is valid
        //  - ICMP code is correct (0)
        //  - ICMP length is at least 8 octets
        //  - Any included options have a non-zero length
        //
        // NOTE: The router is required to check that there is no Link-Layer
        // Address Option, if the solicitation is sent from the unspecified
        // address. However, from the associated predicates, we know that this
        // is only called if the source IPv6 address is a link-local address,
        // and thus _not_ UNSPEC, so we skip that checking here.
        //
        // This leaves the hop limit as the only validity check.
        if ip6.hop_limit() != 255 {
            return Err(GenErr::Unexpected(format!(
                "Received RS with invalid hop limit ({}).",
                ip6.hop_limit()
            )));
        }

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
            &csum,
        );

        let ip6 = Ipv6 {
            source: *self.ip(),
            destination: meta.inner_ip6().unwrap().source(),
            next_header: IngotIpProto::ICMP_V6,
            payload_len: reply_len as u16,

            // RFC 4861 6.1.2 requires that the hop limit be 255 in an RA.
            hop_limit: 255,
            ..Default::default()
        };

        let eth = Ethernet {
            destination: self.src_mac,
            source: self.mac,
            ethertype: Ethertype::IPV6,
        };

        Ok(AllowOrDeny::Allow(MsgBlk::new_ethernet_pkt((
            &eth, &ip6, &ulp_body,
        ))))
    }
}

// Check if an ICMPv6 message is a valid Neighbor Solicitation
//
// See https://www.rfc-editor.org/rfc/rfc4861.html#section-7.1.1 for details on
// the validations performed.
//
// Return the target address from the Neighbor Solicitation.
fn validate_neighbor_solicitation<B: ByteSlice>(
    rdr: &[u8],
    metadata: &impl Ipv6Ref<B>,
) -> Result<Ipv6Addr, GenErr> {
    // First, check if this is in fact a NS message.
    let smol_src = IpAddress::Ipv6(Ipv6Address(metadata.source().bytes()));
    let smol_dst = IpAddress::Ipv6(Ipv6Address(metadata.destination().bytes()));
    let src_pkt = Icmpv6Packet::new_checked(rdr)?;
    let mut csum = Csum::ignored();
    csum.icmpv6 = Checksum::Rx;
    let icmp = Icmpv6Repr::parse(&smol_src, &smol_dst, &src_pkt, &csum)?;

    // `Icmpv6Packet::new_checked` and `Icmpv6Repr::parse` above guarantee:
    //  - Checksum is valid
    //  - ICMP code is correct (0)
    //  - ICMP length is at least 24 octets
    //  - Any included options have a non-zero length

    if metadata.hop_limit() != 255 {
        return Err(GenErr::Unexpected(format!(
            "Received NS with invalid hop limit ({}).",
            metadata.hop_limit()
        )));
    }

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
    if metadata.source() == Ipv6Addr::ANY_ADDR
        && !Ipv6Addr::from(metadata.destination()).is_solicited_node_multicast()
    {
        return Err(GenErr::Unexpected(String::from(
            "Received NS from UNSPEC, but destination is not the solicited \
            node multicast address.",
        )));
    }

    // Cannot contain Link-Layer address option if from the unspecified address.
    if metadata.source() == Ipv6Addr::ANY_ADDR && has_ll_option {
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
            DataPredicate::Icmpv6MsgType(
                MessageType::from(Icmpv6Message::NeighborSolicit).into(),
            ),
        ];

        (hdr_preds, data_preds)
    }

    fn gen_packet(&self, meta: &MblkPacketData) -> GenPacketResult {
        let Some(icmp6) = meta.inner_icmp6() else {
            // Getting here implies the predicate matched, but that the
            // extracted metadata indicates this isn't an ICMPv6 packet. That
            // should be impossible, but we avoid panicking given the kernel
            // context.
            return Err(GenErr::Unexpected(format!(
                "Expected ICMPv6 packet metadata, but found: {:?}",
                meta
            )));
        };

        // Sanity check that this is actually in IPv6 packet.
        let metadata = meta.inner_ip6().ok_or_else(|| {
            // We got the ICMPv6 metadata above but no IPv6 somehow?
            GenErr::Unexpected(format!(
                "Expected IPv6 packet metadata, but found: {:?}",
                meta
            ))
        })?;

        // `Icmpv6Packet` requires the ICMPv6 header and not just the message payload.
        // Given we successfully got the ICMPv6 metadata, rewinding here is fine.
        let mut body = icmp6.emit_vec();
        meta.append_remaining(&mut body);

        // Validate the ICMPv6 packet is actually a Neighbor Solicitation, and
        // that its data is appopriate.
        let target_addr = validate_neighbor_solicitation(&body, metadata)?;

        // Build the NA, whose data depends on how we received the packet. If
        // `None` is returned, the NS is not destined for us, and will be
        // dropped.
        let conv_ip = metadata.source().into();
        let (dst_ip, advert) =
            match construct_neighbor_advert(self, &target_addr, &conv_ip) {
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
            &csum,
        );

        // While the frame must always be sent from the gateway, who the frame
        // is addressed to depends on whether we should multicast the packet.
        let dst_mac = dst_ip.multicast_mac().unwrap_or(self.src_mac);

        let ip6 = Ipv6 {
            source: *self.ip(),
            destination: dst_ip,
            next_header: IngotIpProto::ICMP_V6,
            payload_len: reply_len as u16,

            // RFC 4861 7.1.2 requires that the hop limit be 255 in an NA.
            hop_limit: 255,
            ..Default::default()
        };

        let eth = Ethernet {
            destination: dst_mac,
            source: self.mac,
            ethertype: Ethertype::IPV6,
        };

        Ok(AllowOrDeny::Allow(MsgBlk::new_ethernet_pkt((
            &eth, &ip6, &ulp_body,
        ))))
    }
}

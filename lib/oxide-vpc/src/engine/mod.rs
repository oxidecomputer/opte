// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

pub mod attached_subnets;
pub mod firewall;
pub mod gateway;
pub mod geneve;
pub mod nat;
pub mod overlay;
pub mod router;

use crate::api::BOUNDARY_SERVICES_VNI;
use crate::cfg::VpcCfg;
use crate::engine::geneve::OxideOptions;
use crate::engine::geneve::ValidOxideOption;
use crate::engine::overlay::TUNNEL_ENDPOINT_MAC;
use crate::engine::overlay::Virt2Boundary;
use alloc::sync::Arc;
use core::ops::Deref;
use core::ops::DerefMut;
use ingot::icmp::IcmpV4;
use ingot::icmp::IcmpV4Mut;
use ingot::icmp::IcmpV4Type;
use ingot::icmp::IcmpV6;
use ingot::icmp::IcmpV6Ref;
use ingot::icmp::IcmpV6Type;
use ingot::ip::IpProtocol;
use ingot::types::HeaderLen;
use opte::api::IpAddr;
use opte::api::Vni;
use opte::ddi::mblk::MsgBlk;
use opte::engine::Direction;
use opte::engine::HdlErrAction;
use opte::engine::HdlPktAction;
use opte::engine::HdlPktError;
use opte::engine::LightweightMeta;
use opte::engine::NetworkImpl;
use opte::engine::NetworkParser;
use opte::engine::arp;
use opte::engine::arp::ARP_HTYPE_ETHERNET;
use opte::engine::arp::ArpEthIpv4Ref;
use opte::engine::arp::ArpOp;
use opte::engine::arp::ValidArpEthIpv4;
use opte::engine::checksum::Checksum;
use opte::engine::ether::Ethernet;
use opte::engine::ether::EthernetRef;
use opte::engine::flow_table::FlowTable;
use opte::engine::geneve::GeneveMeta;
use opte::engine::geneve::GeneveMetaRef;
use opte::engine::headers::EncapMeta;
use opte::engine::headers::SizeHoldingEncap;
use opte::engine::icmp::v4::DestinationUnreachable;
use opte::engine::icmp::v4::DestinationUnreachableMut;
use opte::engine::icmp::v4::ValidDestinationUnreachable;
use opte::engine::ip::L3;
use opte::engine::ip::v4::Ipv4;
use opte::engine::ip::v4::Ipv4Addr;
use opte::engine::ip::v4::Ipv4Mut;
use opte::engine::ip::v4::Ipv4Ref;
use opte::engine::ip::v6::Ipv6;
use opte::engine::ip::v6::Ipv6Mut;
use opte::engine::ip::v6::Ipv6Ref;
use opte::engine::packet::FullParsed;
use opte::engine::packet::InnerFlowId;
use opte::engine::packet::OpteMeta;
use opte::engine::packet::Packet;
use opte::engine::packet::ParseError;
use opte::engine::packet::Pullup;
use opte::engine::parse::Ulp;
use opte::engine::parse::ValidGeneveOverV6;
use opte::engine::parse::ValidNoEncap;
use opte::engine::port::UftEntry;
use opte::engine::rule::CompiledTransform;
use opte::ingot::ethernet::Ethertype;
use opte::ingot::types::HeaderParse;
use opte::ingot::types::IntoBufPointer;
use opte::ingot::types::Parsed as IngotParsed;
use opte::ingot::types::Read;
use zerocopy::ByteSlice;
use zerocopy::ByteSliceMut;

/// The maximum size of a generated ICMPv4 error message (RFC 1812,
/// §4.3.2.3).
///
/// Error messages should contain as many bytes of the the original packet
/// as possible, keeping the new packet within this limit.
///
/// Historically, error messages were clipped to the L3 header followed by
/// 64 bits of their own payload (RFC 1191). Tunnelled traffic and newer
/// protocols nested within UDP (e.g., QUIC) require the RFC 1812 value for
/// PLPMTUD to function (RFC 8899).
const RFC1812_MAX_ICMP_PACKET_SIZE: usize = 576;

/// The minimum MTU required on any link for carrying IPv6
/// traffic (RFC 2460, §5).
///
/// RFC 4443 §3.1 requires that any ICMPv6 error messages generated
/// as a reply to a datagram contain as many bytes of the offending
/// packet as possible, keeping the new packet within this limit.
const RFC2460_MIN_IPV6_MTU: usize = 1280;

#[derive(Clone, Copy, Debug, Default)]
pub struct VpcParser {}

impl VpcParser {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Clone)]
pub struct VpcNetwork {
    pub cfg: VpcCfg,
    pub v2b: Arc<Virt2Boundary>,
}

impl core::fmt::Debug for VpcNetwork {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VpcNetwork")
            .field("cfg", &self.cfg)
            .field("v2b", &"<opaque>")
            .finish()
    }
}

fn is_arp_req(arp: &impl ArpEthIpv4Ref) -> bool {
    arp.htype() == ARP_HTYPE_ETHERNET
        && arp.ptype() == Ethertype::IPV4
        && arp.op() == ArpOp::REQUEST
}

fn is_arp_req_for_tpa(tpa: Ipv4Addr, arp: &impl ArpEthIpv4Ref) -> bool {
    is_arp_req(arp) && arp.tpa() == tpa
}

impl VpcNetwork {
    fn handle_arp_out<'a, T: Read + Pullup + 'a>(
        &self,
        pkt: &mut Packet<FullParsed<T>>,
    ) -> Result<HdlPktAction, HdlPktError>
    where
        T::Chunk: ByteSliceMut + IntoBufPointer<'a>,
    {
        let body = pkt.body().ok_or(HdlPktError("outbound ARP (no body)"))?;

        let (arp, ..) = ValidArpEthIpv4::parse(body)
            .map_err(|_| HdlPktError("outbound ARP (parse)"))?;

        if !arp.values_valid() {
            return Err(HdlPktError("outbound ARP (parse -- bad values)"));
        }

        let gw_ip = self.cfg.ipv4_cfg().unwrap().gateway_ip;

        if is_arp_req_for_tpa(gw_ip, &arp) {
            let gw_mac = self.cfg.gateway_mac;

            let hp = arp::gen_arp_reply(gw_mac, gw_ip, arp.sha(), arp.spa());
            return Ok(HdlPktAction::Hairpin(hp));
        }

        Ok(HdlPktAction::Deny)
    }
}

impl NetworkImpl for VpcNetwork {
    type Parser = VpcParser;

    fn handle_pkt<'a, T: Read + Pullup + 'a>(
        &self,
        dir: Direction,
        pkt: &mut Packet<FullParsed<T>>,
        _uft_in: &FlowTable<UftEntry<InnerFlowId>>,
        _uft_out: &FlowTable<UftEntry<InnerFlowId>>,
    ) -> Result<HdlPktAction, HdlPktError>
    where
        T::Chunk: ByteSliceMut + IntoBufPointer<'a>,
    {
        match (dir, pkt.meta().inner_ether().ethertype()) {
            (Direction::Out, Ethertype::ARP) => self.handle_arp_out(pkt),

            _ => Ok(HdlPktAction::Deny),
        }
    }

    fn parser(&self) -> Self::Parser {
        VpcParser {}
    }

    fn handle_oversize<'a, T: Read + Pullup + 'a>(
        &self,
        dir: Direction,
        pkt: &mut Packet<FullParsed<T>>,
    ) -> Result<HdlErrAction, HdlPktError>
    where
        T::Chunk: ByteSliceMut + IntoBufPointer<'a>,
    {
        let meta = pkt.meta();

        let Some(l3) = meta.inner_l3() else {
            // We can't generate an ICMP response without IP present in some
            // form.
            return Ok(HdlErrAction::Deny);
        };

        // If the packet came in encapsulated, then we need to mirror the
        // encapsulation on our outbound frame.
        let (is_external, mut encap) = match dir {
            Direction::In => {
                let Some(eth) = meta.outer_ether() else {
                    return Err(HdlPktError(
                        "inbound oxide-vpc packets must be encapped (l2)",
                    ));
                };
                let Some(L3::Ipv6(v6)) = meta.outer_ip() else {
                    return Err(HdlPktError(
                        "inbound oxide-vpc packets must be encapped (l3)",
                    ));
                };
                let Some(encap) = meta.outer_geneve() else {
                    return Err(HdlPktError(
                        "inbound oxide-vpc packets must be encapped (l4)",
                    ));
                };

                let mut is_external = false;
                let vni = encap.vni();
                let entropy = encap.entropy();
                for opt in OxideOptions::from_meta(encap) {
                    let Ok(opt) = opt else { break };
                    if let Some(ValidOxideOption::External) = opt.option.known()
                    {
                        is_external = true;
                        break;
                    }
                }

                let new_eth = Ethernet {
                    destination: eth.source(),
                    source: eth.destination(),
                    ethertype: Ethertype::IPV6,
                };

                // We'll fill in payload lengths once the inner packet is built.
                let new_v6 = Ipv6 {
                    source: v6.destination(),
                    destination: v6.source(),
                    next_header: ingot::ip::IpProtocol::UDP,
                    ..Default::default()
                };
                let new_geneve = EncapMeta::Geneve(GeneveMeta {
                    entropy,
                    vni: if is_external {
                        Vni::new(BOUNDARY_SERVICES_VNI).unwrap()
                    } else {
                        vni
                    },
                    options: (&[]).into(),
                });

                (is_external, Some((new_eth, new_v6, new_geneve)))
            }
            Direction::Out => (false, None),
        };

        let mut truncated_original =
            MsgBlk::new_ethernet_pkt((meta.inner_l3(), meta.inner_ulp()));

        let body = pkt.body().unwrap_or_default();

        let (ethertype, recipient, mut new_icmp_hdrs, max_sz) = match l3 {
            L3::Ipv4(v4) => {
                let Some(cfg) = self.cfg.ipv4_cfg() else {
                    return Ok(HdlErrAction::Deny);
                };

                // RFC 792
                // "To avoid the infinite regress of messages about messages
                // etc., no ICMP messages are sent about ICMP messages."
                match meta.inner_ulp() {
                    Some(Ulp::IcmpV4(_)) => return Ok(HdlErrAction::Deny),
                    Some(Ulp::IcmpV6(_)) => {
                        return Err(HdlPktError(
                            "IPv4 packet should not contain ICMPv6",
                        ));
                    }
                    _ => {}
                }

                // RFC 1812, §4.3.2.7
                // An ICMP error message MUST NOT be sent as the result of receiving:
                // o A packet destined to an IP broadcast or IP multicast address, or
                // o A packet sent as a Link Layer broadcast or multicast, or
                // o A packet whose source address has a network prefix of zero or is an
                //    invalid source address (as defined in Section [5.3.7]), or [...]
                //
                // This is to avoid causing any traffic amplification upstream.
                let remote = v4.source();
                let rcvd_on = v4.destination();
                if remote.is_multicast()
                    || remote.is_unspecified()
                    || remote.is_broadcast()
                    || remote.is_loopback()
                    || rcvd_on.is_multicast()
                    || rcvd_on.is_broadcast()
                    || rcvd_on.is_unspecified()
                {
                    return Ok(HdlErrAction::Deny);
                }

                // RFC 1812, §4.3.2.4 governs source address selection. The main
                // requirements here are that this is an address that we own in some form.
                //
                // If this packet has arrived from within the current Oxide cluster (i.e.
                // this VPC or one which is peered), then OPTE has a valid address to use
                // as the sender of any ICMP messages. For any external traffic, the best
                // we can do is use the destination address; the control plane has
                // programmed sidecar to forward this traffic to us, so we know that it is
                // owned by the guest in some form.
                let source = if is_external { rcvd_on } else { cfg.gateway_ip };

                let new_icmp = IcmpV4 {
                    ty: IcmpV4Type::DESTINATION_UNREACHABLE,
                    code: DestinationUnreachable::FRAGMENTATION_NEEDED,
                    // MTU and body length are filled in below to require fewer casts
                    // of `rest_of_hdr` to `ValidDestinationUnreachable`.
                    ..Default::default()
                };

                let new_v4 = Ipv4 {
                    source,
                    destination: remote,
                    protocol: IpProtocol::ICMP,
                    ..Default::default()
                };

                (
                    Ethertype::IPV4,
                    IpAddr::from(remote),
                    (
                        L3::<&mut [u8]>::from(new_v4),
                        Ulp::<&mut [u8]>::from(new_icmp),
                    ),
                    RFC1812_MAX_ICMP_PACKET_SIZE,
                )
            }
            L3::Ipv6(v6) => {
                let Some(cfg) = self.cfg.ipv6_cfg() else {
                    return Ok(HdlErrAction::Deny);
                };

                // RFC4443 §2.4(e)
                // An ICMPv6 error message MUST NOT be originated as a result of
                // receiving the following:
                // (e.1) An ICMPv6 error message.
                // (e.2) An ICMPv6 redirect message
                match meta.inner_ulp() {
                    Some(Ulp::IcmpV6(v6))
                        if v6.ty().is_error()
                            || v6.ty() == IcmpV6Type::REDIRECT =>
                    {
                        return Ok(HdlErrAction::Deny);
                    }
                    Some(Ulp::IcmpV4(_)) => {
                        return Err(HdlPktError(
                            "IPv6 packet should not contain ICMPv4",
                        ));
                    }
                    _ => {}
                }

                // (e.6) A packet whose source address does not uniquely identify a
                //       single node -- e.g., the IPv6 Unspecified Address, an IPv6
                //       multicast address, or an address known by the ICMP message
                //       originator to be an IPv6 anycast address.
                let remote = v6.source();
                let rcvd_on = v6.destination();
                if remote.is_multicast()
                    || remote.is_unspecified()
                    || rcvd_on.is_unspecified()
                {
                    return Ok(HdlErrAction::Deny);
                }

                // (e.3)-(e.5) state that ONLY packet too big errors may be generated
                // when the destination address is not unicast, so we apply no
                // restriction on the destination address.

                // Source selection here follows the same rubric as IPv4. However,
                // because we permit broadcast/multicast destinations in the original
                // packet (§3.2), we need to choose one of our external IPs as a
                // source when this destination is not unicast if the gateway IP
                // cannot be used.
                let source = match (is_external, rcvd_on.is_multicast()) {
                    (false, _) => cfg.gateway_ip,
                    (true, false) => rcvd_on,
                    (true, true) => {
                        let ext_ips = cfg.external_ips.load();
                        let attached_subnets = cfg.attached_subnets.load();
                        let ip = ext_ips
                            .floating_ips
                            .first()
                            .copied()
                            .or_else(|| {
                                attached_subnets.iter().find_map(|(k, v)| {
                                    v.is_external.then_some(k.ip())
                                })
                            })
                            .or(ext_ips.ephemeral_ip)
                            .or_else(|| {
                                ext_ips.snat.as_ref().map(|v| v.external_ip)
                            });

                        ip.ok_or(HdlPktError(
                            "no valid external source address for non-unicast packet"
                        ))?
                    }
                };

                let new_icmp = IcmpV6 {
                    ty: IcmpV6Type::PACKET_TOO_BIG,
                    code: 0,
                    // RFC 4443, §3.2
                    rest_of_hdr: self.cfg.mtu.to_be_bytes(),
                    ..Default::default()
                };

                let new_v6 = Ipv6 {
                    source,
                    destination: remote,
                    next_header: IpProtocol::ICMP_V6,
                    ..Default::default()
                };

                (
                    Ethertype::IPV6,
                    IpAddr::from(remote),
                    (L3::from(new_v6), Ulp::from(new_icmp)),
                    RFC2460_MIN_IPV6_MTU,
                )
            }
        };

        // We don't have control over the input headers, which may have any
        // number of extension headers and the like in use. Trunctate that
        // buffer if needed and then determine how many bytes to take from
        // the body.
        //
        // Since we are pushing no extension headers ourselves, we know that
        // the new headers fit within the limit by construction.
        let bytes_used = new_icmp_hdrs.packet_length();
        let headers_to_take =
            (max_sz - bytes_used).min(truncated_original.len());
        let bytes_used = bytes_used + headers_to_take;
        if headers_to_take != truncated_original.len() {
            truncated_original.truncate_chain(headers_to_take);
        }

        let body_to_take = (max_sz - bytes_used).min(body.len());
        let truncated_body = &body[..body_to_take];
        let bytes_used = bytes_used + body_to_take;

        let mut body_csum = Checksum::new();
        body_csum.add_bytes(&truncated_original);
        body_csum.add_bytes(truncated_body);

        // Now that we have determined the body of our new ICMP packet,
        // we can fill in the remainder of its packet headers.
        let pad = match &mut new_icmp_hdrs {
            (L3::Ipv4(v4), Ulp::IcmpV4(icmp4)) => {
                v4.set_total_len(
                    u16::try_from(bytes_used).expect("less than 576B"),
                );

                let inner_bytes = headers_to_take + body_to_take;
                let plus_pad = inner_bytes.next_multiple_of(4);

                let (mut du, ..) = ValidDestinationUnreachable::parse(
                    icmp4.rest_of_hdr_mut().as_mut_slice(),
                )
                .expect("fixed-size field has same size as struct");

                du.set_length(
                    u8::try_from(plus_pad / size_of::<u32>())
                        .expect("plus_pad is less than 144 words (576B)"),
                );
                du.set_mtu(u16::try_from(self.cfg.mtu).unwrap_or(u16::MAX));

                plus_pad - inner_bytes
            }
            (L3::Ipv6(v6), Ulp::IcmpV6(_)) => {
                v6.set_payload_len(
                    u16::try_from(bytes_used - v6.packet_length())
                        .expect("less than 1280B"),
                );
                // IPv6 MTU is already set.
                0
            }
            _ => unreachable!(),
        };

        new_icmp_hdrs
            .1
            .compute_checksum(new_icmp_hdrs.0.pseudo_header(), body_csum);
        new_icmp_hdrs.0.compute_checksum();

        let pad_from = [0u8; 3];

        // Swapping the L3 headers is obvious, but the L2 headers need some
        // explanation for doing the same correctly because of the various
        // transforms in use during processing. Once a packet is processed
        // outbound, it will have its destination updated to the target port's MAC.
        // On the inbound case, we update the source MAC to that of the gateway.
        //
        //  - If we're rejecting on outbound, this reply will be gateway
        //    to guest MAC, which is obviously correct.
        //
        //  - In the internal inbound case, because of the above transform the
        //    gateway MAC is not on the scene and we see the inner MACs of each
        //    port. This is good, as this prevents us from needing a V2P lookup
        //    to ensure the packet will be delivered to the right OPTE on the
        //    original sled. The reply will have the source rewritten to the
        //    gateway MAC at the end of its own inbound processing.
        //
        //  - In the external inbound case, the original source will be zeroed.
        //    Sidecar is only checking for traffic pointed at a switch address
        //    and does not care about the inner MACs, but we should be thorough
        //    in case this contract becomes more strict.
        let new_eth = Ethernet {
            destination: if !is_external {
                meta.inner_ether().source()
            } else {
                TUNNEL_ENDPOINT_MAC.into()
            },
            source: meta.inner_ether().destination(),
            ethertype,
        };

        truncated_original
            .append(MsgBlk::new_pkt((truncated_body, &pad_from[..pad])));
        let encapped_len = (&new_eth, &new_icmp_hdrs).packet_length()
            + truncated_original.byte_len();
        let encapped_len = u16::try_from(encapped_len)
            .expect("maximmum inner packet size is below 1300B");

        // Now we can specialise the encap layers with the inner packet size,
        // and identify a switch address to reach any external sender if required.
        let encap = encap
            .as_mut()
            .map(|(eth, l3, gv)| {
                // ...Sidecar will give us a zeroed source address on NAT'd
                // packets. This isn't a great destination for a frame: it must
                // be a valid switch address to actually be eligible for
                // decapsulation!
                if l3.destination.is_unspecified() {
                    if !is_external {
                        return Err(HdlPktError(
                            "cannot reply to null sled address",
                        ));
                    }

                    let Some(nhs) =
                        self.v2b.get(&recipient).filter(|v| !v.is_empty())
                    else {
                        return Err(HdlPktError(
                            "no external nexthop for ICMP reply",
                        ));
                    };

                    let hash = pkt.l4_hash() as usize;
                    let nh = nhs
                        .iter()
                        .nth(hash % nhs.len())
                        .expect("nhs nonempty, index is always less than len");

                    let EncapMeta::Geneve(gv) = gv;
                    gv.vni = nh.vni;

                    l3.destination = nh.ip;

                    // Clear the ethernet src/dst, since we can't guarantee that
                    // we will be going out the same NIC we came in on.
                    eth.destination = Default::default();
                    eth.source = Default::default();
                }

                let sized_geneve =
                    SizeHoldingEncap { encapped_len, meta: &*gv };
                l3.payload_len = u16::try_from(sized_geneve.packet_length())
                    .expect("inner packet is at most 1294B")
                    .saturating_add(encapped_len);

                Ok((&*eth, &*l3, sized_geneve))
            })
            .transpose()?;

        let mut out = MsgBlk::new_ethernet_pkt((encap, new_eth, new_icmp_hdrs));
        out.append(truncated_original);

        Ok(HdlErrAction::Hairpin(out))
    }
}

impl NetworkParser for VpcParser {
    type InMeta<T: ByteSliceMut> = OxideGeneve<T>;
    type OutMeta<T: ByteSliceMut> = ValidNoEncap<T>;

    #[inline(always)]
    fn parse_outbound<'a, T: Read + 'a>(
        &self,
        rdr: T,
    ) -> Result<IngotParsed<Self::OutMeta<T::Chunk>, T>, ParseError>
    where
        T::Chunk: opte::ingot::types::IntoBufPointer<'a> + ByteSliceMut,
    {
        Ok(ValidNoEncap::parse_read(rdr)?)
    }

    #[inline(always)]
    fn parse_inbound<'a, T: Read + 'a>(
        &self,
        rdr: T,
    ) -> Result<IngotParsed<Self::InMeta<T::Chunk>, T>, ParseError>
    where
        T::Chunk: opte::ingot::types::IntoBufPointer<'a> + ByteSliceMut,
    {
        let IngotParsed { headers, last_chunk, data } =
            ValidGeneveOverV6::parse_read(rdr)?;

        Ok(IngotParsed { last_chunk, data, headers: OxideGeneve(headers) })
    }
}

#[repr(transparent)]
pub struct OxideGeneve<T: ByteSlice>(pub ValidGeneveOverV6<T>);

impl<T: ByteSlice> Deref for OxideGeneve<T> {
    type Target = ValidGeneveOverV6<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: ByteSlice> DerefMut for OxideGeneve<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: ByteSliceMut> LightweightMeta<T> for OxideGeneve<T> {
    #[inline]
    fn run_compiled_transform(&mut self, transform: &CompiledTransform)
    where
        T: ByteSliceMut,
    {
        self.0.run_compiled_transform(transform);
    }

    #[inline]
    fn compute_body_csum(&self) -> Option<Checksum> {
        self.0.compute_body_csum()
    }

    #[inline]
    fn flow(&self) -> InnerFlowId {
        self.0.flow()
    }

    #[inline]
    fn encap_len(&self) -> u16 {
        self.0.encap_len()
    }

    #[inline]
    fn update_inner_checksums(&mut self, body_csum: Option<Checksum>) {
        self.0.update_inner_checksums(body_csum);
    }

    #[inline]
    fn inner_tcp(&self) -> Option<&impl ingot::tcp::TcpRef<T>> {
        self.0.inner_tcp()
    }

    #[inline]
    fn validate(&self, pkt_len: usize) -> Result<(), ParseError> {
        self.0.validate(pkt_len)?;

        geneve::validate_options(&self.0.outer_encap)
    }
}

impl<T: ByteSlice> From<OxideGeneve<T>> for OpteMeta<T> {
    #[inline]
    fn from(value: OxideGeneve<T>) -> Self {
        value.0.into()
    }
}

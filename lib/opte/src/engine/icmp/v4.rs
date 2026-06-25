// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! ICMPv4 headers and processing.

use super::*;
use crate::ddi::mblk::MsgBlk;
use crate::engine::checksum::HeaderChecksum;
use crate::engine::ether::Ethernet;
use crate::engine::ip::v4::Ipv4;
use crate::engine::packet::MblkPacketDataView;
use crate::engine::predicate::Ipv4AddrMatch;
use ingot::ethernet::Ethertype;
use ingot::icmp::IcmpV4;
use ingot::icmp::IcmpV4Packet;
use ingot::icmp::IcmpV4Ref;
use ingot::icmp::IcmpV4Type;
use ingot::icmp::ValidIcmpV4;
use ingot::ip::IpProtocol;
use ingot::types::HeaderLen;
use ingot::types::HeaderParse;
use opte::engine::Checksum as OpteCsum;
pub use opte_api::ip::IcmpEchoReply;
use smoltcp::wire;

impl HairpinAction for IcmpEchoReply {
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        let hdr_preds = vec![
            Predicate::InnerEtherSrc(vec![EtherAddrMatch::Exact(
                self.echo_src_mac,
            )]),
            Predicate::InnerEtherDst(vec![EtherAddrMatch::Exact(
                self.echo_dst_mac,
            )]),
            Predicate::InnerSrcIp4(vec![Ipv4AddrMatch::Exact(
                self.echo_src_ip,
            )]),
            Predicate::InnerDstIp4(vec![Ipv4AddrMatch::Exact(
                self.echo_dst_ip,
            )]),
            Predicate::InnerIpProto(vec![IpProtoMatch::Exact(Protocol::ICMP)]),
            Predicate::IcmpMsgType(vec![
                MessageType::from(wire::Icmpv4Message::EchoRequest).into(),
            ]),
        ];

        (hdr_preds, vec![])
    }

    fn gen_packet(&self, meta: MblkPacketDataView) -> GenPacketResult {
        let Some(icmp) = meta.headers.inner_icmp() else {
            // Getting here implies the predicate matched, but that the
            // extracted metadata indicates this isn't an ICMP packet. That
            // should be impossible, but we avoid panicking given the kernel
            // context.
            return Err(GenErr::Unexpected(format!(
                "Expected ICMP packet metadata, but found: {meta:?}",
            )));
        };

        let ty = MessageType::from(icmp.ty().0);

        // We'll be recycling the sequence and identity.
        let rest_of_hdr = match (ty, icmp.code()) {
            (MessageType { inner: wire::Icmpv4Message::EchoRequest }, 0) => {
                icmp.rest_of_hdr()
            }
            (ty, code) => {
                // We should never hit this case because the predicate
                // should have verified that we are dealing with an
                // Echo Request. However, programming error could
                // cause this to happen -- let's not take any chances.
                return Err(GenErr::Unexpected(format!(
                    "expected an ICMPv4 Echo Request, got {ty} {code}",
                )));
            }
        };

        // Checksum update is minimal for a ping reply.
        // May need to compute from scratch if offloading / request
        // cksum is elided.
        let mut csum = match icmp.checksum() {
            0 => {
                let mut csum = OpteCsum::new();
                csum.add_bytes(meta.body());
                csum.add_bytes(icmp.rest_of_hdr_ref());
                csum
            }
            valid => {
                let mut csum =
                    OpteCsum::from(HeaderChecksum::wrap(valid.to_be_bytes()));
                csum.sub_bytes(&[icmp.ty().0, icmp.code()]);
                csum
            }
        };

        let ty = IcmpV4Type::ECHO_REPLY;
        let code = 0;
        csum.add_bytes(&[ty.0, code]);

        // Build the reply in place, and send it out.
        let body_len: usize = meta.body().len();

        let icmp = IcmpV4 {
            ty,
            code,
            checksum: csum.finalize_for_ingot(),
            rest_of_hdr,
        };

        let mut ip4 = Ipv4 {
            source: self.echo_dst_ip,
            destination: self.echo_src_ip,
            protocol: IpProtocol::ICMP,
            total_len: (Ipv4::MINIMUM_LENGTH + icmp.packet_length() + body_len)
                as u16,
            ..Default::default()
        };
        ip4.compute_checksum();

        let eth = Ethernet {
            destination: self.echo_src_mac,
            source: self.echo_dst_mac,
            ethertype: Ethertype::IPV4,
        };

        let total_len = body_len + (&eth, &ip4, &icmp).packet_length();

        let mut pkt_out = MsgBlk::new_ethernet(total_len);
        pkt_out
            .emit_back((&eth, &ip4, &icmp, meta.body()))
            .expect("Allocated space for pkt headers and body");

        Ok(AllowOrDeny::Allow(pkt_out))
    }
}

/// The ICMPv4 message type.
///
/// We wrap smoltcp's Icmpv4Message type so that we may provide a
/// serde implementation; allowing this value to be used in `Rule`
/// predicates. We call this "message type" instead of just "message"
/// because that's what it is: the type field of the larger ICMP
/// message.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(from = "u8", into = "u8")]
pub struct MessageType {
    inner: wire::Icmpv4Message,
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

impl From<wire::Icmpv4Message> for MessageType {
    fn from(inner: wire::Icmpv4Message) -> Self {
        Self { inner }
    }
}

impl From<MessageType> for wire::Icmpv4Message {
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
        Self { inner: wire::Icmpv4Message::from(val) }
    }
}

impl Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl<B: ByteSlice> QueryEcho for IcmpV4Packet<B> {
    #[inline]
    fn echo_id(&self) -> Option<u16> {
        match (self.ty(), self.code()) {
            (IcmpV4Type::ECHO_REQUEST, 0) | (IcmpV4Type::ECHO_REPLY, 0) => {
                ValidIcmpEcho::parse(self.rest_of_hdr_ref().as_slice())
                    .ok()
                    .map(|(v, ..)| v.id())
            }
            _ => None,
        }
    }
}

impl<B: ByteSlice> QueryEcho for ValidIcmpV4<B> {
    #[inline]
    fn echo_id(&self) -> Option<u16> {
        match (self.ty(), self.code()) {
            (IcmpV4Type::ECHO_REQUEST, 0) | (IcmpV4Type::ECHO_REPLY, 0) => {
                ValidIcmpEcho::parse(self.rest_of_hdr_ref().as_slice())
                    .ok()
                    .map(|(v, ..)| v.id())
            }
            _ => None,
        }
    }
}

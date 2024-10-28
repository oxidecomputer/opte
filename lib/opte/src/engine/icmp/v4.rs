// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! ICMPv4 headers and processing.

use super::*;
use crate::ddi::mblk::MsgBlk;
use crate::engine::ether::Ethernet;
use crate::engine::ingot_packet::MblkPacketData;
use crate::engine::ip::v4::Ipv4;
use crate::engine::ip::L3;
use crate::engine::predicate::Ipv4AddrMatch;
use ingot::ethernet::Ethertype;
use ingot::ip::IpProtocol;
use ingot::types::Emit;
use ingot::types::HeaderLen;
pub use opte_api::ip::IcmpEchoReply;
use smoltcp::wire;
use smoltcp::wire::Icmpv4Packet;
use smoltcp::wire::Icmpv4Repr;

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
        ];

        let data_preds = vec![DataPredicate::IcmpMsgType(
            MessageType::from(wire::Icmpv4Message::EchoRequest).into(),
        )];

        (hdr_preds, data_preds)
    }

    fn gen_packet(&self, meta: &MblkPacketData) -> GenPacketResult {
        let Some(icmp) = meta.inner_icmp() else {
            // Getting here implies the predicate matched, but that the
            // extracted metadata indicates this isn't an ICMP packet. That
            // should be impossible, but we avoid panicking given the kernel
            // context.
            return Err(GenErr::Unexpected(format!(
                "Expected ICMP packet metadata, but found: {:?}",
                meta
            )));
        };

        // TODO: prealloc right size.
        let mut body = icmp.emit_vec();
        meta.append_remaining(&mut body);

        let src_pkt = Icmpv4Packet::new_checked(&body)?;
        let src_icmp = Icmpv4Repr::parse(&src_pkt, &Csum::ignored())?;

        let (src_ident, src_seq_no, src_data) = match src_icmp {
            Icmpv4Repr::EchoRequest { ident, seq_no, data } => {
                (ident, seq_no, data)
            }

            _ => {
                // We should never hit this case because the predicate
                // should have verified that we are dealing with an
                // Echo Request. However, programming error could
                // cause this to happen -- let's not take any chances.
                return Err(GenErr::Unexpected(format!(
                    "expected an ICMPv4 Echo Request, got {} {}",
                    src_pkt.msg_type(),
                    src_pkt.msg_code()
                )));
            }
        };

        let reply = Icmpv4Repr::EchoReply {
            ident: src_ident,
            seq_no: src_seq_no,
            data: src_data,
        };

        let reply_len = reply.buffer_len();
        let mut tmp = vec![0u8; reply_len];
        let mut icmp_reply = Icmpv4Packet::new_unchecked(&mut tmp);
        let mut csum = Csum::ignored();
        csum.icmpv4 = Checksum::Tx;
        reply.emit(&mut icmp_reply, &csum);

        let mut ip4: L3<&mut [u8]> = Ipv4 {
            source: self.echo_dst_ip,
            destination: self.echo_src_ip,
            protocol: IpProtocol::ICMP,
            total_len: (Ipv4::MINIMUM_LENGTH + reply_len) as u16,
            ..Default::default()
        }
        .into();

        ip4.compute_checksum();

        let eth = Ethernet {
            destination: self.echo_src_mac,
            source: self.echo_dst_mac,
            ethertype: Ethertype::IPV4,
        };

        Ok(AllowOrDeny::Allow(MsgBlk::new_ethernet_pkt((&eth, &ip4, &tmp))))
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

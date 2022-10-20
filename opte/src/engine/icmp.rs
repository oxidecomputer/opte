// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! ICMP headers.
use super::ether;
use super::ether::EtherHdr;
use super::ether::EtherMeta;
use super::ip4::Ipv4Hdr;
use super::ip4::Ipv4Meta;
use super::packet::Packet;
use super::packet::PacketMeta;
use super::packet::PacketRead;
use super::packet::PacketReader;
use super::packet::Parsed;
use super::predicate::DataPredicate;
use super::predicate::EtherAddrMatch;
use super::predicate::IpProtoMatch;
use super::predicate::Ipv4AddrMatch;
use super::predicate::Predicate;
use super::rule::AllowOrDeny;
use super::rule::GenErr;
use super::rule::GenPacketResult;
use super::rule::HairpinAction;
use core::fmt;
use core::fmt::Display;
pub use opte_api::ip::IcmpEchoReply;
pub use opte_api::ip::Protocol;
use serde::Deserialize;
use serde::Serialize;
use smoltcp::phy::Checksum;
use smoltcp::phy::ChecksumCapabilities as Csum;
use smoltcp::wire;
use smoltcp::wire::Icmpv4Packet;
use smoltcp::wire::Icmpv4Repr;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::vec::Vec;
    } else {
        use std::vec::Vec;
    }
}

impl HairpinAction for IcmpEchoReply {
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        let hdr_preds = vec![
            Predicate::InnerEtherSrc(vec![EtherAddrMatch::Exact(
                self.echo_src_mac.into(),
            )]),
            Predicate::InnerEtherDst(vec![EtherAddrMatch::Exact(
                self.echo_dst_mac.into(),
            )]),
            Predicate::InnerSrcIp4(vec![Ipv4AddrMatch::Exact(
                self.echo_src_ip,
            )]),
            Predicate::InnerDstIp4(vec![Ipv4AddrMatch::Exact(
                self.echo_dst_ip,
            )]),
            Predicate::InnerIpProto(vec![IpProtoMatch::Exact(Protocol::ICMP)]),
        ];

        let data_preds = vec![DataPredicate::IcmpMsgType(MessageType::from(
            wire::Icmpv4Message::EchoRequest,
        ))];

        (hdr_preds, data_preds)
    }

    fn gen_packet(
        &self,
        _meta: &PacketMeta,
        rdr: &mut PacketReader<Parsed, ()>,
    ) -> GenPacketResult {
        let body = rdr.copy_remaining();
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
        let _ = reply.emit(&mut icmp_reply, &csum);

        let mut ip4 = Ipv4Hdr::from(&Ipv4Meta {
            src: self.echo_dst_ip,
            dst: self.echo_src_ip,
            proto: Protocol::ICMP,
        });
        ip4.set_total_len(ip4.hdr_len() as u16 + reply_len as u16);
        ip4.compute_hdr_csum();

        let eth = EtherHdr::from(&EtherMeta {
            dst: self.echo_src_mac.into(),
            src: self.echo_dst_mac.into(),
            ether_type: ether::ETHER_TYPE_IPV4,
        });

        let mut pkt_bytes =
            Vec::with_capacity(EtherHdr::SIZE + Ipv4Hdr::SIZE + reply_len);
        pkt_bytes.extend_from_slice(&eth.as_bytes());
        pkt_bytes.extend_from_slice(&ip4.as_bytes());
        pkt_bytes.extend_from_slice(&tmp);
        Ok(AllowOrDeny::Allow(Packet::copy(&pkt_bytes)))
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

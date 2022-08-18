// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! ICMP headers.
use super::ether::{self, EtherHdr, EtherMeta, ETHER_HDR_SZ};
use super::ip4::{Ipv4Hdr, Ipv4Meta, IPV4_HDR_SZ};
use super::packet::{Packet, PacketMeta, PacketRead, PacketReader, Parsed};
use super::rule::{
    AllowOrDeny, DataPredicate, EtherAddrMatch, GenErr, GenPacketResult,
    HairpinAction, IpProtoMatch, Ipv4AddrMatch, Predicate,
};
use core::fmt::{self, Display};
pub use opte_api::ip::{Icmp4EchoReply, Protocol};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use smoltcp::phy::{Checksum, ChecksumCapabilities as Csum};
use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr};

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::vec::Vec;
    } else {
        use std::vec::Vec;
    }
}

impl HairpinAction for Icmp4EchoReply {
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

        let data_preds = vec![DataPredicate::Icmp4MsgType(MessageType::from(
            smoltcp::wire::Icmpv4Message::EchoRequest,
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
            Vec::with_capacity(ETHER_HDR_SZ + IPV4_HDR_SZ + reply_len);
        pkt_bytes.extend_from_slice(&eth.as_bytes());
        pkt_bytes.extend_from_slice(&ip4.as_bytes());
        pkt_bytes.extend_from_slice(&tmp);
        Ok(AllowOrDeny::Allow(Packet::copy(&pkt_bytes)))
    }
}

/// The ICMPv4 message type.
///
/// We wrap smoltcp's Icmpv4Message type so that we may provide a
/// serde implementation; allowing this value to be used in [`Rule`]
/// predicates. We call this "message type" instead of just "message"
/// because that's what it is: the type field of the larger ICMP
/// message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageType {
    inner: smoltcp::wire::Icmpv4Message,
}

impl From<smoltcp::wire::Icmpv4Message> for MessageType {
    fn from(inner: smoltcp::wire::Icmpv4Message) -> Self {
        Self { inner }
    }
}

impl From<MessageType> for smoltcp::wire::Icmpv4Message {
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
        Self { inner: smoltcp::wire::Icmpv4Message::from(val) }
    }
}

struct MessageTypeVisitor;

impl<'de> Visitor<'de> for MessageTypeVisitor {
    type Value = MessageType;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an unsigned integer from 0 to 255")
    }

    fn visit_u8<E>(self, value: u8) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(MessageType::from(value))
    }
}

impl<'de> Deserialize<'de> for MessageType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_u8(MessageTypeVisitor)
    }
}

impl Serialize for MessageType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(u8::from(*self))
    }
}

impl Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

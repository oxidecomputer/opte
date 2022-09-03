// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Internet Control Message Protocol version 6

use super::ether::{self, EtherHdr, EtherMeta};
use super::ip6::Ipv6Hdr;
use super::ip6::Ipv6Meta;
use super::packet::{Packet, PacketMeta, PacketRead, PacketReader, Parsed};
use super::rule::{
    AllowOrDeny, DataPredicate, EtherAddrMatch, GenErr, GenPacketResult,
    HairpinAction, IpProtoMatch, Ipv6AddrMatch, Predicate,
};
use core::fmt::{self, Display};
pub use opte_api::ip::{Icmpv6EchoReply, Protocol};
use serde::{Deserialize, Serialize};
use smoltcp::phy::{Checksum, ChecksumCapabilities as Csum};
use smoltcp::wire::{
    Icmpv6Message, Icmpv6Packet, Icmpv6Repr, IpAddress, Ipv6Address,
};

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::vec::Vec;
    } else {
        use std::vec::Vec;
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
        rdr: &mut PacketReader<Parsed, ()>,
    ) -> GenPacketResult {
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

        let mut ip = Ipv6Hdr::from(&Ipv6Meta {
            src: self.dst_ip,
            dst: self.src_ip,
            proto: Protocol::ICMPv6,
        });

        // There are no extension headers, so the ULP is the only content.
        ip.set_pay_len(reply_len as u16);

        let eth = EtherHdr::from(&EtherMeta {
            dst: self.src_mac.into(),
            src: self.dst_mac.into(),
            ether_type: ether::ETHER_TYPE_IPV6,
        });

        let mut pkt_bytes =
            Vec::with_capacity(EtherHdr::SIZE + Ipv6Hdr::SIZE + reply_len);
        pkt_bytes.extend_from_slice(&eth.as_bytes());
        pkt_bytes.extend_from_slice(&ip.as_bytes());
        pkt_bytes.extend_from_slice(&ulp_body);
        Ok(AllowOrDeny::Allow(Packet::copy(&pkt_bytes)))
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! ICMPv4 headers and processing.

use super::IcmpMeta;
use crate::engine::ether::EtherHdr;
use crate::engine::ether::EtherMeta;
use crate::engine::ether::EtherType;
use crate::engine::icmp::HeaderActionModify;
use crate::engine::icmp::UlpMetaModify;
use crate::engine::ip4::Ipv4Hdr;
use crate::engine::ip4::Ipv4Meta;
use crate::engine::packet::Packet;
use crate::engine::packet::PacketMeta;
use crate::engine::packet::PacketRead;
use crate::engine::packet::PacketReader;
use crate::engine::predicate::DataPredicate;
use crate::engine::predicate::EtherAddrMatch;
use crate::engine::predicate::IpProtoMatch;
use crate::engine::predicate::Ipv4AddrMatch;
use crate::engine::predicate::Predicate;
use crate::engine::rule::AllowOrDeny;
use crate::engine::rule::GenErr;
use crate::engine::rule::GenPacketResult;
use crate::engine::rule::HairpinAction;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Display;
pub use opte_api::ip::IcmpEchoReply;
pub use opte_api::ip::Protocol;
use serde::Deserialize;
use serde::Serialize;
use smoltcp::phy::Checksum;
use smoltcp::phy::ChecksumCapabilities as Csum;
use smoltcp::wire;
use smoltcp::wire::Icmpv4Message;
use smoltcp::wire::Icmpv4Packet;
use smoltcp::wire::Icmpv4Repr;

pub type Icmpv4Meta = IcmpMeta<MessageType>;

impl Icmpv4Meta {
    /// Extract an ID from the body of an ICMPv4 packet to use as a
    /// pseudo port for flow differentiation.
    ///
    /// This method returns `None` for any non-echo packets.
    #[inline]
    pub fn echo_id(&self) -> Option<u16> {
        match self.msg_type.inner {
            Icmpv4Message::EchoRequest | Icmpv4Message::EchoReply => {
                Some(u16::from_be_bytes(self.body_echo().id))
            }
            _ => None,
        }
    }
}

impl HeaderActionModify<UlpMetaModify> for Icmpv4Meta {
    fn run_modify(&mut self, spec: &UlpMetaModify) {
        let Some(new_id) = spec.icmp_id else {
            return;
        };

        if self.echo_id().is_none() {
            return;
        }

        let mut echo_data = self.body_echo_mut();
        echo_data.id = new_id.to_be_bytes();
    }
}

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

    fn gen_packet(
        &self,
        meta: &PacketMeta,
        rdr: &mut PacketReader,
    ) -> GenPacketResult {
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

        rdr.seek_back(icmp.hdr_len())?;
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
        reply.emit(&mut icmp_reply, &csum);

        let mut ip4 = Ipv4Meta {
            src: self.echo_dst_ip,
            dst: self.echo_src_ip,
            proto: Protocol::ICMP,
            total_len: (Ipv4Hdr::BASE_SIZE + reply_len) as u16,
            ..Default::default()
        };
        ip4.compute_hdr_csum();

        let eth = EtherMeta {
            dst: self.echo_src_mac,
            src: self.echo_dst_mac,
            ether_type: EtherType::Ipv4,
        };

        let total_len = EtherHdr::SIZE + Ipv4Hdr::BASE_SIZE + reply_len;
        let mut pkt = Packet::alloc_and_expand(total_len);
        let mut wtr = pkt.seg0_wtr();
        eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
        ip4.emit(wtr.slice_mut(ip4.hdr_len()).unwrap());
        wtr.write(&tmp).unwrap();
        Ok(AllowOrDeny::Allow(pkt))
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
    pub inner: wire::Icmpv4Message,
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

#[cfg(test)]
mod test {
    use crate::engine::checksum::Checksum as OpteCsum;
    use crate::engine::headers::RawHeader;
    use crate::engine::icmp::IcmpHdr;
    use crate::engine::icmp::IcmpHdrRaw;
    use smoltcp::wire::Icmpv4Packet;
    use smoltcp::wire::Icmpv4Repr;

    use super::*;

    #[test]
    fn icmp4_body_csum_equals_body() {
        let data = b"reunion\0";
        let mut body_csum = OpteCsum::default();
        body_csum.add_bytes(data);

        let mut cksum_cfg = Csum::ignored();
        cksum_cfg.icmpv4 = Checksum::Both;

        let test_pkt = Icmpv4Repr::EchoRequest { ident: 7, seq_no: 7777, data };
        let mut out = vec![0u8; test_pkt.buffer_len()];
        let mut packet = Icmpv4Packet::new_unchecked(&mut out);
        test_pkt.emit(&mut packet, &cksum_cfg);

        let src = &mut out[..IcmpHdr::SIZE];
        let icmp = IcmpHdr { base: IcmpHdrRaw::new_mut(src).unwrap() };

        assert_eq!(
            Some(body_csum.finalize()),
            icmp.csum_minus_hdr().map(|mut v| v.finalize())
        );
    }
}

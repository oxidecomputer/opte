// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use super::checksum::HeaderChecksum;
use super::ether::EtherHdr;
use super::ether::EtherMeta;
use super::ether::EtherType;
use super::ip4::Ipv4Addr;
use super::ip4::Ipv4Hdr;
use super::ip4::Ipv4Meta;
use super::ip4::Protocol;
use super::ip6::UlpCsumOpt;
use super::packet::Packet;
use super::packet::PacketMeta;
use super::packet::PacketRead;
use super::packet::PacketReader;
use super::predicate::DataPredicate;
use super::predicate::EtherAddrMatch;
use super::predicate::IpProtoMatch;
use super::predicate::Ipv4AddrMatch;
use super::predicate::PortMatch;
use super::predicate::Predicate;
use super::rule::AllowOrDeny;
use super::rule::GenPacketResult;
use super::rule::HairpinAction;
use super::udp::UdpHdr;
use super::udp::UdpMeta;
use core::fmt;
use core::fmt::Display;
use opte_api::DhcpAction;
use opte_api::DhcpReplyType;
use opte_api::MacAddr;
use opte_api::SubnetRouterPair;
use serde::de;
use serde::de::Visitor;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use smoltcp::wire::DhcpPacket;
use smoltcp::wire::DhcpRepr;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::ToString;
        use alloc::vec::Vec;
    } else {
        use std::string::ToString;
        use std::vec::Vec;
    }
}

/// The DHCP message type.
///
/// Why define our own wrapper type when smoltcp already provides this
/// type? We need to use this type as part of a rule predicate value;
/// therefore it must be serializable. There are ways to get around
/// this without creating a new type; the author prefers this way as
/// it's less "magic".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageType {
    inner: smoltcp::wire::DhcpMessageType,
}

impl From<smoltcp::wire::DhcpMessageType> for MessageType {
    fn from(inner: smoltcp::wire::DhcpMessageType) -> Self {
        Self { inner }
    }
}

impl From<MessageType> for smoltcp::wire::DhcpMessageType {
    fn from(mt: MessageType) -> Self {
        mt.inner
    }
}

impl From<DhcpReplyType> for MessageType {
    fn from(rt: DhcpReplyType) -> Self {
        use smoltcp::wire::DhcpMessageType as SmolDMT;

        match rt {
            DhcpReplyType::Offer => Self::from(SmolDMT::Offer),
            DhcpReplyType::Ack => Self::from(SmolDMT::Ack),
        }
    }
}

// smoltcp provides no way to convert the Message Type to a u8, so we
// do it ourselves. It might be nice to send a PR to smoltcp to add
// this impl to its `enum_with_unknown!` macro.
impl From<MessageType> for u8 {
    fn from(mt: MessageType) -> u8 {
        use smoltcp::wire::DhcpMessageType::*;

        match mt.inner {
            Discover => 1,
            Offer => 2,
            Request => 3,
            Decline => 4,
            Ack => 5,
            Nak => 6,
            Release => 7,
            Inform => 8,
            Unknown(val) => val,
        }
    }
}

impl From<u8> for MessageType {
    fn from(val: u8) -> Self {
        use smoltcp::wire::DhcpMessageType as SmolDMT;

        Self { inner: SmolDMT::from(val) }
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
        use smoltcp::wire::DhcpMessageType::*;

        let s = match self.inner {
            Discover => "Discover".to_string(),
            Offer => "Offer".to_string(),
            Request => "Request".to_string(),
            Decline => "Decline".to_string(),
            Ack => "Ack".to_string(),
            Nak => "Nak".to_string(),
            Release => "Release".to_string(),
            Inform => "Inform".to_string(),
            Unknown(val) => format!("Unknown: {}", val),
        };
        write!(f, "{}", s)
    }
}

/// A Classes Static Route Option (121).
///
/// We must implement this type ourselves as smoltcp does not provide
/// this option out of the box. We allow for up to three routes to be
/// specified. See RFC 3442 for more detail.
#[derive(Clone, Debug)]
pub struct ClasslessStaticRouteOpt {
    routes: Vec<SubnetRouterPair>,
}

impl ClasslessStaticRouteOpt {
    /// Create a new Classless Static Route Option (121).
    ///
    /// At least one [`SubnetRouterPair`] must be specified. Up to two
    /// additional pairs may also be specified.
    pub fn new(
        r1: SubnetRouterPair,
        r2: Option<SubnetRouterPair>,
        r3: Option<SubnetRouterPair>,
    ) -> Self {
        let mut routes = vec![r1];

        if r2.is_some() {
            routes.push(r2.unwrap());
        }

        if r3.is_some() {
            routes.push(r3.unwrap());
        }

        Self { routes }
    }

    /// The length needed to encode this value into a series of bytes
    /// as described in RFC 3442.
    ///
    /// XXX Do we need to pad to 4-byte boundary?
    pub fn encode_len(&self) -> u8 {
        // * One byte to specify option code.
        // * One byte to speicfy length of option value.
        let mut total = 2u8;

        for r in &self.routes {
            total += r.encode_len();
        }

        total
    }

    /// Encode the value to a series of bytes as described in RFC 3442.
    pub fn encode(&self) -> Vec<u8> {
        let len = self.encode_len();
        assert!(len < 255);
        let mut bytes = vec![0u8; len as usize];
        bytes[0] = 121;
        // The length byte indicates the length of the encoded subnet
        // and router pairs; it does not include the option code or
        // itself.
        bytes[1] = len - 2;
        let mut pos = 2;

        for r in &self.routes {
            r.encode(&mut bytes[pos..]);
            pos += r.encode_len() as usize;
        }

        bytes
    }
}

// XXX I read up just enough on DHCP to get initial lease working.
// However, I imagine there could be post-lease messages between
// client/server and those might be unicast, at which point these
// preds need to include that possibility. Though it may also require
// a whole separate action (and this should perhaps be named the
// DhcpLeaseAction).
impl HairpinAction for DhcpAction {
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        use smoltcp::wire::DhcpMessageType as SmolDMT;

        let hdr_preds = vec![
            Predicate::InnerEtherDst(vec![EtherAddrMatch::Exact(
                MacAddr::BROADCAST,
            )]),
            Predicate::InnerEtherSrc(vec![EtherAddrMatch::Exact(
                self.client_mac.into(),
            )]),
            Predicate::InnerSrcIp4(vec![Ipv4AddrMatch::Exact(
                Ipv4Addr::ANY_ADDR,
            )]),
            Predicate::InnerDstIp4(vec![Ipv4AddrMatch::Exact(
                Ipv4Addr::LOCAL_BCAST,
            )]),
            Predicate::InnerIpProto(vec![IpProtoMatch::Exact(Protocol::UDP)]),
            Predicate::InnerDstPort(vec![PortMatch::Exact(67)]),
            Predicate::InnerSrcPort(vec![PortMatch::Exact(68)]),
        ];

        let data_preds = match self.reply_type {
            DhcpReplyType::Offer => {
                vec![DataPredicate::DhcpMsgType(MessageType::from(
                    SmolDMT::Discover,
                ))]
            }

            DhcpReplyType::Ack => {
                vec![DataPredicate::DhcpMsgType(MessageType::from(
                    SmolDMT::Request,
                ))]
            }
        };

        (hdr_preds, data_preds)
    }

    fn gen_packet(
        &self,
        _meta: &PacketMeta,
        rdr: &mut PacketReader,
    ) -> GenPacketResult {
        let body = rdr.copy_remaining();
        let client_pkt = DhcpPacket::new_checked(&body)?;
        let client_dhcp = DhcpRepr::parse(&client_pkt)?;
        let mt = MessageType::from(self.reply_type);
        // Forgive me.
        let dns_servers =
            self.dns_servers.map(|ips| ips.map(|mip| mip.map(|ip| ip.into())));

        let reply = DhcpRepr {
            message_type: mt.into(),
            transaction_id: client_dhcp.transaction_id,
            client_hardware_address: self.client_mac.into(),
            client_ip: Ipv4Addr::ANY_ADDR.into(),
            your_ip: self.client_ip.into(),
            server_ip: self.gw_ip.into(),
            router: Some(self.gw_ip.into()),
            subnet_mask: Some(self.subnet_prefix_len.to_netmask().into()),
            // There is no relay agent.
            relay_agent_ip: Ipv4Addr::ANY_ADDR.into(),
            broadcast: false,
            requested_ip: None,
            // The client identifier is an opaque token used by the
            // server, in combination with the chaddr, to uniquely
            // identify a client on the network in order to track its
            // lease status. Our world is much simpler: we are hooked
            // up directly to a guest's virtual interface, and we know
            // this IP is theirs until the port is torn down. There is
            // no tracking to do.
            client_identifier: None,
            server_identifier: Some(self.gw_ip.into()),
            parameter_request_list: None,
            dns_servers,
            max_size: None,
            lease_duration: Some(86400),
        };

        let reply_len = reply.buffer_len();
        let csr_opt =
            ClasslessStaticRouteOpt::new(self.re1, self.re2, self.re3);

        // XXX This is temporary until I can add interface to Packet
        // to initialize a zero'd mblk of N bytes and then get a
        // direct mutable reference to the PacketSeg.
        //
        // We provide exactly the number of bytes needed guaranteeing
        // that emit() should not fail.
        let mut tmp = vec![0u8; reply_len];
        let mut dhcp = DhcpPacket::new_unchecked(&mut tmp);
        let _ = reply.emit(&mut dhcp).unwrap();

        // Need to overwrite the End Option with Classless Static
        // Route Option and then write new End Option marker.
        assert_eq!(tmp.pop(), Some(255));
        tmp.extend_from_slice(&csr_opt.encode());
        tmp.push(255);
        assert_eq!(tmp.len(), reply_len + csr_opt.encode_len() as usize);

        let mut udp = UdpMeta {
            src: 67,
            dst: 68,
            len: (UdpHdr::SIZE + tmp.len()) as u16,
            ..Default::default()
        };

        let ip_dst = if client_dhcp.broadcast {
            Ipv4Addr::LOCAL_BCAST
        } else {
            self.client_ip.into()
        };

        let mut ip = Ipv4Meta {
            src: self.gw_ip,
            dst: ip_dst,
            proto: Protocol::UDP,
            total_len: Ipv4Hdr::BASE_SIZE as u16 + udp.len,
            ..Default::default()
        };
        ip.compute_hdr_csum();

        let eth_dst = if client_dhcp.broadcast {
            MacAddr::BROADCAST
        } else {
            self.client_mac.into()
        };

        let eth = EtherMeta {
            dst: eth_dst,
            src: self.gw_mac,
            ether_type: EtherType::Ipv4,
        };

        let total_len =
            EtherHdr::SIZE + Ipv4Hdr::BASE_SIZE + UdpHdr::SIZE + tmp.len();
        let mut pkt = Packet::alloc_and_expand(total_len);
        let mut wtr = pkt.seg0_wtr();
        eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
        ip.emit(wtr.slice_mut(ip.hdr_len()).unwrap());
        let mut udp_buf = [0u8; UdpHdr::SIZE];
        udp.emit(&mut udp_buf);
        let csum = ip.compute_ulp_csum(UlpCsumOpt::Full, &udp_buf, &tmp);
        udp.csum = HeaderChecksum::from(csum).bytes();
        udp.emit(wtr.slice_mut(udp.hdr_len()).unwrap());
        wtr.write(&tmp).unwrap();
        Ok(AllowOrDeny::Allow(pkt))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::engine::ip4::Ipv4Addr;
    use crate::engine::ip4::Ipv4Cidr;

    #[test]
    fn offlink_encode() {
        let if_ip = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(Ipv4Addr::from([172, 30, 7, 77]), 32)
                .unwrap(),
            router: Ipv4Addr::from([0, 0, 0, 0]),
        };

        let gw = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(Ipv4Addr::from([0, 0, 0, 0]), 0)
                .unwrap(),
            router: Ipv4Addr::from([172, 30, 4, 1]),
        };

        let opt =
            ClasslessStaticRouteOpt::new(if_ip.clone(), Some(gw.clone()), None);
        assert_eq!(
            opt.encode(),
            vec![121, 14, 32, 172, 30, 7, 77, 0, 0, 0, 0, 0, 172, 30, 4, 1]
        );
    }

    #[test]
    fn rfc3442_encode() {
        let router = Ipv4Addr::from([10, 0, 0, 1]);

        let p1 = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(Ipv4Addr::from([0, 0, 0, 0]), 0)
                .unwrap(),
            router,
        };

        let p2 = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(Ipv4Addr::from([10, 0, 0, 0]), 8)
                .unwrap(),
            router,
        };

        let p3 = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(Ipv4Addr::from([10, 0, 0, 0]), 24)
                .unwrap(),
            router,
        };

        let p4 = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(Ipv4Addr::from([10, 17, 0, 0]), 16)
                .unwrap(),
            router,
        };

        let p5 = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(Ipv4Addr::from([10, 27, 129, 0]), 24)
                .unwrap(),
            router,
        };

        let p6 = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(
                Ipv4Addr::from([10, 229, 0, 128]),
                25,
            )
            .unwrap(),
            router,
        };

        let p7 = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(
                Ipv4Addr::from([10, 198, 122, 47]),
                32,
            )
            .unwrap(),
            router,
        };

        let p8 = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(Ipv4Addr::from([10, 16, 0, 0]), 15)
                .unwrap(),
            router,
        };

        let opt = ClasslessStaticRouteOpt::new(p1.clone(), None, None);
        assert_eq!(opt.encode(), vec![121, 5, 0, 10, 0, 0, 1]);

        let opt =
            ClasslessStaticRouteOpt::new(p1.clone(), Some(p2.clone()), None);
        assert_eq!(
            opt.encode(),
            vec![121, 11, 0, 10, 0, 0, 1, 8, 10, 10, 0, 0, 1]
        );

        let opt = ClasslessStaticRouteOpt::new(
            p1.clone(),
            Some(p2.clone()),
            Some(p3.clone()),
        );
        assert_eq!(
            opt.encode(),
            vec![
                121, 19, 0, 10, 0, 0, 1, 8, 10, 10, 0, 0, 1, 24, 10, 0, 0, 10,
                0, 0, 1
            ]
        );

        let opt = ClasslessStaticRouteOpt::new(p4.clone(), None, None);
        assert_eq!(opt.encode(), vec![121, 7, 16, 10, 17, 10, 0, 0, 1],);

        let opt =
            ClasslessStaticRouteOpt::new(p4.clone(), Some(p5.clone()), None);
        assert_eq!(
            opt.encode(),
            vec![
                121, 15, 16, 10, 17, 10, 0, 0, 1, 24, 10, 27, 129, 10, 0, 0, 1
            ],
        );

        let opt = ClasslessStaticRouteOpt::new(
            p4.clone(),
            Some(p5.clone()),
            Some(p6.clone()),
        );
        assert_eq!(
            opt.encode(),
            vec![
                121, 24, 16, 10, 17, 10, 0, 0, 1, 24, 10, 27, 129, 10, 0, 0, 1,
                25, 10, 229, 0, 128, 10, 0, 0, 1
            ],
        );

        let opt =
            ClasslessStaticRouteOpt::new(p6.clone(), Some(p7.clone()), None);
        assert_eq!(
            opt.encode(),
            vec![
                121, 18, 25, 10, 229, 0, 128, 10, 0, 0, 1, 32, 10, 198, 122,
                47, 10, 0, 0, 1
            ]
        );

        let opt = ClasslessStaticRouteOpt::new(
            p6.clone(),
            Some(p7.clone()),
            Some(p8.clone()),
        );
        assert_eq!(
            opt.encode(),
            vec![
                121, 25, 25, 10, 229, 0, 128, 10, 0, 0, 1, 32, 10, 198, 122,
                47, 10, 0, 0, 1, 15, 10, 16, 10, 0, 0, 1
            ]
        );
    }
}

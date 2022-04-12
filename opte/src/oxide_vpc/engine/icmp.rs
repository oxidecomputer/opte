use core::fmt::{self, Display};

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::sync::Arc;
        use alloc::vec::Vec;
    } else {
        use std::sync::Arc;
        use std::vec::Vec;
    }
}

use smoltcp::phy::{Checksum, ChecksumCapabilities as Csum};
use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr};

use crate::api::{Direction, Ipv4Addr, OpteError};
use crate::engine::ether::{
    self, EtherAddr, EtherHdr, EtherMeta, ETHER_HDR_SZ,
};
use crate::engine::icmp::MessageType as Icmp4MessageType;
use crate::engine::ip4::{Ipv4Hdr, Ipv4Meta, Protocol, IPV4_HDR_SZ};
use crate::engine::layer::Layer;
use crate::engine::packet::{
    Initialized, Packet, PacketMeta, PacketRead, PacketReader, Parsed,
};
use crate::engine::port::{self, Port, Pos};
use crate::engine::rule::{
    Action, DataPredicate, EtherAddrMatch, GenErr, GenResult, HairpinAction,
    IpProtoMatch, Ipv4AddrMatch, Predicate, Rule,
};
use crate::oxide_vpc::PortCfg;

pub fn setup(
    port: &mut Port<port::Inactive>,
    cfg: &PortCfg,
) -> core::result::Result<(), OpteError> {
    let reply = Action::Hairpin(Arc::new(Icmp4Reply {
        gw_mac: cfg.gw_mac,
        gw_ip4: cfg.gw_ip,
        guest_mac: cfg.private_mac,
        guest_ip4: cfg.private_ip,
    }));
    let icmp = Layer::new("icmp", port.name(), vec![reply]);

    // ================================================================
    // ICMPv4 Echo Reply
    // ================================================================
    //
    // TODO At first I only predicated on ICMP protocol + Echo Request
    // message type, but in reality I need to predicate against all
    // the specifics like frame dst + src + type as well as IP src +
    // dst + proto, etc. Otherwise, the guest could ping the gateway
    // with an invalid packet but still get a response. Or even worse,
    // could ping for some other valid address but instead of getting
    // a response from that host end up getting a response from OPTE!
    // This makes me think I need to check all my other rules to make
    // sure I didn't short cut the predicates.
    //
    // XXX It would be nice to have a macro shortcut for header
    // predicate that allows you do something like:
    //
    // hdr_pred!(eth_dst: cfg.gw_mac, eth_src: cfg.guest_mac,
    // eth_type: EtherType::Ipv4, ip_src: cfg.guest_ip4, ip_dst: cfg.gw_ip4,
    // ip_proto: Protocol::ICMP)
    //
    // which would generate a Vec of the header predicates.
    let rule = Rule::new(1, icmp.action(0).unwrap().clone());
    let mut rule = rule.add_predicates(vec![
        Predicate::InnerEtherSrc(vec![EtherAddrMatch::Exact(cfg.private_mac)]),
        Predicate::InnerEtherDst(vec![EtherAddrMatch::Exact(cfg.gw_mac)]),
        Predicate::InnerSrcIp4(vec![Ipv4AddrMatch::Exact(cfg.private_ip)]),
        Predicate::InnerDstIp4(vec![Ipv4AddrMatch::Exact(cfg.gw_ip)]),
        Predicate::InnerIpProto(vec![IpProtoMatch::Exact(Protocol::ICMP)]),
    ]);
    rule.add_data_predicate(DataPredicate::Icmp4MsgType(
        Icmp4MessageType::from(smoltcp::wire::Icmpv4Message::EchoRequest),
    ));
    icmp.add_rule(Direction::Out, rule.finalize());

    port.add_layer(icmp, Pos::Before("firewall"))
}

pub struct Icmp4Reply {
    gw_mac: EtherAddr,
    gw_ip4: Ipv4Addr,
    guest_mac: EtherAddr,
    guest_ip4: Ipv4Addr,
}

impl Display for Icmp4Reply {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ICMPv4 Reply")
    }
}

impl HairpinAction for Icmp4Reply {
    fn gen_packet(
        &self,
        _meta: &PacketMeta,
        rdr: &mut PacketReader<Parsed, ()>,
    ) -> GenResult<Packet<Initialized>> {
        let body = rdr.copy_remaining();
        let guest_pkt = Icmpv4Packet::new_checked(&body)?;
        let guest_icmp = Icmpv4Repr::parse(&guest_pkt, &Csum::ignored())?;

        let (guest_ident, guest_seq_no, guest_data) = match guest_icmp {
            Icmpv4Repr::EchoRequest { ident, seq_no, data } => {
                (ident, seq_no, data)
            }

            repr => {
                // We should never hit this case because the predicate
                // should have verified that we are dealing with an
                // Echo Request. However, programming error could
                // cause this to happen -- let's not take any chances.
                return Err(GenErr::Unexpected(format!(
                    "expected an ICMP Echo Request, got {:?}",
                    repr
                )));
            }
        };

        let reply = Icmpv4Repr::EchoReply {
            ident: guest_ident,
            seq_no: guest_seq_no,
            data: guest_data,
        };

        let reply_len = reply.buffer_len();
        let mut tmp = vec![0u8; reply_len];
        let mut icmp_reply = Icmpv4Packet::new_unchecked(&mut tmp);
        let mut csum = Csum::ignored();
        csum.icmpv4 = Checksum::Tx;
        let _ = reply.emit(&mut icmp_reply, &csum);

        let mut ip4 = Ipv4Hdr::from(&Ipv4Meta {
            src: self.gw_ip4,
            dst: self.guest_ip4,
            proto: Protocol::ICMP,
        });
        ip4.set_total_len(ip4.hdr_len() as u16 + reply_len as u16);
        ip4.compute_hdr_csum();

        let eth = EtherHdr::from(&EtherMeta {
            dst: self.guest_mac,
            src: self.gw_mac,
            ether_type: ether::ETHER_TYPE_IPV4,
        });

        let mut pkt_bytes =
            Vec::with_capacity(ETHER_HDR_SZ + IPV4_HDR_SZ + reply_len);
        pkt_bytes.extend_from_slice(&eth.as_bytes());
        pkt_bytes.extend_from_slice(&ip4.as_bytes());
        pkt_bytes.extend_from_slice(&tmp);
        Ok(Packet::copy(&pkt_bytes))
    }
}

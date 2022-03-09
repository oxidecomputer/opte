use core::fmt::{self, Display};

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::sync::Arc;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::vec::Vec;

#[cfg(any(feature = "std", test))]
use std::sync::Arc;
#[cfg(any(feature = "std", test))]
use std::vec::Vec;

use smoltcp::phy::{Checksum, ChecksumCapabilities as Csum};
use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr};

use crate::ether::{self, EtherAddr, EtherHdr, EtherMeta, ETHER_HDR_SZ};
use crate::icmp::IcmpType;
use crate::ip4::{Ipv4Addr, Ipv4Hdr, Ipv4Meta, IPV4_HDR_SZ, Protocol};
use crate::layer::Layer;
use crate::packet::{
    Initialized, Packet, PacketMeta, PacketRead, PacketReader, Parsed
};
use crate::port::{self, Port, Pos};
use crate::rule::{
    Action, DataPredicate, EtherAddrMatch, GenResult, HairpinAction,
    IpProtoMatch, Ipv4AddrMatch, Predicate, Rule
};
use crate::Direction;

pub fn setup(
    port: &mut Port<port::Inactive>,
    cfg: &super::PortCfg,
) -> core::result::Result<(), port::AddLayerError> {
    let reply = Action::Hairpin(Arc::new(Icmp4Reply {
        gw_mac: cfg.gw_mac,
        gw_ip4: cfg.gw_ip,
        guest_mac: cfg.private_mac,
        // guest_ip4: cfg.private_ip,
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
    // This makes me thing I need to check all my other rules to make
    // sure I didn't short cut the predicates.
    //
    // TODO It would be nice to have a macro shortcut for header
    // predicate that allows you do something like:
    //
    // hdr_pred!(cfg.gw_mac, cfg.guest_mac, EtherType::Ipv4,
    // cfg.guest_ip4, cfg.gw_ip4, Protocol::ICMP)
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
    rule.add_data_predicate(DataPredicate::IcmpMsgType(IcmpType::EchoRequest));
    icmp.add_rule(Direction::Out, rule.finalize());

    port.add_layer(icmp, Pos::Before("firewall"))
}

pub struct Icmp4Reply {
    gw_mac: EtherAddr,
    gw_ip4: Ipv4Addr,
    guest_mac: EtherAddr,
    // guest_ip4: Ipv4Addr,
}

impl Display for Icmp4Reply {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ICMPv4 Reply")
    }
}

impl HairpinAction for Icmp4Reply {
    fn gen_packet(
        &self,
        meta: &PacketMeta,
        rdr: &mut PacketReader<Parsed, ()>,
    ) -> GenResult<Packet<Initialized>> {
        let body = rdr.copy_remaining();
        // TODO deal with failure
        let guest_pkt = Icmpv4Packet::new_checked(&body).unwrap();
        // TODO deal with failure
        let guest_icmp = Icmpv4Repr::parse(&guest_pkt, &Csum::ignored())
            .unwrap();

        let (guest_ident, guest_seq_no, guest_data) = match guest_icmp {
            Icmpv4Repr::EchoRequest { ident, seq_no, data } => {
                (ident, seq_no, data)
            }
            _ => todo!("this shouldn't happen, but deal with it somehow"),
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
            dst: meta.inner.ip.as_ref().unwrap().ip4().unwrap().src,
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

#[test]
fn tmp_icmp() {
    let guest_mac = EtherAddr::from([0xa8, 0x40, 0x25, 0xfb, 0x8e, 0xa0]);
    let guest_ip4 = Ipv4Addr::new([192, 168, 1, 245]);
    let gw_mac = EtherAddr::from([0xa8, 0x40, 0x25, 0x77, 0x77, 0x77]);
    let gw_ip4 = Ipv4Addr::new([192, 168, 1, 1]);
    let  bytes = b"reunion\0";
    let mut csum = Csum::ignored();
    csum.icmpv4 = Checksum::Tx;

    let reply = Icmpv4Repr::EchoReply {
        ident: 7777,
        seq_no: 99,
        data: &bytes[..],
    };

    let reply_len = reply.buffer_len();
    let mut tmp = vec![0u8; reply_len];
    let mut icmp_reply = Icmpv4Packet::new_unchecked(&mut tmp);
    let _ = reply.emit(&mut icmp_reply, &csum);

    let mut ip4 = Ipv4Hdr::from(&Ipv4Meta {
        src: gw_ip4,
        dst: guest_ip4,
        proto: Protocol::ICMP,
    });
    ip4.set_total_len(ip4.hdr_len() as u16 + reply_len as u16);
    ip4.compute_hdr_csum();

    let eth = EtherHdr::from(&EtherMeta {
        dst: guest_mac,
        src: gw_mac,
        ether_type: ether::ETHER_TYPE_IPV4,
    });

    let mut pkt_bytes =
        Vec::with_capacity(ETHER_HDR_SZ + IPV4_HDR_SZ + reply_len);
    pkt_bytes.extend_from_slice(&eth.as_bytes());
    pkt_bytes.extend_from_slice(&ip4.as_bytes());
    pkt_bytes.extend_from_slice(&tmp);

    // Can't currently parse this because Packet doesn't support ICMP.
    // Packet::copy(&pkt_bytes).parse().unwrap();


    // TODO: Create method for turning test data into packet captures.
    // Then I could add some type of compile-time flag/option to
    // create captures of test cases so that people can inspect them in
    // wireshark.
    use std::fs::File;
    use std::io::prelude::*;
    use pcap_parser::{Linktype, PcapHeader, ToVec};
    use pcap_parser::pcap::LegacyPcapBlock;

    let mut hdr = PcapHeader {
        magic_number: 0xa1b2c3d4,
        version_major: 2,
        version_minor: 4,
        thiszone: 0,
        sigfigs: 0,
        snaplen: 1500,
        network: Linktype::ETHERNET,
    };

    let mut block = LegacyPcapBlock {
        ts_sec: 7777,
        ts_usec: 7777,
        caplen: pkt_bytes.len() as u32,
        origlen: pkt_bytes.len() as u32,
        data: &pkt_bytes,
    };

    let hdr_bytes = hdr.to_vec().unwrap();
    let block_bytes = block.to_vec().unwrap();
    let mut file = File::create("icmp.pcap").unwrap();
    file.write_all(&hdr_bytes).unwrap();
    file.write_all(&block_bytes).unwrap();
}

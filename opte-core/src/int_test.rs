//! Integration tests.
//!
//! The idea behind these tests is to use actual packet captures to
//! regression test known good captures. This is done by taking a
//! packet capture in the guest as well as on the host -- one for each
//! side of OPTE. These captures are then used to regression test an
//! OPTE pipeline by single-stepping the packets in each capture and
//! verifying that OPTE processing produces the expected bytes.
//!
//! TODO: We should also write tests which programmatically build
//! packets in order to better test more interesting scenarios. For
//! example, attempt an inbound connect to the guest's HTTP server,
//! verify it's blocked by firewall, add a new rule to allow incoming
//! on 80/443, verify the next request passes, remove the rules,
//! verify it once again is denied, etc.
use std::fs;
use std::ops::Range;
use std::prelude::v1::*;
use std::time::{Duration, Instant};

extern crate pcap_parser;
use pcap_parser::pcap::{self, LegacyPcapBlock, PcapHeader};

use crate::firewallng::Firewall;
use crate::flow_table::FLOW_DEF_EXPIRE_SECS;
use crate::input::{VecPacket, VecPacketReader};
use crate::ip4::Protocol;
use crate::layer::Layer;
use crate::nat::{DynNat4, NatPool};
use crate::parse;
use crate::port::{Port, Pos};
use crate::rule::{
    Action, IpProtoMatch, Ipv4AddrMatch, Predicate, Rule, RuleAction,
};
use crate::Direction::{self, *};

fn get_header(offset: &[u8]) -> (&[u8], PcapHeader) {
    match pcap::parse_pcap_header(offset) {
        Ok((new_offset, header)) => (new_offset, header),
        Err(e) => panic!("failed to get header: {:?}", e),
    }
}

fn next_block(offset: &[u8]) -> (&[u8], LegacyPcapBlock) {
    match pcap::parse_pcap_frame(offset) {
        Ok((new_offset, block)) => {
            // We always want access to the entire packet.
            assert_eq!(block.origlen, block.caplen);
            (new_offset, block)
        }

        Err(e) => panic!("failed to get next block: {:?}", e),
    }
}

/// Test a DNS lookup from guest to internet.
///
/// TODO Would be nice to verify if packet hits a layer rule or flow
/// or hits the UFT.
///
/// TODO Would also be nice to verify the number of hits against LFTs
/// and UFT.
#[test]
fn outgoing_dns_lookup() {
    let sub = "10.0.0.0/24".parse().unwrap();
    let guest_mac = [0x02, 0x08, 0x20, 0xd8, 0x35, 0xcf];
    let guest_ip = "10.0.0.210".parse().unwrap();
    let pub_mac = [0xa8, 0x40, 0x25, 0x0, 0x0, 0x63];
    let pub_ip = "10.0.0.99".parse().unwrap();
    let port = Port::new("int_test".to_string(), guest_mac);

    // Setup firewall.
    let fw_layer = Firewall::create_layer();
    port.add_layer(fw_layer, Pos::First);

    // Setup Dynamic NAT
    let mut nat_pool = NatPool::new();
    nat_pool.add(guest_ip, pub_ip, Range { start: 1025, end: 4096 });
    port.set_nat_pool(nat_pool);
    let nat =
        DynNat4::new("dyn-nat4".to_string(), guest_ip, guest_mac, pub_mac);
    let nat_layer = Layer::new("dyn-nat4", Action::Stateful(Box::new(nat)));
    let mut rule = Rule::new(1, RuleAction::Allow);
    rule.add_predicate(Predicate::InnerIpProto(vec![
        IpProtoMatch::Exact(Protocol::TCP),
        IpProtoMatch::Exact(Protocol::UDP),
    ]));
    rule.add_predicate(Predicate::Not(Box::new(Predicate::InnerDstIp4(vec![
        Ipv4AddrMatch::Prefix(sub),
    ]))));
    nat_layer.add_rule(Direction::Out, rule);
    port.add_layer(nat_layer, Pos::After("firewall"));

    let gpath = "dns-lookup-guest.pcap";
    let gbytes = fs::read(gpath).unwrap();
    let hpath = "dns-lookup-host.pcap";
    let hbytes = fs::read(hpath).unwrap();

    assert_eq!(port.num_flows("dyn-nat4", In), 0);
    assert_eq!(port.num_flows("dyn-nat4", Out), 0);
    assert_eq!(port.num_flows("firewall", In), 0);
    assert_eq!(port.num_flows("firewall", Out), 0);

    // ================================================================
    // Packet 1 (DNS query)
    // ================================================================
    let (gbytes, _) = get_header(&gbytes[..]);
    let (gbytes, gblock) = next_block(&gbytes);
    let mut pkt = VecPacket::copy_slice(gblock.data);
    let mut rdr = VecPacketReader::new(&mut pkt);
    let now = Instant::now();
    let res = port.process(Out, &mut rdr, 0);
    assert!(res.is_some());
    assert_eq!(port.num_flows("dyn-nat4", In), 0);
    assert_eq!(port.num_flows("dyn-nat4", Out), 0);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    parse::set_headers(&res.unwrap(), VecPacketReader::new(&mut pkt));

    // TODO While it's easy to compare straight bytes right now this
    // is not how we want to do it moving forward. Instead, we'll want
    // to compare each individual header so we can give detailed error
    // reports on test failure. Furthemore, as more layers are added
    // to the stack it will be rare that a packet goes through
    // processing untouched (at least in the case of the Oxide Network
    // it should never happen for guest traffic). But, for now, this
    // works.
    let (hbytes, _hdr) = get_header(&hbytes[..]);
    let (hbytes, hblock) = next_block(&hbytes);
    assert_eq!(pkt.get_bytes(), hblock.data);

    // ================================================================
    // Packet 2 (DNS query response)
    // ================================================================
    let (_hbytes, hblock) = next_block(&hbytes);
    let mut pkt = VecPacket::copy_slice(hblock.data);
    let mut rdr = VecPacketReader::new(&mut pkt);
    let res = port.process(In, &mut rdr, 0);
    assert!(res.is_some());
    assert_eq!(port.num_flows("dyn-nat4", In), 0);
    assert_eq!(port.num_flows("dyn-nat4", Out), 0);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    parse::set_headers(&res.unwrap(), VecPacketReader::new(&mut pkt));
    let (_gbytes, gblock) = next_block(&gbytes);
    assert_eq!(pkt.get_bytes(), gblock.data);

    // ================================================================
    // Expiration
    // ================================================================

    // Verify that the flow is still valid when it should be.
    port.expire_flows(now + Duration::new(FLOW_DEF_EXPIRE_SECS as u64, 0));
    assert_eq!(port.num_flows("dyn-nat4", In), 0);
    assert_eq!(port.num_flows("dyn-nat4", Out), 0);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    // Verify the flow is expired when it should be.
    port.expire_flows(now + Duration::new(FLOW_DEF_EXPIRE_SECS as u64 + 1, 0));
    assert_eq!(port.num_flows("dyn-nat4", In), 0);
    assert_eq!(port.num_flows("dyn-nat4", Out), 0);
    assert_eq!(port.num_flows("firewall", In), 0);
    assert_eq!(port.num_flows("firewall", Out), 0);
}

// Test an outgoing HTTP request/connection. I happened upon a small
// connectivity check that Ubuntu makes which is good for this
// smaller-scale test (Ubuntu uses this to check for captive portals).
#[test]
fn outgoing_http_req() {
    let sub = "10.0.0.0/24".parse().unwrap();
    let guest_mac = [0x02, 0x08, 0x20, 0xd8, 0x35, 0xcf];
    let guest_ip = "10.0.0.210".parse().unwrap();
    let pub_mac = [0xa8, 0x40, 0x25, 0x0, 0x0, 0x63];
    let pub_ip = "10.0.0.99".parse().unwrap();
    let port = Port::new("int_test".to_string(), guest_mac);

    // Setup firewall.
    let fw_layer = Firewall::create_layer();
    port.add_layer(fw_layer, Pos::First);

    // Setup Dynamic NAT
    let mut nat_pool = NatPool::new();
    // We have to specify exactly one port to match up with the actual
    // port from the pcap.
    nat_pool.add(guest_ip, pub_ip, Range { start: 3839, end: 3840 });
    port.set_nat_pool(nat_pool);
    let nat =
        DynNat4::new("dyn-nat4".to_string(), guest_ip, guest_mac, pub_mac);
    let nat_layer = Layer::new("dyn-nat4", Action::Stateful(Box::new(nat)));
    let mut rule = Rule::new(1, RuleAction::Allow);
    rule.add_predicate(Predicate::InnerIpProto(vec![
        IpProtoMatch::Exact(Protocol::TCP),
        IpProtoMatch::Exact(Protocol::UDP),
    ]));
    rule.add_predicate(Predicate::Not(Box::new(Predicate::InnerDstIp4(vec![
        Ipv4AddrMatch::Prefix(sub),
    ]))));
    nat_layer.add_rule(Direction::Out, rule);
    port.add_layer(nat_layer, Pos::After("firewall"));

    let gpath = "http-out-guest.pcap";
    let gbytes = fs::read(gpath).unwrap();
    let hpath = "http-out-host.pcap";
    let hbytes = fs::read(hpath).unwrap();

    // Assert the baseline before any packet processing occurs.
    assert_eq!(port.num_flows("dyn-nat4", In), 0);
    assert_eq!(port.num_flows("dyn-nat4", Out), 0);
    assert_eq!(port.num_flows("firewall", In), 0);
    assert_eq!(port.num_flows("firewall", Out), 0);

    // ================================================================
    // Packet 1 (SYN)
    // ================================================================
    let (gbytes, _) = get_header(&gbytes[..]);
    let (gbytes, gblock) = next_block(gbytes);
    let mut pkt = VecPacket::copy_slice(gblock.data);
    let mut rdr = VecPacketReader::new(&mut pkt);
    let now = Instant::now();
    let res = port.process(Out, &mut rdr, 0);
    assert!(res.is_some());
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    parse::set_headers(&res.unwrap(), VecPacketReader::new(&mut pkt));
    let (hbytes, _) = get_header(&hbytes[..]);
    let (hbytes, hblock) = next_block(hbytes);
    assert_eq!(pkt.get_bytes(), hblock.data);

    // ================================================================
    // Packet 2 (SYN+ACK)
    // ================================================================
    let (hbytes, hblock) = next_block(hbytes);
    let mut pkt = VecPacket::copy_slice(hblock.data);
    let mut rdr = VecPacketReader::new(&mut pkt);
    let res = port.process(In, &mut rdr, 0);
    assert!(res.is_some());
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    parse::set_headers(&res.unwrap(), VecPacketReader::new(&mut pkt));
    let (gbytes, gblock) = next_block(gbytes);
    assert_eq!(pkt.get_bytes(), gblock.data);

    // ================================================================
    // Packet 3 (ACK)
    // ================================================================
    let (gbytes, gblock) = next_block(gbytes);
    let mut pkt = VecPacket::copy_slice(gblock.data);
    let mut rdr = VecPacketReader::new(&mut pkt);
    let res = port.process(Out, &mut rdr, 0);
    assert!(res.is_some());
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    parse::set_headers(&res.unwrap(), VecPacketReader::new(&mut pkt));
    let (hbytes, hblock) = next_block(hbytes);
    assert_eq!(pkt.get_bytes(), hblock.data);

    // ================================================================
    // Packet 4 (HTTP GET)
    // ================================================================
    let (gbytes, gblock) = next_block(gbytes);
    let mut pkt = VecPacket::copy_slice(gblock.data);
    let mut rdr = VecPacketReader::new(&mut pkt);
    let res = port.process(Out, &mut rdr, 0);
    assert!(res.is_some());
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    parse::set_headers(&res.unwrap(), VecPacketReader::new(&mut pkt));
    let (hbytes, hblock) = next_block(hbytes);
    assert_eq!(pkt.get_bytes(), hblock.data);

    // ================================================================
    // Packet 5 (ACK #4)
    // ================================================================
    let (hbytes, hblock) = next_block(hbytes);
    let mut pkt = VecPacket::copy_slice(hblock.data);
    let mut rdr = VecPacketReader::new(&mut pkt);
    let res = port.process(In, &mut rdr, 0);
    assert!(res.is_some());
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    parse::set_headers(&res.unwrap(), VecPacketReader::new(&mut pkt));
    let (gbytes, gblock) = next_block(gbytes);
    assert_eq!(pkt.get_bytes(), gblock.data);

    // ================================================================
    // Packet 6 (HTTP 301)
    // ================================================================
    let (hbytes, hblock) = next_block(hbytes);
    let mut pkt = VecPacket::copy_slice(hblock.data);
    let mut rdr = VecPacketReader::new(&mut pkt);
    let res = port.process(In, &mut rdr, 0);
    assert!(res.is_some());
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    parse::set_headers(&res.unwrap(), VecPacketReader::new(&mut pkt));
    let (gbytes, gblock) = next_block(gbytes);
    assert_eq!(pkt.get_bytes(), gblock.data);

    // ================================================================
    // Packet 7 (ACK #6)
    // ================================================================
    let (gbytes, gblock) = next_block(gbytes);
    let mut pkt = VecPacket::copy_slice(gblock.data);
    let mut rdr = VecPacketReader::new(&mut pkt);
    let res = port.process(Out, &mut rdr, 0);
    assert!(res.is_some());
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    parse::set_headers(&res.unwrap(), VecPacketReader::new(&mut pkt));
    let (hbytes, hblock) = next_block(hbytes);
    assert_eq!(pkt.get_bytes(), hblock.data);

    // ================================================================
    // Packet 8 (Guest FIN ACK)
    // ================================================================
    let (gbytes, gblock) = next_block(gbytes);
    let mut pkt = VecPacket::copy_slice(gblock.data);
    let mut rdr = VecPacketReader::new(&mut pkt);
    let res = port.process(Out, &mut rdr, 0);
    assert!(res.is_some());
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    parse::set_headers(&res.unwrap(), VecPacketReader::new(&mut pkt));
    let (hbytes, hblock) = next_block(hbytes);
    assert_eq!(pkt.get_bytes(), hblock.data);

    // ================================================================
    // Packet 9 (ACK #8)
    // ================================================================
    let (hbytes, hblock) = next_block(hbytes);
    let mut pkt = VecPacket::copy_slice(hblock.data);
    let mut rdr = VecPacketReader::new(&mut pkt);
    let res = port.process(In, &mut rdr, 0);
    assert!(res.is_some());
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    parse::set_headers(&res.unwrap(), VecPacketReader::new(&mut pkt));
    let (gbytes, gblock) = next_block(gbytes);
    assert_eq!(pkt.get_bytes(), gblock.data);

    // ================================================================
    // Packet 10 (Remote FIN ACK)
    // ================================================================
    let (hbytes, hblock) = next_block(hbytes);
    let mut pkt = VecPacket::copy_slice(hblock.data);
    let mut rdr = VecPacketReader::new(&mut pkt);
    let res = port.process(In, &mut rdr, 0);
    assert!(res.is_some());
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    parse::set_headers(&res.unwrap(), VecPacketReader::new(&mut pkt));
    let (gbytes, gblock) = next_block(gbytes);
    assert_eq!(pkt.get_bytes(), gblock.data);

    // ================================================================
    // Packet 11 (ACK #10)
    // ================================================================
    let (_gbytes, gblock) = next_block(gbytes);
    let mut pkt = VecPacket::copy_slice(gblock.data);
    let mut rdr = VecPacketReader::new(&mut pkt);
    let res = port.process(Out, &mut rdr, 0);
    assert!(res.is_some());
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    parse::set_headers(&res.unwrap(), VecPacketReader::new(&mut pkt));
    let (_hbytes, hblock) = next_block(hbytes);
    assert_eq!(pkt.get_bytes(), hblock.data);

    // ================================================================
    // Expiration
    // ================================================================

    // TODO: TCP flow table needs to hook into expiry, in which case
    // the flows would all expire at the moment of connection
    // teardown.

    // Verify that the flow is still valid when it should be.
    port.expire_flows(now + Duration::new(FLOW_DEF_EXPIRE_SECS as u64, 0));
    assert_eq!(port.num_flows("dyn-nat4", In), 1);
    assert_eq!(port.num_flows("dyn-nat4", Out), 1);
    assert_eq!(port.num_flows("firewall", In), 1);
    assert_eq!(port.num_flows("firewall", Out), 1);

    // Verify the flow is expired when it should be.
    port.expire_flows(now + Duration::new(FLOW_DEF_EXPIRE_SECS as u64 + 1, 0));
    assert_eq!(port.num_flows("dyn-nat4", In), 0);
    assert_eq!(port.num_flows("dyn-nat4", Out), 0);
    assert_eq!(port.num_flows("firewall", In), 0);
    assert_eq!(port.num_flows("firewall", Out), 0);
}

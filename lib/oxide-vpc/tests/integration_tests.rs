// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Integration tests.
//!
//! The idea behind these tests is to use actual packet captures to
//! regression test known good captures. This is done by taking a
//! packet capture in the guest as well as on the host -- one for each
//! side of OPTE. These captures are then used to regression test an
//! OPTE pipeline by single-stepping the packets in each capture and
//! verifying that OPTE processing produces the expected bytes.

use common::icmp::*;
use common::*;
use opte::api::MacAddr;
use opte::api::OpteError;
use opte::ddi::mblk::MsgBlk;
use opte::ddi::time::Moment;
use opte::engine::Direction;
use opte::engine::arp::ARP_HTYPE_ETHERNET;
use opte::engine::arp::ArpEthIpv4;
use opte::engine::arp::ArpEthIpv4Ref;
use opte::engine::arp::ValidArpEthIpv4;
use opte::engine::dhcpv6;
use opte::engine::ether::Ethernet;
use opte::engine::ether::EthernetRef;
use opte::engine::flow_table::FLOW_DEF_EXPIRE_SECS;
use opte::engine::geneve::Vni;
use opte::engine::ip::L3;
use opte::engine::ip::ValidL3;
use opte::engine::ip::v4::Ipv4Addr;
use opte::engine::ip::v4::Ipv4Ref;
use opte::engine::ip::v4::ValidIpv4;
use opte::engine::ip::v6::Ipv6;
use opte::engine::ip::v6::Ipv6Ref;
use opte::engine::ip::v6::ValidIpv6;
use opte::engine::packet::InnerFlowId;
use opte::engine::packet::MblkFullParsed;
use opte::engine::packet::MismatchError;
use opte::engine::packet::Packet;
use opte::engine::parse::ValidUlp;
use opte::engine::port::ProcessError;
use opte::engine::tcp::TIME_WAIT_EXPIRE_SECS;
use opte::engine::tcp::TcpState;
use opte::ingot::geneve::GeneveRef;
use opte::ingot::icmp::IcmpV6Ref;
use opte::ingot::tcp::TcpRef;
use opte::ingot::types::Emit;
use opte::ingot::types::HeaderLen;
use opte::ingot::types::HeaderParse;
use opte::ingot::udp::Udp;
use opte::ingot::udp::UdpRef;
use opte_test_utils as common;
use oxide_vpc::api::ExternalIpCfg;
use oxide_vpc::api::FirewallRule;
use oxide_vpc::api::RouterClass;
use oxide_vpc::api::VpcCfg;
use oxide_vpc::engine::overlay::BOUNDARY_SERVICES_VNI;
use pcap::*;
use smoltcp::phy::ChecksumCapabilities as CsumCapab;
use smoltcp::wire::Icmpv4Packet;
use smoltcp::wire::Icmpv4Repr;
use smoltcp::wire::Icmpv6Message;
use smoltcp::wire::Icmpv6Packet;
use smoltcp::wire::Icmpv6Repr;
use smoltcp::wire::IpAddress;
use smoltcp::wire::Ipv6Address;
use smoltcp::wire::NdiscNeighborFlags;
use smoltcp::wire::NdiscRepr;
use smoltcp::wire::NdiscRouterFlags;
use smoltcp::wire::RawHardwareAddress;
use std::collections::BTreeMap;
use std::prelude::v1::*;
use std::time::Duration;
use uuid::Uuid;

// If we are running `cargo test`, then make sure to
// register the USDT probes before running any tests.
#[cfg(test)]
#[ctor::ctor]
fn register_usdt() {
    usdt::register_probes().unwrap();
}

fn lab_cfg() -> VpcCfg {
    let ip_cfg = IpCfg::Ipv4(Ipv4Cfg {
        vpc_subnet: "172.20.14.0/24".parse().unwrap(),
        private_ip: "172.20.14.16".parse().unwrap(),
        gateway_ip: "172.20.14.1".parse().unwrap(),
        external_ips: ExternalIpCfg {
            snat: Some(SNat4Cfg {
                external_ip: "76.76.21.21".parse().unwrap(),
                ports: 1025..=4096,
            }),
            ephemeral_ip: None,
            floating_ips: vec![],
        },
    });
    VpcCfg {
        ip_cfg,
        guest_mac: MacAddr::from([0xAA, 0x00, 0x04, 0x00, 0xFF, 0x10]),
        gateway_mac: MacAddr::from([0xAA, 0x00, 0x04, 0x00, 0xFF, 0x01]),

        // XXX These values don't really mean anything in this
        // context. This "lab cfg" was created during the early days
        // of OPTE dev when the VPC implementation was just part of an
        // existing IPv4 network. Any tests relying on this cfg need
        // to be rewritten or deleted.
        vni: Vni::new(BOUNDARY_SERVICES_VNI).unwrap(),
        // Site 0xF7, Rack 1, Sled 1, Interface 1
        phys_ip: Ipv6Addr::from([
            0xFD00, 0x0000, 0x00F7, 0x0101, 0x0000, 0x0000, 0x0000, 0x0001,
        ]),
    }
}

// Verify that the list of layers is what we expect.
#[test]
fn check_layers() {
    let g1_cfg = g1_cfg();
    let g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    let port_layers = g1.port.layers();
    assert_eq!(&VPC_LAYERS[..], &port_layers);
}

// Verify Port transition from Ready -> Running.
#[test]
fn port_transition_running() {
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.vpc_map.add(g2_cfg.ipv4().private_ip.into(), g2_cfg.phys_addr());

    // ================================================================
    // Try processing the packet while taking the port through a Ready
    // -> Running.
    // ================================================================
    let mut pkt1_m = tcp_telnet_syn(&g1_cfg, &g2_cfg);

    let pkt1 = parse_outbound(&mut pkt1_m, GenericUlp {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    assert!(matches!(res, Err(ProcessError::BadState(_))));
    assert_port!(g1);
    g1.port.start();
    set!(g1, "port_state=running");
    let pkt1 = parse_outbound(&mut pkt1_m, GenericUlp {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    assert!(matches!(res, Ok(Modified(_))));
    incr!(
        g1,
        [
            "firewall.flows.in, firewall.flows.out",
            "uft.out",
            "stats.port.out_modified, stats.port.out_uft_miss"
        ]
    );
}

// Verify a Port reset transitions it to the Ready state and clears
// all flow state.
#[test]
fn port_transition_reset() {
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.vpc_map.add(g2_cfg.ipv4().private_ip.into(), g2_cfg.phys_addr());

    // ================================================================
    // Try processing the packet while taking the port through a Ready
    // -> Running -> Ready transition. Verify that flows are cleared
    // but rules remain.
    // ================================================================
    let mut pkt1_m = tcp_telnet_syn(&g1_cfg, &g2_cfg);
    let pkt1 = parse_outbound(&mut pkt1_m, GenericUlp {}).unwrap();
    g1.port.start();
    set!(g1, "port_state=running");
    let res = g1.port.process(Out, pkt1);
    expect_modified!(res, pkt1_m);
    incr!(
        g1,
        [
            "firewall.flows.in, firewall.flows.out",
            "uft.out",
            "stats.port.out_modified, stats.port.out_uft_miss"
        ]
    );
    g1.port.reset();
    update!(g1, ["set:port_state=ready", "zero_flows"]);
    let pkt1 = parse_outbound(&mut pkt1_m, GenericUlp {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    assert!(matches!(res, Err(ProcessError::BadState(_))));
    assert_port!(g1);
}

// Verify that pausing a port:
//
// * Prevents any further traffic from being processed.
// * Prevents modification of rules.
// * Allows read-only introspection of state.
#[test]
fn port_transition_pause() {
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    let mut g2 =
        oxide_net_setup("g2_port", &g2_cfg, Some(g1.vpc_map.clone()), None);

    // Allow incoming connections to port 80 on g1.
    let fw_rule: FirewallRule =
        "action=allow priority=10 dir=in protocol=tcp port=80".parse().unwrap();
    firewall::add_fw_rule(
        &g1.port,
        &AddFwRuleReq { port_name: g1.port.name().to_string(), rule: fw_rule },
    )
    .unwrap();
    incr!(g1, ["epoch", "firewall.rules.in"]);
    g1.port.start();
    set!(g1, "port_state=running");
    g2.port.start();
    set!(g2, "port_state=running");

    // ================================================================
    // Send the HTTP SYN.
    // ================================================================
    let mut pkt1_m = http_syn(&g2_cfg, &g1_cfg);
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g2.port.process(Out, pkt1);
    expect_modified!(res, pkt1_m);
    incr!(
        g2,
        [
            "firewall.flows.out, firewall.flows.in",
            "uft.out",
            "stats.port.out_modified, stats.port.out_uft_miss"
        ]
    );

    let pkt1 = parse_inbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(In, pkt1);
    expect_modified!(res, pkt1_m);
    incr!(
        g1,
        [
            "firewall.flows.in, firewall.flows.out",
            "uft.in",
            "stats.port.in_modified, stats.port.in_uft_miss"
        ]
    );

    // ================================================================
    // Pause the port and verify the internal state. Make sure that
    // introspective APIs are allowed.
    // ================================================================
    g2.port.pause().unwrap();
    set!(g2, "port_state=paused");
    let _ = g2.port.list_layers();
    let _ = g2.port.dump_layer("firewall").unwrap();
    let _ = g2.port.dump_tcp_flows().unwrap();
    let _ = g2.port.dump_uft();

    // ================================================================
    // Verify that APIs which modify state are not allowed.
    // ================================================================
    assert!(matches!(g2.port.clear_uft(), Err(OpteError::BadState(_))));
    assert!(matches!(g2.port.expire_flows(), Err(OpteError::BadState(_))));
    // This exercises Port::remove_rule().
    assert!(matches!(
        router::del_entry(
            &g2.port,
            IpCidr::Ip4(g2_cfg.ipv4_cfg().unwrap().vpc_subnet),
            RouterTarget::VpcSubnet(IpCidr::Ip4(
                g2_cfg.ipv4_cfg().unwrap().vpc_subnet
            )),
            RouterClass::System,
        ),
        Err(OpteError::BadState(_))
    ));

    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g2.port.process(Out, pkt1);
    assert!(matches!(res, Err(ProcessError::BadState(_))));
    let fw_rule: FirewallRule =
        "action=allow priority=10 dir=in protocol=tcp port=22".parse().unwrap();
    // This exercises Port::add_rule().
    let res = firewall::add_fw_rule(
        &g2.port,
        &AddFwRuleReq {
            port_name: g2.port.name().to_string(),
            rule: fw_rule.clone(),
        },
    );
    assert!(matches!(res, Err(OpteError::BadState(_))));
    let res = firewall::set_fw_rules(
        &g2.port,
        &SetFwRulesReq {
            port_name: g2.port.name().to_string(),
            rules: vec![fw_rule],
        },
    );
    assert!(matches!(res, Err(OpteError::BadState(_))));

    // ================================================================
    // Verify that the port can move back to Running and process more
    // traffic.
    // ================================================================
    g2.port.start();
    set!(g2, "port_state=running");

    let mut pkt2_m = http_syn_ack(&g1_cfg, &g2_cfg);
    let pkt2 = parse_outbound(&mut pkt2_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt2);
    expect_modified!(res, pkt2_m);
    incr!(g1, ["uft.out", "stats.port.out_modified, stats.port.out_uft_miss"]);

    let pkt2 = parse_inbound(&mut pkt2_m, VpcParser {}).unwrap();
    let res = g2.port.process(In, pkt2);
    expect_modified!(res, pkt2_m);
    incr!(g2, ["uft.in", "stats.port.in_modified, stats.port.in_uft_miss"]);
}

#[test]
fn add_remove_fw_rule() {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    // Add a new inbound rule.
    let rule = "dir=in action=allow priority=10 protocol=TCP";
    firewall::add_fw_rule(
        &g1.port,
        &AddFwRuleReq {
            port_name: g1.port.name().to_string(),
            rule: rule.parse().unwrap(),
        },
    )
    .unwrap();
    incr!(g1, ["epoch", "firewall.rules.in"]);

    // Remove the rule just added, by ID.
    firewall::rem_fw_rule(
        &g1.port,
        &oxide_vpc::api::RemFwRuleReq {
            port_name: g1.port.name().to_string(),
            dir: In,
            id: 0,
        },
    )
    .unwrap();
    update!(g1, ["incr:epoch", "decr:firewall.rules.in"]);
}

// Verify that the guest can ping the virtual gateway.
#[test]
fn gateway_icmp4_ping() {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");
    let mut pcap = PcapBuilder::new("gateway_icmpv4_ping.pcap");
    let ident = 7;
    let seq_no = 777;
    let data = b"reunion\0";

    // ================================================================
    // Generate an ICMP Echo Request from G1 to Virtual GW
    // ================================================================
    let mut pkt1_m = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip.into(),
        g1_cfg.ipv4_cfg().unwrap().gateway_ip.into(),
        ident,
        seq_no,
        &data[..],
        1,
    );
    pcap.add_pkt(&pkt1_m);

    // ================================================================
    // Run the Echo Request through g1's port in the outbound
    // direction and verify it results in an Echo Reply Hairpin packet
    // back to guest.
    // ================================================================
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    let mut hp = match res {
        Ok(Hairpin(hp)) => hp,
        _ => panic!("expected Hairpin, got {:?}", res),
    };
    incr!(g1, ["stats.port.out_uft_miss"]);
    // In this case we are parsing a hairpin reply, so we can't use
    // the VpcParser since it would expect any inbound packet to be
    // encapsulated.
    pcap.add_pkt(&hp);
    // let reply = hp.parse(In, GenericUlp {}).unwrap();
    let reply = parse_inbound(&mut hp, GenericUlp {}).unwrap().to_full_meta();
    let meta = reply.meta();
    assert!(meta.outer_ether().is_none());
    assert!(meta.outer_ip().is_none());
    assert!(meta.outer_encap_geneve_vni_and_origin().is_none());

    let eth = meta.inner_ether();
    assert_eq!(eth.source(), g1_cfg.gateway_mac);
    assert_eq!(eth.destination(), g1_cfg.guest_mac);

    match meta.inner_l3().as_ref().unwrap() {
        L3::Ipv4(ip4) => {
            assert_eq!(ip4.source(), g1_cfg.ipv4_cfg().unwrap().gateway_ip);
            assert_eq!(
                ip4.destination(),
                g1_cfg.ipv4_cfg().unwrap().private_ip
            );
            assert_eq!(ip4.protocol(), IngotIpProto::ICMP);
        }

        L3::Ipv6(_) => panic!("expected inner IPv4 metadata, got IPv6"),
    }

    let mut reply_body = meta.inner_ulp().expect("ICMPv4 is a ULP").emit_vec();
    reply.meta().append_remaining(&mut reply_body);
    let reply_pkt = Icmpv4Packet::new_checked(&reply_body).unwrap();
    let mut csum = CsumCapab::ignored();
    csum.ipv4 = smoltcp::phy::Checksum::Rx;
    csum.icmpv4 = smoltcp::phy::Checksum::Rx;
    let reply_icmp = Icmpv4Repr::parse(&reply_pkt, &csum).unwrap();
    match reply_icmp {
        Icmpv4Repr::EchoReply {
            ident: r_ident,
            seq_no: r_seq_no,
            data: r_data,
        } => {
            assert_eq!(r_ident, ident);
            assert_eq!(r_seq_no, seq_no);
            assert_eq!(r_data, data);
        }

        _ => panic!("expected Echo Reply, got {:?}", reply_icmp),
    }
}

// Verify that guest packet bodies are correctly pulled up if they run
// past the same segment(s) containing the rest of the headers.
#[test]
fn packet_body_pullup() {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");
    let ident = 7;
    let seq_no = 777;
    let data = c"...did Sephiroth do this?";

    // ================================================================
    // Generate an ICMP Echo Request from G1 to Virtual GW
    // ================================================================
    let mut pkt1_m = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip.into(),
        g1_cfg.ipv4_cfg().unwrap().gateway_ip.into(),
        ident,
        seq_no,
        data.to_bytes_with_nul(),
        // Instruct the packet builder to split the body 8 bytes in.
        4,
    );

    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    let hp = match res {
        Ok(Hairpin(hp)) => hp,
        _ => panic!("expected Hairpin, got {:?}", res),
    };

    // Verify that the contents are correctly replicated.
    let (_hdrs, new_body) =
        hp.split_at(hp.len() - data.to_bytes_with_nul().len());
    assert_eq!(new_body, data.to_bytes_with_nul());
}

// Try to send a TCP packet from one guest to another; but in this
// case the guest has not route to the other guest, resulting in the
// packet being dropped.
#[test]
fn guest_to_guest_no_route() {
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.vpc_map.add(g2_cfg.ipv4().private_ip.into(), g2_cfg.phys_addr());
    g1.port.start();
    set!(g1, "port_state=running");
    // Make sure the router is configured to drop all packets.
    router::del_entry(
        &g1.port,
        IpCidr::Ip4(g1_cfg.ipv4().vpc_subnet),
        RouterTarget::VpcSubnet(IpCidr::Ip4(g1_cfg.ipv4().vpc_subnet)),
        RouterClass::System,
    )
    .unwrap();
    update!(g1, ["incr:epoch", "set:router.rules.out=0"]);
    let mut pkt1_m = http_syn(&g1_cfg, &g2_cfg);
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    assert_drop!(
        res,
        DropReason::Layer { name: "router", reason: DenyReason::Default }
    );

    // XXX The firewall layer comes before the router layer (in the
    // outbound direction). The firewall layer allows this traffic;
    // and a flow is created, regardless of the fact that a later
    // layer decides to drop the packet. This means that a flow could
    // take up space in some of the layers even though no traffic can
    // actually flow through it. In the future it would be better to
    // have a way to send "simulated" flow through the layer pipeline
    // for the effect of removing it from any flow tables in which it
    // exists.
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "stats.port.out_drop, stats.port.out_drop_layer",
            "stats.port.out_uft_miss",
        ]
    );
}

// Verify that two guests on the same VPC can communicate.
#[test]
fn guest_to_guest() {
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.vpc_map.add(g2_cfg.ipv4().private_ip.into(), g2_cfg.phys_addr());
    g1.port.start();
    set!(g1, "port_state=running");
    let mut g2 =
        oxide_net_setup("g2_port", &g2_cfg, Some(g1.vpc_map.clone()), None);
    g2.port.start();
    set!(g2, "port_state=running");

    // Allow incoming TCP connection from anyone.
    let rule = "dir=in action=allow priority=10 protocol=TCP";
    firewall::add_fw_rule(
        &g2.port,
        &AddFwRuleReq {
            port_name: g2.port.name().to_string(),
            rule: rule.parse().unwrap(),
        },
    )
    .unwrap();
    incr!(g2, ["epoch", "firewall.rules.in"]);

    let mut pcap_guest1 =
        PcapBuilder::new("overlay_guest_to_guest-guest-1.pcap");
    let mut pcap_phys1 = PcapBuilder::new("overlay_guest_to_guest-phys-1.pcap");

    let mut pcap_guest2 =
        PcapBuilder::new("overlay_guest_to_guest-guest-2.pcap");
    let mut pcap_phys2 = PcapBuilder::new("overlay_guest_to_guest-phys-2.pcap");

    let mut pkt1_m = http_syn(&g1_cfg, &g2_cfg);
    pcap_guest1.add_pkt(&pkt1_m);
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let ulp_csum_b4 = pkt1.meta().inner_ulp.as_ref().unwrap().csum();
    let ip_csum_b4 = pkt1.meta().inner_l3.as_ref().unwrap().csum();

    // ================================================================
    // Run the packet through g1's port in the outbound direction and
    // verify the resulting packet meets expectations.
    // ================================================================
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    expect_modified!(res, pkt1_m);
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "uft.out",
            "stats.port.out_modified, stats.port.out_uft_miss",
        ]
    );
    pcap_phys1.add_pkt(&pkt1_m);

    let nodes = pkt1_m.iter();
    assert_eq!(nodes.count(), 2);

    let pkt2 = parse_inbound(&mut pkt1_m, VpcParser {}).unwrap();
    let ulp_csum_after = pkt2.meta().inner_ulp.csum();
    let ip_csum_after = pkt2.meta().inner_l3.csum();
    assert_eq!(ulp_csum_after, ulp_csum_b4);
    assert_eq!(ip_csum_after, ip_csum_b4);

    let meta = pkt2.meta();
    assert_eq!(meta.outer_eth.source(), MacAddr::ZERO);
    assert_eq!(meta.outer_eth.destination(), MacAddr::ZERO);

    assert_eq!(meta.outer_v6.source(), g1_cfg.phys_ip);
    assert_eq!(meta.outer_v6.destination(), g2_cfg.phys_ip);

    // Geneve entropy.
    assert_eq!(meta.outer_udp.source(), 12700);
    assert_eq!(meta.outer_encap.vni(), g1_cfg.vni);

    let eth = &meta.inner_eth;
    assert_eq!(eth.source(), g1_cfg.guest_mac);
    assert_eq!(eth.destination(), g2_cfg.guest_mac);
    assert_eq!(eth.ethertype(), Ethertype::IPV4);

    match &meta.inner_l3 {
        ValidL3::Ipv4(ip4) => {
            assert_eq!(ip4.source(), g1_cfg.ipv4_cfg().unwrap().private_ip);
            assert_eq!(
                ip4.destination(),
                g2_cfg.ipv4_cfg().unwrap().private_ip
            );
            assert_eq!(ip4.protocol(), IngotIpProto::TCP);
        }
        _ => panic!("expected inner IPv4 metadata, got IPv6"),
    }

    match &meta.inner_ulp {
        ValidUlp::Tcp(tcp) => {
            assert_eq!(tcp.source(), 44490);
            assert_eq!(tcp.destination(), 80);
        }

        // todo: derive Debug on choice?
        // ulp => panic!("expected inner TCP metadata, got: {:?}", ulp),
        _ => panic!("expected inner TCP metadata, got (other)"),
    }

    // ================================================================
    // Now that the packet has been encap'd let's play the role of
    // router and send this inbound to g2's port. For maximum fidelity
    // of the real process we first dump the raw bytes of g1's
    // outgoing packet and then reparse it.
    // ================================================================
    let mut pkt2_m = pkt1_m;
    pcap_phys2.add_pkt(&pkt2_m);
    let pkt2 = parse_inbound(&mut pkt2_m, VpcParser {}).unwrap();

    let res = g2.port.process(In, pkt2);
    expect_modified!(res, pkt2_m);
    pcap_guest2.add_pkt(&pkt2_m);
    incr!(
        g2,
        [
            "firewall.flows.in, firewall.flows.out",
            "uft.in",
            "stats.port.in_modified, stats.port.in_uft_miss",
        ]
    );
    // assert_eq!(pkt2.body_offset(), TCP4_SZ + HTTP_SYN_OPTS_LEN);
    // assert_eq!(pkt2.body_seg(), 0);

    let pkt2 = parse_outbound(&mut pkt2_m, VpcParser {}).unwrap();
    let g2_meta = pkt2.meta();

    // TODO: can we have a convenience method that verifies that the
    // emitspec was a rewind/drop from the head of the pkt?

    let g2_eth = &g2_meta.inner_eth;
    assert_eq!(g2_eth.source(), g1_cfg.gateway_mac);
    assert_eq!(g2_eth.destination(), g2_cfg.guest_mac);
    assert_eq!(g2_eth.ethertype(), Ethertype::IPV4);

    match &g2_meta.inner_l3 {
        Some(ValidL3::Ipv4(ip4)) => {
            assert_eq!(ip4.source(), g1_cfg.ipv4_cfg().unwrap().private_ip);
            assert_eq!(
                ip4.destination(),
                g2_cfg.ipv4_cfg().unwrap().private_ip
            );
            assert_eq!(ip4.protocol(), IngotIpProto::TCP);
        }
        _ => panic!("expected inner IPv4 metadata, got IPv6"),
    }

    match &g2_meta.inner_ulp {
        Some(ValidUlp::Tcp(tcp)) => {
            assert_eq!(tcp.source(), 44490);
            assert_eq!(tcp.destination(), 80);
        }

        // todo: derive Debug on choice?
        // ulp => panic!("expected inner TCP metadata, got: {:?}", ulp),
        _ => panic!("expected inner TCP metadata, got (other)"),
    }
}

// Two guests on different, non-peered VPCs should not be able to
// communicate.
#[test]
fn guest_to_guest_diff_vpc_no_peer() {
    // ================================================================
    // Configure ports for g1 and g2. Place g1 on VNI 99 and g2 on VNI
    // 100.
    // ================================================================
    let g1_cfg = g1_cfg();
    let mut g2_cfg = g2_cfg();
    g2_cfg.vni = Vni::new(100u32).unwrap();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");
    let mut g2 =
        oxide_net_setup("g2_port", &g2_cfg, Some(g1.vpc_map.clone()), None);
    g2.port.start();
    set!(g2, "port_state=running");

    // Allow incoming TCP connection from anyone.
    let rule = "dir=in action=allow priority=10 protocol=TCP";
    firewall::add_fw_rule(
        &g2.port,
        &AddFwRuleReq {
            port_name: g2.port.name().to_string(),
            rule: rule.parse().unwrap(),
        },
    )
    .unwrap();
    incr!(g2, ["epoch", "firewall.rules.in"]);

    // ================================================================
    // Run the packet through g1's port in the outbound direction and
    // verify the packet is dropped.
    // ================================================================
    let mut g1_pkt = http_syn(&g1_cfg, &g2_cfg);
    let pkt1 = parse_outbound(&mut g1_pkt, GenericUlp {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    assert_drop!(
        res,
        DropReason::Layer { name: "overlay", reason: DenyReason::Action }
    );
    incr!(
        g1,
        [
            "firewall.flows.in, firewall.flows.out",
            "stats.port.out_drop, stats.port.out_drop_layer",
            "stats.port.out_uft_miss",
        ]
    );
}

// Verify that a guest can communicate with the internet over IPv4.
#[test]
fn guest_to_internet_ipv4() {
    let mut pcap_guest = PcapBuilder::new("guest_to_internet_ipv4.pcap");
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    // Add router entry that allows g1 to route to internet.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway(None),
        RouterClass::System,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    // ================================================================
    // Generate a TCP SYN packet from g1 to zinascii.com
    // ================================================================
    let dst_ip = "52.10.128.69".parse().unwrap();
    let mut pkt1_m = http_syn2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    pcap_guest.add_pkt(&pkt1_m);

    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();

    // ================================================================
    // Run the packet through g1's port in the outbound direction and
    // verify the resulting packet meets expectations.
    // ================================================================
    let res = g1.port.process(Out, pkt1);
    expect_modified!(res, pkt1_m);
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "nat.flows.out, nat.flows.in",
            "uft.out",
            "stats.port.out_modified, stats.port.out_uft_miss",
        ]
    );

    // Inbound parse asserts specifically that we have:
    // - Ethernet
    // - Ipv6
    // - Udp (dstport 6081)
    // - Geneve
    // - (Inner ULP headers)
    let pkt1 = parse_inbound(&mut pkt1_m, VpcParser {}).unwrap();
    let meta = pkt1.meta();

    assert_eq!(meta.outer_eth.source(), MacAddr::ZERO);
    assert_eq!(meta.outer_eth.destination(), MacAddr::ZERO);

    assert_eq!(meta.outer_v6.source(), g1_cfg.phys_ip);
    // Check that the encoded payload length in the outer header is
    // correct, and matches the actual number of bytes in the rest of
    // the packet.
    let len_post_v6 =
        pkt1.len() - (&meta.outer_eth, &meta.outer_v6).packet_length();
    assert_eq!(meta.outer_v6.payload_len() as usize, len_post_v6);

    assert_eq!(meta.outer_udp.source(), 24329);
    assert_eq!(meta.outer_udp.length() as usize, len_post_v6);

    assert_eq!(meta.inner_eth.source(), g1_cfg.guest_mac);
    assert_eq!(meta.inner_eth.ethertype(), Ethertype::IPV4);

    match &meta.inner_l3 {
        ValidL3::Ipv4(ip4) => {
            assert_eq!(ip4.source(), g1_cfg.snat().external_ip);
            assert_eq!(ip4.destination(), dst_ip);
            assert_eq!(ip4.protocol(), IngotIpProto::TCP);

            let inner_len = len_post_v6
                - (&meta.outer_udp, &meta.outer_encap, &meta.inner_eth)
                    .packet_length();

            // Check that the encoded payload length in the inner header is
            // correct, and matches the actual number of bytes in the rest of
            // the packet.
            // IPv4 total length _DOES_ include the IPv4 header.
            assert_eq!(ip4.total_len() as usize, inner_len,);
        }
        _ => panic!("expected inner IPv4 metadata, got IPv6"),
    }

    match &meta.inner_ulp {
        ValidUlp::Tcp(tcp) => {
            assert_eq!(
                tcp.source(),
                g1_cfg.snat().ports.clone().next_back().unwrap()
            );
            assert_eq!(tcp.destination(), 80);
        }

        // todo: derive Debug on choice?
        // ulp => panic!("expected inner TCP metadata, got: {:?}", ulp),
        _ => panic!("expected inner TCP metadata, got (other)"),
    }

    pcap_guest.add_pkt(&pkt1_m);
}

// Verify that a guest can communicate with the internet over IPv6.
#[test]
fn guest_to_internet_ipv6() {
    let mut pcap_guest = PcapBuilder::new("guest_to_internet_ipv6.pcap");
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    // Add router entry that allows g1 to route to internet.
    router::add_entry(
        &g1.port,
        IpCidr::Ip6("::/0".parse().unwrap()),
        RouterTarget::InternetGateway(None),
        RouterClass::System,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    // ================================================================
    // Generate a TCP SYN packet from g1 to example.com
    // ================================================================
    let dst_ip = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
    let mut pkt1_m = http_syn2(
        g1_cfg.guest_mac,
        g1_cfg.ipv6_cfg().unwrap().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    pcap_guest.add_pkt(&pkt1_m);

    // ================================================================
    // Run the packet through g1's port in the outbound direction and
    // verify the resulting packet meets expectations.
    // ================================================================
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    expect_modified!(res, pkt1_m);
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "nat.flows.out, nat.flows.in",
            "uft.out",
            "stats.port.out_modified, stats.port.out_uft_miss",
        ]
    );

    let pkt1 = parse_inbound(&mut pkt1_m, VpcParser {}).unwrap();
    let meta = pkt1.meta();

    assert_eq!(meta.outer_eth.source(), MacAddr::ZERO);
    assert_eq!(meta.outer_eth.destination(), MacAddr::ZERO);

    assert_eq!(meta.outer_v6.source(), g1_cfg.phys_ip);
    // Check that the encoded payload length in the outer header is
    // correct, and matches the actual number of bytes in the rest of
    // the packet.
    let len_post_v6 =
        pkt1.len() - (&meta.outer_eth, &meta.outer_v6).packet_length();
    assert_eq!(meta.outer_v6.payload_len() as usize, len_post_v6);

    assert_eq!(meta.outer_udp.source(), 63246);
    assert_eq!(meta.outer_udp.length() as usize, len_post_v6);

    assert_eq!(meta.inner_eth.source(), g1_cfg.guest_mac);
    assert_eq!(meta.inner_eth.ethertype(), Ethertype::IPV6);

    match &meta.inner_l3 {
        ValidL3::Ipv6(ip6) => {
            assert_eq!(ip6.source(), g1_cfg.snat6().external_ip);
            assert_eq!(ip6.destination(), dst_ip);
            assert_eq!(ip6.next_header(), IngotIpProto::TCP);

            let inner_len = len_post_v6
                - (
                    &meta.outer_udp,
                    &meta.outer_encap,
                    &meta.inner_eth,
                    &meta.inner_l3,
                )
                    .packet_length();

            // Check that the encoded payload length in the inner header is
            // correct, and matches the actual number of bytes in the rest of
            // the packet.
            // IPv6 payload length _DOES NOT_ include the IPv6 header.
            assert_eq!(ip6.payload_len() as usize, inner_len);
        }
        _ => panic!("expected inner IPv4 metadata, got IPv6"),
    }

    match &meta.inner_ulp {
        ValidUlp::Tcp(tcp) => {
            assert_eq!(
                tcp.source(),
                g1_cfg.snat6().ports.clone().next_back().unwrap()
            );
            assert_eq!(tcp.destination(), 80);
        }

        // todo: derive Debug on choice?
        // ulp => panic!("expected inner TCP metadata, got: {:?}", ulp),
        _ => panic!("expected inner TCP metadata, got (other)"),
    }
    pcap_guest.add_pkt(&pkt1_m);
}

fn multi_external_setup(
    n: usize,
    use_ephemeral: bool,
) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>, IpCfg) {
    if n >= 254 {
        panic!("multi_external_setup can't yet handle that many addresses");
    }

    let base_v4: Ipv4Addr = "10.60.1.1".parse().unwrap();
    let base_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let v4s = (0..n)
        .map(|i| {
            let mut out = base_v4.bytes();
            out[3] += i as u8;
            out.into()
        })
        .collect::<Vec<_>>();

    let v6s = (0..n)
        .map(|i| {
            let mut out = base_v6.bytes();
            out[15] += i as u8;
            out.into()
        })
        .collect::<Vec<_>>();

    let (v4_eph, v6_eph, first_float) = if use_ephemeral {
        (v4s.first().copied(), v6s.first().copied(), 1)
    } else {
        (None, None, 0)
    };

    let ip_cfg = IpCfg::DualStack {
        ipv4: Ipv4Cfg {
            vpc_subnet: "172.30.0.0/22".parse().unwrap(),
            private_ip: "172.30.0.5".parse().unwrap(),
            gateway_ip: "172.30.0.1".parse().unwrap(),
            external_ips: ExternalIpCfg {
                snat: Some(SNat4Cfg {
                    external_ip: "10.77.77.13".parse().unwrap(),
                    ports: 1025..=4096,
                }),
                ephemeral_ip: v4_eph,
                floating_ips: v4s[first_float..].to_vec(),
            },
        },
        ipv6: Ipv6Cfg {
            vpc_subnet: "fd00::/64".parse().unwrap(),
            private_ip: "fd00::5".parse().unwrap(),
            gateway_ip: "fd00::1".parse().unwrap(),
            external_ips: ExternalIpCfg {
                snat: Some(SNat6Cfg {
                    external_ip: "2001:db8::1".parse().unwrap(),
                    ports: 1025..=4096,
                }),
                ephemeral_ip: v6_eph,
                floating_ips: v6s[first_float..].to_vec(),
            },
        },
    };

    (v4s, v6s, ip_cfg)
}

fn multi_external_ip_setup(
    n_ips: usize,
    use_ephemeral: bool,
) -> (PortAndVps, VpcCfg, Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
    // ================================================================
    // In order for a guest to receive external connections, it must
    // have an external IP.
    // ================================================================
    let (ext_v4, ext_v6, ip_cfg) = multi_external_setup(n_ips, use_ephemeral);
    let g1_cfg = g1_cfg2(ip_cfg);
    let mut g1 =
        oxide_net_setup("g1_port", &g1_cfg, None, NonZeroU32::new(8192));
    g1.port.start();
    set!(g1, "port_state=running");

    // Add router entry that allows g1 to route to internet.
    router::add_entry(
        &g1.port,
        IpCidr::Ip6("::/0".parse().unwrap()),
        RouterTarget::InternetGateway(None),
        RouterClass::System,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway(None),
        RouterClass::System,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    // Allow incoming TCP connection on g1 from anyone.
    let rule = "dir=in action=allow priority=10 protocol=TCP";
    firewall::add_fw_rule(
        &g1.port,
        &AddFwRuleReq {
            port_name: g1.port.name().to_string(),
            rule: rule.parse().unwrap(),
        },
    )
    .unwrap();
    incr!(g1, ["epoch", "firewall.rules.in"]);

    (g1, g1_cfg, ext_v4, ext_v6)
}

fn check_external_ip_inbound_behaviour(
    check_reply: bool,
    old_ip_gone: bool,
    firewall_flow_exists: bool,
    port: &mut PortAndVps,
    cfg: &VpcCfg,
    ext_v4: &[Ipv4Addr],
    ext_v6: &[Ipv6Addr],
) {
    let bsvc_phys = TestIpPhys {
        ip: BS_IP_ADDR,
        mac: BS_MAC_ADDR,
        vni: Vni::new(BOUNDARY_SERVICES_VNI).unwrap(),
    };
    let g1_phys =
        TestIpPhys { ip: cfg.phys_ip, mac: cfg.guest_mac, vni: cfg.vni };

    let ext_ips = ext_v4
        .iter()
        .copied()
        .map(IpAddr::Ip4)
        .chain(ext_v6.iter().copied().map(IpAddr::Ip6))
        .collect::<Vec<_>>();
    for (i, ext_ip) in ext_ips.into_iter().enumerate() {
        let flow_port = 44490 + i as u16;

        // Suppose that 'example.com' wants to contact us.
        let partner_ip: IpAddr = match ext_ip {
            IpAddr::Ip4(_) => "93.184.216.34".parse().unwrap(),
            IpAddr::Ip6(_) => {
                "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()
            }
        };
        // ================================================================
        // Generate a TCP SYN packet to the chosen ext_ip
        // ================================================================
        let pkt1 = http_syn3(
            BS_MAC_ADDR,
            partner_ip,
            cfg.guest_mac,
            ext_ip,
            flow_port,
            80,
        );
        let mut pkt1_m = encap_external(pkt1, bsvc_phys, g1_phys);
        let pkt1 = parse_inbound(&mut pkt1_m, VpcParser {}).unwrap();

        let res = port.port.process(In, pkt1);
        if old_ip_gone {
            // If we lose an external IP, the failure mode is obvious:
            // invalidate the action, do not rewrite dst IP to target the
            // port's private IP, which will be filtered by `gateway`.
            assert!(
                matches!(res, Ok(ProcessResult::Drop { .. })),
                "bad result for ip {ext_ip:?}: {res:?}"
            );
            update!(
                port,
                [
                    "incr:firewall.flows.out, firewall.flows.in",
                    "decr:uft.in",
                    "incr:stats.port.in_drop, stats.port.in_drop_layer",
                    "incr:stats.port.in_uft_miss",
                ]
            );
        } else {
            expect_modified!(res, pkt1_m);
            let rules = [
                "firewall.flows.out, firewall.flows.in",
                "nat.flows.out, nat.flows.in",
                "uft.in",
                "stats.port.in_modified, stats.port.in_uft_miss",
            ];
            incr!(port, rules[(if firewall_flow_exists { 2 } else { 0 })..]);
        }

        let private_ip: IpAddr = match ext_ip {
            IpAddr::Ip4(_) => {
                let private_ip = cfg.ipv4().private_ip;
                if !old_ip_gone {
                    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {})
                        .unwrap()
                        .to_full_meta();
                    assert_eq!(
                        pkt1.meta().inner_ip4().unwrap().destination(),
                        private_ip
                    );
                }
                private_ip.into()
            }
            IpAddr::Ip6(_) => {
                let private_ip = cfg.ipv6().private_ip;
                if !old_ip_gone {
                    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {})
                        .unwrap()
                        .to_full_meta();
                    assert_eq!(
                        pkt1.meta().inner_ip6().unwrap().destination(),
                        private_ip
                    );
                }
                private_ip.into()
            }
        };

        if !check_reply {
            continue;
        }

        // ================================================================
        // Generate a reply packet: post processing, this must appear to be
        // sent from the correct address.
        //
        // While FIP selection is based on flow hash, we can guarantee on the first
        // IP (ephemeral) that the wrong src_ip will be selected (as it will
        // draw from a separate pool).
        // ================================================================
        let mut pkt2_m = http_syn_ack2(
            cfg.guest_mac,
            private_ip,
            GW_MAC_ADDR,
            partner_ip,
            flow_port,
        );
        let pkt2 = parse_outbound(&mut pkt2_m, VpcParser {}).unwrap();
        let res = port.port.process(Out, pkt2);
        expect_modified!(res, pkt2_m);
        let pkt2 =
            parse_inbound(&mut pkt2_m, VpcParser {}).unwrap().to_full_meta();

        if old_ip_gone {
            // Failure mode here is different (assuming we have at least one
            // external IP). The packet must fail to send via the old IP,
            // invalidate the entry, and then choose the new external IP.
            update!(
                port,
                [
                    "incr:uft.out",
                    "incr:stats.port.out_modified",
                    "incr:stats.port.out_uft_miss",
                    "incr:nat.flows.in, nat.flows.out",
                ]
            );

            match ext_ip {
                IpAddr::Ip4(ip) => {
                    let chosen_ip = pkt2.meta().inner_ip4().unwrap().source();
                    assert_ne!(chosen_ip, ip);
                    assert_ne!(IpAddr::from(chosen_ip), private_ip);
                }
                IpAddr::Ip6(ip) => {
                    let chosen_ip = pkt2.meta().inner_ip6().unwrap().source();
                    assert_ne!(chosen_ip, ip);
                    assert_ne!(IpAddr::from(chosen_ip), private_ip);
                }
            };
        } else {
            update!(
                port,
                [
                    "incr:uft.out",
                    "incr:stats.port.out_modified, stats.port.out_uft_miss",
                ]
            );
            match ext_ip {
                IpAddr::Ip4(ip) => {
                    assert_eq!(pkt2.meta().inner_ip4().unwrap().source(), ip);
                }
                IpAddr::Ip6(ip) => {
                    assert_eq!(pkt2.meta().inner_ip6().unwrap().source(), ip);
                }
            };
        }
    }
}

#[test]
fn external_ip_receive_and_reply_on_all() {
    let (mut g1, g1_cfg, ext_v4, ext_v6) = multi_external_ip_setup(8, true);

    check_external_ip_inbound_behaviour(
        true, false, false, &mut g1, &g1_cfg, &ext_v4, &ext_v6,
    );
}

#[test]
fn external_ip_balanced_over_floating_ips() {
    let (mut g1, g1_cfg, ext_v4, ext_v6) = multi_external_ip_setup(8, true);

    let partner_ipv4: IpAddr = "93.184.216.34".parse().unwrap();
    let partner_ipv6: IpAddr =
        "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();

    let mut seen_v4s = vec![];
    let mut seen_v6s = vec![];

    // ====================================================================
    // Create several outbound flows, collate chosen external IP addresses.
    // ====================================================================
    for i in 0..16 {
        let flow_port = 44490 + i;
        for partner_ip in [partner_ipv4, partner_ipv6] {
            let private_ip: IpAddr = match partner_ip {
                IpAddr::Ip4(_) => g1_cfg.ipv4().private_ip.into(),
                IpAddr::Ip6(_) => g1_cfg.ipv6().private_ip.into(),
            };

            let mut pkt_m = http_syn3(
                g1_cfg.guest_mac,
                private_ip,
                g1_cfg.gateway_mac,
                partner_ip,
                flow_port,
                80,
            );
            let pkt = parse_outbound(&mut pkt_m, VpcParser {}).unwrap();

            let res = g1.port.process(Out, pkt);
            expect_modified!(res, pkt_m);
            incr!(
                g1,
                [
                    "firewall.flows.out, firewall.flows.in",
                    "nat.flows.out, nat.flows.in",
                    "uft.out",
                    "stats.port.out_modified, stats.port.out_uft_miss",
                ]
            );

            let pkt =
                parse_inbound(&mut pkt_m, VpcParser {}).unwrap().to_full_meta();

            match partner_ip {
                IpAddr::Ip4(_) => {
                    seen_v4s.push(pkt.meta().inner_ip4().unwrap().source());
                }
                IpAddr::Ip6(_) => {
                    seen_v6s.push(pkt.meta().inner_ip6().unwrap().source());
                }
            }
        }
    }

    // ====================================================================
    // Check for spread, assert ephemeral IP not chosen.
    // ====================================================================
    seen_v4s.sort();
    seen_v4s.dedup();
    assert!(seen_v4s.len() > 1);
    seen_v4s.iter().for_each(|ip| {
        assert!(&ext_v4[1..].contains(ip), "unexpected v4 IP: {ip}")
    });

    seen_v6s.sort();
    seen_v6s.dedup();
    assert!(seen_v6s.len() > 1);
    seen_v6s.iter().for_each(|ip| {
        assert!(&ext_v6[1..].contains(ip), "unexpected v6 IP: {ip}")
    });
}

#[test]
fn external_ip_epoch_affinity_preserved() {
    let (mut g1, g1_cfg, ext_v4, ext_v6) = multi_external_ip_setup(2, true);
    let bsvc_phys = TestIpPhys {
        ip: BS_IP_ADDR,
        mac: BS_MAC_ADDR,
        vni: Vni::new(BOUNDARY_SERVICES_VNI).unwrap(),
    };
    let g1_phys = TestIpPhys {
        ip: g1_cfg.phys_ip,
        mac: g1_cfg.guest_mac,
        vni: g1_cfg.vni,
    };

    let new_v4: Ipv4Addr = "10.60.1.10".parse().unwrap();
    let new_v4_cfg = g1_cfg.ipv4_cfg().map(|v| {
        let mut floating_ips = v.external_ips.floating_ips.clone();
        floating_ips.push(new_v4);
        ExternalIpCfg { floating_ips, ..v.external_ips.clone() }
    });
    let new_v6: Ipv6Addr = "2001:db8::10".parse().unwrap();
    let new_v6_cfg = g1_cfg.ipv6_cfg().map(|v| {
        let mut floating_ips = v.external_ips.floating_ips.clone();
        floating_ips.push(new_v6);
        ExternalIpCfg { floating_ips, ..v.external_ips.clone() }
    });

    let mut req = oxide_vpc::api::SetExternalIpsReq {
        port_name: g1.port.name().to_string(),
        external_ips_v4: None,
        external_ips_v6: None,

        // This test does not focus on controlling EIP selection
        // based on destination prefix.
        inet_gw_map: None,
    };

    for ext_ip in [ext_v4[0].into(), ext_v6[0].into()] {
        // ====================================================================
        // Create an inbound flow on each ephemeral IP.
        // ====================================================================
        let (partner_ip, private_ip): (IpAddr, IpAddr) = match ext_ip {
            IpAddr::Ip4(_) => {
                req.external_ips_v4 = new_v4_cfg.clone();
                (
                    "93.184.216.34".parse().unwrap(),
                    g1_cfg.ipv4().private_ip.into(),
                )
            }
            IpAddr::Ip6(_) => {
                req.external_ips_v6 = new_v6_cfg.clone();
                (
                    "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(),
                    g1_cfg.ipv6().private_ip.into(),
                )
            }
        };

        let pkt1 = http_syn2(BS_MAC_ADDR, partner_ip, g1_cfg.guest_mac, ext_ip);
        let mut pkt1_m = encap_external(pkt1, bsvc_phys, g1_phys);
        let pkt1 = parse_inbound(&mut pkt1_m, VpcParser {}).unwrap();

        let res = g1.port.process(In, pkt1);
        expect_modified!(res, pkt1_m);
        incr!(
            g1,
            [
                "firewall.flows.out, firewall.flows.in",
                "nat.flows.out, nat.flows.in",
                "uft.in",
                "stats.port.in_modified, stats.port.in_uft_miss",
            ]
        );

        // ====================================================================
        // Add another floating IP to bump epoch
        // Bumping epoch on other layers (e.g., firewall) is typically fine,
        // since that won't affect the internal flowtable for NAT.
        // ====================================================================
        nat::set_nat_rules(&g1.cfg, &g1.port, req.clone()).unwrap();
        update!(g1, ["incr:epoch", "set:nat.rules.in=4, nat.rules.out=7",]);

        // ================================================================
        // The reply packet must still originate from the ephemeral port
        // after an epoch change.
        // ================================================================
        let mut pkt2_m = http_syn_ack2(
            g1_cfg.guest_mac,
            private_ip,
            GW_MAC_ADDR,
            partner_ip,
            44490,
        );
        let pkt2 = parse_outbound(&mut pkt2_m, VpcParser {}).unwrap();
        let res = g1.port.process(Out, pkt2);
        expect_modified!(res, pkt2_m);
        update!(
            g1,
            [
                "incr:uft.out",
                "incr:stats.port.out_modified, stats.port.out_uft_miss",
            ]
        );

        let pkt2 =
            parse_inbound(&mut pkt2_m, VpcParser {}).unwrap().to_full_meta();
        match ext_ip {
            IpAddr::Ip4(ip) => {
                assert_eq!(pkt2.meta().inner_ip4().unwrap().source(), ip);
            }
            IpAddr::Ip6(ip) => {
                assert_eq!(pkt2.meta().inner_ip6().unwrap().source(), ip);
            }
        };
    }
}

#[test]
fn external_ip_reconfigurable() {
    let (mut g1, g1_cfg, ext_v4, ext_v6) = multi_external_ip_setup(1, true);

    // ====================================================================
    // Create several inbound flows.
    // ====================================================================
    check_external_ip_inbound_behaviour(
        false, false, false, &mut g1, &g1_cfg, &ext_v4, &ext_v6,
    );

    // ====================================================================
    // Install new config.
    // ====================================================================
    let new_v4 = "10.60.1.2".parse().unwrap();
    let new_v4_cfg = g1_cfg.ipv4_cfg().map(|v| ExternalIpCfg {
        floating_ips: vec![new_v4],
        ephemeral_ip: None,
        ..v.external_ips.clone()
    });
    let new_v6 = "2001:db8::2".parse().unwrap();
    let new_v6_cfg = g1_cfg.ipv6_cfg().map(|v| ExternalIpCfg {
        floating_ips: vec![new_v6],
        ephemeral_ip: None,
        ..v.external_ips.clone()
    });

    let req = oxide_vpc::api::SetExternalIpsReq {
        port_name: g1.port.name().to_string(),
        external_ips_v4: new_v4_cfg,
        external_ips_v6: new_v6_cfg,

        // This test does not focus on controlling EIP selection
        // based on destination prefix.
        inet_gw_map: None,
    };
    nat::set_nat_rules(&g1.cfg, &g1.port, req).unwrap();
    update!(
        g1,
        [
            "incr:epoch",
            "set:nat.rules.in=2, nat.rules.out=5",
            "set:firewall.flows.in=2, firewall.flows.out=2",
        ]
    );

    // ====================================================================
    // Port should no longer admit external traffic on old IPs, and affinity
    // with the old external IP should be broken.
    // ====================================================================
    check_external_ip_inbound_behaviour(
        true, true, false, &mut g1, &g1_cfg, &ext_v4, &ext_v6,
    );

    // ====================================================================
    // Port should admit external traffic on new IPs.
    // ====================================================================
    check_external_ip_inbound_behaviour(
        false,
        false,
        true,
        &mut g1,
        &g1_cfg,
        &[new_v4],
        &[new_v6],
    );
}

#[derive(Debug)]
struct IcmpSnatParams {
    private_ip: IpAddr,
    public_ip: IpAddr,
    partner_ip: IpAddr,
    icmp_id: u16,
    snat_port: u16,
}

fn unpack_and_verify_icmp(
    pkt: &mut MsgBlk,
    cfg: &VpcCfg,
    params: &IcmpSnatParams,
    dir: Direction,
    seq_no: u16,
) {
    // Note the reversed direction -- parse the expected *output* format.
    let parsed = match dir {
        In => parse_outbound(pkt, VpcParser {}).unwrap().to_full_meta(),
        Out => parse_inbound(pkt, VpcParser {}).unwrap().to_full_meta(),
    };
    let meta = parsed.meta();

    let (src_eth, dst_eth, src_ip, dst_ip, ident) = match dir {
        Direction::Out => (
            cfg.guest_mac,
            BS_MAC_ADDR,
            params.public_ip,
            params.partner_ip,
            params.snat_port,
        ),
        Direction::In => (
            cfg.gateway_mac,
            cfg.guest_mac,
            params.partner_ip,
            params.private_ip,
            params.icmp_id,
        ),
    };

    let eth = meta.inner_ether();
    assert_eq!(eth.source(), src_eth);
    assert_eq!(eth.destination(), dst_eth);

    match (dst_ip, meta.inner_l3().as_ref().unwrap()) {
        (IpAddr::Ip4(_), L3::Ipv4(meta)) => {
            assert_eq!(eth.ethertype(), Ethertype::IPV4);
            assert_eq!(IpAddr::from(meta.source()), src_ip);
            assert_eq!(IpAddr::from(meta.destination()), dst_ip);
            assert_eq!(meta.protocol(), IngotIpProto::ICMP);

            unpack_and_verify_icmp4(&parsed, ident, seq_no);
        }
        (IpAddr::Ip6(_), L3::Ipv6(meta)) => {
            assert_eq!(eth.ethertype(), Ethertype::IPV6);
            assert_eq!(IpAddr::from(meta.source()), src_ip);
            assert_eq!(IpAddr::from(meta.destination()), dst_ip);
            assert_eq!(meta.next_header(), IngotIpProto::ICMP_V6);

            unpack_and_verify_icmp6(
                &parsed,
                ident,
                seq_no,
                meta.source(),
                meta.destination(),
            );
        }
        (IpAddr::Ip4(_), _) => {
            panic!("expected inner IPv4 metadata, got IPv6")
        }
        (IpAddr::Ip6(_), _) => {
            panic!("expected inner IPv6 metadata, got IPv4")
        }
    }
}

fn unpack_and_verify_icmp4(
    pkt: &Packet<MblkFullParsed>,
    expected_ident: u16,
    seq_no: u16,
) {
    // Because we treat ICMPv4 as a full-fledged ULP, we need to
    // unsplit the emitted header from the body.
    let mut icmp = pkt.meta().inner_ulp().unwrap().emit_vec();
    pkt.meta().append_remaining(&mut icmp);

    let icmp = Icmpv4Packet::new_checked(&icmp[..]).unwrap();

    assert!(icmp.verify_checksum());
    assert_eq!(icmp.echo_ident(), expected_ident);
    assert_eq!(icmp.echo_seq_no(), seq_no);
}

fn unpack_and_verify_icmp6(
    pkt: &Packet<MblkFullParsed>,
    expected_ident: u16,
    seq_no: u16,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
) {
    let src_ip = smoltcp::wire::Ipv6Address::from(src_ip).into();
    let dst_ip = smoltcp::wire::Ipv6Address::from(dst_ip).into();

    // Because we treat ICMPv4 as a full-fledged ULP, we need to
    // unsplit the emitted header from the body.
    let mut icmp = pkt.meta().inner_ulp().unwrap().emit_vec();
    pkt.meta().append_remaining(&mut icmp);
    let icmp = Icmpv6Packet::new_checked(&icmp[..]).unwrap();

    assert!(icmp.verify_checksum(&src_ip, &dst_ip));
    assert_eq!(icmp.echo_ident(), expected_ident);
    assert_eq!(icmp.echo_seq_no(), seq_no);
}

// Verify that an ICMP Echo request has its identifier rewritten by
// SNAT.
#[test]
fn snat_icmp4_echo_rewrite() {
    snat_icmp_shared_echo_rewrite("45.55.45.205".parse().unwrap());
}

// Verify that an ICMPv6 Echo request has its identifier rewritten by
// SNAT.
#[test]
fn snat_icmp6_echo_rewrite() {
    snat_icmp_shared_echo_rewrite("2001:4860:4860::8888".parse().unwrap());
}

fn snat_icmp_shared_echo_rewrite(dst_ip: IpAddr) {
    let mut pcap = match &dst_ip {
        IpAddr::Ip4(_) => PcapBuilder::new("snat-v4-echo-id.pcap"),
        IpAddr::Ip6(_) => PcapBuilder::new("snat-v6-echo-id.pcap"),
    };

    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    let ident = 7;
    let mut seq_no = 777;
    let data = b"reunion\0";

    // Add router entries that allow g1 to route to internet.
    router::add_entry(
        &g1.port,
        IpCidr::Ip6("::/0".parse().unwrap()),
        RouterTarget::InternetGateway(None),
        RouterClass::System,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway(None),
        RouterClass::System,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    let (private_ip, public_ip, mapped_port) = match dst_ip {
        IpAddr::Ip4(_) => (
            g1_cfg.ipv4().private_ip.into(),
            g1_cfg.snat().external_ip.into(),
            g1_cfg.snat().ports.clone().next_back().unwrap(),
        ),
        IpAddr::Ip6(_) => (
            g1_cfg.ipv6().private_ip.into(),
            g1_cfg.snat6().external_ip.into(),
            g1_cfg.snat6().ports.clone().next_back().unwrap(),
        ),
    };

    let params = IcmpSnatParams {
        private_ip,
        public_ip,
        partner_ip: dst_ip,
        icmp_id: ident,
        snat_port: mapped_port,
    };

    // ================================================================
    // Verify echo request rewrite.
    // ================================================================
    let mut pkt1_m = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        private_ip,
        dst_ip,
        ident,
        seq_no,
        &data[..],
        2,
    );
    pcap.add_pkt(&pkt1_m);

    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();

    let res = g1.port.process(Out, pkt1);
    expect_modified!(res, pkt1_m);
    pcap.add_pkt(&pkt1_m);
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "nat.flows.out, nat.flows.in",
            "uft.out",
            "stats.port.out_modified, stats.port.out_uft_miss",
        ]
    );

    unpack_and_verify_icmp(&mut pkt1_m, &g1_cfg, &params, Out, seq_no);

    // ================================================================
    // Verify echo reply rewrite.
    // ================================================================
    let mut pkt2_m = gen_icmp_echo_reply(
        BS_MAC_ADDR,
        g1_cfg.guest_mac,
        dst_ip,
        public_ip,
        mapped_port,
        seq_no,
        &data[..],
        3,
    );

    let g1_phys = TestIpPhys {
        ip: g1_cfg.phys_ip,
        mac: g1_cfg.guest_mac,
        vni: g1_cfg.vni,
    };
    let bsvc_phys = TestIpPhys {
        ip: BS_IP_ADDR,
        mac: BS_MAC_ADDR,
        vni: Vni::new(BOUNDARY_SERVICES_VNI).unwrap(),
    };
    pkt2_m = encap_external(pkt2_m, bsvc_phys, g1_phys);
    pcap.add_pkt(&pkt2_m);

    let pkt2 = parse_inbound(&mut pkt2_m, VpcParser {}).unwrap();

    let res = g1.port.process(In, pkt2);
    expect_modified!(res, pkt2_m);
    pcap.add_pkt(&pkt2_m);
    incr!(g1, ["uft.in", "stats.port.in_modified, stats.port.in_uft_miss"]);

    unpack_and_verify_icmp(&mut pkt2_m, &g1_cfg, &params, In, seq_no);

    // ================================================================
    // Send ICMP Echo Req a second time. We want to verify that a) the
    // UFT entry is used and b) that it runs the attached header
    // transformation.
    // ================================================================
    seq_no += 1;
    let mut pkt3_m = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        private_ip,
        dst_ip,
        ident,
        seq_no,
        &data[..],
        1,
    );
    pcap.add_pkt(&pkt3_m);
    let pkt3 = parse_outbound(&mut pkt3_m, VpcParser {}).unwrap();

    assert_eq!(g1.port.stats_snap().out_uft_hit, 0);
    let res = g1.port.process(Out, pkt3);
    expect_modified!(res, pkt3_m);
    pcap.add_pkt(&pkt3_m);
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);

    assert_eq!(g1.port.stats_snap().out_uft_hit, 1);
    unpack_and_verify_icmp(&mut pkt3_m, &g1_cfg, &params, Out, seq_no);

    // ================================================================
    // Process ICMP Echo Reply a second time. Once again, this time we
    // want to verify that the body transformation comes from the UFT
    // entry.
    // ================================================================
    let mut pkt4_m = gen_icmp_echo_reply(
        BS_MAC_ADDR,
        g1_cfg.guest_mac,
        dst_ip,
        public_ip,
        mapped_port,
        seq_no,
        &data[..],
        2,
    );
    pkt4_m = encap_external(pkt4_m, bsvc_phys, g1_phys);
    pcap.add_pkt(&pkt4_m);
    let pkt4 = parse_inbound(&mut pkt4_m, VpcParser {}).unwrap();

    assert_eq!(g1.port.stats_snap().in_uft_hit, 0);
    let res = g1.port.process(In, pkt4);
    expect_modified!(res, pkt4_m);
    pcap.add_pkt(&pkt4_m);
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);

    assert_eq!(g1.port.stats_snap().in_uft_hit, 1);
    unpack_and_verify_icmp(&mut pkt4_m, &g1_cfg, &params, In, seq_no);

    // ================================================================
    // Insert a new packet along the same S/D pair: this should occupy
    // a new port and install a new rule for matching.
    // ================================================================
    let new_params =
        IcmpSnatParams { icmp_id: 8, snat_port: mapped_port - 1, ..params };

    let mut pkt5_m = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        private_ip,
        dst_ip,
        new_params.icmp_id,
        seq_no,
        &data[..],
        2,
    );
    pcap.add_pkt(&pkt5_m);
    let pkt5 = parse_outbound(&mut pkt5_m, VpcParser {}).unwrap();

    let res = g1.port.process(Out, pkt5);
    expect_modified!(res, pkt5_m);
    pcap.add_pkt(&pkt5_m);
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "nat.flows.out, nat.flows.in",
            "uft.out",
            "stats.port.out_modified, stats.port.out_uft_miss",
        ]
    );

    unpack_and_verify_icmp(&mut pkt5_m, &g1_cfg, &new_params, Out, seq_no);
}

#[test]
fn bad_ip_len() {
    let cfg = lab_cfg();

    let eth = Ethernet {
        destination: MacAddr::BROADCAST,
        source: cfg.guest_mac,
        ethertype: Ethertype::IPV4,
    };

    let ip = Ipv4 {
        source: "0.0.0.0".parse().unwrap(),
        destination: Ipv4Addr::LOCAL_BCAST,
        protocol: IngotIpProto::UDP,
        hop_limit: 64,
        identification: 1,
        ihl: 5,
        // We write a total length of 4 bytes, which is completely
        // bogus for an IP header and should return an error during
        // processing.
        total_len: 4,
        ..Default::default()
    };

    let udp = Udp { source: 68, destination: 67, ..Default::default() };

    let mut pkt_m = MsgBlk::new_ethernet_pkt((eth, ip, udp));
    let res =
        Packet::parse_outbound(pkt_m.iter_mut(), VpcParser {}).err().unwrap();
    assert_eq!(
        res,
        ParseError::BadLength(MismatchError {
            location: c"Ipv4.total_len(min)",
            expected: 20,
            actual: 4
        })
    );
}

// Verify that OPTE generates a hairpin ARP reply when the guest
// queries for the gateway.
#[test]
fn arp_gateway() {
    use opte::engine::arp::ArpOp;

    let cfg = g1_cfg();
    let mut g1 = oxide_net_setup("arp_hairpin", &cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    let eth_hdr = Ethernet {
        destination: MacAddr::BROADCAST,
        source: cfg.guest_mac,
        ethertype: Ethertype::ARP,
    };

    // TODO: ingot?
    let arp = ArpEthIpv4 {
        htype: ARP_HTYPE_ETHERNET,
        ptype: Ethertype::IPV4,
        hlen: 6,
        plen: 4,
        op: ArpOp::REQUEST,
        sha: cfg.guest_mac,
        spa: cfg.ipv4_cfg().unwrap().private_ip,
        tha: MacAddr::from([0x00; 6]),
        tpa: cfg.ipv4_cfg().unwrap().gateway_ip,
    };

    // let mut bytes = eth_hdr.emit_vec();
    // bytes.extend_from_slice(ArpEthIpv4Raw::from(&arp).as_bytes());

    let mut pkt_m = MsgBlk::new_ethernet_pkt((eth_hdr, arp));
    let pkt = parse_outbound(&mut pkt_m, VpcParser {}).unwrap();

    let res = g1.port.process(Out, pkt);
    match res {
        Ok(Hairpin(mut hppkt)) => {
            // In this case we are parsing a hairpin reply, so we
            // can't use the VpcParser since it would expect any
            // inbound packet to be encapsulated.
            let hppkt = parse_inbound(&mut hppkt, GenericUlp {}).unwrap();
            let meta = hppkt.meta();
            let ethm = &meta.inner_eth;
            assert_eq!(ethm.destination(), cfg.guest_mac);
            assert_eq!(ethm.source(), cfg.gateway_mac);
            assert_eq!(ethm.ethertype(), Ethertype::ARP);

            let body = hppkt.to_full_meta().meta().copy_remaining();

            let (arp, ..) = ValidArpEthIpv4::parse(&body[..]).unwrap();
            assert_eq!(arp.op(), ArpOp::REPLY);
            assert_eq!(arp.ptype(), Ethertype::IPV4);
            assert_eq!(arp.sha(), cfg.gateway_mac);
            assert_eq!(arp.spa(), cfg.ipv4_cfg().unwrap().gateway_ip);
            assert_eq!(arp.tha(), cfg.guest_mac);
            assert_eq!(arp.tpa(), cfg.ipv4_cfg().unwrap().private_ip);
        }

        res => panic!("expected a Hairpin, got {:?}", res),
    }
    incr!(g1, ["stats.port.out_uft_miss"]);
}

#[test]
fn flow_expiration() {
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.vpc_map.add(g2_cfg.ipv4().private_ip.into(), g2_cfg.phys_addr());
    g1.port.start();
    set!(g1, "port_state=running");
    let now = Moment::now();

    // ================================================================
    // Run the packet through g1's port in the outbound direction and
    // verify the resulting packet meets expectations.
    // ================================================================
    let mut pkt1_m = http_syn(&g1_cfg, &g2_cfg);
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    expect_modified!(res, pkt1_m);
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "uft.out",
            "stats.port.out_modified, stats.port.out_uft_miss",
        ]
    );

    // ================================================================
    // Verify expiration
    // ================================================================
    g1.port
        .expire_flows_at(now + Duration::new(FLOW_DEF_EXPIRE_SECS, 0))
        .unwrap();
    assert_port!(g1);

    g1.port
        .expire_flows_at(now + Duration::new(FLOW_DEF_EXPIRE_SECS + 1, 0))
        .unwrap();
    zero_flows!(g1);
}

// Test that a guest can send an ICMPv6 echo request / reply to the gateway.
// This tests both link-local and VPC-private IPv6 source addresses, and the
// only supported destination, OPTE's IPv6 link-local derived from its MAC.
#[test]
fn gateway_icmpv6_ping() {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");
    let mut pcap = PcapBuilder::new("gateway_icmpv6_ping.pcap");

    let src_ips = [
        Ipv6Addr::from_eui64(&g1_cfg.guest_mac),
        g1_cfg.ipv6_cfg().unwrap().private_ip,
    ];
    let dst_ip = Ipv6Addr::from_eui64(&g1_cfg.gateway_mac);
    for src_ip in src_ips.iter().copied() {
        test_guest_to_gateway_icmpv6_ping(
            &mut g1, &g1_cfg, &mut pcap, src_ip, dst_ip,
        );
    }
}

fn test_guest_to_gateway_icmpv6_ping(
    g1: &mut PortAndVps,
    g1_cfg: &VpcCfg,
    pcap: &mut PcapBuilder,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
) {
    let ident = 7;
    let seq_no = 777;
    let data = b"reunion\0";

    // ================================================================
    // Generate an ICMP Echo Request from G1 to Virtual GW
    // ================================================================
    let mut pkt1_m = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        src_ip.into(),
        dst_ip.into(),
        ident,
        seq_no,
        &data[..],
        3,
    );
    pcap.add_pkt(&pkt1_m);

    // ================================================================
    // Run the Echo Request through g1's port in the outbound
    // direction and verify it results in an Echo Reply Hairpin packet
    // back to guest.
    // ================================================================
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    let mut hp = match res {
        Ok(Hairpin(hp)) => hp,
        _ => panic!("expected Hairpin, got {:?}", res),
    };
    incr!(g1, ["stats.port.out_uft_miss"]);

    // In this case we are parsing a hairpin reply, so we can't use
    // the VpcParser since it would expect any inbound packet to be
    // encapsulated.
    pcap.add_pkt(&hp);
    let reply = parse_inbound(&mut hp, GenericUlp {}).unwrap();

    let meta = reply.meta();

    let eth = &meta.inner_eth;
    assert_eq!(eth.source(), g1_cfg.gateway_mac);
    assert_eq!(eth.destination(), g1_cfg.guest_mac);

    let (src, dst) = match meta.inner_l3.as_ref().unwrap() {
        ValidL3::Ipv6(ip6) => {
            assert_eq!(ip6.source(), dst_ip);
            assert_eq!(ip6.destination(), src_ip);
            assert_eq!(ip6.next_header(), IngotIpProto::ICMP_V6);
            (
                Ipv6Address::from_bytes(&ip6.source()),
                Ipv6Address::from_bytes(&ip6.destination()),
            )
        }
        _ => panic!("expected inner IPv6 metadata, got IPv4"),
    };

    let Some(ValidUlp::IcmpV6(icmp6)) = &meta.inner_ulp else {
        panic!("expected inner ICMPv6 metadata");
    };

    // `Icmpv6Packet` requires the ICMPv6 header and not just the message payload.
    let mut reply_body = icmp6.emit_vec();
    let msg_type = Icmpv6Message::from(icmp6.ty().0);
    let msg_code = icmp6.code();

    reply_body.extend(reply.to_full_meta().meta().copy_remaining().into_iter());
    let reply_pkt = Icmpv6Packet::new_checked(&reply_body).unwrap();

    // Verify the parsed metadata matches the packet
    assert_eq!(msg_code, reply_pkt.msg_code());
    assert_eq!(msg_type, reply_pkt.msg_type());

    let mut csum = CsumCapab::ignored();
    csum.icmpv6 = smoltcp::phy::Checksum::Rx;
    let reply_icmp =
        Icmpv6Repr::parse(&src.into(), &dst.into(), &reply_pkt, &csum).unwrap();
    match reply_icmp {
        Icmpv6Repr::EchoReply {
            ident: r_ident,
            seq_no: r_seq_no,
            data: r_data,
        } => {
            assert_eq!(r_ident, ident);
            assert_eq!(r_seq_no, seq_no);
            assert_eq!(r_data, data);
        }

        _ => panic!("expected Echo Reply, got {:?}", reply_icmp),
    }
}

// Verify that a Router Solicitation emitted from the guest results in a Router
// Advertisement from the gateway. This tests both a solicitation sent to the
// router's unicast address, or its solicited-node multicast address.
#[test]
fn gateway_router_advert_reply() {
    use smoltcp::time::Duration;

    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");
    let mut pcap = PcapBuilder::new("gateway_router_advert_reply.pcap");

    // ====================================================
    // Generate a Router Solicitation from G1 to Virtual GW
    // ====================================================
    let mut pkt1_m = gen_router_solicitation(&g1_cfg.guest_mac);
    pcap.add_pkt(&pkt1_m);

    // ================================================================
    // Run the Solicitation through g1's port in the outbound
    // direction and verify it results in an Router Advertisement
    // hairpin back to guest.
    // ================================================================
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    let mut hp = match res {
        Ok(Hairpin(hp)) => hp,
        _ => panic!("expected Hairpin, got {:?}", res),
    };
    incr!(g1, ["stats.port.out_uft_miss"]);

    // In this case we are parsing a hairpin reply, so we can't use
    // the VpcParser since it would expect any inbound packet to be
    // encapsulated.
    pcap.add_pkt(&hp);
    let reply = parse_inbound(&mut hp, GenericUlp {}).unwrap();

    let meta = reply.meta();

    let eth = &meta.inner_eth;
    assert_eq!(
        eth.source(),
        g1_cfg.gateway_mac,
        "Router advertisement should come from the gateway's MAC"
    );
    assert_eq!(
        eth.destination(),
        g1_cfg.guest_mac,
        "Router advertisement should be destined for the guest's MAC"
    );

    let ValidL3::Ipv6(ip6) =
        meta.inner_l3.as_ref().expect("No inner IP header")
    else {
        panic!("Inner IP header is not IPv6");
    };

    assert_eq!(
        ip6.source(),
        Ipv6Addr::from_eui64(&g1_cfg.gateway_mac),
        "Router advertisement should come from the \
        gateway's link-local IPv6 address, generated \
        from the EUI-64 transform of its MAC",
    );
    let expected_dst = Ipv6Addr::from_eui64(&g1_cfg.guest_mac);
    assert_eq!(
        ip6.destination(),
        expected_dst,
        "Router advertisement should be destined for \
        the guest's Link-Local IPv6 address, generated from \
        the EUI-64 transform of its MAC"
    );
    assert_eq!(ip6.next_header(), IngotIpProto::ICMP_V6);

    // RFC 4861 6.1.2 requires that the hop limit be 255 in an RA.
    assert_eq!(ip6.hop_limit(), 255);

    let Some(ValidUlp::IcmpV6(icmp6)) = &meta.inner_ulp else {
        panic!("expected inner ICMPv6 metadata");
    };

    // `Icmpv6Packet` requires the ICMPv6 header and not just the message payload.
    // Given we successfully got the ICMPv6 metadata, rewinding here is fine.
    let mut reply_body = icmp6.emit_vec();
    let ip6_src = ip6.source();
    let ip6_dst = ip6.destination();

    reply_body.extend(reply.to_full_meta().meta().copy_remaining().into_iter());
    let reply_pkt = Icmpv6Packet::new_checked(&reply_body).unwrap();

    let mut csum = CsumCapab::ignored();
    csum.icmpv6 = smoltcp::phy::Checksum::Rx;
    let reply_icmp = Icmpv6Repr::parse(
        &IpAddress::Ipv6(ip6_src.into()),
        &IpAddress::Ipv6(ip6_dst.into()),
        &reply_pkt,
        &csum,
    )
    .unwrap();
    match reply_icmp {
        Icmpv6Repr::Ndisc(NdiscRepr::RouterAdvert {
            hop_limit,
            flags,
            router_lifetime,
            reachable_time,
            retrans_time,
            lladdr,
            mtu,
            prefix_info,
        }) => {
            assert_eq!(hop_limit, u8::MAX);
            assert_eq!(flags, NdiscRouterFlags::MANAGED);
            assert_eq!(router_lifetime, Duration::from_secs(9_000));
            assert_eq!(reachable_time, Duration::from_millis(0));
            assert_eq!(retrans_time, Duration::from_millis(0));
            assert_eq!(
                lladdr.expect("Expected a Link-Layer Address option"),
                RawHardwareAddress::from_bytes(&g1_cfg.gateway_mac)
            );
            assert_eq!(mtu, Some(1500));
            assert!(prefix_info.is_none());
        }
        other => {
            panic!(
                "Expected an ICMPv6 Router Advertisement, found {:?}",
                other
            );
        }
    };
}

#[derive(Clone, Copy, Debug)]
struct SolicitTestData {
    ns: SolicitInfo,
    na: Option<AdvertInfo>,
}

// Generate the set of Neighbor Solicitations and their corresponding Neighbor
// Advertisements (if they exist) that we expect to see for conforming clients.
//
// RFC 4861 describes the general expectations about the IP addresses (and MACs)
// that should be included in solicitations and advertisements in most cases.
// These are summarized in section 4.3 and 4.4, though there is also detail
// about validation of solicitations in section 7.1.1 and how to construct the
// corresponding advertisements in 7.2.4.
//
// There are a few key cases to consider:
//
// 1. A guest starts up, and performs Duplicate Address Detection (DAD). This is
//    done by sending an NS from the unspecified IP address, to the
//    solicited-node multicast IP/MAC address, with a target address of the
//    desired IP address.
//
// 2. A guest starts up, and happens to perform DAD for the exact address we
//    want to reserve for OPTE.
//
// 3. The guest has already assigned their link-local address, and they're
//    trying to verify reachability of the gateway neighbor.
//
// 4. The guest is trying to resolve any other link-local IP address.
//
// Here is the summary of our responses. See the implementation of this method
// for more details on exactly what data we expect in the NS and NA, and why.
//
// 1. Drop the packet, since we need the guest to be able to self-assign this
//    address.
// 2. Send an NA, since we _cannot_ let the guest assign this address.
// 3. Send an NA right back to the guest, confirming reachability.
// 4. Drop the packet. We are not providing any L2 emulation, and so the gateway
//    and the guest need to appear to be on an isolated L2 segment. Nothing else
//    should resolve.
fn generate_solicit_test_data(cfg: &VpcCfg) -> Vec<SolicitTestData> {
    vec![
        // When the client first initializes its IPv6 interface, it can give
        // itself a tentative address. This is usually generated from the EUI-64
        // transform of its MAC, but not always. However it derives it, the
        // client first performs Duplicate Address Detection (DAD). This NS is
        // sent from the unspecified IP address, to the solicited-node multicast
        // group for the tentative address. Note that the client is not supposed
        // to set the Link-Layer address option when sending from the
        // unspecified IP address, though we have no way of discriminating that
        // cause for a drop from the fact that the address is not a duplicate.
        //
        // In this case, the guest is using the EUI-64 transform for this
        // tentative address. We should not send an NA, since they must be
        // allowed to self-assign that address.
        SolicitTestData {
            ns: SolicitInfo {
                src_mac: cfg.guest_mac,
                dst_mac: Ipv6Addr::from_eui64(&cfg.guest_mac)
                    .solicited_node_multicast()
                    .unchecked_multicast_mac(),
                src_ip: Ipv6Addr::ANY_ADDR,
                dst_ip: Ipv6Addr::from_eui64(&cfg.guest_mac)
                    .solicited_node_multicast(),
                target_addr: Ipv6Addr::from_eui64(&cfg.guest_mac),
                lladdr: None,
            },
            na: None,
        },
        // In this case, the client happens to pick our gateway's EUI-64
        // link-local address. We _must_ send back an NA, so that they configure
        // to use a different address. Note that the client is not supposed to
        // set the Link-Layer address option.
        //
        // Since the source IP was unspecified, we are required to send the NA
        // to the All-Nodes multicast group. Note that we also must not set the
        // SOLICITED flag, since the response is multicast.
        SolicitTestData {
            ns: SolicitInfo {
                src_mac: cfg.guest_mac,
                dst_mac: Ipv6Addr::from_eui64(&cfg.gateway_mac)
                    .solicited_node_multicast()
                    .unchecked_multicast_mac(),
                src_ip: Ipv6Addr::ANY_ADDR,
                dst_ip: Ipv6Addr::from_eui64(&cfg.gateway_mac)
                    .solicited_node_multicast(),
                target_addr: Ipv6Addr::from_eui64(&cfg.gateway_mac),
                lladdr: None,
            },
            na: Some(AdvertInfo {
                src_mac: cfg.gateway_mac,
                dst_mac: Ipv6Addr::ALL_NODES.unchecked_multicast_mac(),
                src_ip: Ipv6Addr::from_eui64(&cfg.gateway_mac),
                dst_ip: Ipv6Addr::ALL_NODES,
                target_addr: Ipv6Addr::from_eui64(&cfg.gateway_mac),
                lladdr: Some(cfg.gateway_mac),
                flags: NdiscNeighborFlags::ROUTER
                    | NdiscNeighborFlags::OVERRIDE,
            }),
        },
        // In this case, the client is checking reachability of the gateway's IP
        // address. The packet is expected to be unicast to that address, and we
        // need to respond with an NA unicast back to them, so that they can
        // maintain reachability information.
        //
        // Note that here we set the SOLICITED flag.
        SolicitTestData {
            ns: SolicitInfo {
                src_mac: cfg.guest_mac,
                dst_mac: cfg.gateway_mac,
                src_ip: Ipv6Addr::from_eui64(&cfg.guest_mac),
                dst_ip: Ipv6Addr::from_eui64(&cfg.gateway_mac),
                target_addr: Ipv6Addr::from_eui64(&cfg.gateway_mac),
                lladdr: Some(cfg.guest_mac),
            },
            na: Some(AdvertInfo {
                src_mac: cfg.gateway_mac,
                dst_mac: cfg.guest_mac,
                src_ip: Ipv6Addr::from_eui64(&cfg.gateway_mac),
                dst_ip: Ipv6Addr::from_eui64(&cfg.guest_mac),
                target_addr: Ipv6Addr::from_eui64(&cfg.gateway_mac),
                lladdr: Some(cfg.gateway_mac),
                flags: NdiscNeighborFlags::ROUTER
                    | NdiscNeighborFlags::SOLICITED
                    | NdiscNeighborFlags::OVERRIDE,
            }),
        },
        // In our last case, the guest is doing resolution for _any_ old
        // link-local IPv6 address (other than the gateway's, which is tested in
        // case (2)). Since this is resolution, the address should be sent to
        // the solicited-node multicast group. But since the guest already has
        // an assigned IP, the source is _not_ UNSPEC, but that actual IP.
        //
        // We need to drop the packet, since there is nothing else on this L2
        // segment.
        SolicitTestData {
            ns: SolicitInfo {
                src_mac: cfg.guest_mac,
                dst_mac: Ipv6Addr::from_const([0xfe80, 0, 0, 0, 1, 1, 1, 1])
                    .solicited_node_multicast()
                    .unchecked_multicast_mac(),
                src_ip: Ipv6Addr::from_eui64(&cfg.guest_mac),
                dst_ip: Ipv6Addr::from_const([0xfe80, 0, 0, 0, 1, 1, 1, 1]),
                target_addr: Ipv6Addr::from_const([
                    0xfe80, 0, 0, 0, 1, 1, 1, 1,
                ]),
                lladdr: None,
            },
            na: None,
        },
    ]
}

// Assert that the Neighbor Advertisement in `hp` matches the expectations in
// `na`.
fn validate_hairpin_advert(
    pcap: &mut PcapBuilder,
    mut hp: MsgBlk,
    na: AdvertInfo,
) {
    // In this case we are parsing a hairpin reply, so we can't use
    // the VpcParser since it would expect any inbound packet to be
    // encapsulated.
    pcap.add_pkt(&hp);
    let reply = parse_inbound(&mut hp, GenericUlp {}).unwrap();

    let meta = reply.meta();

    // Check that the inner MACs are what we expect.
    let eth = &meta.inner_eth;
    assert_eq!(eth.source(), na.src_mac);
    assert_eq!(eth.destination(), na.dst_mac);

    // Check that the inner IPs are what we expect.
    let ValidL3::Ipv6(ip6) =
        meta.inner_l3.as_ref().expect("No inner IP header")
    else {
        panic!("Inner IP header is not IPv6");
    };
    assert_eq!(ip6.source(), na.src_ip);
    assert_eq!(ip6.destination(), na.dst_ip);
    assert_eq!(ip6.next_header(), IngotIpProto::ICMP_V6);

    // RFC 4861 7.1.2 requires that the hop limit be 255 in an NA.
    assert_eq!(ip6.hop_limit(), 255);

    let Some(ValidUlp::IcmpV6(icmp6)) = &meta.inner_ulp else {
        panic!("expected inner ICMPv6 metadata");
    };

    // `Icmpv6Packet` requires the ICMPv6 header and not just the message payload.
    // Given we successfully got the ICMPv6 metadata, rewinding here is fine.
    let mut reply_body = icmp6.emit_vec();
    let ip6_src = ip6.source();
    let ip6_dst = ip6.destination();

    reply_body.extend(reply.to_full_meta().meta().copy_remaining().into_iter());
    let reply_pkt = Icmpv6Packet::new_checked(&reply_body).unwrap();

    // Validate the details of the Neighbor Advertisement itself.
    let mut csum = CsumCapab::ignored();
    csum.icmpv6 = smoltcp::phy::Checksum::Rx;
    let reply_icmp = Icmpv6Repr::parse(
        &IpAddress::Ipv6(ip6_src.into()),
        &IpAddress::Ipv6(ip6_dst.into()),
        &reply_pkt,
        &csum,
    )
    .unwrap();
    if let Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
        flags,
        target_addr,
        lladdr,
    }) = reply_icmp
    {
        assert_eq!(flags, na.flags);
        assert_eq!(target_addr, na.target_addr.into());
        assert_eq!(
            lladdr,
            na.lladdr.map(|x| RawHardwareAddress::from_bytes(&x))
        );
    } else {
        panic!(
            "Expected an ICMPv6 Neighbor Advertisement, found {:?}",
            reply_icmp
        );
    }
}

// Ensure that we either Drop a Neighbor Solicitation, or generate a Neighbor
// Advertisement with the right data, based on our defined test cases.
#[test]
fn test_gateway_neighbor_advert_reply() {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");
    let mut pcap = PcapBuilder::new("gateway_neighbor_advert_reply.pcap");

    let mut with_checksum = false;
    let data = generate_solicit_test_data(&g1_cfg);
    for d in data {
        let mut pkt = generate_neighbor_solicitation(&d.ns, with_checksum);
        // Alternate between using smoltcp or our `compute_checksums` method
        // to compute the checksums.
        if !with_checksum {
            let mut parsed =
                parse_outbound(&mut pkt, VpcParser {}).unwrap().to_full_meta();
            parsed.compute_checksums();
        }
        with_checksum = !with_checksum;
        pcap.add_pkt(&pkt);
        let pkt1 = parse_outbound(&mut pkt, VpcParser {}).unwrap();
        let res = g1.port.process(Out, pkt1);
        match (res, d.na) {
            (Ok(ProcessResult::Drop { .. }), None) => {
                // Dropped the packet, as we expected
                incr!(
                    g1,
                    [
                        "stats.port.out_drop, stats.port.out_drop_layer",
                        "stats.port.out_uft_miss"
                    ]
                );
            }
            (Ok(Hairpin(hp)), Some(na)) => {
                incr!(g1, ["stats.port.out_uft_miss"]);
                assert_port!(g1);
                validate_hairpin_advert(&mut pcap, hp, na);
            }
            (res, _) => {
                let na =
                    d.na.map(|na| na.to_string())
                        .unwrap_or_else(|| String::from("Drop"));
                panic!(
                    "Generated unexpected packet from NS: {}\n\
                    Result: {:?}\nExpected: {}",
                    d.ns, res, na,
                );
            }
        };
    }
}

// Neighbor advertisements (and any other NDP not targeted *at* the gateway)
// are to be explicitly dropped.
#[test]
fn outbound_ndp_dropped() {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    let IpCfg::DualStack { ipv4: _, ipv6 } = g1_cfg.ip_cfg else {
        panic!("Host should be configured v6 or dual stack.");
    };

    router::add_entry(
        &g1.port,
        IpCidr::Ip6(ipv6.vpc_subnet),
        RouterTarget::VpcSubnet(IpCidr::Ip6(ipv6.vpc_subnet)),
        RouterClass::System,
    )
    .unwrap();
    incr!(g1, ["router.rules.out", "epoch"]);

    // Add router entry that allows g1 to route to internet.
    router::add_entry(
        &g1.port,
        IpCidr::Ip6("::/0".parse().unwrap()),
        RouterTarget::InternetGateway(None),
        RouterClass::System,
    )
    .unwrap();
    incr!(g1, ["router.rules.out", "epoch"]);

    // Test case from Omicron #2857.
    let outbound_na = AdvertInfo {
        src_mac: g1_cfg.guest_mac,
        dst_mac: MacAddr::BROADCAST,
        src_ip: ipv6.private_ip,
        dst_ip: Ipv6Addr::ALL_NODES,
        target_addr: Ipv6Addr::from_const([
            0xfd77, 0xe9d2, 0x9cd9, 0x2000, 0, 0, 0, 6,
        ]),
        lladdr: Some(g1_cfg.guest_mac),
        flags: NdiscNeighborFlags::OVERRIDE,
    };

    let mut pkt_m = generate_neighbor_advertisement(&outbound_na, true);
    let pkt = parse_outbound(&mut pkt_m, VpcParser {}).unwrap();

    let res = g1.port.process(Out, pkt).unwrap();
    match res {
        ProcessResult::Drop { .. } => {
            incr!(
                g1,
                [
                    "stats.port.out_drop, stats.port.out_drop_layer",
                    "stats.port.out_uft_miss"
                ]
            );
        }
        a => panic!(
            "unexpected respondse for outbound NA. Got {a:?}, expected Drop."
        ),
    }
}

// All encapsulated NDP traffic received from elsewhere must be dropped --
// all zones/VMs are technically on their own segment with the gateway.
#[test]
fn inbound_ndp_dropped_at_gateway() {
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    let g2_phys = TestIpPhys {
        ip: g2_cfg.phys_ip,
        mac: g2_cfg.gateway_mac,
        vni: g2_cfg.vni,
    };
    let g1_phys = TestIpPhys {
        ip: g1_cfg.phys_ip,
        mac: g1_cfg.gateway_mac,
        vni: g1_cfg.vni,
    };

    let IpCfg::DualStack { ipv4: _, ipv6: g1_v6 } = g1_cfg.ip_cfg else {
        panic!("Host should be configured v6 or dual stack.");
    };
    let IpCfg::DualStack { ipv4: _, ipv6: g2_v6 } = g2_cfg.ip_cfg else {
        panic!("Host should be configured v6 or dual stack.");
    };

    // Assume we have received an NS from another node: set up as two VMs
    // here, but equally valid if rack-external on same subnet.
    let ns = SolicitInfo {
        src_mac: g2_cfg.guest_mac,
        dst_mac: g2_cfg.gateway_mac,
        src_ip: g2_v6.private_ip,
        dst_ip: g1_v6.private_ip,
        target_addr: g1_v6.private_ip,
        lladdr: Some(g1_cfg.guest_mac),
    };

    let pkt = generate_neighbor_solicitation(&ns, true);
    let mut pkt_m = encap(pkt, g2_phys, g1_phys);
    let pkt = parse_inbound(&mut pkt_m, VpcParser {}).unwrap();
    let res = g1.port.process(In, pkt).unwrap();
    println!("{res:?}");
    match res {
        ProcessResult::Drop { .. } => {
            incr!(
                g1,
                [
                    "stats.port.in_drop, stats.port.in_drop_layer",
                    "stats.port.in_uft_miss",
                    // The firewall increments its flow count because
                    // these two hosts *are allowed to talk to one
                    // another* -- just not on this *subset* of ICMPv6!
                    "firewall.flows.in",
                    "firewall.flows.out"
                ]
            );
        }
        a => panic!(
            "unexpected response for inbound NS. Got {a:?}, expected Drop."
        ),
    }
}

// Build a packet from a DHCPv6 message, from a client to server.
fn packet_from_client_dhcpv6_message(
    cfg: &VpcCfg,
    msg: &dhcpv6::protocol::Message<'_>,
) -> MsgBlk {
    let eth = Ethernet {
        destination: dhcpv6::ALL_RELAYS_AND_SERVERS.multicast_mac().unwrap(),
        source: cfg.guest_mac,
        ethertype: Ethertype::IPV6,
    };

    let payload_len = (msg.buffer_len() + Udp::MINIMUM_LENGTH) as u16;

    let ip = Ipv6 {
        source: Ipv6Addr::from_eui64(&cfg.guest_mac),
        destination: dhcpv6::ALL_RELAYS_AND_SERVERS,
        next_header: IngotIpProto::UDP,
        payload_len,
        ..Default::default()
    };

    let udp = Udp {
        source: dhcpv6::CLIENT_PORT,
        destination: dhcpv6::SERVER_PORT,
        length: payload_len,
        ..Default::default()
    };

    write_dhcpv6_packet(eth, ip, udp, msg)
}

fn write_dhcpv6_packet(
    eth: Ethernet,
    ip: Ipv6,
    udp: Udp,
    msg: &dhcpv6::protocol::Message<'_>,
) -> MsgBlk {
    let total_len = msg.buffer_len() + (&eth, &ip, &udp).packet_length();

    let mut pkt = MsgBlk::new_ethernet(total_len);
    pkt.emit_back((eth, ip, udp)).unwrap();
    let l = pkt.len();
    pkt.resize(total_len).unwrap();
    msg.copy_into(&mut pkt[l..]);

    pkt
}

// Assert the essential details of a DHCPv6 exchange. The client request is in
// `request_pkt`, and the server reply in `reply_pkt`.
//
// This asserts that the Ethernet, IPv6, and UDP metadata correct. It also
// verifies the basics of any DHCPv6 exchange:
//
// - The server must copy the client's Transaction ID verbatim.
// - The server must copy the client's ID option verbatim.
// - The server must include its own Server ID option.
fn verify_dhcpv6_essentials<'a>(
    cfg: &VpcCfg,
    request_pkt: &mut MsgBlk,
    request: &dhcpv6::protocol::Message<'a>,
    reply_pkt: &mut MsgBlk,
    reply: &dhcpv6::protocol::Message<'a>,
) {
    let request_pkt =
        parse_outbound(request_pkt, GenericUlp {}).unwrap().to_full_meta();
    let reply_pkt =
        parse_inbound(reply_pkt, GenericUlp {}).unwrap().to_full_meta();
    let request_meta = request_pkt.meta();
    let reply_meta = reply_pkt.meta();
    let request_ether = request_meta.inner_ether();
    let reply_ether = reply_meta.inner_ether();
    assert_eq!(
        request_ether.destination(),
        dhcpv6::ALL_RELAYS_AND_SERVERS.multicast_mac().unwrap()
    );
    assert_eq!(request_ether.source(), reply_ether.destination());

    let request_ip = request_meta.inner_ip6().unwrap();
    let reply_ip = reply_meta.inner_ip6().unwrap();
    assert_eq!(request_ip.source(), Ipv6Addr::from_eui64(&cfg.guest_mac));
    assert_eq!(request_ip.destination(), dhcpv6::ALL_RELAYS_AND_SERVERS);
    assert_eq!(request_ip.next_header(), IngotIpProto::UDP);
    assert_eq!(reply_ip.destination(), request_ip.source());
    assert_eq!(reply_ip.source(), Ipv6Addr::from_eui64(&cfg.gateway_mac));
    assert_eq!(reply_ip.next_header(), IngotIpProto::UDP);

    let request_udp = request_meta.inner_udp().unwrap();
    let reply_udp = reply_meta.inner_udp().unwrap();
    assert_eq!(request_udp.source(), dhcpv6::CLIENT_PORT);
    assert_eq!(request_udp.destination(), dhcpv6::SERVER_PORT);
    assert_eq!(reply_udp.destination(), dhcpv6::CLIENT_PORT);
    assert_eq!(reply_udp.source(), dhcpv6::SERVER_PORT);

    // Verify the details of the DHCPv6 exchange itself.
    assert_eq!(reply.xid, request.xid);
    assert!(reply.has_option(dhcpv6::options::Code::ServerId));
    let client_id =
        request.find_option(dhcpv6::options::Code::ClientId).unwrap();
    assert_eq!(
        client_id,
        reply.find_option(dhcpv6::options::Code::ClientId).unwrap()
    );

    // Assert FQDN is correctly constructed.
    assert!(reply.has_option(dhcpv6::options::Code::Fqdn));
    let fqdn = reply.find_option(dhcpv6::options::Code::Fqdn).unwrap();
    let dhcpv6::options::Option::Fqdn(fqdn) = fqdn else {
        panic!("Found option from FQDN lookup was not FQDN.");
    };
    assert_eq!(
        &fqdn[1..],
        "\x07testbox\x04test\x05oxide\x08computer\x00".as_bytes()
    );
}

// Test that we reply to a DHCPv6 Solicit or Request message with the right
// reply.
//
// A Request should result in a Reply message with all the data the client
// requested (that the server supports).
//
// A Solicit message normally generates an Advertise message. But if the Solicit
// message also contains the Rapid Commit option, the server is supposed to
// respond with a Reply instead.
//
// In both cases, the contained data is the same. (That's so that the client
// could use the data from more than one server to decide which one to actually
// make a subsequent Request to.)
#[test]
fn test_reply_to_dhcpv6_solicit_or_request() {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");
    let mut pcap = PcapBuilder::new("dhcpv6_solicit_reply.pcap");

    let requested_iana = dhcpv6::options::IaNa {
        id: dhcpv6::options::IaId(0xff7),
        t1: dhcpv6::Lifetime(3600),
        t2: dhcpv6::Lifetime(6200),
        options: vec![],
    };
    // Also request the DNS server list and Domain Search List, via the Option
    // Request option.
    let extra_options = &[
        dhcpv6::options::Code::DnsServers,
        dhcpv6::options::Code::DomainList,
        dhcpv6::options::Code::Fqdn,
    ];
    let oro = dhcpv6::options::OptionRequest(extra_options.as_slice().into());
    let base_options = vec![
        dhcpv6::options::Option::ClientId(dhcpv6::Duid::from(
            &g1_cfg.guest_mac,
        )),
        dhcpv6::options::Option::ElapsedTime(dhcpv6::options::ElapsedTime(10)),
        dhcpv6::options::Option::IaNa(requested_iana.clone()),
        dhcpv6::options::Option::OptionRequest(oro),
    ];

    for msg_type in [
        dhcpv6::protocol::MessageType::Solicit,
        dhcpv6::protocol::MessageType::Request,
    ] {
        for has_rapid_commit in [false, true] {
            let mut options = base_options.clone();
            if has_rapid_commit {
                options.push(dhcpv6::options::Option::RapidCommit);
            }
            // Request messages must include the Server ID we're making the
            // request to.
            if msg_type == dhcpv6::protocol::MessageType::Request {
                options.push(dhcpv6::options::Option::ServerId(
                    dhcpv6::Duid::from(&g1_cfg.gateway_mac),
                ));
            }
            let request = dhcpv6::protocol::Message {
                typ: msg_type,
                xid: dhcpv6::TransactionId::from(&[0u8, 1, 2]),
                options,
            };
            let mut request_pkt_m =
                packet_from_client_dhcpv6_message(&g1_cfg, &request);
            pcap.add_pkt(&request_pkt_m);
            let request_pkt =
                parse_outbound(&mut request_pkt_m, VpcParser {}).unwrap();
            let res = g1.port.process(Out, request_pkt).unwrap();

            let Hairpin(mut hp) = res else {
                panic!("Expected a Hairpin, found {:?}", res);
            };

            // In this case we are parsing a hairpin reply, so we
            // can't use the VpcParser since it would expect any
            // inbound packet to be encapsulated.
            pcap.add_pkt(&hp);

            let reply_pkt =
                parse_inbound(&mut hp, GenericUlp {}).unwrap().to_full_meta();
            let out_body = reply_pkt.meta().copy_remaining();
            drop(reply_pkt);

            let reply =
                dhcpv6::protocol::Message::from_bytes(&out_body).unwrap();
            verify_dhcpv6_essentials(
                &g1_cfg,
                &mut request_pkt_m,
                &request,
                &mut hp,
                &reply,
            );

            // Verify the message type of the reply:
            //
            // Solicit - Rapid Commit -> Advertise
            // Solicit + Rapid Commit -> Reply
            // Request + either -> Reply
            if has_rapid_commit
                || msg_type == dhcpv6::protocol::MessageType::Request
            {
                assert_eq!(reply.typ, dhcpv6::protocol::MessageType::Reply);
            } else {
                assert_eq!(reply.typ, dhcpv6::protocol::MessageType::Advertise);
            }

            // In the case of Solicit + Rapid Commit, we are required to
            // send the Rapid Commit option back in our reply.
            if has_rapid_commit
                && msg_type == dhcpv6::protocol::MessageType::Solicit
            {
                assert!(reply.has_option(dhcpv6::options::Code::RapidCommit));
            }

            // Regardless of the message type, we are supposed to
            // include answers for each Option the client
            // requested (and that we support). That's mostly just
            // the actual VPC-private IPv6 address, but we also check the
            // Domain Search List option.
            let iana = reply.find_option(dhcpv6::options::Code::IaNa).unwrap();
            if let dhcpv6::options::Option::IaNa(dhcpv6::options::IaNa {
                id,
                t1,
                t2,
                options,
            }) = iana
            {
                assert_eq!(id, &requested_iana.id);
                assert!(t1.is_infinite());
                assert!(t2.is_infinite());
                assert!(!options.is_empty());

                if let Some(dhcpv6::options::Option::IaAddr(
                    dhcpv6::options::IaAddr {
                        addr,
                        valid,
                        preferred,
                        options: opts,
                    },
                )) = options.first()
                {
                    assert_eq!(addr, &g1_cfg.ipv6_cfg().unwrap().private_ip);
                    assert!(valid.is_infinite());
                    assert!(preferred.is_infinite());
                    assert!(opts.is_empty());
                } else {
                    panic!("Expected an IA Addr option, found {:#?}", options);
                }
            } else {
                panic!("Expected an IANA option, found {:?}", iana);
            }

            let used_dhcp = base_dhcp_config();

            let domain_list = reply
                .find_option(dhcpv6::options::Code::DomainList)
                .expect("Expected a Domain Search List option");
            let dhcpv6::options::Option::DomainList(bytes) = domain_list else {
                panic!("Expected an Option::DomainList");
            };
            let mut expected_bytes = Vec::new();
            for name in used_dhcp.domain_search_list.iter() {
                expected_bytes.extend_from_slice(name.encode());
            }
            assert_eq!(
                *bytes, expected_bytes,
                "Domain Search List option not correctly encoded"
            );
        }
    }
}

fn establish_http_conn(
    g1_cfg: &VpcCfg,
    g1: &mut PortAndVps,
    dst_ip: Ipv4Addr,
) -> u16 {
    // ================================================================
    // Step 1
    //
    // Run the SYN packet through g1's port in the outbound direction
    // and verify it is accepted.
    // ================================================================
    let mut pkt1_m = http_syn2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    expect_modified!(res, pkt1_m);
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "nat.flows.in, nat.flows.out",
            "uft.out",
            "stats.port.out_modified, stats.port.out_uft_miss",
        ]
    );
    let pkt1 = parse_inbound(&mut pkt1_m, VpcParser {}).unwrap();
    let snat_port =
        pkt1.to_full_meta().meta().inner_ulp().unwrap().src_port().unwrap();

    // ================================================================
    // Step 2
    //
    // Run the SYN+ACK packet through g1's port in the inbound
    // direction and verify it is accepted.
    // ================================================================
    let mut pkt2_m = http_syn_ack2(
        BS_MAC_ADDR,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        snat_port,
    );
    let g1_phys = TestIpPhys {
        ip: g1_cfg.phys_ip,
        mac: g1_cfg.guest_mac,
        vni: g1_cfg.vni,
    };
    let bs_phys = TestIpPhys {
        ip: BS_IP_ADDR,
        mac: BS_MAC_ADDR,
        vni: Vni::new(BOUNDARY_SERVICES_VNI).unwrap(),
    };
    pkt2_m = encap_external(pkt2_m, bs_phys, g1_phys);
    let pkt2 = parse_inbound(&mut pkt2_m, VpcParser {}).unwrap();
    let res = g1.port.process(In, pkt2);
    expect_modified!(res, pkt2_m);
    incr!(g1, ["uft.in", "stats.port.in_modified, stats.port.in_uft_miss"]);

    // ================================================================
    // Step 3
    //
    // Send ACK to establish connection.
    // ================================================================
    let mut pkt3_m = http_ack2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let pkt3 = parse_outbound(&mut pkt3_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt3);
    expect_modified!(res, pkt3_m);
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    snat_port
}

// Verify that changing rules causes invalidation of UFT and LFT
// entries. This variant verifies that the first outbound packet after
// the rule change causes the UFT invalidation.
//
// 1. Setup g1 as client to external HTTP server (ability to send TCP
// outbound and SNAT configured).
//
// 2. Establish an HTTP connection between g1 and the server.
//
// 3. Set firewall rules on g1 to deny all outbound/inbound traffic.
// Verify that the firewall layer's LFT entries are removed.
//
// 4. Try to send the HTTP GET. Verify the packet is denied and that
// the UFT entries for the flow are removed.
#[test]
fn uft_lft_invalidation_out() {
    // ================================================================
    // Step 1
    // ================================================================
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    // Add default route.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway(None),
        RouterClass::System,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    // ================================================================
    // Step 2
    // ================================================================
    let dst_ip = "52.10.128.69".parse().unwrap();
    let _snat_port = establish_http_conn(&g1_cfg, &mut g1, dst_ip);

    // ================================================================
    // Step 3
    // ================================================================
    let any_out = "dir=out action=deny priority=65535 protocol=any";
    firewall::set_fw_rules(
        &g1.port,
        &SetFwRulesReq {
            port_name: g1.port.name().to_string(),
            rules: vec![any_out.parse().unwrap()],
        },
    )
    .unwrap();
    update!(
        g1,
        [
            "incr:epoch",
            "set:firewall.flows.in=0, firewall.flows.out=0",
            "set:firewall.rules.out=1, firewall.rules.in=0",
        ]
    );

    // ================================================================
    // Step 4
    // ================================================================
    let mut pkt4_m = http_get2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let pkt4 = parse_outbound(&mut pkt4_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt4);
    assert_drop!(
        res,
        DropReason::Layer { name: "firewall", reason: DenyReason::Rule }
    );
    update!(
        g1,
        [
            "set:firewall.flows.out=0, firewall.flows.in=0",
            "set:uft.in=0, uft.out=0",
            "incr:stats.port.out_drop, stats.port.out_drop_layer",
            "incr:stats.port.out_uft_miss",
        ]
    );
}

// Verify that changing rules causes invalidation of UFT and LFT
// entries. This variant verifies that the first inbound packet after
// the firewall rule change causes UFT invalidation.
//
// 1. Setup g1 as client to external HTTP server: (ability to send TCP
// outbound and SNAT configured).
//
// 2. Establish an HTTP connection between g1 and the server. Send GET
// and receive ACK for GET.
//
// 3. Set firewall rules on g1 to deny all outbound/inbound traffic.
// Verify that the firewall layer's LFT entries are removed.
//
// 4. Send 301 reply from server to guest. Verify the packet is
// denied and that the UFT entries are removed.
#[test]
fn uft_lft_invalidation_in() {
    // ================================================================
    // Step 1
    // ================================================================
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    // Add default route.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway(None),
        RouterClass::System,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    // ================================================================
    // Step 2
    // ================================================================
    let dst_ip = "52.10.128.69".parse().unwrap();
    let g1_phys = TestIpPhys {
        ip: g1_cfg.phys_ip,
        mac: g1_cfg.guest_mac,
        vni: g1_cfg.vni,
    };
    let snat_port = establish_http_conn(&g1_cfg, &mut g1, dst_ip);

    let mut pkt1_m = http_get2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    expect_modified!(res, pkt1_m);
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);

    let mut pkt2_m = http_get_ack2(
        BS_MAC_ADDR,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        snat_port,
    );
    let bs_phys = TestIpPhys {
        ip: BS_IP_ADDR,
        mac: BS_MAC_ADDR,
        vni: Vni::new(BOUNDARY_SERVICES_VNI).unwrap(),
    };
    pkt2_m = encap_external(pkt2_m, bs_phys, g1_phys);
    let pkt2 = parse_inbound(&mut pkt2_m, VpcParser {}).unwrap();
    let res = g1.port.process(In, pkt2);
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    expect_modified!(res, pkt2_m);

    // ================================================================
    // Step 3
    // ================================================================
    let any_out = "dir=out action=deny priority=65535 protocol=any";
    firewall::set_fw_rules(
        &g1.port,
        &SetFwRulesReq {
            port_name: g1.port.name().to_string(),
            rules: vec![any_out.parse().unwrap()],
        },
    )
    .unwrap();
    update!(
        g1,
        [
            "incr:epoch",
            "set:firewall.flows.in=0, firewall.flows.out=0",
            "set:firewall.rules.out=1, firewall.rules.in=0",
        ]
    );

    // ================================================================
    // Step 4
    // ================================================================
    let mut pkt3_m = http_301_reply2(
        BS_MAC_ADDR,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        snat_port,
    );
    let bs_phys = TestIpPhys {
        ip: BS_IP_ADDR,
        mac: BS_MAC_ADDR,
        vni: Vni::new(BOUNDARY_SERVICES_VNI).unwrap(),
    };
    pkt3_m = encap_external(pkt3_m, bs_phys, g1_phys);
    let pkt3 = parse_inbound(&mut pkt3_m, VpcParser {}).unwrap();
    let res = g1.port.process(In, pkt3);
    assert_drop!(
        res,
        DropReason::Layer { name: "firewall", reason: DenyReason::Default }
    );
    update!(
        g1,
        [
            "set:nat.flows.in=1, nat.flows.out=1",
            "set:uft.in=0, uft.out=0",
            "incr:stats.port.in_drop, stats.port.in_drop_layer",
            "incr:stats.port.in_uft_miss",
        ]
    );
}

fn test_outbound_http(g1_cfg: &VpcCfg, g1: &mut PortAndVps) -> InnerFlowId {
    let g1_phys = TestIpPhys {
        ip: g1_cfg.phys_ip,
        mac: g1_cfg.guest_mac,
        vni: g1_cfg.vni,
    };
    let bs_phys = TestIpPhys {
        ip: BS_IP_ADDR,
        mac: BS_MAC_ADDR,
        vni: Vni::new(BOUNDARY_SERVICES_VNI).unwrap(),
    };

    // ================================================================
    // SYN: Client -> Server
    // ================================================================
    let dst_ip = "52.10.128.69".parse().unwrap();
    let mut pkt1_m = http_syn2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let flow = pkt1.flow();
    let res = g1.port.process(Out, pkt1);
    expect_modified!(res, pkt1_m);
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "nat.flows.in, nat.flows.out",
            "uft.out",
            "stats.port.out_modified, stats.port.out_uft_miss",
        ]
    );
    let pkt1 = parse_inbound(&mut pkt1_m, VpcParser {}).unwrap();
    let snat_port =
        pkt1.to_full_meta().meta().inner_ulp().unwrap().src_port().unwrap();
    assert_eq!(TcpState::SynSent, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // SYN+ACK: Server -> Client
    // ================================================================
    let mut pkt2_m = http_syn_ack2(
        BS_MAC_ADDR,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        snat_port,
    );
    pkt2_m = encap_external(pkt2_m, bs_phys, g1_phys);
    let pkt2 = parse_inbound(&mut pkt2_m, VpcParser {}).unwrap();
    let res = g1.port.process(In, pkt2);
    expect_modified!(res, pkt2_m);
    incr!(g1, ["uft.in", "stats.port.in_modified, stats.port.in_uft_miss"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK: Client -> Server
    // ================================================================
    let mut pkt3_m = http_ack2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let pkt3 = parse_outbound(&mut pkt3_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt3);
    expect_modified!(res, pkt3_m);
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // HTTP GET: Client -> Server
    // ================================================================
    let mut pkt4_m = http_get2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let pkt4 = parse_outbound(&mut pkt4_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt4);
    expect_modified!(res, pkt4_m);
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK HTTP GET: Server -> Client
    // ================================================================
    let mut pkt5_m = http_get_ack2(
        BS_MAC_ADDR,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        snat_port,
    );
    pkt5_m = encap_external(pkt5_m, bs_phys, g1_phys);
    let pkt5 = parse_inbound(&mut pkt5_m, VpcParser {}).unwrap();
    let res = g1.port.process(In, pkt5);
    expect_modified!(res, pkt5_m);
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // HTTP 301 Reply: Server -> Client
    // ================================================================
    let mut pkt6_m = http_301_reply2(
        BS_MAC_ADDR,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        snat_port,
    );
    pkt6_m = encap_external(pkt6_m, bs_phys, g1_phys);
    let pkt6 = parse_inbound(&mut pkt6_m, VpcParser {}).unwrap();
    let res = g1.port.process(In, pkt6);
    expect_modified!(res, pkt6_m);
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK HTTP 301: Client -> Server
    // ================================================================
    let mut pkt7_m = http_301_ack2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let pkt7 = parse_outbound(&mut pkt7_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt7);
    expect_modified!(res, pkt7_m);
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // FIN: Client -> Server
    // ================================================================
    let mut pkt8_m = http_guest_fin2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let pkt8 = parse_outbound(&mut pkt8_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt8);
    expect_modified!(res, pkt8_m);
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    assert_eq!(TcpState::FinWait1, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK FIN: Server -> Client
    // ================================================================
    let mut pkt9_m = http_server_ack_fin2(
        BS_MAC_ADDR,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        snat_port,
    );
    pkt9_m = encap_external(pkt9_m, bs_phys, g1_phys);
    let pkt9 = parse_inbound(&mut pkt9_m, VpcParser {}).unwrap();
    let res = g1.port.process(In, pkt9);
    expect_modified!(res, pkt9_m);
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::FinWait2, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // FIN: Server -> Client
    // ================================================================
    let mut pkt10_m = http_server_fin2(
        BS_MAC_ADDR,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        snat_port,
    );
    pkt10_m = encap_external(pkt10_m, bs_phys, g1_phys);
    let pkt10 = parse_inbound(&mut pkt10_m, VpcParser {}).unwrap();
    let res = g1.port.process(In, pkt10);
    expect_modified!(res, pkt10_m);
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::TimeWait, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK Server FIN: Client -> Server
    // ================================================================
    let mut pkt11_m = http_guest_ack_fin2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let pkt11 = parse_outbound(&mut pkt11_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt11);
    expect_modified!(res, pkt11_m);
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    assert_eq!(TcpState::TimeWait, g1.port.tcp_state(&flow).unwrap());

    flow
}

// Verify TCP state transitions in relation to an outbound connection
// (the "active open"). In this case the guest is the client, the
// server is an external IP.
#[test]
fn tcp_outbound() {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");
    // let now = Moment::now();

    // Add default route.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway(None),
        RouterClass::System,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    // ================================================================
    // Main test on an HTTP flow.
    // ================================================================
    let flow = test_outbound_http(&g1_cfg, &mut g1);

    // ================================================================
    // TCP flow expiry behaviour
    // ================================================================
    // - UFTs for individual flows live on the same cadence as other traffic.
    // - TCP state machine info should be cleaned up after an active close.
    // TimeWait state has a ~2min lifetime before we flush it -- it should still
    // be present at UFT expiry:
    let now = Moment::now();
    g1.port
        .expire_flows_at(now + Duration::new(FLOW_DEF_EXPIRE_SECS + 1, 0))
        .unwrap();
    zero_flows!(g1);
    assert_eq!(TcpState::TimeWait, g1.port.tcp_state(&flow).unwrap());

    // The TCP flow state should then be flushed after 2 mins.
    // Note that this case applies to any active-close initiated by the
    // guest, irrespective of inbound/outbound.
    g1.port
        .expire_flows_at(now + Duration::new(TIME_WAIT_EXPIRE_SECS + 1, 0))
        .unwrap();
    assert_eq!(None, g1.port.tcp_state(&flow));
}

// Verify that a TCP SYN packet will result in a new flow regardless
// of current TCP state. There are two main cases:
// * TIME_WAIT -- either host decided a port was safe to reuse.
// * ESTABLISHED -- an out-of order ACK may have triggered an
//                  accidental flow revival.
#[test]
fn early_tcp_invalidation() {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    // Allow incoming TCP connection on g1 from anyone.
    let rule = "dir=in action=allow priority=10 protocol=TCP";
    firewall::add_fw_rule(
        &g1.port,
        &AddFwRuleReq {
            port_name: g1.port.name().to_string(),
            rule: rule.parse().unwrap(),
        },
    )
    .unwrap();
    incr!(g1, ["epoch", "firewall.rules.in"]);

    // Add default route.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway(None),
        RouterClass::System,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    // ================================================================
    // Setup TIME_WAIT state.
    // ================================================================
    let dst_ip = "52.10.128.69".parse::<IpAddr>().unwrap();
    let flow = test_outbound_http(&g1_cfg, &mut g1);

    // ================================================================
    // Repeat the exact same flow. This SYN is not blocked, the old
    // entry is invalidated, and a new one is created.
    // ================================================================
    let mut pkt1_m = http_syn2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    expect_modified!(res, pkt1_m);
    update!(
        g1,
        [
            "incr:stats.port.out_modified, stats.port.out_uft_miss",
            // We're hitting the old entry, before it is discarded.
            "incr:stats.port.out_uft_hit",
            // Both UFTs are wiped out for reprocessing, but OUT is
            // re-added.
            "decr:uft.in"
        ]
    );
    assert_eq!(TcpState::SynSent, g1.port.tcp_state(&flow).unwrap());
    let pkt1 = parse_inbound(&mut pkt1_m, VpcParser {}).unwrap();
    let snat_port =
        pkt1.to_full_meta().meta().inner_ulp().unwrap().src_port().unwrap();

    // ================================================================
    // Drive to established, then validate the same applies to inbound
    // flows.
    // ================================================================
    let bs_phys = TestIpPhys {
        ip: BS_IP_ADDR,
        mac: BS_MAC_ADDR,
        vni: Vni::new(BOUNDARY_SERVICES_VNI).unwrap(),
    };
    let g1_phys = TestIpPhys {
        ip: g1_cfg.phys_ip,
        mac: g1_cfg.guest_mac,
        vni: g1_cfg.vni,
    };
    let mut pkt2_m = http_syn_ack2(
        BS_MAC_ADDR,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        snat_port,
    );
    pkt2_m = encap_external(pkt2_m, bs_phys, g1_phys);
    let pkt2 = parse_inbound(&mut pkt2_m, VpcParser {}).unwrap();
    let res = g1.port.process(In, pkt2);
    expect_modified!(res, pkt2_m);
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_miss, uft.in"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    let mut pkt1_m = http_syn3(
        BS_MAC_ADDR,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        80,
        snat_port,
    );
    pkt1_m = encap_external(pkt1_m, bs_phys, g1_phys);
    let pkt1 = parse_inbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(In, pkt1);
    expect_modified!(res, pkt1_m);
    update!(
        g1,
        [
            // Hit the old flow...
            "incr:stats.port.in_modified, stats.port.in_uft_hit",
            // Then reprocesssed.
            "incr:stats.port.in_uft_miss",
            "set:uft.in=1, uft.out=0",
        ]
    );
    assert_eq!(TcpState::Listen, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // Suppose we have an earlier flow which was driven to CLOSED,
    // where an ACK-carrying segment arrived out-of-order/duped OR one
    // side sent an RST and knocked out our entry. That flow will move
    // CLOSED->ESTABLISHED.
    // ================================================================
    let dst_ip2 = "52.10.128.70".parse().unwrap();

    // This case is just an ACK, but the same logic applies for
    // FIN+ACK. The FIN+ACK case could be special-cased CLOSED->CLOSED,
    // but we're not doing that for now.
    let mut pkt11_m = http_guest_ack_fin2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip2,
    );
    let pkt11 = parse_outbound(&mut pkt11_m, VpcParser {}).unwrap();
    let flow = pkt11.flow();
    let res = g1.port.process(Out, pkt11);
    expect_modified!(res, pkt11_m);
    incr!(
        g1,
        [
            "stats.port.out_modified, stats.port.out_uft_miss",
            "firewall.flows.in, firewall.flows.out",
            "nat.flows.in, nat.flows.out",
            "uft.out",
        ]
    );
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // This entry will not block new flows on the same tuple.
    // ================================================================
    let mut pkt1_m = http_syn2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip2,
    );
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let flow = pkt1.flow();
    let res = g1.port.process(Out, pkt1);
    expect_modified!(res, pkt1_m);
    update!(
        g1,
        [
            "incr:stats.port.out_modified, stats.port.out_uft_miss",
            // We're hitting the old entry, before it is discarded.
            "incr:stats.port.out_uft_hit",
        ]
    );
    assert_eq!(TcpState::SynSent, g1.port.tcp_state(&flow).unwrap());
}

#[test]
fn ephemeral_ip_preferred_over_snat_outbound() {
    let ip_cfg = IpCfg::DualStack {
        ipv4: Ipv4Cfg {
            vpc_subnet: "172.30.0.0/22".parse().unwrap(),
            private_ip: "172.30.0.5".parse().unwrap(),
            gateway_ip: "172.30.0.1".parse().unwrap(),
            external_ips: ExternalIpCfg {
                snat: Some(SNat4Cfg {
                    external_ip: "10.77.77.13".parse().unwrap(),
                    ports: 1025..=4096,
                }),
                ephemeral_ip: Some("10.60.1.20".parse().unwrap()),
                floating_ips: vec![],
            },
        },
        ipv6: Ipv6Cfg {
            vpc_subnet: "fd00::/64".parse().unwrap(),
            private_ip: "fd00::5".parse().unwrap(),
            gateway_ip: "fd00::1".parse().unwrap(),
            external_ips: ExternalIpCfg {
                snat: Some(SNat6Cfg {
                    external_ip: "2001:db8::1".parse().unwrap(),
                    ports: 1025..=4096,
                }),
                ephemeral_ip: None,
                floating_ips: vec![],
            },
        },
    };

    let g1_cfg = g1_cfg2(ip_cfg);
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    // Add default route.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway(None),
        RouterClass::System,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    let client_ip = "52.10.128.69".parse().unwrap();

    let data = b"reunion";
    let mut pkt1_m = gen_icmpv4_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4().private_ip,
        client_ip,
        7777,
        1,
        data,
        1,
    );
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();

    // Process the packet through our port. It should be allowed through:
    // we have a V2P mapping for the target guest, and a route for the other
    // subnet.
    let res = g1.port.process(Out, pkt1);
    expect_modified!(res, pkt1_m);

    incr!(
        g1,
        [
            "firewall.flows.in, firewall.flows.out",
            "stats.port.out_modified, stats.port.out_uft_miss, uft.out",
            "nat.flows.in, nat.flows.out",
        ]
    );

    let pkt1 = parse_inbound(&mut pkt1_m, VpcParser {}).unwrap().to_full_meta();

    assert_eq!(
        pkt1.meta().inner_ip4().unwrap().source(),
        "10.60.1.20".parse().unwrap(),
        "did not choose assigned ephemeral IP"
    );
}

// Verify TCP state transitions in relation to an inbound connection
// (the "passive open"). In this case the client is external, and the
// guest is the server.
#[test]
fn tcp_inbound() {
    // ================================================================
    // In order for a guest to receive external connections, it must
    // have an external IP.
    // ================================================================
    let ip_cfg = IpCfg::DualStack {
        ipv4: Ipv4Cfg {
            vpc_subnet: "172.30.0.0/22".parse().unwrap(),
            private_ip: "172.30.0.5".parse().unwrap(),
            gateway_ip: "172.30.0.1".parse().unwrap(),
            external_ips: ExternalIpCfg {
                snat: Some(SNat4Cfg {
                    external_ip: "10.77.77.13".parse().unwrap(),
                    ports: 1025..=4096,
                }),
                ephemeral_ip: Some("10.60.1.20".parse().unwrap()),
                floating_ips: vec![],
            },
        },
        ipv6: Ipv6Cfg {
            vpc_subnet: "fd00::/64".parse().unwrap(),
            private_ip: "fd00::5".parse().unwrap(),
            gateway_ip: "fd00::1".parse().unwrap(),
            external_ips: ExternalIpCfg {
                snat: Some(SNat6Cfg {
                    external_ip: "2001:db8::1".parse().unwrap(),
                    ports: 1025..=4096,
                }),
                ephemeral_ip: None,
                floating_ips: vec![],
            },
        },
    };

    let g1_cfg = g1_cfg2(ip_cfg);
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    // Add default route.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway(None),
        RouterClass::System,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    let client_ip = "52.10.128.69".parse().unwrap();
    let serv_mac = g1_cfg.guest_mac;
    let serv_ext_ip = g1_cfg.ipv4().external_ips.ephemeral_ip.unwrap();
    let g1_phys = TestIpPhys {
        ip: g1_cfg.phys_ip,
        mac: g1_cfg.guest_mac,
        vni: g1_cfg.vni,
    };

    // ================================================================
    // SYN: Client -> Server
    // ================================================================
    let mut pkt1_m = http_syn2(BS_MAC_ADDR, client_ip, serv_mac, serv_ext_ip);
    let bs_phys = TestIpPhys {
        ip: BS_IP_ADDR,
        mac: BS_MAC_ADDR,
        vni: Vni::new(BOUNDARY_SERVICES_VNI).unwrap(),
    };
    pkt1_m = encap(pkt1_m, bs_phys, g1_phys);
    let pkt1 = parse_inbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(In, pkt1);
    expect_modified!(res, pkt1_m);
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "nat.flows.in, nat.flows.out",
            "uft.in",
            "stats.port.in_modified, stats.port.in_uft_miss",
        ]
    );
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let flow = pkt1.flow().mirror();
    let sport =
        pkt1.to_full_meta().meta().inner_ulp().unwrap().src_port().unwrap();
    assert_eq!(TcpState::Listen, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // SYN+ACK: Server -> Client
    // ================================================================
    let mut pkt2_m = http_syn_ack2(
        serv_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        client_ip,
        sport,
    );
    let pkt2 = parse_outbound(&mut pkt2_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt2);
    expect_modified!(res, pkt2_m);
    incr!(g1, ["uft.out, stats.port.out_modified, stats.port.out_uft_miss"]);
    assert_eq!(TcpState::SynRcvd, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK: Client -> Server
    // ================================================================
    let mut pkt3_m = http_ack2(BS_MAC_ADDR, client_ip, serv_mac, serv_ext_ip);
    pkt3_m = encap(pkt3_m, bs_phys, g1_phys);
    let pkt3 = parse_inbound(&mut pkt3_m, VpcParser {}).unwrap();
    let res = g1.port.process(In, pkt3);
    expect_modified!(res, pkt3_m);
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // HTTP GET: Client -> Server
    // ================================================================
    let mut pkt4_m = http_get2(BS_MAC_ADDR, client_ip, serv_mac, serv_ext_ip);
    pkt4_m = encap(pkt4_m, bs_phys, g1_phys);
    let pkt4 = parse_inbound(&mut pkt4_m, VpcParser {}).unwrap();
    let res = g1.port.process(In, pkt4);
    expect_modified!(res, pkt4_m);
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK HTTP GET: Server -> Client
    // ================================================================
    let mut pkt5_m = http_get_ack2(
        serv_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        client_ip,
        sport,
    );
    let pkt5 = parse_outbound(&mut pkt5_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt5);
    expect_modified!(res, pkt5_m);
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // HTTP 301 Reply: Server -> Client
    // ================================================================
    let mut pkt6_m = http_301_reply2(
        serv_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        client_ip,
        sport,
    );
    let pkt6 = parse_outbound(&mut pkt6_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt6);
    expect_modified!(res, pkt6_m);
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK HTTP 301: Client -> Server
    // ================================================================
    let mut pkt7_m =
        http_301_ack2(BS_MAC_ADDR, client_ip, serv_mac, serv_ext_ip);
    pkt7_m = encap(pkt7_m, bs_phys, g1_phys);
    let pkt7 = parse_inbound(&mut pkt7_m, VpcParser {}).unwrap();
    let res = g1.port.process(In, pkt7);
    expect_modified!(res, pkt7_m);
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // FIN: Client -> Server
    // ================================================================
    let mut pkt8_m =
        http_guest_fin2(BS_MAC_ADDR, client_ip, serv_mac, serv_ext_ip);
    pkt8_m = encap(pkt8_m, bs_phys, g1_phys);
    let pkt8 = parse_inbound(&mut pkt8_m, VpcParser {}).unwrap();
    let res = g1.port.process(In, pkt8);
    expect_modified!(res, pkt8_m);
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::CloseWait, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK Client FIN: Server -> Client
    // ================================================================
    let mut pkt9_m = http_server_ack_fin2(
        serv_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        client_ip,
        sport,
    );
    let pkt9 = parse_outbound(&mut pkt9_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt9);
    expect_modified!(res, pkt9_m);
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    assert_eq!(TcpState::CloseWait, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // FIN: Server -> Client
    // ================================================================
    let mut pkt10_m = http_server_fin2(
        serv_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        client_ip,
        sport,
    );
    let pkt10 = parse_outbound(&mut pkt10_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt10);
    expect_modified!(res, pkt10_m);
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    assert_eq!(TcpState::LastAck, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK Server FIN: Client -> Server
    // ================================================================
    let mut pkt11_m =
        http_guest_ack_fin2(BS_MAC_ADDR, client_ip, serv_mac, serv_ext_ip);
    pkt11_m = encap(pkt11_m, bs_phys, g1_phys);
    let pkt11 = parse_inbound(&mut pkt11_m, VpcParser {}).unwrap();
    let res = g1.port.process(In, pkt11);
    expect_modified!(res, pkt11_m);
    update!(
        g1,
        [
            "incr:stats.port.in_modified, stats.port.in_uft_hit",
            "set:uft.in=0, uft.out=0",
        ]
    );
    assert_eq!(None, g1.port.tcp_state(&flow));
}

// Verify that the guest cannot spoof outbound packets.
#[test]
fn anti_spoof() {
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    let src_ip = "172.30.0.240".parse::<Ipv4Addr>().unwrap();
    assert_ne!(src_ip, g1_cfg.ipv4().private_ip);
    let src_mac = ox_vpc_mac([0x0, 0x11, 0x22]);
    assert_ne!(src_mac, g1_cfg.guest_mac);

    // ================================================================
    // Try to send an outbound packet with a spoofed IP.
    // ================================================================
    let mut pkt1_m = http_syn2(
        g1_cfg.guest_mac,
        src_ip,
        GW_MAC_ADDR,
        g2_cfg.ipv4().private_ip,
    );
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    assert_drop!(
        res,
        DropReason::Layer { name: "gateway", reason: DenyReason::Default }
    );
    incr!(
        g1,
        [
            "stats.port.out_drop, stats.port.out_drop_layer",
            "stats.port.out_uft_miss",
        ]
    );

    // ================================================================
    // Try to send an outbound packet with a spoofed MAC address.
    // ================================================================
    pkt1_m = http_syn2(
        src_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        g2_cfg.ipv4().private_ip,
    );
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    assert_drop!(
        res,
        DropReason::Layer { name: "gateway", reason: DenyReason::Default }
    );
    incr!(
        g1,
        [
            "stats.port.out_drop, stats.port.out_drop_layer",
            "stats.port.out_uft_miss",
        ]
    );

    // ================================================================
    // Try to send an outbound packet with a spoofed MAC address and IP.
    // ================================================================
    pkt1_m = http_syn2(src_mac, src_ip, GW_MAC_ADDR, g2_cfg.ipv4().private_ip);
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    assert_drop!(
        res,
        DropReason::Layer { name: "gateway", reason: DenyReason::Default }
    );
    incr!(
        g1,
        [
            "stats.port.out_drop, stats.port.out_drop_layer",
            "stats.port.out_uft_miss",
        ]
    );
}

// Ensure that we do _not_ panic when trying to create more TCP flows the limit
// applied to the flow table.
#[test]
fn no_panic_on_flow_table_full() {
    let g1_cfg = g1_cfg();
    // Let's limit to one connection, and try to establish two.
    let flow_table_limit = NonZeroU32::new(1).unwrap();
    let mut g1 =
        oxide_net_setup("g1_port", &g1_cfg, None, Some(flow_table_limit));
    g1.port.start();
    set!(g1, "port_state=running");

    // Add router entry that allows g1 to route to internet.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway(None),
        RouterClass::System,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    // Send one TCP packet to `zinascii.com`.
    let dst_ip: Ipv4Addr = "52.10.128.69".parse().unwrap();
    let mut pkt1_m = http_syn2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );

    // Process the packet through our port. We don't actually care about the
    // contents here, we just want to make sure that the packet can be _sent at
    // all_.
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    assert!(res.is_ok());

    // Send another one, which should exhaust the TCP flow table limit we
    // severely truncated above. Note we need to send to a different IP address.
    // Let's use google.com.
    let dst_ip: Ipv4Addr = "142.251.46.238".parse().unwrap();
    let mut pkt2_m = http_syn2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let pkt2 = parse_outbound(&mut pkt2_m, VpcParser {}).unwrap();
    let res2 = g1.port.process(Out, pkt2);
    assert_drop!(res2, DropReason::TcpErr);
}

#[test]
fn intra_subnet_routes_with_custom() {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    // This guest is 172.30.0.5 on 172.30.0.0/22.
    // Suppose that we have a second subnet, 172.30.4.0/22.
    // The control plane must insert a system route for as long
    // as this subnet exists.
    let cidr = IpCidr::Ip4("172.30.4.0/22".parse().unwrap());
    router::add_entry(
        &g1.port,
        cidr,
        RouterTarget::VpcSubnet(cidr),
        RouterClass::System,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    // define a guest in this range...
    let dst_ip: Ipv4Addr = "172.30.4.5".parse().unwrap();
    let other_guest_mac = ox_vpc_mac([0xF0, 0x00, 0x66]);
    let other_guest_phys_ip = Ipv6Addr::from([
        0xFD00, 0x0000, 0x00F7, 0x0116, 0x0000, 0x0000, 0x0000, 0x0001,
    ]);
    g1.vpc_map.add(
        dst_ip.into(),
        PhysNet {
            ether: other_guest_mac,
            ip: other_guest_phys_ip,
            vni: g1_cfg.vni,
        },
    );
    let data = b"1234\0";

    // Send one ICMP packet to that guest.
    let mut pkt1_m = gen_icmpv4_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4().private_ip,
        dst_ip,
        7777,
        1,
        data,
        1,
    );

    // Process the packet through our port. It should be allowed through:
    // we have a V2P mapping for the target guest, and a route for the other
    // subnet.
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    expect_modified!(res, pkt1_m);
    incr!(
        g1,
        [
            "firewall.flows.in, firewall.flows.out",
            "stats.port.out_modified, stats.port.out_uft_miss, uft.out",
        ]
    );

    // Suppose the user now installs a 'custom' route in the first subnet to
    // drop traffic towards the second subnet. This rule must take priority.
    router::add_entry(&g1.port, cidr, RouterTarget::Drop, RouterClass::Custom)
        .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);
    let mut pkt2_m = gen_icmpv4_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4().private_ip,
        dst_ip,
        7777,
        1,
        data,
        1,
    );
    let pkt2 = parse_outbound(&mut pkt2_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt2);
    assert!(matches!(
        res,
        Ok(ProcessResult::Drop {
            reason: DropReason::Layer { name: "router", .. }
        })
    ));
    update!(
        g1,
        [
            "incr:stats.port.out_drop, stats.port.out_drop_layer",
            "incr:stats.port.out_uft_miss",
            "decr:uft.out"
        ]
    );

    // When the user removes this rule, traffic may flow again to subnet 2.
    router::del_entry(&g1.port, cidr, RouterTarget::Drop, RouterClass::Custom)
        .unwrap();
    update!(g1, ["incr:epoch", "decr:router.rules.out"]);
    let mut pkt3_m = gen_icmpv4_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4().private_ip,
        dst_ip,
        7777,
        1,
        data,
        1,
    );
    let pkt3 = parse_outbound(&mut pkt3_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt3);
    expect_modified!(res, pkt3_m);
}

#[test]
fn port_as_router_target() {
    // RFD 21 allows VPC routers to direct traffic on a subnet
    // towards a given node. There are a few pieces here to consider:
    // * Packet send from a node must send traffic to the correct
    //   PhysNet -- underlay and macaddr of the receiving VM's port.
    // * A node must be able to receive traffic on such a block.
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.vpc_map.add(g2_cfg.ipv4().private_ip.into(), g2_cfg.phys_addr());
    g1.port.start();
    set!(g1, "port_state=running");
    let mut g2 =
        oxide_net_setup("g2_port", &g2_cfg, Some(g1.vpc_map.clone()), None);
    g2.port.start();
    set!(g2, "port_state=running");

    // Node G2 is configured to carry and soft-route VPN traffic on
    // 192.168.0.0/16.
    let cidr = IpCidr::Ip4("192.168.0.0/16".parse().unwrap());
    let dst_ip: Ipv4Addr = "192.168.0.1".parse().unwrap();
    router::add_entry(
        &g1.port,
        cidr,
        RouterTarget::Ip(g2_cfg.ipv4().private_ip.into()),
        RouterClass::Custom,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    // This also requires that we allow g2 to send/recv on this CIDR.
    gateway::allow_cidr(&g2.port, cidr, Direction::In, g2.vpc_map.clone())
        .unwrap();
    gateway::allow_cidr(&g2.port, cidr, Direction::Out, g2.vpc_map.clone())
        .unwrap();
    incr!(g2, ["epoch, epoch, gateway.rules.out, gateway.rules.in"]);

    let data = b"1234\0";

    // Send one ICMP packet to that range.
    let mut pkt1_m = gen_icmpv4_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4().private_ip,
        dst_ip,
        7777,
        1,
        data,
        1,
    );

    // That packet should be allowed: the target IP resolves to a valid
    // V2P Mapping.
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    expect_modified!(res, pkt1_m);
    incr!(
        g1,
        [
            "firewall.flows.in, firewall.flows.out",
            "stats.port.out_modified, stats.port.out_uft_miss, uft.out",
        ]
    );

    let pkt1 = parse_inbound(&mut pkt1_m, VpcParser {}).unwrap();

    // Encap routes between sleds correctly, inner IPs are not modified,
    // and L2 dst matches the guest's NIC.
    let v6_encap_meta = &pkt1.meta().outer_v6;
    assert_eq!(v6_encap_meta.source(), g1_cfg.phys_ip);
    assert_eq!(v6_encap_meta.destination(), g2_cfg.phys_ip);
    assert_eq!(pkt1.meta().inner_eth.destination(), g2_cfg.guest_mac);
    assert_eq!(pkt1.meta().inner_eth.source(), g1_cfg.guest_mac);
    let ValidL3::Ipv4(inner_ip4) = &pkt1.meta().inner_l3 else {
        panic!("encapped v4 packet did not parse back as v4");
    };
    assert_eq!(inner_ip4.source(), g1_cfg.ipv4().private_ip);
    assert_eq!(inner_ip4.destination(), dst_ip);

    // Now deliver the packet to node g2.
    let res = g2.port.process(In, pkt1);
    incr!(
        g2,
        [
            "firewall.flows.in, firewall.flows.out",
            "stats.port.in_modified, stats.port.in_uft_miss, uft.in",
        ]
    );
    expect_modified!(res, pkt1_m);

    // A reply from that address must be allowed out by g2, and accepted
    // by g1.
    let mut pkt2_m = gen_icmpv4_echo_reply(
        g2_cfg.guest_mac,
        g2_cfg.gateway_mac,
        dst_ip,
        g1_cfg.ipv4().private_ip,
        7777,
        1,
        data,
        1,
    );
    let pkt2 = parse_outbound(&mut pkt2_m, VpcParser {}).unwrap();

    let res = g2.port.process(Out, pkt2);
    incr!(g2, ["stats.port.out_modified, stats.port.out_uft_miss, uft.out",]);
    expect_modified!(res, pkt2_m);

    let pkt2 = parse_inbound(&mut pkt2_m, VpcParser {}).unwrap();
    let res = g1.port.process(In, pkt2);
    expect_modified!(res, pkt2_m);
}

#[test]
fn select_eip_conditioned_on_igw() {
    // RFD 21 Internet Gateways are used as a mechanism to narrow
    // down the set of valid source IPs that an outbound packet may
    // choose from, conditioned on a packet's destination network.
    //
    // To do this, the control plane is responsible for installing
    // IGW rules with UUID associations, and then determining which
    // external IPs are associated with each IGW.
    let default_igw = Uuid::from_u128(1);
    let custom_igw0 = Uuid::from_u128(2);
    let custom_igw1 = Uuid::from_u128(3);
    let ipless_igw = Uuid::from_u128(4);

    // The control plane may have several IGWs associated with a given
    // pool. Accordingly, there is a chance that an IP might be a valid choice
    // on several prefixes.
    let all_ips_igw = Uuid::from_u128(5);

    // To test this, we want to set up a port such that:
    // * It has an ephemeral IP in IGW 1.
    //   - If we target 0.0.0.0/0, we choose the eph IP 192.168.0.1 .
    // * It has FIPs across IGWs 2 [dst 1.1.1.0/24], 3 [dst 2.2.2.0/24].
    //   - IGW 2 has FIPs 192.168.0.2, 192.168.0.3. Either will be picked.
    //   - IGW 3 has FIP 192.168.0.4.
    // * It has no EIP in IGW3 [dst 3.3.3.0/24].
    //   - Packets sent here are denied -- we have no valid NAT IPs for this
    //     outbound traffic.
    // * All EIPs are valid on IGW4.
    //   - Packets will choose a random FIP, by priority ordering.

    let ip_cfg = IpCfg::DualStack {
        ipv4: Ipv4Cfg {
            vpc_subnet: "172.30.0.0/22".parse().unwrap(),
            private_ip: "172.30.0.5".parse().unwrap(),
            gateway_ip: "172.30.0.1".parse().unwrap(),
            external_ips: ExternalIpCfg {
                snat: Some(SNat4Cfg {
                    external_ip: "10.77.77.13".parse().unwrap(),
                    ports: 1025..=4096,
                }),
                ephemeral_ip: Some("192.168.0.1".parse().unwrap()),
                floating_ips: vec![
                    "192.168.0.2".parse().unwrap(),
                    "192.168.0.3".parse().unwrap(),
                    "192.168.0.4".parse().unwrap(),
                ],
            },
        },
        // Not really testing V6 here. Same principles apply.
        ipv6: Ipv6Cfg {
            vpc_subnet: "fd00::/64".parse().unwrap(),
            private_ip: "fd00::5".parse().unwrap(),
            gateway_ip: "fd00::1".parse().unwrap(),
            external_ips: ExternalIpCfg {
                snat: Some(SNat6Cfg {
                    external_ip: "2001:db8::1".parse().unwrap(),
                    ports: 1025..=4096,
                }),
                ephemeral_ip: None,
                floating_ips: vec![],
            },
        },
    };

    let g1_cfg = g1_cfg2(ip_cfg);
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    // Add default route.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway(Some(default_igw)),
        RouterClass::System,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    // Add custom inetgw routes.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("1.1.1.0/24".parse().unwrap()),
        RouterTarget::InternetGateway(Some(custom_igw0)),
        RouterClass::Custom,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("2.2.2.0/24".parse().unwrap()),
        RouterTarget::InternetGateway(Some(custom_igw1)),
        RouterClass::Custom,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("3.3.3.0/24".parse().unwrap()),
        RouterTarget::InternetGateway(Some(ipless_igw)),
        RouterClass::Custom,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("4.4.4.0/24".parse().unwrap()),
        RouterTarget::InternetGateway(Some(all_ips_igw)),
        RouterClass::Custom,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    // ====================================================================
    // Install new config.
    // ====================================================================
    let mut inet_gw_map: BTreeMap<_, _> = Default::default();
    inet_gw_map.insert(
        g1_cfg.ipv4_cfg().unwrap().external_ips.ephemeral_ip.unwrap().into(),
        [default_igw, all_ips_igw].into_iter().collect(),
    );
    inet_gw_map.insert(
        g1_cfg.ipv4_cfg().unwrap().external_ips.floating_ips[0].into(),
        [custom_igw0, all_ips_igw].into_iter().collect(),
    );
    inet_gw_map.insert(
        g1_cfg.ipv4_cfg().unwrap().external_ips.floating_ips[1].into(),
        [custom_igw0, all_ips_igw].into_iter().collect(),
    );
    inet_gw_map.insert(
        g1_cfg.ipv4_cfg().unwrap().external_ips.floating_ips[2].into(),
        [custom_igw1, all_ips_igw].into_iter().collect(),
    );

    let new_v4_cfg = g1_cfg.ipv4_cfg().map(|v| v.external_ips.clone());

    let req = oxide_vpc::api::SetExternalIpsReq {
        port_name: g1.port.name().to_string(),
        external_ips_v4: new_v4_cfg,
        external_ips_v6: None,

        // Setting the inet GW mappings for each external IP
        // enables the limiting we aim to test here.
        inet_gw_map: Some(inet_gw_map),
    };
    nat::set_nat_rules(&g1.cfg, &g1.port, req).unwrap();
    update!(g1, ["incr:epoch", "set:nat.rules.out=8"]);

    // Send an ICMP packet for each destination, and verify that the
    // correct source IP is written in (or the packet is denied).
    let ident = 7;
    let seq_no = 777;
    let data = b"reunion\0";

    // Default route.
    let mut pkt1_m = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip.into(),
        "77.77.77.77".parse().unwrap(),
        ident,
        seq_no,
        &data[..],
        1,
    );
    let pkt1 = parse_outbound(&mut pkt1_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt1);
    expect_modified!(res, pkt1_m);
    let pkt1 = parse_inbound(&mut pkt1_m, VpcParser {}).unwrap().to_full_meta();
    assert_eq!(
        pkt1.meta().inner_ip4().unwrap().source(),
        g1_cfg.ipv4().external_ips.ephemeral_ip.unwrap()
    );
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "nat.flows.out, nat.flows.in",
            "stats.port.out_uft_miss, uft.out",
            "stats.port.out_modified",
        ]
    );

    // 1.1.1.0/24
    let mut pkt2_m = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip.into(),
        "1.1.1.1".parse().unwrap(),
        ident,
        seq_no,
        &data[..],
        1,
    );
    let pkt2 = parse_outbound(&mut pkt2_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt2);
    expect_modified!(res, pkt2_m);
    let pkt2 = parse_inbound(&mut pkt2_m, VpcParser {}).unwrap().to_full_meta();
    assert!(
        &g1_cfg.ipv4().external_ips.floating_ips[..2]
            .contains(&pkt2.meta().inner_ip4().unwrap().source())
    );
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "nat.flows.out, nat.flows.in",
            "stats.port.out_uft_miss, uft.out",
            "stats.port.out_modified",
        ]
    );

    // 2.2.2.0/24
    let mut pkt3_m = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip.into(),
        "2.2.2.1".parse().unwrap(),
        ident,
        seq_no,
        &data[..],
        1,
    );
    let pkt3 = parse_outbound(&mut pkt3_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt3);
    expect_modified!(res, pkt3_m);
    let pkt3 = parse_inbound(&mut pkt3_m, VpcParser {}).unwrap().to_full_meta();
    assert_eq!(
        pkt3.meta().inner_ip4().unwrap().source(),
        g1_cfg.ipv4().external_ips.floating_ips[2]
    );
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "nat.flows.out, nat.flows.in",
            "stats.port.out_uft_miss, uft.out",
            "stats.port.out_modified",
        ]
    );

    // 3.3.3.0/24
    let mut pkt4_m = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip.into(),
        "3.3.3.1".parse().unwrap(),
        ident,
        seq_no,
        &data[..],
        1,
    );
    let pkt4 = parse_outbound(&mut pkt4_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt4).unwrap();
    assert!(matches!(res, ProcessResult::Drop { .. }));
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "stats.port.out_uft_miss",
            "stats.port.out_drop, stats.port.out_drop_layer",
        ]
    );

    // 4.4.4.0/24
    let mut pkt5_m = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip.into(),
        "4.4.4.1".parse().unwrap(),
        ident,
        seq_no,
        &data[..],
        1,
    );
    let pkt5 = parse_outbound(&mut pkt5_m, VpcParser {}).unwrap();
    let res = g1.port.process(Out, pkt5);
    expect_modified!(res, pkt5_m);
    let pkt5 = parse_inbound(&mut pkt5_m, VpcParser {}).unwrap().to_full_meta();
    assert!(
        &g1_cfg.ipv4().external_ips.floating_ips[..]
            .contains(&pkt5.meta().inner_ip4().unwrap().source())
    );
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "nat.flows.out, nat.flows.in",
            "stats.port.out_uft_miss, uft.out",
            "stats.port.out_modified",
        ]
    );
}

#[test]
fn icmp_inner_has_nat_applied() {
    let mut pcap = PcapBuilder::new("icmp4_inner_rewrite.pcap");
    let (g1, g1_cfg, ..) = multi_external_ip_setup(1, true);

    let eph_ip = g1_cfg.ipv4().external_ips.ephemeral_ip.unwrap();
    let remote_addr: Ipv4Addr = "4.4.4.4".parse().unwrap();

    let icmp = Icmpv4Repr::TimeExceeded {
        reason: smoltcp::wire::Icmpv4TimeExceeded::TtlExpired,
        header: smoltcp::wire::Ipv4Repr {
            src_addr: remote_addr.into(),
            dst_addr: g1_cfg.ipv4().private_ip.into(),
            next_header: IpProtocol::Udp,
            payload_len: 256,
            hop_limit: 0,
        },
        data: &[0x12, 0x34, 0x00, 0x34, 0x00, 0xf8, 0x00, 0x00],
    };

    let mut body_bytes = vec![0u8; icmp.buffer_len()];
    let mut req_pkt = Icmpv4Packet::new_unchecked(&mut body_bytes);
    icmp.emit(&mut req_pkt, &Default::default());

    let eth = Ethernet {
        destination: g1_cfg.gateway_mac,
        source: g1_cfg.guest_mac,
        ethertype: Ethertype::IPV4,
    };

    let mut ip: L3<&mut [u8]> = Ipv4 {
        source: g1_cfg.ipv4().private_ip,
        destination: remote_addr.into(),
        protocol: IngotIpProto::ICMP,
        total_len: (icmp.buffer_len() + Ipv4::MINIMUM_LENGTH) as u16,
        ..Default::default()
    }
    .into();
    ip.compute_checksum();

    let mut pkt_m = MsgBlk::new_ethernet_pkt((&eth, &ip, &body_bytes));
    pcap.add_pkt(&pkt_m);

    let pkt = Packet::parse_outbound(pkt_m.iter_mut(), VpcParser {}).unwrap();
    let res = g1.port.process(Direction::Out, pkt);
    expect_modified!(res, pkt_m);
    pcap.add_pkt(&pkt_m);

    // Assert that the IP header carried within has had its destination
    // address adjusted from private -> ephemeral IP.
    let final_pkt =
        Packet::parse_inbound(pkt_m.iter_mut(), VpcParser {}).unwrap();
    let meta = final_pkt.to_full_meta();
    let body = meta.body().unwrap();
    let (v4, ..) = ValidIpv4::parse(body).unwrap();
    assert_eq!(v4.destination(), eph_ip);
}

#[test]
fn icmpv6_inner_has_nat_applied() {
    let mut pcap = PcapBuilder::new("icmp6_inner_rewrite.pcap");
    let (mut g1, g1_cfg, ..) = multi_external_ip_setup(1, true);

    let rule = "dir=in action=allow priority=9 protocol=ICMP6";
    firewall::add_fw_rule(
        &g1.port,
        &AddFwRuleReq {
            port_name: g1.port.name().to_string(),
            rule: rule.parse().unwrap(),
        },
    )
    .unwrap();
    incr!(g1, ["epoch", "firewall.rules.in"]);

    let eph_ip = g1_cfg.ipv6().external_ips.ephemeral_ip.unwrap();
    let remote_addr: Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();

    let icmp = Icmpv6Repr::DstUnreachable {
        reason: smoltcp::wire::Icmpv6DstUnreachable::PortUnreachable,
        header: smoltcp::wire::Ipv6Repr {
            src_addr: eph_ip.into(),
            dst_addr: remote_addr.into(),
            next_header: IpProtocol::Udp,
            // Unimportant -- header is truncated.
            payload_len: 256,
            hop_limit: 255,
        },
        data: &[0x12, 0x34, 0x00, 0x34, 0x00, 0xf8, 0x00, 0x00],
    };

    let mut body_bytes = vec![0u8; icmp.buffer_len()];
    let mut req_pkt = Icmpv6Packet::new_unchecked(&mut body_bytes);
    icmp.emit(
        &Ipv6Address::from_bytes(&remote_addr.bytes()).into(),
        &Ipv6Address::from_bytes(&eph_ip.bytes()).into(),
        &mut req_pkt,
        &Default::default(),
    );

    let eth = Ethernet {
        destination: g1_cfg.guest_mac,
        source: BS_MAC_ADDR,
        ethertype: Ethertype::IPV6,
    };

    let ip = Ipv6 {
        source: remote_addr,
        destination: eph_ip.into(),
        next_header: IngotIpProto::ICMP_V6,
        payload_len: icmp.buffer_len() as u16,
        hop_limit: 64,
        ..Default::default()
    };

    let bsvc_phys = TestIpPhys {
        ip: BS_IP_ADDR,
        mac: BS_MAC_ADDR,
        vni: Vni::new(BOUNDARY_SERVICES_VNI).unwrap(),
    };

    let pkt_m = MsgBlk::new_ethernet_pkt((&eth, &ip, &body_bytes));
    let mut pkt_m = encap_external(
        pkt_m,
        bsvc_phys,
        TestIpPhys {
            ip: g1_cfg.phys_ip,
            mac: g1_cfg.guest_mac,
            vni: g1_cfg.vni,
        },
    );
    pcap.add_pkt(&pkt_m);

    let pkt = Packet::parse_inbound(pkt_m.iter_mut(), VpcParser {}).unwrap();
    let res = g1.port.process(Direction::In, pkt);
    expect_modified!(res, pkt_m);
    pcap.add_pkt(&pkt_m);

    // Assert that the IP header carried within has had its source
    // address adjusted from ephemeral -> private IP.
    let final_pkt =
        Packet::parse_outbound(pkt_m.iter_mut(), VpcParser {}).unwrap();
    let meta = final_pkt.to_full_meta();
    let body = meta.body().unwrap();
    let (v6, ..) = ValidIpv6::parse(body).unwrap();
    assert_eq!(v6.source(), g1_cfg.ipv6().private_ip);
}

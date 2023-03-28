// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Integration tests.
//!
//! The idea behind these tests is to use actual packet captures to
//! regression test known good captures. This is done by taking a
//! packet capture in the guest as well as on the host -- one for each
//! side of OPTE. These captures are then used to regression test an
//! OPTE pipeline by single-stepping the packets in each capture and
//! verifying that OPTE processing produces the expected bytes.

mod common;

use common::icmp::*;
use common::*;
use opte::api::MacAddr;
use opte::api::OpteError;
use opte::ddi::time::Moment;
use opte::engine::arp::ArpEthIpv4;
use opte::engine::arp::ArpEthIpv4Raw;
use opte::engine::dhcpv6;
use opte::engine::ether::EtherHdr;
use opte::engine::ether::EtherHdrRaw;
use opte::engine::ether::EtherMeta;
use opte::engine::flow_table::FLOW_DEF_EXPIRE_SECS;
use opte::engine::geneve::Vni;
use opte::engine::headers::EncapMeta;
use opte::engine::headers::IpMeta;
use opte::engine::headers::UlpMeta;
use opte::engine::icmpv6::Icmpv6Hdr;
use opte::engine::ip4::Ipv4Addr;
use opte::engine::ip4::Ipv4Hdr;
use opte::engine::ip4::Ipv4Meta;
use opte::engine::ip4::Protocol;
use opte::engine::ip6::Ipv6Hdr;
use opte::engine::ip6::Ipv6Meta;
use opte::engine::packet::Packet;
use opte::engine::packet::PacketRead;
use opte::engine::packet::ParseError;
use opte::engine::packet::Parsed;
use opte::engine::port::ProcessError;
use opte::engine::tcp::TcpState;
use opte::engine::udp::UdpMeta;
use oxide_vpc::api::FirewallRule;
use oxide_vpc::api::VpcCfg;
use smoltcp::phy::ChecksumCapabilities as CsumCapab;
use smoltcp::wire::Icmpv4Packet;
use smoltcp::wire::Icmpv4Repr;
use smoltcp::wire::Icmpv6Packet;
use smoltcp::wire::Icmpv6Repr;
use smoltcp::wire::IpAddress;
use smoltcp::wire::Ipv6Address;
use smoltcp::wire::NdiscNeighborFlags;
use smoltcp::wire::NdiscRepr;
use smoltcp::wire::NdiscRouterFlags;
use smoltcp::wire::RawHardwareAddress;
use std::prelude::v1::*;
use std::time::Duration;
use zerocopy::AsBytes;

const IP4_SZ: usize = EtherHdr::SIZE + Ipv4Hdr::BASE_SIZE;
const IP6_SZ: usize = EtherHdr::SIZE + Ipv6Hdr::BASE_SIZE;
const TCP4_SZ: usize = IP4_SZ + TcpHdr::BASE_SIZE;
const TCP6_SZ: usize = IP6_SZ + TcpHdr::BASE_SIZE;

// The GeneveHdr includes the UDP header.
const VPC_ENCAP_SZ: usize = IP6_SZ + GeneveHdr::BASE_SIZE;

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
        snat: Some(SNat4Cfg {
            external_ip: "76.76.21.21".parse().unwrap(),
            ports: 1025..=4096,
        }),
        external_ips: None,
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
        vni: Vni::new(99u32).unwrap(),
        // Site 0xF7, Rack 1, Sled 1, Interface 1
        phys_ip: Ipv6Addr::from([
            0xFD00, 0x0000, 0x00F7, 0x0101, 0x0000, 0x0000, 0x0000, 0x0001,
        ]),
        boundary_services: BoundaryServices {
            mac: MacAddr::from([0xA8, 0x40, 0x25, 0x77, 0x77, 0x77]),
            ip: Ipv6Addr::from([
                0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x01, 0xFF, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x77, 0x77,
            ]),
            vni: Vni::new(99u32).unwrap(),
        },
        domain_list: vec!["oxide.computer".parse().unwrap()],
        proxy_arp_enable: false,
        phys_gw_mac: Some(MacAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d])),
    }
}

// Verify that the list of layers is what we expect.
#[test]
fn check_layers() {
    let g1_cfg = g1_cfg();
    let g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    let port_layers = g1.port.layers();
    assert_eq!(&VPC_LAYERS[..], &port_layers);
}

// Verify Port transition from Ready -> Running.
#[test]
fn port_transition_running() {
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    g1.vpc_map.add(g2_cfg.ipv4().private_ip.into(), g2_cfg.phys_addr());

    // ================================================================
    // Try processing the packet while taking the port through a Ready
    // -> Running.
    // ================================================================
    let mut pkt1 = tcp_telnet_syn(&g1_cfg, &g2_cfg);
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
    assert!(matches!(res, Err(ProcessError::BadState(_))));
    assert_port!(g1);
    g1.port.start();
    set!(g1, "port_state=running");
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
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
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    g1.vpc_map.add(g2_cfg.ipv4().private_ip.into(), g2_cfg.phys_addr());

    // ================================================================
    // Try processing the packet while taking the port through a Ready
    // -> Running -> Ready transition. Verify that flows are cleared
    // but rules remain.
    // ================================================================
    let mut pkt1 = tcp_telnet_syn(&g1_cfg, &g2_cfg);
    g1.port.start();
    set!(g1, "port_state=running");
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
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
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
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
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    let mut g2 = oxide_net_setup("g2_port", &g2_cfg, Some(g1.vpc_map.clone()));

    // Allow incoming connections to port 80 on g1.
    let fw_rule: FirewallRule =
        "action=allow priority=10 dir=in protocol=tcp port=80".parse().unwrap();
    firewall::add_fw_rule(
        &g1.port,
        &AddFwRuleReq {
            port_name: g1.port.name().to_string(),
            rule: fw_rule.clone(),
        },
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
    let mut pkt1 = http_syn(&g2_cfg, &g1_cfg);
    let res = g2.port.process(Out, &mut pkt1, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(
        g2,
        [
            "firewall.flows.out, firewall.flows.in",
            "uft.out",
            "stats.port.out_modified, stats.port.out_uft_miss"
        ]
    );

    let res = g1.port.process(In, &mut pkt1, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
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
    assert!(matches!(
        g2.port.expire_flows(Moment::now()),
        Err(OpteError::BadState(_))
    ));
    // This exercises Port::remove_rule().
    assert!(matches!(
        router::del_entry(
            &g2.port,
            IpCidr::Ip4(g2_cfg.ipv4_cfg().unwrap().vpc_subnet),
            RouterTarget::VpcSubnet(IpCidr::Ip4(
                g2_cfg.ipv4_cfg().unwrap().vpc_subnet
            )),
        ),
        Err(OpteError::BadState(_))
    ));
    let res = g2.port.process(Out, &mut pkt1, ActionMeta::new());
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

    let mut pkt2 = http_syn_ack(&g1_cfg, &g2_cfg);
    let res = g1.port.process(Out, &mut pkt2, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["uft.out", "stats.port.out_modified, stats.port.out_uft_miss"]);

    let res = g2.port.process(In, &mut pkt2, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g2, ["uft.in", "stats.port.in_modified, stats.port.in_uft_miss"]);
}

#[test]
fn add_remove_fw_rule() {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
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
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    g1.port.start();
    set!(g1, "port_state=running");
    let mut pcap = PcapBuilder::new("gateway_icmpv4_ping.pcap");
    let ident = 7;
    let seq_no = 777;
    let data = b"reunion\0";

    // ================================================================
    // Generate an ICMP Echo Request from G1 to Virtual GW
    // ================================================================
    let mut pkt1 = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip.into(),
        g1_cfg.ipv4_cfg().unwrap().gateway_ip.into(),
        ident,
        seq_no,
        &data[..],
        1,
    );
    pcap.add_pkt(&pkt1);

    // ================================================================
    // Run the Echo Request through g1's port in the outbound
    // direction and verify it results in an Echo Reply Hairpin packet
    // back to guest.
    // ================================================================
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
    let hp = match res {
        Ok(Hairpin(hp)) => hp,
        _ => panic!("expected Hairpin, got {:?}", res),
    };
    incr!(g1, ["stats.port.out_uft_miss"]);
    // In this case we are parsing a hairpin reply, so we can't use
    // the VpcParser since it would expect any inbound packet to be
    // encapsulated.
    let reply = hp.parse(In, GenericUlp {}).unwrap();
    pcap.add_pkt(&reply);
    assert_eq!(reply.body_offset(), IP4_SZ);
    assert_eq!(reply.body_seg(), 0);
    let meta = reply.meta();
    assert!(meta.outer.ether.is_none());
    assert!(meta.outer.ip.is_none());
    assert!(meta.outer.encap.is_none());

    let eth = meta.inner.ether;
    assert_eq!(eth.src, g1_cfg.gateway_mac);
    assert_eq!(eth.dst, g1_cfg.guest_mac);

    match meta.inner.ip.as_ref().unwrap() {
        IpMeta::Ip4(ip4) => {
            assert_eq!(ip4.src, g1_cfg.ipv4_cfg().unwrap().gateway_ip);
            assert_eq!(ip4.dst, g1_cfg.ipv4_cfg().unwrap().private_ip);
            assert_eq!(ip4.proto, Protocol::ICMP);
        }

        ip6 => panic!("expected inner IPv4 metadata, got IPv6: {:?}", ip6),
    }

    let rdr = reply.get_body_rdr();
    let reply_body = rdr.copy_remaining();
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

// Try to send a TCP packet from one guest to another; but in this
// case the guest has not route to the other guest, resulting in the
// packet being dropped.
#[test]
fn guest_to_guest_no_route() {
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    g1.vpc_map.add(g2_cfg.ipv4().private_ip.into(), g2_cfg.phys_addr());
    g1.port.start();
    set!(g1, "port_state=running");
    // Make sure the router is configured to drop all packets.
    router::del_entry(
        &g1.port,
        IpCidr::Ip4(g1_cfg.ipv4().vpc_subnet),
        RouterTarget::VpcSubnet(IpCidr::Ip4(g1_cfg.ipv4().vpc_subnet)),
    )
    .unwrap();
    update!(g1, ["incr:epoch", "set:router.rules.out=0"]);
    let mut pkt1 = http_syn(&g1_cfg, &g2_cfg);
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
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
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    g1.vpc_map.add(g2_cfg.ipv4().private_ip.into(), g2_cfg.phys_addr());
    g1.port.start();
    set!(g1, "port_state=running");
    let mut g2 = oxide_net_setup("g2_port", &g2_cfg, Some(g1.vpc_map.clone()));
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

    let mut pkt1 = http_syn(&g1_cfg, &g2_cfg);
    pcap_guest1.add_pkt(&pkt1);
    let ulp_csum_b4 = pkt1.meta().inner.ulp.unwrap().csum();
    let ip_csum_b4 = pkt1.meta().inner.ip.unwrap().csum();

    // ================================================================
    // Run the packet through g1's port in the outbound direction and
    // verify the resulting packet meets expectations.
    // ================================================================
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
    pcap_phys1.add_pkt(&pkt1);
    assert!(matches!(res, Ok(Modified)));
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "uft.out",
            "stats.port.out_modified, stats.port.out_uft_miss",
        ]
    );

    assert_eq!(pkt1.body_offset(), VPC_ENCAP_SZ + TCP4_SZ + HTTP_SYN_OPTS_LEN);
    assert_eq!(pkt1.body_seg(), 1);
    let ulp_csum_after = pkt1.meta().inner.ulp.unwrap().csum();
    let ip_csum_after = pkt1.meta().inner.ip.unwrap().csum();
    assert_eq!(ulp_csum_after, ulp_csum_b4);
    assert_eq!(ip_csum_after, ip_csum_b4);

    let meta = pkt1.meta();
    match meta.outer.ether.as_ref() {
        Some(eth) => {
            assert_eq!(eth.src, MacAddr::ZERO);
            assert_eq!(eth.dst, MacAddr::ZERO);
        }

        None => panic!("no outer ether header"),
    }

    match meta.outer.ip.as_ref().unwrap() {
        IpMeta::Ip6(ip6) => {
            assert_eq!(ip6.src, g1_cfg.phys_ip);
            assert_eq!(ip6.dst, g2_cfg.phys_ip);
        }

        val => panic!("expected outer IPv6, got: {:?}", val),
    }

    match meta.outer.encap.as_ref() {
        Some(EncapMeta::Geneve(geneve)) => {
            assert_eq!(geneve.entropy, 7777);
            assert_eq!(geneve.vni, Vni::new(g1_cfg.vni).unwrap());
        }

        None => panic!("expected outer Geneve metadata"),
    }

    let eth = meta.inner.ether;
    assert_eq!(eth.src, g1_cfg.guest_mac);
    assert_eq!(eth.dst, g2_cfg.guest_mac);
    assert_eq!(eth.ether_type, EtherType::Ipv4);

    match meta.inner.ip.as_ref().unwrap() {
        IpMeta::Ip4(ip4) => {
            assert_eq!(ip4.src, g1_cfg.ipv4_cfg().unwrap().private_ip);
            assert_eq!(ip4.dst, g2_cfg.ipv4_cfg().unwrap().private_ip);
            assert_eq!(ip4.proto, Protocol::TCP);
        }

        ip6 => panic!("execpted inner IPv4 metadata, got IPv6: {:?}", ip6),
    }

    match meta.inner.ulp.as_ref().unwrap() {
        UlpMeta::Tcp(tcp) => {
            assert_eq!(tcp.src, 44490);
            assert_eq!(tcp.dst, 80);
        }

        ulp => panic!("expected inner TCP metadata, got: {:?}", ulp),
    }

    // ================================================================
    // Now that the packet has been encap'd let's play the role of
    // router and send this inbound to g2's port. For maximum fidelity
    // of the real process we first dump the raw bytes of g1's
    // outgoing packet and then reparse it.
    // ================================================================
    let mblk = pkt1.unwrap_mblk();
    let mut pkt2 = unsafe {
        Packet::wrap_mblk_and_parse(mblk, In, VpcParser::new()).unwrap()
    };
    pcap_phys2.add_pkt(&pkt2);

    let res = g2.port.process(In, &mut pkt2, ActionMeta::new());
    pcap_guest2.add_pkt(&pkt2);
    assert!(matches!(res, Ok(Modified)));
    incr!(
        g2,
        [
            "firewall.flows.in, firewall.flows.out",
            "uft.in",
            "stats.port.in_modified, stats.port.in_uft_miss",
        ]
    );
    assert_eq!(pkt2.body_offset(), TCP4_SZ + HTTP_SYN_OPTS_LEN);
    assert_eq!(pkt2.body_seg(), 1);

    let g2_meta = pkt2.meta();
    assert!(g2_meta.outer.ether.is_none());
    assert!(g2_meta.outer.ip.is_none());
    assert!(g2_meta.outer.encap.is_none());

    let g2_eth = g2_meta.inner.ether;
    assert_eq!(g2_eth.src, g1_cfg.gateway_mac);
    assert_eq!(g2_eth.dst, g2_cfg.guest_mac);
    assert_eq!(g2_eth.ether_type, EtherType::Ipv4);

    match g2_meta.inner.ip.as_ref().unwrap() {
        IpMeta::Ip4(ip4) => {
            assert_eq!(ip4.src, g1_cfg.ipv4_cfg().unwrap().private_ip);
            assert_eq!(ip4.dst, g2_cfg.ipv4_cfg().unwrap().private_ip);
            assert_eq!(ip4.proto, Protocol::TCP);
        }

        ip6 => panic!("execpted inner IPv4 metadata, got IPv6: {:?}", ip6),
    }

    match g2_meta.inner.ulp.as_ref().unwrap() {
        UlpMeta::Tcp(tcp) => {
            assert_eq!(tcp.src, 44490);
            assert_eq!(tcp.dst, 80);
        }

        ulp => panic!("expected inner TCP metadata, got: {:?}", ulp),
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
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    g1.port.start();
    set!(g1, "port_state=running");
    let mut g2 = oxide_net_setup("g2_port", &g2_cfg, Some(g1.vpc_map.clone()));
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
    let res = g1.port.process(Out, &mut g1_pkt, ActionMeta::new());
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
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    g1.port.start();
    set!(g1, "port_state=running");

    // Add router entry that allows g1 to route to internet.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    // ================================================================
    // Generate a TCP SYN packet from g1 to zinascii.com
    // ================================================================
    let dst_ip = "52.10.128.69".parse().unwrap();
    let mut pkt1 = http_syn2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );

    // ================================================================
    // Run the packet through g1's port in the outbound direction and
    // verify the resulting packet meets expectations.
    // ================================================================
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)), "bad result: {:?}", res);
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "nat.flows.out, nat.flows.in",
            "uft.out",
            "stats.port.out_modified, stats.port.out_uft_miss",
        ]
    );
    assert_eq!(pkt1.body_offset(), VPC_ENCAP_SZ + TCP4_SZ + HTTP_SYN_OPTS_LEN);
    assert_eq!(pkt1.body_seg(), 1);
    let meta = pkt1.meta();
    match meta.outer.ether.as_ref() {
        Some(eth) => {
            assert_eq!(eth.src, MacAddr::ZERO);
            assert_eq!(eth.dst, MacAddr::ZERO);
        }

        None => panic!("no outer ether header"),
    }

    let inner_bytes = match meta.outer.ip.as_ref().unwrap() {
        IpMeta::Ip6(ip6) => {
            assert_eq!(ip6.src, g1_cfg.phys_ip);
            assert_eq!(ip6.dst, g1_cfg.boundary_services.ip);

            // Check that the encoded payload length in the outer header is
            // correct, and matches the actual number of bytes in the rest of
            // the packet.
            let mut bytes = pkt1.get_rdr().copy_remaining();
            assert_eq!(
                ip6.pay_len as usize,
                bytes.len() - EtherHdr::SIZE - Ipv6Hdr::BASE_SIZE
            );

            // Strip off the encapsulation headers
            bytes.drain(..VPC_ENCAP_SZ);
            bytes
        }

        val => panic!("expected outer IPv6, got: {:?}", val),
    };

    match meta.outer.encap.as_ref() {
        Some(EncapMeta::Geneve(geneve)) => {
            assert_eq!(geneve.entropy, 7777);
            assert_eq!(geneve.vni, g1_cfg.boundary_services.vni);
        }

        None => panic!("expected outer Geneve metadata"),
    }

    let eth = meta.inner.ether;
    assert_eq!(eth.src, g1_cfg.guest_mac);
    assert_eq!(eth.dst, g1_cfg.boundary_services.mac);
    assert_eq!(eth.ether_type, EtherType::Ipv4);

    match meta.inner.ip.as_ref().unwrap() {
        IpMeta::Ip4(ip4) => {
            assert_eq!(ip4.src, g1_cfg.snat().external_ip);
            assert_eq!(ip4.dst, dst_ip);
            assert_eq!(ip4.proto, Protocol::TCP);

            // Check that the encoded payload length in the inner header is
            // correct, and matches the actual number of bytes in the rest of
            // the packet.
            // IPv4 total length _DOES_ include the IPv4 header.
            assert_eq!(
                ip4.total_len as usize,
                inner_bytes.len() - EtherHdr::SIZE,
            );
        }

        ip6 => panic!("execpted inner IPv4 metadata, got IPv6: {:?}", ip6),
    }

    match meta.inner.ulp.as_ref().unwrap() {
        UlpMeta::Tcp(tcp) => {
            assert_eq!(
                tcp.src,
                g1_cfg.snat().ports.clone().rev().next().unwrap(),
            );
            assert_eq!(tcp.dst, 80);
        }

        ulp => panic!("expected inner TCP metadata, got: {:?}", ulp),
    }

    let mut pcap_guest = PcapBuilder::new("guest_to_internet_ipv4.pcap");
    pcap_guest.add_pkt(&pkt1);
}

// Verify that a guest can communicate with the internet over IPv6.
#[test]
fn guest_to_internet_ipv6() {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    g1.port.start();
    set!(g1, "port_state=running");

    // Add router entry that allows g1 to route to internet.
    router::add_entry(
        &g1.port,
        IpCidr::Ip6("::/0".parse().unwrap()),
        RouterTarget::InternetGateway,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    // ================================================================
    // Generate a TCP SYN packet from g1 to example.com
    // ================================================================
    let dst_ip = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
    let mut pkt1 = http_syn2(
        g1_cfg.guest_mac,
        g1_cfg.ipv6_cfg().unwrap().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );

    // ================================================================
    // Run the packet through g1's port in the outbound direction and
    // verify the resulting packet meets expectations.
    // ================================================================
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)), "bad result: {:?}", res);
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "nat.flows.out, nat.flows.in",
            "uft.out",
            "stats.port.out_modified, stats.port.out_uft_miss",
        ]
    );
    assert_eq!(pkt1.body_offset(), VPC_ENCAP_SZ + TCP6_SZ + HTTP_SYN_OPTS_LEN);
    assert_eq!(pkt1.body_seg(), 1);
    let meta = pkt1.meta();
    match meta.outer.ether.as_ref() {
        Some(eth) => {
            assert_eq!(eth.src, MacAddr::ZERO);
            assert_eq!(eth.dst, MacAddr::ZERO);
        }

        None => panic!("no outer ether header"),
    }

    let inner_bytes = match meta.outer.ip.as_ref().unwrap() {
        IpMeta::Ip6(ip6) => {
            assert_eq!(ip6.src, g1_cfg.phys_ip);
            assert_eq!(ip6.dst, g1_cfg.boundary_services.ip);

            // Check that the encoded payload length in the outer header is
            // correct, and matches the actual number of bytes in the rest of
            // the packet.
            let mut bytes = pkt1.get_rdr().copy_remaining();
            assert_eq!(
                ip6.pay_len as usize,
                bytes.len() - EtherHdr::SIZE - Ipv6Hdr::BASE_SIZE
            );

            // Strip off the encapsulation headers
            bytes.drain(..VPC_ENCAP_SZ);
            bytes
        }

        val => panic!("expected outer IPv6, got: {:?}", val),
    };

    match meta.outer.encap.as_ref() {
        Some(EncapMeta::Geneve(geneve)) => {
            assert_eq!(geneve.entropy, 7777);
            assert_eq!(geneve.vni, g1_cfg.boundary_services.vni);
        }

        None => panic!("expected outer Geneve metadata"),
    }

    let eth = meta.inner.ether;
    assert_eq!(eth.src, g1_cfg.guest_mac);
    assert_eq!(eth.dst, g1_cfg.boundary_services.mac);
    assert_eq!(eth.ether_type, EtherType::Ipv6);

    match meta.inner.ip.as_ref().unwrap() {
        IpMeta::Ip6(ip6) => {
            assert_eq!(ip6.src, g1_cfg.snat6().external_ip);
            assert_eq!(ip6.dst, dst_ip);
            assert_eq!(ip6.proto, Protocol::TCP);
            assert_eq!(ip6.next_hdr, IpProtocol::Tcp);

            // Check that the encoded payload length in the inner header is
            // correct, and matches the actual number of bytes in the rest of
            // the packet.
            // IPv6 payload length _DOES NOT_ include the IPv6 header.
            assert_eq!(
                ip6.pay_len as usize,
                inner_bytes.len() - EtherHdr::SIZE - Ipv6Hdr::BASE_SIZE
            );
        }

        ip4 => panic!("execpted inner IPv6 metadata, got IPv4: {:?}", ip4),
    }

    match meta.inner.ulp.as_ref().unwrap() {
        UlpMeta::Tcp(tcp) => {
            assert_eq!(
                tcp.src,
                g1_cfg.snat6().ports.clone().rev().next().unwrap(),
            );
            assert_eq!(tcp.dst, 80);
        }

        ulp => panic!("expected inner TCP metadata, got: {:?}", ulp),
    }

    let mut pcap_guest = PcapBuilder::new("guest_to_internet_ipv6.pcap");
    pcap_guest.add_pkt(&pkt1);
}

// Verify that an ICMP Echo request has its identifier rewritten by
// SNAT.
#[test]
fn snat_icmp4_echo_rewrite() {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    g1.port.start();
    set!(g1, "port_state=running");
    let dst_ip: Ipv4Addr = "45.55.45.205".parse().unwrap();
    let ident = 7;
    let mut seq_no = 777;
    let data = b"reunion\0";

    // Add router entry that allows g1 to route to internet.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);
    let mapped_port = g1_cfg.snat().ports.clone().rev().next().unwrap();

    // ================================================================
    // Verify echo request rewrite.
    // ================================================================
    let mut pkt1 = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4().private_ip.into(),
        dst_ip.into(),
        ident,
        seq_no,
        &data[..],
        2,
    );

    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)), "bad result: {:?}", res);
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "nat.flows.out, nat.flows.in",
            "uft.out",
            "stats.port.out_modified, stats.port.out_uft_miss",
        ]
    );

    assert_eq!(pkt1.body_offset(), VPC_ENCAP_SZ + IP4_SZ);
    assert_eq!(pkt1.body_seg(), 0);
    let meta = pkt1.meta();

    let eth = meta.inner.ether;
    assert_eq!(eth.src, g1_cfg.guest_mac);
    assert_eq!(eth.dst, g1_cfg.boundary_services.mac);
    assert_eq!(eth.ether_type, EtherType::Ipv4);

    match meta.inner.ip.as_ref().unwrap() {
        IpMeta::Ip4(ip4) => {
            assert_eq!(ip4.src, g1_cfg.snat().external_ip);
            assert_eq!(ip4.dst, dst_ip);
            assert_eq!(ip4.proto, Protocol::ICMP);
        }

        ip6 => panic!("execpted inner IPv4 metadata, got IPv6: {:?}", ip6),
    }

    let body = pkt1.body_segs().unwrap()[0];
    let icmp = Icmpv4Packet::new_checked(body).unwrap();
    assert!(icmp.verify_checksum());
    assert_eq!(icmp.echo_ident(), mapped_port);
    assert_eq!(icmp.echo_seq_no(), seq_no);

    // ================================================================
    // Verify echo reply rewrite.
    // ================================================================
    let mut pkt2 = gen_icmp_echo_reply(
        g1_cfg.boundary_services.mac,
        g1_cfg.guest_mac,
        dst_ip,
        g1_cfg.snat().external_ip,
        mapped_port,
        seq_no,
        &data[..],
        3,
    );
    let bsvc_phys = TestIpPhys {
        ip: g1_cfg.boundary_services.ip,
        mac: g1_cfg.boundary_services.mac,
        vni: g1_cfg.boundary_services.vni,
    };
    let g1_phys = TestIpPhys {
        ip: g1_cfg.phys_ip,
        mac: g1_cfg.guest_mac,
        vni: g1_cfg.vni,
    };
    pkt2 = encap(pkt2, bsvc_phys, g1_phys);

    let res = g1.port.process(In, &mut pkt2, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)), "bad result: {:?}", res);
    incr!(g1, ["uft.in", "stats.port.in_modified, stats.port.in_uft_miss"]);
    assert_eq!(pkt2.body_offset(), IP4_SZ);
    assert_eq!(pkt2.body_seg(), 0);
    let meta = pkt2.meta();

    let eth = meta.inner.ether;
    assert_eq!(eth.src, g1_cfg.gateway_mac);
    assert_eq!(eth.dst, g1_cfg.guest_mac);
    assert_eq!(eth.ether_type, EtherType::Ipv4);

    match meta.inner.ip.as_ref().unwrap() {
        IpMeta::Ip4(ip4) => {
            assert_eq!(ip4.src, dst_ip);
            assert_eq!(ip4.dst, g1_cfg.ipv4().private_ip);
            assert_eq!(ip4.proto, Protocol::ICMP);
        }

        ip6 => panic!("execpted inner IPv4 metadata, got IPv6: {:?}", ip6),
    }

    let body = pkt2.body_segs().unwrap()[0];
    let icmp = Icmpv4Packet::new_checked(body).unwrap();
    assert!(icmp.verify_checksum());
    assert_eq!(icmp.echo_ident(), ident);
    assert_eq!(icmp.echo_seq_no(), seq_no);

    // ================================================================
    // Send ICMP Echo Req a second time. We want to verify that a) the
    // UFT entry is used and b) that it runs the attached body
    // transformation.
    // ================================================================
    seq_no += 1;
    let mut pkt3 = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4().private_ip.into(),
        dst_ip.into(),
        ident,
        seq_no,
        &data[..],
        1,
    );

    assert_eq!(g1.port.stats_snap().out_uft_hit, 0);
    let res = g1.port.process(Out, &mut pkt3, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)), "bad result: {:?}", res);
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    assert_eq!(pkt3.body_offset(), VPC_ENCAP_SZ + IP4_SZ);
    assert_eq!(pkt3.body_seg(), 1);
    let meta = pkt3.meta();

    let eth = meta.inner.ether;
    assert_eq!(eth.src, g1_cfg.guest_mac);
    assert_eq!(eth.dst, g1_cfg.boundary_services.mac);
    assert_eq!(eth.ether_type, EtherType::Ipv4);

    match meta.inner.ip.as_ref().unwrap() {
        IpMeta::Ip4(ip4) => {
            assert_eq!(ip4.src, g1_cfg.snat().external_ip);
            assert_eq!(ip4.dst, dst_ip);
            assert_eq!(ip4.proto, Protocol::ICMP);
        }

        ip6 => panic!("execpted inner IPv4 metadata, got IPv6: {:?}", ip6),
    }

    let body = pkt3.body_segs().unwrap()[0];
    let icmp = Icmpv4Packet::new_checked(body).unwrap();
    assert!(icmp.verify_checksum());
    assert_eq!(icmp.echo_ident(), mapped_port);
    assert_eq!(icmp.echo_seq_no(), seq_no);
    assert_eq!(g1.port.stats_snap().out_uft_hit, 1);

    // ================================================================
    // Process ICMP Echo Reply a second time. Once again, this time we
    // want to verify that the body transformation comes from the UFT
    // entry.
    // ================================================================
    let mut pkt4 = gen_icmp_echo_reply(
        g1_cfg.boundary_services.mac,
        g1_cfg.guest_mac,
        dst_ip,
        g1_cfg.snat().external_ip,
        mapped_port,
        seq_no,
        &data[..],
        2,
    );

    assert_eq!(g1.port.stats_snap().in_uft_hit, 0);
    let res = g1.port.process(In, &mut pkt4, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)), "bad result: {:?}", res);
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(pkt4.body_offset(), IP4_SZ);
    assert_eq!(pkt4.body_seg(), 0);
    let meta = pkt4.meta();

    let eth = meta.inner.ether;
    assert_eq!(eth.src, g1_cfg.gateway_mac);
    assert_eq!(eth.dst, g1_cfg.guest_mac);
    assert_eq!(eth.ether_type, EtherType::Ipv4);

    match meta.inner.ip.as_ref().unwrap() {
        IpMeta::Ip4(ip4) => {
            assert_eq!(ip4.src, dst_ip);
            assert_eq!(ip4.dst, g1_cfg.ipv4().private_ip);
            assert_eq!(ip4.proto, Protocol::ICMP);
        }

        ip6 => panic!("execpted inner IPv4 metadata, got IPv6: {:?}", ip6),
    }

    let body = pkt4.body_segs().unwrap()[0];
    let icmp = Icmpv4Packet::new_checked(body).unwrap();
    assert!(icmp.verify_checksum());
    assert_eq!(icmp.echo_ident(), ident);
    assert_eq!(icmp.echo_seq_no(), seq_no);
    assert_eq!(g1.port.stats_snap().in_uft_hit, 1);
}

#[test]
fn bad_ip_len() {
    let cfg = lab_cfg();

    let eth = EtherMeta {
        src: cfg.guest_mac,
        dst: MacAddr::BROADCAST,
        ether_type: EtherType::Ipv4,
    };

    let ip = Ipv4Meta {
        src: "0.0.0.0".parse().unwrap(),
        dst: Ipv4Addr::LOCAL_BCAST,
        proto: Protocol::UDP,
        ttl: 64,
        ident: 1,
        hdr_len: 20,
        // We write a total legnth of 4 bytes, which is completely
        // bogus for an IP header and should return an error during
        // processing.
        total_len: 4,
        ..Default::default()
    };

    let udp = UdpMeta { src: 68, dst: 67, ..Default::default() };
    let total_len = EtherHdr::SIZE + usize::from(ip.hdr_len) + udp.hdr_len();
    let mut pkt = Packet::alloc_and_expand(total_len);
    let mut wtr = pkt.seg0_wtr();
    eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
    ip.emit(wtr.slice_mut(ip.hdr_len()).unwrap());
    udp.emit(wtr.slice_mut(udp.hdr_len()).unwrap());
    let res = pkt.parse(Out, VpcParser::new());
    assert_eq!(
        res.err().unwrap(),
        ParseError::BadHeader("IPv4: BadTotalLen { total_len: 4 }".to_string())
    );
}

// Verify that OPTE generates a hairpin ARP reply when the guest
// queries for the gateway.
#[test]
fn arp_gateway() {
    use opte::engine::arp::ArpOp;

    let cfg = g1_cfg();
    let mut g1 = oxide_net_setup("arp_hairpin", &cfg, None);
    g1.port.start();
    set!(g1, "port_state=running");

    let eth_hdr = EtherHdrRaw {
        dst: [0xff; 6],
        src: cfg.guest_mac.bytes(),
        ether_type: [0x08, 0x06],
    };

    let arp = ArpEthIpv4 {
        htype: 1,
        ptype: u16::from(EtherType::Ipv4),
        hlen: 6,
        plen: 4,
        op: ArpOp::Request,
        sha: cfg.guest_mac,
        spa: cfg.ipv4_cfg().unwrap().private_ip,
        tha: MacAddr::from([0x00; 6]),
        tpa: cfg.ipv4_cfg().unwrap().gateway_ip,
    };

    let mut bytes = vec![];
    bytes.extend_from_slice(&eth_hdr.as_bytes());
    bytes.extend_from_slice(ArpEthIpv4Raw::from(&arp).as_bytes());
    let mut pkt = Packet::copy(&bytes).parse(Out, VpcParser::new()).unwrap();
    print_port(&g1.port, &g1.vpc_map);

    let res = g1.port.process(Out, &mut pkt, ActionMeta::new());
    match res {
        Ok(Hairpin(hppkt)) => {
            // In this case we are parsing a hairpin reply, so we
            // can't use the VpcParser since it would expect any
            // inbound packet to be encapsulated.
            let mut hppkt = hppkt.parse(In, GenericUlp {}).unwrap();
            let meta = hppkt.meta();
            let ethm = meta.inner.ether;
            assert_eq!(ethm.dst, cfg.guest_mac);
            assert_eq!(ethm.src, cfg.gateway_mac);
            assert_eq!(ethm.ether_type, EtherType::Arp);
            let eth_len = hppkt.hdr_offsets().inner.ether.hdr_len;

            let mut rdr = hppkt.get_rdr_mut();
            assert!(rdr.seek(eth_len).is_ok());
            let arp = ArpEthIpv4::parse(&mut rdr).unwrap();
            assert_eq!(arp.op, ArpOp::Reply);
            assert_eq!(arp.ptype, u16::from(EtherType::Ipv4));
            assert_eq!(arp.sha, cfg.gateway_mac);
            assert_eq!(arp.spa, cfg.ipv4_cfg().unwrap().gateway_ip);
            assert_eq!(arp.tha, cfg.guest_mac);
            assert_eq!(arp.tpa, cfg.ipv4_cfg().unwrap().private_ip);
        }

        res => panic!("expected a Hairpin, got {:?}", res),
    }
    incr!(g1, ["stats.port.out_uft_miss"]);
}

#[test]
fn flow_expiration() {
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    g1.vpc_map.add(g2_cfg.ipv4().private_ip.into(), g2_cfg.phys_addr());
    g1.port.start();
    set!(g1, "port_state=running");
    let now = Moment::now();

    // ================================================================
    // Run the packet through g1's port in the outbound direction and
    // verify the resulting packet meets expectations.
    // ================================================================
    let mut pkt1 = http_syn(&g1_cfg, &g2_cfg);
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
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
        .expire_flows(now + Duration::new(FLOW_DEF_EXPIRE_SECS as u64, 0))
        .unwrap();
    assert_port!(g1);

    g1.port
        .expire_flows(now + Duration::new(FLOW_DEF_EXPIRE_SECS as u64 + 1, 0))
        .unwrap();
    zero_flows!(g1);
}

// Test that a guest can send an ICMPv6 echo request / reply to the gateway.
// This tests both link-local and VPC-private IPv6 source addresses, and the
// only supported destination, OPTE's IPv6 link-local derived from its MAC.
#[test]
fn gateway_icmpv6_ping() {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
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
    let mut pkt1 = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        src_ip.into(),
        dst_ip.into(),
        ident,
        seq_no,
        &data[..],
        3,
    );
    pcap.add_pkt(&pkt1);

    // ================================================================
    // Run the Echo Request through g1's port in the outbound
    // direction and verify it results in an Echo Reply Hairpin packet
    // back to guest.
    // ================================================================
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
    let hp = match res {
        Ok(Hairpin(hp)) => hp,
        _ => panic!("expected Hairpin, got {:?}", res),
    };
    incr!(g1, ["stats.port.out_uft_miss"]);

    // In this case we are parsing a hairpin reply, so we can't use
    // the VpcParser since it would expect any inbound packet to be
    // encapsulated.
    let reply = hp.parse(In, GenericUlp {}).unwrap();
    pcap.add_pkt(&reply);

    // Ether + IPv6 + ICMPv6
    assert_eq!(reply.body_offset(), IP6_SZ + Icmpv6Hdr::SIZE);
    assert_eq!(reply.body_seg(), 0);

    let meta = reply.meta();
    assert!(meta.outer.ether.is_none());
    assert!(meta.outer.ip.is_none());
    assert!(meta.outer.encap.is_none());

    let eth = meta.inner.ether;
    assert_eq!(eth.src, g1_cfg.gateway_mac);
    assert_eq!(eth.dst, g1_cfg.guest_mac);

    let (src, dst) = match meta.inner.ip.as_ref().unwrap() {
        IpMeta::Ip6(ip6) => {
            assert_eq!(ip6.src, dst_ip);
            assert_eq!(ip6.dst, src_ip);
            assert_eq!(ip6.proto, Protocol::ICMPv6);
            (
                Ipv6Address::from_bytes(&ip6.src),
                Ipv6Address::from_bytes(&ip6.dst),
            )
        }
        ip4 => panic!("expected inner IPv6 metadata, got IPv4: {:?}", ip4),
    };

    let Some(icmp6) = meta.inner_icmp6() else {
        panic!("expected inner ICMPv6 metadata");
    };

    // `Icmpv6Packet` requires the ICMPv6 header and not just the message payload.
    // Given we successfully got the ICMPv6 metadata, rewinding here is fine.
    let mut rdr = reply.get_body_rdr();
    rdr.seek_back(icmp6.hdr_len()).unwrap();

    let reply_body = rdr.copy_remaining();
    let reply_pkt = Icmpv6Packet::new_checked(&reply_body).unwrap();

    // Verify the parsed metadata matches the packet
    assert_eq!(icmp6.msg_code, reply_pkt.msg_code());
    assert_eq!(icmp6.msg_type, reply_pkt.msg_type().into());

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

// Generate a packet containing an NDP Router Solicitation.
//
// The source MAC is used to generate the source IPv6 address, using the EUI-64
// transform. The resulting packet has a multicast MAC address, and the
// All-Routers destination IPv6 address.
fn gen_router_solicitation(src_mac: &MacAddr) -> Packet<Parsed> {
    // The source IPv6 address is the EUI-64 transform of the source MAC.
    let src_ip = Ipv6Addr::from_eui64(src_mac);

    // Must be destined for the All-Routers IPv6 address, and the corresponding
    // multicast Ethernet address.
    let dst_ip: Ipv6Addr = Ipv6Addr::ALL_ROUTERS;
    let dst_mac = dst_ip.multicast_mac().unwrap();

    let solicit = NdiscRepr::RouterSolicit {
        lladdr: Some(RawHardwareAddress::from_bytes(&src_mac)),
    };
    let req = Icmpv6Repr::Ndisc(solicit);
    let mut body_bytes = vec![0u8; req.buffer_len()];
    let mut req_pkt = Icmpv6Packet::new_unchecked(&mut body_bytes);
    let mut csum = CsumCapab::ignored();
    csum.icmpv6 = smoltcp::phy::Checksum::Tx;
    req.emit(
        &IpAddress::Ipv6(src_ip.into()),
        &IpAddress::Ipv6(dst_ip.into()),
        &mut req_pkt,
        &csum,
    );
    let ip6 = Ipv6Meta {
        src: src_ip,
        dst: dst_ip,
        proto: Protocol::ICMPv6,
        next_hdr: IpProtocol::Icmpv6,
        pay_len: req.buffer_len() as u16,
        hop_limit: 255,
        ..Default::default()
    };
    let eth =
        EtherMeta { dst: dst_mac, src: *src_mac, ether_type: EtherType::Ipv6 };

    let total_len = EtherHdr::SIZE + ip6.hdr_len() + req.buffer_len();
    let mut pkt = Packet::alloc_and_expand(total_len);
    let mut wtr = pkt.seg0_wtr();
    eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
    ip6.emit(wtr.slice_mut(ip6.hdr_len()).unwrap());
    wtr.write(&body_bytes).unwrap();
    pkt.parse(Out, VpcParser::new()).unwrap()
}

// Verify that a Router Solicitation emitted from the guest results in a Router
// Advertisement from the gateway. This tests both a solicitation sent to the
// router's unicast address, or its solicited-node multicast address.
#[test]
fn gateway_router_advert_reply() {
    use smoltcp::time::Duration;

    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    g1.port.start();
    set!(g1, "port_state=running");
    let mut pcap = PcapBuilder::new("gateway_router_advert_reply.pcap");

    // ====================================================
    // Generate a Router Solicitation from G1 to Virtual GW
    // ====================================================
    let mut pkt1 = gen_router_solicitation(&g1_cfg.guest_mac);
    pcap.add_pkt(&pkt1);

    // ================================================================
    // Run the Solicitation through g1's port in the outbound
    // direction and verify it results in an Router Advertisement
    // hairpin back to guest.
    // ================================================================
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
    let hp = match res {
        Ok(Hairpin(hp)) => hp,
        _ => panic!("expected Hairpin, got {:?}", res),
    };
    incr!(g1, ["stats.port.out_uft_miss"]);

    // In this case we are parsing a hairpin reply, so we can't use
    // the VpcParser since it would expect any inbound packet to be
    // encapsulated.
    let reply = hp.parse(In, GenericUlp {}).unwrap();
    pcap.add_pkt(&reply);

    // Ether + IPv6 + ICMPv6
    assert_eq!(reply.body_offset(), IP6_SZ + Icmpv6Hdr::SIZE);
    assert_eq!(reply.body_seg(), 0);

    let meta = reply.meta();
    assert!(meta.outer.ether.is_none());
    assert!(meta.outer.ip.is_none());
    assert!(meta.outer.encap.is_none());

    let eth = meta.inner.ether;
    assert_eq!(
        eth.src, g1_cfg.gateway_mac,
        "Router advertisement should come from the gateway's MAC"
    );
    assert_eq!(
        eth.dst, g1_cfg.guest_mac,
        "Router advertisement should be destined for the guest's MAC"
    );

    let IpMeta::Ip6(ip6) = meta.inner.ip.as_ref().expect("No inner IP header") else {
        panic!("Inner IP header is not IPv6");
    };

    assert_eq!(
        ip6.src,
        Ipv6Addr::from_eui64(&g1_cfg.gateway_mac),
        "Router advertisement should come from the \
        gateway's link-local IPv6 address, generated \
        from the EUI-64 transform of its MAC",
    );
    let expected_dst = Ipv6Addr::from_eui64(&g1_cfg.guest_mac);
    assert_eq!(
        ip6.dst, expected_dst,
        "Router advertisement should be destined for \
        the guest's Link-Local IPv6 address, generated from \
        the EUI-64 transform of its MAC"
    );
    assert_eq!(ip6.proto, Protocol::ICMPv6);

    // RFC 4861 6.1.2 requires that the hop limit be 255 in an RA.
    assert_eq!(ip6.hop_limit, 255);

    let Some(icmp6) = meta.inner_icmp6() else {
        panic!("expected inner ICMPv6 metadata");
    };

    // `Icmpv6Packet` requires the ICMPv6 header and not just the message payload.
    // Given we successfully got the ICMPv6 metadata, rewinding here is fine.
    let mut rdr = reply.get_body_rdr();
    rdr.seek_back(icmp6.hdr_len()).unwrap();

    let reply_body = rdr.copy_remaining();
    let reply_pkt = Icmpv6Packet::new_checked(&reply_body).unwrap();
    let mut csum = CsumCapab::ignored();
    csum.icmpv6 = smoltcp::phy::Checksum::Rx;
    let reply_icmp = Icmpv6Repr::parse(
        &IpAddress::Ipv6(ip6.src.into()),
        &IpAddress::Ipv6(ip6.dst.into()),
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

// Create a Neighbor Solicitation.
fn generate_neighbor_solicitation(
    info: &SolicitInfo,
    with_checksum: bool,
) -> Packet<Parsed> {
    let solicit = NdiscRepr::NeighborSolicit {
        target_addr: Ipv6Address::from(info.target_addr),
        lladdr: info.lladdr.map(|x| RawHardwareAddress::from_bytes(&x)),
    };
    let req = Icmpv6Repr::Ndisc(solicit);
    let mut body = vec![0u8; req.buffer_len()];
    let mut req_pkt = Icmpv6Packet::new_unchecked(&mut body);
    let mut csum = CsumCapab::ignored();
    if with_checksum {
        csum.icmpv6 = smoltcp::phy::Checksum::Tx;
    }
    req.emit(
        &IpAddress::Ipv6(info.src_ip.into()),
        &IpAddress::Ipv6(info.dst_ip.into()),
        &mut req_pkt,
        &csum,
    );
    let ip6 = Ipv6Meta {
        src: info.src_ip,
        dst: info.dst_ip,
        proto: Protocol::ICMPv6,
        next_hdr: IpProtocol::Icmpv6,
        hop_limit: 255,
        pay_len: req.buffer_len() as u16,
        ..Default::default()
    };
    let eth = EtherMeta {
        dst: info.dst_mac,
        src: info.src_mac,
        ether_type: EtherType::Ipv6,
    };

    let total_len = EtherHdr::SIZE + ip6.hdr_len() + req.buffer_len();
    let mut pkt = Packet::alloc_and_expand(total_len);
    let mut wtr = pkt.seg0_wtr();
    eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
    ip6.emit(wtr.slice_mut(ip6.hdr_len()).unwrap());
    wtr.write(&body).unwrap();
    pkt.parse(Out, VpcParser::new()).unwrap()
}

// Helper type describing a Neighbor Solicitation
#[derive(Clone, Copy, Debug)]
struct SolicitInfo {
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    target_addr: Ipv6Addr,
    lladdr: Option<MacAddr>,
}

impl std::fmt::Display for SolicitInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let lladdr = match self.lladdr {
            None => "None".to_string(),
            Some(x) => x.to_string(),
        };
        f.debug_struct("SolicitInfo")
            .field("src_mac", &self.src_mac.to_string())
            .field("dst_mac", &self.dst_mac.to_string())
            .field("src_ip", &self.src_ip.to_string())
            .field("dst_ip", &self.dst_ip.to_string())
            .field("target_addr", &self.target_addr.to_string())
            .field("lladdr", &lladdr)
            .finish()
    }
}

// Helper type describing a Neighbor Advertisement
#[derive(Clone, Copy, Debug)]
struct AdvertInfo {
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    target_addr: Ipv6Addr,
    lladdr: Option<MacAddr>,
    flags: NdiscNeighborFlags,
}

impl std::fmt::Display for AdvertInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let lladdr = match self.lladdr {
            None => "None".to_string(),
            Some(x) => x.to_string(),
        };
        f.debug_struct("AdvertInfo")
            .field("src_mac", &self.src_mac.to_string())
            .field("dst_mac", &self.dst_mac.to_string())
            .field("src_ip", &self.src_ip.to_string())
            .field("dst_ip", &self.dst_ip.to_string())
            .field("target_addr", &self.target_addr.to_string())
            .field("lladdr", &lladdr)
            .field("flags", &self.flags)
            .finish()
    }
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
    hp: Packet<Initialized>,
    na: AdvertInfo,
) {
    // In this case we are parsing a hairpin reply, so we can't use
    // the VpcParser since it would expect any inbound packet to be
    // encapsulated.
    let reply = hp.parse(In, GenericUlp {}).unwrap();
    pcap.add_pkt(&reply);

    // Verify Ethernet and IPv6 header basics.
    assert_eq!(reply.body_offset(), IP6_SZ + Icmpv6Hdr::SIZE);
    assert_eq!(reply.body_seg(), 0);
    let meta = reply.meta();
    assert!(meta.outer.ether.is_none());
    assert!(meta.outer.ip.is_none());
    assert!(meta.outer.encap.is_none());

    // Check that the inner MACs are what we expect.
    let eth = meta.inner.ether;
    assert_eq!(eth.src, na.src_mac);
    assert_eq!(eth.dst, na.dst_mac);

    // Check that the inner IPs are what we expect.
    let ip6 = if let IpMeta::Ip6(ip6) =
        meta.inner.ip.as_ref().expect("No inner IP header")
    {
        ip6
    } else {
        panic!("Inner IP header is not IPv6");
    };
    assert_eq!(ip6.src, na.src_ip);
    assert_eq!(ip6.dst, na.dst_ip);
    assert_eq!(ip6.proto, Protocol::ICMPv6);

    // RFC 4861 7.1.2 requires that the hop limit be 255 in an NA.
    assert_eq!(ip6.hop_limit, 255);

    let Some(icmp6) = meta.inner_icmp6() else {
        panic!("expected inner ICMPv6 metadata");
    };

    // `Icmpv6Packet` requires the ICMPv6 header and not just the message payload.
    // Given we successfully got the ICMPv6 metadata, rewinding here is fine.
    let mut rdr = reply.get_body_rdr();
    rdr.seek_back(icmp6.hdr_len()).unwrap();

    // Validate the details of the Neighbor Advertisement itself.
    let reply_body = rdr.copy_remaining();
    let reply_pkt = Icmpv6Packet::new_checked(&reply_body).unwrap();
    let mut csum = CsumCapab::ignored();
    csum.icmpv6 = smoltcp::phy::Checksum::Rx;
    let reply_icmp = Icmpv6Repr::parse(
        &IpAddress::Ipv6(ip6.src.into()),
        &IpAddress::Ipv6(ip6.dst.into()),
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
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
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
            pkt.compute_checksums();
        }
        with_checksum = !with_checksum;
        pcap.add_pkt(&pkt);
        let res = g1.port.process(Out, &mut pkt, ActionMeta::new());
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
                continue;
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

// Build a packet from a DHCPv6 message, from a client to server.
fn packet_from_client_dhcpv6_message<'a>(
    cfg: &VpcCfg,
    msg: &dhcpv6::protocol::Message<'a>,
) -> Packet<Parsed> {
    let eth = EtherMeta {
        dst: dhcpv6::ALL_RELAYS_AND_SERVERS.multicast_mac().unwrap(),
        src: cfg.guest_mac,
        ether_type: EtherType::Ipv6,
    };

    let ip = Ipv6Meta {
        src: Ipv6Addr::from_eui64(&cfg.guest_mac),
        dst: dhcpv6::ALL_RELAYS_AND_SERVERS,
        proto: Protocol::UDP,
        next_hdr: IpProtocol::Udp,
        pay_len: (msg.buffer_len() + UdpHdr::SIZE) as u16,
        ..Default::default()
    };

    let udp = UdpMeta {
        src: dhcpv6::CLIENT_PORT,
        dst: dhcpv6::SERVER_PORT,
        len: (UdpHdr::SIZE + msg.buffer_len()) as u16,
        ..Default::default()
    };

    write_dhcpv6_packet(eth, ip, udp, msg)
}

fn write_dhcpv6_packet<'a>(
    eth: EtherMeta,
    ip: Ipv6Meta,
    udp: UdpMeta,
    msg: &dhcpv6::protocol::Message<'a>,
) -> Packet<Parsed> {
    let reply_len =
        msg.buffer_len() + UdpHdr::SIZE + Ipv6Hdr::BASE_SIZE + EtherHdr::SIZE;
    let mut pkt = Packet::alloc_and_expand(reply_len);
    let mut wtr = pkt.seg0_wtr();
    eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
    ip.emit(wtr.slice_mut(ip.hdr_len()).unwrap());
    udp.emit(wtr.slice_mut(udp.hdr_len()).unwrap());
    let mut msg_buf = vec![0; msg.buffer_len()];
    msg.copy_into(&mut msg_buf).unwrap();
    wtr.write(&msg_buf).unwrap();
    pkt.parse(Out, GenericUlp {}).unwrap()
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
    request_pkt: &Packet<Parsed>,
    request: &dhcpv6::protocol::Message<'a>,
    reply_pkt: &Packet<Parsed>,
    reply: &dhcpv6::protocol::Message<'a>,
) {
    let request_meta = request_pkt.meta();
    let reply_meta = reply_pkt.meta();
    let request_ether = request_meta.inner_ether();
    let reply_ether = reply_meta.inner_ether();
    assert_eq!(
        request_ether.dst,
        dhcpv6::ALL_RELAYS_AND_SERVERS.multicast_mac().unwrap()
    );
    assert_eq!(request_ether.src, reply_ether.dst);

    let request_ip = request_meta.inner_ip6().unwrap();
    let reply_ip = reply_meta.inner_ip6().unwrap();
    assert_eq!(request_ip.src, Ipv6Addr::from_eui64(&cfg.guest_mac));
    assert_eq!(request_ip.dst, dhcpv6::ALL_RELAYS_AND_SERVERS);
    assert_eq!(request_ip.proto, Protocol::UDP);
    assert_eq!(reply_ip.dst, request_ip.src);
    assert_eq!(reply_ip.src, Ipv6Addr::from_eui64(&cfg.gateway_mac));
    assert_eq!(reply_ip.proto, Protocol::UDP);

    let request_udp = request_meta.inner_udp().unwrap();
    let reply_udp = reply_meta.inner_udp().unwrap();
    assert_eq!(request_udp.src, dhcpv6::CLIENT_PORT);
    assert_eq!(request_udp.dst, dhcpv6::SERVER_PORT);
    assert_eq!(reply_udp.dst, dhcpv6::CLIENT_PORT);
    assert_eq!(reply_udp.src, dhcpv6::SERVER_PORT);

    // Verify the details of the DHCPv6 exchange itself.
    assert_eq!(reply.xid, request.xid);
    assert!(reply.has_option(dhcpv6::options::Code::ServerId));
    let client_id =
        request.find_option(dhcpv6::options::Code::ClientId).unwrap();
    assert_eq!(
        client_id,
        reply.find_option(dhcpv6::options::Code::ClientId).unwrap()
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
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
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
    let extra_options =
        &[dhcpv6::options::Code::DnsServers, dhcpv6::options::Code::DomainList];
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
            let mut request_pkt =
                packet_from_client_dhcpv6_message(&g1_cfg, &request);
            pcap.add_pkt(&request_pkt);
            let res = g1
                .port
                .process(Out, &mut request_pkt, ActionMeta::new())
                .unwrap();
            if let Hairpin(hp) = res {
                // In this case we are parsing a hairpin reply, so we
                // can't use the VpcParser since it would expect any
                // inbound packet to be encapsulated.
                let reply_pkt = hp.parse(In, GenericUlp {}).unwrap();
                pcap.add_pkt(&reply_pkt);

                let body = reply_pkt.get_body_rdr().copy_remaining();
                let reply =
                    dhcpv6::protocol::Message::from_bytes(&body).unwrap();
                verify_dhcpv6_essentials(
                    &g1_cfg,
                    &request_pkt,
                    &request,
                    &reply_pkt,
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
                    assert_eq!(
                        reply.typ,
                        dhcpv6::protocol::MessageType::Advertise
                    );
                }

                // In the case of Solicit + Rapid Commit, we are required to
                // send the Rapid Commit option back in our reply.
                if has_rapid_commit
                    && msg_type == dhcpv6::protocol::MessageType::Solicit
                {
                    assert!(
                        reply.has_option(dhcpv6::options::Code::RapidCommit)
                    );
                }

                // Regardless of the message type, we are supposed to
                // include answers for each Option the client
                // requested (and that we support). That's mostly just
                // the actual VPC-private IPv6 address, but we also check the
                // Domain Search List option.
                let iana =
                    reply.find_option(dhcpv6::options::Code::IaNa).unwrap();
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
                        assert_eq!(
                            addr,
                            &g1_cfg.ipv6_cfg().unwrap().private_ip
                        );
                        assert!(valid.is_infinite());
                        assert!(preferred.is_infinite());
                        assert!(opts.is_empty());
                    } else {
                        panic!(
                            "Expected an IA Addr option, found {:#?}",
                            options
                        );
                    }
                } else {
                    panic!("Expected an IANA option, found {:?}", iana);
                }

                let domain_list = reply
                    .find_option(dhcpv6::options::Code::DomainList)
                    .expect("Expected a Domain Search List option");
                let dhcpv6::options::Option::DomainList(bytes) = domain_list else {
                    panic!("Expected an Option::DomainList");
                };
                let mut expected_bytes = Vec::new();
                for name in g1_cfg.domain_list.iter() {
                    expected_bytes.extend_from_slice(name.encode());
                }
                assert_eq!(
                    *bytes, expected_bytes,
                    "Domain Search List option not correctly encoded"
                );
            } else {
                panic!("Expected a Hairpin, found {:?}", res);
            }
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
    let mut pkt1 = http_syn2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "nat.flows.in, nat.flows.out",
            "uft.out",
            "stats.port.out_modified, stats.port.out_uft_miss",
        ]
    );
    let snat_port = pkt1.meta().inner.ulp.unwrap().src_port().unwrap();

    // ================================================================
    // Step 2
    //
    // Run the SYN+ACK packet through g1's port in the inbound
    // direction and verify it is accepted.
    // ================================================================
    let mut pkt2 = http_syn_ack2(
        g1_cfg.boundary_services.mac,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        snat_port,
    );
    let bs_phys = TestIpPhys {
        ip: g1_cfg.boundary_services.ip,
        mac: g1_cfg.boundary_services.mac,
        vni: g1_cfg.boundary_services.vni,
    };
    let g1_phys = TestIpPhys {
        ip: g1_cfg.phys_ip,
        mac: g1_cfg.guest_mac,
        vni: g1_cfg.vni,
    };
    pkt2 = encap(pkt2, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt2, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["uft.in", "stats.port.in_modified, stats.port.in_uft_miss"]);

    // ================================================================
    // Step 3
    //
    // Send ACK to establish connection.
    // ================================================================
    let mut pkt3 = http_ack2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let res = g1.port.process(Out, &mut pkt3, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
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
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    g1.port.start();
    set!(g1, "port_state=running");

    // Add default route.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway,
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
    let mut pkt4 = http_get2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let res = g1.port.process(Out, &mut pkt4, ActionMeta::new());
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
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    g1.port.start();
    set!(g1, "port_state=running");

    // Add default route.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    // ================================================================
    // Step 2
    // ================================================================
    let dst_ip = "52.10.128.69".parse().unwrap();
    let bs_phys = TestIpPhys {
        ip: g1_cfg.boundary_services.ip,
        mac: g1_cfg.boundary_services.mac,
        vni: g1_cfg.boundary_services.vni,
    };
    let g1_phys = TestIpPhys {
        ip: g1_cfg.phys_ip,
        mac: g1_cfg.guest_mac,
        vni: g1_cfg.vni,
    };
    let snat_port = establish_http_conn(&g1_cfg, &mut g1, dst_ip);

    let mut pkt1 = http_get2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);

    let mut pkt2 = http_get_ack2(
        g1_cfg.boundary_services.mac,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        snat_port,
    );
    pkt2 = encap(pkt2, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt2, ActionMeta::new());
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert!(matches!(res, Ok(Modified)));

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
    let mut pkt3 = http_301_reply2(
        g1_cfg.boundary_services.mac,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        snat_port,
    );
    pkt3 = encap(pkt3, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt3, ActionMeta::new());
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

// Verify TCP state transitions in relation to an outbound connection
// (the "active open"). In this case the guest is the client, the
// server is an external IP.
#[test]
fn tcp_outbound() {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    g1.port.start();
    set!(g1, "port_state=running");
    // let now = Moment::now();

    // Add default route.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    let bs_phys = TestIpPhys {
        ip: g1_cfg.boundary_services.ip,
        mac: g1_cfg.boundary_services.mac,
        vni: g1_cfg.boundary_services.vni,
    };
    let g1_phys = TestIpPhys {
        ip: g1_cfg.phys_ip,
        mac: g1_cfg.guest_mac,
        vni: g1_cfg.vni,
    };

    // ================================================================
    // SYN: Client -> Server
    // ================================================================
    let dst_ip = "52.10.128.69".parse().unwrap();
    let mut pkt1 = http_syn2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let flow = pkt1.flow().clone();
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "nat.flows.in, nat.flows.out",
            "uft.out",
            "stats.port.out_modified, stats.port.out_uft_miss",
        ]
    );
    let snat_port = pkt1.meta().inner.ulp.unwrap().src_port().unwrap();
    assert_eq!(TcpState::SynSent, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // SYN+ACK: Server -> Client
    // ================================================================
    let mut pkt2 = http_syn_ack2(
        g1_cfg.boundary_services.mac,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        snat_port,
    );
    pkt2 = encap(pkt2, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt2, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["uft.in", "stats.port.in_modified, stats.port.in_uft_miss"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK: Client -> Server
    // ================================================================
    let mut pkt3 = http_ack2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let res = g1.port.process(Out, &mut pkt3, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // HTTP GET: Client -> Server
    // ================================================================
    let mut pkt4 = http_get2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let res = g1.port.process(Out, &mut pkt4, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK HTTP GET: Server -> Client
    // ================================================================
    let mut pkt5 = http_get_ack2(
        g1_cfg.boundary_services.mac,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        snat_port,
    );
    pkt5 = encap(pkt5, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt5, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // HTTP 301 Reply: Server -> Client
    // ================================================================
    let mut pkt6 = http_301_reply2(
        g1_cfg.boundary_services.mac,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        snat_port,
    );
    pkt6 = encap(pkt6, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt6, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK HTTP 301: Client -> Server
    // ================================================================
    let mut pkt7 = http_301_ack2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let res = g1.port.process(Out, &mut pkt7, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // FIN: Client -> Server
    // ================================================================
    let mut pkt8 = http_guest_fin2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let res = g1.port.process(Out, &mut pkt8, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    assert_eq!(TcpState::FinWait1, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK FIN: Server -> Client
    // ================================================================
    let mut pkt9 = http_server_ack_fin2(
        g1_cfg.boundary_services.mac,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        snat_port,
    );
    pkt9 = encap(pkt9, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt9, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::FinWait2, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // FIN: Server -> Client
    // ================================================================
    let mut pkt10 = http_server_fin2(
        g1_cfg.boundary_services.mac,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        snat_port,
    );
    pkt10 = encap(pkt10, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt10, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::TimeWait, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK Server FIN: Client -> Server
    // ================================================================
    let mut pkt11 = http_guest_ack_fin2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let res = g1.port.process(Out, &mut pkt11, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    assert_eq!(TcpState::TimeWait, g1.port.tcp_state(&flow).unwrap());

    // TODO uncomment in follow up commit and make sure to expire TCP flows.
    //
    // g1.port
    //     .expire_flows(now + Duration::new(FLOW_DEF_EXPIRE_SECS as u64 + 1, 0))
    //     .unwrap();
    // zero_flows!(g1);
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
            snat: Some(SNat4Cfg {
                external_ip: "10.77.77.13".parse().unwrap(),
                ports: 1025..=4096,
            }),
            external_ips: Some("10.60.1.20".parse().unwrap()),
        },
        ipv6: Ipv6Cfg {
            vpc_subnet: "fd00::/64".parse().unwrap(),
            private_ip: "fd00::5".parse().unwrap(),
            gateway_ip: "fd00::1".parse().unwrap(),
            snat: Some(SNat6Cfg {
                external_ip: "2001:db8::1".parse().unwrap(),
                ports: 1025..=4096,
            }),
            external_ips: None,
        },
    };

    let g1_cfg = g1_cfg2(ip_cfg);
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    g1.port.start();
    set!(g1, "port_state=running");

    // Add default route.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules.out"]);

    let client_ip = "52.10.128.69".parse().unwrap();
    let bs_mac = g1_cfg.boundary_services.mac;
    let serv_mac = g1_cfg.guest_mac;
    let serv_ext_ip = g1_cfg.ipv4().external_ips.unwrap();
    let bs_phys = TestIpPhys {
        ip: g1_cfg.boundary_services.ip,
        mac: g1_cfg.boundary_services.mac,
        vni: g1_cfg.boundary_services.vni,
    };
    let g1_phys = TestIpPhys {
        ip: g1_cfg.phys_ip,
        mac: g1_cfg.guest_mac,
        vni: g1_cfg.vni,
    };

    // ================================================================
    // SYN: Client -> Server
    // ================================================================
    let mut pkt1 = http_syn2(bs_mac, client_ip, serv_mac, serv_ext_ip);
    pkt1 = encap(pkt1, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt1, ActionMeta::new());
    let flow = pkt1.flow().mirror();
    assert!(matches!(res, Ok(Modified)));
    incr!(
        g1,
        [
            "firewall.flows.out, firewall.flows.in",
            "nat.flows.in, nat.flows.out",
            "uft.in",
            "stats.port.in_modified, stats.port.in_uft_miss",
        ]
    );
    let sport = pkt1.meta().inner.ulp.unwrap().src_port().unwrap();
    assert_eq!(TcpState::Listen, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // SYN+ACK: Server -> Client
    // ================================================================
    let mut pkt2 = http_syn_ack2(
        serv_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        client_ip,
        sport,
    );
    let res = g1.port.process(Out, &mut pkt2, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)), "expected Modified, got {:?}", res);
    incr!(g1, ["uft.out, stats.port.out_modified, stats.port.out_uft_miss"]);
    assert_eq!(TcpState::SynRcvd, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK: Client -> Server
    // ================================================================
    let mut pkt3 = http_ack2(
        g1_cfg.boundary_services.mac,
        client_ip,
        serv_mac,
        serv_ext_ip,
    );
    pkt3 = encap(pkt3, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt3, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // HTTP GET: Client -> Server
    // ================================================================
    let mut pkt4 = http_get2(bs_mac, client_ip, serv_mac, serv_ext_ip);
    pkt4 = encap(pkt4, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt4, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK HTTP GET: Server -> Client
    // ================================================================
    let mut pkt5 = http_get_ack2(
        serv_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        client_ip,
        sport,
    );
    let res = g1.port.process(Out, &mut pkt5, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // HTTP 301 Reply: Server -> Client
    // ================================================================
    let mut pkt6 = http_301_reply2(
        serv_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        client_ip,
        sport,
    );
    let res = g1.port.process(Out, &mut pkt6, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK HTTP 301: Client -> Server
    // ================================================================
    let mut pkt7 = http_301_ack2(bs_mac, client_ip, serv_mac, serv_ext_ip);
    pkt7 = encap(pkt7, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt7, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // FIN: Client -> Server
    // ================================================================
    let mut pkt8 = http_guest_fin2(bs_mac, client_ip, serv_mac, serv_ext_ip);
    pkt8 = encap(pkt8, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt8, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::CloseWait, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK Client FIN: Server -> Client
    // ================================================================
    let mut pkt9 = http_server_ack_fin2(
        serv_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        client_ip,
        sport,
    );
    let res = g1.port.process(Out, &mut pkt9, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    assert_eq!(TcpState::CloseWait, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // FIN: Server -> Client
    // ================================================================
    let mut pkt10 = http_server_fin2(
        serv_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        client_ip,
        sport,
    );
    let res = g1.port.process(Out, &mut pkt10, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);
    assert_eq!(TcpState::LastAck, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // ACK Server FIN: Client -> Server
    // ================================================================
    let mut pkt11 =
        http_guest_ack_fin2(bs_mac, client_ip, serv_mac, serv_ext_ip);
    pkt11 = encap(pkt11, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt11, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    update!(
        g1,
        [
            "incr:stats.port.in_modified, stats.port.in_uft_hit",
            "set:uft.in=1, uft.out=0",
        ]
    );
    assert_eq!(None, g1.port.tcp_state(&flow));
}

// Verify that the guest cannot spoof outbound packets.
#[test]
fn anti_spoof() {
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    g1.port.start();
    set!(g1, "port_state=running");

    let src_ip = "172.30.0.240".parse::<Ipv4Addr>().unwrap();
    assert_ne!(src_ip, g1_cfg.ipv4().private_ip);
    let src_mac = ox_vpc_mac([0x0, 0x11, 0x22]);
    assert_ne!(src_mac, g1_cfg.guest_mac);

    // ================================================================
    // Try to send an outbound packet with a spoofed IP.
    // ================================================================
    let mut pkt1 = http_syn2(
        g1_cfg.guest_mac,
        src_ip,
        GW_MAC_ADDR,
        g2_cfg.ipv4().private_ip,
    );
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
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
    pkt1 = http_syn2(
        src_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        g2_cfg.ipv4().private_ip,
    );
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
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
    pkt1 = http_syn2(src_mac, src_ip, GW_MAC_ADDR, g2_cfg.ipv4().private_ip);
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
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

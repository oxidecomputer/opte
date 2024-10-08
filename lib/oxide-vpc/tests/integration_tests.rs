// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Integration tests.
//!
//! The idea behind these tests is to use actual packet captures to
//! regression test known good captures. This is done by taking a
//! packet capture in the guest as well as on the host -- one for each
//! side of OPTE. These captures are then used to regression test an
//! OPTE pipeline by single-stepping the packets in each capture and
//! verifying that OPTE processing produces the expected bytes.

use opte_test_utils as common;

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
use opte::engine::icmp::IcmpHdr;
use opte::engine::ip4::Ipv4Addr;
use opte::engine::ip4::Ipv4Hdr;
use opte::engine::ip4::Ipv4HdrError;
use opte::engine::ip4::Ipv4Meta;
use opte::engine::ip4::Protocol;
use opte::engine::ip6::Ipv6Hdr;
use opte::engine::ip6::Ipv6Meta;
use opte::engine::packet::Initialized;
use opte::engine::packet::InnerFlowId;
use opte::engine::packet::Packet;
use opte::engine::packet::PacketRead;
use opte::engine::packet::Parsed;
use opte::engine::port::ProcessError;
use opte::engine::tcp::TcpState;
use opte::engine::tcp::TIME_WAIT_EXPIRE_SECS;
use opte::engine::udp::UdpHdr;
use opte::engine::udp::UdpMeta;
use opte::engine::Direction;
use oxide_vpc::api::ExternalIpCfg;
use oxide_vpc::api::FirewallRule;
use oxide_vpc::api::RouterClass;
use oxide_vpc::api::VpcCfg;
use oxide_vpc::engine::overlay::BOUNDARY_SERVICES_VNI;
use pcap::*;
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
use std::collections::BTreeMap;
use std::prelude::v1::*;
use std::time::Duration;
use uuid::Uuid;
use zerocopy::AsBytes;

const IP4_SZ: usize = EtherHdr::SIZE + Ipv4Hdr::BASE_SIZE;
const IP6_SZ: usize = EtherHdr::SIZE + Ipv6Hdr::BASE_SIZE;
const TCP4_SZ: usize = IP4_SZ + TcpHdr::BASE_SIZE;
const TCP6_SZ: usize = IP6_SZ + TcpHdr::BASE_SIZE;

const VPC_ENCAP_SZ: usize = IP6_SZ + UdpHdr::SIZE + GeneveHdr::BASE_SIZE;

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
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
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
    assert_eq!(reply.body_offset(), IP4_SZ + IcmpHdr::SIZE);
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

    let mut rdr = reply.get_body_rdr();
    rdr.seek_back(IcmpHdr::SIZE).unwrap();
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

        ip6 => panic!("expected inner IPv4 metadata, got IPv6: {:?}", ip6),
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
    assert_eq!(pkt2.body_seg(), 0);

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

        ip6 => panic!("expected inner IPv4 metadata, got IPv6: {:?}", ip6),
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
        }

        None => panic!("expected outer Geneve metadata"),
    }

    let eth = meta.inner.ether;
    assert_eq!(eth.src, g1_cfg.guest_mac);
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

        ip6 => panic!("expected inner IPv4 metadata, got IPv6: {:?}", ip6),
    }

    match meta.inner.ulp.as_ref().unwrap() {
        UlpMeta::Tcp(tcp) => {
            assert_eq!(
                tcp.src,
                g1_cfg.snat().ports.clone().next_back().unwrap(),
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
        }

        None => panic!("expected outer Geneve metadata"),
    }

    let eth = meta.inner.ether;
    assert_eq!(eth.src, g1_cfg.guest_mac);
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

        ip4 => panic!("expected inner IPv6 metadata, got IPv4: {:?}", ip4),
    }

    match meta.inner.ulp.as_ref().unwrap() {
        UlpMeta::Tcp(tcp) => {
            assert_eq!(
                tcp.src,
                g1_cfg.snat6().ports.clone().next_back().unwrap(),
            );
            assert_eq!(tcp.dst, 80);
        }

        ulp => panic!("expected inner TCP metadata, got: {:?}", ulp),
    }

    let mut pcap_guest = PcapBuilder::new("guest_to_internet_ipv6.pcap");
    pcap_guest.add_pkt(&pkt1);
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
        let mut pkt1 = encap_external(pkt1, bsvc_phys, g1_phys);

        let res = port.port.process(In, &mut pkt1, ActionMeta::new());
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
            assert!(
                matches!(res, Ok(Modified)),
                "bad result for ip {ext_ip:?}: {res:?}"
            );
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
                    assert_eq!(
                        pkt1.meta().inner_ip4().unwrap().dst,
                        private_ip
                    );
                }
                private_ip.into()
            }
            IpAddr::Ip6(_) => {
                let private_ip = cfg.ipv6().private_ip;
                if !old_ip_gone {
                    assert_eq!(
                        pkt1.meta().inner_ip6().unwrap().dst,
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
        let mut pkt2 = http_syn_ack2(
            cfg.guest_mac,
            private_ip,
            GW_MAC_ADDR,
            partner_ip,
            flow_port,
        );
        let res = port.port.process(Out, &mut pkt2, ActionMeta::new());

        if old_ip_gone {
            // Failure mode here is different (assuming we have at least one
            // external IP). The packet must fail to send via the old IP,
            // invalidate the entry, and then choose the new external IP.
            assert!(matches!(res, Ok(Modified)), "bad result: {:?}", res);
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
                    let chosen_ip = pkt2.meta().inner_ip4().unwrap().src;
                    assert_ne!(chosen_ip, ip);
                    assert_ne!(IpAddr::from(chosen_ip), private_ip);
                }
                IpAddr::Ip6(ip) => {
                    let chosen_ip = pkt2.meta().inner_ip6().unwrap().src;
                    assert_ne!(chosen_ip, ip);
                    assert_ne!(IpAddr::from(chosen_ip), private_ip);
                }
            };
        } else {
            assert!(matches!(res, Ok(Modified)), "bad result: {:?}", res);
            update!(
                port,
                [
                    "incr:uft.out",
                    "incr:stats.port.out_modified, stats.port.out_uft_miss",
                ]
            );
            match ext_ip {
                IpAddr::Ip4(ip) => {
                    assert_eq!(pkt2.meta().inner_ip4().unwrap().src, ip);
                }
                IpAddr::Ip6(ip) => {
                    assert_eq!(pkt2.meta().inner_ip6().unwrap().src, ip);
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

            let pkt = http_syn3(
                g1_cfg.guest_mac,
                private_ip,
                g1_cfg.gateway_mac,
                partner_ip,
                flow_port,
                80,
            );
            let mut pkt = encap_external(pkt, bsvc_phys, g1_phys);

            let res = g1.port.process(Out, &mut pkt, ActionMeta::new());
            assert!(matches!(res, Ok(Modified)), "bad result: {res:?}");
            incr!(
                g1,
                [
                    "firewall.flows.out, firewall.flows.in",
                    "nat.flows.out, nat.flows.in",
                    "uft.out",
                    "stats.port.out_modified, stats.port.out_uft_miss",
                ]
            );

            match partner_ip {
                IpAddr::Ip4(_) => {
                    seen_v4s.push(pkt.meta().inner_ip4().unwrap().src);
                }
                IpAddr::Ip6(_) => {
                    seen_v6s.push(pkt.meta().inner_ip6().unwrap().src);
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
        let mut pkt1 = encap_external(pkt1, bsvc_phys, g1_phys);

        let res = g1.port.process(In, &mut pkt1, ActionMeta::new());
        assert!(
            matches!(res, Ok(Modified)),
            "bad result for ip {ext_ip:?}: {res:?}"
        );
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
        let mut pkt2 = http_syn_ack2(
            g1_cfg.guest_mac,
            private_ip,
            GW_MAC_ADDR,
            partner_ip,
            44490,
        );
        let res = g1.port.process(Out, &mut pkt2, ActionMeta::new());
        assert!(matches!(res, Ok(Modified)), "bad result: {:?}", res);
        update!(
            g1,
            [
                "incr:uft.out",
                "incr:stats.port.out_modified, stats.port.out_uft_miss",
            ]
        );
        match ext_ip {
            IpAddr::Ip4(ip) => {
                assert_eq!(pkt2.meta().inner_ip4().unwrap().src, ip);
            }
            IpAddr::Ip6(ip) => {
                assert_eq!(pkt2.meta().inner_ip6().unwrap().src, ip);
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
    pkt: &Packet<Parsed>,
    cfg: &VpcCfg,
    params: &IcmpSnatParams,
    dir: Direction,
    seq_no: u16,
    body_seg: usize,
) {
    let meta = pkt.meta();

    let (src_eth, dst_eth, src_ip, dst_ip, encapped, ident) = match dir {
        Direction::Out => (
            cfg.guest_mac,
            BS_MAC_ADDR,
            params.public_ip,
            params.partner_ip,
            true,
            params.snat_port,
        ),
        Direction::In => (
            cfg.gateway_mac,
            cfg.guest_mac,
            params.partner_ip,
            params.private_ip,
            false,
            params.icmp_id,
        ),
    };

    let eth = meta.inner.ether;
    assert_eq!(eth.src, src_eth);
    assert_eq!(eth.dst, dst_eth);

    match (dst_ip, meta.inner.ip.as_ref().unwrap()) {
        (IpAddr::Ip4(_), IpMeta::Ip4(meta)) => {
            assert_eq!(eth.ether_type, EtherType::Ipv4);
            assert_eq!(IpAddr::from(meta.src), src_ip);
            assert_eq!(IpAddr::from(meta.dst), dst_ip);
            assert_eq!(meta.proto, Protocol::ICMP);

            unpack_and_verify_icmp4(pkt, ident, seq_no, encapped, body_seg);
        }
        (IpAddr::Ip6(_), IpMeta::Ip6(meta)) => {
            assert_eq!(eth.ether_type, EtherType::Ipv6);
            assert_eq!(IpAddr::from(meta.src), src_ip);
            assert_eq!(IpAddr::from(meta.dst), dst_ip);
            assert_eq!(meta.proto, Protocol::ICMPv6);

            unpack_and_verify_icmp6(
                pkt, ident, seq_no, encapped, body_seg, meta.src, meta.dst,
            );
        }
        (IpAddr::Ip4(_), ip6) => {
            panic!("expected inner IPv4 metadata, got IPv6: {:?}", ip6)
        }
        (IpAddr::Ip6(_), ip4) => {
            panic!("expected inner IPv6 metadata, got IPv4: {:?}", ip4)
        }
    }
}

fn unpack_and_verify_icmp4(
    pkt: &Packet<Parsed>,
    expected_ident: u16,
    seq_no: u16,
    encapped: bool,
    body_seg: usize,
) {
    let icmp_offset = pkt.body_offset() - IcmpHdr::SIZE;
    let tgt_offset = IP4_SZ + if encapped { VPC_ENCAP_SZ } else { 0 };
    assert_eq!(icmp_offset, tgt_offset);
    assert_eq!(pkt.body_seg(), body_seg);

    // Because we treat ICMPv4 as a full-fledged ULP, we need to
    // unsplit the emitted header from the body.
    let pkt_bytes = pkt.all_bytes();
    let icmp = Icmpv4Packet::new_checked(&pkt_bytes[icmp_offset..]).unwrap();

    assert!(icmp.verify_checksum());
    assert_eq!(icmp.echo_ident(), expected_ident);
    assert_eq!(icmp.echo_seq_no(), seq_no);
}

fn unpack_and_verify_icmp6(
    pkt: &Packet<Parsed>,
    expected_ident: u16,
    seq_no: u16,
    encapped: bool,
    body_seg: usize,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
) {
    // Length is factored into pseudo header calc.
    // We know there are no ext headers.
    let pay_len = pkt.meta().inner_ip6().unwrap().pay_len as usize;

    let src_ip = smoltcp::wire::Ipv6Address::from(src_ip).into();
    let dst_ip = smoltcp::wire::Ipv6Address::from(dst_ip).into();

    let icmp_offset = pkt.body_offset() - IcmpHdr::SIZE;
    let tgt_offset = IP6_SZ + if encapped { VPC_ENCAP_SZ } else { 0 };
    assert_eq!(icmp_offset, tgt_offset);
    assert_eq!(pkt.body_seg(), body_seg);

    // Because we treat ICMPv6 as a full-fledged ULP, we need to
    // unsplit the emitted header from the body.
    let pkt_bytes = pkt.all_bytes();
    let icmp = Icmpv6Packet::new_checked(&pkt_bytes[icmp_offset..][..pay_len])
        .unwrap();

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
    let mut pkt1 = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        private_ip,
        dst_ip,
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

    unpack_and_verify_icmp(&pkt1, &g1_cfg, &params, Out, seq_no, 0);

    // ================================================================
    // Verify echo reply rewrite.
    // ================================================================
    let mut pkt2 = gen_icmp_echo_reply(
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
    pkt2 = encap_external(pkt2, bsvc_phys, g1_phys);

    let res = g1.port.process(In, &mut pkt2, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)), "bad result: {:?}", res);
    incr!(g1, ["uft.in", "stats.port.in_modified, stats.port.in_uft_miss"]);

    unpack_and_verify_icmp(&pkt2, &g1_cfg, &params, In, seq_no, 0);

    // ================================================================
    // Send ICMP Echo Req a second time. We want to verify that a) the
    // UFT entry is used and b) that it runs the attached header
    // transformation.
    // ================================================================
    seq_no += 1;
    let mut pkt3 = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        private_ip,
        dst_ip,
        ident,
        seq_no,
        &data[..],
        1,
    );

    assert_eq!(g1.port.stats_snap().out_uft_hit, 0);
    let res = g1.port.process(Out, &mut pkt3, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)), "bad result: {:?}", res);
    incr!(g1, ["stats.port.out_modified, stats.port.out_uft_hit"]);

    assert_eq!(g1.port.stats_snap().out_uft_hit, 1);
    unpack_and_verify_icmp(&pkt3, &g1_cfg, &params, Out, seq_no, 1);

    // ================================================================
    // Process ICMP Echo Reply a second time. Once again, this time we
    // want to verify that the body transformation comes from the UFT
    // entry.
    // ================================================================
    let mut pkt4 = gen_icmp_echo_reply(
        BS_MAC_ADDR,
        g1_cfg.guest_mac,
        dst_ip,
        public_ip,
        mapped_port,
        seq_no,
        &data[..],
        2,
    );

    assert_eq!(g1.port.stats_snap().in_uft_hit, 0);
    let res = g1.port.process(In, &mut pkt4, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)), "bad result: {:?}", res);
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);

    assert_eq!(g1.port.stats_snap().in_uft_hit, 1);
    unpack_and_verify_icmp(&pkt4, &g1_cfg, &params, In, seq_no, 0);

    // ================================================================
    // Insert a new packet along the same S/D pair: this should occupy
    // a new port and install a new rule for matching.
    // ================================================================
    let new_params =
        IcmpSnatParams { icmp_id: 8, snat_port: mapped_port - 1, ..params };

    let mut pkt5 = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        private_ip,
        dst_ip,
        new_params.icmp_id,
        seq_no,
        &data[..],
        2,
    );

    let res = g1.port.process(Out, &mut pkt5, ActionMeta::new());
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

    unpack_and_verify_icmp(&pkt5, &g1_cfg, &new_params, Out, seq_no, 0);
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
        Ipv4HdrError::BadTotalLen { total_len: 4 }.into()
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
    bytes.extend_from_slice(eth_hdr.as_bytes());
    bytes.extend_from_slice(ArpEthIpv4Raw::from(&arp).as_bytes());
    let mut pkt = Packet::copy(&bytes).parse(Out, VpcParser::new()).unwrap();

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
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
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
    assert_eq!(reply.body_offset(), IP6_SZ + IcmpHdr::SIZE);
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
    assert_eq!(reply.body_offset(), IP6_SZ + IcmpHdr::SIZE);
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

    let IpMeta::Ip6(ip6) = meta.inner.ip.as_ref().expect("No inner IP header")
    else {
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
    assert_eq!(reply.body_offset(), IP6_SZ + IcmpHdr::SIZE);
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

    let mut pkt = generate_neighbor_advertisement(&outbound_na, true);

    let res = g1.port.process(Out, &mut pkt, ActionMeta::new()).unwrap();
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
    let mut pkt = encap(pkt, g2_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt, ActionMeta::new()).unwrap();
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

fn write_dhcpv6_packet(
    eth: EtherMeta,
    ip: Ipv6Meta,
    udp: UdpMeta,
    msg: &dhcpv6::protocol::Message<'_>,
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

                let used_dhcp = base_dhcp_config();

                let domain_list = reply
                    .find_option(dhcpv6::options::Code::DomainList)
                    .expect("Expected a Domain Search List option");
                let dhcpv6::options::Option::DomainList(bytes) = domain_list
                else {
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
    pkt2 = encap_external(pkt2, bs_phys, g1_phys);
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
    pkt2 = encap_external(pkt2, bs_phys, g1_phys);
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
    pkt3 = encap_external(pkt3, bs_phys, g1_phys);
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

fn test_outbound_http(g1_cfg: &VpcCfg, g1: &mut PortAndVps) -> InnerFlowId {
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
    let flow = *pkt1.flow();
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
    pkt2 = encap_external(pkt2, bs_phys, g1_phys);
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
    pkt5 = encap_external(pkt5, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt5, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // HTTP 301 Reply: Server -> Client
    // ================================================================
    let mut pkt6 = http_301_reply2(
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
    pkt6 = encap_external(pkt6, bs_phys, g1_phys);
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
    pkt9 = encap_external(pkt9, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt9, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::FinWait2, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // FIN: Server -> Client
    // ================================================================
    let mut pkt10 = http_server_fin2(
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
    pkt10 = encap_external(pkt10, bs_phys, g1_phys);
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
            "stats.port.out_modified, stats.port.out_uft_miss",
            // We're hitting the old entry, before it is discarded.
            "stats.port.out_uft_hit",
        ]
    );
    assert_eq!(TcpState::SynSent, g1.port.tcp_state(&flow).unwrap());
    let snat_port = pkt1.meta().inner.ulp.unwrap().src_port().unwrap();

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
    let mut pkt2 = http_syn_ack2(
        BS_MAC_ADDR,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        snat_port,
    );
    pkt2 = encap_external(pkt2, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt2, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    let mut pkt1 = http_syn3(
        BS_MAC_ADDR,
        dst_ip,
        g1_cfg.guest_mac,
        g1_cfg.snat().external_ip,
        80,
        snat_port,
    );
    pkt1 = encap_external(pkt1, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt1, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    update!(
        g1,
        [
            "incr:stats.port.in_modified, stats.port.in_uft_hit",
            "set:uft.in=0, uft.out=0",
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
    let mut pkt11 = http_guest_ack_fin2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip2,
    );
    let flow = *pkt11.flow();
    let res = g1.port.process(Out, &mut pkt11, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
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
    let mut pkt1 = http_syn2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        GW_MAC_ADDR,
        dst_ip2,
    );
    let flow = *pkt1.flow();
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(
        g1,
        [
            "stats.port.out_modified, stats.port.out_uft_miss",
            // We're hitting the old entry, before it is discarded.
            "stats.port.out_uft_hit",
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
    let mut pkt1 = gen_icmpv4_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4().private_ip,
        client_ip,
        7777,
        1,
        data,
        1,
    );

    // Process the packet through our port. It should be allowed through:
    // we have a V2P mapping for the target guest, and a route for the other
    // subnet.
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
    assert!(matches!(res, Ok(ProcessResult::Modified)));

    incr!(
        g1,
        [
            "firewall.flows.in, firewall.flows.out",
            "stats.port.out_modified, stats.port.out_uft_miss, uft.out",
            "nat.flows.in, nat.flows.out",
        ]
    );

    assert_eq!(
        pkt1.meta().inner_ip4().unwrap().src,
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
    let mut pkt1 = http_syn2(BS_MAC_ADDR, client_ip, serv_mac, serv_ext_ip);
    let bs_phys = TestIpPhys {
        ip: BS_IP_ADDR,
        mac: BS_MAC_ADDR,
        vni: Vni::new(BOUNDARY_SERVICES_VNI).unwrap(),
    };
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
    let mut pkt3 = http_ack2(BS_MAC_ADDR, client_ip, serv_mac, serv_ext_ip);
    pkt3 = encap(pkt3, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt3, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // HTTP GET: Client -> Server
    // ================================================================
    let mut pkt4 = http_get2(BS_MAC_ADDR, client_ip, serv_mac, serv_ext_ip);
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
    let mut pkt7 = http_301_ack2(BS_MAC_ADDR, client_ip, serv_mac, serv_ext_ip);
    pkt7 = encap(pkt7, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt7, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["stats.port.in_modified, stats.port.in_uft_hit"]);
    assert_eq!(TcpState::Established, g1.port.tcp_state(&flow).unwrap());

    // ================================================================
    // FIN: Client -> Server
    // ================================================================
    let mut pkt8 =
        http_guest_fin2(BS_MAC_ADDR, client_ip, serv_mac, serv_ext_ip);
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
        http_guest_ack_fin2(BS_MAC_ADDR, client_ip, serv_mac, serv_ext_ip);
    pkt11 = encap(pkt11, bs_phys, g1_phys);
    let res = g1.port.process(In, &mut pkt11, ActionMeta::new());
    assert!(matches!(res, Ok(Modified)));
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
    let mut pkt1 = http_syn2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );

    // Process the packet through our port. We don't actually care about the
    // contents here, we just want to make sure that the packet can be _sent at
    // all_.
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
    assert!(res.is_ok());

    // Send another one, which should exhaust the TCP flow table limit we
    // severely truncated above. Note we need to send to a different IP address.
    // Let's use google.com.
    let dst_ip: Ipv4Addr = "142.251.46.238".parse().unwrap();
    let mut pkt2 = http_syn2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip,
        GW_MAC_ADDR,
        dst_ip,
    );
    let res2 = g1.port.process(Out, &mut pkt2, ActionMeta::new());
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
    let mut pkt1 = gen_icmpv4_echo_req(
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
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
    assert!(matches!(res, Ok(ProcessResult::Modified)));
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
    let mut pkt2 = gen_icmpv4_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4().private_ip,
        dst_ip,
        7777,
        1,
        data,
        1,
    );
    let res = g1.port.process(Out, &mut pkt2, ActionMeta::new());
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
    let mut pkt3 = gen_icmpv4_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4().private_ip,
        dst_ip,
        7777,
        1,
        data,
        1,
    );
    let res = g1.port.process(Out, &mut pkt3, ActionMeta::new());
    assert!(matches!(res, Ok(ProcessResult::Modified)));
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
    let mut pkt1 = gen_icmpv4_echo_req(
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
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new());
    assert!(matches!(res, Ok(ProcessResult::Modified)));
    incr!(
        g1,
        [
            "firewall.flows.in, firewall.flows.out",
            "stats.port.out_modified, stats.port.out_uft_miss, uft.out",
        ]
    );

    // Encap routes between sleds correctly, inner IPs are not modified,
    // and L2 dst matches the guest's NIC.
    let v6_encap_meta = pkt1.meta().outer.ip.as_ref().unwrap().ip6().unwrap();
    assert_eq!(v6_encap_meta.src, g1_cfg.phys_ip);
    assert_eq!(v6_encap_meta.dst, g2_cfg.phys_ip);
    assert_eq!(pkt1.meta().inner_ether().dst, g2_cfg.guest_mac);
    assert_eq!(pkt1.meta().inner_ether().src, g1_cfg.guest_mac);
    assert_eq!(pkt1.meta().inner_ip4().unwrap().src, g1_cfg.ipv4().private_ip);
    assert_eq!(pkt1.meta().inner_ip4().unwrap().dst, dst_ip);

    // Now deliver the packet to node g2.
    let res = g2.port.process(In, &mut pkt1, ActionMeta::new());
    incr!(
        g2,
        [
            "firewall.flows.in, firewall.flows.out",
            "stats.port.in_modified, stats.port.in_uft_miss, uft.in",
        ]
    );
    assert!(matches!(res, Ok(ProcessResult::Modified)));

    // A reply from that address must be allowed out by g2, and accepted
    // by g1.
    let mut pkt2 = gen_icmpv4_echo_reply(
        g2_cfg.guest_mac,
        g2_cfg.gateway_mac,
        dst_ip,
        g1_cfg.ipv4().private_ip,
        7777,
        1,
        data,
        1,
    );

    let res = g2.port.process(Out, &mut pkt2, ActionMeta::new());
    incr!(g2, ["stats.port.out_modified, stats.port.out_uft_miss, uft.out",]);
    assert!(matches!(res, Ok(ProcessResult::Modified)));

    let res = g1.port.process(In, &mut pkt2, ActionMeta::new());
    assert!(matches!(res, Ok(ProcessResult::Modified)));
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

    // let ip_cfg = IpCfg::Ipv4(
    //     Ipv4Cfg {
    //         vpc_subnet: "172.30.0.0/22".parse().unwrap(),
    //         private_ip: "172.30.0.5".parse().unwrap(),
    //         gateway_ip: "172.30.0.1".parse().unwrap(),
    //         external_ips: ExternalIpCfg {
    //             snat: Some(SNat4Cfg {
    //                 external_ip: "10.77.77.13".parse().unwrap(),
    //                 ports: 1025..=4096,
    //             }),
    //             ephemeral_ip: Some("192.168.0.1".parse().unwrap()),
    //             floating_ips: vec![
    //                 "192.168.0.2".parse().unwrap(),
    //                 "192.168.0.3".parse().unwrap(),
    //                 "192.168.0.4".parse().unwrap(),
    //             ],
    //         },
    //     });

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
    let mut pkt1 = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip.into(),
        "77.77.77.77".parse().unwrap(),
        ident,
        seq_no,
        &data[..],
        1,
    );
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new()).unwrap();
    assert!(matches!(res, ProcessResult::Modified));
    assert_eq!(
        pkt1.meta().inner_ip4().unwrap().src,
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
    let mut pkt1 = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip.into(),
        "1.1.1.1".parse().unwrap(),
        ident,
        seq_no,
        &data[..],
        1,
    );
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new()).unwrap();
    assert!(matches!(res, ProcessResult::Modified));
    assert!(&g1_cfg.ipv4().external_ips.floating_ips[..2]
        .contains(&pkt1.meta().inner_ip4().unwrap().src));
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
    let mut pkt1 = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip.into(),
        "2.2.2.1".parse().unwrap(),
        ident,
        seq_no,
        &data[..],
        1,
    );
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new()).unwrap();
    assert!(matches!(res, ProcessResult::Modified));
    assert_eq!(
        pkt1.meta().inner_ip4().unwrap().src,
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
    let mut pkt1 = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip.into(),
        "3.3.3.1".parse().unwrap(),
        ident,
        seq_no,
        &data[..],
        1,
    );
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new()).unwrap();
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
    let mut pkt1 = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip.into(),
        "4.4.4.1".parse().unwrap(),
        ident,
        seq_no,
        &data[..],
        1,
    );
    let res = g1.port.process(Out, &mut pkt1, ActionMeta::new()).unwrap();
    assert!(matches!(res, ProcessResult::Modified));
    assert!(&g1_cfg.ipv4().external_ips.floating_ips[..]
        .contains(&pkt1.meta().inner_ip4().unwrap().src));
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

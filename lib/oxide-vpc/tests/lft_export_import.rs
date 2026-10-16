// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Tests for exporting the layer flow tables (LFTs) of one port and importing
//! them into another, as done during live migration.
//!
//! Each test sets up a "source" port and establishes flows through it, then
//! pauses it and exports its LFTs. A "destination" port is created with the
//! same configuration, and the exported state is imported into it while it is
//! still `Ready`. The destination is then started, and we check that the flows
//! established on the source continue to work: replies from the remote side
//! are accepted and un-NAT'd, and the guest's packets keep the same external
//! IP and port.

use common::icmp::gen_icmp_echo_reply;
use common::icmp::gen_icmp_echo_req;
use common::*;
use opte::api::Direction;
use opte::engine::export::PortImportError;
use opte::engine::export::PortLftExport;
use opte::engine::ip::v4::Ipv4Ref;
use opte::engine::ip::v6::Ipv6Ref;
use opte::engine::packet::MblkFullParsed;
use opte::engine::port::PortState;
use opte_test_utils as common;
use smoltcp::wire::Icmpv4Packet;
use smoltcp::wire::Icmpv6Packet;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

const ICMP_DATA: &[u8] = b"migrate\0";

#[derive(Clone, Copy, Debug, PartialEq)]
enum Proto {
    Tcp,
    Udp,
    IcmpEcho,
}

/// A flow between the guest and a remote partner, from the guest's view.
#[derive(Clone, Copy, Debug)]
struct Flow {
    proto: Proto,
    private_ip: IpAddr,
    /// TCP / UDP source port, or the ICMP echo identifier.
    private_port: u16,
    partner_ip: IpAddr,
    /// TCP / UDP destination port. Unused for ICMP.
    partner_port: u16,
}

/// A flow, along with the external address it was NAT'd through on the source
/// port.
#[derive(Clone, Copy, Debug)]
struct MappedFlow {
    flow: Flow,
    external_ip: IpAddr,
    /// External port, or the external ICMP echo identifier.
    external_port: u16,
}

/// The physical host information for a port, from its full config.
fn host_phys_ip(cfg: &VpcCfg) -> TestIpPhys {
    TestIpPhys { ip: cfg.phys_ip, mac: cfg.guest_mac, vni: cfg.vni }
}

/// Create a port with default routes to the internet.
///
/// The port is returned in the `Ready` state.
fn new_port(name: &str, cfg: &VpcCfg, v6: bool) -> PortAndVps {
    let pav = oxide_net_setup(name, cfg, None, None);
    router::add_entry(
        &pav.port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway(None),
        RouterClass::System,
    )
    .unwrap();
    if v6 {
        router::add_entry(
            &pav.port,
            IpCidr::Ip6("::/0".parse().unwrap()),
            RouterTarget::InternetGateway(None),
            RouterClass::System,
        )
        .unwrap();
    }
    pav
}

/// Simulate a migration from `src` to `dst`.
///
/// Pause `src`, export its LFTs, round-trip them through a serialization
/// format, import them into `dst` while it is `Ready`, and start `dst`.
fn migrate(src: &PortAndVps, dst: &PortAndVps) {
    src.port.pause().expect("failed to pause source port");

    let export =
        src.port.export_lfts().expect("failed to export LFTs from source");
    assert!(
        !export.layers.is_empty(),
        "expected the source port to export some LFT state"
    );

    // TODO-completeness: Figure out a serialization format, versioning, schema,
    // etc.
    //
    // For now, just round-trip it through _some_ serialization format, to test
    // moving this between ports on different hosts.
    let serialized = ron::to_string(&export).unwrap();
    let export: PortLftExport = ron::from_str(&serialized).unwrap();

    assert!(matches!(dst.port.state(), PortState::Ready));
    dst.port.import_lfts(export).expect("failed to import LFTs");
    dst.port.start();
}

/// Construct an L4 packet from src to dst.
fn build_l4_packet<U: Emit + EmitDoesNotRelyOnBufContents>(
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: IpAddr,
    ip_dst: IpAddr,
    proto: IngotIpProto,
    ulp: U,
    ulp_len: usize,
) -> MsgBlk {
    let (ethertype, ip) = match (ip_src, ip_dst) {
        (IpAddr::Ip4(source), IpAddr::Ip4(destination)) => (
            Ethertype::IPV4,
            L3Repr::Ipv4(Ipv4 {
                total_len: (Ipv4::MINIMUM_LENGTH + ulp_len) as u16,
                hop_limit: 64,
                protocol: proto,
                source,
                destination,
                ..Default::default()
            }),
        ),
        (IpAddr::Ip6(source), IpAddr::Ip6(destination)) => (
            Ethertype::IPV6,
            L3Repr::Ipv6(Ipv6 {
                payload_len: ulp_len as u16,
                next_header: proto,
                hop_limit: 64,
                source,
                destination,
                ..Default::default()
            }),
        ),
        _ => panic!("source and destination must be the same IP version"),
    };
    let eth = Ethernet { destination: eth_dst, source: eth_src, ethertype };
    ulp_pkt(eth, ip, ulp, &[])
}

/// Build a packet for `flow`, in either direction.
///
/// For a guest packet (direction is out), uses the flow's private IP
/// address. For packets from the partner, use the `external_ip` and
/// `external_port` as the destination. NAT should ... translate them.
fn packet_for_flow(
    cfg: &VpcCfg,
    flow: &Flow,
    direction: Direction,
    external_ip: IpAddr,
    external_port: u16,
    tcp_flags: IngotTcpFlags,
    seq: u16,
) -> MsgBlk {
    // Layer 2 addresses, based on direction.
    let (eth_src, eth_dst) = if matches!(direction, Direction::Out) {
        (cfg.guest_mac, cfg.gateway_mac)
    } else {
        (BS_MAC_ADDR, cfg.guest_mac)
    };

    // Layer 3 addresses, based on direction.
    let (ip_src, sport, ip_dst, dport) = if matches!(direction, Direction::Out)
    {
        (flow.private_ip, flow.private_port, flow.partner_ip, flow.partner_port)
    } else {
        (flow.partner_ip, flow.partner_port, external_ip, external_port)
    };

    // Construct the actual L4 packet for the protocol.
    let pkt = match flow.proto {
        Proto::Tcp => {
            let tcp = Tcp {
                source: sport,
                destination: dport,
                sequence: 1000 + u32::from(seq),
                acknowledgement: 2000 + u32::from(seq),
                flags: tcp_flags,
                window_size: 64240,
                ..Default::default()
            };
            let len = tcp.packet_length();
            build_l4_packet(
                eth_src,
                eth_dst,
                ip_src,
                ip_dst,
                IngotIpProto::TCP,
                tcp,
                len,
            )
        }
        Proto::Udp => {
            let udp = Udp {
                source: sport,
                destination: dport,
                length: Udp::MINIMUM_LENGTH as u16,
                ..Default::default()
            };
            build_l4_packet(
                eth_src,
                eth_dst,
                ip_src,
                ip_dst,
                IngotIpProto::UDP,
                udp,
                Udp::MINIMUM_LENGTH,
            )
        }
        Proto::IcmpEcho if matches!(direction, Direction::Out) => {
            gen_icmp_echo_req(
                eth_src,
                eth_dst,
                ip_src,
                ip_dst,
                flow.private_port,
                seq,
                ICMP_DATA,
                1,
            )
        }
        Proto::IcmpEcho => gen_icmp_echo_reply(
            eth_src,
            eth_dst,
            ip_src,
            ip_dst,
            external_port,
            seq,
            ICMP_DATA,
            1,
        ),
    };

    // Encapsulate outbound packets.
    if matches!(direction, Direction::Out) {
        pkt
    } else {
        encap_external(pkt, *BSVC_PHYS, host_phys_ip(cfg))
    }
}

/// Return the echo identifier out of an ICMP packet.
fn echo_ident(pkt: &Packet<MblkFullParsed>, ip: IpAddr) -> u16 {
    let mut icmp = pkt.meta().inner_icmp().expect("An ICMP packet").emit_vec();
    pkt.meta().append_remaining(&mut icmp);
    match ip {
        IpAddr::Ip4(_) => {
            Icmpv4Packet::new_checked(&icmp[..]).unwrap().echo_ident()
        }
        IpAddr::Ip6(_) => {
            Icmpv6Packet::new_checked(&icmp[..]).unwrap().echo_ident()
        }
    }
}

/// Return the inner source address and port (or echo identifier) of an outbound
/// processed packet.
fn outbound_source(pkt: &mut MsgBlk, proto: Proto) -> (IpAddr, u16) {
    let parsed = parse_inbound(pkt, VpcParser {}).unwrap().to_full_meta();
    let meta = parsed.meta();
    let ip = match (meta.inner_ip4(), meta.inner_ip6()) {
        (Some(ip4), _) => IpAddr::Ip4(ip4.source()),
        (_, Some(ip6)) => IpAddr::Ip6(ip6.source()),
        _ => panic!("expected an inner IP header"),
    };
    let port = match proto {
        Proto::Tcp | Proto::Udp => {
            meta.inner_ulp().unwrap().src_port().unwrap()
        }
        Proto::IcmpEcho => echo_ident(&parsed, ip),
    };
    (ip, port)
}

/// Return the inner destination address and port (or echo identifier) of an
/// inbound processed packet.
fn inbound_destination(pkt: &mut MsgBlk, proto: Proto) -> (IpAddr, u16) {
    let parsed = parse_outbound(pkt, VpcParser {}).unwrap().to_full_meta();
    let meta = parsed.meta();
    let ip = match (meta.inner_ip4(), meta.inner_ip6()) {
        (Some(ip4), _) => IpAddr::Ip4(ip4.destination()),
        (_, Some(ip6)) => IpAddr::Ip6(ip6.destination()),
        _ => panic!("expected an inner IP header"),
    };
    let port = match proto {
        Proto::Tcp | Proto::Udp => {
            meta.inner_ulp().unwrap().dst_port().unwrap()
        }
        Proto::IcmpEcho => echo_ident(&parsed, ip),
    };
    (ip, port)
}

/// Send a packet from the guest on `flow`, and return the external address
/// and port it was translated to.
fn send_from_guest(
    pav: &PortAndVps,
    cfg: &VpcCfg,
    flow: &Flow,
    tcp_flags: IngotTcpFlags,
    seq: u16,
) -> (IpAddr, u16) {
    // The external addresses are unused for the guest's packets.
    let mut pkt_m = packet_for_flow(
        cfg,
        flow,
        Direction::Out,
        flow.private_ip,
        0,
        tcp_flags,
        seq,
    );
    let pkt = parse_outbound(&mut pkt_m, VpcParser {}).unwrap();
    let res = pav.port.process(Out, pkt);
    assert!(
        matches!(res, Ok(Modified(_))),
        "guest packet for {flow:?} was not modified: {res:?}"
    );
    expect_modified!(res, pkt_m);
    outbound_source(&mut pkt_m, flow.proto)
}

/// Send a packet from the partner on `mapped`, addressed to the port's external
/// address. Return the private address and port it was delivered to, or `None`
/// if the port dropped the packet.
fn send_from_partner(
    pav: &PortAndVps,
    cfg: &VpcCfg,
    mapped: &MappedFlow,
    tcp_flags: IngotTcpFlags,
    seq: u16,
) -> Option<(IpAddr, u16)> {
    let mut pkt_m = packet_for_flow(
        cfg,
        &mapped.flow,
        Direction::In,
        mapped.external_ip,
        mapped.external_port,
        tcp_flags,
        seq,
    );
    let pkt = parse_inbound(&mut pkt_m, VpcParser {}).unwrap();
    let res = pav.port.process(In, pkt);
    if matches!(res, Ok(ProcessResult::Drop { .. })) {
        return None;
    }
    expect_modified!(res, pkt_m);
    Some(inbound_destination(&mut pkt_m, mapped.flow.proto))
}

/// Construct some flows from the guest using the cfg's SNAT pools.
///
/// This builds several TCP flows to be sure we use more than the first SNAT
/// port the pools hand out. We have to be sure we're reclaiming things
/// correctly on the destination port.
///
/// Also builds flows for each supported protocol.
fn build_guest_snat_flows(cfg: &VpcCfg) -> Vec<Flow> {
    let private4 = IpAddr::Ip4(cfg.ipv4().private_ip);
    let private6 = IpAddr::Ip6(cfg.ipv6().private_ip);
    let web4: IpAddr = "52.10.128.69".parse().unwrap();
    let web6: IpAddr = "2606:4700:4700::1111".parse().unwrap();
    let dns4: IpAddr = "8.8.8.8".parse().unwrap();
    let ping4: IpAddr = "45.55.45.205".parse().unwrap();
    let tcp4 = |port| Flow {
        proto: Proto::Tcp,
        private_ip: private4,
        private_port: port,
        partner_ip: web4,
        partner_port: 80,
    };
    vec![
        tcp4(40001),
        tcp4(40002),
        tcp4(40003),
        Flow {
            proto: Proto::Tcp,
            private_ip: private6,
            private_port: 40010,
            partner_ip: web6,
            partner_port: 443,
        },
        Flow {
            proto: Proto::Udp,
            private_ip: private4,
            private_port: 40020,
            partner_ip: dns4,
            partner_port: 53,
        },
        Flow {
            proto: Proto::IcmpEcho,
            private_ip: private4,
            private_port: 7,
            partner_ip: ping4,
            partner_port: 0,
        },
    ]
}

/// Start an SNAT flow from the guest on each `flow`, and return the mapped IP /
/// port it uses after translation.
fn start_snat_flows(
    pav: &PortAndVps,
    cfg: &VpcCfg,
    flows: &[Flow],
) -> Vec<MappedFlow> {
    flows
        .iter()
        .map(|flow| {
            let (external_ip, external_port) =
                send_from_guest(pav, cfg, flow, IngotTcpFlags::SYN, 0);
            let (snat_ip, snat_ports) = match flow.private_ip {
                IpAddr::Ip4(_) => (
                    IpAddr::Ip4(cfg.snat().external_ip),
                    cfg.snat().ports.clone(),
                ),
                IpAddr::Ip6(_) => (
                    IpAddr::Ip6(cfg.snat6().external_ip),
                    cfg.snat6().ports.clone(),
                ),
            };
            assert_eq!(external_ip, snat_ip, "flow {flow:?} was not SNAT'd");
            assert!(
                snat_ports.contains(&external_port),
                "flow {flow:?} got SNAT port {external_port} outside \
                {snat_ports:?}",
            );
            MappedFlow { flow: *flow, external_ip, external_port }
        })
        .collect()
}

#[test]
fn lft_import_preserves_snat_flows() {
    // Create the source port, and construct a bunch of outbound flows from the
    // guest. This builds the actual flow, and the external IP addresses that
    // the flows are translated to.
    let cfg = g1_cfg();
    let src = new_port("src", &cfg, true);
    src.port.start();
    let mapped = start_snat_flows(&src, &cfg, &build_guest_snat_flows(&cfg));

    // Migrate the port to the new destination.
    let dst = new_port("dst", &cfg, true);
    migrate(&src, &dst);

    // Assert that each mapped flow "still works".
    for m in &mapped {
        // Send a packet from the partner. This tests that:
        //
        // - The new port's firewall doesn't drop the packet, i.e., we carried
        //   over the entry in the stateful firewall.
        // - The new port reclaimed the same IPs and ports, since the partner
        //   still uses them.
        // - The port itself still NATs the IPs to the correct internal ones.
        let delivered = send_from_partner(
            &dst,
            &cfg,
            m,
            IngotTcpFlags::SYN | IngotTcpFlags::ACK,
            0,
        );
        assert_eq!(
            delivered,
            Some((m.flow.private_ip, m.flow.private_port)),
            "reply for {m:?} was not delivered to the guest",
        );

        // Now send a packet back from the guest. This tests that we're keeping
        // the affinity between flows and external addresses. If we used a
        // different external address, the partner would likely drop / RST the
        // connection since it's unknown, from it's point of view.
        let translated =
            send_from_guest(&dst, &cfg, &m.flow, IngotTcpFlags::ACK, 1);
        assert_eq!(
            translated,
            (m.external_ip, m.external_port),
            "guest packet for {m:?} was translated differently after import",
        );
    }

    // Create a new flow from the guest, and check that we don't reuse any of
    // the imported port numbers.
    let imported: BTreeSet<u16> = mapped
        .iter()
        .filter(|m| {
            m.flow.proto == Proto::Tcp
                && matches!(m.flow.private_ip, IpAddr::Ip4(_))
        })
        .map(|m| m.external_port)
        .collect();
    assert_eq!(imported.len(), 3, "IPv4 TCP flows should use distinct ports");
    let private_port = imported.last().unwrap() + 1;
    let new_flow = Flow { private_port, ..mapped[0].flow };
    let (_, new_port) =
        send_from_guest(&dst, &cfg, &new_flow, IngotTcpFlags::SYN, 0);
    assert!(
        !imported.contains(&new_port),
        "new flow was given port {new_port}, which was imported for an \
        existing flow",
    );
}

#[test]
fn snat_replies_dropped_without_lft_import() {
    // Construct a source port, but _don't_ migrate it.
    let cfg = g1_cfg();
    let src = new_port("src", &cfg, true);
    src.port.start();
    let mapped = start_snat_flows(&src, &cfg, &build_guest_snat_flows(&cfg));
    src.port.pause().unwrap();

    let dst = new_port("dst", &cfg, true);
    dst.port.start();

    // Now, assert that every inbound packet from the partner is dropped, since
    // we haven't imported any stateful firewall entries.
    for m in &mapped {
        let delivered = send_from_partner(
            &dst,
            &cfg,
            m,
            IngotTcpFlags::SYN | IngotTcpFlags::ACK,
            0,
        );
        assert_eq!(
            delivered, None,
            "reply for {m:?} was accepted without any imported state",
        );
    }
}

/// Allow inbound TCP connections from anyone, as the firewall denies inbound
/// traffic by default.
fn allow_inbound_tcp(pav: &PortAndVps) {
    let rule = "dir=in action=allow priority=10 protocol=TCP";
    firewall::add_fw_rule(
        &pav.port,
        &AddFwRuleReq {
            port_name: pav.port.name().to_string(),
            rule: rule.parse().unwrap(),
        },
    )
    .unwrap();
}

/// Construct a VPC config with the provided external IPs.
fn floating_ip_cfg(floating_ips: &[Ipv4Addr]) -> VpcCfg {
    g1_cfg2(IpCfg::DualStack {
        ipv4: Ipv4Cfg {
            vpc_subnet: "172.30.0.0/22".parse().unwrap(),
            private_ip: "172.30.0.5".parse().unwrap(),
            gateway_ip: "172.30.0.1".parse().unwrap(),
            external_ips: ExternalIpCfg {
                snat: Some(SNat4Cfg {
                    external_ip: EXT_IP4.parse().unwrap(),
                    ports: 1025..=4096,
                }),
                ephemeral_ip: None,
                floating_ips: floating_ips.to_vec(),
            },
            attached_subnets: BTreeMap::new(),
            transit_ips: BTreeMap::new(),
        },
        ipv6: Ipv6Cfg {
            vpc_subnet: "fd00::/64".parse().unwrap(),
            private_ip: "fd00::5".parse().unwrap(),
            gateway_ip: "fd00::1".parse().unwrap(),
            external_ips: ExternalIpCfg {
                snat: Some(SNat6Cfg {
                    external_ip: "2001:db8::1".parse().unwrap(),
                    ports: 4097..=8192,
                }),
                ephemeral_ip: None,
                floating_ips: vec![],
            },
            attached_subnets: BTreeMap::new(),
            transit_ips: BTreeMap::new(),
        },
    })
}

#[test]
fn lft_import_preserves_floating_ip_affinity() {
    // Build a port with several external IPs.
    let floating_ips: Vec<Ipv4Addr> =
        (1..=4).map(|i| format!("10.60.1.{i}").parse().unwrap()).collect();
    let cfg = floating_ip_cfg(&floating_ips);
    let private_ip = IpAddr::Ip4(cfg.ipv4().private_ip);
    let partner_ip: IpAddr = "93.184.216.34".parse().unwrap();

    let src = new_port("src", &cfg, false);
    allow_inbound_tcp(&src);
    src.port.start();

    // Map each external IP to a different flow, so we can assert preservation
    // of the affinity between them.
    let mapped: Vec<MappedFlow> = floating_ips
        .iter()
        .enumerate()
        .map(|(i, fip)| {
            let mapped = MappedFlow {
                flow: Flow {
                    proto: Proto::Tcp,
                    private_ip,
                    private_port: 80,
                    partner_ip,
                    partner_port: 44490 + i as u16,
                },
                external_ip: IpAddr::Ip4(*fip),
                external_port: 80,
            };

            // Send a packet from the partner to this external IP.
            let delivered =
                send_from_partner(&src, &cfg, &mapped, IngotTcpFlags::SYN, 0);
            assert_eq!(delivered, Some((private_ip, 80)));

            // And have the guest also reply from the external IP.
            let translated = send_from_guest(
                &src,
                &cfg,
                &mapped.flow,
                IngotTcpFlags::SYN | IngotTcpFlags::ACK,
                0,
            );
            assert_eq!(translated, (mapped.external_ip, 80));
            mapped
        })
        .collect();

    // Now migrate the port.
    let dst = new_port("dst", &cfg, false);
    allow_inbound_tcp(&dst);
    migrate(&src, &dst);

    for m in &mapped {
        // Send a new packet from the guest, and assert that it is translated to
        // the same external IP as it was on the _source_ port.
        let translated =
            send_from_guest(&dst, &cfg, &m.flow, IngotTcpFlags::ACK, 1);
        assert_eq!(
            translated,
            (m.external_ip, 80),
            "guest packet for {m:?} left from a different external IP after \
            import",
        );

        // And that the inbound packet back from the partner is also mapped the
        // same way.
        let delivered = send_from_partner(&dst, &cfg, m, IngotTcpFlags::ACK, 1);
        assert_eq!(delivered, Some((private_ip, 80)));
    }
}

#[test]
fn lft_export_import_require_port_state() {
    let cfg = g1_cfg();
    let src = new_port("src", &cfg, true);
    src.port.start();
    start_snat_flows(&src, &cfg, &build_guest_snat_flows(&cfg));

    assert!(
        src.port.export_lfts().is_err(),
        "should not be able to export LFTs from a running port"
    );
    src.port.pause().unwrap();
    let export = src.port.export_lfts().unwrap();

    // A running destination port must be rejected.
    let dst = new_port("dst", &cfg, true);
    dst.port.start();
    assert!(matches!(
        dst.port.import_lfts(export.clone()),
        Err(PortImportError::BadState(_))
    ));

    // As must a paused one.
    dst.port.pause().unwrap();
    assert!(matches!(
        dst.port.import_lfts(export),
        Err(PortImportError::BadState(_))
    ));
}

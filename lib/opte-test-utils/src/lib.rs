// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Common routines for integration tests.

// This type of pedantry is more trouble than it's worth here.
#![allow(dead_code)]

pub mod dhcp;
pub mod icmp;
pub mod pcap;
#[macro_use]
pub mod port_state;

// Let's make our lives easier and pub use a bunch of stuff.
pub use opte::api::Direction::*;
pub use opte::api::MacAddr;
pub use opte::ddi::mblk::MsgBlk;
pub use opte::ddi::mblk::MsgBlkIterMut;
pub use opte::engine::GenericUlp;
pub use opte::engine::NetworkParser;
pub use opte::engine::ether::EtherMeta;
pub use opte::engine::ether::EtherType;
pub use opte::engine::ether::Ethernet;
pub use opte::engine::geneve::GENEVE_OPT_CLASS_OXIDE;
pub use opte::engine::geneve::GENEVE_PORT;
pub use opte::engine::geneve::GeneveMeta;
pub use opte::engine::geneve::GeneveOption;
pub use opte::engine::geneve::OxideOption;
pub use opte::engine::geneve::Vni;
pub use opte::engine::headers::IpAddr;
pub use opte::engine::headers::IpCidr;
pub use opte::engine::ip::L3Repr;
pub use opte::engine::ip::v4::Ipv4;
pub use opte::engine::ip::v4::Ipv4Addr;
pub use opte::engine::ip::v4::Protocol;
pub use opte::engine::ip::v6::Ipv6;
pub use opte::engine::ip::v6::Ipv6Addr;
pub use opte::engine::layer::DenyReason;
pub use opte::engine::packet::LiteInPkt;
pub use opte::engine::packet::LiteOutPkt;
pub use opte::engine::packet::MblkLiteParsed;
pub use opte::engine::packet::Packet;
pub use opte::engine::packet::ParseError;
pub use opte::engine::port::DropReason;
pub use opte::engine::port::Port;
pub use opte::engine::port::PortBuilder;
pub use opte::engine::port::ProcessResult;
pub use opte::engine::port::ProcessResult::*;
pub use opte::engine::port::meta::ActionMeta;
pub use opte::ingot::ethernet::Ethertype;
pub use opte::ingot::geneve::Geneve;
pub use opte::ingot::geneve::GeneveOpt;
pub use opte::ingot::geneve::GeneveOptionType;
pub use opte::ingot::ip::IpProtocol as IngotIpProto;
pub use opte::ingot::tcp::Tcp;
pub use opte::ingot::tcp::TcpFlags as IngotTcpFlags;
pub use opte::ingot::types::Emit;
pub use opte::ingot::types::EmitDoesNotRelyOnBufContents;
pub use opte::ingot::types::HeaderLen;
pub use opte::ingot::udp::Udp;
pub use opte::provider::Providers;
pub use oxide_vpc::api::AddFwRuleReq;
pub use oxide_vpc::api::BOUNDARY_SERVICES_VNI;
pub use oxide_vpc::api::DhcpCfg;
pub use oxide_vpc::api::ExternalIpCfg;
pub use oxide_vpc::api::GW_MAC_ADDR;
pub use oxide_vpc::api::IpCfg;
pub use oxide_vpc::api::Ipv4Cfg;
pub use oxide_vpc::api::Ipv6Cfg;
pub use oxide_vpc::api::PhysNet;
pub use oxide_vpc::api::RouterClass;
pub use oxide_vpc::api::RouterTarget;
pub use oxide_vpc::api::SNat4Cfg;
pub use oxide_vpc::api::SNat6Cfg;
pub use oxide_vpc::api::SetFwRulesReq;
pub use oxide_vpc::api::TunnelEndpoint;
pub use oxide_vpc::api::VpcCfg;
pub use oxide_vpc::engine::VpcNetwork;
pub use oxide_vpc::engine::VpcParser;
pub use oxide_vpc::engine::firewall;
pub use oxide_vpc::engine::gateway;
pub use oxide_vpc::engine::nat;
pub use oxide_vpc::engine::overlay;
pub use oxide_vpc::engine::overlay::TUNNEL_ENDPOINT_MAC;
pub use oxide_vpc::engine::overlay::Virt2Boundary;
pub use oxide_vpc::engine::overlay::Virt2Phys;
pub use oxide_vpc::engine::overlay::VpcMappings;
pub use oxide_vpc::engine::router;
pub use port_state::*;
pub use smoltcp::wire::IpProtocol;
pub use std::num::NonZeroU32;
pub use std::sync::Arc;

/// Expects that a packet result is modified, and applies that modification.
#[macro_export]
macro_rules! expect_modified {
    ($res:ident, $pkt:ident) => {
        assert!(
            matches!($res, Ok(Modified(_))),
            "expected Modified, got {:?}",
            $res
        );
        #[allow(unused_assignments)]
        if let Ok(Modified(spec)) = $res {
            $pkt = spec.apply($pkt);
        }
    };
}

pub fn parse_inbound<NP: NetworkParser>(
    pkt: &mut MsgBlk,
    parser: NP,
) -> Result<LiteInPkt<MsgBlkIterMut<'_>, NP>, ParseError> {
    Packet::parse_inbound(pkt.iter_mut(), parser)
}

pub fn parse_outbound<NP: NetworkParser>(
    pkt: &mut MsgBlk,
    parser: NP,
) -> Result<LiteOutPkt<MsgBlkIterMut<'_>, NP>, ParseError> {
    Packet::parse_outbound(pkt.iter_mut(), parser)
}

// It's imperative that this list stays in sync with the layers that
// makeup the VPC implementation. We verify this in the `check_layers`
// test.
pub const VPC_LAYERS: [&str; 5] =
    ["gateway", "firewall", "router", "nat", "overlay"];

pub const BS_MAC_ADDR: MacAddr = MacAddr::from_const(TUNNEL_ENDPOINT_MAC);

pub const BS_IP_ADDR: Ipv6Addr =
    Ipv6Addr::from_const([0xfd00, 0x99, 0, 0, 0, 0, 0, 1]);

const UFT_LIMIT: Option<NonZeroU32> = NonZeroU32::new(16);
const TCP_LIMIT: Option<NonZeroU32> = NonZeroU32::new(16);

pub const EXT_IP4: &str = "10.77.77.13";
pub const EXT_IP6: &str = "fd00:100::1";

pub fn ox_vpc_mac(id: [u8; 3]) -> MacAddr {
    MacAddr::from([0xA8, 0x40, 0x25, 0xF0 | id[0], id[1], id[2]])
}

pub fn base_dhcp_config() -> DhcpCfg {
    DhcpCfg {
        hostname: "testbox".parse().ok(),
        host_domain: "test.oxide.computer".parse().ok(),
        domain_search_list: vec!["oxide.computer".parse().unwrap()],
        dns4_servers: vec![
            Ipv4Addr::from([8, 8, 8, 8]),
            Ipv4Addr::from([1, 1, 1, 1]),
        ],
        dns6_servers: vec![
            Ipv6Addr::from_const([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888]),
            Ipv6Addr::from_const([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844]),
            Ipv6Addr::from_const([0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111]),
            Ipv6Addr::from_const([0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001]),
        ],
    }
}

pub fn g1_cfg() -> VpcCfg {
    let ip_cfg = IpCfg::DualStack {
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
                    ports: 4097..=8192,
                }),
                ephemeral_ip: None,
                floating_ips: vec![],
            },
        },
    };
    g1_cfg2(ip_cfg)
}

pub fn g1_cfg2(ip_cfg: IpCfg) -> VpcCfg {
    VpcCfg {
        ip_cfg,
        guest_mac: ox_vpc_mac([0xFA, 0xFA, 0x37]),
        gateway_mac: MacAddr::from([0xA8, 0x40, 0x25, 0xFF, 0x77, 0x77]),
        vni: Vni::new(1287581u32).unwrap(),
        // Site 0xF7, Rack 1, Sled 1, Interface 1
        phys_ip: Ipv6Addr::from([
            0xFD00, 0x0000, 0x00F7, 0x0101, 0x0000, 0x0000, 0x0000, 0x0001,
        ]),
    }
}

pub fn g2_cfg() -> VpcCfg {
    let ip_cfg = IpCfg::DualStack {
        ipv4: Ipv4Cfg {
            vpc_subnet: "172.30.0.0/22".parse().unwrap(),
            private_ip: "172.30.0.6".parse().unwrap(),
            gateway_ip: "172.30.0.1".parse().unwrap(),
            external_ips: ExternalIpCfg {
                snat: Some(SNat4Cfg {
                    external_ip: "10.77.77.23".parse().unwrap(),
                    ports: 4097..=8192,
                }),
                ephemeral_ip: None,
                floating_ips: vec![],
            },
        },
        ipv6: Ipv6Cfg {
            vpc_subnet: "fd00::/64".parse().unwrap(),
            private_ip: "fd00::6".parse().unwrap(),
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
    VpcCfg {
        ip_cfg,
        guest_mac: ox_vpc_mac([0xF0, 0x00, 0x66]),
        gateway_mac: MacAddr::from([0xA8, 0x40, 0x25, 0xFF, 0x77, 0x77]),
        vni: Vni::new(1287581u32).unwrap(),
        // Site 0xF7, Rack 1, Sled 22, Interface 1
        phys_ip: Ipv6Addr::from([
            0xFD00, 0x0000, 0x00F7, 0x0116, 0x0000, 0x0000, 0x0000, 0x0001,
        ]),
    }
}

fn oxide_net_builder(
    name: &str,
    cfg: &oxide_vpc::cfg::VpcCfg,
    vpc_map: Arc<VpcMappings>,
    v2p: Arc<Virt2Phys>,
    v2b: Arc<Virt2Boundary>,
) -> PortBuilder {
    #[allow(clippy::arc_with_non_send_sync)]
    let ectx =
        Arc::new(Providers { log: Box::new(opte::provider::PrintlnLog) });
    let name_cstr = std::ffi::CString::new(name).unwrap();
    let mut pb = PortBuilder::new(name, name_cstr, cfg.guest_mac, ectx);

    let fw_limit = NonZeroU32::new(8096).unwrap();
    let snat_limit = NonZeroU32::new(8096).unwrap();
    let one_limit = NonZeroU32::new(1).unwrap();

    let dhcp = base_dhcp_config();

    firewall::setup(&mut pb, fw_limit).expect("failed to add firewall layer");
    gateway::setup(&mut pb, cfg, vpc_map, fw_limit, &dhcp)
        .expect("failed to setup gateway layer");
    router::setup(&mut pb, cfg, one_limit).expect("failed to add router layer");
    nat::setup(&mut pb, cfg, snat_limit).expect("failed to add nat layer");
    overlay::setup(&mut pb, cfg, v2p, v2b, one_limit)
        .expect("failed to add overlay layer");
    pb
}

pub struct PortAndVps {
    pub port: Port<VpcNetwork>,
    pub vps: VpcPortState,
    pub vpc_map: Arc<VpcMappings>,
    pub cfg: oxide_vpc::cfg::VpcCfg,
}

pub fn oxide_net_setup(
    name: &str,
    cfg: &VpcCfg,
    vpc_map: Option<Arc<VpcMappings>>,
    flow_table_limits: Option<NonZeroU32>,
) -> PortAndVps {
    oxide_net_setup2(name, cfg, vpc_map, flow_table_limits, None)
}

pub fn oxide_net_setup2(
    name: &str,
    cfg: &VpcCfg,
    vpc_map: Option<Arc<VpcMappings>>,
    flow_table_limits: Option<NonZeroU32>,
    custom_updates: Option<&[&str]>,
) -> PortAndVps {
    // We have to setup the global VPC mapping state just like xde
    // would do. Ideally, xde would not concern itself with any
    // VPC-specific concerns. Ideally, xde would be a generic driver
    // for interfacing with one of more OPTE virtual switches. Inside
    // each OPTE virtual switch would be a given type of
    // implementation, like the oxide-vpc implementation. This
    // implementation would have a way to register itself with the
    // virtual switch, somewhat like how a mac-provider registers
    // itself with the mac framework. This mechanism would also
    // provide some way for the implementation to provide
    // switch-global state, and this is where oxide-vpc could place
    // the VPC mappings (so that they can be shared across all ports).
    //
    // However, for the time being, this oxide-vpc global state is
    // hard-coded directly in xde, and therefore we need to mimic that
    // here in the integration test.
    //
    // The interface for `oxide_net_setup()` is arguably a bit odd and
    // looks different from how xde works. Instead of requiring every
    // test to manually allocate a VpcMapping and passing it to this
    // setup function, we allow the test to pass `None` and have this
    // function create a new VpcMapping value on our behalf. If the
    // test involves more than one port, you can pass the existing
    // VpcMaping as argument making sure that each port sees each
    // other in the V2P state.
    let vpc_map = vpc_map.unwrap_or_default();

    let phys_net =
        PhysNet { ether: cfg.guest_mac, ip: cfg.phys_ip, vni: cfg.vni };
    let port_v2p = match &cfg.ip_cfg {
        IpCfg::Ipv4(ipv4) => {
            vpc_map.add(IpAddr::Ip4(ipv4.private_ip), phys_net)
        }
        IpCfg::Ipv6(ipv6) => {
            vpc_map.add(IpAddr::Ip6(ipv6.private_ip), phys_net)
        }
        IpCfg::DualStack { ipv4, ipv6 } => {
            vpc_map.add(IpAddr::Ip4(ipv4.private_ip), phys_net);
            vpc_map.add(IpAddr::Ip6(ipv6.private_ip), phys_net)
        }
    };

    let converted_cfg: oxide_vpc::cfg::VpcCfg = cfg.clone().into();
    let vpc_net = VpcNetwork { cfg: converted_cfg.clone() };
    let uft_limit = flow_table_limits.unwrap_or(UFT_LIMIT.unwrap());
    let tcp_limit = flow_table_limits.unwrap_or(TCP_LIMIT.unwrap());
    let v2b = Arc::new(Virt2Boundary::new());
    v2b.set(
        "0.0.0.0/0".parse().unwrap(),
        vec![TunnelEndpoint {
            ip: "fd00:9900::1".parse().unwrap(),
            vni: Vni::new(BOUNDARY_SERVICES_VNI).unwrap(),
        }],
    );
    v2b.set(
        "::/0".parse().unwrap(),
        vec![TunnelEndpoint {
            ip: "fd00:9900::1".parse().unwrap(),
            vni: Vni::new(BOUNDARY_SERVICES_VNI).unwrap(),
        }],
    );

    let port =
        oxide_net_builder(name, &converted_cfg, vpc_map.clone(), port_v2p, v2b)
            .create(vpc_net, uft_limit, tcp_limit)
            .unwrap();

    // Add router entry that allows the guest to send to other guests
    // on same subnet.
    router::add_entry(
        &port,
        IpCidr::Ip4(cfg.ipv4().vpc_subnet),
        RouterTarget::VpcSubnet(IpCidr::Ip4(cfg.ipv4().vpc_subnet)),
        RouterClass::System,
    )
    .unwrap();

    let vps = VpcPortState::new();
    let mut pav = PortAndVps { port, vps, vpc_map, cfg: converted_cfg };

    let mut updates = vec![
        // * Epoch starts at 1, adding router entry bumps it to 2.
        "set:epoch=2",
        // * Allow inbound IPv6 traffic for guest.
        // * Allow inbound IPv4 traffic for guest.
        // * Deny inbound NDP for guest.
        "set:gateway.rules.in=3",
        // IPv4
        // ----
        //
        // * ARP Gateway MAC addr
        // * ICMP Echo Reply for Gateway
        // * DHCP Offer
        // * DHCP Ack
        // * Outbound traffic from Guest IP + MAC address
        //
        // IPv6
        // ----
        //
        // * NDP NA for Gateway
        // * NDP RA for Gateway
        // * Deny all other NDP
        // * ICMPv6 Echo Reply for Gateway from Guest Link-Local
        // * ICMPv6 Echo Reply for Gateway from Guest VPC ULA
        // * DHCPv6
        // * Outbound traffic from Guest IPv6 + MAC Address
        "set:gateway.rules.out=12",
        // * Allow all outbound traffic
        "set:firewall.rules.out=0",
        // * Outbound IPv4 SNAT
        // * Outbound IPv6 SNAT
        // * Drop uncaught InetGw packets.
        "set:nat.rules.out=3",
    ];

    [
        cfg.ipv4().external_ips.ephemeral_ip.is_some(),
        !cfg.ipv4().external_ips.floating_ips.is_empty(),
        cfg.ipv6().external_ips.ephemeral_ip.is_some(),
        !cfg.ipv6().external_ips.floating_ips.is_empty(),
    ]
    .into_iter()
    .for_each(|c| {
        if c {
            updates.push("incr:nat.rules.in, nat.rules.out")
        }
    });

    updates.extend_from_slice(&[
        // * Allow guest to route to own subnet
        "set:router.rules.out=1",
        // * Outbound encap
        // * Inbound decap
        "set:overlay.rules.in=1, overlay.rules.out=1",
    ]);

    if let Some(val) = custom_updates {
        updates.extend_from_slice(val);
    }

    update!(pav, updates);
    set_default_fw_rules(&mut pav, cfg);
    pav
}

// Set the default firewall rules as described in RFD 63 §2.8.1. The
// implied rules are handled by the default actions of the firewall
// layer. The inbound RDP rule has since been removed from the
// defaults (we need to update the RFD to reflect this).
fn set_default_fw_rules(pav: &mut PortAndVps, cfg: &VpcCfg) {
    let ssh_in = "dir=in action=allow priority=65534 protocol=TCP port=22";
    let icmp_in = "dir=in action=allow priority=65534 protocol=ICMP";
    let vpc_in =
        format!("dir=in action=allow priority=65534 hosts=vni={}", cfg.vni,);
    firewall::set_fw_rules(
        &pav.port,
        &SetFwRulesReq {
            port_name: pav.port.name().to_string(),
            rules: vec![
                vpc_in.parse().unwrap(),
                ssh_in.parse().unwrap(),
                icmp_in.parse().unwrap(),
            ],
        },
    )
    .unwrap();
    update!(pav, ["set:epoch=3", "set:firewall.rules.in=3"]);
}

pub fn ulp_pkt<
    I: Emit + EmitDoesNotRelyOnBufContents,
    U: Emit + EmitDoesNotRelyOnBufContents,
>(
    eth: Ethernet,
    ip: I,
    ulp: U,
    body: &[u8],
) -> MsgBlk {
    let mut pkt = MsgBlk::new_ethernet_pkt((eth, ip, ulp, body));

    let view = Packet::parse_outbound(pkt.iter_mut(), GenericUlp {}).unwrap();
    let mut view = view.to_full_meta();
    view.compute_checksums();
    drop(view);

    // Note: we don't need to create and act on an EmitSpec here
    // because we haven't meaningfully transformed the packet.
    // (processed, introduced new layers, altered options/EHs)

    pkt
}

// Generate a packet representing the start of a TCP handshake for a
// telnet session from src to dst.
pub fn tcp_telnet_syn(src: &VpcCfg, dst: &VpcCfg) -> MsgBlk {
    let body: &[u8] = &[];
    let tcp = Tcp {
        source: 7865,
        destination: 23,
        flags: IngotTcpFlags::SYN,
        sequence: 4224936861,
        acknowledgement: 0,
        ..Default::default()
    };
    let ip4 = Ipv4 {
        source: src.ipv4_cfg().unwrap().private_ip,
        destination: dst.ipv4_cfg().unwrap().private_ip,
        protocol: IngotIpProto::TCP,
        total_len: (Ipv4::MINIMUM_LENGTH + tcp.packet_length() + body.len())
            as u16,
        ..Default::default()
    };
    let eth = Ethernet {
        destination: src.gateway_mac,
        source: src.guest_mac,
        ethertype: Ethertype::IPV4,
    };
    ulp_pkt(eth, ip4, tcp, &[])
}

pub const HTTP_SYN_OPTS_LEN: usize = 20;

// Generate a packet representing the start of a TCP handshake for an
// HTTP request from src to dst.
pub fn http_syn(src: &VpcCfg, dst: &VpcCfg) -> MsgBlk {
    http_syn2(
        src.guest_mac,
        src.ipv4_cfg().unwrap().private_ip,
        dst.guest_mac,
        dst.ipv4_cfg().unwrap().private_ip,
    )
}

// Generate a packet representing the start of a TCP handshake for an
// HTTP request from src to dst.
pub fn http_syn2(
    eth_src: MacAddr,
    ip_src: impl Into<IpAddr>,
    eth_dst: MacAddr,
    ip_dst: impl Into<IpAddr>,
) -> MsgBlk {
    http_syn3(eth_src, ip_src, eth_dst, ip_dst, 44490, 80)
}

pub fn http_syn3(
    eth_src: MacAddr,
    ip_src: impl Into<IpAddr>,
    eth_dst: MacAddr,
    ip_dst: impl Into<IpAddr>,
    sport: u16,
    dport: u16,
) -> MsgBlk {
    let body = vec![];
    #[rustfmt::skip]
    let options = vec![
        // MSS
        0x02, 0x04, 0x05, 0xb4,
        // SACK
        0x04, 0x02,
        // Timestamps
        0x08, 0x0a, 0x09, 0xb4, 0x2a, 0xa9, 0x00, 0x00, 0x00, 0x00,
        // NOP
        0x01,
        // Window Scale
        0x03, 0x03, 0x01,
    ];

    let tcp = Tcp {
        source: sport,
        destination: dport,
        sequence: 2382112979,
        acknowledgement: 0,
        flags: IngotTcpFlags::SYN,
        window_size: 64240,
        options,
        ..Default::default()
    };

    let (ethertype, ip) = match (ip_src.into(), ip_dst.into()) {
        (IpAddr::Ip4(source), IpAddr::Ip4(destination)) => (
            Ethertype::IPV4,
            L3Repr::Ipv4(Ipv4 {
                total_len: (Ipv4::MINIMUM_LENGTH
                    + tcp.packet_length()
                    + body.len()) as u16,
                identification: 2662,
                hop_limit: 64,
                protocol: IngotIpProto::TCP,
                source,
                destination,
                ..Default::default()
            }),
        ),
        (IpAddr::Ip6(source), IpAddr::Ip6(destination)) => (
            Ethertype::IPV6,
            L3Repr::Ipv6(Ipv6 {
                payload_len: (tcp.packet_length() + body.len()) as u16,
                next_header: IngotIpProto::TCP,
                hop_limit: 64,
                source,
                destination,
                ..Default::default()
            }),
        ),
        _ => panic!("source and destination must be the same IP version"),
    };
    // Any packet from the guest is always addressed to the gateway.
    let eth = Ethernet { destination: eth_dst, source: eth_src, ethertype };
    ulp_pkt(eth, ip, tcp, &body)
}

// Generate a packet representing the SYN+ACK reply to `http_tcp_syn()`,
// from g1 to g2.
pub fn http_syn_ack(src: &VpcCfg, dst: &VpcCfg) -> MsgBlk {
    http_syn_ack2(
        src.guest_mac,
        src.ipv4().private_ip,
        GW_MAC_ADDR,
        dst.ipv4().private_ip,
        // This function assumes guest-to-guest, and thus no SNATing
        // of port.
        44490,
    )
}

pub fn http_syn_ack2(
    eth_src: MacAddr,
    ip_src: impl Into<IpAddr>,
    eth_dst: MacAddr,
    ip_dst: impl Into<IpAddr>,
    dport: u16,
) -> MsgBlk {
    let body = vec![];
    let tcp = Tcp {
        source: 80,
        destination: dport,
        sequence: 44161351,
        acknowledgement: 2382112980,
        flags: IngotTcpFlags::SYN | IngotTcpFlags::ACK,
        ..Default::default()
    };
    let (ethertype, ip) = match (ip_src.into(), ip_dst.into()) {
        (IpAddr::Ip4(source), IpAddr::Ip4(destination)) => (
            Ethertype::IPV4,
            L3Repr::Ipv4(Ipv4 {
                total_len: (Ipv4::MINIMUM_LENGTH
                    + tcp.packet_length()
                    + body.len()) as u16,
                identification: 2662,
                hop_limit: 64,
                protocol: IngotIpProto::TCP,
                source,
                destination,
                ..Default::default()
            }),
        ),
        (IpAddr::Ip6(source), IpAddr::Ip6(destination)) => (
            Ethertype::IPV6,
            L3Repr::Ipv6(Ipv6 {
                payload_len: (tcp.packet_length() + body.len()) as u16,
                next_header: IngotIpProto::TCP,
                hop_limit: 64,
                source,
                destination,
                ..Default::default()
            }),
        ),
        _ => panic!("source and destination must be the same IP version"),
    };

    let eth = Ethernet { destination: eth_dst, source: eth_src, ethertype };
    ulp_pkt(eth, ip, tcp, &body)
}

pub fn http_ack2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
) -> MsgBlk {
    let body = vec![];
    let tcp = Tcp {
        source: 44490,
        destination: 80,
        sequence: 2382112980,
        acknowledgement: 44161352,
        flags: IngotTcpFlags::ACK,
        ..Default::default()
    };
    let ip4 = Ipv4 {
        total_len: (Ipv4::MINIMUM_LENGTH + tcp.packet_length() + body.len())
            as u16,
        protocol: IngotIpProto::TCP,
        source: ip_src,
        destination: ip_dst,
        ..Default::default()
    };
    let eth = Ethernet {
        destination: eth_dst,
        source: eth_src,
        ethertype: Ethertype::IPV4,
    };
    ulp_pkt(eth, ip4, tcp, &body)
}

pub fn http_get2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
) -> MsgBlk {
    // The details of the HTTP body are irrelevant to our testing. You
    // only need know it's 18 characters for the purposes of seq/ack.
    let body = b"GET / HTTP/1.1\r\n\r\n";
    let tcp = Tcp {
        source: 44490,
        destination: 80,
        sequence: 2382112980,
        acknowledgement: 44161352,
        flags: IngotTcpFlags::PSH | IngotTcpFlags::ACK,
        ..Default::default()
    };
    let ip4 = Ipv4 {
        total_len: (Ipv4::MINIMUM_LENGTH + tcp.packet_length() + body.len())
            as u16,
        protocol: IngotIpProto::TCP,
        source: ip_src,
        destination: ip_dst,
        ..Default::default()
    };
    let eth = Ethernet {
        destination: eth_dst,
        source: eth_src,
        ethertype: Ethertype::IPV4,
    };
    ulp_pkt(eth, ip4, tcp, body)
}

pub fn http_get_ack2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
    dst_port: u16,
) -> MsgBlk {
    let body = vec![];
    let tcp = Tcp {
        source: 80,
        destination: dst_port,
        sequence: 44161353,
        acknowledgement: 2382112998,
        flags: IngotTcpFlags::ACK,
        ..Default::default()
    };
    let ip4 = Ipv4 {
        total_len: (Ipv4::MINIMUM_LENGTH + tcp.packet_length() + body.len())
            as u16,
        protocol: IngotIpProto::TCP,
        source: ip_src,
        destination: ip_dst,
        ..Default::default()
    };
    let eth = Ethernet {
        destination: eth_dst,
        source: eth_src,
        ethertype: Ethertype::IPV4,
    };
    ulp_pkt(eth, ip4, tcp, &body)
}

pub fn http_301_reply2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
    dst_port: u16,
) -> MsgBlk {
    // The details of the HTTP body are irrelevant to our testing. You
    // only need know it's 34 characters for the purposes of seq/ack.
    let body = "HTTP/1.1 301 Moved Permanently\r\n\r\n".as_bytes();
    let tcp = Tcp {
        source: 80,
        destination: dst_port,
        sequence: 44161353,
        acknowledgement: 2382112998,
        flags: IngotTcpFlags::PSH | IngotTcpFlags::ACK,
        ..Default::default()
    };
    let ip4 = Ipv4 {
        total_len: (Ipv4::MINIMUM_LENGTH + tcp.packet_length() + body.len())
            as u16,
        protocol: IngotIpProto::TCP,
        source: ip_src,
        destination: ip_dst,
        ..Default::default()
    };
    let eth = Ethernet {
        destination: eth_dst,
        source: eth_src,
        ethertype: Ethertype::IPV4,
    };
    ulp_pkt(eth, ip4, tcp, body)
}

pub fn http_301_ack2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
) -> MsgBlk {
    let body = vec![];
    let tcp = Tcp {
        source: 44490,
        destination: 80,
        sequence: 2382112998,
        acknowledgement: 44161353 + 34,
        flags: IngotTcpFlags::ACK,
        ..Default::default()
    };
    let ip4 = Ipv4 {
        total_len: (Ipv4::MINIMUM_LENGTH + tcp.packet_length() + body.len())
            as u16,
        protocol: IngotIpProto::TCP,
        source: ip_src,
        destination: ip_dst,
        ..Default::default()
    };
    let eth = Ethernet {
        destination: eth_dst,
        source: eth_src,
        ethertype: Ethertype::IPV4,
    };
    ulp_pkt(eth, ip4, tcp, &body)
}

pub fn http_guest_fin2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
) -> MsgBlk {
    let body = vec![];
    let tcp = Tcp {
        source: 44490,
        destination: 80,
        sequence: 2382112998,
        acknowledgement: 44161353 + 34,
        flags: IngotTcpFlags::ACK | IngotTcpFlags::FIN,
        ..Default::default()
    };
    let ip4 = Ipv4 {
        total_len: (Ipv4::MINIMUM_LENGTH + tcp.packet_length() + body.len())
            as u16,
        protocol: IngotIpProto::TCP,
        source: ip_src,
        destination: ip_dst,
        ..Default::default()
    };
    let eth = Ethernet {
        destination: eth_dst,
        source: eth_src,
        ethertype: Ethertype::IPV4,
    };
    ulp_pkt(eth, ip4, tcp, &body)
}

pub fn http_server_ack_fin2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
    dst_port: u16,
) -> MsgBlk {
    let body = vec![];
    let tcp = Tcp {
        source: 80,
        destination: dst_port,
        sequence: 44161353 + 34,
        // We are ACKing the FIN, which counts as 1 byte.
        acknowledgement: 2382112998 + 1,
        flags: IngotTcpFlags::ACK,
        ..Default::default()
    };
    let ip4 = Ipv4 {
        total_len: (Ipv4::MINIMUM_LENGTH + tcp.packet_length() + body.len())
            as u16,
        protocol: IngotIpProto::TCP,
        source: ip_src,
        destination: ip_dst,
        ..Default::default()
    };
    let eth = Ethernet {
        destination: eth_dst,
        source: eth_src,
        ethertype: Ethertype::IPV4,
    };
    ulp_pkt(eth, ip4, tcp, &body)
}

pub fn http_server_fin2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
    dst_port: u16,
) -> MsgBlk {
    let body = vec![];
    let tcp = Tcp {
        source: 80,
        destination: dst_port,
        sequence: 44161353 + 34,
        acknowledgement: 2382112998 + 1,
        flags: IngotTcpFlags::ACK | IngotTcpFlags::FIN,
        ..Default::default()
    };
    let ip4 = Ipv4 {
        total_len: (Ipv4::MINIMUM_LENGTH + tcp.packet_length() + body.len())
            as u16,
        protocol: IngotIpProto::TCP,
        source: ip_src,
        destination: ip_dst,
        ..Default::default()
    };
    let eth = Ethernet {
        destination: eth_dst,
        source: eth_src,
        ethertype: Ethertype::IPV4,
    };
    ulp_pkt(eth, ip4, tcp, &body)
}

pub fn http_guest_ack_fin2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
) -> MsgBlk {
    let body = vec![];
    let tcp = Tcp {
        source: 44490,
        destination: 80,
        sequence: 2382112998,
        // We are ACKing the FIN, which counts as 1 byte.
        acknowledgement: 44161353 + 34 + 1,
        flags: IngotTcpFlags::ACK,
        ..Default::default()
    };
    let ip4 = Ipv4 {
        total_len: (Ipv4::MINIMUM_LENGTH + tcp.packet_length() + body.len())
            as u16,
        protocol: IngotIpProto::TCP,
        source: ip_src,
        destination: ip_dst,
        ..Default::default()
    };
    let eth = Ethernet {
        destination: eth_dst,
        source: eth_src,
        ethertype: Ethertype::IPV4,
    };
    ulp_pkt(eth, ip4, tcp, &body)
}

/// A more conveinent way to pass along physical network information
/// inside the tests.
#[derive(Clone, Copy, Debug)]
pub struct TestIpPhys {
    pub ip: Ipv6Addr,
    pub mac: MacAddr,
    pub vni: Vni,
}

/// Encapsulate a guest packet, marking that it has arrived from beyond
/// the rack.
#[must_use]
pub fn encap_external(
    inner_pkt: MsgBlk,
    src: TestIpPhys,
    dst: TestIpPhys,
) -> MsgBlk {
    _encap(inner_pkt, src, dst, true)
}

/// Encapsulate a guest packet.
#[must_use]
pub fn encap(inner_pkt: MsgBlk, src: TestIpPhys, dst: TestIpPhys) -> MsgBlk {
    _encap(inner_pkt, src, dst, false)
}

/// Encapsulate a guest packet.
#[must_use]
fn _encap(
    inner_pkt: MsgBlk,
    src: TestIpPhys,
    dst: TestIpPhys,
    external_snat: bool,
) -> MsgBlk {
    let base_len = inner_pkt.byte_len();

    let mut outer_geneve = Geneve { vni: dst.vni, ..Default::default() };

    if external_snat {
        let external_tag = GeneveOpt {
            class: GENEVE_OPT_CLASS_OXIDE,
            option_type: GeneveOptionType(OxideOption::External.opt_type()),
            ..Default::default()
        };

        outer_geneve.opt_len += (external_tag.packet_length() >> 2) as u8;
        outer_geneve.options.push(external_tag);
    }

    let outer_udp = Udp {
        source: 99,
        destination: GENEVE_PORT,
        length: (base_len + Udp::MINIMUM_LENGTH + outer_geneve.packet_length())
            as u16,
        ..Default::default()
    };

    let outer_ip = Ipv6 {
        source: src.ip,
        destination: dst.ip,
        next_header: IngotIpProto::UDP,
        payload_len: outer_udp.length,
        ..Default::default()
    };

    let outer_eth = Ethernet {
        destination: dst.mac,
        source: src.mac,
        ethertype: Ethertype::IPV6,
    };

    let mut encap_pkt = MsgBlk::new_ethernet_pkt(&(
        outer_eth,
        outer_ip,
        outer_udp,
        outer_geneve,
    ));
    encap_pkt.append(inner_pkt);

    encap_pkt
}

/// Like `assert!`, except you also pass in the `PortAndVps` so that
/// the port state is printed on failure.
#[macro_export]
macro_rules! chk {
    ($pav:expr, $check:expr) => {
        if !$check {
            print_port(&$pav.port, &$pav.vpc_map).unwrap();
            panic!("assertion failed: {}", stringify!($check));
        }
    };
}

#[macro_export]
macro_rules! assert_drop {
    ($res:expr, $expected:expr) => {
        match &$res {
            Ok(ProcessResult::Drop { reason }) => match (reason, &$expected) {
                (
                    DropReason::Layer { name: res_name, reason: res_reason },
                    DropReason::Layer { name: exp_name, reason: exp_reason },
                ) => {
                    assert_eq!(res_name, exp_name);
                    assert_eq!(res_reason, exp_reason);
                }

                (DropReason::TcpErr, DropReason::TcpErr) => (),

                (_, _) => {
                    panic!(
                        "expected drop type: {:?}, but got: {:?}",
                        $expected, $res,
                    );
                }
            },

            _ => panic!("execpted drop, but got: {:?}", $res),
        }
    };
}

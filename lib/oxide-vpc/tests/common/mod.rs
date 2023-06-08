// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Common routines for integration tests.

// This type of pedantry is more trouble than its worth here.
#![allow(dead_code)]

pub mod icmp;
pub mod pcap;
#[macro_use]
pub mod port_state;

// Let's make our lives easier and pub use a bunch of stuff.
pub use opte::api::Direction::*;
pub use opte::api::MacAddr;
pub use opte::engine::checksum::HeaderChecksum;
pub use opte::engine::ether::EtherHdr;
pub use opte::engine::ether::EtherMeta;
pub use opte::engine::ether::EtherType;
pub use opte::engine::geneve::GeneveHdr;
pub use opte::engine::geneve::GeneveMeta;
pub use opte::engine::geneve::Vni;
pub use opte::engine::geneve::GENEVE_PORT;
pub use opte::engine::headers::IpAddr;
pub use opte::engine::headers::IpCidr;
pub use opte::engine::headers::IpHdr;
pub use opte::engine::headers::IpMeta;
pub use opte::engine::headers::UlpHdr;
pub use opte::engine::headers::UlpMeta;
pub use opte::engine::ip4::Ipv4Addr;
pub use opte::engine::ip4::Ipv4Hdr;
pub use opte::engine::ip4::Ipv4Meta;
pub use opte::engine::ip4::Protocol;
pub use opte::engine::ip4::UlpCsumOpt;
pub use opte::engine::ip6::Ipv6Addr;
pub use opte::engine::ip6::Ipv6Hdr;
pub use opte::engine::ip6::Ipv6Meta;
pub use opte::engine::layer::DenyReason;
pub use opte::engine::packet::BodyInfo;
pub use opte::engine::packet::HdrOffset;
pub use opte::engine::packet::Initialized;
pub use opte::engine::packet::Packet;
pub use opte::engine::packet::PacketSeg;
pub use opte::engine::packet::Parsed;
pub use opte::engine::port::meta::ActionMeta;
pub use opte::engine::port::DropReason;
pub use opte::engine::port::Port;
pub use opte::engine::port::PortBuilder;
pub use opte::engine::port::ProcessResult;
pub use opte::engine::port::ProcessResult::*;
pub use opte::engine::tcp::TcpFlags;
pub use opte::engine::tcp::TcpHdr;
pub use opte::engine::tcp::TcpMeta;
pub use opte::engine::udp::UdpHdr;
pub use opte::engine::udp::UdpMeta;
pub use opte::engine::GenericUlp;
pub use opte::ExecCtx;
pub use oxide_vpc::api::AddFwRuleReq;
pub use oxide_vpc::api::BoundaryServices;
pub use oxide_vpc::api::IpCfg;
pub use oxide_vpc::api::Ipv4Cfg;
pub use oxide_vpc::api::Ipv6Cfg;
pub use oxide_vpc::api::PhysNet;
pub use oxide_vpc::api::RouterTarget;
pub use oxide_vpc::api::SNat4Cfg;
pub use oxide_vpc::api::SNat6Cfg;
pub use oxide_vpc::api::SetFwRulesReq;
pub use oxide_vpc::api::VpcCfg;
pub use oxide_vpc::engine::firewall;
pub use oxide_vpc::engine::gateway;
pub use oxide_vpc::engine::nat;
pub use oxide_vpc::engine::overlay;
pub use oxide_vpc::engine::overlay::Virt2Phys;
pub use oxide_vpc::engine::overlay::VpcMappings;
pub use oxide_vpc::engine::router;
pub use oxide_vpc::engine::VpcNetwork;
pub use oxide_vpc::engine::VpcParser;
pub use pcap::*;
pub use port_state::*;
pub use smoltcp::wire::IpProtocol;
pub use std::num::NonZeroU32;
pub use std::sync::Arc;

// It's imperative that this list stays in sync with the layers that
// makeup the VPC implementation. We verify this in the `check_layers`
// test.
pub const VPC_LAYERS: [&str; 5] =
    ["gateway", "firewall", "router", "nat", "overlay"];

// This is the MAC address that OPTE uses to act as the virtual gateway.
pub const GW_MAC_ADDR: MacAddr =
    MacAddr::from_const([0xA8, 0x40, 0x25, 0xFF, 0x77, 0x77]);

const UFT_LIMIT: Option<NonZeroU32> = NonZeroU32::new(16);
const TCP_LIMIT: Option<NonZeroU32> = NonZeroU32::new(16);

pub fn ox_vpc_mac(id: [u8; 3]) -> MacAddr {
    MacAddr::from([0xA8, 0x40, 0x25, 0xF0 | id[0], id[1], id[2]])
}

pub fn g1_cfg() -> VpcCfg {
    let ip_cfg = IpCfg::DualStack {
        ipv4: Ipv4Cfg {
            vpc_subnet: "172.30.0.0/22".parse().unwrap(),
            private_ip: "172.30.0.5".parse().unwrap(),
            gateway_ip: "172.30.0.1".parse().unwrap(),
            snat: Some(SNat4Cfg {
                external_ip: "10.77.77.13".parse().unwrap(),
                ports: 1025..=4096,
            }),
            external_ips: None,
        },
        ipv6: Ipv6Cfg {
            vpc_subnet: "fd00::/64".parse().unwrap(),
            private_ip: "fd00::5".parse().unwrap(),
            gateway_ip: "fd00::1".parse().unwrap(),
            snat: Some(SNat6Cfg {
                external_ip: "2001:db8::1".parse().unwrap(),
                ports: 4097..=8192,
            }),
            external_ips: None,
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
        boundary_services: BoundaryServices {
            mac: MacAddr::from([0xA8, 0x40, 0x25, 0x77, 0x77, 0x77]),
            ip: Ipv6Addr::from([
                0xFD, 0x00, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ]),
            vni: Vni::new(99u32).unwrap(),
        },
        domain_list: vec!["oxide.computer".parse().unwrap()],
    }
}

pub fn g2_cfg() -> VpcCfg {
    let ip_cfg = IpCfg::DualStack {
        ipv4: Ipv4Cfg {
            vpc_subnet: "172.30.0.0/22".parse().unwrap(),
            private_ip: "172.30.0.6".parse().unwrap(),
            gateway_ip: "172.30.0.1".parse().unwrap(),
            snat: Some(SNat4Cfg {
                external_ip: "10.77.77.23".parse().unwrap(),
                ports: 4097..=8192,
            }),
            external_ips: None,
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
    VpcCfg {
        ip_cfg,
        guest_mac: ox_vpc_mac([0xF0, 0x00, 0x66]),
        gateway_mac: MacAddr::from([0xA8, 0x40, 0x25, 0xFF, 0x77, 0x77]),
        vni: Vni::new(1287581u32).unwrap(),
        // Site 0xF7, Rack 1, Sled 22, Interface 1
        phys_ip: Ipv6Addr::from([
            0xFD00, 0x0000, 0x00F7, 0x0116, 0x0000, 0x0000, 0x0000, 0x0001,
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
    }
}

fn oxide_net_builder(
    name: &str,
    cfg: &VpcCfg,
    vpc_map: Arc<VpcMappings>,
    v2p: Arc<Virt2Phys>,
) -> PortBuilder {
    let ectx = Arc::new(ExecCtx { log: Box::new(opte::PrintlnLog {}) });
    let name_cstr = std::ffi::CString::new(name).unwrap();
    let mut pb =
        PortBuilder::new(name, name_cstr, cfg.guest_mac.into(), ectx.clone());

    let fw_limit = NonZeroU32::new(8096).unwrap();
    let snat_limit = NonZeroU32::new(8096).unwrap();
    let one_limit = NonZeroU32::new(1).unwrap();

    firewall::setup(&mut pb, fw_limit).expect("failed to add firewall layer");
    gateway::setup(&mut pb, cfg, vpc_map, fw_limit)
        .expect("failed to setup gateway layer");
    router::setup(&mut pb, cfg, one_limit).expect("failed to add router layer");
    nat::setup(&mut pb, cfg, snat_limit).expect("failed to add nat layer");
    overlay::setup(&mut pb, cfg, v2p, one_limit)
        .expect("failed to add overlay layer");
    pb
}

pub struct PortAndVps {
    pub port: Port<VpcNetwork>,
    pub vps: VpcPortState,
    pub vpc_map: Arc<VpcMappings>,
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
    let vpc_map = if vpc_map.is_none() {
        Arc::new(VpcMappings::new())
    } else {
        vpc_map.unwrap()
    };

    let phys_net =
        PhysNet { ether: cfg.guest_mac, ip: cfg.phys_ip, vni: cfg.vni };
    let port_v2p = match &cfg.ip_cfg {
        IpCfg::Ipv4(ipv4) => {
            vpc_map.add(IpAddr::Ip4(ipv4.private_ip), phys_net)
        }
        IpCfg::Ipv6(ipv6) => {
            vpc_map.add(IpAddr::Ip6(ipv6.private_ip), phys_net)
        }
        IpCfg::DualStack { ref ipv4, ref ipv6 } => {
            vpc_map.add(IpAddr::Ip4(ipv4.private_ip), phys_net);
            vpc_map.add(IpAddr::Ip6(ipv6.private_ip), phys_net)
        }
    };

    let vpc_net = VpcNetwork { cfg: cfg.clone() };
    let uft_limit = flow_table_limits.unwrap_or(UFT_LIMIT.unwrap());
    let tcp_limit = flow_table_limits.unwrap_or(TCP_LIMIT.unwrap());
    let port = oxide_net_builder(name, cfg, vpc_map.clone(), port_v2p)
        .create(vpc_net, uft_limit, tcp_limit)
        .unwrap();

    // Add router entry that allows the guest to send to other guests
    // on same subnet.
    router::add_entry(
        &port,
        IpCidr::Ip4(cfg.ipv4().vpc_subnet),
        RouterTarget::VpcSubnet(IpCidr::Ip4(cfg.ipv4().vpc_subnet)),
    )
    .unwrap();

    let vps = VpcPortState::new();
    let mut pav = PortAndVps { port, vps, vpc_map };

    let nat_rules = match cfg.ipv4().external_ips {
        Some(_) => "incr:nat.rules.in, nat.rules.out",
        _ => "",
    };

    let mut updates = vec![
        // * Epoch starts at 1, adding router entry bumps it to 2.
        "set:epoch=2",
        // * Allow inbound IPv6 traffic for guest.
        // * Allow inbound IPv4 traffic for guest.
        "set:gateway.rules.in=2",
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
        // * ICMPv6 Echo Reply for Gateway from Guest Link-Local
        // * ICMPv6 Echo Reply for Gateway from Guest VPC ULA
        // * DHCPv6
        // * Outbound traffic from Guest IPv6 + MAC Address
        "set:gateway.rules.out=11",
        // * Allow all outbound traffic
        "set:firewall.rules.out=0",
        // * Outbound IPv4 SNAT
        // * Outbound IPv6 SNAT
        "set:nat.rules.out=2",
        nat_rules,
        // * Allow guest to route to own subnet
        "set:router.rules.out=1",
        // * Outbound encap
        // * Inbound decap
        "set:overlay.rules.in=1, overlay.rules.out=1",
    ];

    if let Some(val) = custom_updates {
        updates.extend_from_slice(&val);
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

fn verify_ulp_pkt_offsets(
    pkt: &Packet<Parsed>,
    ip: IpMeta,
    ulp: UlpMeta,
    body_len: usize,
) {
    let mut pos = 0;
    let off = pkt.hdr_offsets();
    assert_eq!(
        off.inner.ether,
        HdrOffset {
            pkt_pos: pos,
            seg_idx: 0,
            seg_pos: pos,
            hdr_len: EtherHdr::SIZE
        },
    );
    pos += EtherHdr::SIZE;
    assert_eq!(
        off.inner.ip.unwrap(),
        HdrOffset {
            pkt_pos: pos,
            seg_idx: 0,
            seg_pos: pos,
            hdr_len: ip.hdr_len()
        },
    );
    pos += ip.hdr_len();
    assert_eq!(
        off.inner.ulp.unwrap(),
        HdrOffset {
            pkt_pos: pos,
            seg_idx: 0,
            seg_pos: pos,
            hdr_len: ulp.hdr_len()
        },
    );
    pos += ulp.hdr_len();
    assert_eq!(
        pkt.body_info(),
        BodyInfo {
            pkt_offset: pos,
            seg_index: 0,
            seg_offset: pos,
            len: body_len
        },
    );
}

pub fn ulp_pkt<'a, I: Into<IpMeta>, U: Into<UlpMeta>>(
    eth: EtherMeta,
    ip: I,
    ulp: U,
    body: &[u8],
) -> Packet<Parsed> {
    let ip = ip.into();
    let ulp = ulp.into();
    let total_len =
        EtherHdr::SIZE + usize::from(ip.hdr_len()) + ulp.hdr_len() + body.len();
    let mut pkt = Packet::alloc_and_expand(total_len);
    let mut wtr = pkt.seg0_wtr();
    eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
    ip.emit(wtr.slice_mut(ip.hdr_len()).unwrap());
    ulp.emit(wtr.slice_mut(ulp.hdr_len()).unwrap());
    wtr.write(&body).unwrap();
    let mut pkt = pkt.parse(Out, GenericUlp {}).unwrap();
    pkt.compute_checksums();
    assert!(pkt.body_csum().is_some());
    verify_ulp_pkt_offsets(&pkt, ip, ulp, body.len());
    pkt
}

// Generate a packet representing the start of a TCP handshake for a
// telnet session from src to dst.
pub fn tcp_telnet_syn(src: &VpcCfg, dst: &VpcCfg) -> Packet<Parsed> {
    let body = vec![];
    let tcp = TcpMeta {
        src: 7865,
        dst: 23,
        flags: TcpFlags::SYN,
        seq: 4224936861,
        ack: 0,
        ..Default::default()
    };
    let ip4 = Ipv4Meta {
        src: src.ipv4_cfg().unwrap().private_ip,
        dst: dst.ipv4_cfg().unwrap().private_ip,
        proto: Protocol::TCP,
        total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len() + body.len()) as u16,
        ..Default::default()
    };
    let eth = EtherMeta {
        ether_type: EtherType::Ipv4,
        src: src.guest_mac,
        dst: src.gateway_mac,
    };
    ulp_pkt(eth, ip4, tcp, &body)
}

pub const HTTP_SYN_OPTS_LEN: usize = 20;

// Generate a packet representing the start of a TCP handshake for an
// HTTP request from src to dst.
pub fn http_syn(src: &VpcCfg, dst: &VpcCfg) -> Packet<Parsed> {
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
) -> Packet<Parsed> {
    let body = vec![];
    let mut options = [0x00; TcpHdr::MAX_OPTION_SIZE];
    #[rustfmt::skip]
    let bytes = [
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
    options[0..bytes.len()].copy_from_slice(&bytes);
    let options_len = bytes.len();

    let tcp = TcpMeta {
        src: 44490,
        dst: 80,
        flags: TcpFlags::SYN,
        seq: 2382112979,
        ack: 0,
        window_size: 64240,
        options_bytes: Some(options),
        options_len,
        csum: [0; 2],
    };
    let (ether_type, ip): (_, IpMeta) = match (ip_src.into(), ip_dst.into()) {
        (IpAddr::Ip4(src), IpAddr::Ip4(dst)) => (
            EtherType::Ipv4,
            Ipv4Meta {
                src,
                dst,
                proto: Protocol::TCP,
                total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len() + body.len())
                    as u16,
                ttl: 64,
                ident: 2662,
                ..Default::default()
            }
            .into(),
        ),
        (IpAddr::Ip6(src), IpAddr::Ip6(dst)) => (
            EtherType::Ipv6,
            Ipv6Meta {
                src,
                dst,
                proto: Protocol::TCP,
                next_hdr: IpProtocol::Tcp,
                pay_len: (tcp.hdr_len() + body.len()) as u16,
                ..Default::default()
            }
            .into(),
        ),
        _ => panic!("source and destination must be the same IP version"),
    };
    // Any packet from the guest is always addressed to the gateway.
    let eth = EtherMeta { ether_type, src: eth_src, dst: eth_dst };
    ulp_pkt(eth, ip, tcp, &body)
}

// Generate a packet representing the SYN+ACK reply to `http_tcp_syn()`,
// from g1 to g2.
pub fn http_syn_ack(src: &VpcCfg, dst: &VpcCfg) -> Packet<Parsed> {
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
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
    dport: u16,
) -> Packet<Parsed> {
    let body = vec![];
    let tcp = TcpMeta {
        src: 80,
        dst: dport,
        flags: TcpFlags::SYN | TcpFlags::ACK,
        seq: 44161351,
        ack: 2382112980,
        ..Default::default()
    };
    let ip4 = Ipv4Meta {
        src: ip_src,
        dst: ip_dst,
        proto: Protocol::TCP,
        total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len() + body.len()) as u16,
        ..Default::default()
    };
    let eth =
        EtherMeta { ether_type: EtherType::Ipv4, src: eth_src, dst: eth_dst };
    ulp_pkt(eth, ip4, tcp, &body)
}

pub fn http_ack2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
) -> Packet<Parsed> {
    let body = vec![];
    let tcp = TcpMeta {
        src: 44490,
        dst: 80,
        flags: TcpFlags::ACK,
        seq: 2382112980,
        ack: 44161352,
        ..Default::default()
    };
    let ip4 = Ipv4Meta {
        src: ip_src,
        dst: ip_dst,
        proto: Protocol::TCP,
        total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len() + body.len()) as u16,
        ..Default::default()
    };
    let eth =
        EtherMeta { ether_type: EtherType::Ipv4, src: eth_src, dst: eth_dst };
    ulp_pkt(eth, ip4, tcp, &body)
}

pub fn http_get2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
) -> Packet<Parsed> {
    // The details of the HTTP body are irrelevant to our testing. You
    // only need know it's 18 characters for the purposes of seq/ack.
    let body = "GET / HTTP/1.1\r\n\r\n".as_bytes();
    let tcp = TcpMeta {
        src: 44490,
        dst: 80,
        flags: TcpFlags::PSH | TcpFlags::ACK,
        seq: 2382112980,
        ack: 44161352,
        ..Default::default()
    };
    let ip4 = Ipv4Meta {
        src: ip_src,
        dst: ip_dst,
        proto: Protocol::TCP,
        total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len() + body.len()) as u16,
        ..Default::default()
    };
    let eth =
        EtherMeta { ether_type: EtherType::Ipv4, src: eth_src, dst: eth_dst };
    ulp_pkt(eth, ip4, tcp, &body)
}

pub fn http_get_ack2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
    dst_port: u16,
) -> Packet<Parsed> {
    let body = vec![];
    let tcp = TcpMeta {
        src: 80,
        dst: dst_port,
        flags: TcpFlags::ACK,
        seq: 44161353,
        ack: 2382112998,
        ..Default::default()
    };
    let ip4 = Ipv4Meta {
        src: ip_src,
        dst: ip_dst,
        proto: Protocol::TCP,
        total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len() + body.len()) as u16,
        ..Default::default()
    };
    let eth =
        EtherMeta { ether_type: EtherType::Ipv4, src: eth_src, dst: eth_dst };
    ulp_pkt(eth, ip4, tcp, &body)
}

pub fn http_301_reply2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
    dst_port: u16,
) -> Packet<Parsed> {
    // The details of the HTTP body are irrelevant to our testing. You
    // only need know it's 34 characters for the purposes of seq/ack.
    let body = "HTTP/1.1 301 Moved Permanently\r\n\r\n".as_bytes();
    let tcp = TcpMeta {
        src: 80,
        dst: dst_port,
        flags: TcpFlags::PSH | TcpFlags::ACK,
        seq: 44161353,
        ack: 2382112998,
        ..Default::default()
    };
    let ip4 = Ipv4Meta {
        src: ip_src,
        dst: ip_dst,
        proto: Protocol::TCP,
        total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len() + body.len()) as u16,
        ..Default::default()
    };
    let eth =
        EtherMeta { ether_type: EtherType::Ipv4, src: eth_src, dst: eth_dst };
    ulp_pkt(eth, ip4, tcp, &body)
}

pub fn http_301_ack2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
) -> Packet<Parsed> {
    let body = vec![];
    let tcp = TcpMeta {
        src: 44490,
        dst: 80,
        flags: TcpFlags::ACK,
        seq: 2382112998,
        ack: 44161353 + 34,
        ..Default::default()
    };
    let ip4 = Ipv4Meta {
        src: ip_src,
        dst: ip_dst,
        proto: Protocol::TCP,
        total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len() + body.len()) as u16,
        ..Default::default()
    };
    let eth =
        EtherMeta { ether_type: EtherType::Ipv4, src: eth_src, dst: eth_dst };
    ulp_pkt(eth, ip4, tcp, &body)
}

pub fn http_guest_fin2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
) -> Packet<Parsed> {
    let body = vec![];
    let tcp = TcpMeta {
        src: 44490,
        dst: 80,
        flags: TcpFlags::ACK | TcpFlags::FIN,
        seq: 2382112998,
        ack: 44161353 + 34,
        ..Default::default()
    };
    let ip4 = Ipv4Meta {
        src: ip_src,
        dst: ip_dst,
        proto: Protocol::TCP,
        total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len() + body.len()) as u16,
        ..Default::default()
    };
    let eth =
        EtherMeta { ether_type: EtherType::Ipv4, src: eth_src, dst: eth_dst };
    ulp_pkt(eth, ip4, tcp, &body)
}

pub fn http_server_ack_fin2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
    dst_port: u16,
) -> Packet<Parsed> {
    let body = vec![];
    let tcp = TcpMeta {
        src: 80,
        dst: dst_port,
        flags: TcpFlags::ACK,
        seq: 44161353 + 34,
        // We are ACKing the FIN, which counts as 1 byte.
        ack: 2382112998 + 1,
        ..Default::default()
    };
    let ip4 = Ipv4Meta {
        src: ip_src,
        dst: ip_dst,
        proto: Protocol::TCP,
        total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len() + body.len()) as u16,
        ..Default::default()
    };
    let eth =
        EtherMeta { ether_type: EtherType::Ipv4, src: eth_src, dst: eth_dst };
    ulp_pkt(eth, ip4, tcp, &body)
}

pub fn http_server_fin2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
    dst_port: u16,
) -> Packet<Parsed> {
    let body = vec![];
    let tcp = TcpMeta {
        src: 80,
        dst: dst_port,
        flags: TcpFlags::ACK | TcpFlags::FIN,
        seq: 44161353 + 34,
        ack: 2382112998 + 1,
        ..Default::default()
    };
    let ip4 = Ipv4Meta {
        src: ip_src,
        dst: ip_dst,
        proto: Protocol::TCP,
        total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len() + body.len()) as u16,
        ..Default::default()
    };
    let eth =
        EtherMeta { ether_type: EtherType::Ipv4, src: eth_src, dst: eth_dst };
    ulp_pkt(eth, ip4, tcp, &body)
}

pub fn http_guest_ack_fin2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
) -> Packet<Parsed> {
    let body = vec![];
    let tcp = TcpMeta {
        src: 44490,
        dst: 80,
        flags: TcpFlags::ACK,
        seq: 2382112998,
        // We are ACKing the FIN, which counts as 1 bytes.
        ack: 44161353 + 34 + 1,
        ..Default::default()
    };
    let ip4 = Ipv4Meta {
        src: ip_src,
        dst: ip_dst,
        proto: Protocol::TCP,
        total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len() + body.len()) as u16,
        ..Default::default()
    };
    let eth =
        EtherMeta { ether_type: EtherType::Ipv4, src: eth_src, dst: eth_dst };
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

/// Encapsulate a guest packet.
#[must_use]
pub fn encap(
    inner_pkt: Packet<Parsed>,
    src: TestIpPhys,
    dst: TestIpPhys,
) -> Packet<Parsed> {
    let inner_ip_len = match inner_pkt.hdr_offsets().inner.ip {
        Some(off) => Some(off.hdr_len),
        None => None,
    };

    let inner_ulp_len = match inner_pkt.hdr_offsets().inner.ulp {
        Some(off) => Some(off.hdr_len),
        None => None,
    };

    let inner_len = inner_pkt.len();

    let geneve = GeneveMeta {
        entropy: 99,
        vni: dst.vni,
        len: (UdpHdr::SIZE + GeneveHdr::BASE_SIZE + inner_len) as u16,
    };

    let ip = Ipv6Meta {
        src: src.ip,
        dst: dst.ip,
        pay_len: geneve.len,
        proto: Protocol::UDP,
        next_hdr: IpProtocol::Udp,
        ..Default::default()
    };

    let eth =
        EtherMeta { ether_type: EtherType::Ipv6, src: src.mac, dst: dst.mac };

    let total_len = EtherHdr::SIZE + usize::from(ip.total_len());
    let mut pkt = Packet::alloc_and_expand(total_len);
    let mut wtr = pkt.seg0_wtr();
    eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
    ip.emit(wtr.slice_mut(ip.hdr_len()).unwrap());
    geneve.emit(wtr.slice_mut(geneve.hdr_len()).unwrap());
    wtr.write(&inner_pkt.all_bytes()).unwrap();
    let pkt = pkt.parse(In, VpcParser::new()).unwrap();
    let off = pkt.hdr_offsets();
    let mut pos = 0;

    assert_eq!(
        off.outer.ether.unwrap(),
        HdrOffset {
            pkt_pos: pos,
            seg_idx: 0,
            seg_pos: pos,
            hdr_len: eth.hdr_len()
        },
    );
    pos += eth.hdr_len();

    assert_eq!(
        off.outer.ip.unwrap(),
        HdrOffset {
            pkt_pos: pos,
            seg_idx: 0,
            seg_pos: pos,
            hdr_len: ip.hdr_len()
        },
    );
    pos += ip.hdr_len();

    assert_eq!(
        off.outer.encap.unwrap(),
        HdrOffset {
            pkt_pos: pos,
            seg_idx: 0,
            seg_pos: pos,
            hdr_len: geneve.hdr_len()
        },
    );
    pos += geneve.hdr_len();

    assert_eq!(
        off.inner.ether,
        HdrOffset {
            pkt_pos: pos,
            seg_idx: 0,
            seg_pos: pos,
            hdr_len: EtherHdr::SIZE
        },
    );
    pos += EtherHdr::SIZE;

    if let Some(hdr_len) = inner_ip_len {
        assert_eq!(
            off.inner.ip.unwrap(),
            HdrOffset { pkt_pos: pos, seg_idx: 0, seg_pos: pos, hdr_len },
        );
        pos += hdr_len;
    }

    if let Some(hdr_len) = inner_ulp_len {
        assert_eq!(
            off.inner.ulp.unwrap(),
            HdrOffset { pkt_pos: pos, seg_idx: 0, seg_pos: pos, hdr_len },
        );
    }

    pkt
}

/// Like `assert!`, except you also pass in the `PortAndVps` so that
/// the port state is printed on failure.
#[macro_export]
macro_rules! chk {
    ($pav:expr, $check:expr) => {
        if !$check {
            print_port(&$pav.port, &$pav.vpc_map);
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

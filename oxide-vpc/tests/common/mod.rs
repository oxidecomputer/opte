// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

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
pub use opte::engine::ether::EtherType;
pub use opte::engine::geneve::GeneveHdr;
pub use opte::engine::geneve::Vni;
pub use opte::engine::geneve::GENEVE_PORT;
pub use opte::engine::headers::IpAddr;
pub use opte::engine::headers::IpCidr;
pub use opte::engine::headers::IpHdr;
pub use opte::engine::headers::UlpHdr;
pub use opte::engine::ip4::Ipv4Addr;
pub use opte::engine::ip4::Ipv4Hdr;
pub use opte::engine::ip4::UlpCsumOpt;
pub use opte::engine::ip6::Ipv6Addr;
pub use opte::engine::ip6::Ipv6Hdr;
pub use opte::engine::layer::DenyReason;
pub use opte::engine::packet::Initialized;
pub use opte::engine::packet::Packet;
pub use opte::engine::packet::Parsed;
pub use opte::engine::port::meta::ActionMeta;
pub use opte::engine::port::DropReason;
pub use opte::engine::port::Port;
pub use opte::engine::port::PortBuilder;
pub use opte::engine::port::ProcessResult;
pub use opte::engine::port::ProcessResult::*;
pub use opte::engine::tcp::TcpFlags;
pub use opte::engine::tcp::TcpHdr;
pub use opte::engine::udp::UdpHdr;
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
pub use pcap::*;
pub use port_state::*;
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
                ports: 1025..=4096,
            }),
            external_ips: None,
        },
    };
    VpcCfg {
        ip_cfg,
        guest_mac: MacAddr::from([0xA8, 0x40, 0x25, 0xFA, 0xFA, 0x37]),
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
        proxy_arp_enable: false,
        phys_gw_mac: Some(MacAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d])),
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
                ports: 4096..=8192,
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
        guest_mac: MacAddr::from([0xA8, 0x40, 0x25, 0xF0, 0x00, 0x66]),
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
        proxy_arp_enable: false,
        phys_gw_mac: Some(MacAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d])),
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
    pub port: Port,
    pub vps: VpcPortState,
    pub vpc_map: Arc<VpcMappings>,
}

pub fn oxide_net_setup(
    name: &str,
    cfg: &VpcCfg,
    vpc_map: Option<Arc<VpcMappings>>,
) -> PortAndVps {
    oxide_net_setup2(name, cfg, vpc_map, None)
}

pub fn oxide_net_setup2(
    name: &str,
    cfg: &VpcCfg,
    vpc_map: Option<Arc<VpcMappings>>,
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

    let port = oxide_net_builder(name, cfg, vpc_map.clone(), port_v2p)
        .create(UFT_LIMIT.unwrap(), TCP_LIMIT.unwrap())
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

pub fn ulp_pkt<I: Into<IpHdr>, U: Into<UlpHdr>>(
    eth: EtherHdr,
    ip: I,
    ulp: U,
    body: &[u8],
) -> Packet<Parsed> {
    let mut bytes = vec![];
    bytes.extend_from_slice(&eth.as_bytes());
    bytes.extend_from_slice(&ip.into().as_bytes());
    bytes.extend_from_slice(&ulp.into().as_bytes());
    bytes.extend_from_slice(&body);
    Packet::copy(&bytes).parse().unwrap()
}

// Generate a packet representing the start of a TCP handshake for a
// telnet session from src to dst.
pub fn tcp_telnet_syn(src: &VpcCfg, dst: &VpcCfg) -> Packet<Parsed> {
    let body = vec![];
    let mut tcp = TcpHdr::new(7865, 23);
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_seq(4224936861);
    let mut ip4 = Ipv4Hdr::new_tcp(
        &mut tcp,
        &body,
        src.ipv4_cfg().unwrap().private_ip,
        dst.ipv4_cfg().unwrap().private_ip,
    );
    ip4.compute_hdr_csum();
    let tcp_csum =
        ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    let eth = EtherHdr::new(EtherType::Ipv4, src.guest_mac, src.gateway_mac);
    ulp_pkt(eth, ip4, tcp, &body)
}

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
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
) -> Packet<Parsed> {
    let body = vec![];
    let mut tcp = TcpHdr::new(44490, 80);
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_seq(2382112979);
    let mut ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, ip_src, ip_dst);
    ip4.compute_hdr_csum();
    let tcp_csum =
        ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    // Any packet from the guest is always addressed to the gateway.
    let eth = EtherHdr::new(EtherType::Ipv4, eth_src, eth_dst);
    ulp_pkt(eth, ip4, tcp, &body)
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
    let mut tcp = TcpHdr::new(80, dport);
    tcp.set_flags(TcpFlags::SYN | TcpFlags::ACK);
    tcp.set_seq(44161351);
    tcp.set_ack(2382112980);
    let mut ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, ip_src, ip_dst);
    ip4.compute_hdr_csum();
    let tcp_csum =
        ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    let eth = EtherHdr::new(EtherType::Ipv4, eth_src, eth_dst);
    ulp_pkt(eth, ip4, tcp, &body)
}

pub fn http_ack2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
) -> Packet<Parsed> {
    let body = vec![];
    let mut tcp = TcpHdr::new(44490, 80);
    tcp.set_flags(TcpFlags::ACK);
    tcp.set_seq(2382112980);
    tcp.set_ack(44161352);
    let mut ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, ip_src, ip_dst);
    ip4.compute_hdr_csum();
    let tcp_csum =
        ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    let eth = EtherHdr::new(EtherType::Ipv4, eth_src, eth_dst);
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
    let mut tcp = TcpHdr::new(44490, 80);
    tcp.set_flags(TcpFlags::PSH | TcpFlags::ACK);
    tcp.set_seq(2382112980);
    tcp.set_ack(44161352);
    let mut ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, ip_src, ip_dst);
    ip4.compute_hdr_csum();
    let tcp_csum =
        ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    let eth = EtherHdr::new(EtherType::Ipv4, eth_src, eth_dst);
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
    let mut tcp = TcpHdr::new(80, dst_port);
    tcp.set_flags(TcpFlags::ACK);
    tcp.set_seq(44161353);
    tcp.set_ack(2382112998);
    let mut ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, ip_src, ip_dst);
    ip4.compute_hdr_csum();
    let tcp_csum =
        ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    let eth = EtherHdr::new(EtherType::Ipv4, eth_src, eth_dst);
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
    let mut tcp = TcpHdr::new(80, dst_port);
    tcp.set_flags(TcpFlags::PSH | TcpFlags::ACK);
    tcp.set_seq(44161353);
    tcp.set_ack(2382112998);
    let mut ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, ip_src, ip_dst);
    ip4.compute_hdr_csum();
    let tcp_csum =
        ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    let eth = EtherHdr::new(EtherType::Ipv4, eth_src, eth_dst);
    ulp_pkt(eth, ip4, tcp, &body)
}

pub fn http_301_ack2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
) -> Packet<Parsed> {
    let body = vec![];
    let mut tcp = TcpHdr::new(44490, 80);
    tcp.set_flags(TcpFlags::ACK);
    tcp.set_seq(2382112998);
    tcp.set_ack(44161353 + 34);
    let mut ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, ip_src, ip_dst);
    ip4.compute_hdr_csum();
    let tcp_csum =
        ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    let eth = EtherHdr::new(EtherType::Ipv4, eth_src, eth_dst);
    ulp_pkt(eth, ip4, tcp, &body)
}

pub fn http_guest_fin2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
) -> Packet<Parsed> {
    let body = vec![];
    let mut tcp = TcpHdr::new(44490, 80);
    tcp.set_flags(TcpFlags::ACK | TcpFlags::FIN);
    tcp.set_seq(2382112998);
    tcp.set_ack(44161353 + 34);
    let mut ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, ip_src, ip_dst);
    ip4.compute_hdr_csum();
    let tcp_csum =
        ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    let eth = EtherHdr::new(EtherType::Ipv4, eth_src, eth_dst);
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
    let mut tcp = TcpHdr::new(80, dst_port);
    tcp.set_flags(TcpFlags::ACK);
    tcp.set_seq(44161353 + 34);
    // We are ACKing the FIN, which counts as 1 byte.
    tcp.set_ack(2382112998 + 1);
    let mut ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, ip_src, ip_dst);
    ip4.compute_hdr_csum();
    let tcp_csum =
        ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    let eth = EtherHdr::new(EtherType::Ipv4, eth_src, eth_dst);
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
    let mut tcp = TcpHdr::new(80, dst_port);
    tcp.set_flags(TcpFlags::ACK | TcpFlags::FIN);
    tcp.set_seq(44161353 + 34);
    tcp.set_ack(2382112998 + 1);
    let mut ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, ip_src, ip_dst);
    ip4.compute_hdr_csum();
    let tcp_csum =
        ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    let eth = EtherHdr::new(EtherType::Ipv4, eth_src, eth_dst);
    ulp_pkt(eth, ip4, tcp, &body)
}

pub fn http_guest_ack_fin2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
    eth_dst: MacAddr,
    ip_dst: Ipv4Addr,
) -> Packet<Parsed> {
    let body = vec![];
    let mut tcp = TcpHdr::new(44490, 80);
    tcp.set_flags(TcpFlags::ACK);
    tcp.set_seq(2382112998);
    // We are ACKing the FIN, which counts as 1 bytes.
    tcp.set_ack(44161353 + 34 + 1);
    let mut ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, ip_src, ip_dst);
    ip4.compute_hdr_csum();
    let tcp_csum =
        ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
    tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
    let eth = EtherHdr::new(EtherType::Ipv4, eth_src, eth_dst);
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
    pkt: Packet<Parsed>,
    src: TestIpPhys,
    dst: TestIpPhys,
) -> Packet<Parsed> {
    let inner_len = pkt.len();
    let geneve = GeneveHdr::new(EtherType::Ether, dst.vni);
    let udp =
        UdpHdr::new(99, GENEVE_PORT, (geneve.hdr_len() + inner_len) as u16);
    let ip = Ipv6Hdr::new_udp(&udp, src.ip, dst.ip);
    let eth = EtherHdr::new(EtherType::Ipv6, src.mac, dst.mac);
    let mut body = geneve.as_bytes();
    body.extend_from_slice(&pkt.all_bytes());
    ulp_pkt(eth, ip, udp, &body)
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

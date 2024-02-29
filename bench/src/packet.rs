// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use opte::engine::dhcpv6::MessageType;
use opte::engine::packet::Initialized;
use opte::engine::packet::Packet;
use opte::engine::Direction;
use opte_test_utils::dhcp::dhcpv6_with_reasonable_defaults;
use opte_test_utils::dhcp::packet_from_client_dhcpv6_message_unparsed;
use opte_test_utils::icmp::gen_icmp_echo_unparsed;
use opte_test_utils::icmp::gen_icmpv6_echo_unparsed;
use opte_test_utils::icmp::generate_ndisc_unparsed;
use opte_test_utils::icmp::NdiscRepr;
use opte_test_utils::icmp::RawHardwareAddress;
use opte_test_utils::overlay::BOUNDARY_SERVICES_VNI;
use opte_test_utils::*;

pub type TestCase = (Packet<Initialized>, Direction);

pub enum ParserKind {
    Generic,
    OxideVpc,
}

/// A family of related parse/process testcases to benchmark.
pub trait BenchPacket {
    /// Label the output packet type in a human-friendly manner.
    fn packet_label(&self) -> String;

    /// Return a list of discrete scenarios
    fn test_cases(&self) -> Vec<Box<dyn BenchPacketInstance>>;
}

/// An individual packet to time the parse/process timing of.
pub trait BenchPacketInstance {
    /// Label for the experiment instance via BencherId.
    fn instance_name(&self) -> String;

    // XXX: We probably want this to take the cfg of one or more nodes
    /// Generate a single test packet.
    fn generate(&self) -> (Packet<Initialized>, Direction);

    /// Create a custom port for this benchmark instance.
    fn create_port(&self) -> Option<PortAndVps> {
        None
    }

    /// Specify which parse logic should be used for this instance.
    fn parse_with(&self) -> ParserKind {
        ParserKind::OxideVpc
    }

    /// Perform any necessary pre-handling logic.
    fn pre_handle(&self, _port: &PortAndVps) {}
}

pub struct UlpProcess {
    fast_path: bool,
}

pub const ULP_FAST_PATH: UlpProcess = UlpProcess { fast_path: true };
pub const ULP_SLOW_PATH: UlpProcess = UlpProcess { fast_path: false };

impl BenchPacket for UlpProcess {
    fn packet_label(&self) -> String {
        if self.fast_path { "ULP-FastPath" } else { "ULP-SlowPath" }.into()
    }

    fn test_cases(&self) -> Vec<Box<dyn BenchPacketInstance>> {
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
                    ephemeral_ip: Some("2001:db8::2".parse().unwrap()),
                    floating_ips: vec![],
                },
            },
        };

        let cfg = g1_cfg2(ip_cfg);

        itertools::iproduct!(
            [IpVariant::V4, IpVariant::V6],
            [ProtoVariant::Tcp, ProtoVariant::Udp],
            [Direction::Out, Direction::In],
            [0, 1400]
        )
        .map(|(ip, proto, direction, body_len)| UlpProcessInstance {
            ip,
            proto,
            direction,
            body_len,
            fast_path: self.fast_path,
            cfg: cfg.clone(),
        })
        .map(|v| Box::new(v) as Box<dyn BenchPacketInstance>)
        .collect()
    }
}

#[derive(Copy, Clone, Debug)]
pub enum IpVariant {
    V4,
    V6,
}

#[derive(Copy, Clone, Debug)]
pub enum ProtoVariant {
    Tcp,
    Udp,
}

#[derive(Clone, Debug)]
pub struct UlpProcessInstance {
    ip: IpVariant,
    proto: ProtoVariant,
    direction: Direction,
    body_len: usize,
    fast_path: bool,

    cfg: VpcCfg,
}

impl BenchPacketInstance for UlpProcessInstance {
    fn pre_handle(&self, port: &PortAndVps) {
        // We want to precreate an outbound packet with the correct
        // flowkey. This will also set up our UFT entry.
        let self_but_out = Self { direction: Direction::Out, ..self.clone() };

        let (pkt, dir) = self_but_out.generate();
        let mut pkt = pkt.parse(dir, VpcParser {}).unwrap();

        if self.fast_path {
            if let ProcessResult::Drop { reason } =
                port.port.process(dir, &mut pkt, ActionMeta::new()).unwrap()
            {
                panic!("failed to pass in pkt: {reason:?}");
            };
        } else {
            port.port.clear_uft().unwrap();
            for layer in VPC_LAYERS {
                port.port.clear_lft(layer).unwrap();
            }
        }
    }

    fn instance_name(&self) -> String {
        format!(
            "{:?}-{:?}-{}-{}B",
            self.ip, self.proto, self.direction, self.body_len
        )
    }

    fn generate(&self) -> (Packet<Initialized>, Direction) {
        let (my_ip, my_guest_ip, partner_ip, ether_type): (
            IpAddr,
            IpAddr,
            IpAddr,
            _,
        ) = match self.ip {
            IpVariant::V4 => (
                self.cfg.ipv4().external_ips.ephemeral_ip.unwrap().into(),
                self.cfg.ipv4().private_ip.into(),
                "93.184.216.34".parse().unwrap(),
                EtherType::Ipv4,
            ),
            IpVariant::V6 => (
                self.cfg.ipv6().external_ips.ephemeral_ip.unwrap().into(),
                self.cfg.ipv6().private_ip.into(),
                "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(),
                EtherType::Ipv6,
            ),
        };
        let (src_mac, dst_mac) = match self.direction {
            In => (BS_MAC_ADDR, self.cfg.guest_mac),
            Out => (self.cfg.guest_mac, self.cfg.gateway_mac),
        };
        let (src_ip, dst_ip, src_port, dst_port) = match self.direction {
            Direction::Out => (my_guest_ip, partner_ip, 10010, 80),
            Direction::In => (partner_ip, my_ip, 80, 10010),
        };
        let eth = EtherMeta { dst: dst_mac, src: src_mac, ether_type };

        let body = vec![0u8; self.body_len];

        let (ulp, next_hdr): (UlpMeta, _) = match self.proto {
            ProtoVariant::Tcp => (
                TcpMeta {
                    src: src_port,
                    dst: dst_port,
                    flags: TcpFlags::ACK,
                    seq: 1234,
                    ack: 3456,
                    window_size: 1,
                    csum: [0; 2],
                    options_bytes: None,
                    options_len: 0,
                }
                .into(),
                IpProtocol::Tcp,
            ),
            ProtoVariant::Udp => (
                UdpMeta {
                    src: src_port,
                    dst: dst_port,
                    len: (UdpHdr::SIZE + body.len()) as u16,
                    csum: [0; 2],
                }
                .into(),
                IpProtocol::Udp,
            ),
        };
        let proto = Protocol::from(next_hdr);
        let ip: IpMeta = match (src_ip, dst_ip) {
            (IpAddr::Ip4(src), IpAddr::Ip4(dst)) => Ipv4Meta {
                src,
                dst,
                proto,
                total_len: (Ipv4Hdr::BASE_SIZE + ulp.hdr_len() + body.len())
                    as u16,
                ..Ipv4Meta::default()
            }
            .into(),
            (IpAddr::Ip6(src), IpAddr::Ip6(dst)) => Ipv6Meta {
                src,
                dst,
                next_hdr,
                proto,
                pay_len: (ulp.hdr_len() + body.len()) as u16,
                ..Ipv6Meta::default()
            }
            .into(),
            _ => unreachable!(),
        };

        let inner_pkt = ulp_pkt(eth, ip, ulp, &body);

        let out_pkt = match self.direction {
            Direction::Out => inner_pkt,
            Direction::In => {
                let bsvc_phys = TestIpPhys {
                    ip: BS_IP_ADDR,
                    mac: BS_MAC_ADDR,
                    vni: Vni::new(BOUNDARY_SERVICES_VNI).unwrap(),
                };
                let guest_phys = TestIpPhys {
                    ip: self.cfg.phys_ip,
                    mac: self.cfg.guest_mac,
                    vni: self.cfg.vni,
                };

                encap_external(inner_pkt, bsvc_phys, guest_phys)
            }
        };

        let buf = out_pkt.all_bytes();

        let len = buf.len();
        let mut pkt = Packet::alloc_and_expand(len);
        let mut wtr = pkt.seg0_wtr();
        wtr.slice_mut(len).unwrap().copy_from_slice(&buf[..]);

        (pkt, self.direction)
    }

    fn create_port(&self) -> Option<PortAndVps> {
        let mut g1 = oxide_net_setup("g1_port", &self.cfg, None, None);
        g1.port.start();
        set!(g1, "port_state=running");

        router::add_entry(
            &g1.port,
            IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
            RouterTarget::InternetGateway,
        )
        .unwrap();
        incr!(g1, ["epoch", "router.rules.out"]);

        router::add_entry(
            &g1.port,
            IpCidr::Ip6("::/0".parse().unwrap()),
            RouterTarget::InternetGateway,
        )
        .unwrap();
        incr!(g1, ["epoch", "router.rules.out"]);

        if !self.fast_path {
            let any_in = "dir=in action=allow priority=1000 protocol=any";
            firewall::set_fw_rules(
                &g1.port,
                &SetFwRulesReq {
                    port_name: g1.port.name().to_string(),
                    rules: vec![any_in.parse().unwrap()],
                },
            )
            .unwrap();
            update!(
                g1,
                [
                    "incr:epoch",
                    "set:firewall.flows.in=0, firewall.flows.out=0",
                    "set:firewall.rules.out=0, firewall.rules.in=1",
                ]
            );
        }

        Some(g1)
    }
}

pub struct Dhcp6;

impl BenchPacket for Dhcp6 {
    fn packet_label(&self) -> String {
        "Hairpin-DHCPv6".into()
    }

    fn test_cases(&self) -> Vec<Box<dyn BenchPacketInstance>> {
        [Dhcp6Instance::Solicit, Dhcp6Instance::Request]
            .into_iter()
            .map(|v| Box::new(v) as Box<dyn BenchPacketInstance>)
            .collect()
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Dhcp6Instance {
    Solicit,
    Request,
}

impl BenchPacketInstance for Dhcp6Instance {
    fn instance_name(&self) -> String {
        format!("{self:?}")
    }

    fn generate(&self) -> (Packet<Initialized>, Direction) {
        let cfg = g1_cfg();
        let class = match self {
            Dhcp6Instance::Solicit => MessageType::Solicit,
            Dhcp6Instance::Request => MessageType::Request,
        };
        let repr = dhcpv6_with_reasonable_defaults(class, false, &cfg);

        (
            packet_from_client_dhcpv6_message_unparsed(&cfg, &repr),
            Direction::Out,
        )
    }
}

pub struct Icmp4;

impl BenchPacket for Icmp4 {
    fn packet_label(&self) -> String {
        "Hairpin-ICMPv4".into()
    }

    fn test_cases(&self) -> Vec<Box<dyn BenchPacketInstance>> {
        [Self]
            .into_iter()
            .map(|v| Box::new(v) as Box<dyn BenchPacketInstance>)
            .collect()
    }
}

impl BenchPacketInstance for Icmp4 {
    fn instance_name(&self) -> String {
        "EchoRequest".into()
    }

    fn generate(&self) -> (Packet<Initialized>, Direction) {
        let cfg = g1_cfg();
        let ident = 7;
        let seq_no = 777;
        let data = b"reunion\0";

        let pkt = gen_icmp_echo_unparsed(
            icmp::IcmpEchoType::Req,
            cfg.guest_mac,
            cfg.gateway_mac,
            cfg.ipv4_cfg().unwrap().private_ip,
            cfg.ipv4_cfg().unwrap().gateway_ip,
            ident,
            seq_no,
            &data[..],
            1,
        );

        (pkt, Direction::Out)
    }
}

pub struct Icmp6;

impl BenchPacket for Icmp6 {
    fn packet_label(&self) -> String {
        "Hairpin-ICMPv6".into()
    }

    fn test_cases(&self) -> Vec<Box<dyn BenchPacketInstance>> {
        [
            Icmp6Instance::Echo,
            Icmp6Instance::NeighborSolicit,
            Icmp6Instance::RouterSolicit,
        ]
        .into_iter()
        .map(|v| Box::new(v) as Box<dyn BenchPacketInstance>)
        .collect()
    }
}

pub enum Icmp6Instance {
    Echo,
    NeighborSolicit,
    RouterSolicit,
}

impl BenchPacketInstance for Icmp6Instance {
    fn instance_name(&self) -> String {
        match self {
            Icmp6Instance::Echo => "EchoRequest",
            Icmp6Instance::NeighborSolicit => "NeighborSolicit",
            Icmp6Instance::RouterSolicit => "RouterSolicit",
        }
        .into()
    }

    fn generate(&self) -> (Packet<Initialized>, Direction) {
        let cfg = g1_cfg();
        let ident = 7;
        let seq_no = 777;
        let data = b"reunion\0";

        let pkt = match self {
            Icmp6Instance::Echo => gen_icmpv6_echo_unparsed(
                icmp::IcmpEchoType::Req,
                cfg.guest_mac,
                cfg.gateway_mac,
                cfg.ipv6_cfg().unwrap().private_ip,
                Ipv6Addr::from_eui64(&cfg.gateway_mac),
                ident,
                seq_no,
                &data[..],
                3,
            ),
            Icmp6Instance::NeighborSolicit => {
                let solicit = NdiscRepr::NeighborSolicit {
                    target_addr: Ipv6Addr::from_eui64(&cfg.gateway_mac).into(),
                    lladdr: Some(RawHardwareAddress::from_bytes(
                        &cfg.guest_mac,
                    )),
                };
                generate_ndisc_unparsed(
                    solicit,
                    cfg.guest_mac,
                    cfg.gateway_mac,
                    Ipv6Addr::from_eui64(&cfg.guest_mac),
                    Ipv6Addr::from_eui64(&cfg.gateway_mac),
                    true,
                )
            }
            Icmp6Instance::RouterSolicit => {
                let src_mac = cfg.guest_mac;
                let solicit = NdiscRepr::RouterSolicit {
                    lladdr: Some(RawHardwareAddress::from_bytes(&src_mac)),
                };
                let dst_ip = Ipv6Addr::ALL_ROUTERS;

                generate_ndisc_unparsed(
                    solicit,
                    src_mac,
                    // Must be destined for the All-Routers IPv6 address, and the corresponding
                    // multicast Ethernet address.
                    dst_ip.multicast_mac().unwrap(),
                    // The source IPv6 address is the EUI-64 transform of the source MAC.
                    Ipv6Addr::from_eui64(&src_mac),
                    dst_ip,
                    true,
                )
            }
        };

        (pkt, Direction::Out)
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

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
//!
//! TODO This module belongs in oxide_vpc as it's testing VPC-specific
//! configuration.
use opte::api::Direction::*;
use opte::api::MacAddr;
use opte::api::OpteError;
use opte::ddi::time::Moment;
use opte::engine::arp::ArpEth4Payload;
use opte::engine::arp::ArpEth4PayloadRaw;
use opte::engine::arp::ArpHdrRaw;
use opte::engine::arp::ARP_HDR_SZ;
use opte::engine::checksum::HeaderChecksum;
use opte::engine::dhcpv6;
use opte::engine::ether::EtherHdr;
use opte::engine::ether::EtherHdrRaw;
use opte::engine::ether::EtherMeta;
use opte::engine::ether::EtherType;
use opte::engine::ether::ETHER_TYPE_ARP;
use opte::engine::ether::ETHER_TYPE_IPV4;
use opte::engine::ether::ETHER_TYPE_IPV6;
use opte::engine::flow_table::FLOW_DEF_EXPIRE_SECS;
use opte::engine::geneve;
use opte::engine::geneve::GeneveHdr;
use opte::engine::geneve::Vni;
use opte::engine::headers::IpAddr;
use opte::engine::headers::IpCidr;
use opte::engine::headers::IpMeta;
use opte::engine::headers::UlpMeta;
use opte::engine::ip4::Ipv4Addr;
use opte::engine::ip4::Ipv4Hdr;
use opte::engine::ip4::Ipv4Meta;
use opte::engine::ip4::Protocol;
use opte::engine::ip4::UlpCsumOpt;
use opte::engine::ip6::Ipv6Addr;
use opte::engine::ip6::Ipv6Hdr;
use opte::engine::ip6::Ipv6Meta;
use opte::engine::packet::Initialized;
use opte::engine::packet::Packet;
use opte::engine::packet::PacketRead;
use opte::engine::packet::PacketReader;
use opte::engine::packet::PacketWriter;
use opte::engine::packet::ParseError;
use opte::engine::packet::Parsed;
use opte::engine::port::meta::ActionMeta;
use opte::engine::port::Port;
use opte::engine::port::PortBuilder;
use opte::engine::port::PortState;
use opte::engine::port::ProcessError;
use opte::engine::port::ProcessResult;
use opte::engine::rule;
use opte::engine::rule::MappingResource;
use opte::engine::rule::Rule;
use opte::engine::tcp::TcpFlags;
use opte::engine::tcp::TcpHdr;
use opte::engine::udp::UdpHdr;
use opte::engine::udp::UdpMeta;
use opte::ExecCtx;
use oxide_vpc::api::AddFwRuleReq;
use oxide_vpc::api::BoundaryServices;
use oxide_vpc::api::FirewallRule;
use oxide_vpc::api::GuestPhysAddr;
use oxide_vpc::api::IpCfg;
use oxide_vpc::api::Ipv4Cfg;
use oxide_vpc::api::Ipv6Cfg;
use oxide_vpc::api::RouterTarget;
use oxide_vpc::api::SNat4Cfg;
use oxide_vpc::api::SNat6Cfg;
use oxide_vpc::api::SetFwRulesReq;
use oxide_vpc::api::VpcCfg;
use oxide_vpc::engine::arp;
use oxide_vpc::engine::dhcp;
use oxide_vpc::engine::firewall;
use oxide_vpc::engine::icmp;
use oxide_vpc::engine::icmpv6;
use oxide_vpc::engine::nat;
use oxide_vpc::engine::overlay;
use oxide_vpc::engine::overlay::Virt2Phys;
use oxide_vpc::engine::router;
use pcap_parser::pcap;
use pcap_parser::pcap::LegacyPcapBlock;
use pcap_parser::pcap::PcapHeader;
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
use std::boxed::Box;
use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::prelude::v1::*;
use std::sync::Arc;
use std::time::Duration;
use zerocopy::AsBytes;
use ProcessResult::*;

// This is the MAC address that OPTE uses to act as the virtual gateway.
pub const GW_MAC_ADDR: MacAddr =
    MacAddr::from_const([0xA8, 0x40, 0x25, 0xFF, 0x77, 0x77]);

const VPC_ENCAP_SZ: usize =
    EtherHdr::SIZE + Ipv6Hdr::SIZE + UdpHdr::SIZE + GeneveHdr::SIZE;
const IP_SZ: usize = EtherHdr::SIZE + Ipv4Hdr::SIZE;

// If we are running `cargo test --feature=usdt`, then make sure to
// register the USDT probes before running any tests.
#[cfg(all(test, feature = "usdt"))]
#[ctor::ctor]
fn register_usdt() {
    usdt::register_probes().unwrap();
}

#[allow(dead_code)]
fn get_header(offset: &[u8]) -> (&[u8], PcapHeader) {
    match pcap::parse_pcap_header(offset) {
        Ok((new_offset, header)) => (new_offset, header),
        Err(e) => panic!("failed to get header: {:?}", e),
    }
}

#[allow(dead_code)]
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

// Used to track various bits of port state for the purpose of
// validating the port as we send it various commands and traffic. It
// is meant to be manipulated and checked by the macros that follow.
struct VpcPortState {
    counts: BTreeMap<String, u32>,
    epoch: u64,
    port_state: PortState,
}

impl VpcPortState {
    fn new() -> Self {
        Self {
            counts: BTreeMap::from(
                [
                    ("arp.rules_in", 0),
                    ("arp.rules_out", 0),
                    ("fw.flows_in", 0),
                    ("fw.flows_out", 0),
                    ("fw.rules_in", 0),
                    ("fw.rules_out", 0),
                    ("icmp.rules_in", 0),
                    ("icmp.rules_out", 0),
                    ("nat.flows_in", 0),
                    ("nat.flows_out", 0),
                    ("nat.rules_in", 0),
                    ("nat.rules_out", 0),
                    ("router.rules_in", 0),
                    ("router.rules_out", 0),
                    ("uft.flows_in", 0),
                    ("uft.flows_out", 0),
                ]
                .map(|(name, val)| (name.to_string(), val)),
            ),
            epoch: 1,
            port_state: PortState::Ready,
        }
    }
}

// Assert that the port matches the expected port state.
macro_rules! assert_port {
    ($pav:expr) => {
        for (field, expected_val) in $pav.vps.counts.iter() {
            let actual_val = match field.as_str() {
                "arp.rules_in" => $pav.port.num_rules("arp", In),
                "arp.rules_out" => $pav.port.num_rules("arp", Out),
                "fw.flows_in" => $pav.port.num_flows("firewall", In),
                "fw.flows_out" => $pav.port.num_flows("firewall", Out),
                "fw.rules_in" => $pav.port.num_rules("firewall", In),
                "fw.rules_out" => $pav.port.num_rules("firewall", Out),
                "icmp.rules_in" => $pav.port.num_rules("icmp", In),
                "icmp.rules_out" => $pav.port.num_rules("icmp", Out),
                "nat.flows_in" => $pav.port.num_flows("nat", In),
                "nat.flows_out" => $pav.port.num_flows("nat", Out),
                "nat.rules_in" => $pav.port.num_rules("nat", In),
                "nat.rules_out" => $pav.port.num_rules("nat", Out),
                "router.rules_in" => $pav.port.num_rules("router", In),
                "router.rules_out" => $pav.port.num_rules("router", Out),
                "uft.flows_in" => $pav.port.num_flows("uft", In),
                "uft.flows_out" => $pav.port.num_flows("uft", Out),
                f => todo!("implement check for field: {}", f),
            };
            assert!(
                *expected_val == actual_val,
                "field value mismatch: field: {}, expected: {}, actual: {}",
                field,
                expected_val,
                actual_val,
            );
        }

        {
            let expected = $pav.vps.epoch;
            let actual = $pav.port.epoch();
            assert!(
                expected == actual,
                "epoch mismatch: expected: {}, actual: {}",
                expected,
                actual,
            );
        }

        {
            let expected = $pav.vps.port_state;
            let actual = $pav.port.state();
            assert!(
                expected == actual,
                "port state mismatch: expected: {}, actual: {}",
                expected,
                actual,
            );
        }
    };
}

// Increment a given field.
macro_rules! incr_field {
    ($vps:expr, $field:expr) => {
        match $vps.counts.get_mut($field) {
            Some(v) => *v += 1,
            None => assert!(false, "field does not exist: {}", $field),
        }
    };
}

// Decrement a given field.
macro_rules! decr_field {
    ($vps:expr, $field:expr) => {
        match $vps.counts.get_mut($field) {
            Some(v) => *v -= 1,
            None => assert!(false, "field does not exist: {}", $field),
        }
    };
}

// Increment the list of fields.
macro_rules! incr_na {
    ($port_and_vps:expr, $fields:expr) => {
        for f in $fields {
            match f {
                "epoch" => $port_and_vps.vps.epoch += 1,
                _ => incr_field!($port_and_vps.vps, f),
            }
        }
    };
}

// Increment the list of fields and assert the port state.
macro_rules! incr {
    ($port_and_vps:expr, $fields:expr) => {
        incr_na!($port_and_vps, $fields);
        assert_port!($port_and_vps);
    };
}

// Drecrement the list of fields.
macro_rules! decr_na {
    ($port_and_vps:expr, $fields:expr) => {
        for f in $fields {
            match f {
                // You can never decrement the epoch.
                _ => decr_field!($port_and_vps.vps, f),
            }
        }
    };
}

// Set the given field to the given value.
macro_rules! set_field {
    ($port_and_vps:expr, $field:expr, $val:expr) => {
        match $port_and_vps.vps.counts.get_mut($field) {
            Some(v) => *v = $val,
            None => assert!(false, "field does not exist: {}", $field),
        }
    };
}

// Set a list of fields to the specific value.
//
// epcoh=M,fw.rules_in=N
macro_rules! set_fields {
    ($port_and_vps:expr, $fields:expr) => {
        for f in $fields {
            match f.split_once("=") {
                Some(("epoch", val)) => {
                    $port_and_vps.vps.epoch += val.parse::<u64>().unwrap();
                }

                Some((field, val)) => {
                    set_field!($port_and_vps, field, val.parse().unwrap());
                }

                _ => panic!("malformed field expr: {}", f),
            }
        }
    };
}

// Update the VpcPortState and assert.
//
// update!(g1, ["incr:epoch,fw.flows_out,fw.flows_in,uft.flows_out"])
macro_rules! update {
    ($port_and_vps:expr, $instructions:expr) => {
        for inst in $instructions {
            match inst.split_once(":") {
                Some(("incr", fields)) => {
                    // Convert "field1,field2,field3" to ["field1",
                    // "field2, "field3"]
                    let fields_arr: Vec<&str> = fields.split(",").collect();
                    incr_na!($port_and_vps, fields_arr);
                }

                Some(("set", fields)) => {
                    let fields_arr: Vec<&str> = fields.split(",").collect();
                    set_fields!($port_and_vps, fields_arr);
                }

                Some(("decr", fields)) => {
                    let fields_arr: Vec<&str> = fields.split(",").collect();
                    decr_na!($port_and_vps, fields_arr);
                }

                Some((op, _)) => {
                    panic!("unknown op: {} instruction: {}", op, inst);
                }

                _ => panic!("malformed instruction: {}", inst),
            }
        }

        assert_port!($port_and_vps);
    };
}

// Set all flow counts to zero.
macro_rules! zero_flows {
    ($port_and_vps:expr) => {
        for (field, count) in $port_and_vps.vps.counts.iter_mut() {
            match field.as_str() {
                "fw.flows_in" | "fw.flows_out" => *count = 0,
                "nat.flows_in" | "nat.flows_out" => *count = 0,
                "router.flows_in" | "router.flows_out" => *count = 0,
                "uft.flows_in" | "uft.flows_out" => *count = 0,
                &_ => (),
            }
        }
    };
}

// Set the expected PortState of the port.
macro_rules! set_state {
    ($port_and_vps:expr, $port_state:expr) => {
        $port_and_vps.vps.port_state = $port_state;
        assert_port!($port_and_vps);
    };
}

// TODO move PcapBuilder stuff to common file
use pcap_parser::Linktype;
use pcap_parser::ToVec;
use std::fs::File;
use std::io::Write;

pub struct PcapBuilder {
    file: File,
}

impl PcapBuilder {
    pub fn new(path: &str) -> Self {
        let mut file = File::create(path).unwrap();

        let mut hdr = PcapHeader {
            magic_number: 0xa1b2c3d4,
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 1500,
            network: Linktype::ETHERNET,
        };

        file.write_all(&hdr.to_vec().unwrap()).unwrap();

        Self { file }
    }

    pub fn add_pkt(&mut self, pkt: &Packet<Parsed>) {
        let pkt_bytes = PacketReader::new(&pkt, ()).copy_remaining();
        let mut block = LegacyPcapBlock {
            ts_sec: 7777,
            ts_usec: 7777,
            caplen: pkt_bytes.len() as u32,
            origlen: pkt_bytes.len() as u32,
            data: &pkt_bytes,
        };

        self.file.write_all(&block.to_vec().unwrap()).unwrap();
    }
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
        private_mac: MacAddr::from([0xAA, 0x00, 0x04, 0x00, 0xFF, 0x10]),
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
            vni: Vni::new(7777u32).unwrap(),
        },
        proxy_arp_enable: false,
        phys_gw_mac: Some(MacAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d])),
    }
}

fn oxide_net_builder(
    name: &str,
    cfg: &VpcCfg,
    v2p: Arc<Virt2Phys>,
) -> PortBuilder {
    let ectx = Arc::new(ExecCtx { log: Box::new(opte::PrintlnLog {}) });
    let name_cstr = std::ffi::CString::new(name).unwrap();
    let mut pb =
        PortBuilder::new(name, name_cstr, cfg.private_mac.into(), ectx.clone());

    let fw_limit = NonZeroU32::new(8096).unwrap();
    let snat_limit = NonZeroU32::new(8096).unwrap();
    let one_limit = NonZeroU32::new(1).unwrap();

    firewall::setup(&mut pb, fw_limit).expect("failed to add firewall layer");
    dhcp::setup(&mut pb, cfg, one_limit).expect("failed to add dhcp layer");
    oxide_vpc::engine::dhcpv6::setup(&mut pb, cfg, one_limit)
        .expect("failed to add dhcpv6 layer");
    icmp::setup(&mut pb, cfg, one_limit).expect("failed to add icmp layer");
    icmpv6::setup(&mut pb, cfg, one_limit).expect("failed to add icmpv6 layer");
    arp::setup(&mut pb, cfg, one_limit).expect("failed to add arp layer");
    router::setup(&mut pb, cfg, one_limit).expect("failed to add router layer");
    nat::setup(&mut pb, cfg, snat_limit).expect("failed to add nat layer");
    overlay::setup(&mut pb, cfg, v2p, one_limit)
        .expect("failed to add overlay layer");

    // Deny all inbound packets by default.
    pb.add_rule("firewall", In, Rule::match_any(65535, rule::Action::Deny))
        .unwrap();
    // Allow all outbound by default.
    let act = pb.layer_action("firewall", 0).unwrap();
    pb.add_rule("firewall", Out, Rule::match_any(65535, act)).unwrap();
    pb
}

struct PortAndVps {
    port: Port,
    vps: VpcPortState,
}

fn oxide_net_setup(
    name: &str,
    cfg: &VpcCfg,
    v2p: Arc<Virt2Phys>,
) -> PortAndVps {
    let port = oxide_net_builder(name, cfg, v2p)
        .create(UFT_LIMIT.unwrap(), TCP_LIMIT.unwrap())
        .unwrap();
    assert_eq!(port.state(), PortState::Ready);
    assert_eq!(port.epoch(), 1);
    check_no_flows(&port);
    let vps = VpcPortState::new();
    let mut pav = PortAndVps { port, vps };
    update!(
        pav,
        [
            "set:arp.rules_in=1,arp.rules_out=2",
            "set:icmp.rules_out=1",
            "set:fw.rules_in=1,fw.rules_out=1",
            "set:nat.rules_out=2",
            "set:router.rules_out=1",
        ]
    );
    assert_port!(pav);
    pav
}

const UFT_LIMIT: Option<NonZeroU32> = NonZeroU32::new(16);
const TCP_LIMIT: Option<NonZeroU32> = NonZeroU32::new(16);

fn g1_cfg() -> VpcCfg {
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
        private_mac: MacAddr::from([0xA8, 0x40, 0x25, 0xFA, 0xFA, 0x37]),
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

fn g2_cfg() -> VpcCfg {
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
        private_mac: MacAddr::from([0xA8, 0x40, 0x25, 0xF0, 0x00, 0x66]),
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

// Verify that no flows are present on the port.
fn check_no_flows(port: &Port) {
    for layer in port.layers() {
        assert_eq!(port.num_flows(&layer, Out), 0);
        assert_eq!(port.num_flows(&layer, In), 0);
    }

    assert_eq!(port.num_flows("uft", Out), 0);
    assert_eq!(port.num_flows("uft", In), 0);
}

// Generate a packet representing the start of a TCP handshake for a
// telnet session from src to dst.
fn tcp_telnet_syn(src: &VpcCfg, dst: &VpcCfg) -> Packet<Parsed> {
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
    let eth = EtherHdr::new(EtherType::Ipv4, src.private_mac, src.gateway_mac);

    let mut bytes = vec![];
    bytes.extend_from_slice(&eth.as_bytes());
    bytes.extend_from_slice(&ip4.as_bytes());
    bytes.extend_from_slice(&tcp.as_bytes());
    bytes.extend_from_slice(&body);
    Packet::copy(&bytes).parse().unwrap()
}

// Generate a packet representing the start of a TCP handshake for an
// HTTP request from src to dst.
fn http_tcp_syn(src: &VpcCfg, dst: &VpcCfg) -> Packet<Parsed> {
    http_tcp_syn2(
        src.private_mac,
        src.ipv4_cfg().unwrap().private_ip,
        dst.ipv4_cfg().unwrap().private_ip,
    )
}

// Generate a packet representing the start of a TCP handshake for an
// HTTP request from src to dst.
fn http_tcp_syn2(
    eth_src: MacAddr,
    ip_src: Ipv4Addr,
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
    let eth = EtherHdr::new(EtherType::Ipv4, eth_src, GW_MAC_ADDR);
    let mut bytes = vec![];
    bytes.extend_from_slice(&eth.as_bytes());
    bytes.extend_from_slice(&ip4.as_bytes());
    bytes.extend_from_slice(&tcp.as_bytes());
    bytes.extend_from_slice(&body);
    Packet::copy(&bytes).parse().unwrap()
}

// Generate a packet representing the SYN+ACK reply to `http_tcp_syn()`,
// from g1 to g2.
fn http_tcp_syn_ack(src: &VpcCfg, dst: &VpcCfg) -> Packet<Parsed> {
    let body = vec![];
    let mut tcp = TcpHdr::new(80, 44490);
    tcp.set_flags(TcpFlags::SYN | TcpFlags::ACK);
    tcp.set_seq(44161351);
    tcp.set_ack(2382112980);
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
    let eth = EtherHdr::new(EtherType::Ipv4, src.private_mac, src.gateway_mac);

    let mut bytes = vec![];
    bytes.extend_from_slice(&eth.as_bytes());
    bytes.extend_from_slice(&ip4.as_bytes());
    bytes.extend_from_slice(&tcp.as_bytes());
    bytes.extend_from_slice(&body);
    Packet::copy(&bytes).parse().unwrap()
}

// Verify Port transition from Ready -> Running.
#[test]
fn port_transition_running() {
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let g2_phys =
        GuestPhysAddr { ether: g2_cfg.private_mac.into(), ip: g2_cfg.phys_ip };

    // Add V2P mappings that allow guests to resolve each others
    // physical addresses.
    let v2p = Arc::new(Virt2Phys::new());
    v2p.set(IpAddr::Ip4(g2_cfg.ipv4_cfg().unwrap().private_ip), g2_phys);
    let mut ameta = ActionMeta::new();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, v2p.clone());

    // Add router entry that allows g1 to send to other guests on the
    // same subnet.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4(g1_cfg.ipv4_cfg().unwrap().vpc_subnet),
        RouterTarget::VpcSubnet(IpCidr::Ip4(
            g1_cfg.ipv4_cfg().unwrap().vpc_subnet,
        )),
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules_out"]);

    // ================================================================
    // Try processing the packet while taking the port through a Ready
    // -> Running.
    // ================================================================
    let mut pkt1 = tcp_telnet_syn(&g1_cfg, &g2_cfg);
    let res = g1.port.process(Out, &mut pkt1, &mut ameta);
    assert!(matches!(res, Err(ProcessError::BadState(_))));
    assert_port!(g1);
    g1.port.start();
    set_state!(g1, PortState::Running);
    let res = g1.port.process(Out, &mut pkt1, &mut ameta);
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["fw.flows_in", "fw.flows_out", "uft.flows_out"]);
}

// Verify a Port reset transitions it to the Ready state and clears
// all flow state.
#[test]
fn port_transition_reset() {
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let g2_phys =
        GuestPhysAddr { ether: g2_cfg.private_mac.into(), ip: g2_cfg.phys_ip };

    // Add V2P mappings that allow guests to resolve each others
    // physical addresses.
    let v2p = Arc::new(Virt2Phys::new());
    v2p.set(IpAddr::Ip4(g2_cfg.ipv4_cfg().unwrap().private_ip), g2_phys);
    let mut ameta = ActionMeta::new();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, v2p.clone());

    // Add router entry that allows g1 to send to other guests on the
    // same subnet.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4(g1_cfg.ipv4_cfg().unwrap().vpc_subnet),
        RouterTarget::VpcSubnet(IpCidr::Ip4(
            g1_cfg.ipv4_cfg().unwrap().vpc_subnet,
        )),
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules_out"]);

    // ================================================================
    // Try processing the packet while taking the port through a Ready
    // -> Running -> Ready transition. Verify that flows are cleared
    // but rules remain.
    // ================================================================
    let mut pkt1 = tcp_telnet_syn(&g1_cfg, &g2_cfg);
    g1.port.start();
    set_state!(g1, PortState::Running);
    let res = g1.port.process(Out, &mut pkt1, &mut ameta);
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["fw.flows_in", "fw.flows_out", "uft.flows_out"]);
    g1.port.reset();
    zero_flows!(g1);
    set_state!(g1, PortState::Ready);
    let res = g1.port.process(Out, &mut pkt1, &mut ameta);
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
    let g1_phys =
        GuestPhysAddr { ether: g1_cfg.private_mac.into(), ip: g1_cfg.phys_ip };
    let g2_cfg = g2_cfg();
    let g2_phys =
        GuestPhysAddr { ether: g2_cfg.private_mac.into(), ip: g2_cfg.phys_ip };

    // Add V2P mappings that allow guests to resolve each others
    // physical addresses.
    let v2p = Arc::new(Virt2Phys::new());
    v2p.set(IpAddr::Ip4(g1_cfg.ipv4_cfg().unwrap().private_ip), g1_phys);
    v2p.set(IpAddr::Ip4(g2_cfg.ipv4_cfg().unwrap().private_ip), g2_phys);
    let mut g1_ameta = ActionMeta::new();
    let mut g2_ameta = ActionMeta::new();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, v2p.clone());
    let mut g2 = oxide_net_setup("g2_port", &g2_cfg, v2p.clone());

    // Add router entry that allows g1 to send to other guests on same
    // subnet.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4(g1_cfg.ipv4_cfg().unwrap().vpc_subnet),
        RouterTarget::VpcSubnet(IpCidr::Ip4(
            g1_cfg.ipv4_cfg().unwrap().vpc_subnet,
        )),
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules_out"]);

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
    incr!(g1, ["epoch", "fw.rules_in"]);
    g1.port.start();
    set_state!(g1, PortState::Running);

    // Add router entry that allows g2 to send to other guests on same
    // subnet.
    router::add_entry(
        &g2.port,
        IpCidr::Ip4(g2_cfg.ipv4_cfg().unwrap().vpc_subnet),
        RouterTarget::VpcSubnet(IpCidr::Ip4(
            g2_cfg.ipv4_cfg().unwrap().vpc_subnet,
        )),
    )
    .unwrap();
    incr!(g2, ["epoch", "router.rules_out"]);
    g2.port.start();
    set_state!(g2, PortState::Running);

    // ================================================================
    // Send the HTTP SYN.
    // ================================================================
    let mut pkt1 = http_tcp_syn(&g2_cfg, &g1_cfg);
    let res = g2.port.process(Out, &mut pkt1, &mut g2_ameta);
    assert!(matches!(res, Ok(Modified)));
    incr!(g2, ["fw.flows_out", "fw.flows_in", "uft.flows_out"]);

    let res = g1.port.process(In, &mut pkt1, &mut g1_ameta);
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["fw.flows_in", "fw.flows_out", "uft.flows_in"]);

    // ================================================================
    // Pause the port and verify the internal state. Make sure that
    // introspective APIs are allowed.
    // ================================================================
    g2.port.pause().unwrap();
    set_state!(g2, PortState::Paused);
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
    let res = g2.port.process(Out, &mut pkt1, &mut g2_ameta);
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
    set_state!(g2, PortState::Running);

    let mut pkt2 = http_tcp_syn_ack(&g1_cfg, &g2_cfg);
    g1_ameta.clear();
    let res = g1.port.process(Out, &mut pkt2, &mut g1_ameta);
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["uft.flows_out"]);

    g2_ameta.clear();
    let res = g2.port.process(In, &mut pkt2, &mut g2_ameta);
    assert!(matches!(res, Ok(Modified)));
    incr!(g2, ["uft.flows_in"]);
}

#[test]
fn add_remove_fw_rule() {
    let g1_cfg = g1_cfg();
    let v2p = Arc::new(Virt2Phys::new());
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, v2p.clone());
    g1.port.start();
    set_state!(g1, PortState::Running);

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
    incr!(g1, ["epoch", "fw.rules_in"]);

    // Remove the rule just added, by ID.
    firewall::rem_fw_rule(
        &g1.port,
        &oxide_vpc::api::RemFwRuleReq {
            port_name: g1.port.name().to_string(),
            dir: In,
            id: 1,
        },
    )
    .unwrap();
    update!(g1, ["incr:epoch", "decr:fw.rules_in"]);
}

enum IcmpEchoType {
    Req,
    Reply,
}

fn gen_icmp_echo_req(
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: IpAddr,
    ip_dst: IpAddr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
) -> Packet<Parsed> {
    match (ip_src, ip_dst) {
        (IpAddr::Ip4(src), IpAddr::Ip4(dst)) => {
            gen_icmpv4_echo_req(eth_src, eth_dst, src, dst, ident, seq_no, data)
        }
        (IpAddr::Ip6(src), IpAddr::Ip6(dst)) => {
            gen_icmpv6_echo_req(eth_src, eth_dst, src, dst, ident, seq_no, data)
        }
        (_, _) => panic!("IP src and dst versions must match"),
    }
}

fn gen_icmpv4_echo_req(
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: Ipv4Addr,
    ip_dst: Ipv4Addr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
) -> Packet<Parsed> {
    let etype = IcmpEchoType::Req;
    gen_icmp_echo(etype, eth_src, eth_dst, ip_src, ip_dst, ident, seq_no, data)
}

fn gen_icmp_echo_reply(
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: Ipv4Addr,
    ip_dst: Ipv4Addr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
) -> Packet<Parsed> {
    let etype = IcmpEchoType::Reply;
    gen_icmp_echo(etype, eth_src, eth_dst, ip_src, ip_dst, ident, seq_no, data)
}

fn gen_icmp_echo(
    etype: IcmpEchoType,
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: Ipv4Addr,
    ip_dst: Ipv4Addr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
) -> Packet<Parsed> {
    let icmp = match etype {
        IcmpEchoType::Req => Icmpv4Repr::EchoRequest { ident, seq_no, data },
        IcmpEchoType::Reply => Icmpv4Repr::EchoReply { ident, seq_no, data },
    };
    let mut icmp_bytes = vec![0u8; icmp.buffer_len()];
    let mut icmp_pkt = Icmpv4Packet::new_unchecked(&mut icmp_bytes);
    let _ = icmp.emit(&mut icmp_pkt, &Default::default());

    let mut ip4 = Ipv4Hdr::from(&Ipv4Meta {
        src: ip_src,
        dst: ip_dst,
        proto: Protocol::ICMP,
    });
    ip4.set_total_len(ip4.hdr_len() as u16 + icmp.buffer_len() as u16);
    ip4.compute_hdr_csum();
    let eth = EtherHdr::from(&EtherMeta {
        dst: eth_dst,
        src: eth_src,
        ether_type: ETHER_TYPE_IPV4,
    });

    let mut pkt_bytes =
        Vec::with_capacity(EtherHdr::SIZE + ip4.hdr_len() + icmp.buffer_len());
    pkt_bytes.extend_from_slice(&eth.as_bytes());
    pkt_bytes.extend_from_slice(&ip4.as_bytes());
    pkt_bytes.extend_from_slice(&icmp_bytes);
    Packet::copy(&pkt_bytes).parse().unwrap()
}

fn gen_icmpv6_echo_req(
    eth_src: MacAddr,
    eth_dst: MacAddr,
    ip_src: Ipv6Addr,
    ip_dst: Ipv6Addr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
) -> Packet<Parsed> {
    let req = Icmpv6Repr::EchoRequest { ident, seq_no, data };
    let mut body_bytes = vec![0u8; req.buffer_len()];
    let mut req_pkt = Icmpv6Packet::new_unchecked(&mut body_bytes);
    let _ = req.emit(
        &Ipv6Address::from_bytes(&ip_src).into(),
        &Ipv6Address::from_bytes(&ip_dst).into(),
        &mut req_pkt,
        &Default::default(),
    );
    let mut ip6 = Ipv6Hdr::from(&Ipv6Meta {
        src: ip_src,
        dst: ip_dst,
        proto: Protocol::ICMPv6,
    });
    ip6.set_total_len(ip6.hdr_len() as u16 + req.buffer_len() as u16);
    let eth = EtherHdr::from(&EtherMeta {
        dst: eth_dst,
        src: eth_src,
        ether_type: ETHER_TYPE_IPV6,
    });

    let mut pkt_bytes =
        Vec::with_capacity(EtherHdr::SIZE + ip6.hdr_len() + req.buffer_len());
    pkt_bytes.extend_from_slice(&eth.as_bytes());
    pkt_bytes.extend_from_slice(&ip6.as_bytes());
    pkt_bytes.extend_from_slice(&body_bytes);
    Packet::copy(&pkt_bytes).parse().unwrap()
}

// Verify that the guest can ping the virtual gateway.
#[test]
fn gateway_icmp4_ping() {
    let g1_cfg = g1_cfg();
    let v2p = Arc::new(Virt2Phys::new());
    let mut ameta = ActionMeta::new();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, v2p.clone());
    g1.port.start();
    set_state!(g1, PortState::Running);
    let mut pcap = PcapBuilder::new("gateway_icmpv4_ping.pcap");
    let ident = 7;
    let seq_no = 777;
    let data = b"reunion\0";

    // ================================================================
    // Generate an ICMP Echo Request from G1 to Virtual GW
    // ================================================================
    let mut pkt1 = gen_icmp_echo_req(
        g1_cfg.private_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip.into(),
        g1_cfg.ipv4_cfg().unwrap().gateway_ip.into(),
        ident,
        seq_no,
        &data[..],
    );
    pcap.add_pkt(&pkt1);

    // ================================================================
    // Run the Echo Request through g1's port in the outbound
    // direction and verify it results in an Echo Reply Hairpin packet
    // back to guest.
    // ================================================================
    let res = g1.port.process(Out, &mut pkt1, &mut ameta);
    let hp = match res {
        Ok(Hairpin(hp)) => hp,
        _ => panic!("expected Hairpin, got {:?}", res),
    };
    assert_port!(g1);

    let reply = hp.parse().unwrap();
    pcap.add_pkt(&reply);

    // Ether + IPv4
    assert_eq!(reply.body_offset(), 14 + 20);
    assert_eq!(reply.body_seg(), 0);

    let meta = reply.meta();
    assert!(meta.outer.ether.is_none());
    assert!(meta.outer.ip.is_none());
    assert!(meta.outer.ulp.is_none());

    match meta.inner.ether.as_ref() {
        Some(eth) => {
            assert_eq!(eth.src, g1_cfg.gateway_mac);
            assert_eq!(eth.dst, g1_cfg.private_mac);
        }

        None => panic!("no inner ether header"),
    }

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
    let g2_phys =
        GuestPhysAddr { ether: g2_cfg.private_mac.into(), ip: g2_cfg.phys_ip };

    // Add V2P mappings that allow guests to resolve each others
    // physical addresses.
    let v2p = Arc::new(Virt2Phys::new());
    v2p.set(IpAddr::Ip4(g2_cfg.ipv4_cfg().unwrap().private_ip), g2_phys);
    let mut ameta = ActionMeta::new();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, v2p.clone());
    g1.port.start();
    set_state!(g1, PortState::Running);
    let mut pkt1 = http_tcp_syn(&g1_cfg, &g2_cfg);
    let res = g1.port.process(Out, &mut pkt1, &mut ameta);
    assert!(matches!(res, Ok(ProcessResult::Drop { .. })));
    // XXX The firewall layer comes before the router layer (in the
    // outbound direction). The firewall layer allows this traffic;
    // and a flow is created, regardless of the fact that a later
    // layer decides to drop the packet. This means that a flow could
    // take up space in some of the layers even though no traffic can
    // actually flow through it. In the future it would be better to
    // have a way to send "simulated" flow through the layer pipeline
    // for the effect of removing it from any flow tables in which it
    // exists.
    incr!(g1, ["fw.flows_out", "fw.flows_in"]);
    assert_port!(g1);
}

// Verify that two guests on the same VPC can communicate.
#[test]
fn guest_to_guest() {
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let g2_phys =
        GuestPhysAddr { ether: g2_cfg.private_mac.into(), ip: g2_cfg.phys_ip };

    // Add V2P mappings that allow guests to resolve each others
    // physical addresses.
    let v2p = Arc::new(Virt2Phys::new());
    v2p.set(IpAddr::Ip4(g2_cfg.ipv4_cfg().unwrap().private_ip), g2_phys);
    let mut ameta = ActionMeta::new();

    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, v2p.clone());
    g1.port.start();
    set_state!(g1, PortState::Running);

    // Add router entry that allows Guest 1 to send to Guest 2.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4(g2_cfg.ipv4_cfg().unwrap().vpc_subnet),
        RouterTarget::VpcSubnet(IpCidr::Ip4(
            g2_cfg.ipv4_cfg().unwrap().vpc_subnet,
        )),
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules_out"]);

    let mut g2 = oxide_net_setup("g2_port", &g2_cfg, v2p.clone());
    g2.port.start();
    set_state!(g2, PortState::Running);

    // Add router entry that allows Guest 2 to send to Guest 1.
    //
    // XXX I just realized that it might make sense to move the router
    // tables up to a global level like the Virt2Phys mappings. This
    // way a new router entry that applies to many guests can placed
    // once instead of on each port individually.
    router::add_entry(
        &g2.port,
        IpCidr::Ip4(g1_cfg.ipv4_cfg().unwrap().vpc_subnet),
        RouterTarget::VpcSubnet(IpCidr::Ip4(
            g1_cfg.ipv4_cfg().unwrap().vpc_subnet,
        )),
    )
    .unwrap();
    incr!(g2, ["epoch", "router.rules_out"]);

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
    incr!(g2, ["epoch", "fw.rules_in"]);

    let mut pcap_guest1 =
        PcapBuilder::new("overlay_guest_to_guest-guest-1.pcap");
    let mut pcap_phys1 = PcapBuilder::new("overlay_guest_to_guest-phys-1.pcap");

    let mut pcap_guest2 =
        PcapBuilder::new("overlay_guest_to_guest-guest-2.pcap");
    let mut pcap_phys2 = PcapBuilder::new("overlay_guest_to_guest-phys-2.pcap");

    let mut pkt1 = http_tcp_syn(&g1_cfg, &g2_cfg);
    pcap_guest1.add_pkt(&pkt1);

    // ================================================================
    // Run the packet through g1's port in the outbound direction and
    // verify the resulting packet meets expectations.
    // ================================================================
    let res = g1.port.process(Out, &mut pkt1, &mut ameta);
    pcap_phys1.add_pkt(&pkt1);
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["fw.flows_out", "fw.flows_in", "uft.flows_out"]);

    // Ether + IPv6 + UDP + Geneve + Ether + IPv4 + TCP
    assert_eq!(pkt1.body_offset(), 14 + 40 + 8 + 8 + 14 + 20 + 20);
    assert_eq!(pkt1.body_seg(), 1);

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

    match meta.outer.ulp.as_ref().unwrap() {
        UlpMeta::Udp(udp) => {
            assert_eq!(udp.src, 7777);
            assert_eq!(udp.dst, geneve::GENEVE_PORT);
        }

        ulp => panic!("expected outer UDP metadata, got: {:?}", ulp),
    }

    match meta.outer.encap.as_ref() {
        Some(geneve) => {
            assert_eq!(geneve.vni, Vni::new(g1_cfg.vni).unwrap());
        }

        None => panic!("expected outer Geneve metadata"),
    }

    match meta.inner.ether.as_ref() {
        Some(eth) => {
            assert_eq!(eth.src, g1_cfg.private_mac);
            assert_eq!(eth.dst, g2_cfg.private_mac);
            assert_eq!(eth.ether_type, ETHER_TYPE_IPV4);
        }

        None => panic!("expected inner Ether header"),
    }

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
    let mblk = pkt1.unwrap();
    let mut pkt2 =
        unsafe { Packet::<Initialized>::wrap(mblk).parse().unwrap() };
    pcap_phys2.add_pkt(&pkt2);

    let res = g2.port.process(In, &mut pkt2, &mut ameta);
    pcap_guest2.add_pkt(&pkt2);
    assert!(matches!(res, Ok(Modified)));
    incr!(g2, ["fw.flows_in", "fw.flows_out", "uft.flows_in"]);

    // Ether + IPv4 + TCP
    assert_eq!(pkt2.body_offset(), 14 + 20 + 20);
    assert_eq!(pkt2.body_seg(), 1);

    let g2_meta = pkt2.meta();
    assert!(g2_meta.outer.ether.is_none());
    assert!(g2_meta.outer.ip.is_none());
    assert!(g2_meta.outer.ulp.is_none());
    assert!(g2_meta.outer.encap.is_none());

    match g2_meta.inner.ether.as_ref() {
        Some(eth) => {
            assert_eq!(eth.src, g1_cfg.private_mac);
            assert_eq!(eth.dst, g2_cfg.private_mac);
            assert_eq!(eth.ether_type, ETHER_TYPE_IPV4);
        }

        None => panic!("expected inner Ether header"),
    }

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

    let g1_phys =
        GuestPhysAddr { ether: g1_cfg.private_mac.into(), ip: g1_cfg.phys_ip };

    // Add V2P mappings that allow guests to resolve each others
    // physical addresses. In this case the only guest in VNI 99 is
    // g1.
    let v2p = Arc::new(Virt2Phys::new());
    v2p.set(IpAddr::Ip4(g1_cfg.ipv4_cfg().unwrap().private_ip), g1_phys);
    let mut ameta = ActionMeta::new();

    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, v2p.clone());
    g1.port.start();
    set_state!(g1, PortState::Running);

    // Add router entry that allows g1 to talk to any other guest on
    // its VPC subnet.
    //
    // In this case both g1 and g2 have the same subnet. However, g1
    // is part of VNI 99, and g2 is part of VNI 100. Without a VPC
    // Peering Gateway they have no way to reach each other.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4(g1_cfg.ipv4_cfg().unwrap().vpc_subnet),
        RouterTarget::VpcSubnet(IpCidr::Ip4(
            g1_cfg.ipv4_cfg().unwrap().vpc_subnet,
        )),
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules_out"]);

    let mut g2 = oxide_net_setup("g2_port", &g2_cfg, v2p.clone());
    g2.port.start();
    set_state!(g2, PortState::Running);

    // Add router entry that allows Guest 2 to send to Guest 1.
    //
    // XXX I just realized that it might make sense to move the router
    // tables up to a global level like the Virt2Phys mappings. This
    // way a new router entry that applies to many guests can placed
    // once instead of on each port individually.
    router::add_entry(
        &g2.port,
        IpCidr::Ip4(g1_cfg.ipv4_cfg().unwrap().vpc_subnet),
        RouterTarget::VpcSubnet(IpCidr::Ip4(
            g1_cfg.ipv4_cfg().unwrap().vpc_subnet,
        )),
    )
    .unwrap();
    incr!(g2, ["epoch", "router.rules_out"]);

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
    incr!(g2, ["epoch", "fw.rules_in"]);

    // ================================================================
    // Run the packet through g1's port in the outbound direction and
    // verify the packet is dropped.
    // ================================================================
    let mut g1_pkt = http_tcp_syn(&g1_cfg, &g2_cfg);
    let res = g1.port.process(Out, &mut g1_pkt, &mut ameta);
    assert!(matches!(res, Ok(ProcessResult::Drop { .. })));
    incr!(g1, ["fw.flows_in", "fw.flows_out"]);
}

// Verify that a guest can communicate with the internet.
#[test]
fn guest_to_internet() {
    let g1_cfg = g1_cfg();
    let v2p = Arc::new(Virt2Phys::new());
    let mut ameta = ActionMeta::new();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, v2p.clone());
    g1.port.start();
    set_state!(g1, PortState::Running);

    // Add router entry that allows g1 to route to internet.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4("0.0.0.0/0".parse().unwrap()),
        RouterTarget::InternetGateway,
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules_out"]);

    // ================================================================
    // Generate a TCP SYN packet from g1 to zinascii.com
    // ================================================================
    let dst_ip = "52.10.128.69".parse().unwrap();
    let mut pkt1 = http_tcp_syn2(
        g1_cfg.private_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip,
        dst_ip,
    );

    // ================================================================
    // Run the packet through g1's port in the outbound direction and
    // verify the resulting packet meets expectations.
    // ================================================================
    let res = g1.port.process(Out, &mut pkt1, &mut ameta);
    assert!(matches!(res, Ok(Modified)), "bad result: {:?}", res);
    incr!(
        g1,
        [
            "fw.flows_out",
            "fw.flows_in",
            "nat.flows_out",
            "nat.flows_in",
            "uft.flows_out"
        ]
    );

    // Ether + IPv6 + UDP + Geneve + Ether + IPv4 + TCP
    assert_eq!(pkt1.body_offset(), 14 + 40 + 8 + 8 + 14 + 20 + 20);
    assert_eq!(pkt1.body_seg(), 1);
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
            assert_eq!(ip6.dst, g1_cfg.boundary_services.ip);
        }

        val => panic!("expected outer IPv6, got: {:?}", val),
    }

    match meta.outer.ulp.as_ref().unwrap() {
        UlpMeta::Udp(udp) => {
            assert_eq!(udp.src, 7777);
            assert_eq!(udp.dst, geneve::GENEVE_PORT);
        }

        ulp => panic!("expected outer UDP metadata, got: {:?}", ulp),
    }

    match meta.outer.encap.as_ref() {
        Some(geneve) => {
            assert_eq!(geneve.vni, g1_cfg.boundary_services.vni);
        }

        None => panic!("expected outer Geneve metadata"),
    }

    match meta.inner.ether.as_ref() {
        Some(eth) => {
            assert_eq!(eth.src, g1_cfg.private_mac);
            assert_eq!(eth.dst, g1_cfg.boundary_services.mac);
            assert_eq!(eth.ether_type, ETHER_TYPE_IPV4);
        }

        None => panic!("expected inner Ether header"),
    }

    match meta.inner.ip.as_ref().unwrap() {
        IpMeta::Ip4(ip4) => {
            assert_eq!(ip4.src, g1_cfg.snat().external_ip);
            assert_eq!(ip4.dst, dst_ip);
            assert_eq!(ip4.proto, Protocol::TCP);
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
}

// Verify that an ICMP Echo request has its identifier rewritten by
// SNAT.
#[test]
fn snat_icmp4_echo_rewrite() {
    let g1_cfg = g1_cfg();
    let v2p = Arc::new(Virt2Phys::new());
    let mut ameta = ActionMeta::new();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, v2p.clone());
    g1.port.start();
    set_state!(g1, PortState::Running);
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
    incr!(g1, ["epoch", "router.rules_out"]);
    let mapped_port = g1_cfg.snat().ports.clone().rev().next().unwrap();

    // ================================================================
    // Verify echo request rewrite.
    // ================================================================
    let mut pkt1 = gen_icmp_echo_req(
        g1_cfg.private_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4().private_ip.into(),
        dst_ip.into(),
        ident,
        seq_no,
        &data[..],
    );

    let res = g1.port.process(Out, &mut pkt1, &mut ameta);
    assert!(matches!(res, Ok(Modified)), "bad result: {:?}", res);
    incr!(
        g1,
        [
            "fw.flows_out",
            "fw.flows_in",
            "nat.flows_out",
            "nat.flows_in",
            "uft.flows_out"
        ]
    );

    assert_eq!(pkt1.body_offset(), VPC_ENCAP_SZ + IP_SZ);
    assert_eq!(pkt1.body_seg(), 1);
    let meta = pkt1.meta();

    match meta.inner.ether.as_ref() {
        Some(eth) => {
            assert_eq!(eth.src, g1_cfg.private_mac);
            assert_eq!(eth.dst, g1_cfg.boundary_services.mac);
            assert_eq!(eth.ether_type, ETHER_TYPE_IPV4);
        }

        None => panic!("expected inner Ether header"),
    }

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
        g1_cfg.private_mac,
        dst_ip,
        g1_cfg.snat().external_ip,
        mapped_port,
        seq_no,
        &data[..],
    );

    let res = g1.port.process(In, &mut pkt2, &mut ameta);
    assert!(matches!(res, Ok(Modified)), "bad result: {:?}", res);
    incr!(g1, ["uft.flows_in"]);
    assert_eq!(pkt2.body_offset(), IP_SZ);
    assert_eq!(pkt2.body_seg(), 1);
    let meta = pkt2.meta();

    match meta.inner.ether.as_ref() {
        Some(eth) => {
            assert_eq!(eth.src, g1_cfg.boundary_services.mac);
            assert_eq!(eth.dst, g1_cfg.private_mac);
            assert_eq!(eth.ether_type, ETHER_TYPE_IPV4);
        }

        None => panic!("expected inner Ether header"),
    }

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
        g1_cfg.private_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4().private_ip.into(),
        dst_ip.into(),
        ident,
        seq_no,
        &data[..],
    );

    assert_eq!(g1.port.stats_snap().out_uft_hit, 0);
    let res = g1.port.process(Out, &mut pkt3, &mut ameta);
    assert!(matches!(res, Ok(Modified)), "bad result: {:?}", res);
    assert_port!(g1);
    assert_eq!(pkt3.body_offset(), VPC_ENCAP_SZ + IP_SZ);
    assert_eq!(pkt3.body_seg(), 1);
    let meta = pkt3.meta();

    match meta.inner.ether.as_ref() {
        Some(eth) => {
            assert_eq!(eth.src, g1_cfg.private_mac);
            assert_eq!(eth.dst, g1_cfg.boundary_services.mac);
            assert_eq!(eth.ether_type, ETHER_TYPE_IPV4);
        }

        None => panic!("expected inner Ether header"),
    }

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
        g1_cfg.private_mac,
        dst_ip,
        g1_cfg.snat().external_ip,
        mapped_port,
        seq_no,
        &data[..],
    );

    assert_eq!(g1.port.stats_snap().in_uft_hit, 0);
    let res = g1.port.process(In, &mut pkt4, &mut ameta);
    assert!(matches!(res, Ok(Modified)), "bad result: {:?}", res);
    assert_port!(g1);
    assert_eq!(pkt4.body_offset(), IP_SZ);
    assert_eq!(pkt4.body_seg(), 1);
    let meta = pkt4.meta();

    match meta.inner.ether.as_ref() {
        Some(eth) => {
            assert_eq!(eth.src, g1_cfg.boundary_services.mac);
            assert_eq!(eth.dst, g1_cfg.private_mac);
            assert_eq!(eth.ether_type, ETHER_TYPE_IPV4);
        }

        None => panic!("expected inner Ether header"),
    }

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
    let pkt = Packet::alloc(42);

    let ether = EtherHdr::from(&EtherMeta {
        src: cfg.private_mac,
        dst: MacAddr::BROADCAST,
        ether_type: ETHER_TYPE_IPV4,
    });

    let mut ip = Ipv4Hdr::from(&Ipv4Meta {
        src: "0.0.0.0".parse().unwrap(),
        dst: Ipv4Addr::LOCAL_BCAST,
        proto: Protocol::UDP,
    });

    // We write a total legnth of 4 bytes, which is completely bogus
    // for an IP header and should return an error during processing.
    ip.set_total_len(4);

    let udp = UdpHdr::from(&UdpMeta { src: 68, dst: 67 });

    let mut wtr = PacketWriter::new(pkt, None);
    let _ = wtr.write(&ether.as_bytes()).unwrap();
    let _ = wtr.write(&ip.as_bytes()).unwrap();
    let _ = wtr.write(&udp.as_bytes()).unwrap();
    let res = wtr.finish().parse();
    assert_eq!(
        res.err().unwrap(),
        ParseError::BadHeader("IPv4: BadTotalLen { total_len: 4 }".to_string())
    );

    let pkt = Packet::alloc(42);

    let ether = EtherHdr::from(&EtherMeta {
        src: cfg.private_mac,
        dst: MacAddr::BROADCAST,
        ether_type: ETHER_TYPE_IPV4,
    });

    let mut ip = Ipv4Hdr::from(&Ipv4Meta {
        src: "0.0.0.0".parse().unwrap(),
        dst: Ipv4Addr::LOCAL_BCAST,
        proto: Protocol::UDP,
    });

    // We write an incorrect total legnth of 40 bytes, but the real
    // total length should only be 28 bytes.
    ip.set_total_len(40);

    let udp = UdpHdr::from(&UdpMeta { src: 68, dst: 67 });

    let mut wtr = PacketWriter::new(pkt, None);
    let _ = wtr.write(&ether.as_bytes()).unwrap();
    let _ = wtr.write(&ip.as_bytes()).unwrap();
    let _ = wtr.write(&udp.as_bytes()).unwrap();
    let res = wtr.finish().parse();
    assert_eq!(
        res.err().unwrap(),
        ParseError::BadInnerIpLen { expected: 8, actual: 20 }
    );
}

// Verify that OPTE generates a hairpin ARP reply when the guest
// queries for the gateway.
#[test]
fn arp_gateway() {
    use opte::engine::arp::ArpOp;
    use opte::engine::ether::ETHER_TYPE_IPV4;

    let cfg = g1_cfg();
    let mut ameta = ActionMeta::new();
    let v2p = Arc::new(Virt2Phys::new());
    let mut g1 = oxide_net_setup("arp_hairpin", &cfg, v2p.clone());
    g1.port.start();
    set_state!(g1, PortState::Running);
    let reply_hdr_sz = EtherHdr::SIZE + ARP_HDR_SZ;

    let pkt = Packet::alloc(42);
    let eth_hdr = EtherHdrRaw {
        dst: [0xff; 6],
        src: cfg.private_mac.bytes(),
        ether_type: [0x08, 0x06],
    };

    let arp_hdr = ArpHdrRaw {
        htype: [0x00, 0x01],
        ptype: [0x08, 0x00],
        hlen: 0x06,
        plen: 0x04,
        op: [0x00, 0x01],
    };

    let arp = ArpEth4Payload {
        sha: cfg.private_mac,
        spa: cfg.ipv4_cfg().unwrap().private_ip,
        tha: MacAddr::from([0x00; 6]),
        tpa: cfg.ipv4_cfg().unwrap().gateway_ip,
    };

    let mut wtr = PacketWriter::new(pkt, None);
    let _ = wtr.write(eth_hdr.as_bytes()).unwrap();
    let _ = wtr.write(arp_hdr.as_bytes()).unwrap();
    let _ = wtr.write(ArpEth4PayloadRaw::from(arp).as_bytes()).unwrap();
    let mut pkt = wtr.finish().parse().unwrap();

    let res = g1.port.process(Out, &mut pkt, &mut ameta);
    match res {
        Ok(Hairpin(hppkt)) => {
            let hppkt = hppkt.parse().unwrap();
            let meta = hppkt.meta();
            let ethm = meta.inner.ether.as_ref().unwrap();
            let arpm = meta.inner.arp.as_ref().unwrap();
            assert_eq!(ethm.dst, cfg.private_mac);
            assert_eq!(ethm.src, cfg.gateway_mac);
            assert_eq!(ethm.ether_type, ETHER_TYPE_ARP);
            assert_eq!(arpm.op, ArpOp::Reply);
            assert_eq!(arpm.ptype, ETHER_TYPE_IPV4);

            let mut rdr = PacketReader::new(&hppkt, ());
            assert!(rdr.seek(reply_hdr_sz).is_ok());
            let arp = ArpEth4Payload::from(
                &ArpEth4PayloadRaw::parse(&mut rdr).unwrap(),
            );

            assert_eq!(arp.sha, cfg.gateway_mac);
            assert_eq!(arp.spa, cfg.ipv4_cfg().unwrap().gateway_ip);
            assert_eq!(arp.tha, cfg.private_mac);
            assert_eq!(arp.tpa, cfg.ipv4_cfg().unwrap().private_ip);
        }

        res => panic!("expected a Hairpin, got {:?}", res),
    }
    assert_port!(g1);
}

#[test]
fn flow_expiration() {
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let g2_phys =
        GuestPhysAddr { ether: g2_cfg.private_mac.into(), ip: g2_cfg.phys_ip };

    // Add V2P mappings that allow guests to resolve each others
    // physical addresses.
    let v2p = Arc::new(Virt2Phys::new());
    v2p.set(IpAddr::Ip4(g2_cfg.ipv4_cfg().unwrap().private_ip), g2_phys);
    let mut ameta = ActionMeta::new();

    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, v2p.clone());
    g1.port.start();
    set_state!(g1, PortState::Running);
    let now = Moment::now();

    // Add router entry that allows Guest 1 to send to Guest 2.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4(g2_cfg.ipv4_cfg().unwrap().vpc_subnet),
        RouterTarget::VpcSubnet(IpCidr::Ip4(
            g2_cfg.ipv4_cfg().unwrap().vpc_subnet,
        )),
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules_out"]);

    // ================================================================
    // Run the packet through g1's port in the outbound direction and
    // verify the resulting packet meets expectations.
    // ================================================================
    let mut pkt1 = http_tcp_syn(&g1_cfg, &g2_cfg);
    let res = g1.port.process(Out, &mut pkt1, &mut ameta);
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["fw.flows_out", "fw.flows_in", "uft.flows_out"]);

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

#[test]
fn firewall_replace_rules() {
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let g2_phys =
        GuestPhysAddr { ether: g2_cfg.private_mac.into(), ip: g2_cfg.phys_ip };

    // Add V2P mappings that allow guests to resolve each others
    // physical addresses.
    let v2p = Arc::new(Virt2Phys::new());
    v2p.set(IpAddr::Ip4(g2_cfg.ipv4_cfg().unwrap().private_ip), g2_phys);
    let mut ameta = ActionMeta::new();

    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, v2p.clone());
    g1.port.start();
    set_state!(g1, PortState::Running);

    // Add router entry that allows Guest 1 to send to Guest 2.
    router::add_entry(
        &g1.port,
        IpCidr::Ip4(g2_cfg.ipv4_cfg().unwrap().vpc_subnet),
        RouterTarget::VpcSubnet(IpCidr::Ip4(
            g2_cfg.ipv4_cfg().unwrap().vpc_subnet,
        )),
    )
    .unwrap();
    incr!(g1, ["epoch", "router.rules_out"]);

    let mut g2 = oxide_net_setup("g2_port", &g2_cfg, v2p.clone());
    g2.port.start();
    set_state!(g2, PortState::Running);

    // Allow incoming TCP connection on g2 from anyone.
    let rule = "dir=in action=allow priority=10 protocol=TCP";
    firewall::add_fw_rule(
        &g2.port,
        &AddFwRuleReq {
            port_name: g2.port.name().to_string(),
            rule: rule.parse().unwrap(),
        },
    )
    .unwrap();
    incr!(g2, ["epoch", "fw.rules_in"]);

    // ================================================================
    // Run the telnet SYN packet through g1's port in the outbound
    // direction and verify if passes the firewall.
    // ================================================================
    let mut pkt1 = http_tcp_syn(&g1_cfg, &g2_cfg);
    let res = g1.port.process(Out, &mut pkt1, &mut ameta);
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["fw.flows_out", "fw.flows_in", "uft.flows_out"]);

    // ================================================================
    // Modify the outgoing ruleset, but still allow the traffic to
    // pass. This test makes sure that flow table entries are updated
    // without issue and everything still works.
    //
    // XXX It would be nice if tests could verify that a probe fires
    // (in this case uft-invalidated) without using dtrace.
    // ================================================================
    let any_out = "dir=out action=deny priority=65535 protocol=any";
    let tcp_out = "dir=out action=allow priority=1000 protocol=TCP";
    firewall::set_fw_rules(
        &g1.port,
        &SetFwRulesReq {
            port_name: g1.port.name().to_string(),
            rules: vec![any_out.parse().unwrap(), tcp_out.parse().unwrap()],
        },
    )
    .unwrap();
    update!(
        g1,
        [
            "incr:epoch",
            "set:fw.flows_in=0,fw.flows_out=0,fw.rules_out=2,fw.rules_in=0"
        ]
    );
    let mut pkt2 = http_tcp_syn(&g1_cfg, &g2_cfg);
    let res = g1.port.process(Out, &mut pkt2, &mut ameta);
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, ["fw.flows_in", "fw.flows_out"]);

    // ================================================================
    // Now that the packet has been encap'd let's play the role of
    // router and send this inbound to g2's port. For maximum fidelity
    // of the real process we first dump the raw bytes of g1's
    // outgoing packet and then reparse it.
    // ================================================================
    let mblk = pkt2.unwrap();
    let mut pkt3 =
        unsafe { Packet::<Initialized>::wrap(mblk).parse().unwrap() };
    let mut pkt3_copy =
        Packet::<Initialized>::copy(&pkt3.all_bytes()).parse().unwrap();
    let res = g2.port.process(In, &mut pkt3, &mut ameta);
    assert!(matches!(res, Ok(Modified)));
    incr!(g2, ["fw.flows_in", "fw.flows_out", "uft.flows_in"]);

    // ================================================================
    // Replace g2's firewall rule set to deny all inbound TCP traffic.
    // Verify the rules have been replaced and retry processing of the
    // g2_pkt, but this time it should be dropped.
    // ================================================================
    let new_rule = "dir=in action=deny priority=1000 protocol=TCP";
    firewall::set_fw_rules(
        &g2.port,
        &SetFwRulesReq {
            port_name: g2.port.name().to_string(),
            rules: vec![new_rule.parse().unwrap()],
        },
    )
    .unwrap();
    update!(
        g2,
        [
            "incr:epoch",
            "set:fw.flows_in=0,fw.flows_out=0,fw.rules_in=1,fw.rules_out=0"
        ]
    );

    // Verify the packet is dropped and that the firewall flow table
    // entry (along with its dual) was invalidated.
    let res = g2.port.process(In, &mut pkt3_copy, &mut ameta);
    use opte::engine::port::DropReason;
    match res {
        Ok(ProcessResult::Drop { reason: DropReason::Layer { name } }) => {
            assert_eq!("firewall", name);
        }

        _ => panic!("expected drop but got: {:?}", res),
    }
    update!(g2, ["set:uft.flows_in=0"]);
}

// Test that a guest can send an ICMPv6 echo request / reply to the gateway.
// This tests both link-local and VPC-private IPv6 source addresses, and the
// only supported destination, OPTE's IPv6 link-local derived from its MAC.
#[test]
fn gateway_icmpv6_ping() {
    let g1_cfg = g1_cfg();
    let v2p = Arc::new(Virt2Phys::new());
    let mut ameta = ActionMeta::new();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, v2p.clone());
    g1.port.start();
    set_state!(g1, PortState::Running);
    let mut pcap = PcapBuilder::new("gateway_icmpv6_ping.pcap");

    let src_ips = [
        Ipv6Addr::from_eui64(&g1_cfg.private_mac),
        g1_cfg.ipv6_cfg().unwrap().private_ip,
    ];
    let dst_ip = Ipv6Addr::from_eui64(&g1_cfg.gateway_mac);
    for src_ip in src_ips.iter().copied() {
        test_guest_to_gateway_icmpv6_ping(
            &g1, &mut ameta, &g1_cfg, &mut pcap, src_ip, dst_ip,
        );
    }
}

fn test_guest_to_gateway_icmpv6_ping(
    g1: &PortAndVps,
    ameta: &mut ActionMeta,
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
        g1_cfg.private_mac,
        g1_cfg.gateway_mac,
        src_ip.into(),
        dst_ip.into(),
        ident,
        seq_no,
        &data[..],
    );
    pcap.add_pkt(&pkt1);

    // ================================================================
    // Run the Echo Request through g1's port in the outbound
    // direction and verify it results in an Echo Reply Hairpin packet
    // back to guest.
    // ================================================================
    let res = g1.port.process(Out, &mut pkt1, ameta);
    let hp = match res {
        Ok(Hairpin(hp)) => hp,
        _ => panic!("expected Hairpin, got {:?}", res),
    };
    assert_port!(g1);

    let reply = hp.parse().unwrap();
    pcap.add_pkt(&reply);

    // Ether + IPv6
    assert_eq!(reply.body_offset(), EtherHdr::SIZE + Ipv6Hdr::SIZE);
    assert_eq!(reply.body_seg(), 0);

    let meta = reply.meta();
    assert!(meta.outer.ether.is_none());
    assert!(meta.outer.ip.is_none());
    assert!(meta.outer.ulp.is_none());

    match meta.inner.ether.as_ref() {
        Some(eth) => {
            assert_eq!(eth.src, g1_cfg.gateway_mac);
            assert_eq!(eth.dst, g1_cfg.private_mac);
        }

        None => panic!("no inner ether header"),
    }

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

    let rdr = reply.get_body_rdr();
    let reply_body = rdr.copy_remaining();
    let reply_pkt = Icmpv6Packet::new_checked(&reply_body).unwrap();
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
    let _ = req.emit(
        &IpAddress::Ipv6(src_ip.into()),
        &IpAddress::Ipv6(dst_ip.into()),
        &mut req_pkt,
        &csum,
    );
    let mut ip6 = Ipv6Hdr::from(&Ipv6Meta {
        src: src_ip,
        dst: dst_ip,
        proto: Protocol::ICMPv6,
    });
    ip6.set_total_len(ip6.hdr_len() as u16 + req.buffer_len() as u16);
    let eth = EtherHdr::from(&EtherMeta {
        dst: dst_mac,
        src: *src_mac,
        ether_type: ETHER_TYPE_IPV6,
    });

    let mut pkt_bytes =
        Vec::with_capacity(EtherHdr::SIZE + ip6.hdr_len() + req.buffer_len());
    pkt_bytes.extend_from_slice(&eth.as_bytes());
    pkt_bytes.extend_from_slice(&ip6.as_bytes());
    pkt_bytes.extend_from_slice(&body_bytes);
    Packet::copy(&pkt_bytes).parse().unwrap()
}

// Verify that a Router Solicitation emitted from the guest results in a Router
// Advertisement from the gateway. This tests both a solicitation sent to the
// router's unicast address, or its solicited-node multicast address.
#[test]
fn gateway_router_advert_reply() {
    use smoltcp::time::Duration;

    let g1_cfg = g1_cfg();
    let v2p = Arc::new(Virt2Phys::new());
    let mut ameta = ActionMeta::new();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, v2p.clone());
    g1.port.start();
    set_state!(g1, PortState::Running);
    let mut pcap = PcapBuilder::new("gateway_router_advert_reply.pcap");

    // ====================================================
    // Generate a Router Solicitation from G1 to Virtual GW
    // ====================================================
    let mut pkt1 = gen_router_solicitation(&g1_cfg.private_mac);
    pcap.add_pkt(&pkt1);

    // ================================================================
    // Run the Solicitation through g1's port in the outbound
    // direction and verify it results in an Router Advertisement
    // hairpin back to guest.
    // ================================================================
    let res = g1.port.process(Out, &mut pkt1, &mut ameta);
    let hp = match res {
        Ok(Hairpin(hp)) => hp,
        _ => panic!("expected Hairpin, got {:?}", res),
    };
    assert_port!(g1);

    let reply = hp.parse().unwrap();
    pcap.add_pkt(&reply);

    // Ether + IPv6
    assert_eq!(reply.body_offset(), EtherHdr::SIZE + Ipv6Hdr::SIZE);
    assert_eq!(reply.body_seg(), 0);

    let meta = reply.meta();
    assert!(meta.outer.ether.is_none());
    assert!(meta.outer.ip.is_none());
    assert!(meta.outer.ulp.is_none());

    match meta.inner.ether.as_ref() {
        Some(eth) => {
            assert_eq!(
                eth.src, g1_cfg.gateway_mac,
                "Router advertisement should come from the gateway's MAC"
            );
            assert_eq!(
                eth.dst, g1_cfg.private_mac,
                "Router advertisement should be destined for the guest's MAC"
            );
        }

        None => panic!("no inner ether header"),
    }

    let (src, dst) = match meta.inner.ip.as_ref().unwrap() {
        IpMeta::Ip6(ip6) => {
            assert_eq!(
                ip6.src,
                Ipv6Addr::from_eui64(&g1_cfg.gateway_mac),
                "Router advertisement should come from the \
                gateway's link-local IPv6 address, generated \
                from the EUI-64 transform of its MAC",
            );
            let expected_dst = Ipv6Addr::from_eui64(&g1_cfg.private_mac);
            assert_eq!(
                ip6.dst, expected_dst,
                "Router advertisement should be destined for \
                the guest's Link-Local IPv6 address, generated from \
                the EUI-64 transform of its MAC"
            );
            assert_eq!(ip6.proto, Protocol::ICMPv6);
            (
                Ipv6Address::from_bytes(&ip6.src),
                Ipv6Address::from_bytes(&expected_dst),
            )
        }
        ip4 => panic!("expected inner IPv6 metadata, got IPv4: {:?}", ip4),
    };

    let rdr = reply.get_body_rdr();
    let reply_body = rdr.copy_remaining();
    let reply_pkt = Icmpv6Packet::new_checked(&reply_body).unwrap();
    let mut csum = CsumCapab::ignored();
    csum.icmpv6 = smoltcp::phy::Checksum::Rx;
    let reply_icmp =
        Icmpv6Repr::parse(&src.into(), &dst.into(), &reply_pkt, &csum).unwrap();
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
fn generate_neighbor_solicitation(info: &SolicitInfo) -> Packet<Parsed> {
    let solicit = NdiscRepr::NeighborSolicit {
        target_addr: Ipv6Address::from(info.target_addr),
        lladdr: info.lladdr.map(|x| RawHardwareAddress::from_bytes(&x)),
    };
    let req = Icmpv6Repr::Ndisc(solicit);
    let mut body = vec![0u8; req.buffer_len()];
    let mut req_pkt = Icmpv6Packet::new_unchecked(&mut body);
    let mut csum = CsumCapab::ignored();
    csum.icmpv6 = smoltcp::phy::Checksum::Tx;
    let _ = req.emit(
        &IpAddress::Ipv6(info.src_ip.into()),
        &IpAddress::Ipv6(info.dst_ip.into()),
        &mut req_pkt,
        &csum,
    );
    let mut ip6 = Ipv6Hdr::from(&Ipv6Meta {
        src: info.src_ip,
        dst: info.dst_ip,
        proto: Protocol::ICMPv6,
    });
    ip6.set_total_len(ip6.hdr_len() as u16 + req.buffer_len() as u16);
    let eth = EtherHdr::from(&EtherMeta {
        dst: info.dst_mac,
        src: info.src_mac,
        ether_type: ETHER_TYPE_IPV6,
    });

    let mut pkt_bytes =
        Vec::with_capacity(EtherHdr::SIZE + ip6.hdr_len() + req.buffer_len());
    pkt_bytes.extend_from_slice(&eth.as_bytes());
    pkt_bytes.extend_from_slice(&ip6.as_bytes());
    pkt_bytes.extend_from_slice(&body);
    Packet::copy(&pkt_bytes).parse().unwrap()
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
                src_mac: cfg.private_mac,
                dst_mac: Ipv6Addr::from_eui64(&cfg.private_mac)
                    .solicited_node_multicast()
                    .unchecked_multicast_mac(),
                src_ip: Ipv6Addr::ANY_ADDR,
                dst_ip: Ipv6Addr::from_eui64(&cfg.private_mac)
                    .solicited_node_multicast(),
                target_addr: Ipv6Addr::from_eui64(&cfg.private_mac),
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
                src_mac: cfg.private_mac,
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
                src_mac: cfg.private_mac,
                dst_mac: cfg.gateway_mac,
                src_ip: Ipv6Addr::from_eui64(&cfg.private_mac),
                dst_ip: Ipv6Addr::from_eui64(&cfg.gateway_mac),
                target_addr: Ipv6Addr::from_eui64(&cfg.gateway_mac),
                lladdr: Some(cfg.private_mac),
            },
            na: Some(AdvertInfo {
                src_mac: cfg.gateway_mac,
                dst_mac: cfg.private_mac,
                src_ip: Ipv6Addr::from_eui64(&cfg.gateway_mac),
                dst_ip: Ipv6Addr::from_eui64(&cfg.private_mac),
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
                src_mac: cfg.private_mac,
                dst_mac: Ipv6Addr::from_const([0xfe80, 0, 0, 0, 1, 1, 1, 1])
                    .solicited_node_multicast()
                    .unchecked_multicast_mac(),
                src_ip: Ipv6Addr::from_eui64(&cfg.private_mac),
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
    let reply = hp.parse().unwrap();
    pcap.add_pkt(&reply);

    // Verify Ethernet and IPv6 header basics.
    assert_eq!(reply.body_offset(), EtherHdr::SIZE + Ipv6Hdr::SIZE);
    assert_eq!(reply.body_seg(), 0);
    let meta = reply.meta();
    assert!(meta.outer.ether.is_none());
    assert!(meta.outer.ip.is_none());
    assert!(meta.outer.ulp.is_none());

    // Check that the inner MACs are what we expect.
    let eth = meta.inner.ether.as_ref().expect("No inner Ethernet header");
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

    // Validate the details of the Neighbor Advertisement itself.
    let rdr = reply.get_body_rdr();
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
    let v2p = Arc::new(Virt2Phys::new());
    let mut ameta = ActionMeta::new();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, v2p.clone());
    g1.port.start();
    set_state!(g1, PortState::Running);
    let mut pcap = PcapBuilder::new("gateway_neighbor_advert_reply.pcap");

    let data = generate_solicit_test_data(&g1_cfg);
    for d in data.into_iter() {
        let mut pkt = generate_neighbor_solicitation(&d.ns);
        pcap.add_pkt(&pkt);
        let res = g1.port.process(Out, &mut pkt, &mut ameta);
        match (res, d.na) {
            (Ok(ProcessResult::Drop { .. }), None) => {
                // Dropped the packet, as we expected
                continue;
            }
            (Ok(Hairpin(hp)), Some(na)) => {
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
    let eth = EtherHdr::from(&EtherMeta {
        dst: dhcpv6::ALL_RELAYS_AND_SERVERS.multicast_mac().unwrap(),
        src: cfg.private_mac,
        ether_type: ETHER_TYPE_IPV6,
    });

    let mut ip = Ipv6Hdr::from(&Ipv6Meta {
        src: Ipv6Addr::from_eui64(&cfg.private_mac),
        dst: dhcpv6::ALL_RELAYS_AND_SERVERS,
        proto: Protocol::UDP,
    });
    ip.set_pay_len((msg.buffer_len() + UdpHdr::SIZE) as u16);

    let mut udp = UdpHdr::from(&UdpMeta {
        src: dhcpv6::CLIENT_PORT,
        dst: dhcpv6::SERVER_PORT,
    });
    udp.set_pay_len(msg.buffer_len() as u16);

    write_dhcpv6_packet(eth, ip, udp, msg)
}

fn write_dhcpv6_packet<'a>(
    eth: EtherHdr,
    ip: Ipv6Hdr,
    udp: UdpHdr,
    msg: &dhcpv6::protocol::Message<'a>,
) -> Packet<Parsed> {
    // Allocate a buffer into which we'll copy the packet.
    let reply_len =
        msg.buffer_len() + UdpHdr::SIZE + Ipv6Hdr::SIZE + EtherHdr::SIZE;
    let mut buf = vec![0; reply_len];

    // Copy the Ethernet header.
    let mut start = 0;
    let mut end = EtherHdr::SIZE;
    buf[start..end].copy_from_slice(&eth.as_bytes());

    // Copy the IPv6 header.
    start = end;
    end += Ipv6Hdr::SIZE;
    buf[start..end].copy_from_slice(&ip.as_bytes());

    // Copy the UDP header.
    start = end;
    end += UdpHdr::SIZE;
    buf[start..end].copy_from_slice(&udp.as_bytes());

    // Copy in the remainder, which is the DHCPv6 message itself.
    start = end;
    msg.copy_into(&mut buf[start..]).unwrap();

    // Make a packet
    Packet::copy(&buf).parse().unwrap()
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
    let request_ether = request_meta.inner_ether().unwrap();
    let reply_ether = reply_meta.inner_ether().unwrap();
    assert_eq!(
        request_ether.dst,
        dhcpv6::ALL_RELAYS_AND_SERVERS.multicast_mac().unwrap()
    );
    assert_eq!(request_ether.src, reply_ether.dst);

    let request_ip = request_meta.inner_ip6().unwrap();
    let reply_ip = reply_meta.inner_ip6().unwrap();
    assert_eq!(request_ip.src, Ipv6Addr::from_eui64(&cfg.private_mac));
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
    let v2p = Arc::new(Virt2Phys::new());
    let mut ameta = ActionMeta::new();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, v2p.clone());
    g1.port.start();
    set_state!(g1, PortState::Running);
    let mut pcap = PcapBuilder::new("dhcpv6_solicit_reply.pcap");

    let requested_iana = dhcpv6::options::IaNa {
        id: dhcpv6::options::IaId(0xff7),
        t1: dhcpv6::Lifetime(3600),
        t2: dhcpv6::Lifetime(6200),
        options: vec![],
    };
    let base_options = vec![
        dhcpv6::options::Option::ClientId(dhcpv6::Duid::from(
            &g1_cfg.private_mac,
        )),
        dhcpv6::options::Option::ElapsedTime(dhcpv6::options::ElapsedTime(10)),
        dhcpv6::options::Option::IaNa(requested_iana.clone()),
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
            let res =
                g1.port.process(Out, &mut request_pkt, &mut ameta).unwrap();
            if let Hairpin(hp) = res {
                let reply_pkt = hp.parse().unwrap();
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

                // Regardless of the message type, we are supposed to include
                // answers for each Option the client requested (and that we
                // support). That's mostly just the actual VPC-private IPv6 address.
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
            } else {
                panic!("Expected a Hairpin, found {:?}", res);
            }
        }
    }
}

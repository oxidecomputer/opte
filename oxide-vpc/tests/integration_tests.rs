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
use opte::api::{Direction::*, MacAddr, OpteError};
use opte::ddi::time::Moment;
use opte::engine::arp::{
    ArpEth4Payload, ArpEth4PayloadRaw, ArpHdrRaw, ARP_HDR_SZ,
};
use opte::engine::checksum::HeaderChecksum;
use opte::engine::ether::{
    EtherHdr, EtherHdrRaw, EtherMeta, EtherType, ETHER_HDR_SZ, ETHER_TYPE_ARP,
    ETHER_TYPE_IPV4, ETHER_TYPE_IPV6,
};
use opte::engine::flow_table::FLOW_DEF_EXPIRE_SECS;
use opte::engine::geneve::{self, Vni};
use opte::engine::headers::{IpAddr, IpCidr, IpMeta, UlpMeta};
use opte::engine::ip4::{Ipv4Addr, Ipv4Hdr, Ipv4Meta, Protocol, UlpCsumOpt};
use opte::engine::ip6::{Ipv6Addr, Ipv6Hdr, Ipv6Meta, IPV6_HDR_SZ};
use opte::engine::packet::{
    Initialized, Packet, PacketRead, PacketReader, PacketWriter, ParseError,
    Parsed,
};
use opte::engine::port::meta::ActionMeta;
use opte::engine::port::{
    Port, PortBuilder, PortState, ProcessError, ProcessResult,
};
use opte::engine::rule::{self, MappingResource, Rule};
use opte::engine::tcp::{TcpFlags, TcpHdr};
use opte::engine::udp::{UdpHdr, UdpMeta};
use opte::ExecCtx;
use oxide_vpc::api::{
    AddFwRuleReq, FirewallRule, GuestPhysAddr, RouterTarget, SNat4Cfg,
    SNat6Cfg, SetFwRulesReq,
};
use oxide_vpc::api::{BoundaryServices, IpCfg, Ipv4Cfg, Ipv6Cfg, VpcCfg};
use oxide_vpc::engine::overlay::{self, Virt2Phys};
use oxide_vpc::engine::{arp, dhcp, firewall, icmp, icmpv6, nat, router};
use pcap_parser::pcap::{self, LegacyPcapBlock, PcapHeader};
use smoltcp::phy::ChecksumCapabilities as CsumCapab;
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
use pcap_parser::{Linktype, ToVec};
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
        snat_cfg: Some(SNat4Cfg {
            public_ip: "76.76.21.21".parse().unwrap(),
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
    let name_cstr = cstr_core::CString::new(name).unwrap();
    let mut pb =
        PortBuilder::new(name, name_cstr, cfg.private_mac.into(), ectx.clone());

    let fw_limit = NonZeroU32::new(8096).unwrap();
    let snat_limit = NonZeroU32::new(8096).unwrap();
    let one_limit = NonZeroU32::new(1).unwrap();

    firewall::setup(&mut pb, fw_limit).expect("failed to add firewall layer");
    dhcp::setup(&mut pb, cfg, one_limit).expect("failed to add dhcp4 layer");
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
            snat_cfg: Some(SNat4Cfg {
                // NOTE: This is not a routable IP, but remember that a
                // "public IP" for an Oxide guest could either be a
                // public, routable IP or simply an IP on their wider LAN
                // which the oxide Rack is simply a part of.
                public_ip: "10.77.77.13".parse().unwrap(),
                ports: 1025..=4096,
            }),
            external_ips: None,
        },
        ipv6: Ipv6Cfg {
            vpc_subnet: "fd00::/64".parse().unwrap(),
            private_ip: "fd00::5".parse().unwrap(),
            gateway_ip: "fd00::1".parse().unwrap(),
            snat_cfg: Some(SNat6Cfg {
                public_ip: "2001:db8::1".parse().unwrap(),
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
            snat_cfg: Some(SNat4Cfg {
                // NOTE: This is not a routable IP, but remember that a
                // "public IP" for an Oxide guest could either be a
                // public, routable IP or simply an IP on their wider LAN
                // which the oxide Rack is simply a part of.
                public_ip: "10.77.77.23".parse().unwrap(),
                ports: 4096..=8192,
            }),
            external_ips: None,
        },
        ipv6: Ipv6Cfg {
            vpc_subnet: "fd00::/64".parse().unwrap(),
            private_ip: "fd00::5".parse().unwrap(),
            gateway_ip: "fd00::1".parse().unwrap(),
            snat_cfg: Some(SNat6Cfg {
                public_ip: "2001:db8::1".parse().unwrap(),
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
    use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr};

    let req = Icmpv4Repr::EchoRequest { ident, seq_no, data };
    let mut body_bytes = vec![0u8; req.buffer_len()];
    let mut req_pkt = Icmpv4Packet::new_unchecked(&mut body_bytes);
    let _ = req.emit(&mut req_pkt, &Default::default());
    let mut ip4 = Ipv4Hdr::from(&Ipv4Meta {
        src: ip_src,
        dst: ip_dst,
        proto: Protocol::ICMP,
    });
    ip4.set_total_len(ip4.hdr_len() as u16 + req.buffer_len() as u16);
    ip4.compute_hdr_csum();
    let eth = EtherHdr::from(&EtherMeta {
        dst: eth_dst,
        src: eth_src,
        ether_type: ETHER_TYPE_IPV4,
    });

    let mut pkt_bytes =
        Vec::with_capacity(ETHER_HDR_SZ + ip4.hdr_len() + req.buffer_len());
    pkt_bytes.extend_from_slice(&eth.as_bytes());
    pkt_bytes.extend_from_slice(&ip4.as_bytes());
    pkt_bytes.extend_from_slice(&body_bytes);
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
    use smoltcp::wire::{Icmpv6Packet, Icmpv6Repr, Ipv6Address};

    let req = Icmpv6Repr::EchoRequest { ident, seq_no, data };
    let mut body_bytes = vec![0u8; req.buffer_len()];
    let mut req_pkt = Icmpv6Packet::new_unchecked(&mut body_bytes);
    let _ = req.emit(
        &Ipv6Address::from_bytes(ip_src.bytes().as_slice()).into(),
        &Ipv6Address::from_bytes(ip_dst.bytes().as_slice()).into(),
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
        Vec::with_capacity(ETHER_HDR_SZ + ip6.hdr_len() + req.buffer_len());
    pkt_bytes.extend_from_slice(&eth.as_bytes());
    pkt_bytes.extend_from_slice(&ip6.as_bytes());
    pkt_bytes.extend_from_slice(&body_bytes);
    Packet::copy(&pkt_bytes).parse().unwrap()
}

// Verify that the guest can ping the virtual gateway.
#[test]
fn gateway_icmp4_ping() {
    use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr};
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

    let mut rdr = PacketReader::new(&reply, ());
    // Need to seek to body.
    rdr.seek(14 + 20).unwrap();
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
            assert_eq!(
                ip4.src,
                g1_cfg.ipv4_cfg().unwrap().snat_cfg.as_ref().unwrap().public_ip
            );
            assert_eq!(ip4.dst, dst_ip);
            assert_eq!(ip4.proto, Protocol::TCP);
        }

        ip6 => panic!("execpted inner IPv4 metadata, got IPv6: {:?}", ip6),
    }

    match meta.inner.ulp.as_ref().unwrap() {
        UlpMeta::Tcp(tcp) => {
            assert_eq!(
                tcp.src,
                g1_cfg
                    .ipv4_cfg()
                    .unwrap()
                    .snat_cfg
                    .as_ref()
                    .unwrap()
                    .ports
                    .clone()
                    .rev()
                    .next()
                    .unwrap(),
            );
            assert_eq!(tcp.dst, 80);
        }

        ulp => panic!("expected inner TCP metadata, got: {:?}", ulp),
    }
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
    let reply_hdr_sz = ETHER_HDR_SZ + ARP_HDR_SZ;

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
#[test]
fn gateway_icmpv6_ping() {
    use smoltcp::wire::{Icmpv6Packet, Icmpv6Repr, Ipv6Address};

    let g1_cfg = g1_cfg();
    let v2p = Arc::new(Virt2Phys::new());
    let mut ameta = ActionMeta::new();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, v2p.clone());
    g1.port.start();
    set_state!(g1, PortState::Running);
    let mut pcap = PcapBuilder::new("gateway_icmpv6_ping.pcap");
    let ident = 7;
    let seq_no = 777;
    let data = b"reunion\0";

    // ================================================================
    // Generate an ICMP Echo Request from G1 to Virtual GW
    // ================================================================
    let mut pkt1 = gen_icmp_echo_req(
        g1_cfg.private_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv6_cfg().unwrap().private_ip.into(),
        g1_cfg.ipv6_cfg().unwrap().gateway_ip.into(),
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

    // Ether + IPv6
    assert_eq!(reply.body_offset(), ETHER_HDR_SZ + IPV6_HDR_SZ);
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
            assert_eq!(ip6.src, g1_cfg.ipv6_cfg().unwrap().gateway_ip);
            assert_eq!(ip6.dst, g1_cfg.ipv6_cfg().unwrap().private_ip);
            assert_eq!(ip6.proto, Protocol::ICMPv6);
            (
                Ipv6Address::from_bytes(ip6.src.bytes().as_slice()),
                Ipv6Address::from_bytes(ip6.dst.bytes().as_slice()),
            )
        }
        ip4 => panic!("expected inner IPv6 metadata, got IPv4: {:?}", ip4),
    };

    let mut rdr = PacketReader::new(&reply, ());
    // Need to seek to body.
    rdr.seek(ETHER_HDR_SZ + IPV6_HDR_SZ).unwrap();
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

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

#![feature(extern_types)]

use std::fmt::Display;
use std::io;
use std::process::exit;
use std::str::FromStr;
use clap::{Parser, Subcommand, Args};
use opte::api::{
    Direction, IpAddr, Ipv4Addr, Ipv4Cidr, Ipv6Addr, MacAddr, Vni,
};
use opte::engine::flow_table::FlowEntryDump;
use opte::engine::ioctl as api;
use opte::engine::layer::InnerFlowId;
use opte::engine::rule::RuleDump;
use opte_ioctl::OpteHdl;
use oxide_vpc::api::{
    Action as FirewallAction, AddRouterEntryIpv4Req, Address,
    Filters as FirewallFilters, FirewallRule, GuestPhysAddr, PhysNet, PortInfo,
    Ports, ProtoFilter, RemFwRuleReq, RouterTarget, SNatCfg, SetVirt2PhysReq,
};
use oxide_vpc::engine::overlay::DumpVirt2PhysResp;

/// Administer the Oxide Packet Transformation Engine (OPTE)
#[derive(Debug, Parser)]
#[clap(author, version, about)]
struct Opte {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// List all ports.
    ListPorts,

    /// List all layers under a given port.
    ListLayers {
        #[clap(short)]
        port: String,
    },

    /// Dump the contents of the layer with the given name
    DumpLayer {
        #[clap(short)]
        port: String,
        name: String,
    },

    /// Clear all entries from the Unified Flow Table
    ClearUft {
        #[clap(short)]
        port: String,
    },

    /// Dump the Unified Flow Table
    DumpUft {
        #[clap(short)]
        port: String,
    },

    /// Dump TCP flows
    DumpTcpFlows {
        #[clap(short)]
        port: String,
    },

    /// Dump virtual to physical address mapping
    DumpV2P,

    /// Add a firewall rule
    AddFwRule {
        #[clap(short)]
        port: String,

        #[clap(long = "dir")]
        direction: Direction,

        #[clap(flatten)]
        filters: Filters,

        #[clap(long)]
        action: FirewallAction,

        #[clap(long)]
        priority: u16,
    },

    /// Remove a firewall rule
    RmFwRule {
        #[clap(short)]
        port: String,

        #[clap(long = "dir")]
        direction: Direction,

        id: u64,
    },

    /// Set/replace all firewall rules atomically.
    /// 
    /// Rules are read from standard input, one per line.
    SetFwRules {
        #[clap(short)]
        port: String,
    },

    /// Create an xde device
    CreateXde {
        name: String,

        #[clap(long)]
        private_mac: MacAddr,

        #[clap(long)]
        private_ip: std::net::Ipv4Addr,

        #[clap(long)]
        vpc_subnet: Ipv4Cidr,

        #[clap(long)]
        gateway_mac: MacAddr,

        #[clap(long)]
        gateway_ip: std::net::Ipv4Addr,

        #[clap(long)]
        bsvc_addr: std::net::Ipv6Addr,

        #[clap(long)]
        bsvc_vni: Vni,

        #[clap(long)]
        vpc_vni: Vni,

        #[clap(long)]
        src_underlay_addr: std::net::Ipv6Addr,

        #[clap(long, requires_all(&["snat-start", "snat-end"]))]
        snat_ip: Option<std::net::Ipv4Addr>,

        #[clap(long)]
        snat_start: Option<u16>,

        #[clap(long)]
        snat_end: Option<u16>,

        #[clap(long)]
        snat_gw_mac: Option<MacAddr>,

        #[clap(long)]
        external_ipv4: Option<Ipv4Addr>,

        #[clap(long)]
        passthrough: bool,
    },

    /// Delete an xde device
    DeleteXde { name: String },

    /// Set up xde underlay devices
    SetXdeUnderlay { u1: String, u2: String },

    /// Set a virtual-to-physical mapping
    SetV2P {
        vpc_ip4: std::net::Ipv4Addr,
        vpc_mac: MacAddr,
        underlay_ip: std::net::Ipv6Addr,
        vni: Vni,
    },

    /// Add a new IPv4 router entry
    AddRouterEntryIpv4 {
        #[clap(short)]
        port: String,

        dest: opte::api::Ipv4Cidr,

        target: RouterTarget,
    },
}

#[derive(Debug, Args)]
struct Filters {
    /// The host address or subnet to which the rule applies
    #[clap(long)]
    hosts: Address,

    /// The protocol to which the rule applies
    #[clap(long)]
    protocol: ProtoFilter,

    /// The port(s) to which the rule applies
    #[clap(long)]
    ports: Ports,
}

impl From<Filters> for FirewallFilters {
    fn from(f: Filters) -> Self {
        Self::new()
            .set_hosts(f.hosts)
            .set_protocol(f.protocol)
            .set_ports(f.ports)
            .clone()
    }
}

fn print_port_header() {
    println!(
        "{:<32} {:<24} {:<16} {:<8}",
        "LINK", "MAC ADDRESS", "IPv4 ADDRESS", "STATE"
    );
}

fn print_port(pi: PortInfo) {
    println!(
        "{:<32} {:<24} {:<16} {:<8}",
        pi.name,
        pi.mac_addr.to_string(),
        pi.ip4_addr.to_string(),
        pi.state,
    );
}

fn print_flow_header() {
    println!(
        "{:<6} {:<16} {:<6} {:<16} {:<6} {:<8} {:<22}",
        "PROTO", "SRC IP", "SPORT", "DST IP", "DPORT", "HITS", "ACTION"
    );
}

fn print_flow(flow_id: &InnerFlowId, flow_entry: &FlowEntryDump) {
    let (src_ip, dst_ip) = match (flow_id.src_ip, flow_id.dst_ip) {
        (IpAddr::Ip4(src), IpAddr::Ip4(dst)) => (src, dst),
        _ => todo!("support for IPv6"),
    };

    // For those types with custom Display implementations
    // we need to first format in into a String before
    // passing it to println in order for the format
    // specification to be honored.
    println!(
        "{:<6} {:<16} {:<6} {:<16} {:<6} {:<8} {:<22}",
        flow_id.proto.to_string(),
        src_ip.to_string(),
        flow_id.src_port,
        dst_ip.to_string(),
        flow_id.dst_port,
        flow_entry.hits,
        flow_entry.state_summary,
    );
}

fn print_rule_header() {
    println!("{:<8} {:<6} {:<48} {:<18}", "ID", "PRI", "PREDICATES", "ACTION");
}

fn print_rule(id: u64, rule: &RuleDump) {
    let hdr_preds = rule
        .predicates
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<String>>()
        .join(" ");

    let data_preds = rule
        .data_predicates
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<String>>()
        .join(" ");

    let mut preds = format!("{} {}", hdr_preds, data_preds);

    if preds == "" {
        preds = "*".to_string();
    }

    println!("{:<8} {:<6} {:<48} {:<?}", id, rule.priority, preds, rule.action);
}

fn print_hrb() {
    println!("{:=<70}", "=");
}

fn print_hr() {
    println!("{:-<70}", "-");
}

fn print_list_layers(resp: &api::ListLayersResp) {
    println!(
        "{:<12} {:<10} {:<10} {:<10}",
        "NAME", "RULES IN", "RULES OUT", "FLOWS",
    );

    for desc in &resp.layers {
        println!(
            "{:<12} {:<10} {:<10} {:<10}",
            desc.name, desc.rules_in, desc.rules_out, desc.flows,
        );
    }
}

fn print_v2p_header() {
    println!("{:<24} {:<17} {}", "VPC IP", "VPC MAC ADDR", "UNDERLAY IP");
}

fn print_v2p_ip4((src, phys): &(Ipv4Addr, GuestPhysAddr)) {
    let eth = format!("{}", phys.ether);
    println!(
        "{:<24} {:<17} {}",
        std::net::Ipv4Addr::from(src.bytes()),
        eth,
        std::net::Ipv6Addr::from(phys.ip.bytes()),
    );
}

fn print_v2p_ip6((src, phys): &(Ipv6Addr, GuestPhysAddr)) {
    let eth = format!("{}", phys.ether);
    println!(
        "{:<24} {:<17} {}",
        std::net::Ipv6Addr::from(src.bytes()),
        eth,
        std::net::Ipv6Addr::from(phys.ip.bytes()),
    );
}

fn print_v2p(resp: &DumpVirt2PhysResp) {
    println!("Virtual to Physical Mappings");
    print_hrb();
    for vpc in &resp.mappings {
        println!("");
        println!("VPC {}", vpc.vni);
        print_hr();
        println!("");
        println!("IPv4 mappings");
        print_hr();
        print_v2p_header();
        for pair in &vpc.ip4 {
            print_v2p_ip4(pair);
        }

        println!("");
        println!("IPv6 mappings");
        print_hr();
        print_v2p_header();
        for pair in &vpc.ip6 {
            print_v2p_ip6(pair);
        }
    }
}

fn print_layer(resp: &api::DumpLayerResp) {
    println!("Layer {}", resp.name);
    print_hrb();
    println!("Inbound Flows");
    print_hr();
    print_flow_header();
    for (flow_id, flow_state) in &resp.ft_in {
        print_flow(flow_id, flow_state);
    }

    println!("\nOutbound Flows");
    print_hr();
    print_flow_header();
    for (flow_id, flow_state) in &resp.ft_out {
        print_flow(flow_id, flow_state);
    }

    println!("\nInbound Rules");
    print_hr();
    print_rule_header();
    for (id, rule) in &resp.rules_in {
        print_rule(*id, rule);
    }

    println!("\nOutbound Rules");
    print_hr();
    print_rule_header();
    for (id, rule) in &resp.rules_out {
        print_rule(*id, rule);
    }

    println!("");
}

fn print_uft(resp: &api::DumpUftResp) {
    println!("Unified Flow Table");
    print_hrb();
    println!("Inbound Flows [{}/{}]", resp.uft_in_num_flows, resp.uft_in_limit);
    print_hr();
    print_flow_header();
    for (flow_id, flow_state) in &resp.uft_in {
        print_flow(flow_id, flow_state);
    }

    println!(
        "\nOutbound Flows [{}/{}]",
        resp.uft_out_num_flows, resp.uft_out_limit
    );
    print_hr();
    print_flow_header();
    for (flow_id, flow_state) in &resp.uft_out {
        print_flow(flow_id, flow_state);
    }

    println!("");
}

fn die<E: Display>(error: E) -> ! {
    eprintln!("ERROR: {}", error);
    exit(1);
}

trait UnwrapOrDie<T, E: Display> {
    fn unwrap_or_die(self) -> T;
}

impl<T, E: Display> UnwrapOrDie<T, E> for Result<T, E> {
    fn unwrap_or_die(self) -> T {
        match self {
            Ok(val) => val,
            Err(e) => die(e),
        }
    }
}

fn main() {
    let args = Opte::parse();
    match args.cmd {
        Command::ListPorts => {
            let hdl = OpteHdl::open(OpteHdl::DLD_CTL).unwrap();
            print_port_header();
            for p in hdl.list_ports().unwrap().ports {
                print_port(p);
            }
        }

        Command::ListLayers { port } => {
            let hdl = OpteHdl::open(OpteHdl::DLD_CTL).unwrap_or_die();
            print_list_layers(&hdl.list_layers(&port).unwrap_or_die());
        }

        Command::DumpLayer { port, name } => {
            let hdl = OpteHdl::open(OpteHdl::DLD_CTL).unwrap_or_die();
            print_layer(&hdl.get_layer_by_name(&port, &name).unwrap_or_die());
        }

        Command::ClearUft { port } => {
            let hdl = OpteHdl::open(OpteHdl::DLD_CTL).unwrap_or_die();
            hdl.clear_uft(&port).unwrap_or_die();
        }

        Command::DumpUft { port } => {
            let hdl = OpteHdl::open(OpteHdl::DLD_CTL).unwrap_or_die();
            print_uft(&hdl.dump_uft(&port).unwrap_or_die());
        }

        Command::DumpTcpFlows { port } => {
            let hdl = OpteHdl::open(OpteHdl::DLD_CTL).unwrap_or_die();
            let flows = hdl.dump_tcp_flows(&port).unwrap_or_die().flows;
            for (flow_id, entry) in flows {
                println!("{} {:?}", flow_id, entry);
            }
        }

        Command::DumpV2P => {
            let hdl = OpteHdl::open(OpteHdl::DLD_CTL).unwrap_or_die();
            print_v2p(&hdl.dump_v2p().unwrap_or_die());
        }

        Command::SetFwRules { port } => {
            let mut rules = vec![];
            for line in io::stdin().lines() {
                let rule_str = line.unwrap_or_die();
                let r = FirewallRule::from_str(&rule_str).unwrap_or_die();
                rules.push(r);
            }

            let hdl = OpteHdl::open(OpteHdl::DLD_CTL).unwrap_or_die();
            hdl.set_firewall_rules(&port, rules).unwrap_or_die();
        }

        Command::CreateXde {
            name,
            private_mac,
            private_ip,
            vpc_subnet,
            gateway_mac,
            gateway_ip,
            bsvc_addr,
            bsvc_vni,
            vpc_vni,
            src_underlay_addr,
            snat_ip,
            snat_start,
            snat_end,
            snat_gw_mac,
            external_ipv4,
            passthrough,
        } => {
            let hdl = OpteHdl::open(OpteHdl::DLD_CTL).unwrap_or_die();
            let snat = match snat_ip {
                Some(ip) => Some(SNatCfg {
                    public_ip: ip.into(),
                    ports: core::ops::RangeInclusive::new(
                        snat_start.unwrap(),
                        snat_end.unwrap(),
                    ),
                    phys_gw_mac: snat_gw_mac.unwrap(),
                }),

                None => None,
            };

            hdl.create_xde(
                &name,
                private_mac,
                private_ip,
                vpc_subnet,
                gateway_mac,
                gateway_ip,
                bsvc_addr,
                bsvc_vni,
                vpc_vni,
                src_underlay_addr,
                snat,
                external_ipv4,
                passthrough,
            )
            .unwrap_or_die();
        }

        Command::DeleteXde { name } => {
            let hdl = OpteHdl::open(OpteHdl::DLD_CTL).unwrap_or_die();
            let _ = hdl.delete_xde(&name).unwrap_or_die();
        }

        Command::SetXdeUnderlay { u1, u2 } => {
            let hdl = OpteHdl::open(OpteHdl::DLD_CTL).unwrap_or_die();
            let _ = hdl.set_xde_underlay(&u1, &u2).unwrap_or_die();
        }

        Command::AddFwRule { port, direction, filters, action, priority } => {
            let hdl = OpteHdl::open(OpteHdl::DLD_CTL).unwrap_or_die();
            let rule = FirewallRule {
                direction,
                filters: filters.into(),
                action,
                priority,
            };
            hdl.add_firewall_rule(&port, &rule).unwrap_or_die();
        }

        Command::RmFwRule { port, direction, id } => {
            let hdl = OpteHdl::open(OpteHdl::DLD_CTL).unwrap_or_die();
            let request = RemFwRuleReq { port_name: port, dir: direction, id };
            hdl.remove_firewall_rule(&request).unwrap_or_die();
        }

        Command::SetV2P { vpc_ip4, vpc_mac, underlay_ip, vni } => {
            let hdl = OpteHdl::open(OpteHdl::DLD_CTL).unwrap_or_die();
            let vip = opte::api::IpAddr::Ip4(vpc_ip4.into());
            let phys = PhysNet { ether: vpc_mac, ip: underlay_ip.into(), vni };
            let req = SetVirt2PhysReq { vip, phys };
            hdl.set_v2p(&req).unwrap_or_die();
        }

        Command::AddRouterEntryIpv4 { port, dest, target } => {
            let hdl = OpteHdl::open(OpteHdl::DLD_CTL).unwrap_or_die();
            let req = AddRouterEntryIpv4Req { port_name: port, dest, target };
            hdl.add_router_entry_ip4(&req).unwrap_or_die();
        }
    }
}

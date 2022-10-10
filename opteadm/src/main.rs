// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

#![feature(extern_types)]

use std::fmt::Display;
use std::io;
use std::process::exit;
use std::str::FromStr;

use structopt::StructOpt;

use opte::api::Direction;
use opte::api::IpCidr;
use opte::api::Ipv4Addr;
use opte::api::Ipv4Cidr;
use opte::api::MacAddr;
use opte::api::Vni;
use opte::engine::print::print_layer;
use opte::engine::print::print_list_layers;
use opte::engine::print::print_uft;
use opteadm::OpteAdm;
use oxide_vpc::api::Action as FirewallAction;
use oxide_vpc::api::AddRouterEntryReq;
use oxide_vpc::api::Address;
use oxide_vpc::api::BoundaryServices;
use oxide_vpc::api::Filters as FirewallFilters;
use oxide_vpc::api::FirewallRule;
use oxide_vpc::api::IpCfg;
use oxide_vpc::api::Ipv4Cfg;
use oxide_vpc::api::PhysNet;
use oxide_vpc::api::PortInfo;
use oxide_vpc::api::Ports;
use oxide_vpc::api::ProtoFilter;
use oxide_vpc::api::RemFwRuleReq;
use oxide_vpc::api::RouterTarget;
use oxide_vpc::api::SNat4Cfg;
use oxide_vpc::api::SetVirt2PhysReq;
use oxide_vpc::api::VpcCfg;
use oxide_vpc::engine::print::print_v2p;

/// Administer the Oxide Packet Transformation Engine (OPTE)
#[derive(Debug, StructOpt)]
enum Command {
    /// List all ports.
    ListPorts,

    /// List all layers under a given port.
    ListLayers {
        #[structopt(short)]
        port: String,
    },

    /// Dump the contents of the layer with the given name
    DumpLayer {
        #[structopt(short)]
        port: String,
        name: String,
    },

    /// Clear all entries from the Unified Flow Table
    ClearUft {
        #[structopt(short)]
        port: String,
    },

    /// Dump the Unified Flow Table
    DumpUft {
        #[structopt(short)]
        port: String,
    },

    /// Dump TCP flows
    DumpTcpFlows {
        #[structopt(short)]
        port: String,
    },

    /// Dump virtual to physical address mapping
    DumpV2P,

    /// Add a firewall rule
    AddFwRule {
        #[structopt(short)]
        port: String,

        #[structopt(long = "dir")]
        direction: Direction,

        #[structopt(flatten)]
        filters: Filters,

        #[structopt(long)]
        action: FirewallAction,

        #[structopt(long)]
        priority: u16,
    },

    /// Remove a firewall rule
    RmFwRule {
        #[structopt(short)]
        port: String,

        #[structopt(long = "dir")]
        direction: Direction,

        id: u64,
    },

    /// Set/replace all firewall rules atomically
    SetFwRules {
        #[structopt(short)]
        port: String,
    },

    /// Create an xde device
    CreateXde {
        name: String,

        #[structopt(long)]
        private_mac: MacAddr,

        #[structopt(long)]
        private_ip: std::net::Ipv4Addr,

        #[structopt(long)]
        vpc_subnet: Ipv4Cidr,

        #[structopt(long)]
        gateway_mac: MacAddr,

        #[structopt(long)]
        gateway_ip: std::net::Ipv4Addr,

        #[structopt(long)]
        bsvc_addr: std::net::Ipv6Addr,

        #[structopt(long)]
        bsvc_vni: Vni,

        #[structopt(long, default_value = "00:00:00:00:00:00")]
        bsvc_mac: MacAddr,

        #[structopt(long)]
        vpc_vni: Vni,

        #[structopt(long)]
        src_underlay_addr: std::net::Ipv6Addr,

        #[structopt(long, requires_all(&["snat-start", "snat-end"]))]
        snat_ip: Option<std::net::Ipv4Addr>,

        #[structopt(long)]
        snat_start: Option<u16>,

        #[structopt(long)]
        snat_end: Option<u16>,

        #[structopt(long)]
        phys_gw_mac: Option<MacAddr>,

        #[structopt(long)]
        external_ipv4: Option<Ipv4Addr>,

        #[structopt(long)]
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

    /// Add a new router entry, either IPv4 or IPv6.
    AddRouterEntry {
        /// The OPTE port to which the route is added
        #[structopt(short)]
        port: String,
        /// The network destination to which the route applies.
        dest: IpCidr,
        /// The location to which traffic matching the destination is sent.
        target: RouterTarget,
    },
}

#[derive(Debug, StructOpt)]
struct Filters {
    /// The host address or subnet to which the rule applies
    #[structopt(long)]
    hosts: Address,

    /// The protocol to which the rule applies
    #[structopt(long)]
    protocol: ProtoFilter,

    /// The port(s) to which the rule applies
    #[structopt(long)]
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
        "{:<32} {:<24} {:<16} {:<16} {:<40} {:<40} {:<8}",
        "LINK",
        "MAC ADDRESS",
        "IPv4 ADDRESS",
        "EXTERNAL IPv4",
        "IPv6 ADDRESS",
        "EXTERNAL IPv6",
        "STATE"
    );
}

fn print_port(pi: PortInfo) {
    let none = String::from("None");
    println!(
        "{:<32} {:<24} {:<16} {:<16} {:<40} {:<40} {:<8}",
        pi.name,
        pi.mac_addr.to_string(),
        pi.ip4_addr.map(|x| x.to_string()).unwrap_or_else(|| none.clone()),
        pi.external_ip4_addr
            .map(|x| x.to_string())
            .unwrap_or_else(|| none.clone()),
        pi.ip6_addr.map(|x| x.to_string()).unwrap_or_else(|| none.clone()),
        pi.external_ip6_addr
            .map(|x| x.to_string())
            .unwrap_or_else(|| none.clone()),
        pi.state,
    );
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
    let cmd = Command::from_args();
    match cmd {
        Command::ListPorts => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap();
            print_port_header();
            for p in hdl.list_ports().unwrap().ports {
                print_port(p);
            }
        }

        Command::ListLayers { port } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap_or_die();
            print_list_layers(&hdl.list_layers(&port).unwrap_or_die());
        }

        Command::DumpLayer { port, name } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap_or_die();
            print_layer(&hdl.get_layer_by_name(&port, &name).unwrap_or_die());
        }

        Command::ClearUft { port } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap_or_die();
            hdl.clear_uft(&port).unwrap_or_die();
        }

        Command::DumpUft { port } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap_or_die();
            print_uft(&hdl.dump_uft(&port).unwrap_or_die());
        }

        Command::DumpTcpFlows { port } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap_or_die();
            let flows = hdl.dump_tcp_flows(&port).unwrap_or_die().flows;
            for (flow_id, entry) in flows {
                println!("{} {:?}", flow_id, entry);
            }
        }

        Command::DumpV2P => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap_or_die();
            print_v2p(&hdl.dump_v2p().unwrap_or_die());
        }

        Command::AddFwRule { port, direction, filters, action, priority } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap_or_die();
            let rule = FirewallRule {
                direction,
                filters: filters.into(),
                action,
                priority,
            };
            hdl.add_firewall_rule(&port, &rule).unwrap_or_die();
        }

        Command::SetFwRules { port } => {
            let mut rules = vec![];
            for line in io::stdin().lines() {
                let rule_str = line.unwrap_or_die();
                let r = FirewallRule::from_str(&rule_str).unwrap_or_die();
                rules.push(r);
            }

            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap_or_die();
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
            bsvc_mac,
            vpc_vni,
            src_underlay_addr,
            snat_ip,
            snat_start,
            snat_end,
            phys_gw_mac,
            external_ipv4,
            passthrough,
        } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap_or_die();
            let snat = match snat_ip {
                Some(ip) => Some(SNat4Cfg {
                    external_ip: ip.into(),
                    ports: core::ops::RangeInclusive::new(
                        snat_start.unwrap(),
                        snat_end.unwrap(),
                    ),
                }),

                None => None,
            };

            let cfg = VpcCfg {
                ip_cfg: IpCfg::Ipv4(Ipv4Cfg {
                    vpc_subnet,
                    private_ip: private_ip.into(),
                    gateway_ip: gateway_ip.into(),
                    snat,
                    external_ips: external_ipv4,
                }),
                private_mac,
                gateway_mac,
                vni: vpc_vni,
                phys_ip: src_underlay_addr.into(),
                boundary_services: BoundaryServices {
                    ip: bsvc_addr.into(),
                    vni: bsvc_vni,
                    mac: bsvc_mac,
                },
                // XXX-EXT-IP: This is part of the external IP hack. We're
                // removing this shortly, and won't be supporting creating OPTE
                // ports through `opteadm` that use the hack.
                proxy_arp_enable: false,
                phys_gw_mac,
            };

            hdl.create_xde(&name, cfg, passthrough).unwrap_or_die();
        }

        Command::DeleteXde { name } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap_or_die();
            let _ = hdl.delete_xde(&name).unwrap_or_die();
        }

        Command::SetXdeUnderlay { u1, u2 } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap_or_die();
            let _ = hdl.set_xde_underlay(&u1, &u2).unwrap_or_die();
        }

        Command::RmFwRule { port, direction, id } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap_or_die();
            let request = RemFwRuleReq { port_name: port, dir: direction, id };
            hdl.remove_firewall_rule(&request).unwrap_or_die();
        }

        Command::SetV2P { vpc_ip4, vpc_mac, underlay_ip, vni } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap_or_die();
            let vip = opte::api::IpAddr::Ip4(vpc_ip4.into());
            let phys = PhysNet { ether: vpc_mac, ip: underlay_ip.into(), vni };
            let req = SetVirt2PhysReq { vip, phys };
            hdl.set_v2p(&req).unwrap_or_die();
        }

        Command::AddRouterEntry { port, dest, target } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap_or_die();
            let req = AddRouterEntryReq { port_name: port, dest, target };
            hdl.add_router_entry(&req).unwrap_or_die();
        }
    }
}

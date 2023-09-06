// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

use std::io;
use std::str::FromStr;

use structopt::StructOpt;

use opte::api::Direction;
use opte::api::DomainName;
use opte::api::IpAddr;
use opte::api::IpCidr;
use opte::api::Ipv6Addr;
use opte::api::MacAddr;
use opte::api::Vni;
use opte::engine::print::print_layer;
use opte::engine::print::print_list_layers;
use opte::engine::print::print_tcp_flows;
use opte::engine::print::print_uft;
use opteadm::OpteAdm;
use oxide_vpc::api::AddRouterEntryReq;
use oxide_vpc::api::Address;
use oxide_vpc::api::BoundaryServices;
use oxide_vpc::api::Filters as FirewallFilters;
use oxide_vpc::api::FirewallAction;
use oxide_vpc::api::FirewallRule;
use oxide_vpc::api::IpCfg;
use oxide_vpc::api::Ipv4Cfg;
use oxide_vpc::api::Ipv6Cfg;
use oxide_vpc::api::PhysNet;
use oxide_vpc::api::PortInfo;
use oxide_vpc::api::Ports;
use oxide_vpc::api::ProtoFilter;
use oxide_vpc::api::RemFwRuleReq;
use oxide_vpc::api::RouterTarget;
use oxide_vpc::api::SNat4Cfg;
use oxide_vpc::api::SNat6Cfg;
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
        /// The name for the `xde` device.
        name: String,

        /// The private MAC address for the guest.
        #[structopt(long)]
        guest_mac: MacAddr,

        /// The private IP address for the guest.
        #[structopt(long)]
        private_ip: IpAddr,

        /// The private IP subnet to which the guest belongs.
        #[structopt(long)]
        vpc_subnet: IpCidr,

        /// The MAC address to use as the virtual gateway.
        ///
        /// This is the MAC OPTE itself uses when responding directly to the
        /// client, for example, to DHCP requests.
        #[structopt(long)]
        gateway_mac: MacAddr,

        /// The IP address to use as the virtual gateway.
        ///
        /// This is the IP OPTE itself uses when responding directly to the
        /// client, for example, to DHCP requests.
        #[structopt(long)]
        gateway_ip: IpAddr,

        /// The IP address for Boundary Services, where packets destined to
        /// off-rack networks are sent.
        #[structopt(long)]
        bsvc_addr: Ipv6Addr,

        /// The VNI used for Boundary Services.
        #[structopt(long)]
        bsvc_vni: Vni,

        /// The MAC address for Boundary Services.
        #[structopt(long, default_value = "00:00:00:00:00:00")]
        bsvc_mac: MacAddr,

        /// The VNI for the VPC to which the guest belongs.
        #[structopt(long)]
        vpc_vni: Vni,

        /// The IP address of the hosting sled, on the underlay / physical
        /// network.
        #[structopt(long)]
        src_underlay_addr: Ipv6Addr,

        /// The external IP address used for source NAT for the guest.
        #[structopt(long, requires_all(&["snat-start", "snat-end"]))]
        snat_ip: Option<IpAddr>,

        /// The starting L4 port used for source NAT for the guest.
        #[structopt(long)]
        snat_start: Option<u16>,

        /// The ending L4 port used for source NAT for the guest.
        #[structopt(long)]
        snat_end: Option<u16>,

        /// A list of domain names provided to the guest, used when resolving
        /// hostnames.
        #[structopt(long, parse(try_from_str))]
        domain_list: Vec<DomainName>,

        #[structopt(long)]
        external_ip: Option<IpAddr>,

        #[structopt(long)]
        passthrough: bool,
    },

    /// Delete an xde device
    DeleteXde { name: String },

    /// Set up xde underlay devices
    SetXdeUnderlay { u1: String, u2: String },

    /// Set a virtual-to-physical mapping
    SetV2P { vpc_ip: IpAddr, vpc_mac: MacAddr, underlay_ip: Ipv6Addr, vni: Vni },

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

fn main() -> anyhow::Result<()> {
    let cmd = Command::from_args();
    match cmd {
        Command::ListPorts => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;
            print_port_header();
            for p in hdl.list_ports()?.ports {
                print_port(p);
            }
        }

        Command::ListLayers { port } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;
            print_list_layers(&hdl.list_layers(&port)?);
        }

        Command::DumpLayer { port, name } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;
            print_layer(&hdl.get_layer_by_name(&port, &name)?);
        }

        Command::ClearUft { port } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;
            hdl.clear_uft(&port)?;
        }

        Command::DumpUft { port } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;
            print_uft(&hdl.dump_uft(&port)?);
        }

        Command::DumpTcpFlows { port } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;
            print_tcp_flows(&hdl.dump_tcp_flows(&port)?);
        }

        Command::DumpV2P => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;
            print_v2p(&hdl.dump_v2p()?);
        }

        Command::AddFwRule { port, direction, filters, action, priority } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;
            let rule = FirewallRule {
                direction,
                filters: filters.into(),
                action,
                priority,
            };
            hdl.add_firewall_rule(&port, &rule)?;
        }

        Command::SetFwRules { port } => {
            let mut rules = vec![];
            for line in io::stdin().lines() {
                let rule_str = line?;
                let r = FirewallRule::from_str(&rule_str)
                    .map_err(|e| anyhow::anyhow!("Invalid rule: {e}"))?;
                rules.push(r);
            }

            let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;
            hdl.set_firewall_rules(&port, rules)?;
        }

        Command::CreateXde {
            name,
            guest_mac,
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
            domain_list,
            external_ip,
            passthrough,
        } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;

            let ip_cfg = match private_ip {
                IpAddr::Ip4(private_ip) => {
                    let IpCidr::Ip4(vpc_subnet) = vpc_subnet else {
                        anyhow::bail!("expected IPv4 VPC subnet");
                    };

                    let IpAddr::Ip4(gateway_ip) = gateway_ip else {
                        anyhow::bail!("expected IPv4 gateway IP");
                    };

                    let snat = match snat_ip {
                        Some(IpAddr::Ip4(ip)) => Some(SNat4Cfg {
                            external_ip: ip,
                            ports: core::ops::RangeInclusive::new(
                                snat_start.unwrap(),
                                snat_end.unwrap(),
                            ),
                        }),
                        Some(IpAddr::Ip6(_)) => {
                            anyhow::bail!("expected IPv4 SNAT IP");
                        }
                        None => None,
                    };

                    let external_ip = match external_ip {
                        Some(IpAddr::Ip4(ip)) => Some(ip),
                        Some(IpAddr::Ip6(_)) => {
                            anyhow::bail!("expected IPv4 external IP");
                        }
                        None => None,
                    };

                    IpCfg::Ipv4(Ipv4Cfg {
                        vpc_subnet,
                        private_ip,
                        gateway_ip,
                        snat,
                        external_ips: external_ip,
                    })
                }
                IpAddr::Ip6(private_ip) => {
                    let IpCidr::Ip6(vpc_subnet) = vpc_subnet else {
                        anyhow::bail!("expected IPv6 VPC subnet");
                    };

                    let IpAddr::Ip6(gateway_ip) = gateway_ip else {
                        anyhow::bail!("expected IPv6 gateway IP");
                    };

                    let snat = match snat_ip {
                        Some(IpAddr::Ip4(_)) => {
                            anyhow::bail!("expected IPv6 SNAT IP");
                        }
                        Some(IpAddr::Ip6(ip)) => Some(SNat6Cfg {
                            external_ip: ip,
                            ports: core::ops::RangeInclusive::new(
                                snat_start.unwrap(),
                                snat_end.unwrap(),
                            ),
                        }),
                        None => None,
                    };

                    let external_ip = match external_ip {
                        Some(IpAddr::Ip4(_)) => {
                            anyhow::bail!("expected IPv6 external IP");
                        }
                        Some(IpAddr::Ip6(ip)) => Some(ip),
                        None => None,
                    };

                    IpCfg::Ipv6(Ipv6Cfg {
                        vpc_subnet,
                        private_ip,
                        gateway_ip,
                        snat,
                        external_ips: external_ip,
                    })
                }
            };

            let cfg = VpcCfg {
                ip_cfg,
                guest_mac,
                gateway_mac,
                vni: vpc_vni,
                phys_ip: src_underlay_addr,
                boundary_services: BoundaryServices {
                    ip: bsvc_addr,
                    vni: bsvc_vni,
                    mac: bsvc_mac,
                },
                domain_list,
            };

            hdl.create_xde(&name, cfg, passthrough)?;
        }

        Command::DeleteXde { name } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;
            let _ = hdl.delete_xde(&name)?;
        }

        Command::SetXdeUnderlay { u1, u2 } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;
            let _ = hdl.set_xde_underlay(&u1, &u2)?;
        }

        Command::RmFwRule { port, direction, id } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;
            let request = RemFwRuleReq { port_name: port, dir: direction, id };
            hdl.remove_firewall_rule(&request)?;
        }

        Command::SetV2P { vpc_ip, vpc_mac, underlay_ip, vni } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;
            let phys = PhysNet { ether: vpc_mac, ip: underlay_ip, vni };
            let req = SetVirt2PhysReq { vip: vpc_ip, phys };
            hdl.set_v2p(&req)?;
        }

        Command::AddRouterEntry { port, dest, target } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;
            let req = AddRouterEntryReq { port_name: port, dest, target };
            hdl.add_router_entry(&req)?;
        }
    }

    Ok(())
}
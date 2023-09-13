// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

use std::io;
use std::str::FromStr;

use clap::Args;
use clap::Parser;

use opte::api::Direction;
use opte::api::DomainName;
use opte::api::IpAddr;
use opte::api::IpCidr;
use opte::api::Ipv4Addr;
use opte::api::Ipv6Addr;
use opte::api::MacAddr;
use opte::api::Vni;
use opte::api::API_VERSION;
use opte::engine::print::print_layer;
use opte::engine::print::print_list_layers;
use opte::engine::print::print_tcp_flows;
use opte::engine::print::print_uft;
use opteadm::OpteAdm;
use opteadm::COMMIT_COUNT;
use opteadm::MAJOR_VERSION;
use oxide_vpc::api::AddRouterEntryReq;
use oxide_vpc::api::Address;
use oxide_vpc::api::BoundaryServices;
use oxide_vpc::api::DhcpCfg;
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
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Parser)]
#[command(version=opte_pkg_version())]
enum Command {
    /// List all ports.
    ListPorts,

    /// List all layers under a given port.
    ListLayers {
        #[arg(short)]
        port: String,
    },

    /// Dump the contents of the layer with the given name.
    DumpLayer {
        #[arg(short)]
        port: String,
        name: String,
    },

    /// Clear all entries from the Unified Flow Table.
    ClearUft {
        #[arg(short)]
        port: String,
    },

    /// Dump the Unified Flow Table.
    DumpUft {
        #[arg(short)]
        port: String,
    },

    /// Dump TCP flows
    DumpTcpFlows {
        #[arg(short)]
        port: String,
    },

    /// Dump virtual to physical address mapping
    DumpV2P,

    /// Add a firewall rule
    AddFwRule {
        #[arg(short)]
        port: String,

        #[arg(long = "dir")]
        direction: Direction,

        #[command(flatten)]
        filters: Filters,

        #[arg(long)]
        action: FirewallAction,

        #[arg(long)]
        priority: u16,
    },

    /// Remove a firewall rule.
    RmFwRule {
        #[arg(short)]
        port: String,

        #[arg(long = "dir")]
        direction: Direction,

        id: u64,
    },

    /// Set/replace all firewall rules atomically.
    SetFwRules {
        #[arg(short)]
        port: String,
    },

    /// Create an xde device
    CreateXde {
        /// The name for the `xde` device.
        name: String,

        /// The private MAC address for the guest.
        #[arg(long)]
        guest_mac: MacAddr,

        /// The private IP address for the guest.
        #[arg(long)]
        private_ip: IpAddr,

        /// The private IP subnet to which the guest belongs.
        #[arg(long)]
        vpc_subnet: IpCidr,

        /// The MAC address to use as the virtual gateway.
        ///
        /// This is the MAC OPTE itself uses when responding directly to the
        /// client, for example, to DHCP requests.
        #[arg(long)]
        gateway_mac: MacAddr,

        /// The IP address to use as the virtual gateway.
        ///
        /// This is the IP OPTE itself uses when responding directly to the
        /// client, for example, to DHCP requests.
        #[arg(long)]
        gateway_ip: IpAddr,

        /// The IP address for Boundary Services, where packets destined to
        /// off-rack networks are sent.
        #[arg(long)]
        bsvc_addr: Ipv6Addr,

        /// The VNI used for Boundary Services.
        #[arg(long)]
        bsvc_vni: Vni,

        /// The MAC address for Boundary Services.
        #[arg(long, default_value = "00:00:00:00:00:00")]
        bsvc_mac: MacAddr,

        /// The VNI for the VPC to which the guest belongs.
        #[arg(long)]
        vpc_vni: Vni,

        /// The IP address of the hosting sled, on the underlay / physical
        /// network.
        #[arg(long)]
        src_underlay_addr: Ipv6Addr,

        #[command(flatten)]
        snat: Option<SnatConfig>,

        #[command(flatten)]
        dhcp: DhcpConfig,

        /// A comma-separated list of domain names provided to the guest,
        /// used when resolving hostnames.
        #[arg(long, value_delimiter = ',')]
        domain_list: Vec<DomainName>,

        #[arg(long)]
        external_ip: Option<IpAddr>,

        #[arg(long)]
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
        #[arg(short)]
        port: String,
        /// The network destination to which the route applies.
        dest: IpCidr,
        /// The location to which traffic matching the destination is sent.
        target: RouterTarget,
    },
}

#[derive(Debug, Parser)]
struct Filters {
    /// The host address or subnet to which the rule applies
    #[arg(long)]
    hosts: Address,

    /// The protocol to which the rule applies
    #[arg(long)]
    protocol: ProtoFilter,

    /// The port(s) to which the rule applies
    #[arg(long)]
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

#[derive(Args, Debug)]
#[group(requires_all = ["snat_ip", "snat_start", "snat_end"], multiple = true)]
struct SnatConfig {
    /// The external IP address used for source NAT for the guest.
    #[arg(long, required = false)]
    snat_ip: IpAddr,

    /// The starting L4 port used for source NAT for the guest.
    #[arg(long, required = false)]
    snat_start: u16,

    /// The ending L4 port used for source NAT for the guest.
    #[arg(long, required = false)]
    snat_end: u16,
}

impl TryFrom<SnatConfig> for SNat4Cfg {
    type Error = anyhow::Error;

    fn try_from(value: SnatConfig) -> Result<Self, Self::Error> {
        let IpAddr::Ip4(external_ip) = value.snat_ip else {
            anyhow::bail!("expected IPv4 SNAT IP");
        };

        Ok(SNat4Cfg { external_ip, ports: value.snat_start..=value.snat_end })
    }
}

impl TryFrom<SnatConfig> for SNat6Cfg {
    type Error = anyhow::Error;

    fn try_from(value: SnatConfig) -> Result<Self, Self::Error> {
        let IpAddr::Ip6(external_ip) = value.snat_ip else {
            anyhow::bail!("expected IPv6 SNAT IP");
        };

        Ok(SNat6Cfg { external_ip, ports: value.snat_start..=value.snat_end })
    }
}

#[derive(Args, Debug)]
struct DhcpConfig {
    /// The hostname a connected guest should be provided via DHCP.
    #[arg(long)]
    hostname: Option<DomainName>,

    /// The domain used by a guest to contruct its FQDN, provided via DHCP.
    #[arg(long)]
    host_domain: Option<DomainName>,

    /// A comma-delimited list of DNS server IP addresses to provide over DHCP.
    ///
    /// These must match the IP version the port is configured for.
    #[arg(long, value_delimiter = ',')]
    dns_servers: Vec<IpAddr>,
}

impl TryFrom<DhcpConfig> for DhcpCfg<Ipv4Addr> {
    type Error = anyhow::Error;

    fn try_from(value: DhcpConfig) -> Result<Self, Self::Error> {
        let dns_servers = value
            .dns_servers
            .into_iter()
            .enumerate()
            .map(|(idx, ip)| {
                if let IpAddr::Ip4(ip) = ip {
                    Ok(ip)
                } else {
                    anyhow::bail!("DNS server #{idx}: expected Ipv4")
                }
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            hostname: value.hostname,
            host_domain: value.host_domain,
            dns_servers,
        })
    }
}

impl TryFrom<DhcpConfig> for DhcpCfg<Ipv6Addr> {
    type Error = anyhow::Error;

    fn try_from(value: DhcpConfig) -> Result<Self, Self::Error> {
        let dns_servers = value
            .dns_servers
            .into_iter()
            .enumerate()
            .map(|(idx, ip)| {
                if let IpAddr::Ip6(ip) = ip {
                    Ok(ip)
                } else {
                    anyhow::bail!("DNS server #{idx}: expected Ipv6")
                }
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            hostname: value.hostname,
            host_domain: value.host_domain,
            dns_servers,
        })
    }
}

fn opte_pkg_version() -> String {
    format!("{MAJOR_VERSION}.{API_VERSION}.{COMMIT_COUNT}")
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
    let cmd = Command::parse();
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
            snat,
            dhcp,
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

                    let snat = snat.map(SNat4Cfg::try_from).transpose()?;

                    let dhcp = dhcp.try_into()?;

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
                        dhcp,
                    })
                }
                IpAddr::Ip6(private_ip) => {
                    let IpCidr::Ip6(vpc_subnet) = vpc_subnet else {
                        anyhow::bail!("expected IPv6 VPC subnet");
                    };

                    let IpAddr::Ip6(gateway_ip) = gateway_ip else {
                        anyhow::bail!("expected IPv6 gateway IP");
                    };

                    let snat = snat.map(SNat6Cfg::try_from).transpose()?;

                    let dhcp = dhcp.try_into()?;

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
                        dhcp,
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

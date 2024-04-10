// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

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
use opte::api::MAJOR_VERSION;
use opte::engine::print::print_layer;
use opte::engine::print::print_list_layers;
use opte::engine::print::print_tcp_flows;
use opte::engine::print::print_uft;
use opteadm::OpteAdm;
use opteadm::COMMIT_COUNT;
use oxide_vpc::api::AddRouterEntryReq;
use oxide_vpc::api::Address;
use oxide_vpc::api::ClearVirt2BoundaryReq;
use oxide_vpc::api::DelRouterEntryReq;
use oxide_vpc::api::DelRouterEntryResp;
use oxide_vpc::api::DhcpCfg;
use oxide_vpc::api::ExternalIpCfg;
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
use oxide_vpc::api::RemoveCidrResp;
use oxide_vpc::api::RouterClass;
use oxide_vpc::api::RouterTarget;
use oxide_vpc::api::SNat4Cfg;
use oxide_vpc::api::SNat6Cfg;
use oxide_vpc::api::SetExternalIpsReq;
use oxide_vpc::api::SetVirt2BoundaryReq;
use oxide_vpc::api::SetVirt2PhysReq;
use oxide_vpc::api::TunnelEndpoint;
use oxide_vpc::api::VpcCfg;
use oxide_vpc::engine::overlay::BOUNDARY_SERVICES_VNI;
use oxide_vpc::engine::print::print_v2b;
use oxide_vpc::engine::print::print_v2p;
use std::io;
use std::io::Write;
use std::str::FromStr;
use tabwriter::TabWriter;

/// Administer the Oxide Packet Transformation Engine (OPTE)
#[derive(Debug, Parser)]
#[command(version=opte_pkg_version())]
#[allow(clippy::large_enum_variant)]
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

    /// Clear all entries from the given Layer's Flow Table.
    ClearLft {
        #[arg(short)]
        port: String,
        layer: String,
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

    /// Dump virtual to boundary address mapping
    DumpV2B,

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

        /// The VNI for the VPC to which the guest belongs.
        #[arg(long)]
        vpc_vni: Vni,

        /// The IP address of the hosting sled, on the underlay / physical
        /// network.
        #[arg(long)]
        src_underlay_addr: Ipv6Addr,

        #[command(flatten)]
        external_net: ExternalNetConfig,

        #[command(flatten)]
        dhcp: DhcpConfig,

        #[arg(long)]
        passthrough: bool,
    },

    /// Delete an xde device
    DeleteXde { name: String },

    /// Set up xde underlay devices
    SetXdeUnderlay { u1: String, u2: String },

    /// Set a virtual-to-physical mapping
    SetV2P { vpc_ip: IpAddr, vpc_mac: MacAddr, underlay_ip: Ipv6Addr, vni: Vni },

    /// Set a virtual-to-boundary mapping
    SetV2B { prefix: IpCidr, tunnel_endpoint: Vec<Ipv6Addr> },

    /// Clear a virtual-to-boundary mapping
    ClearV2B { prefix: IpCidr, tunnel_endpoint: Vec<Ipv6Addr> },

    /// Add a new router entry, either IPv4 or IPv6.
    AddRouterEntry {
        #[command(flatten)]
        route: RouterRule,
    },

    /// Remove an existing router entry, either IPv4 or IPv6.
    DelRouterEntry {
        #[command(flatten)]
        route: RouterRule,
    },

    /// Configure external network addresses used by a port for VPC-external traffic.
    SetExternalIps {
        /// The OPTE port to configure
        #[arg(short)]
        port: String,

        #[command(flatten)]
        external_net: ExternalNetConfig,
    },

    /// Allows a guest to send and receive traffic on a given CIDR block.
    AllowCidr {
        /// The OPTE port to configure
        #[arg(short)]
        port: String,

        /// The IP block to allow through the gateway.
        prefix: IpCidr,
    },

    /// Prevents a guest from sending/receiving traffic on a given CIDR block.
    RemoveCidr {
        /// The OPTE port to configure
        #[arg(short)]
        port: String,

        /// The IP block to deny at the gateway.
        prefix: IpCidr,
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

#[derive(Debug, Parser)]
struct RouterRule {
    /// The OPTE port to which the route change is applied.
    #[arg(short)]
    port: String,
    /// The network destination to which the route applies.
    dest: IpCidr,
    /// The location to which traffic matching the destination is sent.
    target: RouterTarget,
    /// The class of router a rule belongs to ('system' or 'custom')
    class: RouterClass,
}

// TODO: expand this to allow for v4 and v6 simultaneously?
/// Per-port configuration for rack-external networking.
#[derive(Args, Clone, Debug)]
struct ExternalNetConfig {
    #[command(flatten)]
    snat: Option<SnatConfig>,

    /// An external IP address used for 1-to-1 NAT.
    ///
    /// If `floating_ip`s are defined, then a port will receive and reply
    /// (but not originate traffic) on this address.
    #[arg(long)]
    ephemeral_ip: Option<IpAddr>,

    /// A comma-separated list of floating IP addresses which a port will prefer
    /// for sending and receiving traffic.
    #[arg(long)]
    floating_ip: Vec<IpAddr>,
}

impl TryFrom<ExternalNetConfig> for ExternalIpCfg<Ipv4Addr> {
    type Error = anyhow::Error;

    fn try_from(value: ExternalNetConfig) -> Result<Self, Self::Error> {
        let snat = value.snat.map(SNat4Cfg::try_from).transpose()?;

        let ephemeral_ip = match value.ephemeral_ip {
            Some(IpAddr::Ip4(ip)) => Some(ip),
            Some(IpAddr::Ip6(_)) => {
                anyhow::bail!("expected IPv4 external IP");
            }
            None => None,
        };

        let floating_ips = value
            .floating_ip
            .iter()
            .copied()
            .map(|ip| match ip {
                IpAddr::Ip4(ip) => Ok(ip),
                _ => anyhow::bail!("expected IPv4 floating IP"),
            })
            .collect::<Result<Vec<opte::api::Ipv4Addr>, _>>()?;

        Ok(Self { snat, ephemeral_ip, floating_ips })
    }
}

impl TryFrom<ExternalNetConfig> for ExternalIpCfg<Ipv6Addr> {
    type Error = anyhow::Error;

    fn try_from(value: ExternalNetConfig) -> Result<Self, Self::Error> {
        let snat = value.snat.map(SNat6Cfg::try_from).transpose()?;

        let ephemeral_ip = match value.ephemeral_ip {
            Some(IpAddr::Ip4(_)) => {
                anyhow::bail!("expected IPv6 external IP");
            }
            Some(IpAddr::Ip6(ip)) => Some(ip),
            None => None,
        };

        let floating_ips = value
            .floating_ip
            .iter()
            .copied()
            .map(|ip| match ip {
                IpAddr::Ip6(ip) => Ok(ip),
                _ => anyhow::bail!("expected IPv6 floating IP"),
            })
            .collect::<Result<Vec<opte::api::Ipv6Addr>, _>>()?;

        Ok(Self { snat, ephemeral_ip, floating_ips })
    }
}

#[derive(Args, Clone, Copy, Debug)]
#[group(requires_all = ["snat_ip", "snat_start", "snat_end"], multiple = true)]
struct SnatConfig {
    /// The external IP address used for source NAT for the guest.
    ///
    /// Requires `snat_ip`, `snat_start`, and `snat_end` to be defined.
    #[arg(long, required = false)]
    snat_ip: IpAddr,

    /// The starting L4 port used for source NAT for the guest.
    ///
    /// See `snat_ip` for mandatory shared arguments.
    #[arg(long, required = false)]
    snat_start: u16,

    /// The ending L4 port used for source NAT for the guest.
    ///
    /// See `snat_ip` for mandatory shared arguments.
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
    #[arg(long, value_delimiter = ',')]
    dns_servers: Vec<IpAddr>,

    /// A comma-separated list of domain names provided to the guest,
    /// used when resolving hostnames.
    #[arg(long, value_delimiter = ',')]
    domain_search_list: Vec<DomainName>,
}

impl From<DhcpConfig> for DhcpCfg {
    fn from(value: DhcpConfig) -> Self {
        let mut dns4_servers = vec![];
        let dns6_servers = value
            .dns_servers
            .into_iter()
            .filter_map(|ip| match ip {
                IpAddr::Ip4(ip) => {
                    dns4_servers.push(ip);
                    None
                }
                IpAddr::Ip6(ip) => Some(ip),
            })
            .collect();

        Self {
            hostname: value.hostname,
            host_domain: value.host_domain,
            domain_search_list: value.domain_search_list,
            dns4_servers,
            dns6_servers,
        }
    }
}

fn opte_pkg_version() -> String {
    format!("{MAJOR_VERSION}.{API_VERSION}.{COMMIT_COUNT}")
}

fn print_port_header(t: &mut impl Write) -> std::io::Result<()> {
    writeln!(
        t,
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        "LINK",
        "MAC ADDRESS",
        "IPv4 ADDRESS",
        "EPHEMERAL IPv4",
        "FLOATING IPv4",
        "IPv6 ADDRESS",
        "EXTERNAL IPv6",
        "FLOATING IPv6",
        "STATE"
    )
}

fn print_port(t: &mut impl Write, pi: PortInfo) -> std::io::Result<()> {
    let none = "None".to_string();
    let n_rows = pi
        .floating_ip4_addrs
        .as_ref()
        .map(|v| v.len())
        .unwrap_or(1)
        .max(pi.floating_ip6_addrs.as_ref().map(|v| v.len()).unwrap_or(1));

    writeln!(
        t,
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        pi.name,
        pi.mac_addr.to_string(),
        pi.ip4_addr.map(|x| x.to_string()).unwrap_or_else(|| none.clone()),
        pi.ephemeral_ip4_addr
            .map(|x| x.to_string())
            .unwrap_or_else(|| none.clone()),
        pi.floating_ip4_addrs
            .as_ref()
            .and_then(|vec| vec.first())
            .map(|x| x.to_string())
            .unwrap_or_else(|| none.clone()),
        pi.ip6_addr.map(|x| x.to_string()).unwrap_or_else(|| none.clone()),
        pi.ephemeral_ip6_addr
            .map(|x| x.to_string())
            .unwrap_or_else(|| none.clone()),
        pi.floating_ip6_addrs
            .as_ref()
            .and_then(|vec| vec.first())
            .map(|x| x.to_string())
            .unwrap_or_else(|| none.clone()),
        pi.state,
    )?;

    for i in 1..n_rows {
        writeln!(
            t,
            "\t\t\t\t{}\t\t\t{}\t",
            pi.floating_ip4_addrs
                .as_ref()
                .and_then(|vec| vec.get(i))
                .map(|x| x.to_string())
                .unwrap_or_else(String::new),
            pi.floating_ip6_addrs
                .as_ref()
                .and_then(|vec| vec.get(i))
                .map(|x| x.to_string())
                .unwrap_or_else(String::new),
        )?;
    }

    if n_rows > 1 {
        // This is required over a plain \n to preserve column alignment
        // between all ports.
        writeln!(t, "\t\t\t\t\t\t\t\t",)?;
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cmd = Command::parse();
    let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;

    match cmd {
        Command::ListPorts => {
            let mut t = TabWriter::new(std::io::stdout());
            print_port_header(&mut t)?;
            for p in hdl.list_ports()?.ports {
                print_port(&mut t, p)?;
            }
            t.flush()?;
        }

        Command::ListLayers { port } => {
            print_list_layers(&hdl.list_layers(&port)?)?;
        }

        Command::DumpLayer { port, name } => {
            let resp = &hdl.get_layer_by_name(&port, &name)?;
            print!("Port {port} - ");
            print_layer(&resp)?;
        }

        Command::ClearUft { port } => {
            hdl.clear_uft(&port)?;
        }

        Command::ClearLft { port, layer } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;
            hdl.clear_lft(&port, &layer)?;
        }

        Command::DumpUft { port } => {
            print_uft(&hdl.dump_uft(&port)?)?;
        }

        Command::DumpTcpFlows { port } => {
            print_tcp_flows(&hdl.dump_tcp_flows(&port)?)?;
        }

        Command::DumpV2P => {
            print_v2p(&hdl.dump_v2p()?)?;
        }

        Command::DumpV2B => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;
            print_v2b(&hdl.dump_v2b()?)?;
        }

        Command::AddFwRule { port, direction, filters, action, priority } => {
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
            vpc_vni,
            src_underlay_addr,
            dhcp,
            external_net,
            passthrough,
        } => {
            let ip_cfg = match private_ip {
                IpAddr::Ip4(private_ip) => {
                    let IpCidr::Ip4(vpc_subnet) = vpc_subnet else {
                        anyhow::bail!("expected IPv4 VPC subnet");
                    };

                    let IpAddr::Ip4(gateway_ip) = gateway_ip else {
                        anyhow::bail!("expected IPv4 gateway IP");
                    };

                    let external_ips = external_net.try_into()?;

                    IpCfg::Ipv4(Ipv4Cfg {
                        vpc_subnet,
                        private_ip,
                        gateway_ip,
                        external_ips,
                    })
                }
                IpAddr::Ip6(private_ip) => {
                    let IpCidr::Ip6(vpc_subnet) = vpc_subnet else {
                        anyhow::bail!("expected IPv6 VPC subnet");
                    };

                    let IpAddr::Ip6(gateway_ip) = gateway_ip else {
                        anyhow::bail!("expected IPv6 gateway IP");
                    };

                    let external_ips = external_net.try_into()?;

                    IpCfg::Ipv6(Ipv6Cfg {
                        vpc_subnet,
                        private_ip,
                        gateway_ip,
                        external_ips,
                    })
                }
            };

            let cfg = VpcCfg {
                ip_cfg,
                guest_mac,
                gateway_mac,
                vni: vpc_vni,
                phys_ip: src_underlay_addr,
            };

            hdl.create_xde(&name, cfg, dhcp.into(), passthrough)?;
        }

        Command::DeleteXde { name } => {
            let _ = hdl.delete_xde(&name)?;
        }

        Command::SetXdeUnderlay { u1, u2 } => {
            let _ = hdl.set_xde_underlay(&u1, &u2)?;
        }

        Command::RmFwRule { port, direction, id } => {
            let request = RemFwRuleReq { port_name: port, dir: direction, id };
            hdl.remove_firewall_rule(&request)?;
        }

        Command::SetV2P { vpc_ip, vpc_mac, underlay_ip, vni } => {
            let phys = PhysNet { ether: vpc_mac, ip: underlay_ip, vni };
            let req = SetVirt2PhysReq { vip: vpc_ip, phys };
            hdl.set_v2p(&req)?;
        }

        Command::SetV2B { prefix, tunnel_endpoint } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;
            let tep = tunnel_endpoint
                .into_iter()
                .map(|ip| TunnelEndpoint {
                    ip,
                    vni: Vni::new(BOUNDARY_SERVICES_VNI).unwrap(),
                })
                .collect();
            let req = SetVirt2BoundaryReq { vip: prefix, tep };
            hdl.set_v2b(&req)?;
        }

        Command::ClearV2B { prefix, tunnel_endpoint } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::XDE_CTL)?;
            let tep = tunnel_endpoint
                .into_iter()
                .map(|ip| TunnelEndpoint {
                    ip,
                    vni: Vni::new(BOUNDARY_SERVICES_VNI).unwrap(),
                })
                .collect();
            let req = ClearVirt2BoundaryReq { vip: prefix, tep };
            hdl.clear_v2b(&req)?;
        }

        Command::AddRouterEntry {
            route: RouterRule { port, dest, target, class },
        } => {
            let req =
                AddRouterEntryReq { port_name: port, dest, target, class };
            hdl.add_router_entry(&req)?;
        }

        Command::DelRouterEntry {
            route: RouterRule { port, dest, target, class },
        } => {
            let req =
                DelRouterEntryReq { port_name: port, dest, target, class };
            if let DelRouterEntryResp::NotFound = hdl.del_router_entry(&req)? {
                anyhow::bail!(
                    "could not delete entry -- no matching rule found"
                );
            }
        }

        Command::SetExternalIps { port, external_net } => {
            if let Ok(cfg) =
                ExternalIpCfg::<Ipv4Addr>::try_from(external_net.clone())
            {
                let req = SetExternalIpsReq {
                    port_name: port,
                    external_ips_v4: Some(cfg),
                    external_ips_v6: None,
                };
                hdl.set_external_ips(&req)?;
            } else if let Ok(cfg) =
                ExternalIpCfg::<Ipv6Addr>::try_from(external_net)
            {
                let req = SetExternalIpsReq {
                    port_name: port,
                    external_ips_v6: Some(cfg),
                    external_ips_v4: None,
                };
                hdl.set_external_ips(&req)?;
            } else {
                // TODO: show *actual* parse failure.
                anyhow::bail!("expected IPv4 *or* IPv6 config.");
            }
        }

        Command::AllowCidr { port, prefix } => {
            hdl.allow_cidr(&port, prefix)?;
        }

        Command::RemoveCidr { port, prefix } => {
            if let RemoveCidrResp::NotFound = hdl.remove_cidr(&port, prefix)? {
                anyhow::bail!(
                    "could not remove cidr {prefix} from gateway -- not found"
                );
            }
        }
    }

    Ok(())
}

#![feature(extern_types)]

use std::convert::TryInto;
use std::net::Ipv6Addr;

use structopt::StructOpt;

use opte_core::ether::EtherAddr;
use opte_core::flow_table::FlowEntryDump;
use opte_core::geneve;
use opte_core::geneve::Vni;
use opte_core::headers::IpAddr;
use opte_core::ioctl::{self as api, AddPortReq, PortInfo};
use opte_core::ip4::{Ipv4Addr, Ipv4Cidr};
use opte_core::ip6 as opte_ip6;
use opte_core::layer::InnerFlowId;
use opte_core::oxide_net::firewall::{
    self, Action, Address, FirewallRule, FwRemRuleReq, Ports, ProtoFilter,
};
use opte_core::oxide_net::{overlay, router};
use opte_core::rule::RuleDump;
use opte_core::vpc::VpcSubnet4;
use opte_core::Direction;
use opteadm::OpteAdm;

/// Administer the Oxide Packet Transformation Engine (OPTE)
#[derive(Debug, StructOpt)]
enum Command {
    /// List all ports.
    ListPorts,

    /// Add a new port.
    AddPort(AddPort),

    /// Delete an existing port.
    DeletePort {
        #[structopt(long)]
        name: String,
    },

    /// Set the overlay configuration.
    SetOverlay(SetOverlay),

    // List all layers under a given port.
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

    /// Dump the unified flow tables (UFT)
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
        action: Action,

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

    XdeCreate {
        name: String,
        private_mac: String,
        private_ip: String,
        gateway_mac: String,
        gateway_ip: String,
        boundary_services_addr: std::net::Ipv6Addr,
        boundary_services_vni: Vni,
        vpc_vni: Vni,
        src_underlay_addr: std::net::Ipv6Addr,
        #[structopt(long)]
        passthrough: bool,
    },

    XdeDelete {
        name: String,
    },

    /// Set a virtual-to-physical mapping
    SetV2P {
        vip4: Ipv4Addr,
        phys_ether: EtherAddr,
        phys_ip: Ipv6Addr,
        vni: geneve::Vni,
    },

    /// Add a new IPv4 router entry
    AddRouterEntryIpv4 {
        #[structopt(short)]
        port: String,

        dest: Ipv4Cidr,

        target: router::RouterTarget,
    },
}

#[derive(Debug, StructOpt)]
struct SetOverlay {
    #[structopt(short)]
    port: String,

    #[structopt(flatten)]
    boundary_services: BoundarySvcs,

    #[structopt(long)]
    vni: u32,

    #[structopt(long)]
    ip: Ipv6Addr,
}

#[derive(Debug, StructOpt)]
struct BoundarySvcs {
    #[structopt(long)]
    bs_mac_addr: EtherAddr,

    #[structopt(long)]
    bs_ip: std::net::Ipv6Addr,

    #[structopt(long)]
    bs_vni: u32,
}

impl From<BoundarySvcs> for overlay::PhysNet {
    fn from(bs: BoundarySvcs) -> Self {
        Self {
            ether: bs.bs_mac_addr,
            ip: opte_ip6::Ipv6Addr::from(bs.bs_ip),
            vni: geneve::Vni::new(bs.bs_vni).unwrap(),
        }
    }
}

impl From<SetOverlay> for overlay::SetOverlayReq {
    fn from(req: SetOverlay) -> Self {
        Self {
            port_name: req.port,
            cfg: overlay::OverlayCfg {
                boundary_services: overlay::PhysNet::from(
                    req.boundary_services,
                ),
                vni: geneve::Vni::new(req.vni).unwrap(),
                phys_ip_src: opte_ip6::Ipv6Addr::from(req.ip.octets()),
            },
        }
    }
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

impl From<Filters> for firewall::Filters {
    fn from(f: Filters) -> Self {
        Self::new()
            .set_hosts(f.hosts)
            .protocol(f.protocol)
            .ports(f.ports)
            .clone()
    }
}

#[derive(Debug, StructOpt)]
struct AddPort {
    #[structopt(long)]
    name: String,

    #[structopt(flatten)]
    port_cfg: PortCfg,
}

impl From<AddPort> for AddPortReq {
    fn from(r: AddPort) -> Self {
        Self { link_name: r.name, port_cfg: api::PortCfg::from(r.port_cfg) }
    }
}

// The port configuration determines the networking configuration of
// said port (and thus the guest that is linked to it).
#[derive(Debug, StructOpt)]
struct PortCfg {
    #[structopt(long)]
    private_ip: Ipv4Addr,

    #[structopt(long)]
    snat: Option<SnatCfg>,
}

impl From<PortCfg> for api::PortCfg {
    fn from(s: PortCfg) -> Self {
        Self { private_ip: s.private_ip, snat: s.snat.map(api::SnatCfg::from) }
    }
}

// A Source NAT (SNAT) configuration. This configuration allows a
// guest to map its private IP to a slice of a public IP, by
// allocating a contiguous range of ports from that public IP to the
// private IP. This range is then used to perform outgoing NAT for the
// purposes of allowing the guest to talk to the internet without a
// dedicated public IP.
#[derive(Debug, StructOpt)]
struct SnatCfg {
    #[structopt(long)]
    public_mac: EtherAddr,

    #[structopt(long)]
    public_ip: Ipv4Addr,

    #[structopt(long)]
    port_start: u16,

    #[structopt(long)]
    port_end: u16,

    #[structopt(long)]
    vpc_sub4: VpcSubnet4,
}

impl From<SnatCfg> for api::SnatCfg {
    fn from(s: SnatCfg) -> Self {
        Self {
            public_mac: s.public_mac,
            public_ip: s.public_ip,
            port_start: s.port_start,
            port_end: s.port_end,
            vpc_sub4: s.vpc_sub4,
        }
    }
}

impl std::str::FromStr for SnatCfg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut public_mac = None;
        let mut public_ip = None;
        let mut port_start = None;
        let mut port_end = None;
        let mut vpc_sub4 = None;

        for token in s.split(" ") {
            match token.split_once("=") {
                Some(("public_mac", val)) => {
                    public_mac = Some(val.parse()?);
                }

                Some(("public_ip", val)) => {
                    public_ip = Some(val.parse()?);
                }

                Some(("port_start", val)) => {
                    port_start =
                        Some(val.parse::<u16>().map_err(|e| e.to_string())?);
                }

                Some(("port_end", val)) => {
                    port_end =
                        Some(val.parse::<u16>().map_err(|e| e.to_string())?);
                }

                Some(("vpc_sub4", val)) => {
                    vpc_sub4 = Some(val.parse()?);
                }

                _ => {
                    return Err(format!("bad token: {}", token));
                }
            };
        }

        if public_mac == None {
            return Err(format!("missing public_mac"));
        }

        if public_ip == None {
            return Err(format!("missing public_ip"));
        }

        if port_start == None {
            return Err(format!("missing port_start"));
        }

        if port_end == None {
            return Err(format!("missing port_end"));
        }

        if vpc_sub4 == None {
            return Err(format!("missing vpc_sub4"));
        }

        Ok(Self {
            public_mac: public_mac.unwrap(),
            public_ip: public_ip.unwrap(),
            port_start: port_start.unwrap(),
            port_end: port_end.unwrap(),
            vpc_sub4: vpc_sub4.unwrap(),
        })
    }
}

fn print_port_header() {
    println!(
        "{:<32} {:<24} {:<16} {:<6}",
        "LINK", "MAC ADDRESS", "IPv4 ADDRESS", "IN USE"
    );
}

fn print_port(pi: PortInfo) {
    println!(
        "{:<32} {:<24} {:<16} {:<6}",
        pi.name,
        pi.mac_addr.to_string(),
        pi.ip4_addr.to_string(),
        if pi.in_use { "Y".to_string() } else { "N".to_string() },
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
    let mut preds = rule
        .predicates
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<String>>()
        .join(" ");
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
        "{:<12} {:<10} {:<10} {:<10} {:<10}",
        "NAME", "RULES IN", "RULES OUT", "FLOWS IN", "FLOWS OUT"
    );

    for desc in &resp.layers {
        println!(
            "{:<12} {:<10} {:<10} {:<10} {:<10}",
            desc.name,
            desc.rules_in,
            desc.rules_out,
            desc.flows_in,
            desc.flows_out,
        );
    }
}

fn print_v2p(resp: &overlay::GetVirt2PhysResp) {
    println!("ipv4");
    println!(
        "{:<12} {:<20} {:<20} {:<10}",
        "SOURCE", "DEST ETH", "DEST IP", "VNI"
    );

    for (src, dst) in &resp.ip4 {
        //XXX something about the Display impl for these types is interacting
        //badly with column layout
        let v4 = std::net::Ipv4Addr::from(src.to_be_bytes());
        let v6 = std::net::Ipv6Addr::from(dst.ip.to_bytes());
        let eth = format!("{}", dst.ether);
        println!("{:<12} {:<20} {:<20} {:<10}", v4, eth, v6, dst.vni.value(),);
    }

    println!("ipv6");
    println!(
        "{:<12} {:<20} {:<20} {:<10}",
        "SOURCE", "DEST ETH", "DEST IP", "VNI"
    );

    for (src, dst) in &resp.ip6 {
        //XXX something about the Display impl for these types is interacting
        //badly with column layout
        let v6s = std::net::Ipv6Addr::from(src.to_bytes());
        let v6 = std::net::Ipv6Addr::from(dst.ip.to_bytes());
        let eth = format!("{}", dst.ether);
        println!("{:<12} {:<20} {:<20} {:<10}", v6s, eth, v6, dst.vni.value(),);
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

fn main() {
    let cmd = Command::from_args();
    match cmd {
        Command::ListPorts => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::OPTE_CTL).unwrap();
            print_port_header();
            for p in hdl.list_ports().unwrap().ports {
                print_port(p);
            }
        }

        Command::AddPort(req) => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::OPTE_CTL).unwrap();
            hdl.add_port(&req.try_into().unwrap()).unwrap();
        }

        Command::DeletePort { name } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::OPTE_CTL).unwrap();
            hdl.delete_port(&name).unwrap();
        }

        Command::SetOverlay(req) => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::OPTE_CTL).unwrap();
            hdl.set_overlay(&req.into()).unwrap();
        }

        Command::ListLayers { port } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap();
            print_list_layers(&hdl.list_layers(&port).unwrap());
        }

        Command::DumpLayer { port, name } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap();
            print_layer(&hdl.get_layer_by_name(&port, &name).unwrap());
        }

        Command::DumpUft { port } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap();
            print_uft(&hdl.uft(&port).unwrap());
        }

        Command::DumpTcpFlows { port } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::OPTE_CTL).unwrap();
            for (flow_id, entry) in hdl.tcp_flows(&port).unwrap().flows {
                println!("{} {:?}", flow_id, entry);
            }
        }

        Command::DumpV2P => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap();
            print_v2p(&hdl.get_v2p().unwrap());
        }

        Command::AddFwRule { port, direction, filters, action, priority } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap();
            let rule = FirewallRule {
                direction,
                filters: filters.into(),
                action,
                priority,
            };
            hdl.add_firewall_rule(&port, &rule).unwrap();
        }

        Command::XdeCreate {
            name,
            private_mac,
            private_ip,
            gateway_mac,
            gateway_ip,
            boundary_services_addr,
            boundary_services_vni,
            vpc_vni,
            src_underlay_addr,
            passthrough,
        } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap();
            hdl.create_xde(
                &name,
                &private_mac,
                &private_ip,
                &gateway_mac,
                &gateway_ip,
                boundary_services_addr,
                boundary_services_vni,
                vpc_vni,
                src_underlay_addr,
                passthrough,
            )
            .unwrap();
        }

        Command::XdeDelete { name } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap();
            hdl.delete_xde(&name).unwrap();
        }

        Command::RmFwRule { port, direction, id } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap();
            let request = FwRemRuleReq { port_name: port, dir: direction, id };
            hdl.remove_firewall_rule(&request).unwrap();
        }

        Command::SetV2P { vip4, phys_ether, phys_ip, vni } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap();
            let vip = IpAddr::Ip4(vip4);
            let phys = overlay::PhysNet {
                ether: phys_ether,
                ip: opte_ip6::Ipv6Addr::from(phys_ip),
                vni,
            };
            let req = overlay::SetVirt2PhysReq { vip, phys };
            hdl.set_v2p(&req).unwrap();
        }

        Command::AddRouterEntryIpv4 { port, dest, target } => {
            let hdl = opteadm::OpteAdm::open(OpteAdm::DLD_CTL).unwrap();
            let req =
                router::AddRouterEntryIpv4Req { port_name: port, dest, target };
            hdl.add_router_entry_ip4(&req).unwrap();
        }
    }
}

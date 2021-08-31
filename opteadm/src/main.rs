#![feature(extern_types)]

use std::convert::TryInto;
use std::net::Ipv4Addr;

use structopt::StructOpt;

use opte_core::firewallng::FwRemRuleReq;
use opte_core::firewallng::{
    self, Action, Address, FirewallRule, Ports, ProtoFilter,
};
use opte_core::flow_table::FlowEntryDump;
use opte_core::ioctl::SetIpConfigReq;
use opte_core::layer::{InnerFlowId, IpAddr, LayerDumpResp};
use opte_core::port::UftDumpResp;
use opte_core::rule::RuleDump;
use opte_core::Direction;

/// Administer the Oxide Packet Transformation Engine (OPTE)
#[derive(Debug, StructOpt)]
enum Command {
    SetIpConfig(SetIpConfig),

    /// Dump the contents of the layer with the given name
    LayerDump {
        name: String,
    },

    /// Dump the unified flow tables (UFT)
    UftDump,

    /// Dump TCP flows
    TcpFlowsDump,

    /// Add a firewall rule
    FwAdd {
        direction: Direction,
        #[structopt(flatten)]
        filters: Filters,
        action: Action,
        priority: u16,
    },

    /// Remove a firewall rule
    FwRm {
        direction: Direction,
        id: u64,
    },
}

#[derive(Debug, StructOpt)]
struct Filters {
    /// The host address or subnet to which the rule applies
    hosts: Address,

    /// The protocol to which the rule applies
    protocol: ProtoFilter,

    /// The port(s) to which the rule applies
    ports: Ports,
}

impl From<Filters> for firewallng::Filters {
    fn from(f: Filters) -> Self {
        firewallng::Filters::new()
            .set_hosts(f.hosts)
            .protocol(f.protocol)
            .ports(f.ports)
            .clone()
    }
}

/// Create an IP configuration in OPTE
#[derive(Debug, StructOpt)]
struct SetIpConfig {
    /// Private IP address
    #[structopt(long)]
    private_ip: Ipv4Addr,

    /// Public IP address
    #[structopt(long)]
    public_ip: Ipv4Addr,

    /// Start port
    #[structopt(long)]
    port_start: u16,

    /// End port
    #[structopt(long)]
    port_end: u16,

    /// VPC subnet
    #[structopt(long)]
    vpc_sub4: String,
}

impl From<SetIpConfig> for SetIpConfigReq {
    fn from(s: SetIpConfig) -> SetIpConfigReq {
        SetIpConfigReq {
            private_ip: s.private_ip.to_string(),
            public_ip: s.public_ip.to_string(),
            port_start: s.port_start.to_string(),
            port_end: s.port_end.to_string(),
            vpc_sub4: s.vpc_sub4,
        }
    }
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

    println!("{:<8} {:<6} {:<48} {:<?}", id, rule.priority, preds, rule.action,);
}

fn print_hrb() {
    println!("{:=<70}", "=");
}

fn print_hr() {
    println!("{:-<70}", "-");
}

fn print_layer(resp: &LayerDumpResp) {
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

fn print_uft(resp: &UftDumpResp) {
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
    let handle = opteadm::OpteAdm::new().unwrap();
    match cmd {
        Command::SetIpConfig(request) => {
            handle.set_ip_config(&request.try_into().unwrap()).unwrap();
        }
        Command::LayerDump { name } => {
            print_layer(&handle.get_layer_by_name(&name).unwrap());
        }
        Command::UftDump => {
            print_uft(&handle.uft().unwrap());
        }
        Command::TcpFlowsDump => {
            for (flow_id, entry) in handle.tcp_flows().unwrap() {
                println!("{} {:?}", flow_id, entry);
            }
        }
        Command::FwAdd { direction, filters, action, priority } => {
            let rule = FirewallRule {
                direction,
                filters: filters.into(),
                action,
                priority,
            };
            handle.add_firewall_rule(&rule).unwrap();
        }
        Command::FwRm { direction, id } => {
            let request = FwRemRuleReq { dir: direction, id };
            handle.remove_firewall_rule(&request).unwrap();
        }
    }
}

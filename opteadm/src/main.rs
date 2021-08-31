#![feature(extern_types)]

use std::convert::TryInto;
use std::net::Ipv4Addr;

use structopt::StructOpt;

use opte_core::ether::EtherAddr;
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

use illumos_ddi_dki::minor_t;

/// Administer the Oxide Packet Transformation Engine (OPTE)
#[derive(Debug, StructOpt)]
enum Command {
    ListPorts,

    SetIpConfig(SetIpConfig),

    /// Dump the contents of the layer with the given name
    LayerDump {
        #[structopt(short)]
        port: String,
        name: String,
    },

    /// Dump the unified flow tables (UFT)
    UftDump {
        #[structopt(short)]
        port: String,
    },

    /// Dump TCP flows
    TcpFlowsDump {
        #[structopt(short)]
        port: String
    },

    /// Add a firewall rule
    FwAdd {
        #[structopt(short)]
        port: String,

        #[structopt(long="dir")]
        direction: Direction,

        #[structopt(flatten)]
        filters: Filters,

        #[structopt(long)]
        action: Action,

        #[structopt(long)]
        priority: u16,
    },

    /// Remove a firewall rule
    FwRm {
        #[structopt(short)]
        port: String,

        #[structopt(long="dir")]
        direction: Direction,

        id: u64,
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

impl From<Filters> for firewallng::Filters {
    fn from(f: Filters) -> Self {
        firewallng::Filters::new()
            .set_hosts(f.hosts)
            .protocol(f.protocol)
            .ports(f.ports)
            .clone()
    }
}

// TODO I have to move this to lib.rs
// fn list_ports(dev: c_int) -> ListPortsResp {
//     let mut req = ListPortsReq { unused: () };
//     let resp: ListPortsResp =
//         run_ioctl(dev, IoctlCmd::ListPorts, &mut req).unwrap();
//     resp
// }

/// Create an IP configuration in OPTE
#[derive(Debug, StructOpt)]
struct SetIpConfig {
    #[structopt(short)]
    port: String,

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

    /// Gateway IP
    #[structopt(long)]
    gw_ip: Ipv4Addr,

    /// Gateway MAC address
    #[structopt(long)]
    gw_mac: EtherAddr
}

impl From<SetIpConfig> for SetIpConfigReq {
    fn from(s: SetIpConfig) -> SetIpConfigReq {
        SetIpConfigReq {
            private_ip: s.private_ip.to_string(),
            public_ip: s.public_ip.to_string(),
            port_start: s.port_start.to_string(),
            port_end: s.port_end.to_string(),
            vpc_sub4: s.vpc_sub4,
            gw_ip: s.gw_ip.to_string(),
            gw_mac: s.gw_mac.to_string(),
        }
    }
}

fn print_port_header() {
    println!("{:<6} {:<32} {:<24}", "MINOR", "LINK", "MAC ADDRESS");
}

fn print_port((minor, link, mac): (minor_t, String, EtherAddr)) {
    println!("{:<6} {:<32} {:<42}", minor, link, mac);
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


// TODO: Figure out how to integrate the list-ports and multiple
// instance stuff with Ben's work

// fn main() {
//     let args: Vec<String> = std::env::args().collect();

//     if args.len() == 2 {
//         let cmd = &args[1];

//         if cmd == "list-ports" {
//             let dev = CString::new(OPTE_DEV).unwrap();
//             let fd = unsafe { open(dev.as_ptr(), O_RDWR) };
//             if fd == -1 {
//                 unsafe {
//                     eprintln!(
//                         "failed to open opte device: {}",
//                         *libc::___errno()
//                     );
//                 }
//                 process::exit(1);
//             }

//             let resp = list_ports(fd);
//             print_port_header();
//             for x in resp.links {
//                 print_port(x);
//             }

//             unsafe { close(fd) };
//             process::exit(0);
//         }
//     }

//     if args.len() >= 3 {
//         let link = &args[1];
//         let cmd = &args[2];
//         let path = format!("/devices/pseudo/opte@0:{}", link);
//         let dev = CString::new(path.clone()).unwrap();
//         let fd = unsafe { open(dev.as_ptr(), O_RDWR) };
//         if fd == -1 {
//             unsafe {
//                 eprintln!("failed to open {}: {}", path, *libc::___errno());
//             }
//             process::exit(1);
//         }

//         if cmd == "layer-dump" {
//             if args.len() == 3 {
//                 eprintln!("must specify layer name");
//                 process::exit(1);
//             }

//             let resp = dump_layer(fd, &args[3]);
//             println!("Layer {}", resp.name);
//             print_hrb();
//             println!("Inbound Flows");
//             print_hr();
//             print_flow_header();
//             for (flow_id, flow_state) in resp.ft_in {
//                 print_flow(flow_id, flow_state);
//             }

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
    match cmd {
        Command::ListPorts => {
            let hdl = opteadm::OpteAdm::open_ctl().unwrap();
            print_port_header();
            for p in hdl.list_ports().unwrap().links {
                print_port(p);
            }
        }

        Command::SetIpConfig(req) => {
            let hdl = opteadm::OpteAdm::open_port(&req.port).unwrap();
            hdl.set_ip_config(&req.try_into().unwrap()).unwrap();
        }

        Command::LayerDump { port, name } => {
            let hdl = opteadm::OpteAdm::open_port(&port).unwrap();
            print_layer(&hdl.get_layer_by_name(&name).unwrap());
        }

        Command::UftDump { port } => {
            let hdl = opteadm::OpteAdm::open_port(&port).unwrap();
            print_uft(&hdl.uft().unwrap());
        }

        Command::TcpFlowsDump { port } => {
            let hdl = opteadm::OpteAdm::open_port(&port).unwrap();
            for (flow_id, entry) in hdl.tcp_flows().unwrap() {
                println!("{} {:?}", flow_id, entry);
            }
        }

        Command::FwAdd { port, direction, filters, action, priority } => {
            let hdl = opteadm::OpteAdm::open_port(&port).unwrap();
            let rule = FirewallRule {
                direction,
                filters: filters.into(),
                action,
                priority,
            };
            hdl.add_firewall_rule(&rule).unwrap();
        }

        Command::FwRm { port, direction, id } => {
            let hdl = opteadm::OpteAdm::open_port(&port).unwrap();
            let request = FwRemRuleReq { dir: direction, id };
            hdl.remove_firewall_rule(&request).unwrap();
        }
    }
}

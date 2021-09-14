#![feature(extern_types)]
#![allow(unused_imports)]

extern crate opte_core;

use libc::{close, ioctl, malloc, open, strlen, strncpy, O_RDWR};
use std::ffi::{CStr, CString};
use std::fmt;
use std::mem;
use std::os::raw::{c_char, c_int, c_void};
use std::process;
use std::ptr;
use std::slice;
use std::str::FromStr;

use opte_core::ether::EtherAddr;
use opte_core::firewallng::{
    FwAddRuleReq, FwAddRuleResp, FwRemRuleReq, FwRemRuleResp,
};
use opte_core::flow_table::{FlowEntryDump, FlowTable};
use opte_core::ioctl::{
    Ioctl, IoctlCmd, ListPortsReq, ListPortsResp, SetIpConfigReq,
    SetIpConfigResp
};
use opte_core::layer::{InnerFlowId, IpAddr, LayerDumpReq, LayerDumpResp};
use opte_core::port::{
    TcpFlowsDumpReq, TcpFlowsDumpResp, UftDumpReq, UftDumpResp,
};
use opte_core::rule::{ActionSummary, RuleDump};
use opte_core::tcp_state::TcpFlowState;
use opte_core::Direction;

extern crate illumos_ddi_dki;
use illumos_ddi_dki::minor_t;

use serde::de::DeserializeOwned;
use serde::Serialize;

extern crate postcard;

const OPTE_DEV: &str = "/dev/opte";

fn run_ioctl<R, P>(
    dev: c_int,
    cmd: IoctlCmd,
    req: &mut R,
) -> Result<P, postcard::Error>
where
    R: Serialize,
    P: DeserializeOwned,
{
    let mut iterations = 0;
    let req_bytes = postcard::to_allocvec(req).unwrap();
    let mut resp_buf: Vec<u8> = vec![0; 32];
    let mut rioctl = Ioctl {
        req_bytes: req_bytes.as_ptr(),
        req_len: req_bytes.len(),
        resp_bytes: resp_buf.as_mut_ptr(),
        resp_len: resp_buf.len(),
        resp_len_needed: 0,
    };

    loop {
        let ret = unsafe { ioctl(dev, cmd as c_int, &rioctl) };

        unsafe {
            if ret == -1 && *libc::___errno() != libc::ENOBUFS {
                eprintln!("ioctl failed: {:?}: {:?}", cmd, *libc::___errno());

                // If no response length was specified by the driver,
                // then we know it didn't understand the `cmd`. This
                // is either caused by a mismatch between kernel
                // driver and opteadm, or a missing match case in
                // `IoctlCmd::try_from::<c_int>()`
                if rioctl.resp_len_needed == 0 {
                    eprintln!("unrecognized cmd: {:?}", cmd);
                    process::exit(1);
                }

                return postcard::from_bytes(slice::from_raw_parts(
                    rioctl.resp_bytes,
                    rioctl.resp_len_needed,
                ));
            }
        }

        // TODO Probably want a separate field to indicate response
        // len needed: e.g. resp_len is the length of buffer supplied
        // by userspace and resp_len_needed is length needed.
        assert!(rioctl.resp_len_needed != 0);
        if rioctl.resp_len_needed > rioctl.resp_len {
            if iterations > 3 {
                eprintln!(
                    "failed to dump fw tables after {} iterations",
                    iterations
                );
                unsafe { close(dev) };
                process::exit(1);
            }

            iterations += 1;
            resp_buf = Vec::with_capacity(rioctl.resp_len_needed);
            for _i in 0..rioctl.resp_len_needed {
                resp_buf.push(0);
            }
            rioctl = Ioctl {
                req_bytes: req_bytes.as_ptr(),
                req_len: req_bytes.len(),
                resp_bytes: resp_buf.as_mut_ptr(),
                resp_len: resp_buf.len(),
                resp_len_needed: 0,
            };

            continue;
        } else {
            break;
        }
    }

    unsafe {
        postcard::from_bytes(slice::from_raw_parts(
            rioctl.resp_bytes,
            rioctl.resp_len_needed,
        ))
    }
}

fn list_ports(dev: c_int) -> ListPortsResp {
    let mut req = ListPortsReq { unused: () };
    let resp: ListPortsResp =
        run_ioctl(dev, IoctlCmd::ListPorts, &mut req).unwrap();
    resp
}

fn dump_layer(dev: c_int, name: &str) -> LayerDumpResp {
    let mut req = LayerDumpReq { name: name.to_string() };
    let resp: LayerDumpResp =
        run_ioctl(dev, IoctlCmd::LayerDump, &mut req).unwrap();
    resp
}

fn dump_tcp_flows(dev: c_int) -> Vec<(InnerFlowId, FlowEntryDump)> {
    let mut req = TcpFlowsDumpReq { req: () };
    let resp: TcpFlowsDumpResp =
        run_ioctl(dev, IoctlCmd::TcpFlowsDump, &mut req).unwrap();
    resp.flows
}

fn dump_uft(dev: c_int) -> UftDumpResp {
    let mut req = UftDumpReq { unused: () };
    let resp: UftDumpResp =
        run_ioctl(dev, IoctlCmd::UftDump, &mut req).unwrap();
    resp
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

fn print_flow(flow_id: InnerFlowId, flow_entry: FlowEntryDump) {
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

fn print_rule(id: u64, rule: RuleDump) {
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

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() == 2 {
        let cmd = &args[1];

        if cmd == "list-ports" {
            let dev = CString::new(OPTE_DEV).unwrap();
            let fd = unsafe { open(dev.as_ptr(), O_RDWR) };
            if fd == -1 {
                unsafe {
                    eprintln!(
                        "failed to open opte device: {}",
                        *libc::___errno()
                    );
                }
                process::exit(1);
            }

            let resp = list_ports(fd);
            print_port_header();
            for x in resp.links {
                print_port(x);
            }

            unsafe { close(fd) };
            process::exit(0);
        }
    }

    if args.len() >= 3 {
        let link = &args[1];
        let cmd = &args[2];
        let path = format!("/devices/pseudo/opte@0:{}", link);
        let dev = CString::new(path.clone()).unwrap();
        let fd = unsafe { open(dev.as_ptr(), O_RDWR) };
        if fd == -1 {
            unsafe {
                eprintln!("failed to open {}: {}", path, *libc::___errno());
            }
            process::exit(1);
        }

        if cmd == "layer-dump" {
            if args.len() == 3 {
                eprintln!("must specify layer name");
                process::exit(1);
            }

            let resp = dump_layer(fd, &args[3]);
            println!("Layer {}", resp.name);
            print_hrb();
            println!("Inbound Flows");
            print_hr();
            print_flow_header();
            for (flow_id, flow_state) in resp.ft_in {
                print_flow(flow_id, flow_state);
            }

            println!("\nOutbound Flows");
            print_hr();
            print_flow_header();
            for (flow_id, flow_state) in resp.ft_out {
                print_flow(flow_id, flow_state);
            }

            println!("\nInbound Rules");
            print_hr();
            print_rule_header();
            for (id, rule) in resp.rules_in {
                print_rule(id, rule);
            }

            println!("\nOutbound Rules");
            print_hr();
            print_rule_header();
            for (id, rule) in resp.rules_out {
                print_rule(id, rule);
            }

            println!("");
        }

        if cmd == "uft-dump" {
            let resp = dump_uft(fd);
            println!("Unified Flow Table");
            print_hrb();
            println!(
                "Inbound Flows [{}/{}]",
                resp.uft_in_num_flows, resp.uft_in_limit
            );
            print_hr();
            print_flow_header();
            for (flow_id, flow_state) in resp.uft_in {
                print_flow(flow_id, flow_state);
            }

            println!(
                "\nOutbound Flows [{}/{}]",
                resp.uft_out_num_flows, resp.uft_out_limit
            );
            print_hr();
            print_flow_header();
            for (flow_id, flow_state) in resp.uft_out {
                print_flow(flow_id, flow_state);
            }

            println!("");
        }

        if cmd == "tcp-flows-dump" {
            let flows = dump_tcp_flows(fd);
            for (flow_id, entry) in flows {
                println!("{} {:?}", flow_id, entry);
            }
        }

        if cmd == "fw-add" {
            let rulestr = args[3..].join(" ");
            let rule = rulestr.parse().unwrap();
            let mut req = FwAddRuleReq { rule };
            let resp: FwAddRuleResp =
                run_ioctl(fd, IoctlCmd::FwAddRule, &mut req).unwrap();
            match resp.resp {
                Ok(()) => println!("added firewall rule"),
                Err(msg) => println!("failed to add firewall rule: {}", msg),
            }
        }

        if cmd == "fw-rm" {
            let dir = args[3].parse().unwrap();
            let id = args[4].parse().unwrap();
            let mut req = FwRemRuleReq { dir, id };
            let resp: FwRemRuleResp =
                run_ioctl(fd, IoctlCmd::FwRemRule, &mut req).unwrap();
            match resp.resp {
                Ok(()) => println!("removed firewall rule"),
                Err(msg) => println!("failed to remove firewall rule: {}", msg),
            }
        }

        if cmd == "set-ip-config" {
            let mut req: SetIpConfigReq = args[3..].join(" ").parse().unwrap();
            println!("Sending request: {:?}", req);
            let resp: SetIpConfigResp =
                run_ioctl(fd, IoctlCmd::SetIpConfig, &mut req).unwrap();
            match resp.resp {
                Ok(_) => println!("set IP config successfully"),
                Err(msg) => println!("error setting IP config: {}", msg),
            }
        }

        unsafe { close(fd) };
    }
}

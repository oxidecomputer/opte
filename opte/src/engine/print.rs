// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Print comannd responses in human-friendly manner.
//!
//! This is mostly just a place to hang printing routines so that they
//! can be used by both opteadm and integration tests.

use super::ioctl::ActionDescEntryDump;
use super::ioctl::DumpLayerResp;
use super::ioctl::DumpTcpFlowsResp;
use super::ioctl::DumpUftResp;
use super::ioctl::ListLayersResp;
use super::ioctl::RuleDump;
use super::ioctl::TcpFlowEntryDump;
use super::ioctl::UftEntryDump;
use super::packet::InnerFlowId;
use std::collections::VecDeque;
use std::string::String;
use std::string::ToString;

/// Print a [`DumpLayerResp`].
pub fn print_layer(resp: &DumpLayerResp) {
    println!("Layer {}", resp.name);
    print_hrb();
    println!("Inbound Flows");
    print_hr();
    print_lft_flow_header();
    for (flow_id, flow_state) in &resp.ft_in {
        print_lft_flow(flow_id, flow_state);
    }

    println!("\nOutbound Flows");
    print_hr();
    print_lft_flow_header();
    for (flow_id, flow_state) in &resp.ft_out {
        print_lft_flow(flow_id, flow_state);
    }

    println!("\nInbound Rules");
    print_hr();
    print_rule_header();
    for rte in &resp.rules_in {
        print_rule(rte.id, rte.hits, &rte.rule);
    }
    print_def_rule(resp.default_in_hits, &resp.default_in);

    println!("\nOutbound Rules");
    print_hr();
    print_rule_header();
    for rte in &resp.rules_out {
        print_rule(rte.id, rte.hits, &rte.rule);
    }
    print_def_rule(resp.default_out_hits, &resp.default_out);

    println!("");
}

/// Print a [`ListLayersResp`].
pub fn print_list_layers(resp: &ListLayersResp) {
    println!(
        "{:<12} {:<10} {:<10} {:<8} {:<8} {:<10}",
        "NAME", "RULES IN", "RULES OUT", "DEF IN", "DEF OUT", "FLOWS",
    );

    for desc in &resp.layers {
        println!(
            "{:<12} {:<10} {:<10} {:<8} {:<8} {:<10}",
            desc.name,
            desc.rules_in,
            desc.rules_out,
            desc.default_in,
            desc.default_out,
            desc.flows,
        );
    }
}

/// Print a [`DumpUftResp`].
pub fn print_uft(uft: &DumpUftResp) {
    println!("UFT Inbound: {}/{}", uft.in_num_flows, uft.in_limit);
    print_hr();
    print_uft_flow_header();
    for (flow_id, flow_state) in &uft.in_flows {
        print_uft_flow(flow_id, flow_state);
    }

    println!("");
    println!("UFT Outbound: {}/{}", uft.out_num_flows, uft.out_limit);
    print_hr();
    print_uft_flow_header();
    for (flow_id, flow_state) in &uft.out_flows {
        print_uft_flow(flow_id, flow_state);
    }
}

/// Print the header for the [`print_rule()`] output.
pub fn print_rule_header() {
    println!(
        "{:<6} {:<6} {:<6} {:<38} {:<18}",
        "ID", "PRI", "HITS", "PREDICATES", "ACTION"
    );
}

pub fn print_def_rule(hits: u64, action: &str) {
    println!("{:<6} {:<6} {:<6} {:<38} {:<?}", "DEF", "--", hits, "--", action);
}

/// Print a [`RuleDump`].
pub fn print_rule(id: u64, hits: u64, rule: &RuleDump) {
    let mut preds = rule
        .predicates
        .iter()
        .map(ToString::to_string)
        .chain(rule.data_predicates.iter().map(ToString::to_string))
        .collect::<VecDeque<String>>();

    let first_pred = if preds.len() == 0 {
        "*".to_string()
    } else {
        preds.pop_front().unwrap()
    };

    println!(
        "{:<6} {:<6} {:<6} {:<38} {:<?}",
        id, rule.priority, hits, first_pred, rule.action
    );

    let mut multi_preds = false;
    while let Some(pred) = preds.pop_front() {
        println!("{:<6} {:<6} {:<6} {:<38}", "", "", "", pred);
        multi_preds = true;
    }

    // If a rule has multiple predicates, add a blank line to get some
    // separation so it's easier to discern where one rule ends and
    // another begins.
    if multi_preds {
        println!("");
    }
}

/// Print the header for the [`print_lft_flow()`] output.
pub fn print_lft_flow_header() {
    println!(
        "{:<6} {:<16} {:<6} {:<16} {:<6} {:<8} {:<22}",
        "PROTO", "SRC IP", "SPORT", "DST IP", "DPORT", "HITS", "ACTION"
    );
}

/// Print information about a layer flow.
pub fn print_lft_flow(flow_id: &InnerFlowId, flow_entry: &ActionDescEntryDump) {
    // For those types with custom Display implementations we need to
    // first format in into a String before passing it to println in
    // order for the format specification to be honored.
    println!(
        "{:<6} {:<16} {:<6} {:<16} {:<6} {:<8} {:<22}",
        flow_id.proto.to_string(),
        flow_id.src_ip.to_string(),
        flow_id.src_port,
        flow_id.dst_ip.to_string(),
        flow_id.dst_port,
        flow_entry.hits,
        flow_entry.summary,
    );
}

/// Print the header for the [`print_uft_flow()`] output.
pub fn print_uft_flow_header() {
    println!(
        "{:<6} {:<16} {:<6} {:<16} {:<6} {:<8} {:<22}",
        "PROTO", "SRC IP", "SPORT", "DST IP", "DPORT", "HITS", "XFORMS"
    );
}

/// Print information about a UFT entry.
pub fn print_uft_flow(flow_id: &InnerFlowId, flow_entry: &UftEntryDump) {
    // For those types with custom Display implementations we need to
    // first format in into a String before passing it to println in
    // order for the format specification to be honored.
    println!(
        "{:<6} {:<16} {:<6} {:<16} {:<6} {:<8} {:<22}",
        flow_id.proto.to_string(),
        flow_id.src_ip.to_string(),
        flow_id.src_port,
        flow_id.dst_ip.to_string(),
        flow_id.dst_port,
        flow_entry.hits,
        flow_entry.summary,
    );
}

/// Print a [`DumpTcpFlowsResp`].
pub fn print_tcp_flows(flows: &DumpTcpFlowsResp) {
    println!(
        "{:<48} {:<12} {:<8} {:<8} {:<8} {:<10} {:<10}",
        "FLOW", "STATE", "HITS", "SEGS IN", "SEGS OUT", "BYTES IN", "BYTES OUT"
    );
    for (flow_id, entry) in &flows.flows {
        print_tcp_flow(flow_id, entry);
    }
}

fn print_tcp_flow(id: &InnerFlowId, entry: &TcpFlowEntryDump) {
    println!(
        "{:<48} {:<12} {:<8} {:<8} {:<8} {:<10} {:<10}",
        format!("{id}"),
        entry.tcp_state.tcp_state.to_string(),
        entry.hits,
        entry.segs_in,
        entry.segs_out,
        entry.bytes_in,
        entry.bytes_out,
    );
}

/// Print horizontal rule in bold.
pub fn print_hrb() {
    println!("{:=<70}", "=");
}

/// Print horizontal rule.
pub fn print_hr() {
    println!("{:-<70}", "-");
}

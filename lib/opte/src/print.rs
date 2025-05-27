// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Print comannd responses in human-friendly manner.
//!
//! This is mostly just a place to hang printing routines so that they
//! can be used by both opteadm and integration tests.

use crate::api::DumpLayerResp;
use crate::api::DumpTcpFlowsResp;
use crate::api::DumpUftResp;
use crate::api::InnerFlowId;
use crate::api::L4Info;
use crate::api::TcpFlowEntryDump;
use opte_api::ActionDescEntryDump;
use opte_api::ListLayersResp;
use opte_api::RuleDump;
use opte_api::UftEntryDump;
use std::collections::VecDeque;
use std::io::Write;
use std::string::String;
use std::string::ToString;
use tabwriter::TabWriter;

/// Print a [`DumpLayerResp`].
pub fn print_layer(resp: &DumpLayerResp) -> std::io::Result<()> {
    print_layer_into(&mut std::io::stdout(), resp)
}

/// Print a [`DumpLayerResp`].
pub fn print_layer_into(
    writer: &mut impl Write,
    resp: &DumpLayerResp,
) -> std::io::Result<()> {
    let mut t = TabWriter::new(writer);

    writeln!(t, "Layer {}", resp.name)?;
    write_hrb(&mut t)?;
    writeln!(t, "Inbound Flows")?;
    write_hr(&mut t)?;
    print_lft_flow_header(&mut t)?;
    for (flow_id, flow_state) in &resp.ft_in {
        print_lft_flow(&mut t, flow_id, flow_state)?;
    }
    t.flush()?;

    writeln!(t, "\nOutbound Flows")?;
    write_hr(&mut t)?;
    print_lft_flow_header(&mut t)?;
    for (flow_id, flow_state) in &resp.ft_out {
        print_lft_flow(&mut t, flow_id, flow_state)?;
    }
    t.flush()?;

    writeln!(t, "\nInbound Rules")?;
    write_hr(&mut t)?;
    print_rule_header(&mut t)?;
    for rte in &resp.rules_in {
        print_rule(&mut t, rte.id, rte.hits, &rte.rule)?;
    }
    print_def_rule(&mut t, resp.default_in_hits, &resp.default_in)?;
    t.flush()?;

    writeln!(t, "\nOutbound Rules")?;
    write_hr(&mut t)?;
    print_rule_header(&mut t)?;
    for rte in &resp.rules_out {
        print_rule(&mut t, rte.id, rte.hits, &rte.rule)?;
    }
    print_def_rule(&mut t, resp.default_out_hits, &resp.default_out)?;
    t.flush()?;

    writeln!(t)?;
    t.flush()
}

/// Print a [`ListLayersResp`].
pub fn print_list_layers(resp: &ListLayersResp) -> std::io::Result<()> {
    print_list_layers_into(&mut std::io::stdout(), resp)
}

/// Print a [`ListLayersResp`] into a given writer.
pub fn print_list_layers_into(
    writer: &mut impl Write,
    resp: &ListLayersResp,
) -> std::io::Result<()> {
    let mut t = TabWriter::new(writer);
    writeln!(t, "NAME\tRULES IN\tRULES OUT\tDEF IN\tDEF OUT\tFLOWS")?;

    for desc in &resp.layers {
        writeln!(
            t,
            "{}\t{}\t{}\t{}\t{}\t{}",
            desc.name,
            desc.rules_in,
            desc.rules_out,
            desc.default_in,
            desc.default_out,
            desc.flows,
        )?;
    }
    t.flush()
}

/// Print a [`DumpUftResp`].
pub fn print_uft(uft: &DumpUftResp) -> std::io::Result<()> {
    print_uft_into(&mut std::io::stdout(), uft)
}

/// Print a [`DumpUftResp`] into a given writer.
pub fn print_uft_into(
    writer: &mut impl Write,
    uft: &DumpUftResp,
) -> std::io::Result<()> {
    let mut t = TabWriter::new(writer);

    writeln!(t, "UFT Inbound: {}/{}", uft.in_num_flows, uft.in_limit)?;
    write_hr(&mut t)?;
    print_uft_flow_header(&mut t)?;
    for (flow_id, flow_state) in &uft.in_flows {
        print_uft_flow(&mut t, flow_id, flow_state)?;
    }
    t.flush()?;

    writeln!(t)?;
    writeln!(t, "UFT Outbound: {}/{}", uft.out_num_flows, uft.out_limit)?;
    write_hr(&mut t)?;
    print_uft_flow_header(&mut t)?;
    for (flow_id, flow_state) in &uft.out_flows {
        print_uft_flow(&mut t, flow_id, flow_state)?;
    }
    t.flush()
}

/// Print the header for the [`print_rule()`] output.
pub fn print_rule_header(t: &mut impl Write) -> std::io::Result<()> {
    writeln!(t, "ID\tPRI\tHITS\tPREDICATES\tACTION")
}

pub fn print_def_rule(
    t: &mut impl Write,
    hits: u64,
    action: &str,
) -> std::io::Result<()> {
    writeln!(t, "DEF\t--\t{hits}\t--\t{action:?}")
}

/// Print a [`RuleDump`].
pub fn print_rule(
    t: &mut impl Write,
    id: u64,
    hits: u64,
    rule: &RuleDump,
) -> std::io::Result<()> {
    let mut preds = rule
        .predicates
        .iter()
        .map(ToString::to_string)
        .chain(rule.data_predicates.iter().map(ToString::to_string))
        .collect::<VecDeque<String>>();

    let first_pred = if preds.is_empty() {
        "*".to_string()
    } else {
        preds.pop_front().unwrap()
    };

    writeln!(
        t,
        "{id}\t{}\t{hits}\t{first_pred}\t{:<?}",
        rule.priority, rule.action
    )?;

    let mut multi_preds = false;
    while let Some(pred) = preds.pop_front() {
        writeln!(t, "\t\t\t{pred}\t")?;
        multi_preds = true;
    }

    // If a rule has multiple predicates, add a blank line to get some
    // separation so it's easier to discern where one rule ends and
    // another begins.
    if multi_preds {
        writeln!(t, "\t\t\t\t")?;
    }

    Ok(())
}

/// Print the header for the [`print_lft_flow()`] output.
pub fn print_lft_flow_header(t: &mut impl Write) -> std::io::Result<()> {
    writeln!(t, "PROTO\tSRC IP\tSPORT/TY\tDST IP\tDPORT\tHITS\tACTION")
}

/// Print information about a layer flow.
pub fn print_lft_flow(
    t: &mut impl Write,
    flow_id: &InnerFlowId,
    flow_entry: &ActionDescEntryDump,
) -> std::io::Result<()> {
    let sport_o;
    let dport_o;
    let (sport, dport) = match flow_id.l4_info() {
        Some(L4Info::Ports(p)) => {
            sport_o = p.src_port.to_string();
            dport_o = p.dst_port.to_string();
            (sport_o.as_str(), dport_o.as_str())
        }
        Some(L4Info::Icmpv4(p)) | Some(L4Info::Icmpv6(p)) => {
            sport_o = format!("{:#02x}/{:#02x}", p.ty, p.code);
            dport_o = p.id.to_string();
            (sport_o.as_str(), dport_o.as_str())
        }
        None => ("N/A", "N/A"),
    };

    writeln!(
        t,
        "{}\t{}\t{}\t{}\t{}\t{}\t{}",
        flow_id.protocol(),
        flow_id.src_ip(),
        sport,
        flow_id.dst_ip(),
        dport,
        flow_entry.hits,
        flow_entry.summary,
    )
}

/// Print the header for the [`print_uft_flow()`] output.
pub fn print_uft_flow_header(t: &mut impl Write) -> std::io::Result<()> {
    writeln!(t, "PROTO\tSRC IP\tSPORT/TY\tDST IP\tDPORT\tHITS\tXFORMS")
}

/// Print information about a UFT entry.
pub fn print_uft_flow(
    t: &mut impl Write,
    flow_id: &InnerFlowId,
    flow_entry: &UftEntryDump,
) -> std::io::Result<()> {
    let sport_o;
    let dport_o;
    let (sport, dport) = match flow_id.l4_info() {
        Some(L4Info::Ports(p)) => {
            sport_o = p.src_port.to_string();
            dport_o = p.dst_port.to_string();
            (sport_o.as_str(), dport_o.as_str())
        }
        Some(L4Info::Icmpv4(p)) | Some(L4Info::Icmpv6(p)) => {
            sport_o = format!("{:#02x}/{:#02x}", p.ty, p.code);
            dport_o = p.id.to_string();
            (sport_o.as_str(), dport_o.as_str())
        }
        None => ("N/A", "N/A"),
    };

    writeln!(
        t,
        "{}\t{}\t{}\t{}\t{}\t{}\t{}",
        flow_id.protocol(),
        flow_id.src_ip(),
        sport,
        flow_id.dst_ip(),
        dport,
        flow_entry.hits,
        flow_entry.summary,
    )
}

/// Print a [`DumpTcpFlowsResp`].
pub fn print_tcp_flows(flows: &DumpTcpFlowsResp) -> std::io::Result<()> {
    print_tcp_flows_into(&mut std::io::stdout(), flows)
}

/// Print a [`DumpTcpFlowsResp`] into a given writer.
pub fn print_tcp_flows_into(
    writer: &mut impl Write,
    flows: &DumpTcpFlowsResp,
) -> std::io::Result<()> {
    let mut t = TabWriter::new(writer);

    writeln!(t, "FLOW\tSTATE\tHITS\tSEGS IN\tSEGS OUT\tBYTES IN\tBYTES OUT")?;
    for (flow_id, entry) in &flows.flows {
        print_tcp_flow(&mut t, flow_id, entry)?;
    }

    t.flush()
}

fn print_tcp_flow(
    t: &mut impl Write,
    id: &InnerFlowId,
    entry: &TcpFlowEntryDump,
) -> std::io::Result<()> {
    writeln!(
        t,
        "{id}\t{}\t{}\t{}\t{}\t{}\t{}",
        entry.tcp_state.tcp_state,
        entry.hits,
        entry.segs_in,
        entry.segs_out,
        entry.bytes_in,
        entry.bytes_out,
    )
}

/// Output a horizontal rule in bold to the given writer.
pub fn write_hrb(t: &mut impl Write) -> std::io::Result<()> {
    writeln!(t, "{:=<70}", "=")
}

/// Print a horizontal rule in bold.
pub fn print_hrb() {
    println!("{:=<70}", "=");
}

/// Output a horizontal rule in bold to the given writer.
pub fn write_hr(t: &mut impl Write) -> std::io::Result<()> {
    writeln!(t, "{:-<70}", "-")
}

/// Print a horizontal rule.
pub fn print_hr() {
    println!("{:-<70}", "-");
}

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
use opte_api::Direction;
use opte_api::ListLayersResp;
use opte_api::RuleDump;
use opte_api::UftEntryDump;
use std::collections::VecDeque;
use std::io::Write;
use std::string::String;
use std::string::ToString;
use tabwriter::TabWriter;

#[derive(Debug, Clone)]
pub struct PropRow<'a> {
    pub layer: &'a str,
    pub dir: Direction,
    pub rule_id: PropRuleId,
    pub name: &'a str,
    pub value: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropRuleId {
    Rule(u64),
    Default,
}

/// Flatten dumped layers into `PropRow`s, filtered by direction, rule
/// id, and/or property name. `None` (or empty slice for `prop_filter`)
/// means no restriction.
pub fn collect_prop_rows<'a>(
    layers: &'a [DumpLayerResp],
    direction: Option<Direction>,
    rule_id: Option<u64>,
    prop_filter: Option<&'a [String]>,
) -> Vec<PropRow<'a>> {
    let want_in = direction != Some(Direction::Out);
    let want_out = direction != Some(Direction::In);
    let prop_wanted = |name: &str| -> bool {
        prop_filter.is_none_or(|allow| allow.iter().any(|n| n == name))
    };

    let mut rows = Vec::new();
    for layer in layers {
        let dirs = [
            (want_in, Direction::In, &layer.rules_in),
            (want_out, Direction::Out, &layer.rules_out),
        ];
        for (want, dir, rules) in dirs {
            if !want {
                continue;
            }
            for entry in rules {
                if rule_id.is_some_and(|r| r != entry.id) {
                    continue;
                }
                for prop in &entry.rule.action_properties {
                    if !prop_wanted(&prop.name) {
                        continue;
                    }
                    rows.push(PropRow {
                        layer: &layer.name,
                        dir,
                        rule_id: PropRuleId::Rule(entry.id),
                        name: &prop.name,
                        value: &prop.value,
                    });
                }
            }
        }
    }
    rows
}

pub fn print_props(rows: &[PropRow<'_>]) -> std::io::Result<()> {
    print_props_into(&mut std::io::stdout(), rows)
}

pub fn print_props_into(
    writer: &mut impl Write,
    rows: &[PropRow<'_>],
) -> std::io::Result<()> {
    let mut t = TabWriter::new(writer);
    writeln!(t, "LAYER\tDIR\tRULE\tPROPERTY\tVALUE")?;
    for row in rows {
        let rule = match row.rule_id {
            PropRuleId::Rule(id) => id.to_string(),
            PropRuleId::Default => "DEF".to_string(),
        };
        writeln!(
            t,
            "{}\t{}\t{}\t{}\t{}",
            row.layer, row.dir, rule, row.name, row.value,
        )?;
    }
    t.flush()
}

/// Print rows as `LAYER:DIR:RULE:PROPERTY:VALUE`, with `:` and `\` in
/// fields backslash-escaped. Modeled after `dladm show-linkprop -c`.
pub fn print_props_parseable(rows: &[PropRow<'_>]) -> std::io::Result<()> {
    print_props_parseable_into(&mut std::io::stdout(), rows)
}

pub fn print_props_parseable_into(
    writer: &mut impl Write,
    rows: &[PropRow<'_>],
) -> std::io::Result<()> {
    for row in rows {
        let rule = match row.rule_id {
            PropRuleId::Rule(id) => id.to_string(),
            PropRuleId::Default => "-".to_string(),
        };
        writeln!(
            writer,
            "{}:{}:{}:{}:{}",
            escape_parseable(row.layer),
            escape_parseable(&row.dir.to_string()),
            escape_parseable(&rule),
            escape_parseable(row.name),
            escape_parseable(row.value),
        )?;
    }
    Ok(())
}

fn escape_parseable(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            ':' => out.push_str(r"\:"),
            other => out.push(other),
        }
    }
    out
}

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
    let (sport, dport) = match flow_id.l4_info() {
        Some(L4Info::Ports(p)) => {
            (p.src_port.to_string(), p.dst_port.to_string())
        }
        Some(L4Info::Icmpv4(p)) | Some(L4Info::Icmpv6(p)) => {
            (format!("{:#04x}/{:#04x}", p.ty, p.code), p.id.to_string())
        }
        None => ("N/A".into(), "N/A".into()),
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
    let (sport, dport) = match flow_id.l4_info() {
        Some(L4Info::Ports(p)) => {
            (p.src_port.to_string(), p.dst_port.to_string())
        }
        Some(L4Info::Icmpv4(p)) | Some(L4Info::Icmpv6(p)) => {
            (format!("{:#04x}/{:#04x}", p.ty, p.code), p.id.to_string())
        }
        None => ("N/A".into(), "N/A".into()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_parseable_passes_plain_chars() {
        assert_eq!(escape_parseable("overlay"), "overlay");
        assert_eq!(escape_parseable(""), "");
        assert_eq!(escape_parseable("99"), "99");
    }

    #[test]
    fn escape_parseable_escapes_colon_and_backslash() {
        // IPv6 address: every ':' must be escaped.
        assert_eq!(
            escape_parseable("fd00:1122:7788:101::4"),
            r"fd00\:1122\:7788\:101\:\:4",
        );
        // Backslash itself doubles up.
        assert_eq!(escape_parseable(r"a\b"), r"a\\b");
        // Combined.
        assert_eq!(escape_parseable(r"a:b\c"), r"a\:b\\c");
    }

    fn rule_dump(
        id: u64,
        action: &str,
        props: &[(&str, &str)],
    ) -> opte_api::RuleTableEntryDump {
        opte_api::RuleTableEntryDump {
            id,
            hits: 0,
            rule: RuleDump {
                priority: 0,
                predicates: vec![],
                data_predicates: vec![],
                action: action.to_string(),
                action_properties: props
                    .iter()
                    .map(|(n, v)| opte_api::ActionProperty {
                        name: n.to_string(),
                        value: v.to_string(),
                    })
                    .collect(),
            },
        }
    }

    fn layer(name: &str) -> DumpLayerResp {
        DumpLayerResp {
            name: name.to_string(),
            rules_in: vec![rule_dump(0, "Decap", &[])],
            rules_out: vec![
                rule_dump(0, "Encap", &[("vni", "99"), ("phys_ip_src", "fd00::4")]),
                rule_dump(1, "Encap", &[("vni", "100")]),
            ],
            default_in: "deny".into(),
            default_in_hits: 0,
            default_out: "deny".into(),
            default_out_hits: 0,
            ft_in: vec![],
            ft_out: vec![],
        }
    }

    #[test]
    fn collect_no_filters_returns_all_props() {
        let layers = vec![layer("overlay")];
        let rows = collect_prop_rows(&layers, None, None, None);
        // 0 inbound props (decap), 3 outbound props (2 + 1).
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|r| r.layer == "overlay"));
    }

    #[test]
    fn collect_filters_by_direction() {
        let layers = vec![layer("overlay")];
        let rows = collect_prop_rows(
            &layers,
            Some(Direction::In),
            None,
            None,
        );
        assert!(rows.is_empty(), "decap has no exposed properties");
    }

    #[test]
    fn collect_filters_by_rule_id() {
        let layers = vec![layer("overlay")];
        let rows = collect_prop_rows(&layers, None, Some(1), None);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "vni");
        assert_eq!(rows[0].value, "100");
    }

    #[test]
    fn collect_filters_by_prop_name() {
        let layers = vec![layer("overlay")];
        let names: Vec<String> = vec!["vni".into()];
        let rows = collect_prop_rows(&layers, None, None, Some(&names));
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.name == "vni"));
    }

    #[test]
    fn collect_empty_prop_filter_matches_nothing() {
        // Some(&[]) is "an explicit list of zero properties" — the CLI
        // should pass None when --prop is omitted, not an empty Vec.
        let layers = vec![layer("overlay")];
        let empty: Vec<String> = vec![];
        let rows = collect_prop_rows(&layers, None, None, Some(&empty));
        assert!(rows.is_empty());
    }

    #[test]
    fn print_props_parseable_emits_one_line_per_row() {
        let rows = vec![
            PropRow {
                layer: "overlay",
                dir: Direction::Out,
                rule_id: PropRuleId::Rule(0),
                name: "vni",
                value: "99",
            },
            PropRow {
                layer: "overlay",
                dir: Direction::Out,
                rule_id: PropRuleId::Default,
                name: "phys_ip_src",
                value: "fd00::4",
            },
        ];
        let mut buf = Vec::new();
        print_props_parseable_into(&mut buf, &rows).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(
            out,
            "overlay:OUT:0:vni:99\noverlay:OUT:-:phys_ip_src:fd00\\:\\:4\n",
        );
    }
}

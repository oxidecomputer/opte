// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Module to parse and verify Geneve headers from snoop hex output.
//!
//! This uses the existing OPTE/ingot Geneve types to parse raw packet bytes
//! and extract key multicast-related fields for test assertions.

use opte::engine::geneve::Vni;
use opte::engine::ip::v6::Ipv6Ref;
use opte::engine::parse::ValidGeneveOverV6;
use opte::ingot::geneve::GeneveRef;
use opte::ingot::types::HeaderParse;
use oxide_vpc::api::Ipv6Addr;
use oxide_vpc::api::Replication;
use oxide_vpc::engine::geneve::extract_multicast_replication;

/// Parsed Geneve header information for test verification.
pub struct GeneveInfo {
    pub vni: Vni,
    pub outer_ipv6_dst: Ipv6Addr,
    pub replication: Option<Replication>,
}

/// Parse a Geneve/IPv6 packet from raw bytes and extract multicast-related
/// fields.
///
/// Returns VNI, outer IPv6 destination, and replication mode from Geneve
/// options.
pub fn parse_geneve_packet(bytes: &[u8]) -> Result<GeneveInfo, String> {
    let (pkt, _, _) = ValidGeneveOverV6::parse(bytes)
        .map_err(|e| format!("Failed to parse Geneve/IPv6 packet: {e:?}"))?;

    let vni = pkt.outer_encap.vni();
    let outer_ipv6_dst = pkt.outer_v6.destination();
    let replication = extract_multicast_replication(&pkt.outer_encap);

    Ok(GeneveInfo { vni, outer_ipv6_dst, replication })
}

/// Parse hex string from snoop output into bytes.
///
/// Snoop output with `-x0` flag is hex digits without separators:
/// "ffffffffffff001122334455..."
pub fn parse_snoop_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    hex_str
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let hex_byte = std::str::from_utf8(chunk)
                .map_err(|e| format!("Invalid UTF-8: {e}"))?;
            u8::from_str_radix(hex_byte, 16)
                .map_err(|e| format!("Invalid hex: {e}"))
        })
        .collect()
}

/// Extract snoop hex output from command output.
///
/// We support common `snoop -P -x0` formats:
/// - Lines of contiguous hex digits (with or without spaces).
/// - Hex dumps with an offset prefix like `0:` or `0000:` followed by
///   groups of hex digits (2/4/8/16 chars).
///
/// To avoid false positives from summary lines (e.g., "UDP port 6081"), the
/// tokenized fallback triggers only for lines that look like offset-prefixed
/// hex dumps.
pub fn extract_snoop_hex(snoop_output: &str) -> Result<String, String> {
    let mut hex_bytes = String::new();

    for line in snoop_output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.contains("Using device") {
            continue;
        }

        // Case 1: entire line is hex digits + whitespace (e.g., "aa bb cc ..." or
        //         single long line of hex). Remove whitespace and append.
        if trimmed.chars().all(|c| c.is_ascii_hexdigit() || c.is_whitespace()) {
            for ch in trimmed.chars().filter(|c| c.is_ascii_hexdigit()) {
                hex_bytes.push(ch);
            }
            continue;
        }

        // Case 2: offset-prefixed hexdump lines (e.g., "0: 4500 003c ...").
        // Only consider tokenized parsing if the first token looks like an
        // offset (decimal or hex) ending with a ':' to avoid pulling numbers
        // from summary lines.
        let mut tokens = trimmed.split_whitespace();
        let Some(first) = tokens.next() else { continue };
        if !first.ends_with(':') {
            continue; // Not a hexdump line
        }
        let mut off = first.trim_end_matches(':');
        if off.starts_with("0x") || off.starts_with("0X") {
            off = &off[2..];
        }
        if !off.chars().all(|c| c.is_ascii_hexdigit()) {
            continue; // Not a valid offset
        }

        for tok in tokens {
            let mut t = tok.trim_end_matches(':');
            if t.len() > 2 && (t.starts_with("0x") || t.starts_with("0X")) {
                t = &t[2..];
            }
            if t.is_empty() {
                continue;
            }
            // Accept groups commonly used in dumps: bytes (2), words (4), dwords (8),
            // or qwords (16). Ignore anything else to avoid accidental matches.
            let len = t.len();
            if matches!(len, 2 | 4 | 8 | 16)
                && t.chars().all(|c| c.is_ascii_hexdigit())
            {
                hex_bytes.push_str(t);
            }
        }
    }

    if hex_bytes.is_empty() {
        return Err("No hex data found in snoop output".to_string());
    }

    // Ensure even number of nibbles to form complete bytes.
    if hex_bytes.len() % 2 == 1 {
        hex_bytes.pop();
    }

    Ok(hex_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_contiguous_hex() {
        let input = "deadbeefCAFEBABE";
        let out = extract_snoop_hex(input).unwrap();
        assert_eq!(out, "deadbeefCAFEBABE");
        let bytes = parse_snoop_hex(&out).unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]);
    }

    #[test]
    fn extract_bytes_with_spaces() {
        let input = "45 00 00 3c 1c 46 40 00";
        let out = extract_snoop_hex(input).unwrap();
        assert_eq!(out, "4500003c1c464000");
    }

    #[test]
    fn extract_offset_words() {
        let input = "0: 4500 003c 1c46 4000";
        let out = extract_snoop_hex(input).unwrap();
        assert_eq!(out, "4500003c1c464000");
    }

    #[test]
    fn extract_offset_bytes() {
        let input = "0: 45 00 00 3c 1c 46 40 00";
        let out = extract_snoop_hex(input).unwrap();
        assert_eq!(out, "4500003c1c464000");
    }

    #[test]
    fn ignore_summary_numbers() {
        let input = r#"
Using device xde_test_sim1 (promiscuous)
UDP:  fe80::1 > ff04::224.1.2.3, port 6081
0: 4500 003c 1c46 4000
"#;
        let out = extract_snoop_hex(input).unwrap();
        assert_eq!(out, "4500003c1c464000");
        // Should not accidentally include "6081"
        assert!(!out.contains("6081"));
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Module to parse and verify Geneve headers from snoop hex output.
//!
//! This uses the existing OPTE/ingot Geneve types to parse raw packet bytes
//! and extract key multicast-related fields for test assertions.

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use opte::engine::geneve::Vni;
use opte::engine::ip::v6::Ipv6Ref;
use opte::engine::parse::ValidGeneveOverV6;
use opte::ingot::geneve::GeneveRef;
use opte::ingot::types::HeaderParse;
use oxide_vpc::api::Ipv6Addr;
use oxide_vpc::api::MulticastUnderlay;
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
/// Returns VNI, outer IPv6 destination, and replication mode from Geneve options.
pub fn parse_geneve_packet(bytes: &[u8]) -> Result<GeneveInfo> {
    let (pkt, _, _) = ValidGeneveOverV6::parse(bytes)
        .context("Failed to parse Geneve/IPv6 packet")?;

    let vni = pkt.outer_encap.vni();
    let outer_ipv6_dst = pkt.outer_v6.destination();
    let replication = extract_multicast_replication(&pkt.outer_encap);

    Ok(GeneveInfo { vni, outer_ipv6_dst, replication })
}

/// Parse and verify a Geneve packet from snoop output.
///
/// This helper combines the common pattern of:
/// - Extracting hex from snoop output
/// - Parsing the first packet's hex into bytes
/// - Parsing Geneve packet from bytes
/// - Asserting VNI, outer IPv6 destination, and [`Replication`] mode
///
/// # Panics
///
/// Panics if parsing fails or if any of the expected values don't match.
///
/// # Example
/// ```no_run
/// let snoop_output = snoop_underlay.assert_packet("on underlay");
/// let stdout = String::from_utf8_lossy(&snoop_output.stdout);
/// geneve_verify::assert_geneve_packet(
///     &stdout,
///     vni,
///     mcast_underlay,
///     Replication::External,
/// );
/// ```
pub fn assert_geneve_packet(
    snoop_stdout: &str,
    expected_vni: Vni,
    expected_underlay: MulticastUnderlay,
    expected_replication: Replication,
) {
    let packets = extract_snoop_hex(snoop_stdout).unwrap_or_else(|e| {
        panic!(
            "Expected snoop output to contain parseable hex dump: {e}\n\nSnoop output was:\n{snoop_stdout}"
        )
    });

    let packet_bytes = parse_snoop_hex(&packets[0]).unwrap_or_else(|e| {
        panic!("Expected hex string to parse into packet bytes: {e}")
    });

    let geneve_info = parse_geneve_packet(&packet_bytes).unwrap_or_else(|e| {
        panic!(
            "Expected packet bytes to be valid Geneve packet with VNI and replication option: {e}"
        )
    });

    assert_eq!(
        geneve_info.vni, expected_vni,
        "Geneve VNI mismatch (expected {expected_vni})"
    );

    assert_eq!(
        geneve_info.outer_ipv6_dst,
        Ipv6Addr::from(expected_underlay),
        "Geneve outer IPv6 destination should be underlay multicast address {}",
        Ipv6Addr::from(expected_underlay)
    );

    assert_eq!(
        geneve_info.replication,
        Some(expected_replication),
        "Geneve replication mode should be {expected_replication:?}"
    );
}

/// Parse hex string from snoop output into bytes.
///
/// Snoop output with `-x0` flag is hex digits without separators:
/// "ffffffffffff001122334455..."
pub fn parse_snoop_hex(hex_str: &str) -> Result<Vec<u8>> {
    hex_str
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let hex_byte =
                std::str::from_utf8(chunk).context("Invalid UTF-8")?;
            u8::from_str_radix(hex_byte, 16).context("Invalid hex")
        })
        .collect()
}

/// Intermediate representation of a parsed snoop output line.
enum ParsedLine {
    /// Pure hex content (e.g., "deadbeef" or "de ad be ef")
    Hex(String),
    /// Offset-prefixed hex dump line (e.g., "0: 4500 003c")
    OffsetLine { offset: usize, hex: String },
    /// Line to ignore (empty, device info, summary text)
    Ignore,
}

/// Fold parsed lines into packets, splitting on offset 0 resets.
struct PacketAcc {
    packets: Vec<String>,
    current: String,
    saw_offset_zero: bool,
}

/// Extract snoop hex output from command output, splitting by packet boundaries.
///
/// We support common `snoop -P -x0` formats:
/// - Lines of contiguous hex digits (with or without spaces).
/// - Hex dumps with an offset prefix like `0:` or `0000:` followed by
///   groups of hex digits (2/4/8/16 chars).
///
/// When snoop captures multiple packets with `-c N`, each packet's hex dump
/// starts at offset 0. We detect this to split packets into separate strings.
///
/// To avoid false positives from summary lines (e.g., "UDP port 6081"), the
/// tokenized fallback triggers only for lines that look like offset-prefixed
/// hex dumps.
///
/// Returns a Vec of hex strings, one per packet. For single-packet captures,
/// just use `result[0]`.
pub fn extract_snoop_hex(snoop_output: &str) -> Result<Vec<String>> {
    // Parse a single line into structured representation
    fn parse_line(line: &str) -> ParsedLine {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.contains("Using device") {
            return ParsedLine::Ignore;
        }

        // a) Entire line is hex digits + whitespace (e.g., "aa bb cc ..." or
        // single long line of hex). Remove whitespace and collect.
        if trimmed.chars().all(|c| c.is_ascii_hexdigit() || c.is_whitespace()) {
            return ParsedLine::Hex(
                trimmed.chars().filter(|c| c.is_ascii_hexdigit()).collect(),
            );
        }

        // b) Offset-prefixed hexdump lines (e.g., "0: 4500 003c ...").
        // Only consider tokenized parsing if the first token looks like an
        // offset (decimal or hex) ending with a ':' to avoid pulling numbers
        // from summary lines.
        let mut tokens = trimmed.split_whitespace();
        let Some(first) = tokens.next() else {
            return ParsedLine::Ignore;
        };
        if !first.ends_with(':') {
            return ParsedLine::Ignore; // Not a hexdump line
        }

        let off = first
            .trim_end_matches(':')
            .strip_prefix("0x")
            .or_else(|| first.trim_end_matches(':').strip_prefix("0X"))
            .unwrap_or_else(|| first.trim_end_matches(':'));

        if !off.chars().all(|c| c.is_ascii_hexdigit()) {
            return ParsedLine::Ignore; // Not a valid offset
        }

        let offset_val = usize::from_str_radix(off, 16).unwrap_or(usize::MAX);

        // Extract hex tokens from remainder of line
        let hex: String = tokens
            .filter_map(|tok| {
                let t = tok
                    .trim_end_matches(':')
                    .strip_prefix("0x")
                    .or_else(|| tok.trim_end_matches(':').strip_prefix("0X"))
                    .unwrap_or_else(|| tok.trim_end_matches(':'));

                // Accept groups commonly used in dumps: bytes (2), words (4),
                // dwords (8), or qwords (16). Ignore anything else to avoid
                // accidental matches.
                let len = t.len();
                (matches!(len, 2 | 4 | 8 | 16)
                    && t.chars().all(|c| c.is_ascii_hexdigit()))
                .then_some(t)
            })
            .collect();

        ParsedLine::OffsetLine { offset: offset_val, hex }
    }

    // Transform all lines into parsed representation
    let parsed_lines: Vec<ParsedLine> =
        snoop_output.lines().map(parse_line).collect();

    let acc = parsed_lines.into_iter().fold(
        PacketAcc {
            packets: Vec::new(),
            current: String::new(),
            saw_offset_zero: false,
        },
        |mut acc, line| {
            match line {
                ParsedLine::Hex(hex) => {
                    acc.current.push_str(&hex);
                }
                ParsedLine::OffsetLine { offset, hex } => {
                    if offset == 0 {
                        if acc.saw_offset_zero && !acc.current.is_empty() {
                            // Start of new packet - save previous
                            acc.packets.push(std::mem::take(&mut acc.current));
                        }
                        acc.saw_offset_zero = true;
                    }
                    acc.current.push_str(&hex);
                }
                ParsedLine::Ignore => {}
            }
            acc
        },
    );

    // Collect final packet
    let mut packets = acc.packets;
    if !acc.current.is_empty() {
        packets.push(acc.current);
    }

    if packets.is_empty() {
        bail!("No hex data found in snoop output");
    }

    // Normalize: ensure even number of nibbles to form complete bytes
    Ok(packets
        .into_iter()
        .map(|mut p| {
            if p.len() % 2 == 1 {
                p.pop();
            }
            p
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_contiguous_hex() {
        let input = "deadbeefCAFEBABE";
        let packets = extract_snoop_hex(input).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], "deadbeefCAFEBABE");
        let bytes = parse_snoop_hex(&packets[0]).unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]);
    }

    #[test]
    fn extract_bytes_with_spaces() {
        let input = "45 00 00 3c 1c 46 40 00";
        let packets = extract_snoop_hex(input).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], "4500003c1c464000");
    }

    #[test]
    fn extract_offset_words() {
        let input = "0: 4500 003c 1c46 4000";
        let packets = extract_snoop_hex(input).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], "4500003c1c464000");
    }

    #[test]
    fn extract_offset_bytes() {
        let input = "0: 45 00 00 3c 1c 46 40 00";
        let packets = extract_snoop_hex(input).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], "4500003c1c464000");
    }

    #[test]
    fn ignore_summary_numbers() {
        let input = r#"
Using device xde_test_sim1 (promiscuous)
UDP:  fe80::1 > ff04::224.1.2.3, port 6081
0: 4500 003c 1c46 4000
"#;
        let packets = extract_snoop_hex(input).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], "4500003c1c464000");
        // Should not accidentally include "6081"
        assert!(!packets[0].contains("6081"));
    }

    #[test]
    fn extract_multiple_packets() {
        let input = r#"
0: 4500 003c
8: 1c46 4000
0: 6000 0000
8: 0014 1140
"#;
        let packets = extract_snoop_hex(input).unwrap();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0], "4500003c1c464000");
        assert_eq!(packets[1], "6000000000141140");
    }
}

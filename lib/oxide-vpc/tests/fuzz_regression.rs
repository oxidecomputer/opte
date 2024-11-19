// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Fuzz regression tests.
//!
//! These tests capture past known-bad packets which have made some part
//! of OPTE panic in the past, and ensure that it does not today.

use opte::ddi::mblk::MsgBlk;
use opte::engine::packet::Packet;
use oxide_vpc::engine::VpcParser;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Case {
    description: String,
    packet: String,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct Label {
    family: String,
    name: String,
}

fn run_tests(
    root_dir: &str,
    test_fn: impl Fn(&[u8]) + std::panic::RefUnwindSafe,
) {
    let base_resource_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/resources");

    // Find all test descriptions in tests/resources/$root_dir.
    let mut tests: HashMap<Label, Case> = HashMap::new();
    let my_test_dir = base_resource_path.join(root_dir);
    for entry in std::fs::read_dir(my_test_dir)
        .unwrap_or_else(|e| panic!("failed to find directory {root_dir}: {e}"))
    {
        let entry = entry.unwrap_or_else(|e| {
            panic!("failed to enumerate child of {root_dir}: {e}")
        });

        let path_owned = entry.path();
        let path = path_owned.as_path();
        if path.extension() != Some("ron".as_ref()) {
            continue;
        }

        let contents = std::fs::read_to_string(path).unwrap_or_else(|e| {
            panic!("failed to read contents of {}: {e}", path.display())
        });

        let cases: HashMap<String, Case> = ron::from_str(&contents)
            .unwrap_or_else(|e| {
                panic!("failed to parse {}: {e}", path.display())
            });

        let family =
            path.file_stem().and_then(OsStr::to_str).unwrap_or("<unlabelled>");

        tests.extend(
            cases
                .into_iter()
                .map(|(name, v)| (Label { family: family.into(), name }, v)),
        )
    }

    // Run all captured tests.
    let mut pkt_path = base_resource_path.join("data");
    for (label, case) in tests {
        let Label { family, name } = label;
        pkt_path.push(&case.packet);
        let data = std::fs::read(&pkt_path).unwrap_or_else(|e| {
            panic!(
                "{root_dir}, {family}/{name}: could not read data from {}: {e}",
                pkt_path.as_path().display(),
            )
        });
        pkt_path.pop();

        if let Err(e) = std::panic::catch_unwind(|| test_fn(&data[..])) {
            let case_str;
            let case_fmt = if case.description.is_empty() {
                ""
            } else {
                case_str = format!("\n -- {}", case.description);
                case_str.as_str()
            };
            eprintln!(
                "\nFuzz regression failure in: \
                {family}/{name}{case_fmt}\n\n\
                Packet {}:\n\
                {:x?}",
                case.packet,
                &data[..]
            );

            std::panic::resume_unwind(e)
        }
    }
}

#[test]
fn parse_in_regression() {
    run_tests("parse_in", |data| {
        let mut msg = MsgBlk::copy(data);
        let _ = Packet::parse_inbound(msg.iter_mut(), VpcParser {});
    });
}

#[test]
fn parse_out_regression() {
    run_tests("parse_out", |data| {
        let mut msg = MsgBlk::copy(data);
        let _ = Packet::parse_outbound(msg.iter_mut(), VpcParser {});
    });
}

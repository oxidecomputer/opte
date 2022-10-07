// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Routines for verifying various Port state.

use opte::engine::port::PortState;
use std::collections::BTreeMap;

/// Track various bits of Port state for the purpose of verifying
/// certain events occur when traffic crosses the port or an
/// administration command is procssed. This type should be
/// manipulated by the macros that follow.
///
/// # Counts
///
/// Each entry in the `counts` map represents some type of particular
/// port state which has a count associated with it. When a port's
/// overall state is asserted we make sure that its internal state
/// matches these counts.
///
/// `<layer>.rules_{in,out}`: The expected number of rules in a given
/// direction in a given layer. This does not apply to the UFT, as
/// it's just a flow table, there are no rules.
///
/// `<layer>.flows_{in,out}`: The expected number of entries in the
/// flow table in a given direction in a given layer. The number of
/// UFT flows is stored under `uft.flows_{in,out}`.
///
/// # Epoch
///
/// Tracks the current `epoch` value of the port.
///
/// # Port State
///
/// This tracks the current `PortState` value of the port.
///
/// NOTE: This word state is a bit overloaded here. The purpose of
/// VpcPortState is to track the overall state of the Port, where
/// `PortState` is just one piece of that overall state.
pub struct VpcPortState {
    pub counts: BTreeMap<String, u32>,
    pub epoch: u64,
    pub port_state: PortState,
}

impl VpcPortState {
    pub fn new() -> Self {
        Self {
            counts: BTreeMap::from(
                [
                    ("arp.rules_in", 0),
                    ("arp.rules_out", 0),
                    ("fw.flows_in", 0),
                    ("fw.flows_out", 0),
                    ("fw.rules_in", 0),
                    ("fw.rules_out", 0),
                    ("icmp.rules_in", 0),
                    ("icmp.rules_out", 0),
                    ("nat.flows_in", 0),
                    ("nat.flows_out", 0),
                    ("nat.rules_in", 0),
                    ("nat.rules_out", 0),
                    ("router.rules_in", 0),
                    ("router.rules_out", 0),
                    ("uft.flows_in", 0),
                    ("uft.flows_out", 0),
                ]
                .map(|(name, val)| (name.to_string(), val)),
            ),
            epoch: 1,
            port_state: PortState::Ready,
        }
    }
}

/// Assert that the port's current overall state matches the expected
/// state stored in the VpcPortState.
#[macro_export]
macro_rules! assert_port {
    ($pav:expr) => {
        for (field, expected_val) in $pav.vps.counts.iter() {
            let actual_val = match field.as_str() {
                "arp.rules_in" => $pav.port.num_rules("arp", In),
                "arp.rules_out" => $pav.port.num_rules("arp", Out),
                "fw.flows_in" => $pav.port.num_flows("firewall", In),
                "fw.flows_out" => $pav.port.num_flows("firewall", Out),
                "fw.rules_in" => $pav.port.num_rules("firewall", In),
                "fw.rules_out" => $pav.port.num_rules("firewall", Out),
                "icmp.rules_in" => $pav.port.num_rules("icmp", In),
                "icmp.rules_out" => $pav.port.num_rules("icmp", Out),
                "nat.flows_in" => $pav.port.num_flows("nat", In),
                "nat.flows_out" => $pav.port.num_flows("nat", Out),
                "nat.rules_in" => $pav.port.num_rules("nat", In),
                "nat.rules_out" => $pav.port.num_rules("nat", Out),
                "router.rules_in" => $pav.port.num_rules("router", In),
                "router.rules_out" => $pav.port.num_rules("router", Out),
                "uft.flows_in" => $pav.port.num_flows("uft", In),
                "uft.flows_out" => $pav.port.num_flows("uft", Out),
                f => todo!("implement check for field: {}", f),
            };
            assert!(
                *expected_val == actual_val,
                "field value mismatch: field: {}, expected: {}, actual: {}",
                field,
                expected_val,
                actual_val,
            );
        }

        {
            let expected = $pav.vps.epoch;
            let actual = $pav.port.epoch();
            assert!(
                expected == actual,
                "epoch mismatch: expected: {}, actual: {}",
                expected,
                actual,
            );
        }

        {
            let expected = $pav.vps.port_state;
            let actual = $pav.port.state();
            assert!(
                expected == actual,
                "port state mismatch: expected: {}, actual: {}",
                expected,
                actual,
            );
        }
    };
}

/// Increment a field in the `VpcPortState.counts` map.
#[macro_export]
macro_rules! incr_field {
    ($vps:expr, $field:expr) => {
        match $vps.counts.get_mut($field) {
            Some(v) => *v += 1,
            None => assert!(false, "field does not exist: {}", $field),
        }
    };
}

/// Decrement a field in the `VpcPortState.counts` map.
#[macro_export]
macro_rules! decr_field {
    ($vps:expr, $field:expr) => {
        match $vps.counts.get_mut($field) {
            Some(v) => *v -= 1,
            None => assert!(false, "field does not exist: {}", $field),
        }
    };
}

/// Increment a list of fields in the `VpcPortState.counts` map.
#[macro_export]
macro_rules! incr_na {
    ($port_and_vps:expr, $fields:expr) => {
        for f in $fields {
            match f {
                "epoch" => $port_and_vps.vps.epoch += 1,
                _ => incr_field!($port_and_vps.vps, f),
            }
        }
    };
}

/// Increment a list of fields in the `VpcPortState.counts` map and
/// assert the port state.
#[macro_export]
macro_rules! incr {
    ($port_and_vps:expr, $fields:expr) => {
        incr_na!($port_and_vps, $fields);
        assert_port!($port_and_vps);
    };
}

/// Decrement a list of fields in the `VpcPortState.counts` map.
#[macro_export]
macro_rules! decr_na {
    ($port_and_vps:expr, $fields:expr) => {
        for f in $fields {
            match f {
                // You can never decrement the epoch.
                _ => decr_field!($port_and_vps.vps, f),
            }
        }
    };
}

/// Set the value of a field in the `VpcPortState.counts` map.
#[macro_export]
macro_rules! set_field {
    ($port_and_vps:expr, $field:expr, $val:expr) => {
        match $port_and_vps.vps.counts.get_mut($field) {
            Some(v) => *v = $val,
            None => assert!(false, "field does not exist: {}", $field),
        }
    };
}

/// Set multiple fields at once.
///
/// ```
/// set_fields!(pav, "epcoh=M,fw.rules_in=N");
/// ```
#[macro_export]
macro_rules! set_fields {
    ($port_and_vps:expr, $fields:expr) => {
        for f in $fields {
            match f.split_once("=") {
                Some(("epoch", val)) => {
                    $port_and_vps.vps.epoch += val.parse::<u64>().unwrap();
                }

                Some((field, val)) => {
                    set_field!($port_and_vps, field, val.parse().unwrap());
                }

                _ => panic!("malformed field expr: {}", f),
            }
        }
    };
}

/// Update the `VpcPortState` and assert.
///
/// ```
/// update!(g1, ["incr:epoch,fw.flows_out,fw.flows_in,uft.flows_out"])
/// ```
#[macro_export]
macro_rules! update {
    ($port_and_vps:expr, $instructions:expr) => {
        for inst in $instructions {
            match inst.split_once(":") {
                Some(("incr", fields)) => {
                    // Convert "field1,field2,field3" to ["field1",
                    // "field2, "field3"]
                    let fields_arr: Vec<&str> = fields.split(",").collect();
                    incr_na!($port_and_vps, fields_arr);
                }

                Some(("set", fields)) => {
                    let fields_arr: Vec<&str> = fields.split(",").collect();
                    set_fields!($port_and_vps, fields_arr);
                }

                Some(("decr", fields)) => {
                    let fields_arr: Vec<&str> = fields.split(",").collect();
                    decr_na!($port_and_vps, fields_arr);
                }

                Some((op, _)) => {
                    panic!("unknown op: {} instruction: {}", op, inst);
                }

                _ => panic!("malformed instruction: {}", inst),
            }
        }

        assert_port!($port_and_vps);
    };
}

/// Set all flow counts to zero.
#[macro_export]
macro_rules! zero_flows {
    ($port_and_vps:expr) => {
        for (field, count) in $port_and_vps.vps.counts.iter_mut() {
            match field.as_str() {
                "fw.flows_in" | "fw.flows_out" => *count = 0,
                "nat.flows_in" | "nat.flows_out" => *count = 0,
                "router.flows_in" | "router.flows_out" => *count = 0,
                "uft.flows_in" | "uft.flows_out" => *count = 0,
                &_ => (),
            }
        }
    };
}

/// Set the expected PortState of the port and assert.
#[macro_export]
macro_rules! set_state {
    ($port_and_vps:expr, $port_state:expr) => {
        $port_and_vps.vps.port_state = $port_state;
        assert_port!($port_and_vps);
    };
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Routines for verifying various Port state.

use super::*;
use opte::engine::port::*;
use opte::engine::print::*;
use oxide_vpc::engine::overlay::VpcMappings;
use oxide_vpc::engine::print::*;
use std::collections::BTreeMap;

/// Print various port state in a human-friendly manner when a test
/// assertion fails.
pub fn print_port(port: &Port, vpc_map: &VpcMappings) {
    print_v2p(&vpc_map.dump());
    println!("");

    println!("Port: {} [{}]", port.name(), port.state());
    print_hrb();

    println!("");
    println!("Layers");
    print_hr();
    let list_layers = port.list_layers();
    print_list_layers(&list_layers);

    // Only some states will report a UFT.
    if let Ok(uft) = port.dump_uft() {
        print_uft(&uft);
    }

    println!("");

    for layer in &list_layers.layers {
        print_layer(&port.dump_layer(&layer.name).unwrap());
    }

    println!("");
    println!("Port Stats");
    print_hr();
    println!("{:#?}", port.stats_snap());

    print_hrb();
    println!("");
}

/// Track various bits of port state for the purpose of verifying
/// certain events occur when traffic crosses the port or an
/// administration command is processed. This type should be
/// manipulated by the macros that follow.
///
/// The various port state is manipulated via "fields", which are just
/// period-delimited strings. A field is any string with zero-or-more
/// periods. The period is used to denote some type of hierarchy to
/// make it easier to map these fields to some type of state in the
/// port. It's best not to overthink this, but instead look at some
/// examples.
///
/// ```
/// firewall.rules.in => number of inbound rules in the 'firewall' layer
/// uft.out => number of outbound UFT entries
/// epoch => the Port's epoch
/// port_state => the Port's PortState value
/// ```
///
/// How a given field maps to this structure is at the discretion of
/// the supporting macros. But the basic idea is to split the field
/// name, creating a `SplitField` value, and match against that in
/// order to determine the action to be taken.
pub struct VpcPortState {
    /// Any field that is a counter can be stored here.
    pub counts: BTreeMap<String, u64>,
    /// The Port's `PortState`.
    pub port_state: PortState,
}

impl VpcPortState {
    pub fn new() -> Self {
        let mut counts = BTreeMap::new();
        for layer in &VPC_LAYERS {
            counts.insert(format!("{layer}.rules.in"), 0);
            counts.insert(format!("{layer}.rules.out"), 0);
            counts.insert(format!("{layer}.flows.in"), 0);
            counts.insert(format!("{layer}.flows.out"), 0);
        }

        counts.insert("uft.in".to_string(), 0);
        counts.insert("uft.out".to_string(), 0);
        counts.insert("epoch".to_string(), 0);

        Self { counts, port_state: PortState::Ready }
    }
}

pub enum SplitField<'a> {
    One(&'a str),
    Two(&'a str, &'a str),
    Three(&'a str, &'a str, &'a str),
    Other(&'a str),
}

pub fn split_field(s: &str) -> SplitField {
    let split: Vec<&str> = s.split(".").collect();

    match split.len() {
        1 => SplitField::One(split[0]),
        2 => SplitField::Two(split[0], split[1]),
        3 => SplitField::Three(split[0], split[1], split[2]),
        _ => SplitField::Other(s),
    }
}

/// Assert that the port's current overall state matches the expected
/// state stored in the VpcPortState.
#[macro_export]
macro_rules! assert_port {
    ($pav:expr) => {
        for (field, expected_val) in $pav.vps.counts.iter() {
            let val = match split_field(field) {
                SplitField::One("epoch") => $pav.port.epoch(),

                SplitField::Two("uft", dir) => {
                    $pav.port.num_flows("uft", dir.parse().unwrap()) as u64
                }

                SplitField::Three(layer, "flows", dir) => {
                    $pav.port.num_flows(layer, dir.parse().unwrap()) as u64
                }

                SplitField::Three(layer, "rules", dir) => {
                    $pav.port.num_rules(layer, dir.parse().unwrap()) as u64
                }

                _ => todo!("impl check for: {field}"),
            };

            if *expected_val != val {
                print_port(&$pav.port, &$pav.vpc_map);
                panic!(
                    "field value mismatch: field: {field}, \
                     expected: {expected_val}, actual: {val}"
                );
            }
        }

        {
            let expected = $pav.vps.port_state;
            let actual = $pav.port.state();
            if expected != actual {
                print_port(&$pav.port, &$pav.vpc_map);
                panic!(
                    "port_state mismatch: expected: {expected}, \
                     actual: {actual}"
                );
            }
        }
    };
}

/// Increment a field in the `VpcPortState.counts` map.
#[macro_export]
macro_rules! incr_field_na {
    ($vps:expr, $field:expr) => {
        match $vps.counts.get_mut($field) {
            Some(v) => *v += 1,
            None => panic!("field is not a counter: '{}'", $field),
        }
    };
}

/// Increment a list of fields in the `VpcPortState.counts` map.
#[macro_export]
macro_rules! incr_na {
    ($pav:expr, $fields:expr) => {
        let fields_v: Vec<&str> = $fields.split(", ").collect();
        for f in fields_v {
            incr_field_na!($pav.vps, f);
        }
    };
}

/// Increment a list of fields in the `VpcPortState.counts` map and
/// assert the port state.
#[macro_export]
macro_rules! incr {
    ($pav:expr, $fields:expr) => {
        incr_na!($pav, $fields);
        assert_port!($pav);
    };
}

/// Decrement a field in the `VpcPortState.counts` map.
#[macro_export]
macro_rules! decr_field_na {
    ($vps:expr, $field:expr) => {
        match $vps.counts.get_mut($field) {
            Some(v) => *v -= 1,
            None => panic!("field is not a counter: '{}'", $field),
        }
    };
}

/// Decrement a list of fields in the `VpcPortState.counts` map.
#[macro_export]
macro_rules! decr_na {
    ($pav:expr, $fields:expr) => {
        let fields_v: Vec<&str> = $fields.split(", ").collect();
        for f in fields_v {
            decr_field_na!($pav.vps, f);
        }
    };
}

/// Decrement a list of fields in the `VpcPortState.counts` map and
/// assert the port state.
#[macro_export]
macro_rules! decr {
    ($pav:expr, $fields:expr) => {
        decr_na!($pav, $fields);
        assert_port!($pav);
    };
}

/// Set the value of a field.
#[macro_export]
macro_rules! set_field_na {
    ($pav:expr, $field:expr) => {
        match $field.split_once("=") {
            Some(("port_state", val)) => {
                $pav.vps.port_state = val.parse().unwrap();
            }

            Some((field, val)) => match $pav.vps.counts.get_mut(field) {
                Some(v) => match val.parse() {
                    Ok(val) => *v = val,
                    Err(_) => {
                        panic!(
                            "not a number: field: '{field}' val: '{val}'"
                        );
                    }
                },

                None => panic!("field is not a counter: '{}'", field),
            },

            _ => panic!("malformed set expr: '{}'", $field),
        }
    };
}

/// Set the values of a list of fields.
#[macro_export]
macro_rules! set_na {
    ($pav:expr, $fields:expr) => {
        let fields_v: Vec<&str> = $fields.split(", ").collect();
        for f in fields_v {
            set_field_na!($pav, f);
        }
    };
}

/// Set the values of a list of fields and assert.
///
/// ```
/// set_fields!(pav, "port_state=running, epoch=4, firewall.rules.in=6");
/// ```
#[macro_export]
macro_rules! set {
    ($pav:expr, $fields:expr) => {
        set_na!($pav, $fields);
        assert_port!($pav);
    };
}

/// Update the `VpcPortState` and assert. This macro allows one to use
/// the `set!`, `incr!`, and `decr!` in one atomic check. This takes
/// the form of an array of strings with the format `<instr>:<fields
/// list>` where `<instr>` is one of `set`, `incr`, or `decr`, and
/// `<fields list>` is a `, ` separated list of strings appropriate
/// for the given instruction.
///
/// ```
/// update!(g1, ["incr:epoch, firewall.flows.out", "set:port_state=running"])
/// ```
#[macro_export]
macro_rules! update {
    ($pav:expr, $instructions:expr) => {
        for inst in $instructions {
            match inst.split_once(":") {
                Some(("incr", fields)) => {
                    incr_na!($pav, fields);
                }

                Some(("set", fields)) => {
                    set_na!($pav, fields);
                }

                Some(("decr", fields)) => {
                    decr_na!($pav, fields);
                }

                Some((op, _)) => {
                    panic!("unknown op: '{}' instruction: '{}'", op, inst);
                }

                _ => panic!("malformed instruction: '{}'", inst),
            }
        }

        assert_port!($pav);
    };
}

/// Set all flow counts to zero.
#[macro_export]
macro_rules! zero_flows {
    ($pav:expr) => {
        for layer in &VPC_LAYERS {
            $pav.vps.counts.insert(format!("{layer}.flows.in"), 0);
            $pav.vps.counts.insert(format!("{layer}.flows.out"), 0);
        }

        $pav.vps.counts.insert("uft.out".to_string(), 0);
        $pav.vps.counts.insert("uft.in".to_string(), 0);
    };
}

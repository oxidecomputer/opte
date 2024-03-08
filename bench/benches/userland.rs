// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Userland packet parsing and processing microbenchmarks.

use criterion::criterion_group;
use criterion::criterion_main;
use criterion::BenchmarkId;
use criterion::Criterion;
use opte_bench::alloc::*;
use opte_bench::packet::BenchPacket;
use opte_bench::packet::BenchPacketInstance;
use opte_bench::packet::Dhcp4;
use opte_bench::packet::Dhcp6;
use opte_bench::packet::Icmp4;
use opte_bench::packet::Icmp6;
use opte_bench::packet::ParserKind;
use opte_bench::packet::TestCase;
use opte_bench::packet::ULP_FAST_PATH;
use opte_bench::packet::ULP_SLOW_PATH;
use opte_bench::MeasurementInfo;
use opte_test_utils::*;
use std::hint::black_box;

// Top level runner. Specifies packet classes.
//
// Timing/memory measurements are selected by `config` in the below
// `criterion_group!` invocations.
pub fn block<M: MeasurementInfo + 'static>(
    c: &mut Criterion<M>,
    do_parse: bool,
) {
    let all_tests: Vec<Box<dyn BenchPacket>> = vec![
        Box::new(Dhcp4),
        Box::new(Dhcp6),
        Box::new(Icmp4),
        Box::new(Icmp6),
        Box::new(ULP_FAST_PATH),
        Box::new(ULP_SLOW_PATH),
    ];

    for experiment in &all_tests {
        for case in experiment.test_cases() {
            if do_parse {
                test_parse(c, &**experiment, &*case);
            }
            test_handle(c, &**experiment, &*case);
        }
    }
}

pub fn parse_and_process<M: MeasurementInfo + 'static>(c: &mut Criterion<M>) {
    block(c, true)
}

pub fn process_only<M: MeasurementInfo + 'static>(c: &mut Criterion<M>) {
    block(c, false)
}

// Run benchmarks for parsing a given type of packet.
pub fn test_parse<M: MeasurementInfo + 'static>(
    c: &mut Criterion<M>,
    experiment: &dyn BenchPacket,
    case: &dyn BenchPacketInstance,
) {
    let mut c = c.benchmark_group(format!(
        "parse/{}/{}",
        experiment.packet_label(),
        M::label()
    ));
    let parser = case.parse_with();
    c.bench_with_input(
        BenchmarkId::from_parameter(case.instance_name()),
        &case,
        |b, inp| {
            b.iter_batched(
                || inp.generate(),
                // match *outside* the closure to prevent its selection from being timed.
                match parser {
                    ParserKind::Generic => |(in_pkt, direction): TestCase| {
                        in_pkt.parse(direction, GenericUlp {})
                    },
                    ParserKind::OxideVpc => |(in_pkt, direction): TestCase| {
                        in_pkt.parse(direction, VpcParser {})
                    },
                },
                criterion::BatchSize::PerIteration,
            )
        },
    );
}

// Run benchmarks for processing (e.g., generating hairpins, rewriting
// fields, encapsulation) for a given type of packet.
pub fn test_handle<M: MeasurementInfo + 'static>(
    c: &mut Criterion<M>,
    experiment: &dyn BenchPacket,
    case: &dyn BenchPacketInstance,
) {
    let port = match case.create_port() {
        Some(port) => port,
        None => {
            let g1_cfg = g1_cfg();
            let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
            g1.port.start();
            set!(g1, "port_state=running");

            g1
        }
    };
    let mut c = c.benchmark_group(format!(
        "process/{}/{}",
        experiment.packet_label(),
        M::label()
    ));

    c.bench_with_input(
        BenchmarkId::from_parameter(case.instance_name()),
        &case,
        |b, _i| {
            b.iter_batched(
                || {
                    let (init_pkt, dir) = case.generate();
                    let parsed_pkt = match case.parse_with() {
                        ParserKind::Generic => {
                            init_pkt.parse(dir, GenericUlp {}).unwrap()
                        }
                        ParserKind::OxideVpc => {
                            init_pkt.parse(dir, VpcParser {}).unwrap()
                        }
                    };

                    case.pre_handle(&port);

                    (parsed_pkt, dir)
                },
                |(mut pkt, dir)| {
                    assert!(!matches!(
                        port.port
                            .process(
                                dir,
                                black_box(&mut pkt),
                                ActionMeta::new(),
                            )
                            .unwrap(),
                        ProcessResult::Drop { .. }
                    ))
                },
                criterion::BatchSize::PerIteration,
            )
        },
    );
}

criterion_group!(wall, parse_and_process);
criterion_group!(
    name = alloc;
    config = new_crit(Allocs);
    targets = process_only
);
criterion_group!(
    name = byte_alloc;
    config = new_crit(BytesAlloced);
    targets = process_only
);
criterion_main!(wall, alloc, byte_alloc);

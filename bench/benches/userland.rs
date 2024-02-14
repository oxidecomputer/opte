// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

use criterion::criterion_group;
use criterion::criterion_main;
use criterion::BenchmarkId;
use criterion::Criterion;
use opte_bench::alloc::*;
use opte_bench::packet::BenchPacket;
use opte_bench::packet::BenchPacketInstance;
use opte_bench::packet::Dhcp6;
use opte_bench::packet::Icmp4;
use opte_bench::MeasurementInfo;
use opte_test_utils::*;
use std::hint::black_box;

// WANT: Parsing time as well for different packet classes,
// scale on options len etc.
pub fn block<M: MeasurementInfo + 'static>(c: &mut Criterion<M>) {
    let all_tests: Vec<Box<dyn BenchPacket>> =
        vec![Box::new(Dhcp6 {}), Box::new(Icmp4 {})];

    for experiment in &all_tests {
        for case in experiment.test_cases() {
            test_parse(c, &**experiment, &*case);
            test_handle(c, &**experiment, &*case);
        }
    }
}

pub fn test_parse<M: MeasurementInfo + 'static>(
    c: &mut Criterion<M>,
    experiment: &dyn BenchPacket,
    case: &dyn BenchPacketInstance,
) {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    let mut c = c.benchmark_group(format!(
        "parse/{}/{}",
        experiment.packet_label(),
        M::label()
    ));
    c.bench_with_input(
        BenchmarkId::from_parameter(case.instance_name()),
        &case,
        |b, inp| {
            b.iter_batched(
                || inp.generate(),
                |(in_pkt, direction)| in_pkt.parse(direction, GenericUlp {}),
                criterion::BatchSize::PerIteration,
            )
        },
    );
}

pub fn test_handle<M: MeasurementInfo + 'static>(
    c: &mut Criterion<M>,
    experiment: &dyn BenchPacket,
    case: &dyn BenchPacketInstance,
) {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    let mut c = c.benchmark_group(format!(
        "process/{}/{}",
        experiment.packet_label(),
        M::label()
    ));
    let (pkt, dir) = case.generate();
    let mut pkt = pkt.parse(dir, GenericUlp {}).unwrap();

    c.bench_with_input(
        BenchmarkId::from_parameter(case.instance_name()),
        &case,
        |b, _i| {
            b.iter_with_large_drop(|| {
                g1.port.process(Out, black_box(&mut pkt), ActionMeta::new())
            })
        },
    );
}

criterion_group!(wall, block);
criterion_group!(
    name = alloc;
    config = new_crit(Allocs);
    targets = block
);
criterion_group!(
    name = byte_alloc;
    config = new_crit(BytesAlloced);
    targets = block
);
criterion_main!(wall, alloc, byte_alloc);

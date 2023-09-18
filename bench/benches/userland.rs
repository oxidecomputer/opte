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
use opte_bench::packet::Dhcp6;
use opte_bench::MeasurementInfo;
// use opte_test_utils::dhcp::dhcpv6_with_reasonable_defaults;
// use opte_test_utils::dhcp::packet_from_client_dhcpv6_message;
use opte_test_utils::icmp::gen_icmp_echo_req;
use opte_test_utils::*;
use std::hint::black_box;
use std::vec;

// WANT: Parsing time as well for different packet classes,
// scale on options len etc.

pub fn icmpv4_ping<M: MeasurementInfo + 'static>(c: &mut Criterion<M>) {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");
    let ident = 7;
    let seq_no = 777;
    let data = b"reunion\0";

    let mut pkt1 = gen_icmp_echo_req(
        g1_cfg.guest_mac,
        g1_cfg.gateway_mac,
        g1_cfg.ipv4_cfg().unwrap().private_ip.into(),
        g1_cfg.ipv4_cfg().unwrap().gateway_ip.into(),
        ident,
        seq_no,
        &data[..],
        1,
    );

    let mut c = c.benchmark_group(M::label());

    let mut hit = false;
    c.bench_function("ICMPv4", |b| {
        b.iter_with_large_drop(|| {
            if !hit {
                black_box(vec![0u8]);
            }
            hit = !hit;
            g1.port.process(Out, black_box(&mut pkt1), ActionMeta::new())
        })
    });
}

pub fn block<M: MeasurementInfo + 'static>(c: &mut Criterion<M>) {
    let all_tests: Vec<Box<dyn BenchPacket>> = vec![Box::new(Dhcp6 {})];

    // XXX: Probably shouldn't reuse port: break into trait later.
    //      AND want way to specify params to vary on per-pkt basis.
    //      AND directionality.
    for experiment in &all_tests {
        test_parse(c, experiment);
        test_handle(c, experiment);
    }
}

// XXX: this is so ugly.

pub fn test_parse<M: MeasurementInfo + 'static>(
    c: &mut Criterion<M>,
    experiment: &Box<dyn BenchPacket>,
) {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    let mut c = c.benchmark_group(format!("parse/{}", M::label()));

    for case in experiment.test_cases() {
        c.bench_with_input(
            BenchmarkId::from_parameter(case.instance_name()),
            &case,
            |b, inp| {
                b.iter_batched(
                    || inp.generate(),
                    |(in_pkt, direction)| {
                        in_pkt.parse(direction, GenericUlp {})
                    },
                    criterion::BatchSize::PerIteration,
                )
            },
        );
    }
}

pub fn test_handle<M: MeasurementInfo + 'static>(
    c: &mut Criterion<M>,
    experiment: &Box<dyn BenchPacket>,
) {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    let mut c = c.benchmark_group(format!("process/{}", M::label()));

    for case in experiment.test_cases() {
        let (mut pkt, dir) = case.generate();
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

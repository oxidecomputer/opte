// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Userland packet parsing and processing microbenchmarks.

use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::Throughput;
use criterion::criterion_group;
use criterion::criterion_main;
use opte::engine::packet::Packet;
use opte_bench::MeasurementInfo;
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
use opte_test_utils::*;
use oxide_vpc::api::IpAddr;
use oxide_vpc::api::Ipv4Addr;
use oxide_vpc::api::Ipv6Addr;
use oxide_vpc::api::SourceFilter;
use std::collections::BTreeSet;
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
                    ParserKind::Generic => {
                        |(mut in_pkt, direction): TestCase| {
                            black_box(match direction {
                                In => Packet::parse_inbound(
                                    in_pkt.iter_mut(),
                                    GenericUlp {},
                                ),
                                Out => Packet::parse_outbound(
                                    in_pkt.iter_mut(),
                                    GenericUlp {},
                                ),
                            })
                            .unwrap();
                        }
                    }
                    ParserKind::OxideVpc => {
                        |(mut in_pkt, direction): TestCase| {
                            black_box(match direction {
                                In => {
                                    Packet::parse_inbound(
                                        in_pkt.iter_mut(),
                                        VpcParser {},
                                    )
                                    .unwrap();
                                }
                                Out => {
                                    Packet::parse_outbound(
                                        in_pkt.iter_mut(),
                                        VpcParser {},
                                    )
                                    .unwrap();
                                }
                            });
                        }
                    }
                },
                criterion::BatchSize::LargeInput,
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

    let parser = case.parse_with();
    c.bench_with_input(
        BenchmarkId::from_parameter(case.instance_name()),
        &case,
        |b, _i| {
            b.iter_batched(
                || {
                    let (init_pkt, dir) = case.generate();
                    case.pre_handle(&port);

                    (init_pkt, dir)
                },
                // Can't seem to match outside here -- must be missing something.
                // Sadly, we can't elide parsing here as the
                // packet is now a view over the generated pkt.
                |(mut pkt_m, dir): TestCase| match parser {
                    ParserKind::Generic => {
                        let res = match dir {
                            In => {
                                let pkt = Packet::parse_inbound(
                                    pkt_m.iter_mut(),
                                    GenericUlp {},
                                )
                                .unwrap();
                                port.port.process(dir, black_box(pkt)).unwrap()
                            }
                            Out => {
                                let pkt = Packet::parse_outbound(
                                    pkt_m.iter_mut(),
                                    GenericUlp {},
                                )
                                .unwrap();
                                port.port.process(dir, black_box(pkt)).unwrap()
                            }
                        };
                        assert!(!matches!(res, ProcessResult::Drop { .. }));
                        if let Modified(spec) = res {
                            black_box(spec.apply(pkt_m));
                        }
                    }
                    ParserKind::OxideVpc => {
                        let res = match dir {
                            In => {
                                let pkt = Packet::parse_inbound(
                                    pkt_m.iter_mut(),
                                    VpcParser {},
                                )
                                .unwrap();
                                port.port.process(dir, black_box(pkt)).unwrap()
                            }
                            Out => {
                                let pkt = Packet::parse_outbound(
                                    pkt_m.iter_mut(),
                                    VpcParser {},
                                )
                                .unwrap();
                                port.port.process(dir, black_box(pkt)).unwrap()
                            }
                        };
                        assert!(!matches!(res, ProcessResult::Drop { .. }));
                        if let Modified(spec) = res {
                            black_box(spec.apply(pkt_m));
                        }
                    }
                },
                criterion::BatchSize::LargeInput,
            )
        },
    );
}

/// Generate a source IP address for filter testing (10.0.0.x).
fn make_src_v4(i: u32) -> IpAddr {
    IpAddr::Ip4(Ipv4Addr::from(0x0a000000u32 + i))
}

/// Generate a source IP address for filter testing (fd00::x).
fn make_src_v6(i: u32) -> IpAddr {
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&[0xfd, 0x00, 0x00, 0x00]);
    bytes[12..16].copy_from_slice(&i.to_be_bytes());
    IpAddr::Ip6(Ipv6Addr::from(bytes))
}

/// Benchmark [`SourceFilter::allows`] for various filter configurations.
fn source_filter_allows(c: &mut Criterion) {
    let mut group = c.benchmark_group("source_filter/allows");
    group.throughput(Throughput::Elements(1));

    let src_v4 = make_src_v4(100); // Not in any source list
    let src_v6 = make_src_v6(100);

    // Fast path: EXCLUDE() with empty sources (*, G)
    let filter_any = SourceFilter::default();
    group.bench_function("exclude_empty_v4", |b| {
        b.iter(|| black_box(filter_any.allows(black_box(src_v4))))
    });
    group.bench_function("exclude_empty_v6", |b| {
        b.iter(|| black_box(filter_any.allows(black_box(src_v6))))
    });

    // EXCLUDE with sources: "Miss" case where source is not in exclusion list
    for size in [1, 5, 10, 50, 100] {
        let sources_v4: BTreeSet<_> = (0..size).map(make_src_v4).collect();
        let filter_v4 = SourceFilter::Exclude(sources_v4);
        group.bench_with_input(
            BenchmarkId::new("exclude_miss_v4", size),
            &filter_v4,
            |b, f| b.iter(|| black_box(f.allows(black_box(src_v4)))),
        );
        let src_in_list_v4 = make_src_v4(0);
        group.bench_with_input(
            BenchmarkId::new("exclude_hit_v4", size),
            &filter_v4,
            |b, f| b.iter(|| black_box(f.allows(black_box(src_in_list_v4)))),
        );

        let sources_v6: BTreeSet<_> = (0..size).map(make_src_v6).collect();
        let filter_v6 = SourceFilter::Exclude(sources_v6);
        group.bench_with_input(
            BenchmarkId::new("exclude_miss_v6", size),
            &filter_v6,
            |b, f| b.iter(|| black_box(f.allows(black_box(src_v6)))),
        );
        let src_in_list_v6 = make_src_v6(0);
        group.bench_with_input(
            BenchmarkId::new("exclude_hit_v6", size),
            &filter_v6,
            |b, f| b.iter(|| black_box(f.allows(black_box(src_in_list_v6)))),
        );
    }

    // INCLUDE with sources: "Hit" case where source is in inclusion list
    for size in [1, 5, 10, 50, 100] {
        let sources_v4: BTreeSet<_> = (0..size).map(make_src_v4).collect();
        let filter_v4 = SourceFilter::Include(sources_v4);
        let src_in_list_v4 = make_src_v4(0);
        group.bench_with_input(
            BenchmarkId::new("include_hit_v4", size),
            &filter_v4,
            |b, f| b.iter(|| black_box(f.allows(black_box(src_in_list_v4)))),
        );
        group.bench_with_input(
            BenchmarkId::new("include_miss_v4", size),
            &filter_v4,
            |b, f| b.iter(|| black_box(f.allows(black_box(src_v4)))),
        );

        let sources_v6: BTreeSet<_> = (0..size).map(make_src_v6).collect();
        let filter_v6 = SourceFilter::Include(sources_v6);
        let src_in_list_v6 = make_src_v6(0);
        group.bench_with_input(
            BenchmarkId::new("include_hit_v6", size),
            &filter_v6,
            |b, f| b.iter(|| black_box(f.allows(black_box(src_in_list_v6)))),
        );
        group.bench_with_input(
            BenchmarkId::new("include_miss_v6", size),
            &filter_v6,
            |b, f| b.iter(|| black_box(f.allows(black_box(src_v6)))),
        );
    }

    // INCLUDE() empty, rejecting all
    let filter_none = SourceFilter::Include(BTreeSet::new());
    group.bench_function("include_empty_v4", |b| {
        b.iter(|| black_box(filter_none.allows(black_box(src_v4))))
    });
    group.bench_function("include_empty_v6", |b| {
        b.iter(|| black_box(filter_none.allows(black_box(src_v6))))
    });

    group.finish();
}

criterion_group!(wall, parse_and_process, source_filter_allows);
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

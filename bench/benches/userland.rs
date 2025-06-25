// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Userland packet parsing and processing microbenchmarks.

use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::PlotConfiguration;
use criterion::criterion_group;
use criterion::criterion_main;
use opte::api::InnerFlowId;
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
use rand::Rng;
use rand::SeedableRng;
use rand::seq::SliceRandom;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::atomic::AtomicU64;

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

pub fn maps(c: &mut Criterion) {
    let seed = 0x1de0_2222_3333_4444;
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    // ~4mil entries ought to be enough.
    const ELS_SHIFT: i32 = 22;
    const MAX_ELS: usize = 1 << ELS_SHIFT;
    let flow_ids: Vec<_> = (0..=MAX_ELS)
        .map(|_| {
            let is_tcp = rng.random();
            InnerFlowId {
                proto: if is_tcp {
                    IngotIpProto::TCP.0
                } else {
                    IngotIpProto::UDP.0
                },
                addrs: opte::api::AddrPair::V4 {
                    src: Ipv4Addr::from_const(rng.random()),
                    dst: Ipv4Addr::from_const(rng.random()),
                },
                proto_info: rng.random(),
            }
        })
        .collect();

    // Make sure we have the same random element insert/delete order per test.
    let mut shuffle_sets = vec![];
    for i in 4..=ELS_SHIFT {
        let n = 1usize << i;
        let mut set: Vec<_> = flow_ids[..n].iter().copied().collect();
        set.shuffle(&mut rng);
        shuffle_sets.push(set);
    }

    let mut shuffled = flow_ids.clone();
    shuffled.shuffle(&mut rng);

    let mut g = c.benchmark_group("hmaps/insert");
    g.plot_config(
        PlotConfiguration::default()
            .summary_scale(criterion::AxisScale::Logarithmic),
    );
    for i in 4..=ELS_SHIFT {
        let n = 1usize << i;
        let add_list = &shuffle_sets[(i - 4) as usize];

        g.bench_with_input(BenchmarkId::new("BTreeMap", n), &n, |b, &n| {
            let map = flow_ids[..n]
                .iter()
                .copied()
                .map(|a| (a, Arc::new(())))
                .collect::<BTreeMap<_, _>>();
            let mmap = RefCell::new(map);
            let i = AtomicU64::new(0);

            b.iter_batched(
                || {
                    let mut mmap = mmap.borrow_mut();
                    let raw_idx =
                        i.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let my_idx = (raw_idx as usize) % n;
                    let last_idx = (raw_idx.wrapping_sub(1) as usize) % n;
                    mmap.insert(add_list[last_idx], Arc::new(()));
                    mmap.remove(&add_list[my_idx]);
                    add_list[my_idx]
                },
                |my_idx| {
                    let mut mmap = mmap.borrow_mut();
                    mmap.insert(core::hint::black_box(my_idx), Arc::new(()));
                },
                criterion::BatchSize::SmallInput,
            );
        });

        g.bench_with_input(BenchmarkId::new("ahash", n), &n, |b, &n| {
            let map = flow_ids[..n]
                .iter()
                .copied()
                .map(|a| (a, Arc::new(())))
                .collect::<hashbrown::HashMap<_, _, ahash::RandomState>>();
            let mmap = RefCell::new(map);
            let i = AtomicU64::new(0);

            b.iter_batched(
                || {
                    let mut mmap = mmap.borrow_mut();
                    let raw_idx =
                        i.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let my_idx = (raw_idx as usize) % n;
                    let last_idx = (raw_idx.wrapping_sub(1) as usize) % n;
                    mmap.insert(add_list[last_idx], Arc::new(()));
                    mmap.remove(&add_list[my_idx]);
                    add_list[my_idx]
                },
                |my_idx| {
                    let mut mmap = mmap.borrow_mut();
                    mmap.insert(core::hint::black_box(my_idx), Arc::new(()));
                },
                criterion::BatchSize::SmallInput,
            );
        });

        g.bench_with_input(BenchmarkId::new("foldhash", n), &n, |b, &n| {
            let map = flow_ids[..n]
                .iter()
                .copied()
                .map(|a| (a, Arc::new(())))
                .collect::<hashbrown::HashMap<_, _>>();
            let mmap = RefCell::new(map);
            let i = AtomicU64::new(0);

            b.iter_batched(
                || {
                    let mut mmap = mmap.borrow_mut();
                    let raw_idx =
                        i.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let my_idx = (raw_idx as usize) % n;
                    let last_idx = (raw_idx.wrapping_sub(1) as usize) % n;
                    mmap.insert(add_list[last_idx], Arc::new(()));
                    mmap.remove(&add_list[my_idx]);
                    add_list[my_idx]
                },
                |my_idx| {
                    let mut mmap = mmap.borrow_mut();
                    mmap.insert(core::hint::black_box(my_idx), Arc::new(()));
                },
                criterion::BatchSize::SmallInput,
            );
        });

        g.bench_with_input(BenchmarkId::new("siphash", n), &n, |b, &n| {
            let map = flow_ids[..n]
                .iter()
                .copied()
                .map(|a| (a, Arc::new(())))
                .collect::<std::collections::HashMap<_, _>>();
            let mmap = RefCell::new(map);
            let i = AtomicU64::new(0);

            b.iter_batched(
                || {
                    let mut mmap = mmap.borrow_mut();
                    let raw_idx =
                        i.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let my_idx = (raw_idx as usize) % n;
                    let last_idx = (raw_idx.wrapping_sub(1) as usize) % n;
                    mmap.insert(add_list[last_idx], Arc::new(()));
                    mmap.remove(&add_list[my_idx]);
                    add_list[my_idx]
                },
                |my_idx| {
                    let mut mmap = mmap.borrow_mut();
                    mmap.insert(core::hint::black_box(my_idx), Arc::new(()));
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    g.finish();

    let mut g = c.benchmark_group("hmaps/get");
    g.plot_config(
        PlotConfiguration::default()
            .summary_scale(criterion::AxisScale::Logarithmic),
    );
    for i in 4..=ELS_SHIFT {
        let n = 1usize << i;
        let add_list = &shuffle_sets[(i - 4) as usize];

        g.bench_with_input(BenchmarkId::new("BTreeMap", n), &n, |b, &n| {
            let map = flow_ids[..n]
                .iter()
                .copied()
                .map(|a| (a, Arc::new(())))
                .collect::<BTreeMap<_, _>>();
            let i = AtomicU64::new(0);

            b.iter_batched_ref(
                || {
                    let raw_idx =
                        i.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let my_idx = (raw_idx as usize) % n;
                    add_list[my_idx]
                },
                |my_idx| {
                    core::hint::black_box(map.get(my_idx));
                },
                criterion::BatchSize::SmallInput,
            );
        });

        g.bench_with_input(BenchmarkId::new("ahash", n), &n, |b, &n| {
            let map = flow_ids[..n]
                .iter()
                .copied()
                .map(|a| (a, Arc::new(())))
                .collect::<hashbrown::HashMap<_, _, ahash::RandomState>>();
            let i = AtomicU64::new(0);

            b.iter_batched_ref(
                || {
                    let raw_idx =
                        i.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let my_idx = (raw_idx as usize) % n;
                    add_list[my_idx]
                },
                |my_idx| {
                    core::hint::black_box(map.get(my_idx));
                },
                criterion::BatchSize::SmallInput,
            );
        });

        g.bench_with_input(BenchmarkId::new("foldhash", n), &n, |b, &n| {
            let map = flow_ids[..n]
                .iter()
                .copied()
                .map(|a| (a, Arc::new(())))
                .collect::<hashbrown::HashMap<_, _>>();
            let i = AtomicU64::new(0);

            b.iter_batched_ref(
                || {
                    let raw_idx =
                        i.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let my_idx = (raw_idx as usize) % n;
                    add_list[my_idx]
                },
                |my_idx| {
                    core::hint::black_box(map.get(my_idx));
                },
                criterion::BatchSize::SmallInput,
            );
        });

        g.bench_with_input(BenchmarkId::new("siphash", n), &n, |b, &n| {
            let map = flow_ids[..n]
                .iter()
                .copied()
                .map(|a| (a, Arc::new(())))
                .collect::<std::collections::HashMap<_, _>>();
            let i = AtomicU64::new(0);

            b.iter_batched_ref(
                || {
                    let raw_idx =
                        i.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let my_idx = (raw_idx as usize) % n;
                    add_list[my_idx]
                },
                |my_idx| {
                    core::hint::black_box(map.get(my_idx));
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    g.finish();
}

criterion_group!(micro, maps);
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
criterion_main!(wall, alloc, byte_alloc, micro);

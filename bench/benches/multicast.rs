// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Multicast microbenchmarks.

use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::Throughput;
use criterion::criterion_group;
use criterion::criterion_main;
use oxide_vpc::api::FilterMode;
use oxide_vpc::api::IpAddr;
use oxide_vpc::api::Ipv4Addr;
use oxide_vpc::api::Ipv6Addr;
use oxide_vpc::api::SourceFilter;
use std::collections::BTreeSet;
use std::hint::black_box;

/// Generate a source IP address for filter testing (10.0.0.x).
/// These are unicast source addresses, not multicast group destinations.
fn make_src_v4(i: u32) -> IpAddr {
    IpAddr::Ip4(Ipv4Addr::from(0x0a000000u32 + i))
}

/// Generate a source IP address for filter testing (fd00::x).
/// These are unicast source addresses, not multicast group destinations.
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
        let filter_v4 =
            SourceFilter { mode: FilterMode::Exclude, sources: sources_v4 };
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
        let filter_v6 =
            SourceFilter { mode: FilterMode::Exclude, sources: sources_v6 };
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
        let filter_v4 =
            SourceFilter { mode: FilterMode::Include, sources: sources_v4 };
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
        let filter_v6 =
            SourceFilter { mode: FilterMode::Include, sources: sources_v6 };
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
    let filter_none =
        SourceFilter { mode: FilterMode::Include, sources: BTreeSet::new() };
    group.bench_function("include_empty_v4", |b| {
        b.iter(|| black_box(filter_none.allows(black_box(src_v4))))
    });
    group.bench_function("include_empty_v6", |b| {
        b.iter(|| black_box(filter_none.allows(black_box(src_v6))))
    });

    group.finish();
}

criterion_group!(benches, source_filter_allows);
criterion_main!(benches);

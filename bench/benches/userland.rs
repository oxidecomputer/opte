// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use opte_bench::alloc::*;
use opte_bench::MeasurementInfo;
use opte_test_utils::dhcp::dhcpv6_with_reasonable_defaults;
use opte_test_utils::dhcp::packet_from_client_dhcpv6_message;
use opte_test_utils::icmp::gen_icmp_echo_req;
use opte_test_utils::*;
use std::hint::black_box;

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

    c.bench_function("ICMPv4", |b| {
        b.iter_with_large_drop(|| {
            g1.port.process(Out, black_box(&mut pkt1), ActionMeta::new())
        })
    });
}

pub fn dhcp<M: MeasurementInfo + 'static>(c: &mut Criterion<M>) {
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None, None);
    g1.port.start();
    set!(g1, "port_state=running");

    use opte::engine::dhcpv6::MessageType;

    let d1 =
        dhcpv6_with_reasonable_defaults(MessageType::Solicit, false, &g1_cfg);
    let d2 =
        dhcpv6_with_reasonable_defaults(MessageType::Request, false, &g1_cfg);
    let mut pkt1 = packet_from_client_dhcpv6_message(&g1_cfg, &d1);
    let mut pkt2 = packet_from_client_dhcpv6_message(&g1_cfg, &d2);

    let mut c = c.benchmark_group(M::label());

    c.bench_function("DHCPv6 Solicit", |b| {
        b.iter_with_large_drop(|| {
            g1.port.process(Out, black_box(&mut pkt1), ActionMeta::new())
        })
    });

    c.bench_function("DHCPv6 Request", |b| {
        b.iter_with_large_drop(|| {
            g1.port.process(Out, black_box(&mut pkt2), ActionMeta::new())
        })
    });
}

criterion_group!(hairpin_wall, icmpv4_ping, dhcp);
criterion_group!(
    name = hairpin_alloc;
    config = new_crit(Allocs);
    targets = icmpv4_ping, dhcp
);
criterion_group!(
    name = hairpin_byte_alloc;
    config = new_crit(BytesAlloced);
    targets = icmpv4_ping, dhcp
);
criterion_main!(hairpin_wall, hairpin_alloc, hairpin_byte_alloc);
// criterion_main!(hairpin_alloc);

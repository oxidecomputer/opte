// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Functions for printing comannd responses.
//!
//! This is mostly just a place to hang printing routines so that they
//! can be used by both opteadm and integration tests.

use crate::api::GuestPhysAddr;
use crate::api::Ipv4Addr;
use crate::api::Ipv6Addr;
use crate::engine::overlay::DumpVirt2BoundaryResp;
use crate::engine::overlay::DumpVirt2PhysResp;
use alloc::string::ToString;
use opte::api::IpCidr;
use opte::engine::geneve::Vni;
use opte::engine::print::*;

/// Print the header for the [`print_v2p()`] output.
fn print_v2p_header() {
    println!("{:<24} {:<17} UNDERLAY IP", "VPC IP", "VPC MAC ADDR");
}

/// Print a [`DumpVirt2PhysResp`].
pub fn print_v2p(resp: &DumpVirt2PhysResp) {
    println!("Virtual to Physical Mappings");
    print_hrb();
    for vpc in &resp.mappings {
        println!();
        println!("VPC {}", vpc.vni);
        print_hr();
        println!();
        println!("IPv4 mappings");
        print_hr();
        print_v2p_header();
        for pair in &vpc.ip4 {
            print_v2p_ip4(pair);
        }

        println!();
        println!("IPv6 mappings");
        print_hr();
        print_v2p_header();
        for pair in &vpc.ip6 {
            print_v2p_ip6(pair);
        }
    }
}

/// Print the header for the [`print_v2p()`] output.
fn print_v2b_header() {
    println!("{:<24} {:<17} VNI", "TUNNELED PREFIX", "BOUNDARY IP");
}

fn print_v2b_entry(prefix: IpCidr, boundary: Ipv6Addr, vni: Vni) {
    println!("{:<24} {:<17} {}", prefix.to_string(), boundary.to_string(), vni);
}

/// Print a [`DumpVirt2BoundaryResp`].
pub fn print_v2b(resp: &DumpVirt2BoundaryResp) {
    println!("Virtual to Boundary Mappings");
    print_hrb();
    println!();
    println!("IPv4 mappings");
    print_hr();
    print_v2b_header();
    for x in &resp.mappings.ip4 {
        for tep in &x.1 {
            print_v2b_entry(x.0.into(), tep.ip, tep.vni);
        }
    }
    println!();
    println!("IPv6 mappings");
    print_hr();
    print_v2b_header();
    for x in &resp.mappings.ip6 {
        for tep in &x.1 {
            print_v2b_entry(x.0.into(), tep.ip, tep.vni);
        }
    }
    println!();
}

fn print_v2p_ip4((src, phys): &(Ipv4Addr, GuestPhysAddr)) {
    let eth = format!("{}", phys.ether);
    println!(
        "{:<24} {:<17} {}",
        std::net::Ipv4Addr::from(src.bytes()),
        eth,
        std::net::Ipv6Addr::from(phys.ip.bytes()),
    );
}

fn print_v2p_ip6((src, phys): &(Ipv6Addr, GuestPhysAddr)) {
    let eth = format!("{}", phys.ether);
    println!(
        "{:<24} {:<17} {}",
        std::net::Ipv6Addr::from(src.bytes()),
        eth,
        std::net::Ipv6Addr::from(phys.ip.bytes()),
    );
}

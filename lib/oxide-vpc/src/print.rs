// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Functions for printing command responses.
//!
//! This is mostly just a place to hang printing routines so that they
//! can be used by both opteadm and integration tests.

use crate::api::DumpMcastForwardingResp;
use crate::api::DumpMcastSubscriptionsResp;
use crate::api::DumpVirt2BoundaryResp;
use crate::api::DumpVirt2PhysResp;
use crate::api::FilterMode;
use crate::api::GuestPhysAddr;
use crate::api::Ipv4Addr;
use crate::api::Ipv6Addr;
use crate::api::SourceFilter;
use opte::api::IpCidr;
use opte::api::Vni;
use opte::print::*;
use std::io::Write;
use tabwriter::TabWriter;

/// Print the header for the [`print_v2p()`] output.
fn print_v2p_header(t: &mut impl Write) -> std::io::Result<()> {
    writeln!(t, "VPC_IP\tVPC MAC ADDR\tUNDERLAY IP")
}

/// Print a [`DumpVirt2PhysResp`].
pub fn print_v2p(resp: &DumpVirt2PhysResp) -> std::io::Result<()> {
    print_v2p_into(&mut std::io::stdout(), resp)
}

/// Print a [`DumpVirt2PhysResp`] into a given writer.
pub fn print_v2p_into(
    writer: &mut impl Write,
    resp: &DumpVirt2PhysResp,
) -> std::io::Result<()> {
    let mut t = TabWriter::new(writer);
    writeln!(t, "Virtual to Physical Mappings")?;
    write_hrb(&mut t)?;
    for vpc in &resp.mappings {
        writeln!(t, "\nVPC {}", vpc.vni)?;
        write_hr(&mut t)?;
        writeln!(t, "\nIPv4 mappings")?;
        write_hr(&mut t)?;
        print_v2p_header(&mut t)?;
        for pair in &vpc.ip4 {
            print_v2p_ip4(&mut t, pair)?;
        }
        t.flush()?;

        writeln!(t, "\nIPv6 mappings")?;
        write_hr(&mut t)?;
        print_v2p_header(&mut t)?;
        for pair in &vpc.ip6 {
            print_v2p_ip6(&mut t, pair)?;
        }
        t.flush()?;
    }
    t.flush()
}

/// Print the header for the [`print_v2p()`] output.
fn print_v2b_header(t: &mut impl Write) -> std::io::Result<()> {
    writeln!(t, "TUNNELED PREFIX\tBOUNDARY IP\tVNI")
}

fn print_v2b_entry(
    t: &mut impl Write,
    prefix: IpCidr,
    boundary: Ipv6Addr,
    vni: Vni,
) -> std::io::Result<()> {
    writeln!(t, "{prefix}\t{boundary}\t{vni}")
}

/// Print a [`DumpVirt2BoundaryResp`].
pub fn print_v2b(resp: &DumpVirt2BoundaryResp) -> std::io::Result<()> {
    print_v2b_into(&mut std::io::stdout(), resp)
}

/// Print a [`DumpVirt2BoundaryResp`] into a given writer.
pub fn print_v2b_into(
    writer: &mut impl Write,
    resp: &DumpVirt2BoundaryResp,
) -> std::io::Result<()> {
    let mut t = TabWriter::new(writer);
    writeln!(t, "Virtual to Boundary Mappings")?;
    write_hrb(&mut t)?;
    writeln!(t, "\nIPv4 mappings")?;
    write_hr(&mut t)?;
    print_v2b_header(&mut t)?;
    for x in &resp.mappings.ip4 {
        for tep in &x.1 {
            print_v2b_entry(&mut t, x.0.into(), tep.ip, tep.vni)?;
        }
    }
    t.flush()?;

    writeln!(t, "\nIPv6 mappings")?;
    write_hr(&mut t)?;
    print_v2b_header(&mut t)?;
    for x in &resp.mappings.ip6 {
        for tep in &x.1 {
            print_v2b_entry(&mut t, x.0.into(), tep.ip, tep.vni)?;
        }
    }
    writeln!(t)?;

    t.flush()
}

fn print_v2p_ip4(
    t: &mut impl Write,
    (src, phys): &(Ipv4Addr, GuestPhysAddr),
) -> std::io::Result<()> {
    writeln!(
        t,
        "{}\t{}\t{}",
        std::net::Ipv4Addr::from(src.bytes()),
        phys.ether,
        std::net::Ipv6Addr::from(phys.ip.bytes()),
    )
}

fn print_v2p_ip6(
    t: &mut impl Write,
    (src, phys): &(Ipv6Addr, GuestPhysAddr),
) -> std::io::Result<()> {
    writeln!(
        t,
        "{}\t{}\t{}",
        std::net::Ipv6Addr::from(src.bytes()),
        phys.ether,
        std::net::Ipv6Addr::from(phys.ip.bytes()),
    )
}

/// Print the header for the [`print_mcast_fwd()`] output.
fn print_mcast_fwd_header(t: &mut impl Write) -> std::io::Result<()> {
    writeln!(t, "GROUP IP\tUNDERLAY IP\tVNI\tREPLICATION\tFILTER")
}

/// Print a [`DumpMcastForwardingResp`].
pub fn print_mcast_fwd(resp: &DumpMcastForwardingResp) -> std::io::Result<()> {
    print_mcast_fwd_into(&mut std::io::stdout(), resp)
}

/// Print a [`DumpMcastForwardingResp`] into a given writer.
pub fn print_mcast_fwd_into(
    writer: &mut impl Write,
    resp: &DumpMcastForwardingResp,
) -> std::io::Result<()> {
    let mut t = TabWriter::new(writer);
    writeln!(t, "Multicast Forwarding Table")?;
    write_hrb(&mut t)?;
    writeln!(t)?;
    print_mcast_fwd_header(&mut t)?;
    write_hr(&mut t)?;

    for entry in &resp.entries {
        for hop in &entry.next_hops {
            write!(
                t,
                "{}\t{}\t{}\t{:?}\t",
                entry.underlay,
                hop.next_hop.addr,
                hop.next_hop.vni,
                hop.replication
            )?;
            write_source_filter(&mut t, &hop.source_filter)?;
            writeln!(t)?;
        }
    }
    writeln!(t)?;
    t.flush()
}

/// Print the header for the [`print_mcast_subs()`] output.
fn print_mcast_subs_header(t: &mut impl Write) -> std::io::Result<()> {
    writeln!(t, "UNDERLAY GROUP\tPORT\tFILTER")
}

/// Print a [`DumpMcastSubscriptionsResp`].
pub fn print_mcast_subs(
    resp: &DumpMcastSubscriptionsResp,
) -> std::io::Result<()> {
    print_mcast_subs_into(&mut std::io::stdout(), resp)
}

/// Print a [`DumpMcastSubscriptionsResp`] into a given writer.
pub fn print_mcast_subs_into(
    writer: &mut impl Write,
    resp: &DumpMcastSubscriptionsResp,
) -> std::io::Result<()> {
    let mut t = TabWriter::new(writer);
    writeln!(t, "Multicast Subscriptions")?;
    write_hrb(&mut t)?;
    writeln!(t)?;
    print_mcast_subs_header(&mut t)?;
    write_hr(&mut t)?;

    for entry in &resp.entries {
        for sub in &entry.subscribers {
            write!(t, "{}\t{}\t", entry.underlay, sub.port)?;
            write_source_filter(&mut t, &sub.filter)?;
            writeln!(t)?;
        }
    }
    writeln!(t)?;
    t.flush()
}

/// Write a source filter to the given writer.
///
/// Uses notation inspired by RFC 3376 (IGMPv3) and RFC 3810 (MLDv2):
/// - `INCLUDE(S1, S2)` - accept only from listed sources
/// - `EXCLUDE(S1, S2)` - accept from all except listed sources
/// - `EXCLUDE()` - accept any source (*, G)
/// - `INCLUDE()` - accept nothing
///
/// See <https://www.rfc-editor.org/rfc/rfc3376> (IGMPv3) and
/// <https://www.rfc-editor.org/rfc/rfc3810> (MLDv2).
fn write_source_filter(
    t: &mut impl Write,
    filter: &SourceFilter,
) -> std::io::Result<()> {
    let mode = match filter.mode {
        FilterMode::Include => "INCLUDE",
        FilterMode::Exclude => "EXCLUDE",
    };
    if filter.sources.is_empty() {
        if matches!(filter.mode, FilterMode::Exclude) {
            write!(t, "{mode}() (any)")
        } else {
            write!(t, "{mode}() (none)")
        }
    } else {
        write!(t, "{mode}(")?;
        let mut first = true;
        for source in &filter.sources {
            if !first {
                write!(t, ", ")?;
            }
            write!(t, "{source}")?;
            first = false;
        }
        write!(t, ")")
    }
}

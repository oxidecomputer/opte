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
use opte::api::IpCidr;
use opte::engine::geneve::Vni;
use opte::engine::print::*;
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

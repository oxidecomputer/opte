// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Utility functions to allow a port to permit traffic on an
//! additional set of CIDR blocks, e.g. to enable transit for
//! VPC-wide VPN traffic.

use super::*;
use crate::api::RemoveCidrResp;
use crate::engine::VpcNetwork;
use opte::api::IpCidr;
use opte::api::NoResp;
use opte::engine::port::Port;
use opte::engine::rule::Finalized;

fn make_holepunch_rule(
    guest_mac: MacAddr,
    gateway_mac: MacAddr,
    dest: IpCidr,
    dir: Direction,
    vpc_mappings: Arc<VpcMappings>,
) -> Rule<Finalized> {
    let (cidr_in_pred, cidr_out_pred) = match dest {
        IpCidr::Ip4(v4) => (
            Predicate::InnerDstIp4(vec![Ipv4AddrMatch::Prefix(v4)]),
            Predicate::InnerSrcIp4(vec![Ipv4AddrMatch::Prefix(v4)]),
        ),
        IpCidr::Ip6(v6) => (
            Predicate::InnerDstIp6(vec![Ipv6AddrMatch::Prefix(v6)]),
            Predicate::InnerSrcIp6(vec![Ipv6AddrMatch::Prefix(v6)]),
        ),
    };

    match dir {
        Direction::In => {
            let mut cidr_in = Rule::new(
                1000,
                Action::Static(Arc::new(RewriteSrcMac { gateway_mac })),
            );
            cidr_in.add_predicate(cidr_in_pred);
            cidr_in.add_predicate(Predicate::InnerEtherDst(vec![
                EtherAddrMatch::Exact(guest_mac),
            ]));

            cidr_in.finalize()
        }
        Direction::Out => {
            let vpc_meta = Arc::new(VpcMeta::new(vpc_mappings));
            let mut cidr_out = Rule::new(1000, Action::Meta(vpc_meta));
            cidr_out.add_predicate(Predicate::InnerEtherSrc(vec![
                EtherAddrMatch::Exact(guest_mac),
            ]));
            cidr_out.add_predicate(cidr_out_pred);

            cidr_out.finalize()
        }
    }
}

/// Allows a guest to send or receive traffic on a CIDR block
/// other than their private IP.
pub fn allow_cidr(
    port: &Port<VpcNetwork>,
    dest: IpCidr,
    dir: Direction,
    vpc_mappings: Arc<VpcMappings>,
) -> Result<NoResp, OpteError> {
    let rule = make_holepunch_rule(
        port.mac_addr(),
        port.network().cfg.gateway_mac,
        dest,
        dir,
        vpc_mappings,
    );
    port.add_rule(NAME, dir, rule)?;
    Ok(NoResp::default())
}

/// Prevents a guest from sending/receiving traffic on a CIDR block
/// other than their private IP.
pub fn remove_cidr(
    port: &Port<VpcNetwork>,
    dest: IpCidr,
    dir: Direction,
    vpc_mappings: Arc<VpcMappings>,
) -> Result<RemoveCidrResp, OpteError> {
    let rule = make_holepunch_rule(
        port.mac_addr(),
        port.network().cfg.gateway_mac,
        dest,
        dir,
        vpc_mappings,
    );

    let maybe_id = port.find_rule(NAME, dir, &rule)?;
    if let Some(id) = maybe_id {
        port.remove_rule(NAME, dir, id)?;
    }

    Ok(if maybe_id.is_none() {
        RemoveCidrResp::NotFound
    } else {
        RemoveCidrResp::Ok
    })
}

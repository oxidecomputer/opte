// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Utility functions to allow a port to permit traffic on an
//! additional set of CIDR blocks, e.g. to enable transit for
//! VPC-wide VPN traffic.

use super::*;
use crate::api::RemoveCidrResp;
use crate::cfg::IpCfg;
use crate::engine::VpcNetwork;
use alloc::collections::btree_map::Entry;
use opte::api::IpCidr;
use opte::api::NoResp;
use opte::engine::port::Port;
use opte::engine::rule::Finalized;

pub(super) fn make_holepunch_rule(
    guest_mac: MacAddr,
    gateway_mac: MacAddr,
    dest: IpCidr,
    dir: Direction,
    vpc_meta: &Arc<VpcMeta>,
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
            let mut cidr_out = Rule::new(1000, Action::Meta(vpc_meta.clone()));
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
    modify_cidr(port, dest, dir, vpc_mappings, true).map(|_| NoResp::default())
}

/// Prevents a guest from sending/receiving traffic on a CIDR block
/// other than their private IP.
pub fn remove_cidr(
    port: &Port<VpcNetwork>,
    dest: IpCidr,
    dir: Direction,
    vpc_mappings: Arc<VpcMappings>,
) -> Result<RemoveCidrResp, OpteError> {
    modify_cidr(port, dest, dir, vpc_mappings, false).map(|changed| {
        if changed {
            RemoveCidrResp::Ok(dest)
        } else {
            RemoveCidrResp::NotFound
        }
    })
}

fn modify_cidr(
    port: &Port<VpcNetwork>,
    dest: IpCidr,
    dir: Direction,
    vpc_mappings: Arc<VpcMappings>,
    allow: bool,
) -> Result<bool, OpteError> {
    let mut existing = false;
    let mut remove = false;

    match (&port.network().cfg.ip_cfg, dest) {
        (IpCfg::Ipv4(ipv4), IpCidr::Ip4(ipv4_cidr))
        | (IpCfg::DualStack { ipv4, .. }, IpCidr::Ip4(ipv4_cidr)) => {
            ipv4.transit_ips.update(|v| {
                let mut new = v.clone();
                let el = new.entry(ipv4_cidr);
                existing = matches!(el, Entry::Occupied(_));
                if allow || existing {
                    let el = el.or_default();
                    match dir {
                        Direction::In => el.allow_in = allow,
                        Direction::Out => el.allow_out = allow,
                    }
                    remove = !allow && !el.allow_in && !el.allow_out;
                }
                if remove {
                    new.remove(&ipv4_cidr);
                }
                Some(new)
            });
        }
        (IpCfg::Ipv6(ipv6), IpCidr::Ip6(ipv6_cidr))
        | (IpCfg::DualStack { ipv6, .. }, IpCidr::Ip6(ipv6_cidr)) => {
            ipv6.transit_ips.update(|v| {
                let mut new = v.clone();
                let el = new.entry(ipv6_cidr);
                existing = matches!(el, Entry::Occupied(_));
                if allow || existing {
                    let el = el.or_default();
                    match dir {
                        Direction::In => el.allow_in = allow,
                        Direction::Out => el.allow_out = allow,
                    }
                    remove = !allow && !el.allow_in && !el.allow_out;
                }
                if remove {
                    new.remove(&ipv6_cidr);
                }
                Some(new)
            });
        }
        _ => return Err(OpteError::InvalidIpCfg),
    }

    super::set_gateway_rules(port, vpc_mappings)?;

    Ok(existing)
}

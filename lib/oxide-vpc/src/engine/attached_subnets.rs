// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use super::VpcNetwork;
use super::overlay::VpcMappings;
use crate::api::AttachSubnetReq;
use crate::api::DetachSubnetReq;
use crate::api::DetachSubnetResp;
use crate::api::InternetGatewayMap;
use crate::cfg::IpCfg;
use alloc::sync::Arc;
use opte::api::IpCidr;
use opte::api::OpteError;
use opte::engine::port::Port;

pub fn attach_subnet(
    port: &Port<VpcNetwork>,
    inet_gw_map: Option<&InternetGatewayMap>,
    vpc_mappings: &Arc<VpcMappings>,
    req: AttachSubnetReq,
) -> Result<(), OpteError> {
    let cfg = &port.network().cfg;
    let changed = match (req.cidr, &cfg.ip_cfg) {
        (IpCidr::Ip4(v4), IpCfg::Ipv4(v4_cfg))
        | (IpCidr::Ip4(v4), IpCfg::DualStack { ipv4: v4_cfg, .. }) => {
            v4_cfg.attached_subnets.update(|map| {
                let install = if let Some(val) = map.get(&v4) {
                    val != &req.cfg
                } else {
                    true
                };
                install.then(|| {
                    let mut out = map.clone();
                    out.insert(v4, req.cfg);
                    out
                })
            })
        }
        (IpCidr::Ip6(v6), IpCfg::Ipv6(v6_cfg))
        | (IpCidr::Ip6(v6), IpCfg::DualStack { ipv6: v6_cfg, .. }) => {
            v6_cfg.attached_subnets.update(|map| {
                let install = if let Some(val) = map.get(&v6) {
                    val != &req.cfg
                } else {
                    true
                };
                install.then(|| {
                    let mut out = map.clone();
                    out.insert(v6, req.cfg);
                    out
                })
            })
        }
        // Trying to attach a CIDR class which this port cannot use.
        _ => return Err(OpteError::InvalidIpCfg),
    };

    if changed {
        super::nat::refresh_nat_rules(port, inet_gw_map)?;
        super::gateway::set_gateway_rules(port, vpc_mappings.clone())?;
    }

    Ok(())
}

pub fn detach_subnet(
    port: &Port<VpcNetwork>,
    inet_gw_map: Option<&InternetGatewayMap>,
    vpc_mappings: &Arc<VpcMappings>,
    req: DetachSubnetReq,
) -> Result<DetachSubnetResp, OpteError> {
    let cfg = &port.network().cfg;
    let changed = match (req.cidr, &cfg.ip_cfg) {
        (IpCidr::Ip4(v4), IpCfg::Ipv4(v4_cfg))
        | (IpCidr::Ip4(v4), IpCfg::DualStack { ipv4: v4_cfg, .. }) => {
            v4_cfg.attached_subnets.update(|map| {
                map.contains_key(&v4).then(|| {
                    let mut out = map.clone();
                    out.remove(&v4);
                    out
                })
            })
        }
        (IpCidr::Ip6(v6), IpCfg::Ipv6(v6_cfg))
        | (IpCidr::Ip6(v6), IpCfg::DualStack { ipv6: v6_cfg, .. }) => {
            v6_cfg.attached_subnets.update(|map| {
                map.contains_key(&v6).then(|| {
                    let mut out = map.clone();
                    out.remove(&v6);
                    out
                })
            })
        }
        // Trying to attach a CIDR class which this port cannot use.
        _ => return Err(OpteError::InvalidIpCfg),
    };

    if changed {
        super::nat::refresh_nat_rules(port, inet_gw_map)?;
        super::gateway::set_gateway_rules(port, vpc_mappings.clone())?;
    }

    Ok(if !changed {
        DetachSubnetResp::NotFound
    } else {
        DetachSubnetResp::Ok(req.cidr)
    })
}

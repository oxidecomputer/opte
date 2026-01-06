// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! The ARP implementation of the Virtual Gateway.

use super::BuildCtx;
use opte::api::MacAddr;
use opte::api::OpteError;
use opte::engine::ether::ETHER_TYPE_ARP;
use opte::engine::predicate::EtherAddrMatch;
use opte::engine::predicate::EtherTypeMatch;
use opte::engine::predicate::Predicate;
use opte::engine::rule::Action;
use opte::engine::rule::Rule;

pub(crate) fn setup(ctx: &mut BuildCtx) -> Result<(), OpteError> {
    // ================================================================
    // Outbound ARP Request for Gateway, from Guest
    //
    // We need to respond to guest ARP requests so it may resolve the
    // gateway (OPTE) IP address.
    // ================================================================
    let mut rule = Rule::new(1, Action::HandlePacket);
    rule.add_predicates(vec![
        Predicate::InnerEtherType(vec![EtherTypeMatch::Exact(ETHER_TYPE_ARP)]),
        Predicate::InnerEtherDst(vec![EtherAddrMatch::Exact(
            MacAddr::BROADCAST,
        )]),
        Predicate::InnerEtherSrc(vec![EtherAddrMatch::Exact(
            ctx.cfg.guest_mac,
        )]),
    ]);
    ctx.out_rules.push(rule.finalize());

    Ok(())
}

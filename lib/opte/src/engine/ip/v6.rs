// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use ingot::ip::Ecn;
use ingot::ip::IpProtocol;
use ingot::ip::LowRentV6EhRepr;
use ingot::types::primitives::*;
use ingot::types::util::Repeated;
use ingot::Ingot;
use opte_api::Ipv6Addr;

#[derive(Debug, Clone, Ingot, Eq, PartialEq)]
#[ingot(impl_default)]
pub struct Ipv6 {
    #[ingot(default = "6")]
    pub version: u4,
    pub dscp: u6,
    #[ingot(is = "u2")]
    pub ecn: Ecn,
    pub flow_label: u20be,

    pub payload_len: u16be,
    #[ingot(is = "u8", next_layer)]
    pub next_header: IpProtocol,
    #[ingot(default = 128)]
    pub hop_limit: u8,

    #[ingot(is = "[u8; 16]", default = Ipv6Addr::ANY_ADDR)]
    pub source: Ipv6Addr,
    #[ingot(is = "[u8; 16]", default = Ipv6Addr::ANY_ADDR)]
    pub destination: Ipv6Addr,

    #[ingot(subparse(on_next_layer))]
    pub v6ext: Repeated<LowRentV6EhRepr>,
}

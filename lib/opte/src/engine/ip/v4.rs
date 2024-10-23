// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use crate::engine::checksum::Checksum;
use ingot::ip::Ecn;
use ingot::ip::IpProtocol;
use ingot::ip::Ipv4Flags;
use ingot::types::primitives::*;
use ingot::types::Emit;
use ingot::types::Header;
use ingot::types::Vec;
use ingot::Ingot;
use opte_api::Ipv4Addr;
use zerocopy::ByteSliceMut;
use zerocopy::IntoBytes;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct Ipv4 {
    #[ingot(default = 4)]
    pub version: u4,
    #[ingot(default = 5)]
    pub ihl: u4,
    pub dscp: u6,
    #[ingot(is = "u2")]
    pub ecn: Ecn,
    pub total_len: u16be,

    pub identification: u16be,
    #[ingot(is = "u3")]
    pub flags: Ipv4Flags,
    pub fragment_offset: u13be,

    #[ingot(default = 128)]
    pub hop_limit: u8,
    #[ingot(is = "u8", next_layer)]
    pub protocol: IpProtocol,
    pub checksum: u16be,

    #[ingot(is = "[u8; 4]", default = Ipv4Addr::ANY_ADDR)]
    pub source: Ipv4Addr,
    #[ingot(is = "[u8; 4]", default = Ipv4Addr::ANY_ADDR)]
    pub destination: Ipv4Addr,

    #[ingot(var_len = "(ihl * 4).saturating_sub(20)")]
    pub options: Vec<u8>,
}

impl Ipv4 {
    #[inline]
    pub fn compute_checksum(&mut self) {
        self.checksum = 0;

        let mut csum = Checksum::new();

        let mut bytes = [0u8; 56];
        self.emit_raw(&mut bytes[..]);
        csum.add_bytes(&bytes[..]);

        self.checksum = csum.finalize_for_ingot();
    }
}

impl<V: ByteSliceMut> ValidIpv4<V> {
    #[inline]
    pub fn compute_checksum(&mut self) {
        self.set_checksum(0);

        let mut csum = Checksum::new();

        csum.add_bytes(self.0.as_bytes());

        match &self.1 {
            Header::Repr(opts) => {
                csum.add_bytes(&*opts);
            }
            Header::Raw(opts) => {
                csum.add_bytes(&*opts);
            }
        }

        self.set_checksum(csum.finalize_for_ingot());
    }
}

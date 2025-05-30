// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

use crate::dev_map::DevMap;
use alloc::collections::btree_map::BTreeMap;
use alloc::collections::btree_set::BTreeSet;
use core::mem;
use opte::api::MacAddr;
use opte::api::Vni;
use opte::ddi::mblk::MsgBlk;
use opte::ddi::mblk::MsgBlkChain;

type Key = (u32, u64);

/// Eh.
pub struct Mailbox {
    boxen: BTreeMap<Key, MsgBlkChain>,
    have_packets: BTreeSet<Key>,
}

impl Default for Mailbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Mailbox {
    pub const fn new() -> Self {
        Self { boxen: BTreeMap::new(), have_packets: BTreeSet::new() }
    }

    pub fn sync(&mut self, devs: &DevMap) {
        self.have_packets.clear();
        self.boxen =
            devs.iter_keys().map(|k| (*k, MsgBlkChain::empty())).collect();
    }

    #[inline]
    pub fn deliver(&mut self, vni: Vni, mac: MacAddr, pkt: MsgBlk) {
        let key = (vni.as_u32(), mac_to_u64(mac));
        self.deliver_direct(key, pkt);
    }

    #[inline]
    pub fn deliver_direct(&mut self, key: Key, pkt: MsgBlk) {
        if let Some(chain) = self.boxen.get_mut(&key) {
            chain.append(pkt);
            self.have_packets.insert(key);
        }
    }

    #[inline]
    pub fn drain(&mut self) -> impl Iterator<Item = (Key, MsgBlkChain)> {
        let mut the_set = BTreeSet::new();
        mem::swap(&mut the_set, &mut self.have_packets);

        the_set.into_iter().map(|v| {
            let mut chain = MsgBlkChain::empty();
            let space = self.boxen.get_mut(&v).unwrap();
            mem::swap(&mut chain, space);
            (v, chain)
        })
    }
}

#[inline(always)]
fn mac_to_u64(val: MacAddr) -> u64 {
    let val = val.bytes();
    u64::from_be_bytes([0, 0, val[0], val[1], val[2], val[3], val[4], val[5]])
}

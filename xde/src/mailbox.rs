// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

use crate::dev_map::FastKey;
use alloc::collections::btree_map::BTreeMap;
use core::mem;
use opte::api::MacAddr;
use opte::api::Vni;
use opte::ddi::mblk::MsgBlk;
use opte::ddi::mblk::MsgBlkChain;

/// Eh.
pub struct Mailbox {
    boxen: BTreeMap<FastKey, MsgBlkChain>,
}

impl Default for Mailbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Mailbox {
    pub const fn new() -> Self {
        Self { boxen: BTreeMap::new() }
    }

    #[inline]
    pub fn post(&mut self, vni: Vni, mac: MacAddr, pkt: MsgBlk) {
        let key = FastKey::new(vni, mac);
        self.post_by_key(key, pkt);
    }

    #[inline]
    pub fn post_by_key(&mut self, key: FastKey, pkt: MsgBlk) {
        let chain =
            self.boxen.entry(key).or_insert_with(|| MsgBlkChain::empty());
        chain.append(pkt);
    }

    #[inline]
    pub fn drain(&mut self) -> impl Iterator<Item = (FastKey, MsgBlkChain)> {
        let mut the_set = BTreeMap::new();
        mem::swap(&mut the_set, &mut self.boxen);
        the_set.into_iter()
    }
}

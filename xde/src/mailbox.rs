// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

use crate::dev_map::FastKey;
use alloc::collections::btree_map::BTreeMap;
use core::mem;
use core::ptr::NonNull;
use opte::api::MacAddr;
use opte::api::Vni;
use opte::ddi::mblk::MsgBlk;
use opte::ddi::mblk::MsgBlkChain;

/// Eh.
pub struct Mailbox {
    boxen: BTreeMap<FastKey, MsgBlkChain>,
    // Avoid any lookup on adjacent runs of packets hitting a single port.
    last_caller: Option<(FastKey, NonNull<MsgBlkChain>)>,
}

impl Default for Mailbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Mailbox {
    pub const fn new() -> Self {
        Self { boxen: BTreeMap::new(), last_caller: None }
    }

    #[inline]
    pub fn post(&mut self, vni: Vni, mac: MacAddr, pkt: MsgBlk) {
        let key = FastKey::new(vni, mac);
        self.post_by_key(key, pkt);
    }

    #[inline]
    pub fn post_by_key(&mut self, key: FastKey, pkt: MsgBlk) {
        let chain = if let Some((stored_key, mut chain_ptr)) = self.last_caller
            && stored_key == key
        {
            // SAFETY: We have a guarantee that the pointer is not aliased
            // by holding `&mut self` -- this would invalidate any `&mut`s we
            // might return.
            // We know the pointer remains valid because:
            // a) any inserts which could change the structure of `boxen`
            //    unconditionally update this pointer after the insert is made
            //    (they've used a different chain).
            // b) chain pkt append will not add a new `MsgBlkChain` to `boxen`.
            // c) `drain` (the only public way to remove entries from `boxen`)
            //    sets `last_caller` to `None`.
            unsafe { chain_ptr.as_mut() }
        } else {
            let chain =
                self.boxen.entry(key).or_insert_with(|| MsgBlkChain::empty());
            self.last_caller = Some((key, chain.into()));
            chain
        };

        chain.append(pkt);
    }

    #[inline]
    pub fn drain(&mut self) -> impl Iterator<Item = (FastKey, MsgBlkChain)> {
        let mut the_set = BTreeMap::new();
        mem::swap(&mut the_set, &mut self.boxen);
        self.last_caller = None;
        the_set.into_iter()
    }
}

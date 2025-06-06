// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

use crate::dev_map::FastKey;
use alloc::collections::btree_map::BTreeMap;
use core::mem;
use core::num::NonZeroUsize;
use core::ptr::NonNull;
use opte::ddi::mblk::MsgBlk;
use opte::ddi::mblk::MsgBlkChain;

/// Temporary storage to collect and transmit packets bound for the same
/// destination in a single batch.
pub struct Postbox {
    boxen: BTreeMap<FastKey, MsgBlkChain>,
    // Avoid any lookup on adjacent runs of packets hitting a single port.
    last_caller: Option<(FastKey, NonNull<MsgBlkChain>)>,
}

impl Default for Postbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Postbox {
    pub const fn new() -> Self {
        Self { boxen: BTreeMap::new(), last_caller: None }
    }

    /// Append the given `pkt` to the given
    #[inline]
    pub fn post(&mut self, key: FastKey, pkt: MsgBlk) {
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
                self.boxen.entry(key).or_insert_with(MsgBlkChain::empty);
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

/// A [`Postbox`] with dedicated storage for the underlay ports.
pub struct TxPostbox {
    local_ports: Postbox,
    underlay: [UnderlayChain; 2],
}

impl TxPostbox {
    pub const fn new() -> Self {
        Self {
            local_ports: Postbox::new(),
            underlay: [UnderlayChain::new(), UnderlayChain::new()],
        }
    }

    #[inline]
    pub fn post_local(&mut self, key: FastKey, pkt: MsgBlk) {
        self.local_ports.post(key, pkt);
    }

    #[inline]
    pub fn postbox(&mut self) -> &mut Postbox {
        &mut self.local_ports
    }

    #[inline]
    pub fn post_underlay(
        &mut self,
        idx: usize,
        hint: Option<NonZeroUsize>,
        pkt: MsgBlk,
    ) {
        let chain = &mut self.underlay[idx];
        let was_empty = chain.msgs.is_empty();
        chain.msgs.append(pkt);

        if was_empty {
            chain.last_hint = hint;
        } else if hint != chain.last_hint {
            chain.last_hint = None;
        }
    }

    #[inline]
    pub fn drain_underlay(&mut self, idx: usize) -> Option<UnderlayChain> {
        let chain = &mut self.underlay[idx];
        if chain.msgs.is_empty() {
            return None;
        }

        let mut out = UnderlayChain::new();
        mem::swap(chain, &mut out);

        Some(out)
    }
}

impl Default for TxPostbox {
    fn default() -> Self {
        Self::new()
    }
}

pub struct UnderlayChain {
    /// The message chain in question.
    pub msgs: MsgBlkChain,

    /// If we have a run of packets on one flow, MAC will honour this
    /// and put them all in the same Tx queue (and avoid recomputing
    /// the hash). Use this where we can.
    pub last_hint: Option<NonZeroUsize>,
}

impl UnderlayChain {
    const fn new() -> Self {
        Self { msgs: MsgBlkChain::empty(), last_hint: None }
    }
}

impl Default for UnderlayChain {
    fn default() -> Self {
        Self::new()
    }
}

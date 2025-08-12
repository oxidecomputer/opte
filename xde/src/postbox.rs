// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

use crate::dev_map::VniMac;
use crate::mac::TxHint;
use crate::xde::UnderlayIndex;
use alloc::collections::btree_map::BTreeMap;
use core::iter::FusedIterator;
use core::ptr::NonNull;
use opte::ddi::mblk::MsgBlk;
use opte::ddi::mblk::MsgBlkChain;

/// Temporary storage to collect and transmit packets bound for the same
/// destination in a single batch.
pub struct Postbox {
    boxes: Boxes,
    // Avoid any lookup on adjacent runs of packets hitting a single port.
    last_caller: Option<(VniMac, NonNull<MsgBlkChain>)>,
}

impl Default for Postbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Postbox {
    pub const fn new() -> Self {
        Self { boxes: Boxes::None, last_caller: None }
    }

    /// Append the given `pkt` to a chain for delivery to `key`.
    #[inline]
    pub fn post(&mut self, key: VniMac, pkt: MsgBlk) {
        let chain = if let Some((stored_key, mut chain_ptr)) = self.last_caller
            && stored_key == key
        {
            // SAFETY: We have a guarantee that the pointer is not aliased
            // by holding `&mut self` -- this would invalidate any other
            // `&mut`s we might return.
            // We know the pointer remains valid because:
            // a) any inserts which *could* change the structure of `boxes`
            //    unconditionally update this pointer after the insert is made
            //    (even if an existing chain was selected).
            // b) chain pkt append will not add a new `MsgBlkChain` to `boxes`.
            // c) `drain` (the only public way to remove entries from `boxes`)
            //    sets `last_caller` to `None`.
            unsafe { chain_ptr.as_mut() }
        } else {
            let chain = self.boxes.get_chain(key);
            self.last_caller = Some((key, chain.into()));
            chain
        };

        chain.append(pkt);
    }

    #[inline]
    pub fn drain(self) -> impl Iterator<Item = (VniMac, MsgBlkChain)> {
        self.boxes.into_iter()
    }
}

// SAFETY: The only `!Send`/`!Sync` element in here is the `NonNull<...>`.
// We never allow `&self` to use this mutably.
unsafe impl Send for Postbox {}
unsafe impl Sync for Postbox {}

/// Avoid any heap allocation when there is only one recipient in a
/// packet chain.
enum Boxes {
    None,
    One(VniMac, MsgBlkChain),
    Many(BTreeMap<VniMac, MsgBlkChain>),
}

impl Boxes {
    #[inline(always)]
    fn get_chain(&mut self, key: VniMac) -> &mut MsgBlkChain {
        // Need to check if we have an upgrade due first, due to borrowck.
        // E.g., can't return v from Self::One(k, v) early on.
        match self {
            Self::None => {
                *self = Self::One(key, MsgBlkChain::empty());
            }
            Self::One(k, ..) if *k != key => {
                let mut scratch = Self::Many(BTreeMap::new());
                core::mem::swap(&mut scratch, self);
                let Self::One(old_k, old_v) = scratch else { unreachable!() };
                let Self::Many(map) = self else { unreachable!() };
                map.insert(old_k, old_v);
            }
            _ => {}
        }

        match self {
            Self::One(_, v) => v,
            Self::Many(map) => {
                map.entry(key).or_insert_with(MsgBlkChain::empty)
            }
            _ => unreachable!(),
        }
    }
}

impl IntoIterator for Boxes {
    type Item = (VniMac, MsgBlkChain);

    type IntoIter = BoxIter;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Boxes::None => BoxIter::OneOrNone(None.into_iter()),
            Boxes::One(v, m) => BoxIter::OneOrNone(Some((v, m)).into_iter()),
            Boxes::Many(m) => BoxIter::Many(m.into_iter()),
        }
    }
}

enum BoxIter {
    OneOrNone(core::option::IntoIter<(VniMac, MsgBlkChain)>),
    Many(alloc::collections::btree_map::IntoIter<VniMac, MsgBlkChain>),
}

impl Iterator for BoxIter {
    type Item = (VniMac, MsgBlkChain);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::OneOrNone(v) => v.next(),
            Self::Many(v) => v.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::OneOrNone(v) => v.size_hint(),
            Self::Many(v) => v.size_hint(),
        }
    }
}

impl ExactSizeIterator for BoxIter {}
impl FusedIterator for BoxIter {}

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

    /// Append a `MsgBlk` to the chain of a local (loopback) port.
    #[inline]
    pub fn post_local(&mut self, key: VniMac, pkt: MsgBlk) {
        self.local_ports.post(key, pkt);
    }

    /// Append a `MsgBlk` to the chain of an underlay NIC.
    #[inline]
    pub fn post_underlay(
        &mut self,
        idx: UnderlayIndex,
        hint: TxHint,
        pkt: MsgBlk,
    ) {
        let chain = &mut self.underlay[idx as usize];
        let was_empty = chain.msgs.is_empty();
        chain.msgs.append(pkt);

        if was_empty {
            chain.last_hint = hint;
        } else if hint != chain.last_hint {
            chain.last_hint = TxHint::NoneOrMixed;
        }
    }

    /// Extract the message chain for underlay NIC `idx`.
    #[inline]
    pub fn deconstruct(self) -> (Postbox, [UnderlayChain; 2]) {
        (self.local_ports, self.underlay)
    }
}

impl Default for TxPostbox {
    fn default() -> Self {
        Self::new()
    }
}

/// A `MsgBlkChain` with a shared fanout hint.
pub struct UnderlayChain {
    /// The message chain in question.
    pub msgs: MsgBlkChain,

    /// If we have a run of packets on one flow, MAC will honour this
    /// and put them all in the same Tx queue (and avoid recomputing
    /// the hash). Use this where we can.
    pub last_hint: TxHint,
}

impl UnderlayChain {
    const fn new() -> Self {
        Self { msgs: MsgBlkChain::empty(), last_hint: TxHint::NoneOrMixed }
    }
}

impl Default for UnderlayChain {
    fn default() -> Self {
        Self::new()
    }
}

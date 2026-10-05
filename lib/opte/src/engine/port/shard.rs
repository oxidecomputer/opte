// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Utilities for flow tables sharded using the flow key.

use crate::api::InnerFlowId;
use crate::ddi::sync::KRwLock;
use crate::ddi::time::Moment;
use crate::engine::flow_table::ExpiryPolicy;
use crate::engine::flow_table::FlowState;
use crate::engine::flow_table::FlowTable;
use crate::engine::flow_table::FlowTableDump;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use c8str::C8Str;
use core::hash::BuildHasher;
use core::hash::Hash;
use core::num::NonZeroU16;
use core::num::NonZeroU32;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use rustc_hash::FxSeededState;

// struct CacheAligned<T: Sized> {
//     t: T,
//     pad: [u8; T::SI mem::sizeof::<T>()],
// }

pub(super) struct ShardedTable<S: FlowState> {
    hasher: FxSeededState,

    capacity: NonZeroU32,
    usage: AtomicUsize,

    // TODO cache align/pad contents?
    // For now just separate allocs.
    maps: Vec<Box<KRwLock<FlowTable<S>>>>,
}

impl<S: FlowState> ShardedTable<S> {
    pub fn new(
        port: &Arc<C8Str>,
        name: &str,
        limit: NonZeroU32,
        policy: Option<Arc<dyn ExpiryPolicy<S>>>,
        fanout: NonZeroU16,
    ) -> Self {
        let maps = (0..fanout.get())
            .map(|_| {
                KRwLock::new(FlowTable::new(
                    Arc::clone(port),
                    name,
                    limit,
                    None,
                ))
                .into()
            })
            .collect();

        Self {
            // TODO: ask rng.
            hasher: FxSeededState::with_seed(0),
            maps,
            capacity: limit,
            usage: 0.into(),
        }
    }

    pub fn get_shard(&self, key: &InnerFlowId) -> &KRwLock<FlowTable<S>> {
        let hash = self.hasher.hash_one(key) as usize;

        self.maps.get(hash % self.maps.len()).unwrap()
    }

    pub fn can_i_make_a_flow(&self) -> Result<(), ()> {
        let capacity = usize::try_from(self.capacity.get()).unwrap();
        self.usage
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |before| {
                (before < capacity).then_some(before + 1)
            })
            .map_err(|_| ())
            .map(|_| ())
    }

    pub fn free_up(&self, n: usize) {
        self.usage.fetch_sub(n, Ordering::Relaxed);
    }

    pub fn iter(&self) -> impl Iterator<Item = &KRwLock<FlowTable<S>>> {
        self.maps.iter().map(|v| v.as_ref())
    }

    pub fn clear(&self) {
        for el in &self.maps {
            let mut el = el.write();
            let n = el.num_flows();
            el.clear();
            self.free_up(n as usize);
        }
    }

    pub fn get_limit(&self) -> NonZeroU32 {
        self.capacity
    }

    pub fn dump(&self) -> FlowTableDump<S::DumpVal> {
        self.maps.iter().map(|v| v.read().dump()).flatten().collect()
    }

    pub fn num_flows(&self) -> u32 {
        u32::try_from(self.usage.load(Ordering::Relaxed)).unwrap_or(u32::MAX)
    }

    pub fn expire_flows(&self, now: Moment) {
        for el in &self.maps {
            let mut el = el.write();
            let n = el.num_flows();
            el.expire_flows(now);
            let n_2 = el.num_flows();
            self.free_up(n.saturating_sub(n_2) as usize);
        }
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! The flow table implementation.
//!
//! This provides the underlying implementation for the various flow
//! tables: UFT, LFT, and the TCP Flow Table.

use super::packet::InnerFlowId;
use crate::ddi::sync::KRwLock;
use crate::ddi::time::MILLIS;
use crate::ddi::time::Moment;
use crate::engine::layer::LayerError;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::collections::btree_map::Entry;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;
use c8str::C8Str;
use core::ffi::CStr;
use core::fmt;
use core::num::NonZeroU16;
use core::num::NonZeroU32;
use core::ops::ControlFlow;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
#[cfg(all(not(feature = "std"), not(test)))]
use illumos_sys_hdrs::uintptr_t;
use itertools::Either;
#[cfg(any(feature = "test-help", test))]
use opte_api::Direction;
use serde::Serialize;
use serde::de::DeserializeOwned;

// XXX This really shouldn't be pub but for now we are leaking this
// info for the purpose of testing until the Port API has support for
// setting/getting TTL on a per Flow Table basis.
pub const FLOW_DEF_EXPIRE_SECS: u64 = 60;
pub const FLOW_DEF_TTL: Ttl = Ttl::new_seconds(FLOW_DEF_EXPIRE_SECS);

pub const FLOW_TABLE_DEF_MAX_ENTRIES: u32 = 8192;

/// The Time To Live in milliseconds.
#[derive(Clone, Copy, Debug)]
pub struct Ttl(u64);

impl Ttl {
    pub fn as_seconds(&self) -> u64 {
        self.0 / 1_000
    }

    pub fn as_milliseconds(&self) -> u64 {
        self.0
    }

    /// Is `last_hit` expired?
    pub fn is_expired(&self, last_hit: Moment, now: Moment) -> bool {
        now.delta_as_millis(last_hit) >= self.0
    }

    /// Create a new TTL based on seconds.
    pub const fn new_seconds(seconds: u64) -> Self {
        Ttl(seconds * MILLIS)
    }
}

/// An eviction policy table which makes TCP flow entries without live flowstate
/// parents trivially evictable. When present, the TCP flow state will signal
/// a value to be used in its place.
#[derive(Clone, Copy, Debug)]
pub(super) struct TtlDelegateTcp(pub Ttl);

/// A metric of how stale a flow entry is, used to determine whether
/// any existing entry can be evicted to make room for a new one.
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Default)]
pub(super) enum EvictionPriority {
    /// The flow is not eligible for eviction.
    #[default]
    Protected,
    /// The flow entry may be evicted to make room for a new one.
    ///
    /// A numerically larger priority is more eligible for eviction.
    Evictable(NonZeroU16),
}

/// A policy for expiring flow table entries over time.
pub(super) trait ExpiryPolicy<S: FlowState>:
    fmt::Debug + Send + Sync
{
    /// Returns whether the given flow should be removed, given current flow
    /// state, the time a packet was last received, and the current time.
    fn is_expired(&self, entry: &FlowEntry<S>, now: Moment) -> bool;

    /// Returns whether a given flow can be evicted in favour of a new one
    /// prior to its expiry time.
    ///
    /// If so, this function will return `Some(priority)` -- a higher priority
    /// is more eligible to be evicted.
    fn eviction_priority(
        &self,
        entry: &FlowEntry<S>,
        now: Moment,
    ) -> Option<EvictionPriority>;
}

impl<S: FlowState> ExpiryPolicy<S> for Ttl {
    fn is_expired(&self, entry: &FlowEntry<S>, now: Moment) -> bool {
        self.is_expired(entry.last_hit(), now)
    }

    fn eviction_priority(
        &self,
        _entry: &FlowEntry<S>,
        _now: Moment,
    ) -> Option<EvictionPriority> {
        None
    }
}

impl<S: FlowState> ExpiryPolicy<S> for TtlDelegateTcp {
    fn is_expired(&self, entry: &FlowEntry<S>, now: Moment) -> bool {
        self.0.is_expired(entry.last_hit(), now)
    }

    fn eviction_priority(
        &self,
        entry: &FlowEntry<S>,
        _now: Moment,
    ) -> Option<EvictionPriority> {
        // TCP flows are expected to have a `TcpFlowEntryState` registered as
        // a child or ancestor. If present, this will reduce the eviction
        // priority to a level appropriate to how long the flow has been in its
        // current state. Otherwise we should assume the flow has closed and
        // that this entry is unneeded.
        //
        // Other flows in these tables have no additional context to suggest
        // that they are lingering too long in a given state.
        match entry.id().protocol() {
            opte_api::Protocol::TCP => {
                Some(EvictionPriority::Evictable(NonZeroU16::MAX))
            }
            _ => None,
        }
    }
}

/// Methods of a [`FlowEntry`] called on related flows across table boundaries.
///
/// This is only intended to be implemented by [`FlowEntry`], but must be a
/// trait as the state type parameter `S: `[`FlowState`] differs on a table by
/// table basis.
pub(super) trait FlowEntryInfo: fmt::Debug + Send + Sync {
    /// Set the last hit time on this entry to `new_time` if it is later
    /// than the stored value.
    fn inherit_last_hit(&self, new_time: Moment);

    /// Forcibly set the last hit time on this entry to `new_time`, when
    /// required by some tests/benchmarks.
    #[cfg(any(feature = "std", test))]
    fn inherit_last_hit_force(&self, new_time: Moment);

    /// Determine whether this flow entry can be evicted to make room for
    /// another, recursively checking all children when needed.
    fn eviction_priority(&self, now: Moment) -> Option<EvictionPriority>;

    /// Set `self` as a parent node to `child`.
    fn push_child(
        &self,
        child: &Arc<dyn FlowEntryInfo>,
    ) -> Result<(), FlowTableAddError>;

    /// Remove `child` from this entry's list of children.
    fn remove_child(&self, child: &Arc<dyn FlowEntryInfo>);

    /// Mark this flow entry, and all those which depend on it for validity,
    /// as being invalid.
    fn mark_dead(&self);

    /// Mark this flow entry as having completed slowpath processing, removing
    /// the existing hold and transitioning its state to `Ready`.
    fn mark_ready(&self);
}

impl<S: FlowState> FlowEntryInfo for FlowEntry<S> {
    fn inherit_last_hit(&self, new_time: Moment) {
        let new = new_time.raw();
        // An error from the below call implies a concurrent modification with
        // a time later than `new_time`. In that case there's just nothing left
        // to do here.
        _ = self.lifetime.last_hit.try_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |prior| (prior < new).then_some(new),
        );
    }

    #[cfg(any(feature = "std", test))]
    fn inherit_last_hit_force(&self, new_time: Moment) {
        self.lifetime.last_hit.store(new_time.raw(), Ordering::Relaxed);
    }

    fn eviction_priority(&self, now: Moment) -> Option<EvictionPriority> {
        let own_prio = self.policy.eviction_priority(self, now);

        // An explicit signal that this flow is well-behaved wins outright.
        if let Some(EvictionPriority::Protected) = own_prio {
            return own_prio;
        }

        // A priority of `None` tells us nothing, and will eventually resolve
        // into `EvictionPriority::Protected` if no explicit priorities are
        // provided.
        //
        // If we have an explicit priority, we keep the most-protected (lowest)
        // priority which we know of.
        let mut best_prio = own_prio;
        if self.lifetime.n_children.load(Ordering::Relaxed) > 0 {
            for maybe_child in &*self.lifetime.children.read() {
                if let Some(child) = maybe_child.0.upgrade() {
                    match (best_prio, child.eviction_priority(now)) {
                        (None, a) => best_prio = a,
                        (Some(_), None) => {}
                        (Some(old), Some(new)) => {
                            best_prio = Some(new.min(old))
                        }
                    }
                }
            }
        }

        best_prio
    }

    fn push_child(
        &self,
        child: &Arc<dyn FlowEntryInfo>,
    ) -> Result<(), FlowTableAddError> {
        let mut children = self.lifetime.children.write();

        // Sadly, BTreeSet::entry remains a nightly API.
        let to_place = ByAddr(Arc::downgrade(child));
        let can_insert =
            children.len() < Self::MAX_CHILDREN || children.contains(&to_place);
        if can_insert {
            children.insert(to_place);
            self.lifetime.n_children.store(children.len(), Ordering::Relaxed);
            Ok(())
        } else {
            Err(FlowTableAddError::MaxCapacity(
                u64::try_from(Self::MAX_CHILDREN).expect("usize is u64"),
            ))
        }
    }

    fn remove_child(&self, child: &Arc<dyn FlowEntryInfo>) {
        let mut children = self.lifetime.children.write();
        children.remove(&ByAddr(Arc::downgrade(child)));
        self.lifetime.n_children.store(children.len(), Ordering::Relaxed);
    }

    fn mark_dead(&self) {
        // Unwrap safety: all stored values must be valid `Liveness`.
        let old_state = Liveness::from(
            self.lifetime.state.swap(Liveness::Dead.into(), Ordering::Relaxed),
        );

        if old_state != Liveness::Dead {
            // Any flow entry is only valid while all of its parents still
            // exist. Timeout-driven expiry will not remove an entry while there
            // are still live parents, but during eviction we need to go through
            // and mark them as invalid in turn.
            for maybe_child in &*self.lifetime.children.read() {
                if let Some(child) = maybe_child.0.upgrade() {
                    child.mark_dead();
                }
            }
        }
    }

    fn mark_ready(&self) {
        self.lifetime.state.update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            let curr = Liveness::from(v);
            u8::from(curr.transition_to_ready().expect(
                "every increment should correspond to exactly one decrement",
            ))
        });
    }
}

pub type FlowTableDump<T> = Vec<(InnerFlowId, T)>;

/// Errors encountered when trying to add an element to a flow entry.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FlowTableAddError {
    /// There is no space in the table to contain a new entry. The table's
    /// capacity is returned.
    MaxCapacity(u64),
    /// An entry is already present in the table with the same key.
    Existing,
}

/// Errors encountered when trying to add an element to a flow entry.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FlowTableGetError {
    /// A `FlowEntry` has too many threads attempting to hold it parallel.
    LivenessFull,
}

impl From<FlowTableGetError> for LayerError {
    fn from(value: FlowTableGetError) -> Self {
        match value {
            FlowTableGetError::LivenessFull => LayerError::EntryTooBusy,
        }
    }
}

#[derive(Debug)]
pub(super) struct FlowTable<S: FlowState> {
    port: Arc<C8Str>,
    name_c: CString,
    limit: NonZeroU32,
    policy: Arc<dyn ExpiryPolicy<S>>,
    map: BTreeMap<InnerFlowId, Arc<FlowEntry<S>>>,

    // When looking up an eviction candidate, we cannot perform a whole table
    // scan. Ideally we would have a secondary candidate list maintained by
    // the periodic cleanup task. However, eviction priority policy is currently
    // too free-form for us to keep flow hashes in any way that would allow the
    // datapath to quickly find a global maximum. Sorting flows by timestamp
    // would *not* suffice for helping us find a better entry or a point to exit
    // early.
    //
    // For now, and in any future case where we have no valid entries in said
    // list, we want to examine a subset of `map` but don't want to keep
    // rechecking the first `n` entries. Whenever an entry is not `Protected`
    // but has a lower score than an element we end up evicting, we add it to
    // a small cache if there is space. This increases the odds of finding *a*
    // misbehaving flow.
    //
    // At present this is only extended during a partial scan from the datapath.
    // In future it will be more helpful for the periodic cleanup task to
    // provide better estimates here, but this would make its own full table scan
    // too expensive.
    eviction_cursor: Option<InnerFlowId>,
    evictable_cache: BTreeSet<InnerFlowId>,
}

impl<S: FlowState> FlowTable<S> {
    /// The maximum number of distinct entries that a single call to
    /// [`Self::find_evictable_entry`] will consider.
    const SCAN_BUDGET: usize = 2048;

    /// The maximum number of distinct entries that a single call to
    /// [`Self::find_evictable_entry`] will consider.
    const EVICTION_CACHE_MAX: usize = 512;

    /// Add a new entry to the flow table, returning a shared reference to
    /// the entry.
    ///
    /// # Errors
    ///
    /// If the table is at max capacity, an error is returned and no
    /// modification is made to the table.
    ///
    /// If an entry already exists for this flow, an error is returned
    /// if that flow is in a `Larval` or `Ready` state..
    pub fn add(
        &mut self,
        flow_id: InnerFlowId,
        state: S,
    ) -> Result<Arc<FlowEntry<S>>, FlowTableAddError> {
        self.check_for_space()?;
        let entry = Arc::new(FlowEntry::new(flow_id, state, self));
        match self.map.entry(flow_id) {
            Entry::Vacant(slot) => {
                slot.insert(Arc::clone(&entry));
                Ok(entry)
            }
            Entry::Occupied(slot) if slot.get().is_killed() => {
                *slot.into_mut() = Arc::clone(&entry);
                Ok(entry)
            }
            Entry::Occupied(_) => Err(FlowTableAddError::Existing),
        }
    }

    #[cfg(test)]
    /// Add a new entry to the flow table, unconditionally marking its
    /// lifecycle state as [`FlowStateLifecycle::Ready`].
    fn add_ready(
        &mut self,
        flow_id: InnerFlowId,
        state: S,
    ) -> Result<Arc<FlowEntry<S>>, FlowTableAddError> {
        self.add(flow_id, state).inspect(|v| v.mark_ready())
    }

    /// Add a new entry to the flow table while eliding the capacity check.
    ///
    /// This is meant for table implementations that enforce their own limit.
    pub fn add_unchecked(
        &mut self,
        flow_id: InnerFlowId,
        state: S,
    ) -> Arc<FlowEntry<S>> {
        let entry = Arc::new(FlowEntry::new(flow_id, state, self));
        self.map.insert(flow_id, Arc::clone(&entry));
        entry
    }

    /// Add a new entry to the flow table, assigning it the same lifetime as
    /// an existing entry in another table.
    ///
    /// As in [`Self::add_unchecked`], this elides the capacity check.
    pub fn add_unchecked_partner<T: FlowState>(
        &mut self,
        flow_id: InnerFlowId,
        state: S,
        partner: &FlowEntry<T>,
    ) -> Arc<FlowEntry<S>> {
        let mut entry = FlowEntry::new(flow_id, state, self);
        entry.lifetime = Arc::clone(&partner.lifetime);
        let entry = Arc::new(entry);
        self.map.insert(flow_id, Arc::clone(&entry));
        entry
    }

    // Clear all entries from the flow table.
    pub fn clear(&mut self) {
        core::mem::take(&mut self.map)
            .into_values()
            .for_each(|v| FlowEntry::on_remove(&v));
    }

    // Clear all entries from the flow table without explicitly marking
    // each entry as `Dead`.
    pub fn clear_raw(&mut self) {
        self.map.clear()
    }

    pub fn dump(&self) -> FlowTableDump<S::DumpVal> {
        let mut flows = Vec::with_capacity(self.map.len());
        for (flow_id, entry) in &self.map {
            flows.push((*flow_id, entry.dump()));
        }
        flows
    }

    /// Remove a flow from the flowtable, firing a flow expiry DTrace
    /// probe if successful.
    pub(crate) fn expire(&mut self, flowid: &InnerFlowId) {
        if let Some(el) = self.map.remove(flowid) {
            flow_expired_probe(
                self.port.as_c8_str(),
                &self.name_c,
                flowid,
                el.last_hit(),
                None,
            );
        }
    }

    fn expire_at(&mut self, flowid: &InnerFlowId, now: Moment) {
        if let Some(el) = self.map.remove(flowid) {
            flow_expired_probe(
                self.port.as_c8_str(),
                &self.name_c,
                flowid,
                el.last_hit(),
                Some(now),
            );
        }
    }

    /// Remove all flows from `self` which are past their expiry time.
    pub fn expire_flows(&mut self, now: Moment) {
        let name_c = &self.name_c;

        self.map.retain(|flowid, entry| {
            // If this element is in use by a current slow-path walk, we
            // need to leave it in place until the thread operating on it
            // determines that it's ready.
            let liveness = entry.liveness();
            if liveness.is_protected() {
                return true;
            }

            // A flow cannot be expired by the timer while it still has children
            // relying upon its existence. Check whether any remain, and remove
            // dangling references to child entries which have expired.
            //
            // The dangling entries here will have been left by `expire_flows`
            // called on other layers.
            {
                // Any contention here will come from evictions occurring
                // on a higher-level table: e.g., datapath evictions happening
                // in the UFT/TCP tables, while this operation occurs on an
                // LFT.
                let mut children = entry.lifetime.children.write();
                children.retain(|el| el.0.upgrade().is_some());
                entry
                    .lifetime
                    .n_children
                    .store(children.len(), Ordering::Relaxed);
                if !children.is_empty() {
                    return true;
                }
            }

            if liveness.is_dead() || entry.is_expired(now) {
                flow_expired_probe(
                    self.port.as_c8_str(),
                    name_c,
                    flowid,
                    entry.last_hit(),
                    Some(now),
                );
                FlowEntry::on_remove(entry);

                return false;
            }

            true
        });

        self.cleanup_eviction_cache(now);
    }

    /// Remove all flows from `self` which are past their expiry time,
    /// identifying the partner flow `extractor(&flow_state)` of each and
    /// removing it from `partner`.
    ///
    /// Flows identified by `extractor` in `partner` *MUST* share the same
    /// `FlowLifetime` as the entry removed from `self`.
    pub fn expire_flows_partner<F, T>(
        &mut self,
        partner: &mut FlowTable<T>,
        extractor: F,
        now: Moment,
    ) where
        F: Fn(&S) -> InnerFlowId,
        T: FlowState,
    {
        let name_c = &self.name_c;

        self.map.retain(|flowid, entry| {
            // If this element is in use by a current slow-path walk, we
            // need to leave it in place until the thread operating on it
            // determines that it's ready.
            let liveness = entry.liveness();
            if liveness.is_protected() {
                return true;
            }

            // A flow cannot be expired by the timer while it still has children
            // relying upon its existence. Check whether any remain, and remove
            // dangling references to child entries which have expired.
            //
            // The dangling entries here will have been left by `expire_flows`
            // called on other layers.
            {
                // Any contention here will come from evictions occurring
                // on a higher-level table: e.g., datapath evictions happening
                // in the UFT/TCP tables, while this operation occurs on an
                // LFT.
                let mut children = entry.lifetime.children.write();
                children.retain(|el| el.0.upgrade().is_some());
                entry
                    .lifetime
                    .n_children
                    .store(children.len(), Ordering::Relaxed);
                if !children.is_empty() {
                    return true;
                }
            }

            if liveness.is_dead() || entry.is_expired(now) {
                flow_expired_probe(
                    self.port.as_c8_str(),
                    name_c,
                    flowid,
                    entry.last_hit(),
                    Some(now),
                );
                FlowEntry::on_remove(entry);

                // The partner flow is guaranteed to have the same lifetime.
                // Accordingly, we don't need to call `on_remove` against it.
                let partner_flow = extractor(entry.state());
                #[cfg(debug_assertions)]
                {
                    if let Some(other) = partner.map.get(&partner_flow) {
                        assert!(Arc::ptr_eq(&entry.lifetime, &other.lifetime))
                    }
                }
                partner.expire_at(&partner_flow, now);

                return false;
            }

            true
        });

        self.cleanup_eviction_cache(now);
    }

    /// Remove any elements from `self.eviction_cache` which have become
    /// `Protected` or stale.
    fn cleanup_eviction_cache(&mut self, now: Moment) {
        self.evictable_cache.retain(|id| match self.map.get(id) {
            Some(v) => match v.eviction_priority(now) {
                None | Some(EvictionPriority::Protected) => false,
                Some(_) => true,
            },
            None => false,
        });
    }

    /// Determine whether there is currently space for a new entry to be
    /// inserted.
    ///
    /// If out of space, this method will attempt to evict an existing entry.
    pub fn check_for_space(&mut self) -> Result<(), FlowTableAddError> {
        if self.map.len() < self.limit.get() as usize {
            return Ok(());
        }

        if let Some((key, _)) = self.find_evictable_entry() {
            self.expire(&key);
            Ok(())
        } else {
            Err(FlowTableAddError::MaxCapacity(self.limit.get() as u64))
        }
    }

    /// Select the flow entry most eligible for eviction (i.e., having the
    /// numerically highest priority and the oldest timestamp).
    ///
    /// Entries which have been killed due to the loss of a dependency will be
    /// used where possible.
    pub fn find_evictable_entry(
        &mut self,
    ) -> Option<(InnerFlowId, &FlowEntry<S>)> {
        let now = Moment::now();

        // The datastructures here help find at least one evictable entry, from
        // which we select the best we know of. We cache the keys of any flows
        // which were misbehaving in some way, expecting that these are liable
        // to *keep* misbehaving for subsequent packets and to become worse over
        // time.
        //
        // Finding the best (table-wide) in a limited number of operations is
        // currently infeasible with how eviction scoring is designed.
        let to_scan = self.map.len().min(Self::SCAN_BUDGET);

        let mut to_evict = None;
        let mut visited = 0;

        // First, check our cache of entries which had *an* eviction score, and
        // store a reference to the most eligible. While doing so, clean out any
        // entries which are unevictable, or are dead references.
        self.evictable_cache.retain(|id| match self.map.get(id) {
            Some(entry) => {
                visited += 1;
                match update_eviction_incumbent(
                    id,
                    entry,
                    None,
                    &mut to_evict,
                    now,
                ) {
                    // Sadly, there's no retain_until method, so we can't leave
                    // the cache scan early if we encounter `Break`. If there are
                    // several such entries, then leaving them in place *will*
                    // help subsequent packets.
                    ControlFlow::Continue(EvictionPriority::Protected) => false,
                    _ => true,
                }
            }
            None => false,
        });

        let done =
            matches!(to_evict, Some(Candidate { key: EvictionKey::Dead, .. }));

        while !done && visited < to_scan {
            let map = if let Some(from) = self.eviction_cursor.take() {
                Either::Left(self.map.range(from..))
            } else {
                Either::Right(self.map.iter())
            };

            for (key, entry) in map {
                // Note: we can't use .take() on map because we need to discover
                // the flow ID we'll be starting with on the next scan.
                if visited >= to_scan {
                    self.eviction_cursor = Some(*key);
                    break;
                }
                visited += 1;

                if let ControlFlow::Break(_) = update_eviction_incumbent(
                    key,
                    entry,
                    Some(&mut self.evictable_cache),
                    &mut to_evict,
                    now,
                ) {
                    break;
                }
            }
        }

        to_evict.map(|Candidate { id, entry, source, .. }| {
            match source {
                EvictionSource::Table => self.eviction_cursor = Some(id),
                EvictionSource::Cache => _ = self.evictable_cache.remove(&id),
            }
            (id, entry.as_ref())
        })
    }

    /// Get the maximum number of entries this flow table may hold.
    pub fn get_limit(&self) -> NonZeroU32 {
        self.limit
    }

    /// Get a reference to the flow entry for a given flow, if one exists.
    ///
    /// This method will return flows even if they are `Dead`.
    pub fn get(&self, flow_id: &InnerFlowId) -> Option<&Arc<FlowEntry<S>>> {
        self.map.get(flow_id)
    }

    /// Get a reference to the flow entry for a given flow, if one exists,
    /// incrementing its hold count while doing so.
    ///
    /// This method will return `Ok(None)` if an entry is marked as dead, and
    /// will only return an error if the flow has too many parallel holds.
    /// Callers which want to see and handle `Dead` entries  should combine
    /// [`Self::get`] with [`FlowEntry::is_killed`].
    pub fn get_and_hold(
        &self,
        flow_id: &InnerFlowId,
    ) -> Result<Option<&Arc<FlowEntry<S>>>, FlowTableGetError> {
        match self.get(flow_id).map(|v| v.add_hold().map(|_| v)) {
            Some(Ok(v)) => Ok(Some(v)),
            Some(Err(HoldIncrementError::LivenessFull)) => {
                Err(FlowTableGetError::LivenessFull)
            }
            None | Some(Err(HoldIncrementError::Dead)) => Ok(None),
        }
    }

    /// Mark all flow table entries as requiring revalidation after a
    /// reset or removal of rules.
    ///
    /// It is typically cheaper to use [`FlowTable::clear`]; dirty entries
    /// will occupy flowtable space until they are denied or expire. As such
    /// this method should be used only when the original state (`S`) *must*
    /// be preserved to ensure correctness.
    pub fn mark_dirty(&self) {
        self.map.values().for_each(|v| v.set_dirty());
    }

    pub fn new(
        port: Arc<C8Str>,
        name: &str,
        limit: NonZeroU32,
        policy: Option<Arc<dyn ExpiryPolicy<S>>>,
    ) -> FlowTable<S> {
        let policy = policy.unwrap_or_else(|| Arc::new(FLOW_DEF_TTL));

        Self {
            port,
            name_c: CString::new(name).unwrap(),
            limit,
            policy,
            map: BTreeMap::new(),
            eviction_cursor: None,
            evictable_cache: BTreeSet::new(),
        }
    }

    /// Get the number of flows in this table.
    pub fn num_flows(&self) -> u32 {
        self.map.len() as u32
    }

    /// Remove an entry from this table using a given key, `flow`.
    pub fn remove(&mut self, flow: &InnerFlowId) -> Option<Arc<FlowEntry<S>>> {
        self.map.remove(flow).inspect(FlowEntry::on_remove)
    }

    /// Remove an entry from this table using a given key, `flow` if it
    /// satisfies a given predicate `f`.
    pub fn remove_if(
        &mut self,
        flow: InnerFlowId,
        f: impl FnOnce(&FlowEntry<S>) -> bool,
    ) -> Option<Arc<FlowEntry<S>>> {
        match self.map.entry(flow) {
            Entry::Occupied(v) if f(v.get()) => {
                FlowEntry::on_remove(v.get());
                Some(v.remove())
            }
            _ => None,
        }
    }

    #[cfg(any(feature = "std", test))]
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (&InnerFlowId, &Arc<FlowEntry<S>>)> {
        self.map.iter()
    }
}

fn flow_expired_probe(
    port: &C8Str,
    name: &CStr,
    flowid: &InnerFlowId,
    last_hit: Moment,
    now: Option<Moment>,
) {
    let now = now.unwrap_or_default().raw_millis();
    let last_hit = last_hit.raw_millis();
    cfg_if! {
        if #[cfg(all(not(feature = "std"), not(test)))] {
            __dtrace_probe_flow__expired(
                port.as_ptr() as uintptr_t,
                name.as_ptr() as uintptr_t,
                flowid,
                last_hit,
                now,
            );
        } else if #[cfg(feature = "usdt")] {
            use std::string::ToString;
            let port_s = port.to_str();
            let name_s = name.to_str().unwrap();
            crate::opte_provider::flow__expired!(
                || (port_s, name_s, flowid.to_string(), last_hit, now)
            );
        } else {
            _ = (port, name, flowid, last_hit, now);
        }
    }
}

/// A type that can be "dumped" for the purposes of presenting an
/// external view into internal state of the `FlowEntry`.
pub trait Dump: fmt::Debug + Send + Sync {
    type DumpVal: DeserializeOwned + Serialize;

    fn dump(&self, hits: u64) -> Self::DumpVal;
}

/// Common functions needed from the interior state of a flow table entry.
pub(super) trait FlowState: Dump + 'static {
    /// Return an iterator containing references to all flow entries from other
    /// tables which underpin `self`.
    fn parents(&self) -> impl Iterator<Item = Arc<dyn FlowEntryInfo>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// The current lifecycle state of a flow entry.
///
/// This comprises a current state (larval, ready, or dead), and a number of
/// holds created from the slowpath which are currently using this entry. This
/// affects when flows can be used, removed, and evicted from the datpath and
/// cleanup contexts.
///
/// Flow entries are created in a `Larval` state with one hold. When
/// slowpath processing concludes, the flow is moved to `Ready` and this
/// hold is released. Existing LFTs, when acquired, will begin in a
/// `Ready` state and should take an additional hold.
///
/// A flow may transition:
///  * `Larval` -> `Ready`,
///  * `Larval` -> `Dead`,
///  * `Ready` -> `Dead`.
enum Liveness {
    /// This flow entry has been created but has not yet been finalised by
    /// a packet reaching the end of its processing. It is ineligible for
    /// eviction or expiry.
    ///
    /// This entry is eligible for removal at the end of slowpath processing if
    /// it has a single hold, and the packet encounters an error or is
    /// explicitly denied.
    Larval { holds: Holds },
    /// A packet using this flow entry has made it to the end of its processing
    /// and the flow is eligible for eviction and/or expiry if it has no holds.
    Ready { holds: Holds },
    /// This flow entry has been killed, either because one of its parents
    /// has been evicted or it has itself expired and been removed from the
    /// flow table.
    ///
    /// When detected, such flows should not be used,
    Dead,
}

impl Liveness {
    // This type's 3 states require 2 bits to represent the discriminant.
    // The remaining 6 contain the hold count.
    const MAX_HOLDS: u8 = u8::MAX >> 2;

    /// Return whether this flow is in a larval state.
    #[cfg(any(feature = "test-help", test))]
    fn is_larval(&self) -> bool {
        matches!(self, Self::Larval { .. })
    }

    /// Return whether this flow has been killed.
    fn is_dead(&self) -> bool {
        matches!(self, Self::Dead)
    }

    /// Return whether this flow has any active slowpath holds.
    #[cfg(any(feature = "test-help", test))]
    fn is_held(&self) -> bool {
        self.holds().is_some_and(|n| n > 0)
    }

    /// Return whether this flow is eligible for eviction/expiry.
    fn is_protected(&self) -> bool {
        match self {
            Self::Larval { .. } => true,
            Self::Ready { holds } => holds.get() >= 1,
            _ => false,
        }
    }

    /// Set the number of active slowpath holds.
    #[cfg(test)]
    fn with_holds(self, holds: Holds) -> Result<Self, HoldIncrementError> {
        match self {
            Liveness::Larval { .. } => Ok(Liveness::Larval { holds }),
            Liveness::Ready { .. } => Ok(Liveness::Ready { holds }),
            Liveness::Dead => Err(HoldIncrementError::Dead),
        }
    }

    /// Return the number of active slowpath holds.
    #[cfg(any(feature = "test-help", test))]
    fn holds(&self) -> Option<u8> {
        match self {
            Liveness::Larval { holds } => Some(holds.get()),
            Liveness::Ready { holds } => Some(holds.get()),
            Liveness::Dead => None,
        }
    }

    /// Increment the hold count on a state, returning the target state when
    /// this is a valid transition.
    fn increment_holds(mut self) -> Result<Self, HoldIncrementError> {
        let slot = match &mut self {
            Liveness::Larval { holds } => holds,
            Liveness::Ready { holds } => holds,
            Liveness::Dead => return Err(HoldIncrementError::Dead),
        };

        *slot = slot.increment()?;

        Ok(self)
    }

    /// Remove one hold from a flow state in a live or larval state, returning
    /// the target state this flow should have. Removing a hold from a dead flow
    /// is a NO-OP.
    ///
    /// Returns an error if the flow is alive and has no holds.
    fn decrement_holds(mut self) -> Result<Self, HoldDecrementError> {
        let slot = match &mut self {
            Liveness::Larval { holds } => holds,
            Liveness::Ready { holds } => holds,
            Liveness::Dead => return Ok(self),
        };

        *slot = slot.decrement()?;

        Ok(self)
    }

    /// Move this flow from a larval to ready state at the end of datapath
    /// processing, removing one hold in either state.
    ///
    /// Returns an error if the flow is alive and has no holds.
    fn transition_to_ready(self) -> Result<Self, HoldDecrementError> {
        match self {
            Liveness::Larval { holds } => Liveness::Ready { holds },
            val => val,
        }
        .decrement_holds()
    }
}

impl Default for Liveness {
    fn default() -> Self {
        Self::Larval { holds: Holds::ONE }
    }
}

/// Errors encountered by [`Liveness::increment_holds`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum HoldIncrementError {
    /// A `FlowEntry` has too many threads attempting to hold it parallel.
    LivenessFull,
    /// The entry has been moved to the `Dead` state by another thread.
    Dead,
}

/// Errors encountered by [`Liveness::increment_holds`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum HoldDecrementError {
    /// The flow entry is live and has no recorded holds.
    NoHolds,
}

impl From<u8> for Liveness {
    fn from(value: u8) -> Self {
        let tag = value & 0b11;
        let holds = Holds::new(value >> 2).expect("maximum is u8::MAX >> 2");

        match tag {
            0 => Self::Larval { holds },
            1 => Self::Ready { holds },
            2 => {
                // This is a purely internal type. If we have a non-zero hold
                // counter, we've made a serious programming error with our
                // atomic handling and cannot reason about a flow's state.
                assert_eq!(
                    holds.get(),
                    0,
                    "Dead flows cannot have holds, saw {holds:?}"
                );
                Self::Dead
            }
            v => unreachable!("illegal flowstate tag {v}"),
        }
    }
}

impl From<Liveness> for u8 {
    fn from(value: Liveness) -> u8 {
        let (tag, holds) = match value {
            Liveness::Larval { holds } => (0, holds.get()),
            Liveness::Ready { holds } => (1, holds.get()),
            Liveness::Dead => (2, 0),
        };

        if holds > Liveness::MAX_HOLDS {
            unreachable!("`Holds` ensures hold count is in-bounds")
        }

        holds << 2 | tag
    }
}

impl From<Liveness> for AtomicU8 {
    fn from(value: Liveness) -> Self {
        u8::from(value).into()
    }
}

/// Lifecycle state for a flow entry or set of interlinked flow entries.
struct FlowLifetime {
    /// This tracks the last time the flow was matched.
    ///
    /// These are raw u64s sourced from a `Moment`, which tracks time
    /// in nanoseconds.
    last_hit: AtomicU64,

    /// Whether this flow entry has been explicitly removed.
    ///
    /// Is a [`Liveness`].
    state: AtomicU8,

    /// An estimate of the number of elements in [`Self::children`], used
    /// to avoid locking and querying consistently empty elements.
    n_children: AtomicUsize,

    /// Entries in remote tables which rely on the continued existence of
    /// this flow.
    ///
    /// Child entries can also provide a flow with a measure of whether
    /// it is eligible for eviction.
    children: KRwLock<BTreeSet<ByAddr>>,
}

impl FlowLifetime {
    fn liveness(&self) -> Liveness {
        Liveness::from(self.state.load(Ordering::Relaxed))
    }
}

impl fmt::Debug for FlowLifetime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let FlowLifetime { last_hit, state, n_children, children: _ } = self;
        f.debug_struct("FlowEntry")
            .field("last_hit", last_hit)
            .field("state", &Liveness::from(state.load(Ordering::Relaxed)))
            .field("n_children", n_children)
            .field("children", &"<lock>")
            .finish()
    }
}

/// Helper newtype to deduplicate child flow entries by address.
struct ByAddr(Weak<dyn FlowEntryInfo>);

impl PartialEq for ByAddr {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::addr_eq(self.0.as_ptr(), other.0.as_ptr())
    }
}

impl Eq for ByAddr {}

impl Ord for ByAddr {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.as_ptr().cast::<()>().cmp(&other.0.as_ptr().cast::<()>())
    }
}

impl PartialOrd for ByAddr {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The FlowEntry holds any arbitrary state type `S`.
#[derive(Debug)]
pub(super) struct FlowEntry<S: FlowState> {
    /// The 5-tuple of this flow, used as the lookup key in the parent map.
    id: InnerFlowId,

    state: S,

    /// Number of times this flow has been matched.
    hits: AtomicU64,

    /// State determining whether this flow can be expired or evicted.
    lifetime: Arc<FlowLifetime>,

    /// Records whether this flow predates a rule change, and
    /// must rerun rule processing before `state` can be used.
    dirty: AtomicBool,

    policy: Arc<dyn ExpiryPolicy<S>>,
}

impl<S: FlowState> FlowEntry<S> {
    /// In OPTE, we generally expect at most three children per LFT entry: the
    /// in/out UFT entries and TCP entry. We can keep some extra space for now
    /// to allow for this to change in future, as well as to provide some
    /// breathing room if we need to replace one of those relationships.
    const MAX_CHILDREN: usize = 16;

    fn dump(&self) -> S::DumpVal {
        self.state.dump(self.hits.load(Ordering::Relaxed))
    }

    pub fn id(&self) -> &InnerFlowId {
        &self.id
    }

    pub fn state(&self) -> &S {
        &self.state
    }

    /// Increments this flow's hit counter and updates its timestamp to
    /// the current instant.
    pub fn hit(&self) {
        self.hit_at(Moment::now())
    }

    /// Increments this flow's hit counter and updates its timestamp to
    /// a given timestamp.
    ///
    /// This is used to minimise calls to `gethrtime` in fastpath
    /// operations. Callers *MUST* be certain that expiry logic for this flow
    /// entry uses saturating comparisons, particularly if timestamps are
    /// sourced before grabbing a lock / processing a packet / any other
    /// long-running operation. **This is doubly true if you are not holding
    /// the port lock.**
    pub(crate) fn hit_at(&self, now: Moment) {
        self.hits.fetch_add(1, Ordering::Relaxed);
        self.lifetime.last_hit.store(now.raw(), Ordering::Relaxed);
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Relaxed)
    }

    pub fn set_dirty(&self) {
        self.dirty.store(true, Ordering::Relaxed)
    }

    pub fn mark_clean(&self) {
        self.dirty.store(false, Ordering::Relaxed)
    }

    pub fn last_hit(&self) -> Moment {
        Moment::from_raw_nanos(self.lifetime.last_hit.load(Ordering::Relaxed))
    }

    fn liveness(&self) -> Liveness {
        self.lifetime.liveness()
    }

    /// Returns whether this flow entry has explicitly been marked as invalid
    /// (e.g., one of its ancestors has been evicted).
    pub(crate) fn is_killed(&self) -> bool {
        self.liveness() == Liveness::Dead
    }

    /// Returns whether this flow entry is past its policy's expiry time.
    fn is_expired(&self, now: Moment) -> bool {
        self.policy.is_expired(self, now)
    }

    /// Transition this flow entry's state to `Dead`, update the last hit time
    /// of its parents if it has been used more recently than they have, and
    /// remove any of their references to `self`.
    fn on_remove(self: &Arc<Self>) {
        self.mark_dead();

        let my_time = self.last_hit();
        let dyn_entry = Arc::clone(self) as Arc<dyn FlowEntryInfo>;
        for parent in self.state.parents() {
            parent.inherit_last_hit(my_time);
            parent.remove_child(&dyn_entry);
        }
    }

    fn new(id: InnerFlowId, state: S, in_table: &FlowTable<S>) -> Self {
        FlowEntry {
            id,
            state,
            hits: 0.into(),
            dirty: false.into(),
            policy: Arc::clone(&in_table.policy),
            lifetime: Arc::new(FlowLifetime {
                last_hit: Moment::now().raw().into(),
                state: Liveness::default().into(),
                n_children: 0.into(),
                children: KRwLock::new(BTreeSet::new()),
            }),
        }
    }

    /// Increments the slowpath hold counter on this flow entry. This prevents
    /// eviction of this flow entry by another attempted insertion, or removal
    /// of this entry by the periodic cleanup task.
    ///
    /// This function *should* be called with a read or write lock on the
    /// `FlowEntry`'s enclosing table to ensure that another thread cannot
    /// see it with a zeroed hold count in the table.
    pub(super) fn add_hold(&self) -> Result<(), HoldIncrementError> {
        let mut err = None;
        self.lifetime
            .state
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                let curr = Liveness::from(v);
                curr.increment_holds()
                    .inspect_err(|v| err = Some(*v))
                    .ok()
                    .map(Into::into)
            })
            .map_err(|_| {
                err.take().expect("err must have been set in `try_update`")
            })
            .map(|_| ())
    }

    /// Test helper for single-threaded execution to verify that this flow
    /// is `Ready` or `Dead` at the end of port processing.
    #[cfg(any(feature = "test-help", test))]
    pub(crate) fn verify_not_larval(
        &self,
        table: &str,
        key: &InnerFlowId,
        dir: Option<Direction>,
    ) {
        let dir_spec = match dir {
            None => "",
            Some(Direction::In) => " (In)",
            Some(Direction::Out) => " (Out)",
        };
        let liveness = self.liveness();
        if liveness.is_larval() || liveness.is_held() {
            panic!(
                "table {table}{dir_spec}: flow {key} was left in \
                unexpected state {liveness:?} after processing"
            );
        }
    }
}

pub trait StateSummary {
    fn summary(&self) -> String;
}

#[cfg(all(not(feature = "std"), not(test)))]
unsafe extern "C" {
    pub safe fn __dtrace_probe_flow__expired(
        port: uintptr_t,
        layer: uintptr_t,
        flowid: *const InnerFlowId,
        last_hit: u64,
        now: u64,
    );

    pub safe fn __dtrace_probe_ft__entry__invalidated(
        dir: uintptr_t,
        port: uintptr_t,
        layer: uintptr_t,
        ifid: *const InnerFlowId,
        epoch: uintptr_t,
    );
}

/// A score of how likely we are to evict a given flow.
#[derive(Copy, Clone)]
enum EvictionKey {
    Dead,
    Evictable(EvictionPriority, Moment),
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum EvictionSource {
    Table,
    Cache,
}

struct Candidate<'a, S: FlowState> {
    key: EvictionKey,
    source: EvictionSource,
    id: InnerFlowId,
    entry: &'a Arc<FlowEntry<S>>,
}

fn update_eviction_incumbent<'a, S: FlowState>(
    id: &InnerFlowId,
    entry: &'a Arc<FlowEntry<S>>,
    cache: Option<&mut BTreeSet<InnerFlowId>>,
    versus: &mut Option<Candidate<'a, S>>,
    now: Moment,
) -> ControlFlow<(), EvictionPriority> {
    let source = if cache.is_some() {
        EvictionSource::Table
    } else {
        EvictionSource::Cache
    };

    // Flow entries in a larval state are being used by an in-progress slow
    // path walk. Taking them out would be rude! More pressingly, they lack
    // any active parents, so they will likely look *very* evictable, when
    // they really should not be.
    let liveness = entry.liveness();
    if liveness.is_protected() {
        return ControlFlow::Continue(EvictionPriority::Protected);
    }

    // We may be visiting this entry before the periodic task is able to reap
    // it. If so, we have a max-priority candidate, due to it losing either the
    // support of a crucial LFT or timer expiry.
    if liveness.is_dead()
        || (entry.lifetime.n_children.load(Ordering::Relaxed) > 0
            && entry.is_expired(now))
    {
        *versus =
            Some(Candidate { key: EvictionKey::Dead, id: *id, entry, source });
        ControlFlow::Break(())?;
    }

    // If we have no information, then default to preserving the flow.
    let prio = entry.eviction_priority(now).unwrap_or_default();
    if let EvictionPriority::Protected = prio {
        return ControlFlow::Continue(prio);
    }

    let last_hit = entry.last_hit();

    match versus {
        None => {
            *versus = Some(Candidate {
                key: EvictionKey::Evictable(prio, last_hit),
                id: *id,
                entry,
                source,
            });
        }
        Some(Candidate {
            key: EvictionKey::Evictable(curr_prio, curr_time),
            ..
        }) if prio > *curr_prio
            || (prio == *curr_prio && last_hit < *curr_time) =>
        {
            *versus = Some(Candidate {
                key: EvictionKey::Evictable(prio, last_hit),
                id: *id,
                entry,
                source,
            });
        }
        Some(_) => {
            if let Some(cache) = cache
                && cache.len() < FlowTable::<S>::EVICTION_CACHE_MAX
            {
                _ = cache.insert(*id);
            }
        }
    }

    ControlFlow::Continue(prio)
}

// We use a private submodule here to ensure that all uses of `Holds` are
// validated.
use holds::*;
mod holds {
    use super::Liveness;

    /// Tried to construct a [`Holds`] with more than
    /// [`super::Liveness::MAX_HOLDS`].
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
    pub struct TooManyHolds;

    impl From<TooManyHolds> for super::HoldIncrementError {
        fn from(_: TooManyHolds) -> Self {
            Self::LivenessFull
        }
    }

    /// Tried to remove a hold when there are none.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
    pub struct NoHolds;

    impl From<NoHolds> for super::HoldDecrementError {
        fn from(_: NoHolds) -> Self {
            Self::NoHolds
        }
    }

    /// A validated, sufficiently-small hold count for flow liveness state.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Default)]
    pub(super) struct Holds(u8);

    impl Holds {
        #[cfg(test)]
        pub const ZERO: Self = Self(0);
        pub const ONE: Self = Self(1);
        #[cfg(test)]
        pub const MAX: Self = Self(Liveness::MAX_HOLDS);

        pub const fn new(value: u8) -> Result<Self, TooManyHolds> {
            if value <= Liveness::MAX_HOLDS {
                Ok(Self(value))
            } else {
                Err(TooManyHolds)
            }
        }

        pub const fn get(self) -> u8 {
            self.0
        }

        pub const fn increment(self) -> Result<Self, TooManyHolds> {
            Self::new(self.get() + 1)
        }

        pub const fn decrement(self) -> Result<Self, NoHolds> {
            if let Some(new) = self.0.checked_sub(1) {
                Ok(Self(new))
            } else {
                Err(NoHolds)
            }
        }
    }
}

pub mod util {
    use core::num::NonZeroU16;

    /// Choose a priority value between `start_prio..=end_prio`
    /// based on `delta_ms`'s position between two timestamps.
    ///
    /// Returns `None` if start > end. Clamps to `start_prio` when delta
    /// is before the time range, and to `end_prio` when delta falls after it.
    pub fn priority_lerp(
        start_time_ms: u64,
        start_prio: NonZeroU16,
        end_time_ms: u64,
        end_prio: NonZeroU16,
        delta_ms: u64,
    ) -> Option<NonZeroU16> {
        if start_time_ms > end_time_ms || end_prio < start_prio {
            return None;
        }

        Some(if delta_ms <= start_time_ms {
            start_prio
        } else if delta_ms >= end_time_ms {
            end_prio
        } else {
            // Compute our priority using fixed point arithmetic.
            // Since we're working in terms of 16-bit numbers, we need as
            // many bits of fractional precision between 0.0 and 1.0.
            const SCALE: u64 = 16;
            const ONE_SCALED: u64 = 1 << SCALE;
            const FRACTION_MASK: u64 = ONE_SCALED - 1;

            debug_assert_eq!(FRACTION_MASK.count_ones(), SCALE as u32);
            debug_assert_eq!(
                FRACTION_MASK.leading_zeros(),
                u64::BITS - (SCALE as u32)
            );

            // Fixed-point division of a real by an integer is fairly
            // straightforward -- don't convert the denominator into the
            // target base.
            let inner_pos = (delta_ms - start_time_ms) << SCALE;
            let window_len = end_time_ms - start_time_ms;

            let inner_frac = inner_pos / window_len;

            let n_entries = u64::from(end_prio.get() - start_prio.get());

            let entry_fixed_pt = n_entries * inner_frac;

            let round_up = entry_fixed_pt & FRACTION_MASK >= ONE_SCALED / 2;
            let entry = u16::try_from(entry_fixed_pt >> SCALE)
                .expect("start and end points of lerp are both u16s")
                + u16::from(round_up);

            start_prio.saturating_add(entry)
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::api::PortInfo;
    use crate::engine::ip::v4::Protocol;
    use crate::engine::packet::AddrPair;
    use c8str::c8;
    use core::assert_matches;
    use core::time::Duration;

    fn dummy_port_name() -> Arc<C8Str> {
        const PORT_NAME: &C8Str = c8!("port");
        Arc::from(PORT_NAME.to_owned().into_boxed_c8_str())
    }

    impl Dump for () {
        type DumpVal = ();

        fn dump(&self, _hits: u64) {}
    }

    impl FlowState for () {
        fn parents(&self) -> impl Iterator<Item = Arc<dyn FlowEntryInfo>> {
            [].into_iter()
        }
    }

    #[derive(Debug, Clone)]
    struct ParentSet(Vec<Arc<dyn FlowEntryInfo>>);

    impl Dump for ParentSet {
        type DumpVal = ();

        fn dump(&self, _hits: u64) {}
    }

    impl FlowState for ParentSet {
        fn parents(&self) -> impl Iterator<Item = Arc<dyn FlowEntryInfo>> {
            self.0.iter().cloned()
        }
    }

    pub const FT_SIZE: NonZeroU32 = NonZeroU32::new(16).unwrap();

    #[derive(Debug, Clone)]
    struct FixedPolicy {
        time: Duration,
        default: Option<EvictionPriority>,
        manual: BTreeMap<InnerFlowId, EvictionPriority>,
    }

    impl<S: FlowState> ExpiryPolicy<S> for FixedPolicy {
        fn is_expired(&self, entry: &FlowEntry<S>, now: Moment) -> bool {
            entry.last_hit().delta_as_millis(now)
                >= (self.time.as_millis() as u64)
        }

        fn eviction_priority(
            &self,
            entry: &FlowEntry<S>,
            _now: Moment,
        ) -> Option<EvictionPriority> {
            self.manual.get(entry.id()).copied().or(self.default)
        }
    }

    #[test]
    fn flow_expired() {
        let flowid = InnerFlowId {
            proto: Protocol::TCP.into(),
            addrs: AddrPair::V4 {
                src: "192.168.2.10".parse().unwrap(),
                dst: "76.76.21.21".parse().unwrap(),
            },
            proto_info: PortInfo { src_port: 37890, dst_port: 443 }.into(),
        };

        let mut ft = FlowTable::new(
            dummy_port_name(),
            "flow-expired-test",
            FT_SIZE,
            None,
        );
        assert_eq!(ft.num_flows(), 0);
        ft.add_ready(flowid, ()).unwrap();
        let now = Moment::now();
        assert_eq!(ft.num_flows(), 1);
        ft.expire_flows(now);
        assert_eq!(ft.num_flows(), 1);
        ft.expire_flows(now + Duration::new(FLOW_DEF_EXPIRE_SECS, 0));
        assert_eq!(ft.num_flows(), 0);
    }

    #[test]
    fn flow_clear() {
        let flowid = InnerFlowId {
            proto: Protocol::TCP.into(),
            addrs: AddrPair::V4 {
                src: "192.168.2.10".parse().unwrap(),
                dst: "76.76.21.21".parse().unwrap(),
            },
            proto_info: PortInfo { src_port: 37890, dst_port: 443 }.into(),
        };

        let mut ft =
            FlowTable::new(dummy_port_name(), "flow-clear-test", FT_SIZE, None);
        assert_eq!(ft.num_flows(), 0);
        ft.add_ready(flowid, ()).unwrap();
        assert_eq!(ft.num_flows(), 1);
        ft.clear();
        assert_eq!(ft.num_flows(), 0);
    }

    #[test]
    fn children_prevent_timer_expiry() {
        let flowid = InnerFlowId {
            proto: Protocol::TCP.into(),
            addrs: AddrPair::V4 {
                src: "192.168.2.10".parse().unwrap(),
                dst: "76.76.21.21".parse().unwrap(),
            },
            proto_info: PortInfo { src_port: 37890, dst_port: 443 }.into(),
        };

        let pname = dummy_port_name();

        let mut ft1 =
            FlowTable::new(pname.clone(), "parent-table", FT_SIZE, None);
        let mut ft2 = FlowTable::new(pname, "child-table", FT_SIZE, None);
        let fe1 = ft1.add_ready(flowid, ()).unwrap();
        let fe2 = ft2.add_ready(flowid, ()).unwrap();

        let now = fe2.last_hit();
        fe1.push_child(&(fe2 as Arc<dyn FlowEntryInfo>)).unwrap();

        // A flow entry cannot be removed by the timer until all its children
        // have been evicted or expired.
        let t2 = now + Duration::new(FLOW_DEF_EXPIRE_SECS, 0);
        ft1.expire_flows(t2);
        assert_eq!(ft1.num_flows(), 1);

        // If we go via ft2 first, we will be able to remove its entries (which
        // have no children), which in turn makes ft1's entries available for
        // eviction.
        ft2.expire_flows(t2);
        assert_eq!(ft2.num_flows(), 0);
        ft1.expire_flows(t2);
        assert_eq!(ft1.num_flows(), 0);
    }

    #[test]
    fn timer_expiry_propagation() {
        let flowid = InnerFlowId {
            proto: Protocol::TCP.into(),
            addrs: AddrPair::V4 {
                src: "192.168.2.10".parse().unwrap(),
                dst: "76.76.21.21".parse().unwrap(),
            },
            proto_info: PortInfo { src_port: 37890, dst_port: 443 }.into(),
        };

        let pname = dummy_port_name();

        let mut ft1 =
            FlowTable::new(pname.clone(), "parent-table", FT_SIZE, None);
        let mut ft2 = FlowTable::new(pname, "child-table", FT_SIZE, None);
        let fe1 = ft1.add_ready(flowid, ()).unwrap();
        let fe2 = ft2
            .add_ready(flowid, ParentSet(vec![fe1.clone() as Arc<_>]))
            .unwrap();

        let t1 = fe2.last_hit();
        fe1.push_child(&(fe2.clone() as Arc<dyn FlowEntryInfo>)).unwrap();

        // Updating the last-hit time of a flow won't immediately propagate to
        // its children.
        let t2 = t1 + Duration::from_secs(10);
        fe2.hit_at(t2);
        assert!(fe1.last_hit() <= t1);

        // When fe2 is expired, it should pass on its expiry time to fe1.
        let t3 = t2 + Duration::new(FLOW_DEF_EXPIRE_SECS, 0);
        ft2.expire_flows(t3);
        assert_eq!(ft2.num_flows(), 0);
        assert_eq!(fe1.last_hit(), t2);
    }

    #[test]
    fn eviction_basics() {
        let flowid = InnerFlowId {
            proto: Protocol::TCP.into(),
            addrs: AddrPair::V4 {
                src: "192.168.2.10".parse().unwrap(),
                dst: "76.76.21.21".parse().unwrap(),
            },
            proto_info: PortInfo { src_port: 37890, dst_port: 443 }.into(),
        };

        let pname = dummy_port_name();

        // Fill up the tables.
        let mut default_ft =
            FlowTable::new(pname.clone(), "no-prio-table", FT_SIZE, None);
        let mut evict_ft = FlowTable::new(
            pname,
            "prio-table",
            FT_SIZE,
            Some(Arc::new(FixedPolicy {
                time: Duration::from_secs(FLOW_DEF_EXPIRE_SECS),
                default: Some(EvictionPriority::Evictable(NonZeroU16::MIN)),
                manual: Default::default(),
            })),
        );
        for i in 0..default_ft.limit.get() {
            let new_id = InnerFlowId {
                proto: Protocol::UDP.into(),
                addrs: AddrPair::V4 {
                    src: "192.168.2.10".parse().unwrap(),
                    dst: "76.76.21.21".parse().unwrap(),
                },
                proto_info: PortInfo { src_port: i as u16, dst_port: 443 }
                    .into(),
            };
            default_ft.add_ready(new_id, ()).unwrap();
            evict_ft.add_ready(new_id, ()).unwrap();
        }

        // With the default policy and a table full of UDP entries, we can't make
        // room for anything new.
        assert!(default_ft.add_ready(flowid, ()).is_err());
        assert_eq!(default_ft.num_flows(), FT_SIZE.get());

        // On a table where every flow is evictable, we can!
        assert!(evict_ft.add_ready(flowid, ()).is_ok());
        assert_eq!(evict_ft.num_flows(), FT_SIZE.get());

        // If we soft-kill a flow entry (i.e., one of its ancestors was evicted)
        // then we can make room to insert a new one.
        default_ft.map.values().next().unwrap().mark_dead();
        assert_eq!(default_ft.num_flows(), FT_SIZE.get());
        assert!(default_ft.add_ready(flowid, ()).is_ok());
        assert_eq!(default_ft.num_flows(), FT_SIZE.get());
    }

    #[test]
    fn eviction_selects_highest_prio() {
        let flowid = InnerFlowId {
            proto: Protocol::TCP.into(),
            addrs: AddrPair::V4 {
                src: "192.168.2.10".parse().unwrap(),
                dst: "76.76.21.21".parse().unwrap(),
            },
            proto_info: PortInfo { src_port: 37890, dst_port: 443 }.into(),
        };

        let sacrificial_flow = InnerFlowId {
            proto: Protocol::UDP.into(),
            addrs: AddrPair::V4 {
                src: "192.168.2.10".parse().unwrap(),
                dst: "76.76.21.21".parse().unwrap(),
            },
            proto_info: PortInfo { src_port: 5, dst_port: 443 }.into(),
        };

        let mut evict_ft = FlowTable::new(
            dummy_port_name(),
            "prio-table",
            FT_SIZE,
            Some(Arc::new(FixedPolicy {
                time: Duration::from_secs(FLOW_DEF_EXPIRE_SECS),
                default: Some(EvictionPriority::Evictable(NonZeroU16::MIN)),
                manual: vec![(
                    sacrificial_flow,
                    EvictionPriority::Evictable(16.try_into().unwrap()),
                )]
                .into_iter()
                .collect(),
            })),
        );
        for i in 0..evict_ft.limit.get() {
            let new_id = InnerFlowId {
                proto: Protocol::UDP.into(),
                addrs: AddrPair::V4 {
                    src: "192.168.2.10".parse().unwrap(),
                    dst: "76.76.21.21".parse().unwrap(),
                },
                proto_info: PortInfo { src_port: i as u16, dst_port: 443 }
                    .into(),
            };
            evict_ft.add_ready(new_id, ()).unwrap();
        }

        // We've set this table up so that one of these flows will have a
        // far higher eviction priority than its neighbours. This could
        // be driven by protocol, by time, or some other aspect of flow state.
        //
        // This is the entry we will evict, regardless of the age of all others.
        assert!(evict_ft.map.contains_key(&sacrificial_flow));
        assert!(evict_ft.add_ready(flowid, ()).is_ok());
        assert_eq!(evict_ft.num_flows(), FT_SIZE.get());
        assert!(!evict_ft.map.contains_key(&sacrificial_flow));
    }

    #[test]
    fn eviction_invalidates_descendents() {
        let flowid = InnerFlowId {
            proto: Protocol::TCP.into(),
            addrs: AddrPair::V4 {
                src: "192.168.2.10".parse().unwrap(),
                dst: "76.76.21.21".parse().unwrap(),
            },
            proto_info: PortInfo { src_port: 37890, dst_port: 443 }.into(),
        };

        let pname = dummy_port_name();

        let mut ft1 =
            FlowTable::new(pname.clone(), "parent-table", FT_SIZE, None);
        let mut ft2 =
            FlowTable::new(pname.clone(), "child-table", FT_SIZE, None);
        let mut ft2_2 =
            FlowTable::new(pname.clone(), "other-child-table", FT_SIZE, None);
        let mut ft3 = FlowTable::new(pname, "grandchild-table", FT_SIZE, None);
        let fe1 = ft1.add_ready(flowid, ()).unwrap();
        let fe2 = ft2.add_ready(flowid, ()).unwrap();
        let fe_out_of_chain = ft2_2.add_ready(flowid, ()).unwrap();
        let fe3 = ft3.add_ready(flowid, ()).unwrap();

        fe1.push_child(&(fe2.clone() as Arc<dyn FlowEntryInfo>)).unwrap();
        fe2.push_child(&(fe3.clone() as Arc<dyn FlowEntryInfo>)).unwrap();
        fe_out_of_chain
            .push_child(&(fe3.clone() as Arc<dyn FlowEntryInfo>))
            .unwrap();

        // If we invalidate fe1, then all of its *direct descendants* will also
        // be invalid.
        fe1.mark_dead();
        assert!(fe1.is_killed());
        assert!(fe2.is_killed());
        assert!(fe3.is_killed());
        assert!(!fe_out_of_chain.is_killed());
    }

    #[test]
    fn eviction_priority_inheritance() {
        let flowid = InnerFlowId {
            proto: Protocol::UDP.into(),
            addrs: AddrPair::V4 {
                src: "192.168.2.10".parse().unwrap(),
                dst: "76.76.21.21".parse().unwrap(),
            },
            proto_info: PortInfo { src_port: 37890, dst_port: 443 }.into(),
        };

        let pname = dummy_port_name();

        let mut ft1 =
            FlowTable::new(pname.clone(), "parent-table", FT_SIZE, None);
        let mut ft2 = FlowTable::new(
            pname.clone(),
            "child-table",
            FT_SIZE,
            Some(Arc::new(FixedPolicy {
                time: Duration::from_secs(FLOW_DEF_EXPIRE_SECS),
                default: Some(EvictionPriority::Evictable(NonZeroU16::MAX)),
                manual: Default::default(),
            })),
        );
        let mut ft2_2 = FlowTable::new(
            pname.clone(),
            "other-child-table",
            FT_SIZE,
            Some(Arc::new(FixedPolicy {
                time: Duration::from_secs(FLOW_DEF_EXPIRE_SECS),
                default: Some(EvictionPriority::Evictable(NonZeroU16::MIN)),
                manual: Default::default(),
            })),
        );
        let mut ft2_3 = FlowTable::new(
            pname,
            "other-other-child-table",
            FT_SIZE,
            Some(Arc::new(FixedPolicy {
                time: Duration::from_secs(FLOW_DEF_EXPIRE_SECS),
                default: Some(EvictionPriority::Protected),
                manual: Default::default(),
            })),
        );

        let fe1 = ft1.add_ready(flowid, ()).unwrap();
        let fe2 = ft2.add_ready(flowid, ()).unwrap();
        let fe2_2 = ft2_2.add_ready(flowid, ()).unwrap();
        let fe2_3 = ft2_3.add_ready(flowid, ()).unwrap();

        // By default, we have no entry expressing a preference.
        let now = fe2_3.last_hit();
        assert_eq!(fe1.eviction_priority(now), None);

        // When an explicit priority is requested by any descendent, we choose the
        // strongest requirement that the flow remain in place. Each flow we push
        // here makes the flow less likely for eviction.
        fe1.push_child(&(fe2.clone() as Arc<dyn FlowEntryInfo>)).unwrap();
        assert_eq!(
            fe1.eviction_priority(now),
            Some(EvictionPriority::Evictable(NonZeroU16::MAX)),
        );

        fe1.push_child(&(fe2_2.clone() as Arc<dyn FlowEntryInfo>)).unwrap();
        assert_eq!(
            fe1.eviction_priority(now),
            Some(EvictionPriority::Evictable(NonZeroU16::MIN)),
        );

        fe1.push_child(&(fe2_3.clone() as Arc<dyn FlowEntryInfo>)).unwrap();
        assert_eq!(
            fe1.eviction_priority(now),
            Some(EvictionPriority::Protected),
        );

        // Removal of any entry (i.e., because that entry expired) should result
        // in a corresponding change to the flow priority.
        fe1.remove_child(&(fe2_3 as Arc<dyn FlowEntryInfo>));
        fe1.remove_child(&(fe2_2 as Arc<dyn FlowEntryInfo>));
        assert_eq!(
            fe1.eviction_priority(now),
            Some(EvictionPriority::Evictable(NonZeroU16::MAX)),
        );
    }

    #[test]
    fn eviction_candidate_scan_saves_progress() {
        let scan_budget = u32::try_from(FlowTable::<()>::SCAN_BUDGET).unwrap();
        let table_size: NonZeroU32 = 5000.try_into().unwrap();
        let perturb_at = 4500;
        assert!(table_size.get() > scan_budget);
        assert!((scan_budget..table_size.get()).contains(&perturb_at));

        let sacrificial_flow = InnerFlowId {
            proto: Protocol::UDP.into(),
            addrs: AddrPair::V4 {
                src: "192.168.2.10".parse().unwrap(),
                dst: "76.76.21.21".parse().unwrap(),
            },
            proto_info: PortInfo { src_port: perturb_at as u16, dst_port: 443 }
                .into(),
        };

        let not_quite_sacrificial_flow = InnerFlowId {
            proto_info: PortInfo {
                src_port: (perturb_at + 1) as u16,
                dst_port: 443,
            }
            .into(),
            ..sacrificial_flow
        };

        let mut evict_ft = FlowTable::new(
            dummy_port_name(),
            "prio-table",
            table_size,
            Some(Arc::new(FixedPolicy {
                time: Duration::from_secs(FLOW_DEF_EXPIRE_SECS),
                default: Some(EvictionPriority::Protected),
                manual: vec![
                    (
                        sacrificial_flow,
                        EvictionPriority::Evictable(16.try_into().unwrap()),
                    ),
                    (
                        not_quite_sacrificial_flow,
                        EvictionPriority::Evictable(15.try_into().unwrap()),
                    ),
                ]
                .into_iter()
                .collect(),
            })),
        );
        for i in 0..evict_ft.limit.get() {
            let new_id = InnerFlowId {
                proto: Protocol::UDP.into(),
                addrs: AddrPair::V4 {
                    src: "192.168.2.10".parse().unwrap(),
                    dst: "76.76.21.21".parse().unwrap(),
                },
                proto_info: PortInfo { src_port: i as u16, dst_port: 443 }
                    .into(),
            };
            evict_ft.add_ready(new_id, ()).unwrap();

            if i == perturb_at {
                assert_eq!(new_id, sacrificial_flow);
                let entry = evict_ft.map.get(&new_id).unwrap();
                entry.hit_at(entry.last_hit() - Duration::from_secs(61));
            }
        }

        assert!(evict_ft.eviction_cursor.is_none());

        // The usable entry should only be seen after several scans, in this
        // case. Each scan, successful or otherwise, will advance the cursor.
        assert!(evict_ft.find_evictable_entry().is_none());
        let c1 = evict_ft.eviction_cursor.unwrap();
        assert!(evict_ft.evictable_cache.is_empty());

        assert!(evict_ft.find_evictable_entry().is_none());
        let c2 = evict_ft.eviction_cursor.unwrap();
        assert!(c1 < c2);
        assert!(evict_ft.evictable_cache.is_empty());

        // At this point, we will scan past two evictable flows. We need to
        // select the most evictable flow here, and keep a record of the one
        // we _didn't_ select. The next search will choose this element.
        assert!(evict_ft.find_evictable_entry().is_some());
        let c3 = evict_ft.eviction_cursor.unwrap();
        assert!(c2 < c3);
        assert!(evict_ft.evictable_cache.contains(&not_quite_sacrificial_flow));

        evict_ft.expire(&c3);

        // A scan should wrap around at the end of the map, if we hit the end
        // with some remaining budget. Accordingly expect that the flow ID
        // checkpoint is *lower* this time.
        assert!(evict_ft.find_evictable_entry().is_some());
        let c4 = evict_ft.eviction_cursor.unwrap();
        assert!(evict_ft.evictable_cache.is_empty());
        assert!(c4 < c3);
    }

    #[test]
    fn priority_lerp() {
        let low = 10.try_into().unwrap();
        let high = 20.try_into().unwrap();

        assert_eq!(
            util::priority_lerp(500, low, 1_000, high, 750),
            Some(15.try_into().unwrap()),
        );

        // Double check rounding.
        assert_eq!(
            util::priority_lerp(500, low, 1_000, high, 975),
            Some(19.try_into().unwrap()),
        );

        assert_eq!(util::priority_lerp(500, low, 1_000, high, 976), Some(high));

        // Show we don't shoot past [low, high] at boundaries.
        assert_eq!(util::priority_lerp(500, low, 1_000, high, 501), Some(low));

        assert_eq!(util::priority_lerp(500, low, 1_000, high, 999), Some(high));
    }

    #[test]
    fn priority_lerp_clamps() {
        let low = 10.try_into().unwrap();
        let high = 20.try_into().unwrap();

        assert_eq!(util::priority_lerp(500, low, 1_000, high, 200), Some(low));

        assert_eq!(
            util::priority_lerp(500, low, 1_000, high, 10_000),
            Some(high),
        );
    }

    #[test]
    fn priority_lerp_rejects_bad_params() {
        // Start > end time is an illegal parameter choice.
        assert_eq!(
            util::priority_lerp(
                1_000,
                1.try_into().unwrap(),
                500,
                2.try_into().unwrap(),
                750
            ),
            None
        );

        // We could support linear interpolation down from a higher to lower
        // value, but have no reason to do so today.
        assert_eq!(
            util::priority_lerp(
                0,
                2.try_into().unwrap(),
                10,
                1.try_into().unwrap(),
                5
            ),
            None
        );
    }

    #[test]
    fn liveness_roundtrips_u8() {
        let families = [
            (Liveness::Larval { holds: Holds::default() }),
            (Liveness::Ready { holds: Holds::default() }),
        ];

        let roundtrip = |v| assert_eq!(v, Liveness::from(u8::from(v)));

        for base in families {
            for i in 0..Liveness::MAX_HOLDS {
                let val = base.with_holds(Holds::new(i).unwrap()).unwrap();
                roundtrip(val);
            }
        }

        roundtrip(Liveness::Dead);
    }

    #[test]
    fn liveness_state_transitions() {
        // In standard operation, we'll typically either create a new entry,
        // or retrieve one which was present (and increment its hold.
        let ready_lft = Liveness::Ready { holds: Holds::ZERO };
        assert_eq!(
            Liveness::Larval { holds: Holds::ONE }.transition_to_ready(),
            Ok(ready_lft)
        );

        assert_eq!(
            Liveness::Ready { holds: Holds::ZERO }
                .increment_holds()
                .unwrap()
                .transition_to_ready(),
            Ok(ready_lft)
        );

        // And we can't remove holds if there are none left.
        assert_eq!(
            Liveness::Larval { holds: Holds::ZERO }.transition_to_ready(),
            Err(HoldDecrementError::NoHolds)
        );
        assert_eq!(
            ready_lft.transition_to_ready(),
            Err(HoldDecrementError::NoHolds)
        );

        // If we have a full set of holds, we can free them but not permit
        // any more.
        for full in [
            Liveness::Larval { holds: Holds::MAX },
            Liveness::Ready { holds: Holds::MAX },
        ] {
            assert_eq!(
                full.increment_holds(),
                Err(HoldIncrementError::LivenessFull)
            );
            assert_eq!(
                full.transition_to_ready(),
                Ok(Liveness::Ready { holds: Holds::MAX.decrement().unwrap() })
            );
        }

        // If we picked up an LFT which was already valid (return path traffic,
        // loss of a UFT, and/or parallel execution) then we expect to
        // remain Ready with an altered hold count.
        let holds = Holds::new(2).unwrap();
        assert_eq!(
            Liveness::Ready { holds }.transition_to_ready(),
            Ok(Liveness::Ready { holds: holds.decrement().unwrap() })
        );

        // TCP flow entries can be marked as dead at any time, because their
        // state is driven by their own FSM logic in addition to the standard
        // expiry & eviction mechanics.
        assert_eq!(Liveness::Dead.transition_to_ready(), Ok(Liveness::Dead));

        // If a flow entry is dead when we try to make use of it, we prevent a
        // hold from being taken. The main use of this is to prevent ourselves
        // from making use of an entry which is `Dead` but still in the map.
        assert_eq!(
            Liveness::Dead.increment_holds(),
            Err(HoldIncrementError::Dead)
        );
    }

    #[test]
    fn get_and_hold_must_be_alive() {
        let flowid = InnerFlowId {
            proto: Protocol::TCP.into(),
            addrs: AddrPair::V4 {
                src: "192.168.2.10".parse().unwrap(),
                dst: "76.76.21.21".parse().unwrap(),
            },
            proto_info: PortInfo { src_port: 37890, dst_port: 443 }.into(),
        };

        let mut ft =
            FlowTable::new(dummy_port_name(), "test-table", FT_SIZE, None);
        let my_entry = ft.add_ready(flowid, ()).unwrap();

        // Mark the entry as dead -- e.g., TCP state invalidation or we
        // evicted an LFT underpinning a UFT. That entry remains in the table
        // so that we don't need to lock-and-remove from arbitrarily many
        // tables.
        my_entry.mark_dead();

        // We can still see it, it's just dead. `get` assumes the caller is
        // guarding against this case to perform its own removals etc.
        assert_matches!(ft.get(&flowid), Some(e) if e.is_killed());

        // If we *need* a valid entry, then we cannot see it at all.
        assert_matches!(ft.get_and_hold(&flowid), Ok(None));
    }

    #[test]
    fn flow_entry_transitions() {
        let flowid = InnerFlowId {
            proto: Protocol::TCP.into(),
            addrs: AddrPair::V4 {
                src: "192.168.2.10".parse().unwrap(),
                dst: "76.76.21.21".parse().unwrap(),
            },
            proto_info: PortInfo { src_port: 37890, dst_port: 443 }.into(),
        };

        let mut ft =
            FlowTable::new(dummy_port_name(), "test-table", FT_SIZE, None);

        // An entry is initialised as `Larval`. While held, it must be immune
        // to eviction and expiry.
        let my_entry = ft.add(flowid, ()).unwrap();
        let t0 = my_entry.last_hit();
        my_entry.hit_at(t0 - Duration::from_secs(61));

        for is_ready in [false, true] {
            if is_ready {
                assert!(!my_entry.liveness().is_protected());
                my_entry.add_hold().unwrap();
            } else {
                assert!(my_entry.liveness().is_larval());
            }

            assert!(my_entry.liveness().is_protected());

            assert!(ft.find_evictable_entry().is_none());
            ft.expire_flows(t0);
            assert_eq!(ft.num_flows(), 1);
            assert!(!my_entry.is_killed());

            my_entry.mark_ready();

            assert!(!my_entry.liveness().is_protected());
        }

        // Removing the entry marks it as dead.
        ft.remove(&flowid).unwrap();
        assert!(my_entry.is_killed());

        // As does clearing the map.
        let my_entry = ft.add_ready(flowid, ()).unwrap();
        assert_matches!(my_entry.liveness(), Liveness::Ready { .. });
        ft.clear();
        assert!(my_entry.is_killed());
    }
}

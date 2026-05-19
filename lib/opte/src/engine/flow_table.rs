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
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;
use core::fmt;
use core::num::NonZeroU16;
use core::num::NonZeroU32;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
#[cfg(all(not(feature = "std"), not(test)))]
use illumos_sys_hdrs::uintptr_t;
use opte_api::OpteError;
use serde::Serialize;
use serde::de::DeserializeOwned;

// XXX This really shouldn't be pub but for now we are leaking this
// info for the purpose of testing until the Port API has support for
// setting/getting TTL on a per Flow Table basis.
pub const FLOW_DEF_EXPIRE_SECS: u64 = 60;
pub const FLOW_DEF_TTL: Ttl = Ttl::new_seconds(FLOW_DEF_EXPIRE_SECS);

pub const FLOW_TABLE_DEF_MAX_ENTRIES: u32 = 8192;

type Result<T> = core::result::Result<T, OpteError>;

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

/// A metric of how stale a flow entry is, used to determine whether
/// any existing entry can be evicted to make room for a new one.
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Default)]
pub enum EvictionPriority {
    /// The flow is not eligible for eviction.
    #[default]
    Protected,
    /// The flow entry may be evicted to make room for a new one.
    ///
    /// A numerically larger priority is more eligible for eviction.
    Evictable(NonZeroU16),
}

/// A policy for expiring flow table entries over time.
pub trait ExpiryPolicy<S: FlowState>: fmt::Debug + Send + Sync {
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
pub trait FlowEntryInfo: fmt::Debug + Send + Sync {
    /// Set the last hit time on this entry to `new_time` if it is later
    /// than the stored value.
    fn inherit_last_hit(&self, new_time: Moment);

    /// Determine whether this flow entry can be evicted to make room for
    /// another, recursively checking all children when needed.
    fn eviction_priority(&self, now: Moment) -> Option<EvictionPriority>;

    /// Set `self` as a parent node to `child`.
    fn push_child(&self, child: &Arc<dyn FlowEntryInfo>);

    /// Remove `child` from this entry's list of children.
    fn remove_child(&self, child: &Arc<dyn FlowEntryInfo>);

    /// Mark this flow entry, and all those which depend on it for validity,
    /// as being invalid.
    fn mark_evicted(&self);
}

impl<S: FlowState> FlowEntryInfo for FlowEntry<S> {
    fn inherit_last_hit(&self, new_time: Moment) {
        let new = new_time.raw_millis();
        // An error from the below call implies a concurrent modification with
        // a time later than `new_time`. In that case there's just nothing left
        // to do here.
        _ = self.lifetime.last_hit.try_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |prior| (prior < new).then_some(new),
        );
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
        for maybe_child in &*self.lifetime.children.read() {
            if let Some(child) = maybe_child.0.upgrade() {
                match (best_prio, child.eviction_priority(now)) {
                    (None, a) => best_prio = a,
                    (Some(_), None) => {}
                    (Some(old), Some(new)) => best_prio = Some(new.min(old)),
                }
            }
        }

        best_prio
    }

    fn push_child(&self, child: &Arc<dyn FlowEntryInfo>) {
        let mut children = self.lifetime.children.write();
        children.insert(ByAddr(Arc::downgrade(child)));
    }

    fn remove_child(&self, child: &Arc<dyn FlowEntryInfo>) {
        let mut children = self.lifetime.children.write();
        children.remove(&ByAddr(Arc::downgrade(child)));
    }

    fn mark_evicted(&self) {
        if !self.lifetime.killed.swap(true, Ordering::Relaxed) {
            // Any flow entry is only valid while all of its parents still
            // exist. Timeout-driven expiry will not remove an entry while there
            // are still live parents, but during eviction we need to go through
            // and mark them as invalid in turn.
            for maybe_child in &*self.lifetime.children.read() {
                if let Some(child) = maybe_child.0.upgrade() {
                    child.mark_evicted();
                }
            }
        }
    }
}

pub type FlowTableDump<T> = Vec<(InnerFlowId, T)>;

#[derive(Debug)]
pub struct FlowTable<S: FlowState> {
    port_c: CString,
    name_c: CString,
    limit: NonZeroU32,
    policy: Arc<dyn ExpiryPolicy<S>>,
    map: BTreeMap<InnerFlowId, Arc<FlowEntry<S>>>,
}

impl<S: FlowState> FlowTable<S> {
    /// Add a new entry to the flow table, returning a shared refrence to
    /// the entry.
    ///
    /// # Errors
    ///
    /// If the table is at max capacity, an error is returned and no
    /// modification is made to the table.
    ///
    /// If an entry already exists for this flow, it is overwritten.
    pub fn add(
        &mut self,
        flow_id: InnerFlowId,
        state: S,
    ) -> Result<Arc<FlowEntry<S>>> {
        self.check_for_space()?;
        let entry = Arc::new(FlowEntry::new(flow_id, state, self));
        self.map.insert(flow_id, Arc::clone(&entry));
        Ok(entry)
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
        self.map.clear()
    }

    pub fn dump(&self) -> FlowTableDump<S::DumpVal> {
        let mut flows = Vec::with_capacity(self.map.len());
        for (flow_id, entry) in &self.map {
            flows.push((*flow_id, entry.dump()));
        }
        flows
    }

    pub fn expire(&mut self, flowid: &InnerFlowId) {
        flow_expired_probe(&self.port_c, &self.name_c, flowid, None, None);
        if let Some(entry) = self.map.remove(flowid) {
            entry.propagate_last_hit();
            entry.mark_evicted();
        }
    }

    pub fn expire_flows<F>(&mut self, now: Moment, f: F) -> Vec<InnerFlowId>
    where
        F: Fn(&S) -> InnerFlowId,
    {
        let name_c = &self.name_c;
        let port_c = &self.port_c;
        let mut expired = vec![];

        self.map.retain(|flowid, entry| {
            // A flow cannot be expired by the timer while it still has children
            // relying upon its existence. Check whether any remain, and remove
            // dangling references to child entries which have expired.
            {
                // We have a write lock on the port, so there shouldn't be
                // contention here.
                let mut children = entry.lifetime.children.write();
                children.retain(|el| el.0.upgrade().is_some());
                if !children.is_empty() {
                    return true;
                }
            }
            if entry.is_expired(now) {
                let my_time = entry.last_hit();
                flow_expired_probe(
                    port_c,
                    name_c,
                    flowid,
                    Some(my_time.raw_millis()),
                    Some(now.raw_millis()),
                );
                entry.propagate_last_hit();
                expired.push(f(entry.state()));
                return false;
            }

            !entry.is_killed()
        });

        expired
    }

    /// Determine whether there is currently space for a new entry to be
    /// inserted.
    ///
    /// If out of space, this method will attempt to evict an existing entry.
    pub fn check_for_space(&mut self) -> Result<()> {
        if self.map.len() < self.limit.get() as usize {
            return Ok(());
        }

        if let Some((key, _)) = self.find_evictable_entry() {
            self.expire(&key);
            Ok(())
        } else {
            Err(OpteError::MaxCapacity(self.limit.get() as u64))
        }
    }

    /// Select the flow entry most eligible for eviction (i.e., having the
    /// numerically highest priority and the oldest timestamp).
    ///
    /// Entries which have been killed due to the loss of a dependency will be
    /// used where possible.
    pub fn find_evictable_entry(&self) -> Option<(InnerFlowId, &FlowEntry<S>)> {
        let now = Moment::now();

        // TODO: some form of datastructure to accelerate this?
        // Who would be responsible for keeping that up to date?
        // If that cache is wrong, we're just hitting the O(n) scan anyhow.

        let mut to_evict = None;
        for (key, entry) in self.map.iter() {
            if entry.is_killed() {
                to_evict = Some((EvictionKey::Dead, *key, entry));
                break;
            }

            // If we have no information, then default to preserving the flow.
            let prio = entry.eviction_priority(now).unwrap_or_default();
            if let EvictionPriority::Protected = prio {
                continue;
            }

            let last_hit = entry.last_hit();

            match to_evict {
                None => {
                    to_evict = Some((
                        EvictionKey::Evictable(prio, last_hit),
                        *key,
                        entry,
                    ))
                }
                Some((EvictionKey::Evictable(curr_prio, curr_time), ..))
                    if prio >= curr_prio && last_hit < curr_time =>
                {
                    to_evict = Some((
                        EvictionKey::Evictable(prio, last_hit),
                        *key,
                        entry,
                    ));
                }
                Some(_) => {}
            }
        }

        to_evict.map(|(_, k, v)| (k, v.as_ref()))
    }

    /// Get the maximum number of entries this flow table may hold.
    pub fn get_limit(&self) -> NonZeroU32 {
        self.limit
    }

    /// Get a reference to the flow entry for a given flow, if one exists.
    pub fn get(&self, flow_id: &InnerFlowId) -> Option<&Arc<FlowEntry<S>>> {
        // Flows which are marked as `killed` no longer really exist, but they
        // have not yet been reaped.
        self.map.get(flow_id).and_then(|v| (!v.is_killed()).then_some(v))
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
        port: &str,
        name: &str,
        limit: NonZeroU32,
        policy: Option<Arc<dyn ExpiryPolicy<S>>>,
    ) -> FlowTable<S> {
        let policy = policy.unwrap_or_else(|| Arc::new(FLOW_DEF_TTL));

        Self {
            port_c: CString::new(port).unwrap(),
            name_c: CString::new(name).unwrap(),
            limit,
            policy,
            map: BTreeMap::new(),
        }
    }

    /// Get the number of flows in this table.
    pub fn num_flows(&self) -> u32 {
        self.map.len() as u32
    }

    pub fn remove(&mut self, flow: &InnerFlowId) -> Option<Arc<FlowEntry<S>>> {
        self.map.remove(flow)
    }

    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (&InnerFlowId, &Arc<FlowEntry<S>>)> {
        self.map.iter()
    }
}

#[allow(unused_variables)]
fn flow_expired_probe(
    port: &CString,
    name: &CString,
    flowid: &InnerFlowId,
    last_hit: Option<u64>,
    now: Option<u64>,
) {
    cfg_if! {
        if #[cfg(all(not(feature = "std"), not(test)))] {
            __dtrace_probe_flow__expired(
                port.as_ptr() as uintptr_t,
                name.as_ptr() as uintptr_t,
                flowid,
                last_hit.unwrap_or_default() as usize,
                now.unwrap_or_default() as usize,
            );
        } else if #[cfg(feature = "usdt")] {
            use std::string::ToString;
            let port_s = port.to_str().unwrap();
            let name_s = name.to_str().unwrap();
            crate::opte_provider::flow__expired!(
                || (port_s, name_s, flowid.to_string(), last_hit.unwrap_or_default(), now.unwrap_or_default())
            );
        } else {
            let (_, _, _) = (port, name, flowid);
        }
    }
}

/// A type that can be "dumped" for the purposes of presenting an
/// external view into internal state of the [`FlowEntry<T>`].
pub trait Dump: fmt::Debug + Send + Sync {
    type DumpVal: DeserializeOwned + Serialize;

    fn dump(&self, hits: u64) -> Self::DumpVal;
}

/// Common functions needed from the interior state of a flow table entry.
pub trait FlowState: Dump {
    /// Return an iterator containing references to all flow entries from other
    /// tables which underpin `self`.
    fn parents(&self) -> impl Iterator<Item = Arc<dyn FlowEntryInfo>> {
        [].into_iter()
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
    killed: AtomicBool,

    /// Entries in remote tables which rely on the continued existence of
    /// this flow.
    ///
    /// Child entries can also provide a flow with a measure of whether
    /// it is eligible for eviction.
    children: KRwLock<BTreeSet<ByAddr>>,
}

impl fmt::Debug for FlowLifetime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let FlowLifetime { last_hit, killed, children: _ } = self;
        f.debug_struct("FlowEntry")
            .field("last_hit", last_hit)
            .field("killed", killed)
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
pub struct FlowEntry<S: FlowState> {
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
    fn dump(&self) -> S::DumpVal {
        self.state.dump(self.hits.load(Ordering::Relaxed))
    }

    pub fn id(&self) -> &InnerFlowId {
        &self.id
    }

    pub fn state_mut(&mut self) -> &mut S {
        &mut self.state
    }

    pub fn state(&self) -> &S {
        &self.state
    }

    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
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

    /// Returns whether this flow entry has explicitly been marked as invalid
    /// (e.g., one of its ancestors has been evicted).
    fn is_killed(&self) -> bool {
        self.lifetime.killed.load(Ordering::Relaxed)
    }

    /// Returns whether this flow entry is past its policy's expiry time.
    fn is_expired(&self, now: Moment) -> bool {
        self.policy.is_expired(self, now)
    }

    /// Update the last hit time of this flow entry's parents if it has been
    /// used more recently.
    fn propagate_last_hit(&self) {
        let my_time = self.last_hit();
        for parent in self.state.parents() {
            parent.inherit_last_hit(my_time);
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
                killed: false.into(),
                children: KRwLock::new(BTreeSet::new()),
            }),
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
        last_hit: uintptr_t,
        now: uintptr_t,
    );

    pub safe fn __dtrace_probe_ft__entry__invalidated(
        dir: uintptr_t,
        port: uintptr_t,
        layer: uintptr_t,
        ifid: *const InnerFlowId,
        epoch: uintptr_t,
    );
}

impl Dump for () {
    type DumpVal = ();

    fn dump(&self, _hits: u64) {}
}

impl FlowState for () {}

/// A score of how likely we are to evict a given flow.
enum EvictionKey {
    Dead,
    Evictable(EvictionPriority, Moment),
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::api::PortInfo;
    use crate::engine::ip::v4::Protocol;
    use crate::engine::packet::AddrPair;
    use crate::engine::packet::FLOW_ID_DEFAULT;
    use core::time::Duration;

    pub const FT_SIZE: Option<NonZeroU32> = NonZeroU32::new(16);

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

        let mut ft =
            FlowTable::new("port", "flow-expired-test", FT_SIZE.unwrap(), None);
        assert_eq!(ft.num_flows(), 0);
        ft.add(flowid, ()).unwrap();
        let now = Moment::now();
        assert_eq!(ft.num_flows(), 1);
        ft.expire_flows(now, |_| FLOW_ID_DEFAULT);
        assert_eq!(ft.num_flows(), 1);
        ft.expire_flows(now + Duration::new(FLOW_DEF_EXPIRE_SECS, 0), |_| {
            FLOW_ID_DEFAULT
        });
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
            FlowTable::new("port", "flow-clear-test", FT_SIZE.unwrap(), None);
        assert_eq!(ft.num_flows(), 0);
        ft.add(flowid, ()).unwrap();
        assert_eq!(ft.num_flows(), 1);
        ft.clear();
        assert_eq!(ft.num_flows(), 0);
    }
}

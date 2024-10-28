// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! The flow table implementation.
//!
//! This provides the underlying implementation for the various flow
//! tables: UFT, LFT, and the TCP Flow Table.

use super::packet::InnerFlowId;
use crate::ddi::time::Moment;
use crate::ddi::time::MILLIS;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::num::NonZeroU32;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
#[cfg(all(not(feature = "std"), not(test)))]
use illumos_sys_hdrs::uintptr_t;
use opte_api::OpteError;
use serde::de::DeserializeOwned;
use serde::Serialize;

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

/// A policy for expiring flow table entries over time.
pub trait ExpiryPolicy<S: Dump>: fmt::Debug {
    /// Returns whether the given flow should be removed, given current flow
    /// state, the time a packet was last received, and the current time.
    fn is_expired(&self, entry: &FlowEntry<S>, now: Moment) -> bool;
}

impl<S: Dump> ExpiryPolicy<S> for Ttl {
    fn is_expired(&self, entry: &FlowEntry<S>, now: Moment) -> bool {
        entry.is_expired(now, *self)
    }
}

pub type FlowTableDump<T> = Vec<(InnerFlowId, T)>;

#[derive(Debug)]
pub struct FlowTable<S: Dump> {
    port_c: CString,
    name_c: CString,
    limit: NonZeroU32,
    policy: Box<dyn ExpiryPolicy<S>>,
    map: BTreeMap<InnerFlowId, Arc<FlowEntry<S>>>,
}

impl<S> FlowTable<S>
where
    // S: Clone + fmt::Debug + Dump,
    S: fmt::Debug + Dump,
{
    /// Add a new entry to the flow table.
    ///
    /// # Errors
    ///
    /// If the table is at max capacity, an error is returned and no
    /// modification is made to the table.
    ///
    /// If an entry already exists for this flow, it is overwritten.
    pub fn add(&mut self, flow_id: InnerFlowId, state: S) -> Result<()> {
        if self.map.len() == self.limit.get() as usize {
            return Err(OpteError::MaxCapacity(self.limit.get() as u64));
        }

        let entry = FlowEntry::new(state);
        self.map.insert(flow_id, entry.into());
        Ok(())
    }

    /// Add a new entry to the flow table, returning a shared refrence to
    /// the entry.
    ///
    /// # Errors
    ///
    /// If the table is at max capacity, an error is returned and no
    /// modification is made to the table.
    ///
    /// If an entry already exists for this flow, it is overwritten.
    pub fn add_and_return(
        &mut self,
        flow_id: InnerFlowId,
        state: S,
    ) -> Result<Arc<FlowEntry<S>>> {
        if self.map.len() == self.limit.get() as usize {
            return Err(OpteError::MaxCapacity(self.limit.get() as u64));
        }

        let entry = Arc::new(FlowEntry::new(state));
        self.map.insert(flow_id, entry.clone());
        Ok(entry)
    }

    /// Add a new entry to the flow table while eliding the capacity check.
    ///
    /// This is meant for table implementations that enforce their own limit.
    pub fn add_unchecked(&mut self, flow_id: InnerFlowId, state: S) {
        let entry = FlowEntry::new(state);
        self.map.insert(flow_id, entry.into());
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
        self.map.remove(flowid);
    }

    pub fn expire_flows<F>(&mut self, now: Moment, f: F) -> Vec<InnerFlowId>
    where
        F: Fn(&S) -> InnerFlowId,
    {
        let name_c = &self.name_c;
        let port_c = &self.port_c;
        let mut expired = vec![];

        self.map.retain(|flowid, entry| {
            if self.policy.is_expired(entry, now) {
                flow_expired_probe(
                    port_c,
                    name_c,
                    flowid,
                    Some(entry.last_hit.load(Ordering::Relaxed)),
                    Some(now.raw_millis()),
                );
                expired.push(f(entry.state()));
                return false;
            }

            true
        });

        expired
    }

    /// Get the maximum number of entries this flow table may hold.
    pub fn get_limit(&self) -> NonZeroU32 {
        self.limit
    }

    /// Get a reference to the flow entry for a given flow, if one
    /// exists.
    pub fn get(&self, flow_id: &InnerFlowId) -> Option<&Arc<FlowEntry<S>>> {
        self.map.get(flow_id)
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
        policy: Option<Box<dyn ExpiryPolicy<S>>>,
    ) -> FlowTable<S> {
        let policy = policy.unwrap_or_else(|| Box::new(FLOW_DEF_TTL));

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
            unsafe {
                __dtrace_probe_flow__expired(
                    port.as_ptr() as uintptr_t,
                    name.as_ptr() as uintptr_t,
                    flowid,
                    last_hit.unwrap_or_default() as usize,
                    now.unwrap_or_default() as usize,
                );
            }
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
pub trait Dump {
    type DumpVal: DeserializeOwned + Serialize;

    fn dump(&self, hits: u64) -> Self::DumpVal;
}

/// The FlowEntry holds any arbitrary state type `S`.
#[derive(Debug)]
pub struct FlowEntry<S: Dump> {
    state: S,

    /// Number of times this flow has been matched.
    hits: AtomicU64,

    /// This tracks the last time the flow was matched.
    ///
    /// These are raw u64s sourced from a `Moment`, which tracks time
    /// in nanoseconds.
    last_hit: AtomicU64,

    /// Records whether this flow predates a rule change, and
    /// must rerun rule processing before `state` can be used.
    dirty: AtomicBool,
}

impl<S: Dump> FlowEntry<S> {
    fn dump(&self) -> S::DumpVal {
        self.state.dump(self.hits.load(Ordering::Relaxed))
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

    /// Increments this flow's hit counter and
    pub fn hit(&self) {
        self.hit_at(Moment::now())
    }

    /// Increments a flow's hit counter and sets th
    ///
    /// This is used to minimise calls to `gethrtime` in fastpath
    /// operations. Callers *MUST* be certain that expiry logic for this flow
    /// entry uses saturating comparisons, particularly if timestamps are
    /// sourced before grabbing a lock / processing a packet / any other
    /// long-running operation. **This is doubly true if you are not holding
    /// the port lock.**
    pub(crate) fn hit_at(&self, now: Moment) {
        self.hits.fetch_add(1, Ordering::Relaxed);
        self.last_hit.store(now.raw(), Ordering::Relaxed);
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
        Moment::from_raw_nanos(self.last_hit.load(Ordering::Relaxed))
    }

    fn is_expired(&self, now: Moment, ttl: Ttl) -> bool {
        ttl.is_expired(self.last_hit(), now)
    }

    fn new(state: S) -> Self {
        FlowEntry {
            state,
            hits: 0.into(),
            last_hit: Moment::now().raw().into(),
            dirty: false.into(),
        }
    }
}

pub trait StateSummary {
    fn summary(&self) -> String;
}

#[cfg(all(not(feature = "std"), not(test)))]
extern "C" {
    pub fn __dtrace_probe_flow__expired(
        port: uintptr_t,
        layer: uintptr_t,
        flowid: *const InnerFlowId,
        last_hit: uintptr_t,
        now: uintptr_t,
    );

    pub fn __dtrace_probe_ft__entry__invalidated(
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

#[cfg(test)]
mod test {
    use super::*;
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
            src_port: 37890,
            dst_port: 443,
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
            src_port: 37890,
            dst_port: 443,
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

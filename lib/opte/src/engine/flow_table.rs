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
use alloc::collections::BTreeMap;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::num::NonZeroU32;
use opte_api::OpteError;
use serde::de::DeserializeOwned;
use serde::Serialize;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use illumos_sys_hdrs::uintptr_t;
        use super::rule::flow_id_sdt_arg;
    }
}

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

pub type FlowTableDump<T> = Vec<(InnerFlowId, T)>;

#[derive(Debug)]
pub struct FlowTable<S: Dump> {
    port_c: CString,
    name_c: CString,
    limit: NonZeroU32,
    ttl: Ttl,
    map: BTreeMap<InnerFlowId, FlowEntry<S>>,
}

impl<S> FlowTable<S>
where
    S: Clone + fmt::Debug + Dump,
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
        self.map.insert(flow_id, entry);
        Ok(())
    }

    /// Add a new entry to the flow table while eliding the capacity check.
    ///
    /// This is meant for table implementations that enforce their own limit.
    pub fn add_unchecked(&mut self, flow_id: InnerFlowId, state: S) {
        let entry = FlowEntry::new(state);
        self.map.insert(flow_id, entry);
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
        let ttl = self.ttl;
        let mut expired = vec![];

        self.map.retain(|flowid, entry| {
            if entry.is_expired(now, ttl) {
                flow_expired_probe(
                    port_c,
                    name_c,
                    flowid,
                    Some(entry.last_hit),
                    Some(now),
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
    pub fn get(&mut self, flow_id: &InnerFlowId) -> Option<&FlowEntry<S>> {
        self.map.get(flow_id)
    }

    /// Get a mutable reference to the flow entry for a given flow, if
    /// one exists.
    pub fn get_mut(
        &mut self,
        flow_id: &InnerFlowId,
    ) -> Option<&mut FlowEntry<S>> {
        self.map.get_mut(flow_id)
    }

    /// Mark all flow table entries as requiring revalidation after a
    /// reset or removal of rules.
    ///
    /// It is typically cheaper to use [`FlowTable::clear`]; dirty entries
    /// will occupy flowtable space until they are denied or expire. As such
    /// this method should be used only when the original state (`S`) *must*
    /// be preserved to ensure correctness.
    pub fn mark_dirty(&mut self) {
        self.map.values_mut().for_each(|v| v.dirty = true);
    }

    pub fn new(
        port: &str,
        name: &str,
        limit: NonZeroU32,
        ttl: Option<Ttl>,
    ) -> FlowTable<S> {
        let ttl = ttl.unwrap_or(FLOW_DEF_TTL);

        Self {
            port_c: CString::new(port).unwrap(),
            name_c: CString::new(name).unwrap(),
            limit,
            ttl,
            map: BTreeMap::new(),
        }
    }

    /// Get the number of flows in this table.
    pub fn num_flows(&self) -> u32 {
        self.map.len() as u32
    }

    pub fn remove(&mut self, flow: &InnerFlowId) -> Option<FlowEntry<S>> {
        self.map.remove(flow)
    }

    pub fn ttl(&self) -> Ttl {
        self.ttl
    }
}

#[allow(unused_variables)]
fn flow_expired_probe(
    port: &CString,
    name: &CString,
    flowid: &InnerFlowId,
    last_hit: Option<Moment>,
    now: Option<Moment>,
) {
    last_hit.unwrap_or_default();
    cfg_if! {
        if #[cfg(all(not(feature = "std"), not(test)))] {
            let arg = flow_id_sdt_arg::from(flowid);

            unsafe {
                __dtrace_probe_flow__expired(
                    port.as_ptr() as uintptr_t,
                    name.as_ptr() as uintptr_t,
                    &arg as *const flow_id_sdt_arg as uintptr_t,
                    last_hit.and_then(|m| m.raw_millis()).unwrap_or_default() as usize,
                    now.and_then(|m| m.raw_millis()).unwrap_or_default() as usize,
                );
            }
        } else if #[cfg(feature = "usdt")] {
            use std::string::ToString;
            let port_s = port.to_str().unwrap();
            let name_s = name.to_str().unwrap();
            crate::opte_provider::flow__expired!(
                || (port_s, name_s, flowid.to_string(), 0, 0)
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
#[derive(Clone, Debug)]
pub struct FlowEntry<S: Dump> {
    state: S,

    /// Number of times this flow has been matched.
    hits: u64,

    /// This tracks the last time the flow was matched.
    last_hit: Moment,

    /// Records whether this flow predates a rule change, and
    /// must rerun rule processing before `state` can be used.
    dirty: bool,
}

impl<S: Dump> FlowEntry<S> {
    fn dump(&self) -> S::DumpVal {
        self.state.dump(self.hits)
    }

    pub fn state_mut(&mut self) -> &mut S {
        &mut self.state
    }

    pub fn state(&self) -> &S {
        &self.state
    }

    pub fn hits(&self) -> u64 {
        self.hits
    }

    pub fn hit(&mut self) {
        self.hits += 1;
        self.last_hit = Moment::now();
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn mark_clean(&mut self) {
        self.dirty = false
    }

    pub fn last_hit(&self) -> &Moment {
        &self.last_hit
    }

    fn is_expired(&self, now: Moment, ttl: Ttl) -> bool {
        ttl.is_expired(self.last_hit, now)
    }

    fn new(state: S) -> Self {
        FlowEntry { state, hits: 0, last_hit: Moment::now(), dirty: false }
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
        flowid: uintptr_t,
        last_hit: uintptr_t,
        now: uintptr_t,
    );

    pub fn __dtrace_probe_ft__entry__invalidated(
        dir: uintptr_t,
        port: uintptr_t,
        layer: uintptr_t,
        ifid: uintptr_t,
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
    use crate::engine::headers::IpAddr;
    use crate::engine::ip4::Protocol;
    use crate::engine::packet::FLOW_ID_DEFAULT;
    use core::time::Duration;

    pub const FT_SIZE: Option<NonZeroU32> = NonZeroU32::new(16);

    #[test]
    fn flow_expired() {
        let flowid = InnerFlowId {
            proto: Protocol::TCP,
            src_ip: IpAddr::Ip4("192.168.2.10".parse().unwrap()),
            src_port: 37890,
            dst_ip: IpAddr::Ip4("76.76.21.21".parse().unwrap()),
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
            proto: Protocol::TCP,
            src_ip: IpAddr::Ip4("192.168.2.10".parse().unwrap()),
            src_port: 37890,
            dst_ip: IpAddr::Ip4("76.76.21.21".parse().unwrap()),
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

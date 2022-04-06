use core::fmt;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::collections::BTreeMap;
        use alloc::string::{String, ToString};
        use alloc::vec::Vec;
        use illumos_ddi_dki::uintptr_t;
        use crate::rule::flow_id_sdt_arg;
    } else {
        use std::collections::BTreeMap;
        use std::string::{String, ToString};
        use std::vec::Vec;
    }
}

use serde::{Deserialize, Serialize};

use opte_core_api::OpteError;

use crate::layer::InnerFlowId;
use crate::time::{Moment, MILLIS};
use crate::CString;

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

#[derive(Debug)]
pub struct FlowTable<S> {
    port_c: CString,
    name_c: CString,
    limit: u32,
    ttl: Ttl,
    map: BTreeMap<InnerFlowId, FlowEntry<S>>,
}

impl<S> FlowTable<S>
where
    S: Clone + fmt::Debug + StateSummary,
{
    /// Add a new entry to the flow table.
    ///
    /// # Errors
    ///
    /// If the table is at max capacity, an error is returned and no
    /// modification is made to the table.
    ///
    /// If an entry already exists for this flow, an error is returned
    /// and no modification is made to the table.
    pub fn add(&mut self, flow_id: InnerFlowId, state: S) -> Result<()> {
        if self.map.len() == self.limit as usize {
            return Err(OpteError::MaxCapacity(self.limit as u64));
        }

        let entry = FlowEntry::new(state);
        match self.map.insert(flow_id.clone(), entry) {
            None => Ok(()),
            Some(_) => return Err(OpteError::FlowExists(flow_id.to_string())),
        }
    }

    // Clear all entries from the flow table.
    pub fn clear(&mut self) {
        self.map.clear()
    }

    pub fn dump(&self) -> Vec<(InnerFlowId, FlowEntryDump)> {
        let mut flows = Vec::with_capacity(self.map.len());
        for (flow_id, entry) in &self.map {
            flows.push((flow_id.clone(), FlowEntryDump::from(entry)));
        }
        flows
    }

    pub fn expire_flows(&mut self, now: Moment) {
        let name_c = &self.name_c;
        let port_c = &self.port_c;
        let ttl = self.ttl;

        self.map.retain(|flowid, state| {
            if state.is_expired(now, ttl) {
                flow_expired_probe(port_c, name_c, flowid);
                return false;
            }

            true
        });
    }

    /// Get the maximum number of entries this flow table may hold.
    pub fn get_limit(&self) -> u32 {
        self.limit
    }

    pub fn get_mut(
        &mut self,
        flow_id: &InnerFlowId,
    ) -> Option<&mut FlowEntry<S>> {
        self.map.get_mut(flow_id)
    }

    pub fn new(
        port: &str,
        name: &str,
        limit: Option<u32>,
        ttl: Option<Ttl>,
    ) -> FlowTable<S> {
        let limit = limit.unwrap_or(FLOW_TABLE_DEF_MAX_ENTRIES);
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

    pub fn ttl(&self) -> Ttl {
        self.ttl
    }
}

fn flow_expired_probe(port: &CString, name: &CString, flowid: &InnerFlowId) {
    cfg_if! {
        if #[cfg(all(not(feature = "std"), not(test)))] {
            let arg = flow_id_sdt_arg::from(flowid);

            unsafe {
                __dtrace_probe_flow__expired(
                    port.as_ptr() as uintptr_t,
                    name.as_ptr() as uintptr_t,
                    &arg as *const flow_id_sdt_arg as uintptr_t,
                );
            }
        } else if #[cfg(feature = "usdt")] {
            use std::arch::asm;

            let port_s = port.to_str().unwrap();
            let name_s = name.to_str().unwrap();
            crate::opte_provider::flow__expired!(
                || (port_s, name_s, flowid.to_string())
            );
        } else {
            let (_, _, _) = (port, name, flowid);
        }
    }
}

/// The FlowEntry holds any arbitrary state type `S`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FlowEntry<S> {
    state: S,

    // Number of times this flow has been matched.
    hits: u64,

    // This tracks the last time the flow was matched.
    #[serde(skip)]
    last_hit: Moment,
}

impl<S> FlowEntry<S> {
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

    pub fn last_hit(&self) -> &Moment {
        &self.last_hit
    }

    fn is_expired(&self, now: Moment, ttl: Ttl) -> bool {
        ttl.is_expired(self.last_hit, now)
    }

    fn new(state: S) -> Self {
        FlowEntry { state, hits: 0, last_hit: Moment::now() }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FlowEntryDump {
    pub hits: u64,
    pub state_summary: String,
}

pub trait StateSummary {
    fn summary(&self) -> String;
}

impl<S: StateSummary> From<&FlowEntry<S>> for FlowEntryDump {
    fn from(entry: &FlowEntry<S>) -> Self {
        FlowEntryDump { hits: entry.hits, state_summary: entry.state.summary() }
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
extern "C" {
    pub fn __dtrace_probe_flow__expired(
        port: uintptr_t,
        layer: uintptr_t,
        flowid: uintptr_t,
    );
}

impl StateSummary for () {
    fn summary(&self) -> String {
        "()".to_string()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::headers::IpAddr;
    use crate::ip4::Protocol;
    use core::time::Duration;

    #[test]
    fn flow_exists() {
        let flowid = InnerFlowId {
            proto: Protocol::TCP,
            src_ip: IpAddr::Ip4("192.168.2.10".parse().unwrap()),
            src_port: 37890,
            dst_ip: IpAddr::Ip4("76.76.21.21".parse().unwrap()),
            dst_port: 443,
        };

        let mut ft = FlowTable::new("port", "flow-expired-test", None, None);
        assert_eq!(ft.num_flows(), 0);
        ft.add(flowid.clone(), ()).unwrap();
        assert_eq!(ft.num_flows(), 1);
        assert!(ft.add(flowid, ()).is_err());
    }

    #[test]
    fn flow_expired() {
        let flowid = InnerFlowId {
            proto: Protocol::TCP,
            src_ip: IpAddr::Ip4("192.168.2.10".parse().unwrap()),
            src_port: 37890,
            dst_ip: IpAddr::Ip4("76.76.21.21".parse().unwrap()),
            dst_port: 443,
        };

        let mut ft = FlowTable::new("port", "flow-expired-test", None, None);
        assert_eq!(ft.num_flows(), 0);
        ft.add(flowid, ()).unwrap();
        let now = Moment::now();
        assert_eq!(ft.num_flows(), 1);
        ft.expire_flows(now);
        assert_eq!(ft.num_flows(), 1);
        ft.expire_flows(now + Duration::new(FLOW_DEF_EXPIRE_SECS as u64, 0));
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

        let mut ft = FlowTable::new("port", "flow-clear-test", None, None);
        assert_eq!(ft.num_flows(), 0);
        ft.add(flowid, ()).unwrap();
        assert_eq!(ft.num_flows(), 1);
        ft.clear();
        assert_eq!(ft.num_flows(), 0);
    }
}

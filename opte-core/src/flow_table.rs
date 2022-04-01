use core::fmt;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::{String, ToString};
        use alloc::vec::Vec;
        use illumos_ddi_dki::{gethrtime, hrtime_t, uintptr_t};
        use crate::rule::flow_id_sdt_arg;
    } else {
        use std::string::{String, ToString};
        use std::time::{Duration, Instant};
        use std::vec::Vec;
    }
}

use serde::{Deserialize, Serialize};

use crate::layer::InnerFlowId;
use crate::CString;

pub const FLOW_DEF_EXPIRE_SECS: u32 = 60;
pub const FLOW_TABLE_DEF_MAX_ENTRIES: u32 = 8192;

#[derive(Debug)]
pub struct FlowTable<S> {
    port_c: CString,
    name_c: CString,
    limit: u32,

    // XXX I originally commented this out because I thought it was
    // causing a double fault that I was seeing, but the DFs were
    // actually being caused by blowing the kernel stack. Go ahead and
    // reinstate the BTreeMap.
    //
    // map: BTreeMap<FlowId, FlowState>,
    map: Vec<(InnerFlowId, FlowEntry<S>)>,
}

impl<S> FlowTable<S>
where
    S: Clone + fmt::Debug + StateSummary,
{
    pub fn add(&mut self, flow_id: InnerFlowId, state: S) {
        if self.map.len() == self.limit as usize {
            todo!("return error indicating max capacity");
        }

        let entry = FlowEntry::new(state);
        self.map.push((flow_id, entry));
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

    #[cfg(all(not(feature = "std"), not(test)))]
    pub fn expire_flows(&mut self, now: hrtime_t) {
        let name_c = &self.name_c;
        let port_c = &self.port_c;

        self.map.retain(|(flowid, state)| {
            #[cfg(any(feature = "std", test))]
            let now = Instant::now();

            if state.is_expired(now) {
                flow_expired_probe(port_c, name_c, flowid);
                return false;
            }

            true
        });
    }

    #[cfg(any(feature = "std", test))]
    pub fn expire_flows(&mut self, now: Instant) {
        let name_c = &self.name_c;
        let port_c = &self.port_c;

        self.map.retain(|(flowid, state)| {
            if state.is_expired(now) {
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

    pub fn get(
        &self,
        flow_id: &InnerFlowId,
    ) -> Option<&(InnerFlowId, FlowEntry<S>)> {
        for (i, (k, _v)) in self.map.iter().enumerate() {
            if k == flow_id {
                return self.map.get(i);
            }
        }

        None
    }

    pub fn get_mut(
        &mut self,
        flow_id: &InnerFlowId,
    ) -> Option<&mut (InnerFlowId, FlowEntry<S>)> {
        for (i, (k, _v)) in self.map.iter().enumerate() {
            if k == flow_id {
                return self.map.get_mut(i);
            }
        }

        None
    }

    pub fn new(port: &str, name: &str, limit: Option<u32>) -> FlowTable<S> {
        let limit = limit.unwrap_or(FLOW_TABLE_DEF_MAX_ENTRIES);
        FlowTable {
            port_c: CString::new(port).unwrap(),
            name_c: CString::new(name).unwrap(),
            limit,
            map: Vec::with_capacity(limit as usize),
        }
    }

    /// Get the number of flows in this table.
    pub fn num_flows(&self) -> u32 {
        self.map.len() as u32
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

#[cfg(any(feature = "std", test))]
fn instant_default() -> Instant {
    Instant::now()
}

/// The FlowEntry holds any arbitrary state type `S`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FlowEntry<S> {
    state: S,

    // Number of times this flow has been matched.
    hits: u64,

    // Expiration is based on a monotonic time source (like hrtime).
    // It contains the number of seconds after which this flow should
    // be considered expired.
    #[cfg(all(not(feature = "std"), not(test)))]
    #[serde(skip)]
    ttl: u32,
    #[cfg(any(feature = "std", test))]
    #[serde(skip)]
    ttl: Duration,

    // This tracks the last time the flow was matched.
    #[cfg(all(not(feature = "std"), not(test)))]
    #[serde(skip)]
    last_hit: hrtime_t,
    #[cfg(any(feature = "std", test))]
    #[serde(skip)]
    // TODO Not sure why I had to supply default here when I already
    // marked it as skip, but the compiler complained about `Instant`
    // not implementing `Default`.
    #[serde(default = "instant_default")]
    last_hit: Instant,
}

impl<S> FlowEntry<S> {
    pub fn get_state_mut(&mut self) -> &mut S {
        &mut self.state
    }

    pub fn get_state(&self) -> &S {
        &self.state
    }

    pub fn get_hits(&self) -> u64 {
        self.hits
    }

    #[cfg(all(not(feature = "std"), not(test)))]
    pub fn hit(&mut self) {
        self.hits += 1;
        unsafe {
            self.last_hit = gethrtime();
        }
    }

    #[cfg(any(feature = "std", test))]
    pub fn hit(&mut self) {
        self.hits += 1;
        self.last_hit = Instant::now();
    }

    #[cfg(all(not(feature = "std"), not(test)))]
    fn is_expired(&self, now: hrtime_t) -> bool {
        ((now - self.last_hit) / 1_000_000_000) > self.ttl.into()
    }

    #[cfg(any(feature = "std", test))]
    fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.last_hit) >= self.ttl
    }

    fn new(state: S) -> Self {
        FlowEntry {
            state,
            hits: 0,

            #[cfg(all(not(feature = "std"), not(test)))]
            ttl: FLOW_DEF_EXPIRE_SECS,
            #[cfg(any(feature = "std", test))]
            ttl: Duration::new(FLOW_DEF_EXPIRE_SECS as u64, 0),

            #[cfg(all(not(feature = "std"), not(test)))]
            last_hit: unsafe { gethrtime() },
            #[cfg(any(feature = "std", test))]
            last_hit: Instant::now(),
        }
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

#[test]
fn flow_expired() {
    use crate::headers::IpAddr;
    use crate::ip4::Protocol;

    let flowid = InnerFlowId {
        proto: Protocol::TCP,
        src_ip: IpAddr::Ip4("192.168.2.10".parse().unwrap()),
        src_port: 37890,
        dst_ip: IpAddr::Ip4("76.76.21.21".parse().unwrap()),
        dst_port: 443,
    };

    let mut ft = FlowTable::new("port", "flow-expired-test", None);

    assert_eq!(ft.num_flows(), 0);
    ft.add(flowid, ());
    let now = Instant::now();
    assert_eq!(ft.num_flows(), 1);
    ft.expire_flows(now);
    assert_eq!(ft.num_flows(), 1);
    ft.expire_flows(now + Duration::new(FLOW_DEF_EXPIRE_SECS as u64, 0));
    assert_eq!(ft.num_flows(), 0);
}

#[test]
fn flow_clear() {
    use crate::headers::IpAddr;
    use crate::ip4::Protocol;

    let flowid = InnerFlowId {
        proto: Protocol::TCP,
        src_ip: IpAddr::Ip4("192.168.2.10".parse().unwrap()),
        src_port: 37890,
        dst_ip: IpAddr::Ip4("76.76.21.21".parse().unwrap()),
        dst_port: 443,
    };

    let mut ft = FlowTable::new("port", "flow-clear-test", None);

    assert_eq!(ft.num_flows(), 0);
    ft.add(flowid, ());
    assert_eq!(ft.num_flows(), 1);
    ft.clear();
    assert_eq!(ft.num_flows(), 0);
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Flow stat objects modified and tracked as rules and entries are used.

use crate::api::InnerFlowId;
use crate::ddi::sync::KRwLock;
use crate::ddi::sync::KRwLockType;
use crate::ddi::time::Moment;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::collections::btree_map::Entry;
use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use opte_api::Direction;
use opte_api::FlowStat as ApiFlowStat;
use opte_api::FullCounter as ApiFullCounter;
use opte_api::PacketCounter as ApiPktCounter;
use opte_api::TcpState;
use uuid::Uuid;

/// Opaque identifier for tracking unique stat objects.
#[derive(Copy, Clone, Hash, PartialEq, PartialOrd, Eq, Ord)]
pub struct StatId(u64);

pub struct FlowStat {
    /// The direction of this flow half.
    pub dir: Direction,
    /// The other half of this flow.
    pub partner: InnerFlowId,
    /// `TableStat`s to whom we must return our own `stats`.
    pub parents: Vec<Arc<TableStat>>,
    /// The cached list of IDs of root `TableStat` entries.
    pub bases: BTreeSet<Uuid>,

    /// Actual stats associated with this flow.
    pub shared: Arc<SharedFlowStat>,

    /// When was this flow last updated?
    pub last_hit: AtomicU64,
}

pub struct SharedFlowStat {
    /// Actual stats associated with this flow.
    pub stats: PacketCounter,

    /// Tcp?
    ///
    /// Yeah this needs some rework wrt today...
    pub tcp: Option<TcpState>,

    /// パケットはどちらにきましたか。
    pub first_dir: Direction,
}

impl From<&FlowStat> for ApiFlowStat<InnerFlowId> {
    fn from(value: &FlowStat) -> Self {
        ApiFlowStat {
            partner: value.partner,
            dir: value.dir,
            bases: value.bases.iter().copied().collect(),
            stats: (&value.shared.stats).into(),
        }
    }
}

pub struct TableStat {
    pub id: Option<Uuid>,

    pub parents: Vec<Arc<TableStat>>,
    pub children: KRwLock<Vec<Weak<dyn FoldStat>>>,

    /// The actual stats!
    pub stats: Arc<FullCounter>,

    /// When was this flow last updated?
    pub last_hit: AtomicU64,
}

pub struct PacketCounter {
    pub id: StatId,

    pub pkts_in: AtomicU64,
    pub bytes_in: AtomicU64,
    pub pkts_out: AtomicU64,
    pub bytes_out: AtomicU64,
}

impl From<&PacketCounter> for ApiPktCounter {
    fn from(val: &PacketCounter) -> Self {
        ApiPktCounter {
            pkts_in: val.pkts_in.load(Ordering::Relaxed),
            bytes_in: val.bytes_in.load(Ordering::Relaxed),
            pkts_out: val.pkts_out.load(Ordering::Relaxed),
            bytes_out: val.bytes_out.load(Ordering::Relaxed),
        }
    }
}

pub struct FullCounter {
    pub allow: AtomicU64,
    pub deny: AtomicU64,
    pub hairpin: AtomicU64,
    pub packets: PacketCounter,
}

impl From<&FullCounter> for ApiFullCounter {
    fn from(val: &FullCounter) -> Self {
        ApiFullCounter {
            packets: (&val.packets).into(),
            allow: val.allow.load(Ordering::Relaxed),
            deny: val.deny.load(Ordering::Relaxed),
            hairpin: val.hairpin.load(Ordering::Relaxed),
        }
    }
}

pub trait FoldStat: Send + Sync {
    fn fold(&self, into: &FullCounter, visited: &mut BTreeSet<StatId>);
}

impl FoldStat for FlowStat {
    fn fold(&self, into: &FullCounter, visited: &mut BTreeSet<StatId>) {
        if !visited.insert(self.shared.stats.id) {
            self.shared.stats.combine(&into.packets);
        }
    }
}

impl FoldStat for TableStat {
    fn fold(&self, into: &FullCounter, visited: &mut BTreeSet<StatId>) {
        if !visited.insert(self.stats.id()) {
            self.stats.combine(into);
        }
    }
}

impl PacketCounter {
    fn combine(&self, into: &Self) {
        into.pkts_in
            .fetch_add(self.pkts_in.load(Ordering::Relaxed), Ordering::Relaxed);
        into.bytes_in.fetch_add(
            self.bytes_in.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        into.pkts_out.fetch_add(
            self.pkts_out.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        into.bytes_out.fetch_add(
            self.bytes_out.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
    }
}

impl FullCounter {
    fn combine(&self, into: &Self) {
        into.packets.combine(&self.packets);
        into.allow
            .fetch_add(self.allow.load(Ordering::Relaxed), Ordering::Relaxed);
        into.deny
            .fetch_add(self.deny.load(Ordering::Relaxed), Ordering::Relaxed);
        into.hairpin
            .fetch_add(self.hairpin.load(Ordering::Relaxed), Ordering::Relaxed);
    }

    #[inline]
    fn id(&self) -> StatId {
        self.packets.id
    }
}

/// Tracking/handling of all stats.
///
/// ?? Describe?
#[derive(Default)]
pub struct StatTree {
    next_id: u64,
    roots: BTreeMap<Uuid, Arc<TableStat>>,
    intermediate: Vec<Arc<TableStat>>,
    flows: BTreeMap<InnerFlowId, Arc<FlowStat>>,
}

impl StatTree {
    fn get_id(&mut self) -> StatId {
        let out = self.next_id;
        self.next_id += 1;
        StatId(out)
    }

    fn pkt_counter(&mut self) -> PacketCounter {
        PacketCounter {
            id: self.get_id(),
            pkts_in: 0.into(),
            bytes_in: 0.into(),
            pkts_out: 0.into(),
            bytes_out: 0.into(),
        }
    }

    fn full_counter(&mut self) -> FullCounter {
        FullCounter {
            allow: 0.into(),
            deny: 0.into(),
            hairpin: 0.into(),
            packets: self.pkt_counter(),
        }
    }

    pub fn new_root(&mut self) -> Arc<TableStat> {
        // TODO: RNG in illumos kernel?
        let uuid = Uuid::from_u64_pair(0, self.next_id);
        self.new_root_with_id(uuid)
    }

    pub fn new_root_with_id(&mut self, uuid: Uuid) -> Arc<TableStat> {
        let mut children = KRwLock::new(vec![]);
        children.init(KRwLockType::Driver);

        let out = Arc::new(TableStat {
            id: Some(uuid),
            parents: vec![],
            children,
            stats: self.full_counter().into(),
            last_hit: Moment::now().raw().into(),
        });

        // TODO: what if already exists?!
        let _ = self.roots.insert(uuid, out.clone());

        out
    }

    pub fn new_intermediate(
        &mut self,
        parents: Vec<Arc<TableStat>>,
    ) -> Arc<TableStat> {
        let mut children = KRwLock::new(vec![]);
        children.init(KRwLockType::Driver);

        let out = Arc::new(TableStat {
            id: None,
            parents,
            children,
            stats: self.full_counter().into(),
            last_hit: Moment::now().raw().into(),
        });

        for parent in &out.parents {
            let mut p_children = parent.children.write();
            let weak = Arc::downgrade(&out);
            p_children.push(weak);
        }

        self.intermediate.push(out.clone());

        out
    }

    pub fn new_flow(
        &mut self,
        flow_id: &InnerFlowId,
        partner_flow: &InnerFlowId,
        dir: Direction,
        parents: Vec<Arc<TableStat>>,
    ) -> Arc<FlowStat> {
        if let Entry::Occupied(e) = self.flows.entry(*flow_id) {
            // TODO: what to do with (maybe new) parents & bases?!
            return e.get().clone();
        }

        let bases = get_base_ids(&parents);

        let out = match self.flows.entry(*partner_flow) {
            // Miss, but existing partner.
            Entry::Occupied(partner) => Arc::new(FlowStat {
                dir,
                partner: *partner_flow,
                parents,
                bases,
                shared: partner.get().shared.clone(),
                last_hit: Moment::now().raw().into(),
            }),
            // Miss, no partner.
            Entry::Vacant(_) => {
                Arc::new(FlowStat {
                    dir,
                    partner: *partner_flow,
                    parents,
                    bases,
                    shared: Arc::new(SharedFlowStat {
                        stats: self.pkt_counter(),
                        // TODO
                        tcp: None,
                        first_dir: dir,
                    }),
                    last_hit: Moment::now().raw().into(),
                })
            }
        };

        self.flows
            .insert(*flow_id, out)
            .expect("Proven a miss on flow_id already")
            .clone()
    }
}

fn get_base_ids(parents: &[Arc<TableStat>]) -> BTreeSet<Uuid> {
    let mut out = BTreeSet::new();

    let mut work_set = parents.to_vec();
    while let Some(el) = work_set.pop() {
        work_set.extend_from_slice(&el.parents);
        if let Some(id) = el.id {
            out.insert(id);
        }
    }

    out
}

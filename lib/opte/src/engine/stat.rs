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

// TODO EXPIRY
// TODO DELETION

/// Opaque identifier for tracking unique stat objects.
#[derive(Copy, Clone, Hash, PartialEq, PartialOrd, Eq, Ord, Debug)]
pub struct StatId(u64);

impl StatId {
    fn new(val: &mut u64) -> Self {
        let out = *val;
        *val += 1;
        StatId(out)
    }
}

/// Reduced form of an action for stats tracking purposes.
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Ord, Eq, Hash, Default)]
pub enum Action {
    #[default]
    Allow,
    Deny,
    Hairpin,
}

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

impl FlowStat {
    pub fn hit(&self, pkt_size: u64) {
        self.hit_at(pkt_size, Moment::now());
    }

    pub fn hit_at(&self, pkt_size: u64, time: Moment) {
        self.last_hit.store(time.raw(), Ordering::Relaxed);
        self.shared.stats.hit(self.dir, pkt_size);
    }
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
    pub stats: FullCounter,

    /// When was this flow last updated?
    pub last_hit: AtomicU64,
}

impl core::fmt::Debug for TableStat {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!()
    }
}

impl TableStat {
    /// Allow a packet which will track local stats via a UFT entry.
    pub fn allow(&self) {
        self.allow_at(Moment::now());
    }

    /// Allow a packet (at a given timestamp) which will track local stats via
    /// a UFT entry.
    pub fn allow_at(&self, time: Moment) {
        self.last_hit.store(time.raw(), Ordering::Relaxed);
        self.stats.allow.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an action for a packet which will ultimately be dropped or
    /// hairpinned.
    pub fn act(&self, action: Action, pkt_size: u64, direction: Direction) {
        self.act_at(action, pkt_size, direction, Moment::now());
    }

    /// Record an action for a packet (at a given time) which will ultimately
    /// be dropped or hairpinned.
    pub fn act_at(
        &self,
        action: Action,
        pkt_size: u64,
        direction: Direction,
        time: Moment,
    ) {
        self.last_hit.store(time.raw(), Ordering::Relaxed);
        self.stats.packets.hit(direction, pkt_size);
        let stat = match action {
            Action::Allow => &self.stats.allow,
            Action::Deny => &self.stats.deny,
            Action::Hairpin => &self.stats.hairpin,
        };
        stat.fetch_add(1, Ordering::Relaxed);
    }
}

pub struct PacketCounter {
    pub id: StatId,

    pub pkts_in: AtomicU64,
    pub bytes_in: AtomicU64,
    pub pkts_out: AtomicU64,
    pub bytes_out: AtomicU64,
}

impl PacketCounter {
    fn from_next_id(id: &mut u64) -> PacketCounter {
        PacketCounter {
            id: StatId::new(id),
            pkts_in: 0.into(),
            bytes_in: 0.into(),
            pkts_out: 0.into(),
            bytes_out: 0.into(),
        }
    }

    #[inline]
    fn hit(&self, direction: Direction, pkt_size: u64) {
        let (pkts, bytes) = match direction {
            Direction::In => (&self.pkts_in, &self.bytes_in),
            Direction::Out => (&self.pkts_out, &self.bytes_out),
        };
        pkts.fetch_add(1, Ordering::Relaxed);
        bytes.fetch_add(pkt_size, Ordering::Relaxed);
    }

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

impl FullCounter {
    fn from_next_id(id: &mut u64) -> FullCounter {
        FullCounter {
            allow: 0.into(),
            deny: 0.into(),
            hairpin: 0.into(),
            packets: PacketCounter::from_next_id(id),
        }
    }

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
    /// Gets or creates the root stat for a given UUID.
    ///
    /// Allocates a new UUID if none is provided.
    pub fn root(&mut self, uuid: Option<Uuid>) -> Arc<TableStat> {
        let uuid = uuid.unwrap_or_else(|| Uuid::from_u64_pair(0, self.next_id));
        let ids = &mut self.next_id;

        self.roots
            .entry(uuid)
            .or_insert_with_key(|id| {
                let mut children = KRwLock::new(vec![]);
                children.init(KRwLockType::Driver);

                Arc::new(TableStat {
                    id: Some(*id),
                    parents: vec![],
                    children,
                    stats: FullCounter::from_next_id(ids),
                    last_hit: Moment::now().raw().into(),
                })
            })
            .clone()
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
            stats: FullCounter::from_next_id(&mut self.next_id),
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
            //       I *think* these should win out, insert, and preserve
            //       the old stats. Need to think about it.
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
                        stats: PacketCounter::from_next_id(&mut self.next_id),
                        // TODO
                        tcp: None,
                        first_dir: dir,
                    }),
                    last_hit: Moment::now().raw().into(),
                })
            }
        };

        // Proven a miss on flow_id already
        let _ = self.flows.insert(*flow_id, out.clone());
        out
    }

    #[cfg(test)]
    pub fn dump(&self) -> String {
        let mut out = String::new();
        out.push_str("Roots\n");
        for (id, root) in &self.roots {
            let d = ApiFullCounter::from(&root.stats);
            out.push_str(&format!("\t{:?}/{id} -> {d:?}\n", root.stats.id()));
        }
        out.push_str("Ints\n");
        for root in &self.intermediate {
            let d = ApiFullCounter::from(&root.stats);
            out.push_str(&format!("\t{:?} -> {d:?}\n", root.stats.id()));
        }
        out.push_str("Flows\n");
        for (id, stat) in &self.flows {
            let d: ApiFlowStat<InnerFlowId> = stat.as_ref().into();
            out.push_str(&format!(
                "\t{}/{}/{:?} -> {d:?}\n",
                id, stat.dir, stat.shared.stats.id
            ));
        }
        out
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

/// XXX holds stats as they arrive on a packet.
pub struct FlowStatBuilder {
    parents: Vec<Arc<TableStat>>,
    layer_end: usize,
}

impl FlowStatBuilder {
    pub fn new() -> Self {
        Self {
            // TODO: do we want this cfg'able?
            parents: Vec::with_capacity(16),
            layer_end: 0,
        }
    }

    /// Push a parent onto this flow.
    pub fn push(&mut self, parent: Arc<TableStat>) {
        self.parents.push(parent);
    }

    /// Mark all current parents as [`Action::Allow`].
    pub fn new_layer(&mut self) {
        self.layer_end = self.parents.len();
    }

    /// Return a list of stat parents if this packet is bound for flow creation.
    pub fn terminate(
        &mut self,
        action: Action,
        pkt_size: u64,
        direction: Direction,
        create_flow: bool,
    ) -> Option<Vec<Arc<TableStat>>> {
        match action {
            Action::Allow if create_flow => {
                self.parents.iter().for_each(|v| v.allow());
                // TODO: should *take*?
                Some(self.parents.clone())
            }
            Action::Allow => {
                self.parents
                    .iter()
                    .for_each(|v| v.act(action, pkt_size, direction));
                None
            }
            Action::Deny | Action::Hairpin => {
                let (accepted, last_layer) =
                    self.parents.split_at(self.layer_end);
                accepted
                    .iter()
                    .for_each(|v| v.act(Action::Allow, pkt_size, direction));
                last_layer
                    .iter()
                    .for_each(|v| v.act(action, pkt_size, direction));

                None
            }
        }
    }
}

impl Default for FlowStatBuilder {
    fn default() -> Self {
        Self::new()
    }
}

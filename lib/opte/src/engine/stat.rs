// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Flow stat objects modified and tracked as rules and entries are used.

use crate::api::InnerFlowId;
use crate::ddi::sync::KRwLock;
use crate::ddi::time::Moment;
use crate::engine::flow_table::Ttl;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::collections::btree_map::Entry;
use alloc::string::String;
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

// TODO DELETION ON FLOW CLOSE [and holding onto 'dead flows']

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
    pub parents: Box<[StatParent]>,
    /// The cached list of IDs of reachable `RootStat` entries.
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

#[derive(Clone, Debug)]
pub enum StatParent {
    Root(Arc<RootStat>),
    Intermediate(Arc<IntermediateStat>),
}

impl From<Arc<RootStat>> for StatParent {
    fn from(value: Arc<RootStat>) -> Self {
        Self::Root(value)
    }
}

impl From<Arc<IntermediateStat>> for StatParent {
    fn from(value: Arc<IntermediateStat>) -> Self {
        Self::Intermediate(value)
    }
}

impl StatParent {
    fn parents(&self) -> &[StatParent] {
        match self {
            Self::Root(_) => &[],
            Self::Intermediate(i) => &i.parents,
        }
    }

    fn global_id(&self) -> StatId {
        self.inner().stats.id()
    }

    fn root_id(&self) -> Option<&Uuid> {
        match self {
            Self::Root(r) => Some(&r.id),
            Self::Intermediate(_) => None,
        }
    }

    fn inner(&self) -> &TableStat {
        match self {
            Self::Root(r) => &r.body,
            Self::Intermediate(i) => &i.body,
        }
    }

    /// Allow a packet which will track local stats via a UFT entry.
    pub fn allow(&self) {
        self.inner().allow();
    }

    /// Allow a packet (at a given timestamp) which will track local stats via
    /// a UFT entry.
    pub fn allow_at(&self, time: Moment) {
        self.inner().allow_at(time);
    }

    /// Record an action for a packet which will ultimately be dropped or
    /// hairpinned.
    pub fn act(&self, action: Action, pkt_size: u64, direction: Direction) {
        self.inner().act(action, pkt_size, direction);
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
        self.inner().act_at(action, pkt_size, direction, time);
    }

    /// Add a weak child reference to this stat object.
    pub fn append_child(&self, child: impl Into<StatChild>) {
        let mut p_children = self.inner().children.write();
        p_children.push(child.into());
    }
}

#[derive(Clone, Debug)]
pub enum StatChild {
    Intermediate(Weak<IntermediateStat>),
    Flow(Weak<FlowStat>),
}

impl From<&Arc<IntermediateStat>> for StatChild {
    fn from(value: &Arc<IntermediateStat>) -> Self {
        Self::Intermediate(Arc::downgrade(value))
    }
}

impl From<&Arc<FlowStat>> for StatChild {
    fn from(value: &Arc<FlowStat>) -> Self {
        Self::Flow(Arc::downgrade(value))
    }
}

#[derive(Debug)]
pub struct RootStat {
    pub id: Uuid,
    body: TableStat,
}

#[derive(Debug)]
pub struct IntermediateStat {
    pub parents: Box<[StatParent]>,
    body: TableStat,
}

struct TableStat {
    /// A list of other stat-related objects who name this table
    /// stat as one of its parents.
    children: KRwLock<Vec<StatChild>>,

    /// The actual stats!
    stats: FullCounter,

    /// When was this flow last updated?
    last_hit: AtomicU64,
}

impl core::fmt::Debug for TableStat {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!()
    }
}

impl TableStat {
    fn allow(&self) {
        self.allow_at(Moment::now());
    }

    fn allow_at(&self, time: Moment) {
        self.last_hit.store(time.raw(), Ordering::Relaxed);
        self.stats.allow.fetch_add(1, Ordering::Relaxed);
    }

    fn act(&self, action: Action, pkt_size: u64, direction: Direction) {
        self.act_at(action, pkt_size, direction, Moment::now());
    }

    fn act_at(
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
    pub created_at: Moment,

    pub pkts_in: AtomicU64,
    pub bytes_in: AtomicU64,
    pub pkts_out: AtomicU64,
    pub bytes_out: AtomicU64,
}

impl PacketCounter {
    fn from_next_id(id: &mut u64) -> PacketCounter {
        PacketCounter {
            id: StatId::new(id),
            created_at: Moment::now(),

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
            created_at: val.created_at.raw(),
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

impl FoldStat for IntermediateStat {
    fn fold(&self, into: &FullCounter, visited: &mut BTreeSet<StatId>) {
        if !visited.insert(self.body.stats.id()) {
            self.body.stats.combine(into);
        }
    }
}

impl FoldStat for RootStat {
    fn fold(&self, into: &FullCounter, visited: &mut BTreeSet<StatId>) {
        if !visited.insert(self.body.stats.id()) {
            self.body.stats.combine(into);
        }
    }
}

/// Tracking/handling of all stats.
///
/// ?? Describe?
#[derive(Default)]
pub struct StatTree {
    next_id: u64,
    roots: BTreeMap<Uuid, Arc<RootStat>>,
    intermediate: Vec<Arc<IntermediateStat>>,
    flows: BTreeMap<InnerFlowId, Arc<FlowStat>>,
}

impl StatTree {
    /// Gets or creates the root stat for a given UUID.
    ///
    /// Allocates a new UUID if none is provided.
    pub fn root(&mut self, uuid: Option<Uuid>) -> Arc<RootStat> {
        let uuid = uuid.unwrap_or_else(|| Uuid::from_u64_pair(0, self.next_id));
        let ids = &mut self.next_id;

        self.roots
            .entry(uuid)
            .or_insert_with(|| {
                Arc::new(RootStat {
                    id: uuid,
                    body: TableStat {
                        children: KRwLock::new(vec![]),
                        stats: FullCounter::from_next_id(ids),
                        last_hit: Moment::now().raw().into(),
                    },
                })
            })
            .clone()
    }

    pub fn new_intermediate(
        &mut self,
        parents: Vec<StatParent>,
    ) -> Arc<IntermediateStat> {
        let out = Arc::new(IntermediateStat {
            parents: parents.into(),
            body: TableStat {
                children: KRwLock::new(vec![]),
                stats: FullCounter::from_next_id(&mut self.next_id),
                last_hit: Moment::now().raw().into(),
            },
        });

        for parent in &out.parents {
            parent.append_child(&out);
        }

        self.intermediate.push(out.clone());

        out
    }

    pub fn new_flow(
        &mut self,
        flow_id: &InnerFlowId,
        partner_flow: &InnerFlowId,
        dir: Direction,
        parents: Vec<StatParent>,
    ) -> Arc<FlowStat> {
        if let Entry::Occupied(e) = self.flows.entry(*flow_id) {
            // TODO: what to do with (maybe new) parents & bases?!
            //       I *think* these should win out, insert, and preserve
            //       the old stats. Need to think about it.
            return e.get().clone();
        }

        let parents = parents.into_boxed_slice();
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

        for parent in &out.parents {
            parent.append_child(&out);
        }

        // Proven a miss on flow_id already
        let _ = self.flows.insert(*flow_id, out.clone());
        out
    }

    pub fn expire(&mut self, now: Moment) {
        const EXPIRY_WINDOW: Ttl = Ttl::new_seconds(10);
        // Root removal and re-entry? Don't want any gaps.
        const ROOT_EXPIRY_WINDOW: Ttl = Ttl::new_seconds(100);

        #[derive(Default, Eq, PartialEq)]
        enum Liveness {
            #[default]
            NotSeen,
            SeenKeep,
            Seen(InnerFlowId),
        }

        #[derive(Default)]
        struct JointLive {
            lhs: Liveness,
            rhs: Liveness,
        }

        // Flows -- need to account for shared component between arc'd things.
        let mut possibly_expired: BTreeMap<StatId, JointLive> = BTreeMap::new();
        for (k, v) in &self.flows {
            let t_hit =
                Moment::from_raw_nanos(v.last_hit.load(Ordering::Relaxed));
            let can_remove = EXPIRY_WINDOW.is_expired(t_hit, now)
                && Arc::strong_count(v) == 1;
            let base_id = v.shared.stats.id;
            let el = possibly_expired.entry(base_id).or_default();
            match (v.dir, can_remove) {
                (Direction::In, false) => {
                    el.lhs = Liveness::SeenKeep;
                }
                (Direction::Out, false) => {
                    el.rhs = Liveness::SeenKeep;
                }
                (Direction::In, true) => {
                    el.lhs = Liveness::Seen(*k);
                }
                (Direction::Out, true) => {
                    el.rhs = Liveness::Seen(*k);
                }
            }
        }
        for v in possibly_expired.values() {
            let cannot_remove = v.lhs == Liveness::SeenKeep
                || v.rhs == Liveness::SeenKeep
                || (v.lhs == Liveness::NotSeen && v.rhs == Liveness::NotSeen);
            if cannot_remove {
                continue;
            }

            #[allow(clippy::mutable_key_type)]
            let mut parents: BTreeSet<ById> = Default::default();
            let mut base_stats = None;
            if let Liveness::Seen(id) = v.lhs {
                if let Some(flow) = self.flows.remove(&id) {
                    let flow = Arc::into_inner(flow)
                        .expect("strong count 1 is enforced above");
                    for p_id in flow.parents {
                        parents.insert(ById(p_id));
                    }
                    base_stats = Some(flow.shared);
                }
            }
            if let Liveness::Seen(id) = v.rhs {
                if let Some(flow) = self.flows.remove(&id) {
                    let flow = Arc::into_inner(flow)
                        .expect("strong count 1 is enforced above");
                    for p_id in flow.parents {
                        parents.insert(ById(p_id));
                    }
                    base_stats = Some(flow.shared);
                }
            }

            // At long last, combine!
            let base_stats =
                base_stats.expect("should not have no parent here!!");
            for parent in parents {
                base_stats.stats.combine(&parent.0.inner().stats.packets);
            }
        }

        // Intermediates.
        self.intermediate.retain(|v| {
            // Time is... not relevant here. The LFTs are GONE.
            if Arc::strong_count(v) == 1 {
                for p in &v.parents {
                    v.body.stats.combine(&p.inner().stats);
                }
                false
            } else {
                true
            }
        });

        // Roots may need to be held onto for some time in case rules with the
        // same ID come and go in adjacent control plane operations...
        self.roots.retain(|_, v| {
            let t_hit =
                Moment::from_raw_nanos(v.body.last_hit.load(Ordering::Relaxed));
            Arc::strong_count(v) > 1
                || !ROOT_EXPIRY_WINDOW.is_expired(t_hit, now)
        });
    }

    // TEMP
    pub fn dump(&self) -> String {
        let mut out = String::new();
        out.push_str("--Roots--\n");
        for (id, root) in &self.roots {
            let d = ApiFullCounter::from(&root.body.stats);
            out.push_str(&format!(
                "\t{:?}/{id} -> {d:?}\n",
                root.body.stats.id()
            ));
        }
        out.push_str("----\n\n");
        out.push_str("--Ints--\n");
        for root in &self.intermediate {
            let d = ApiFullCounter::from(&root.body.stats);
            out.push_str(&format!("\t{:?} -> {d:?}\n", root.body.stats.id()));
            let parents: Vec<Option<Uuid>> =
                root.parents.iter().map(|v| v.root_id().copied()).collect();
            out.push_str(&format!("\t\tparents {parents:?}\n\n"));
        }
        out.push_str("----\n\n");
        out.push_str("--Flows--\n");
        for (id, stat) in &self.flows {
            // let d: ApiFlowStat<InnerFlowId> = stat.as_ref().into();
            let d: ApiPktCounter = (&stat.as_ref().shared.stats).into();
            let parents: Vec<_> =
                stat.parents.iter().map(|v| v.global_id()).collect();
            out.push_str(&format!("\t{id}/{} ->\n", stat.dir));
            out.push_str(&format!("\t\t{:?} {d:?}\n", stat.shared.stats.id));
            out.push_str(&format!("\t\tparents {:?}\n", parents));
            out.push_str(&format!("\t\tbases {:?}\n\n", stat.bases));
        }
        out.push_str("----\n");
        out
    }
}

fn get_base_ids(parents: &[StatParent]) -> BTreeSet<Uuid> {
    let mut out = BTreeSet::new();

    let mut work_set = parents.to_vec();
    while let Some(el) = work_set.pop() {
        work_set.extend_from_slice(el.parents());
        if let Some(id) = el.root_id() {
            out.insert(*id);
        }
    }

    out
}

/// XXX holds stats as they arrive on a packet.
pub struct FlowStatBuilder {
    parents: Vec<StatParent>,
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
    pub fn push(&mut self, parent: impl Into<StatParent>) {
        self.parents.push(parent.into());
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
    ) -> Option<Vec<StatParent>> {
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

struct ById(StatParent);

impl PartialOrd for ById {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ById {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.global_id().cmp(&other.0.global_id())
    }
}

impl PartialEq for ById {
    fn eq(&self, other: &Self) -> bool {
        self.0.global_id() == other.0.global_id()
    }
}

impl Eq for ById {}

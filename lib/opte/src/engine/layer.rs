// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! A layer in a port.

use super::flow_table::Dump;
use super::flow_table::FlowEntry;
use super::flow_table::FlowTable;
use super::flow_table::FlowTableDump;
use super::flow_table::FLOW_DEF_EXPIRE_SECS;
use super::ioctl;
use super::ioctl::ActionDescEntryDump;
use super::packet::BodyTransformError;
use super::packet::InnerFlowId;
use super::packet::MblkFullParsed;
use super::packet::MblkPacketData;
use super::packet::Packet;
use super::packet::FLOW_ID_DEFAULT;
use super::port::meta::ActionMeta;
use super::port::Transforms;
use super::rule;
use super::rule::ht_probe;
use super::rule::Action;
use super::rule::ActionDesc;
use super::rule::AllowOrDeny;
use super::rule::Finalized;
use super::rule::GenBtError;
use super::rule::HdrTransformError;
use super::rule::Rule;
use crate::d_error::DError;
#[cfg(all(not(feature = "std"), not(test)))]
use crate::d_error::LabelBlock;
use crate::ddi::kstat::KStatNamed;
use crate::ddi::kstat::KStatProvider;
use crate::ddi::kstat::KStatU64;
use crate::ddi::mblk::MsgBlk;
use crate::ddi::time::Moment;
use crate::ExecCtx;
use crate::LogLevel;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::fmt;
use core::fmt::Display;
use core::num::NonZeroU32;
use core::result;
use illumos_sys_hdrs::c_char;
use illumos_sys_hdrs::uintptr_t;
use opte_api::Direction;

#[derive(Debug)]
pub enum LayerError {
    BodyTransform(BodyTransformError),
    FlowTableFull { layer: &'static str, dir: Direction },
    GenDesc(rule::GenDescError),
    GenBodyTransform(GenBtError),
    GenHdrTransform { layer: &'static str, err: rule::GenHtError },
    GenPacket(rule::GenErr),
    HeaderTransform(HdrTransformError),
    ModMeta(String),
}

impl From<GenBtError> for LayerError {
    fn from(e: GenBtError) -> Self {
        Self::GenBodyTransform(e)
    }
}

impl From<HdrTransformError> for LayerError {
    fn from(e: HdrTransformError) -> Self {
        Self::HeaderTransform(e)
    }
}

impl From<BodyTransformError> for LayerError {
    fn from(e: BodyTransformError) -> Self {
        Self::BodyTransform(e)
    }
}

/// Why a given packet was denied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenyReason {
    /// The packet was denied by the action itself.
    ///
    /// For example, a hairpin action might decide it can't parse the
    /// body of the packet it's attempting to respond to.
    Action,

    /// The packet was denied by the default action.
    ///
    /// In this case the packet matched no rules and the
    /// [`DefaultAction`] was taken for the given direction.
    Default,

    /// The packet was denied by a rule.
    ///
    /// The packet matched a [`Rule`] and that rule's action was
    /// [`Action::Deny`].
    Rule,
}

impl Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Action => write!(f, "action"),
            Self::Default => write!(f, "default"),
            Self::Rule => write!(f, "rule"),
        }
    }
}

// TODO: Represent `name` as joint C+RStr to implement fully.
#[derive(Debug, DError)]
pub enum LayerResult {
    Allow,
    Deny {
        name: &'static str,
        reason: DenyReason,
    },
    #[leaf]
    Hairpin(MsgBlk),
    HandlePkt,
}

impl Display for LayerResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "Allow"),
            Self::HandlePkt => write!(f, "Handle Packet"),
            Self::Deny { name, reason } => {
                write!(f, "Deny: layer: {}, reason: {}", name, reason)
            }
            Self::Hairpin(_) => write!(f, "Hairpin"),
        }
    }
}

pub type RuleId = u64;

pub enum Error {
    RuleNotFound { id: RuleId },
}

pub type Result<T> = result::Result<T, Error>;

#[derive(Clone, Copy, Debug)]
pub enum LftError {
    MaxCapacity,
}

#[derive(Clone, Debug)]
struct LftOutEntry {
    in_flow_pair: InnerFlowId,
    action_desc: ActionDescEntry,
}

impl LftOutEntry {
    fn extract_pair(&self) -> InnerFlowId {
        self.in_flow_pair
    }
}

impl Display for LftOutEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.action_desc)
    }
}

impl Dump for LftOutEntry {
    type DumpVal = ActionDescEntryDump;

    fn dump(&self, hits: u64) -> ActionDescEntryDump {
        ActionDescEntryDump { hits, summary: self.to_string() }
    }
}

struct LayerFlowTable {
    limit: NonZeroU32,
    count: u32,
    ft_in: FlowTable<ActionDescEntry>,
    ft_out: FlowTable<LftOutEntry>,
}

#[derive(Debug)]
pub struct LftDump {
    ft_in: FlowTableDump<ActionDescEntryDump>,
    ft_out: FlowTableDump<ActionDescEntryDump>,
}

impl LayerFlowTable {
    fn add_pair(
        &mut self,
        action_desc: ActionDescEntry,
        in_flow: InnerFlowId,
        out_flow: InnerFlowId,
    ) {
        // We add unchekced because the limit is now enforced by
        // LayerFlowTable, not the individual flow tables.
        self.ft_in.add_unchecked(in_flow, action_desc.clone());
        let out_entry = LftOutEntry { in_flow_pair: in_flow, action_desc };
        self.ft_out.add_unchecked(out_flow, out_entry);
        self.count += 1;
    }

    /// Clear all flow table entries.
    fn clear(&mut self) {
        self.ft_in.clear();
        self.ft_out.clear();
        self.count = 0;
    }

    fn dump(&self) -> LftDump {
        LftDump { ft_in: self.ft_in.dump(), ft_out: self.ft_out.dump() }
    }

    fn expire_flows(&mut self, now: Moment) {
        // XXX The two sides can have different traffic patterns and
        // thus one side could be considered expired while the other
        // is active. You could have one side seeing packets while the
        // other side is idle; so what do we do? Currently this impl
        // bases expiration on the outgoing side only, but expires
        // both entries (just like it's imperative to add an entry as
        // a pair, it's also imperative to remove an entry as a pair).
        // Perhaps the two sides should share a single moment (though
        // that would required mutex or atomic). Or perhaps both sides
        // should be checked, and if either side is expired the pair
        // is considered expired (or active). Maybe this should be
        // configurable?
        let to_expire =
            self.ft_out.expire_flows(now, LftOutEntry::extract_pair);
        for flow in to_expire {
            self.ft_in.expire(&flow);
        }
        self.count = self.ft_out.num_flows();
    }

    fn get_in(&self, flow: &InnerFlowId) -> EntryState {
        match self.ft_in.get(flow) {
            Some(entry) => {
                entry.hit();
                if entry.is_dirty() {
                    EntryState::Dirty(entry.state().clone())
                } else {
                    EntryState::Clean(entry.state().clone())
                }
            }

            None => EntryState::None,
        }
    }

    fn get_out(&self, flow: &InnerFlowId) -> EntryState {
        match self.ft_out.get(flow) {
            Some(entry) => {
                entry.hit();
                let action = entry.state().action_desc.clone();
                if entry.is_dirty() {
                    EntryState::Dirty(action)
                } else {
                    EntryState::Clean(action)
                }
            }

            None => EntryState::None,
        }
    }

    fn remove_in(
        &mut self,
        flow: &InnerFlowId,
    ) -> Option<Arc<FlowEntry<ActionDescEntry>>> {
        self.ft_in.remove(flow)
    }

    fn remove_out(
        &mut self,
        flow: &InnerFlowId,
    ) -> Option<Arc<FlowEntry<LftOutEntry>>> {
        self.ft_out.remove(flow)
    }

    fn mark_clean(&mut self, dir: Direction, flow: &InnerFlowId) {
        match dir {
            Direction::In => {
                let entry = self.ft_in.get(flow);
                if let Some(entry) = entry {
                    entry.mark_clean();
                }
            }
            Direction::Out => {
                let entry = self.ft_out.get(flow);
                if let Some(entry) = entry {
                    entry.mark_clean();
                }
            }
        }
    }

    /// Mark all flow table entries as requiring revalidation after a
    /// reset or removal of rules.
    ///
    /// It is typically cheaper to use [`LayerFlowTable::clear`]; dirty entries
    /// will occupy flowtable space until they are denied or expire. As such
    /// this method should be used only when the original state (`S`) *must*
    /// be preserved to ensure correctness.
    fn mark_dirty(&mut self) {
        self.ft_in.mark_dirty();
        self.ft_out.mark_dirty();
    }

    fn new(port: &str, layer: &str, limit: NonZeroU32) -> Self {
        Self {
            count: 0,
            limit,
            ft_in: FlowTable::new(port, &format!("{}_in", layer), limit, None),
            ft_out: FlowTable::new(
                port,
                &format!("{}_out", layer),
                limit,
                None,
            ),
        }
    }

    fn num_flows(&self) -> u32 {
        self.count
    }
}

/// The result of a flowtable lookup.
pub enum EntryState {
    /// No flow entry was found matching a given flowid.
    None,
    /// An existing flow table entry was found.
    Clean(ActionDescEntry),
    /// An existing flow table entry was found, but rule processing must be rerun
    /// to use the original action or invalidate the underlying entry.
    Dirty(ActionDescEntry),
}

/// The default action of a layer.
///
/// At the moment this can only be allow or deny. That should cover
/// all use cases for the time being. However, it's probably
/// reasonable to open this up to be any [`Action`], if such a use
/// case were to present itself. For now, we stay conservative, and
/// supply only what the current consumers need.
#[derive(Copy, Clone, Debug)]
pub enum DefaultAction {
    Allow,
    StatefulAllow,
    Deny,
}

impl Display for DefaultAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::StatefulAllow => write!(f, "stateful allow"),
            Self::Deny => write!(f, "deny"),
        }
    }
}

impl From<DefaultAction> for &Action {
    fn from(value: DefaultAction) -> Self {
        match value {
            DefaultAction::Allow => &Action::Allow,
            DefaultAction::StatefulAllow => &Action::StatefulAllow,
            DefaultAction::Deny => &Action::Deny,
        }
    }
}

#[derive(Clone, Debug)]
pub enum ActionDescEntry {
    NoOp,
    Desc(Arc<dyn ActionDesc>),
}

impl Dump for ActionDescEntry {
    type DumpVal = ActionDescEntryDump;

    fn dump(&self, hits: u64) -> Self::DumpVal {
        ActionDescEntryDump { hits, summary: self.to_string() }
    }
}

impl Display for ActionDescEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NoOp => write!(f, "no-op"),
            Self::Desc(desc) => write!(f, "{}", desc),
        }
    }
}

/// The actions of a layer.
///
/// This describes the actions a layer's rules can take as well as the
/// [`DefaultAction`] to take when a rule doesn't match.
#[derive(Debug)]
pub struct LayerActions {
    /// The list of actions shared among the layer's rules. An action
    /// doesn't have to be shared, each rule is free to create its
    /// own, but sharing is a way to use less memory if many rules
    /// share the same action.
    pub actions: Vec<Action>,

    /// The default action to take if no rule matches in the inbound
    /// direction.
    pub default_in: DefaultAction,

    /// The default action to take if no rule matches in the outbound
    /// direction.
    pub default_out: DefaultAction,
}

#[derive(KStatProvider)]
struct LayerStats {
    /// The number of inbound packets that matched an LFT entry.
    in_lft_hit: KStatU64,

    /// The number of inbound packets dropped because there was no
    /// space in the LFT.
    in_lft_full: KStatU64,

    /// The number of inbound packets that did not match an LFT entry
    /// and required rule processing.
    in_lft_miss: KStatU64,

    /// The number of inbound packets that matched a rule.
    in_rule_match: KStatU64,

    /// The number of inbound packets that did not match a rule,
    /// resulting in the default action being applied.
    in_rule_nomatch: KStatU64,

    /// The number of inbound packets denied by this layer,
    /// either explicitly or due to the default action.
    in_deny: KStatU64,

    /// The current number of inbound rules.
    in_rules: KStatU64,

    /// The number of outbound packets that matched an LFT entry.
    out_lft_hit: KStatU64,

    /// The number of outbound packets dropped because there was no
    /// space in the LFT.
    out_lft_full: KStatU64,

    /// The number of outbound packets that did not match an LFT entry
    /// and required rule processing.
    out_lft_miss: KStatU64,

    /// The number of outbound packets that matched a rule.
    out_rule_match: KStatU64,

    /// The number of outbound packets that did not match a rule,
    /// resulting in the default action being applied.
    out_rule_nomatch: KStatU64,

    /// The number of outbound packets denied by this layer,
    /// either explicitly or due to the default action.
    out_deny: KStatU64,

    /// The current number of outbound rules.
    out_rules: KStatU64,

    /// The maximum number of active flows that the LFT can hold.
    lft_capacity: KStatU64,

    /// The current number of flows (entries in LFT).
    flows: KStatU64,

    /// The Time To Live for all flows, in seconds. When a flow is
    /// inactive for longer than the TTL, it is considered expired.
    flow_ttl: KStatU64,

    /// The number of times add_rule() has been called.
    add_rule_called: KStatU64,

    /// The number of times remove_rule() has been called.
    remove_rule_called: KStatU64,

    /// The number of times set_rules() has been called.
    set_rules_called: KStatU64,
}

pub struct Layer {
    port_c: CString,
    name: &'static str,
    name_c: CString,
    actions: Vec<Action>,
    default_in: DefaultAction,
    default_in_hits: u64,
    default_out: DefaultAction,
    default_out_hits: u64,
    ft: LayerFlowTable,
    ft_cstr: CString,
    rules_in: RuleTable,
    rules_out: RuleTable,
    rt_cstr: CString,
    stats: KStatNamed<LayerStats>,
}

impl Layer {
    pub fn action(&self, idx: usize) -> Option<Action> {
        self.actions.get(idx).cloned()
    }

    pub fn add_rule(&mut self, dir: Direction, rule: Rule<Finalized>) {
        match dir {
            Direction::Out => {
                self.rules_out.add(rule);
                self.stats.vals.out_rules += 1;
            }

            Direction::In => {
                self.rules_in.add(rule);
                self.stats.vals.in_rules += 1;
            }
        }

        self.stats.vals.add_rule_called += 1;
    }

    /// Clear all flows from the layer's flow tables.
    pub(crate) fn clear_flows(&mut self) {
        self.ft.clear();
        self.stats.vals.flows.set(0);
    }

    pub(crate) fn default_action(&self, dir: Direction) -> DefaultAction {
        match dir {
            Direction::In => self.default_in,
            Direction::Out => self.default_out,
        }
    }

    /// Dump the contents of this layer. This is used for presenting
    /// the layer state in a human-friendly manner.
    pub(crate) fn dump(&self) -> ioctl::DumpLayerResp {
        let rules_in = self.rules_in.dump();
        let rules_out = self.rules_out.dump();
        let ftd = self.ft.dump();
        ioctl::DumpLayerResp {
            name: self.name.to_string(),
            ft_in: ftd.ft_in,
            ft_out: ftd.ft_out,
            rules_in,
            rules_out,
            default_in: self.default_in.to_string(),
            default_in_hits: self.default_in_hits,
            default_out: self.default_out.to_string(),
            default_out_hits: self.default_out_hits,
        }
    }

    fn gen_desc_fail_probe(
        &self,
        dir: Direction,
        flow: &InnerFlowId,
        err: &rule::GenDescError,
    ) {
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                let dir_c = CString::new(format!("{}", dir)).unwrap();
                let msg_c = CString::new(format!("{:?}", err)).unwrap();

                unsafe {
                    __dtrace_probe_gen__desc__fail(
                        self.port_c.as_ptr() as uintptr_t,
                        self.name_c.as_ptr() as uintptr_t,
                        dir_c.as_ptr() as uintptr_t,
                        flow,
                        msg_c.as_ptr() as uintptr_t,
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                let port_s = self.port_c.to_str().unwrap();
                let name_s = self.name_c.to_str().unwrap();
                let flow_s = flow.to_string();
                let msg_s = format!("{:?}", err);

                crate::opte_provider::gen__desc__fail!(
                    || (port_s, name_s, dir, flow_s, msg_s)
                );
            } else {
                let (..) = (&self.port_c, &self.name_c, dir, flow, err);
            }
        }
    }

    fn gen_ht_fail_probe(
        &self,
        dir: Direction,
        flow: &InnerFlowId,
        err: &rule::GenHtError,
    ) {
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                let dir_c = CString::new(format!("{}", dir)).unwrap();
                let msg_c = CString::new(format!("{:?}", err)).unwrap();

                unsafe {
                    __dtrace_probe_gen__ht__fail(
                        self.port_c.as_ptr() as uintptr_t,
                        self.name_c.as_ptr() as uintptr_t,
                        dir_c.as_ptr() as uintptr_t,
                        flow,
                        msg_c.as_ptr() as uintptr_t,
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                let port_s = self.port_c.to_str().unwrap();
                let flow_s = flow.to_string();
                let err_s = format!("{:?}", err);

                crate::opte_provider::gen__ht__fail!(
                    || (port_s, &self.name, dir, flow_s, err_s)
                );
            } else {
                let (..) = (dir, flow, err);
            }
        }
    }

    /// Expire all flows whose TTL has been reached based on the
    /// passed in moment.
    pub(crate) fn expire_flows(&mut self, now: Moment) {
        self.ft.expire_flows(now);
        self.stats.vals.flows.set(self.ft.num_flows() as u64);
    }

    pub(crate) fn layer_process_entry_probe(
        &self,
        dir: Direction,
        ifid: &InnerFlowId,
    ) {
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                unsafe {
                    __dtrace_probe_layer__process__entry(
                        dir as uintptr_t,
                        self.port_c.as_ptr() as uintptr_t,
                        self.name_c.as_ptr() as uintptr_t,
                        ifid,
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                let port_s = self.port_c.to_str().unwrap();
                let ifid_s = ifid.to_string();

                crate::opte_provider::layer__process__entry!(
                    || (dir, port_s, &self.name, ifid_s)
                );
            } else {
                let (_, _) = (dir, ifid);
            }
        }
    }

    fn layer_process_return_probe(
        &self,
        dir: Direction,
        flow_before: &InnerFlowId,
        flow_after: &InnerFlowId,
        res: &result::Result<LayerResult, LayerError>,
    ) {
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                // XXX This would probably be better as separate probes;
                // for now this does the trick.
                let (eb, extra_str) = match res {
                    Ok(v @ LayerResult::Deny { name, reason }) => (
                        LabelBlock::from_nested(v),
                        Some(format!("{{name: \"{name}\", reason: {reason:?}}}\0"))
                    ),
                    Ok(v) => (LabelBlock::from_nested(v), None),
                    // TODO: Handle the error types in a zero-cost way.
                    Err(e) => (Ok(LabelBlock::new()), Some(format!("ERROR: {:?}\0", e))),
                };

                // Truncation is captured *in* the LabelBlock.
                let mut eb = match eb {
                    Ok(block) => block,
                    Err(block) => block,
                };

                let extra_cstr = extra_str
                    .as_ref()
                    .and_then(
                        |v| core::ffi::CStr::from_bytes_until_nul(v.as_bytes()).ok()
                    );

                unsafe {
                    if let Some(extra_cstr) = extra_cstr {
                        let _ = eb.append_name_raw(extra_cstr);
                    }
                    __dtrace_probe_layer__process__return(
                        dir as uintptr_t,
                        self.port_c.as_ptr() as uintptr_t,
                        self.name_c.as_ptr() as uintptr_t,
                        flow_before,
                        flow_after,
                        eb.as_ptr(),
                    );
                }
                drop(extra_str);
            } else if #[cfg(feature = "usdt")] {
                let port_s = self.port_c.to_str().unwrap();
                let flow_b_s = flow_before.to_string();
                let flow_a_s = flow_after.to_string();
                // XXX This would probably be better as separate probes;
                // for now this does the trick.
                let res_s = match res {
                    Ok(v) => format!("{}", v),
                    Err(e) => format!("ERROR: {:?}", e),
                };
                crate::opte_provider::layer__process__return!(
                    || ((dir, port_s), &self.name, &flow_b_s, &flow_a_s, &res_s)
                );
            } else {
                let (_, _, _, _) = (dir, flow_before, flow_after, res);
            }
        }
    }

    /// Return the name of the layer.
    pub fn name(&self) -> &str {
        self.name
    }

    pub fn new(
        name: &'static str,
        port: &str,
        actions: LayerActions,
        ft_limit: NonZeroU32,
    ) -> Self {
        let port_c = CString::new(port).unwrap();
        let name_c = CString::new(name).unwrap();

        // Unwrap: We know this is fine because the stat names are
        // generated from the LayerStats structure.
        let mut stats = KStatNamed::new(
            "xde",
            &format!("{}_{}", port, name),
            LayerStats::new(),
        )
        .unwrap();
        stats.vals.lft_capacity.set(ft_limit.get() as u64);
        stats.vals.flow_ttl.set(FLOW_DEF_EXPIRE_SECS);

        Layer {
            actions: actions.actions,
            default_in: actions.default_in,
            default_in_hits: 0,
            default_out: actions.default_out,
            default_out_hits: 0,
            name,
            name_c,
            port_c,
            ft: LayerFlowTable::new(port, name, ft_limit),
            ft_cstr: CString::new(format!("ft-{}", name)).unwrap(),
            rules_in: RuleTable::new(port, name, Direction::In),
            rules_out: RuleTable::new(port, name, Direction::Out),
            rt_cstr: CString::new(format!("rt-{}", name)).unwrap(),
            stats,
        }
    }

    /// Return the number of active flows.
    pub(crate) fn num_flows(&self) -> u32 {
        self.ft.num_flows()
    }

    /// Return the number of rules defined in this layer in the given
    /// direction.
    pub(crate) fn num_rules(&self, dir: Direction) -> usize {
        match dir {
            Direction::Out => self.rules_out.num_rules(),
            Direction::In => self.rules_in.num_rules(),
        }
    }

    pub(crate) fn process(
        &mut self,
        ectx: &ExecCtx,
        dir: Direction,
        pkt: &mut Packet<MblkFullParsed>,
        xforms: &mut Transforms,
        ameta: &mut ActionMeta,
    ) -> result::Result<LayerResult, LayerError> {
        use Direction::*;
        let flow_before = *pkt.flow();
        self.layer_process_entry_probe(dir, pkt.flow());
        let res = match dir {
            Out => self.process_out(ectx, pkt, xforms, ameta),
            In => self.process_in(ectx, pkt, xforms, ameta),
        };
        self.layer_process_return_probe(dir, &flow_before, pkt.flow(), &res);
        res
    }

    fn process_in(
        &mut self,
        ectx: &ExecCtx,
        pkt: &mut Packet<MblkFullParsed>,
        xforms: &mut Transforms,
        ameta: &mut ActionMeta,
    ) -> result::Result<LayerResult, LayerError> {
        // We have no FlowId, thus there can be no FlowTable entry.
        if *pkt.flow() == FLOW_ID_DEFAULT {
            return self.process_in_rules(ectx, pkt, xforms, ameta);
        }

        // Do we have a FlowTable entry? If so, use it.
        let flow = *pkt.flow();
        let action = match self.ft.get_in(&flow) {
            EntryState::Dirty(ActionDescEntry::Desc(action))
                if action.is_valid() =>
            {
                self.ft.mark_clean(Direction::In, &flow);
                Some(ActionDescEntry::Desc(action))
            }
            EntryState::Dirty(_) => {
                // NoOps are included in this case as we can't ask the actor whether
                // it remains valid: the simplest method to do so is to rerun lookup.
                self.ft.remove_in(&flow);
                None
            }
            EntryState::Clean(action) => Some(action),
            EntryState::None => None,
        };

        match action {
            Some(ActionDescEntry::NoOp) => {
                self.stats.vals.in_lft_hit += 1;
                Ok(LayerResult::Allow)
            }

            Some(ActionDescEntry::Desc(desc)) => {
                self.stats.vals.in_lft_hit += 1;
                let flow_before = *pkt.flow();
                let ht = desc.gen_ht(Direction::In);
                pkt.hdr_transform(&ht)?;
                xforms.hdr.push(ht);
                ht_probe(
                    &self.port_c,
                    self.ft_cstr.as_c_str(),
                    Direction::In,
                    &flow_before,
                    pkt.flow(),
                );

                if let Some(body_segs) = pkt.body() {
                    if let Some(bt) =
                        desc.gen_bt(Direction::In, pkt.meta(), body_segs)?
                    {
                        pkt.body_transform(Direction::In, &*bt)?;
                        xforms.body.push(bt);
                    }
                }

                Ok(LayerResult::Allow)
            }

            None => {
                // No FlowTable entry, perhaps there is a matching Rule?
                self.process_in_rules(ectx, pkt, xforms, ameta)
            }
        }
    }

    fn process_in_rules(
        &mut self,
        ectx: &ExecCtx,
        pkt: &mut Packet<MblkFullParsed>,
        xforms: &mut Transforms,
        ameta: &mut ActionMeta,
    ) -> result::Result<LayerResult, LayerError> {
        use Direction::In;

        self.stats.vals.in_lft_miss += 1;
        let rule = self.rules_in.find_match(pkt.flow(), pkt.meta(), ameta);

        let action = if let Some(rule) = rule {
            self.stats.vals.in_rule_match += 1;
            rule.action()
        } else {
            self.stats.vals.in_rule_nomatch += 1;
            self.default_in_hits += 1;
            self.default_in.into()
        };

        match action {
            Action::Allow => Ok(LayerResult::Allow),

            Action::StatefulAllow => {
                if self.ft.count == self.ft.limit.get() {
                    self.stats.vals.in_lft_full += 1;
                    return Err(LayerError::FlowTableFull {
                        layer: self.name,
                        dir: In,
                    });
                }

                // The outbound flow ID mirrors the inbound. Remember,
                // the "top" of layer represents how the client sees
                // the traffic, and the "bottom" of the layer
                // represents how the network sees the traffic.
                let flow_out = pkt.flow().mirror();
                let desc = ActionDescEntry::NoOp;
                self.ft.add_pair(desc, *pkt.flow(), flow_out);
                self.stats.vals.flows += 1;
                Ok(LayerResult::Allow)
            }

            Action::Deny => {
                self.stats.vals.in_deny += 1;
                let reason = if rule.is_some() {
                    self.rule_deny_probe(In, pkt.flow());
                    DenyReason::Rule
                } else {
                    DenyReason::Default
                };

                Ok(LayerResult::Deny { name: self.name, reason })
            }

            Action::Meta(action) => match action.mod_meta(pkt.flow(), ameta) {
                Ok(res) => match res {
                    AllowOrDeny::Allow(_) => Ok(LayerResult::Allow),

                    AllowOrDeny::Deny => Ok(LayerResult::Deny {
                        name: self.name,
                        reason: DenyReason::Action,
                    }),
                },

                Err(msg) => Err(LayerError::ModMeta(msg)),
            },

            Action::Static(action) => {
                let ht = match action.gen_ht(In, pkt.flow(), pkt.meta(), ameta)
                {
                    Ok(aord) => match aord {
                        AllowOrDeny::Allow(ht) => ht,
                        AllowOrDeny::Deny => {
                            return Ok(LayerResult::Deny {
                                name: self.name,
                                reason: DenyReason::Action,
                            });
                        }
                    },

                    Err(e) => {
                        self.record_gen_ht_failure(ectx, In, pkt.flow(), &e);
                        return Err(LayerError::GenHdrTransform {
                            layer: self.name,
                            err: e,
                        });
                    }
                };

                let flow_before = *pkt.flow();
                pkt.hdr_transform(&ht)?;
                xforms.hdr.push(ht);
                ht_probe(
                    &self.port_c,
                    self.rt_cstr.as_c_str(),
                    In,
                    &flow_before,
                    pkt.flow(),
                );

                Ok(LayerResult::Allow)
            }

            Action::Stateful(action) => {
                // A stateful action requires a flow entry in both
                // directions: inbound and outbound. This entry holds
                // an implementation of ActionDesc, which has two
                // responsibilities:
                //
                // 1) To provide the means of generating a header
                //    transformation for that given flow,
                //
                // 2) To track any resources obtained as part of
                //    providing this header transformation, so that
                //    they may be released when the flow expires.
                //
                // If we cannot obtain a flow entry, there is no sense
                // in generating an action descriptor.
                //
                // You might think that a stateful action without a
                // resource requirement can get by without an FT
                // entry; i.e., that you could just generate the
                // desc/header transformation from scratch for each
                // packet until an FT entry becomes available. This is
                // not correct. For example, in the case of
                // implementing a stateful firewall, you want outbound
                // connection attempts to create dynamic inbound rules
                // to allow the handshake from the remote; an entry on
                // the other side is required.
                //
                // In general, the semantic of a StatefulAction is
                // that it gets an FT entry. If there are no slots
                // available, then we must fail until one opens up.
                if self.ft.count == self.ft.limit.get() {
                    self.stats.vals.in_lft_full += 1;
                    return Err(LayerError::FlowTableFull {
                        layer: self.name,
                        dir: In,
                    });
                }

                let desc = match action.gen_desc(pkt.flow(), pkt, ameta) {
                    Ok(aord) => match aord {
                        AllowOrDeny::Allow(desc) => desc,

                        AllowOrDeny::Deny => {
                            return Ok(LayerResult::Deny {
                                name: self.name,
                                reason: DenyReason::Action,
                            });
                        }
                    },

                    Err(e) => {
                        self.record_gen_desc_failure(ectx, In, pkt.flow(), &e);
                        return Err(LayerError::GenDesc(e));
                    }
                };

                let flow_before = *pkt.flow();
                let ht_in = desc.gen_ht(In);
                pkt.hdr_transform(&ht_in)?;
                xforms.hdr.push(ht_in);
                ht_probe(
                    &self.port_c,
                    self.rt_cstr.as_c_str(),
                    Direction::In,
                    &flow_before,
                    pkt.flow(),
                );

                if let Some(body_segs) = pkt.body() {
                    if let Some(bt) = desc.gen_bt(In, pkt.meta(), body_segs)? {
                        pkt.body_transform(In, &*bt)?;
                        xforms.body.push(bt);
                    }
                }

                // The outbound flow ID must be calculated _after_ the
                // header transformation. Remember, the "top"
                // (outbound) of layer represents how the client sees
                // the traffic, and the "bottom" (inbound) of the
                // layer represents how the network sees the traffic.
                // The final step is to mirror the IPs and ports to
                // reflect the traffic direction change.
                let flow_out = pkt.flow().mirror();
                self.ft.add_pair(
                    ActionDescEntry::Desc(desc),
                    flow_before,
                    flow_out,
                );
                self.stats.vals.flows += 1;
                Ok(LayerResult::Allow)
            }

            Action::Hairpin(action) => {
                match action.gen_packet(pkt.meta()) {
                    Ok(AllowOrDeny::Allow(pkt)) => {
                        Ok(LayerResult::Hairpin(pkt))
                    }
                    Ok(AllowOrDeny::Deny) => Ok(LayerResult::Deny {
                        name: self.name,
                        reason: DenyReason::Action,
                    }),
                    Err(e) => {
                        // XXX SDT probe, error stat, log
                        Err(LayerError::GenPacket(e))
                    }
                }
            }

            Action::HandlePacket => Ok(LayerResult::HandlePkt),
        }
    }

    fn process_out(
        &mut self,
        ectx: &ExecCtx,
        pkt: &mut Packet<MblkFullParsed>,
        xforms: &mut Transforms,
        ameta: &mut ActionMeta,
    ) -> result::Result<LayerResult, LayerError> {
        // We have no FlowId, thus there can be no FlowTable entry.
        if *pkt.flow() == FLOW_ID_DEFAULT {
            return self.process_out_rules(ectx, pkt, xforms, ameta);
        }

        // Do we have a FlowTable entry? If so, use it.
        let flow = *pkt.flow();
        let action = match self.ft.get_out(&flow) {
            EntryState::Dirty(ActionDescEntry::Desc(action))
                if action.is_valid() =>
            {
                self.ft.mark_clean(Direction::Out, &flow);
                Some(ActionDescEntry::Desc(action))
            }
            EntryState::Dirty(_) => {
                // NoOps are included in this case as we can't ask the actor whether
                // it remains valid: the simplest method to do so is to rerun lookup.
                self.ft.remove_out(&flow);
                None
            }
            EntryState::Clean(action) => Some(action),
            EntryState::None => None,
        };

        match action {
            Some(ActionDescEntry::NoOp) => {
                self.stats.vals.out_lft_hit += 1;
                Ok(LayerResult::Allow)
            }

            Some(ActionDescEntry::Desc(desc)) => {
                self.stats.vals.out_lft_hit += 1;
                let flow_before = *pkt.flow();
                let ht = desc.gen_ht(Direction::Out);
                pkt.hdr_transform(&ht)?;
                xforms.hdr.push(ht);
                ht_probe(
                    &self.port_c,
                    self.ft_cstr.as_c_str(),
                    Direction::Out,
                    &flow_before,
                    pkt.flow(),
                );

                if let Some(body_segs) = pkt.body() {
                    if let Some(bt) =
                        desc.gen_bt(Direction::Out, pkt.meta(), body_segs)?
                    {
                        pkt.body_transform(Direction::Out, &*bt)?;
                        xforms.body.push(bt);
                    }
                }

                Ok(LayerResult::Allow)
            }

            None => {
                // No FlowTable entry, perhaps there is matching Rule?
                self.process_out_rules(ectx, pkt, xforms, ameta)
            }
        }
    }

    fn process_out_rules(
        &mut self,
        ectx: &ExecCtx,
        pkt: &mut Packet<MblkFullParsed>,
        xforms: &mut Transforms,
        ameta: &mut ActionMeta,
    ) -> result::Result<LayerResult, LayerError> {
        use Direction::Out;

        self.stats.vals.out_lft_miss += 1;
        let rule = self.rules_out.find_match(pkt.flow(), pkt.meta(), ameta);

        let action = if let Some(rule) = rule {
            self.stats.vals.out_rule_match += 1;
            rule.action()
        } else {
            self.stats.vals.out_rule_nomatch += 1;
            self.default_out_hits += 1;
            self.default_out.into()
        };

        match action {
            Action::Allow => Ok(LayerResult::Allow),

            Action::StatefulAllow => {
                if self.ft.count == self.ft.limit.get() {
                    self.stats.vals.out_lft_full += 1;
                    return Err(LayerError::FlowTableFull {
                        layer: self.name,
                        dir: Out,
                    });
                }

                // The inbound flow ID must be calculated _after_ the
                // header transformation. Remember, the "top"
                // (outbound) of layer represents how the client sees
                // the traffic, and the "bottom" (inbound) of the
                // layer represents how the network sees the traffic.
                // The final step is to mirror the IPs and ports to
                // reflect the traffic direction change.
                let flow_in = pkt.flow().mirror();
                self.ft.add_pair(ActionDescEntry::NoOp, flow_in, *pkt.flow());
                self.stats.vals.flows += 1;
                Ok(LayerResult::Allow)
            }

            Action::Deny => {
                self.stats.vals.out_deny += 1;
                let reason = if rule.is_some() {
                    self.rule_deny_probe(Out, pkt.flow());
                    DenyReason::Rule
                } else {
                    DenyReason::Default
                };

                Ok(LayerResult::Deny { name: self.name, reason })
            }

            Action::Meta(action) => match action.mod_meta(pkt.flow(), ameta) {
                Ok(res) => match res {
                    AllowOrDeny::Allow(_) => Ok(LayerResult::Allow),

                    AllowOrDeny::Deny => Ok(LayerResult::Deny {
                        name: self.name,
                        reason: DenyReason::Action,
                    }),
                },

                Err(msg) => Err(LayerError::ModMeta(msg)),
            },

            Action::Static(action) => {
                let ht = match action.gen_ht(Out, pkt.flow(), pkt.meta(), ameta)
                {
                    Ok(aord) => match aord {
                        AllowOrDeny::Allow(ht) => ht,
                        AllowOrDeny::Deny => {
                            return Ok(LayerResult::Deny {
                                name: self.name,
                                reason: DenyReason::Action,
                            });
                        }
                    },

                    Err(e) => {
                        self.record_gen_ht_failure(ectx, Out, pkt.flow(), &e);
                        return Err(LayerError::GenHdrTransform {
                            layer: self.name,
                            err: e,
                        });
                    }
                };

                let flow_before = *pkt.flow();
                pkt.hdr_transform(&ht)?;
                xforms.hdr.push(ht);
                ht_probe(
                    &self.port_c,
                    self.rt_cstr.as_c_str(),
                    Out,
                    &flow_before,
                    pkt.flow(),
                );

                Ok(LayerResult::Allow)
            }

            Action::Stateful(action) => {
                // A stateful action requires a flow entry in both
                // directions: inbound and outbound. This entry holds
                // an implementation of ActionDesc, which has two
                // responsibilities:
                //
                // 1) To provide the means of generating a header
                //    transformation for that given flow,
                //
                // 2) To track any resources obtained as part of
                //    providing this header transformation, so that
                //    they may be released when the flow expires.
                //
                // If we cannot obtain a flow entry, there is no sense
                // in generating an action descriptor.
                //
                // You might think that a stateful action without a
                // resource requirement can get by without an FT
                // entry; i.e., that you could just generate the
                // desc/header transformation from scratch for each
                // packet until an FT entry becomes available. This is
                // not correct. For example, in the case of
                // implementing a stateful firewall, you want outbound
                // connection attempts to create dynamic inbound rules
                // to allow the handshake from the remote; an entry on
                // the other side is required.
                //
                // In general, the semantic of a StatefulAction is
                // that it gets an FT entry. If there are no slots
                // available, then we must fail until one opens up.
                if self.ft.count == self.ft.limit.get() {
                    self.stats.vals.out_lft_full += 1;
                    return Err(LayerError::FlowTableFull {
                        layer: self.name,
                        dir: Out,
                    });
                }

                let desc = match action.gen_desc(pkt.flow(), pkt, ameta) {
                    Ok(aord) => match aord {
                        AllowOrDeny::Allow(desc) => desc,

                        AllowOrDeny::Deny => {
                            return Ok(LayerResult::Deny {
                                name: self.name,
                                reason: DenyReason::Action,
                            });
                        }
                    },

                    Err(e) => {
                        self.record_gen_desc_failure(ectx, Out, pkt.flow(), &e);
                        return Err(LayerError::GenDesc(e));
                    }
                };

                let flow_before = *pkt.flow();
                let ht_out = desc.gen_ht(Out);
                pkt.hdr_transform(&ht_out)?;
                xforms.hdr.push(ht_out);
                ht_probe(
                    &self.port_c,
                    self.rt_cstr.as_c_str(),
                    Out,
                    &flow_before,
                    pkt.flow(),
                );

                if let Some(body_segs) = pkt.body() {
                    if let Some(bt) = desc.gen_bt(Out, pkt.meta(), body_segs)? {
                        pkt.body_transform(Out, &*bt)?;
                        xforms.body.push(bt);
                    }
                }

                // The inbound flow ID must be calculated _after_ the
                // header transformation. Remember, the "top" of layer
                // represents how the client sees the traffic, and the
                // "bottom" of the layer represents how the network
                // sees the traffic. The `ifid_after` value represents
                // how the network sees the traffic. The final step is
                // to mirror the IPs and ports to reflect the traffic
                // direction change.
                let flow_in = pkt.flow().mirror();
                self.ft.add_pair(
                    ActionDescEntry::Desc(desc),
                    flow_in,
                    flow_before,
                );
                self.stats.vals.flows += 1;
                Ok(LayerResult::Allow)
            }

            Action::Hairpin(action) => {
                match action.gen_packet(pkt.meta()) {
                    Ok(AllowOrDeny::Allow(pkt)) => {
                        Ok(LayerResult::Hairpin(pkt))
                    }
                    Ok(AllowOrDeny::Deny) => Ok(LayerResult::Deny {
                        name: self.name,
                        reason: DenyReason::Action,
                    }),
                    Err(e) => {
                        // XXX SDT probe, error stat, log
                        Err(LayerError::GenPacket(e))
                    }
                }
            }

            Action::HandlePacket => Ok(LayerResult::HandlePkt),
        }
    }

    fn record_gen_desc_failure(
        &self,
        ectx: &ExecCtx,
        dir: Direction,
        flow: &InnerFlowId,
        err: &rule::GenDescError,
    ) {
        // XXX increment stat
        ectx.log.log(
            LogLevel::Error,
            &format!(
                "failed to generate descriptor for stateful action: {} {:?}",
                flow, err
            ),
        );
        self.gen_desc_fail_probe(dir, flow, err);
    }

    fn record_gen_ht_failure(
        &self,
        ectx: &ExecCtx,
        dir: Direction,
        flow: &InnerFlowId,
        err: &rule::GenHtError,
    ) {
        // XXX increment stat
        ectx.log.log(
            LogLevel::Error,
            &format!(
                "failed to generate HdrTransform for static action: {} {:?}",
                flow, err
            ),
        );
        self.gen_ht_fail_probe(dir, flow, err);
    }

    /// Remove the rule with the specified direction and ID, if such a
    /// rule exists.
    pub(crate) fn remove_rule(
        &mut self,
        dir: Direction,
        id: RuleId,
    ) -> Result<()> {
        match dir {
            Direction::In => {
                self.rules_in.remove(id)?;
                self.stats.vals.in_rules -= 1;
            }

            Direction::Out => {
                self.rules_out.remove(id)?;
                self.stats.vals.out_rules -= 1;
            }
        }

        self.stats.vals.remove_rule_called += 1;
        Ok(())
    }

    pub(crate) fn rule_deny_probe(
        &self,
        dir: Direction,
        flow_id: &InnerFlowId,
    ) {
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                unsafe {
                    __dtrace_probe_rule__deny(
                        self.port_c.as_ptr() as uintptr_t,
                        self.name_c.as_ptr() as uintptr_t,
                        dir as uintptr_t,
                        flow_id,
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                let port_s = self.port_c.to_str().unwrap();
                let flow_s = flow_id.to_string();

                crate::opte_provider::rule__deny!(
                    || (port_s, &self.name, dir, flow_s)
                );
            } else {
                let (_, _) = (dir, flow_id);
            }
        }
    }

    /// Find a rule and return its [`RuleId`].
    ///
    /// Search for a matching rule that has the same direction and
    /// predicates as the specified rule. If no matching rule is
    /// found, then `None` is returned.
    pub(crate) fn find_rule(
        &self,
        dir: Direction,
        rule: &Rule<Finalized>,
    ) -> Option<RuleId> {
        match dir {
            Direction::Out => self.rules_out.find_rule(rule),
            Direction::In => self.rules_in.find_rule(rule),
        }
    }

    /// Set all rules at once, in an atomic manner.
    ///
    /// Updating the ruleset immediately invalidates all flows
    /// established in the Flow Table.
    pub fn set_rules(
        &mut self,
        in_rules: Vec<Rule<Finalized>>,
        out_rules: Vec<Rule<Finalized>>,
    ) {
        self.ft.clear();
        self.set_rules_core(in_rules, out_rules);
    }

    /// Set all rules at once without clearing the flow table.
    ///
    /// See [`FlowTable::mark_dirty`] for the performance and correctness
    /// implications.
    pub fn set_rules_soft(
        &mut self,
        in_rules: Vec<Rule<Finalized>>,
        out_rules: Vec<Rule<Finalized>>,
    ) {
        self.ft.mark_dirty();
        self.set_rules_core(in_rules, out_rules);
    }

    fn set_rules_core(
        &mut self,
        in_rules: Vec<Rule<Finalized>>,
        out_rules: Vec<Rule<Finalized>>,
    ) {
        self.rules_in.set_rules(in_rules);
        self.rules_out.set_rules(out_rules);
        self.stats.vals.set_rules_called += 1;
        self.stats.vals.in_rules.set(self.rules_in.num_rules() as u64);
        self.stats.vals.out_rules.set(self.rules_out.num_rules() as u64);
    }

    pub fn stats_snap(&self) -> LayerStatsSnap {
        self.stats.vals.snapshot()
    }
}

#[derive(Debug)]
struct RuleTableEntry {
    id: RuleId,
    hits: u64,
    rule: Rule<rule::Finalized>,
}

impl From<&RuleTableEntry> for ioctl::RuleTableEntryDump {
    fn from(rte: &RuleTableEntry) -> Self {
        Self {
            id: rte.id,
            hits: rte.hits,
            rule: super::ioctl::RuleDump::from(&rte.rule),
        }
    }
}

#[derive(Debug)]
pub struct RuleTable {
    port_c: CString,
    layer_c: CString,
    dir: Direction,
    rules: Vec<RuleTableEntry>,
    next_id: RuleId,
}

#[derive(Debug, Eq, PartialEq)]
pub enum RulePlace {
    Insert(usize),
    End,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleRemoveErr {
    NotFound,
}

impl RuleTable {
    fn add(&mut self, rule: Rule<rule::Finalized>) {
        match self.find_pos(&rule) {
            RulePlace::End => {
                let rte = RuleTableEntry { id: self.next_id, hits: 0, rule };
                self.rules.push(rte);
            }

            RulePlace::Insert(idx) => {
                let rte = RuleTableEntry { id: self.next_id, hits: 0, rule };
                self.rules.insert(idx, rte);
            }
        }
        self.next_id += 1;
    }

    fn dump(&self) -> Vec<ioctl::RuleTableEntryDump> {
        let mut dump = Vec::new();
        for rte in &self.rules {
            dump.push(ioctl::RuleTableEntryDump::from(rte));
        }
        dump
    }

    fn find_match(
        &mut self,
        ifid: &InnerFlowId,
        pmeta: &MblkPacketData,
        ameta: &ActionMeta,
    ) -> Option<&Rule<rule::Finalized>> {
        for rte in self.rules.iter_mut() {
            if rte.rule.is_match(pmeta, ameta) {
                rte.hits += 1;
                Self::rule_match_probe(
                    self.port_c.as_c_str(),
                    self.layer_c.as_c_str(),
                    self.dir,
                    ifid,
                    &rte.rule,
                );
                return Some(&rte.rule);
            }
        }

        Self::rule_no_match_probe(
            self.port_c.as_c_str(),
            self.layer_c.as_c_str(),
            self.dir,
            ifid,
        );
        None
    }

    // Find the position in which to insert this rule.
    fn find_pos(&self, rule: &Rule<rule::Finalized>) -> RulePlace {
        for (i, rte) in self.rules.iter().enumerate() {
            if rule.priority() < rte.rule.priority() {
                return RulePlace::Insert(i);
            }

            // Deny takes precedence at the same priority. If we are
            // adding a Deny, and one or more Deny entries already
            // exist, the new rule is added in the front. The same
            // goes for multiple non-deny entries at the same
            // priority.
            if rule.priority() == rte.rule.priority()
                && (rule.action().is_deny() || !rte.rule.action().is_deny())
            {
                return RulePlace::Insert(i);
            }
        }

        RulePlace::End
    }

    /// Find the rule and return its id.
    ///
    /// Search for a matching rule that has the same predicates as the
    /// specified rule. If no matching rule is found, then `None` is
    /// returned.
    pub fn find_rule(&self, query_rule: &Rule<Finalized>) -> Option<RuleId> {
        self.rules.iter().find(|rte| rte.rule == *query_rule).map(|rte| rte.id)
    }

    fn new(port: &str, layer: &str, dir: Direction) -> Self {
        Self {
            port_c: CString::new(port).unwrap(),
            layer_c: CString::new(layer).unwrap(),
            dir,
            rules: vec![],
            next_id: 0,
        }
    }

    fn num_rules(&self) -> usize {
        self.rules.len()
    }

    // Remove the rule with the given `id`. Otherwise, return not found.
    fn remove(&mut self, id: RuleId) -> Result<()> {
        for (rule_idx, rte) in self.rules.iter().enumerate() {
            if id == rte.id {
                let _ = self.rules.remove(rule_idx);
                return Ok(());
            }
        }

        Err(Error::RuleNotFound { id })
    }

    pub fn rule_no_match_probe(
        port: &CStr,
        layer: &CStr,
        dir: Direction,
        flow_id: &InnerFlowId,
    ) {
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                let arg = rule_no_match_sdt_arg {
                    port: port.as_ptr(),
                    layer: layer.as_ptr(),
                    dir: dir as uintptr_t,
                    flow_id,
                };

                unsafe {
                    __dtrace_probe_rule__no__match(
                        &arg as *const rule_no_match_sdt_arg as uintptr_t,
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                let port_s = port.to_str().unwrap();
                let layer_s = layer.to_str().unwrap();

                crate::opte_provider::rule__no__match!(
                    || (port_s, layer_s, dir, flow_id.to_string())
                );
            } else {
                let (..) = (port, layer, dir, flow_id);
            }
        }
    }

    fn rule_match_probe(
        port: &CStr,
        layer: &CStr,
        dir: Direction,
        flow_id: &InnerFlowId,
        rule: &Rule<rule::Finalized>,
    ) {
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                let action_str = rule.action().to_string();
                let action_str_c = CString::new(action_str).unwrap();
                let arg = rule_match_sdt_arg {
                    port: port.as_ptr(),
                    layer: layer.as_ptr(),
                    dir: dir as uintptr_t,
                    flow_id,
                    rule_type: action_str_c.as_ptr(),
                };

                unsafe {
                    __dtrace_probe_rule__match(
                        &arg as *const rule_match_sdt_arg as uintptr_t,
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                let port_s = port.to_str().unwrap();
                let layer_s = layer.to_str().unwrap();
                let action_s = rule.action().to_string();

                crate::opte_provider::rule__match!(
                    || (port_s, layer_s, dir, flow_id.to_string(),
                        action_s)
                );
            } else {
                let (..) = (port, layer, dir, flow_id, rule);
            }
        }
    }

    pub fn set_rules(&mut self, new_rules: Vec<Rule<rule::Finalized>>) {
        self.rules.clear();
        for r in new_rules {
            self.add(r);
        }
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
extern "C" {
    pub fn __dtrace_probe_gen__desc__fail(
        port: uintptr_t,
        layer: uintptr_t,
        dir: uintptr_t,
        ifid: *const InnerFlowId,
        msg: uintptr_t,
    );

    pub fn __dtrace_probe_gen__ht__fail(
        port: uintptr_t,
        layer: uintptr_t,
        dir: uintptr_t,
        ifid: *const InnerFlowId,
        msg: uintptr_t,
    );

    pub fn __dtrace_probe_layer__process__entry(
        dir: uintptr_t,
        port: uintptr_t,
        name: uintptr_t,
        ifid: *const InnerFlowId,
    );
    pub fn __dtrace_probe_layer__process__return(
        dir: uintptr_t,
        port: uintptr_t,
        name: uintptr_t,
        flow_before: *const InnerFlowId,
        flow_after: *const InnerFlowId,
        res: *const LabelBlock<2>,
    );

    pub fn __dtrace_probe_rule__match(arg: uintptr_t);
    pub fn __dtrace_probe_rule__no__match(arg: uintptr_t);

    pub fn __dtrace_probe_rule__deny(
        port: uintptr_t,
        layer: uintptr_t,
        dir: uintptr_t,
        flow: *const InnerFlowId,
    );
}

#[repr(C)]
pub struct rule_match_sdt_arg {
    pub port: *const c_char,
    pub layer: *const c_char,
    pub dir: uintptr_t,
    pub flow_id: *const InnerFlowId,
    pub rule_type: *const c_char,
}

#[repr(C)]
pub struct rule_no_match_sdt_arg {
    pub port: *const c_char,
    pub layer: *const c_char,
    pub dir: uintptr_t,
    pub flow_id: *const InnerFlowId,
}

#[cfg(test)]
mod test {
    use ingot::ethernet::Ethernet;
    use ingot::ethernet::Ethertype;
    use ingot::tcp::Tcp;
    use ingot::types::HeaderLen;

    use crate::engine::ip::v4::Ipv4;
    use crate::engine::GenericUlp;

    use super::*;

    #[test]
    fn find_rule() {
        use crate::engine::predicate::Ipv4AddrMatch;
        use crate::engine::predicate::Predicate;
        use crate::engine::rule;

        let mut rule_table = RuleTable::new("port", "test", Direction::Out);
        let mut rule = Rule::new(
            1,
            Action::Static(Arc::new(rule::Identity::new("find_rule"))),
        );
        let cidr = "10.0.0.0/24".parse().unwrap();
        rule.add_predicate(Predicate::InnerSrcIp4(vec![
            Ipv4AddrMatch::Prefix(cidr),
        ]));

        rule_table.add(rule.finalize());

        let mut test_pkt = MsgBlk::new_ethernet_pkt((
            Ethernet { ethertype: Ethertype::IPV4, ..Default::default() },
            Ipv4 {
                source: "10.0.0.77".parse().unwrap(),
                destination: "52.10.128.69".parse().unwrap(),
                protocol: ingot::ip::IpProtocol::TCP,
                identification: 1,
                total_len: (20 + Tcp::MINIMUM_LENGTH) as u16,
                ..Default::default()
            },
            Tcp {
                source: 5555,
                destination: 443,
                window_size: 64240,
                ..Default::default()
            },
        ));

        let pmeta = Packet::parse_outbound(test_pkt.iter_mut(), GenericUlp {})
            .unwrap()
            .to_full_meta();

        // The pkt/rdr aren't actually used in this case.
        let ameta = ActionMeta::new();
        let ifid = *pmeta.flow();
        assert!(rule_table.find_match(&ifid, &pmeta.meta(), &ameta).is_some());
    }
}
// TODO Reinstate
// #[test]
// fn layer_nat() {
//     use crate::ether::{EtherAddr, EtherMeta, ETHER_TYPE_IPV4};
//     use crate::headers::{
//         IpMeta, Ipv4Meta, TcpMeta, UdpMeta, UlpMeta,
//     };
//     use crate::nat::{DynNat4, NatPool};
//     use crate::rule::{IpProtoMatch, Ipv4AddrMatch, Predicate};

//     let priv_mac = EtherAddr::from([0x02, 0x08, 0x20, 0xd8, 0x35, 0xcf]);
//     let pub_mac = EtherAddr::from([0xa8, 0x40, 0x25, 0x00, 0x00, 0x63]);
//     let dest_mac = EtherAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d]);
//     let guest_ip = "10.0.0.220".parse().unwrap();
//     let public_ip = "10.8.99.220".parse().unwrap();
//     let dest_ip = "52.10.128.69".parse().unwrap();
//     let nat = DynNat4::new("test".to_string(), guest_ip, priv_mac, pub_mac);
//     let layer = Layer::new("dyn-nat4", vec![Action::Stateful(Box::new(nat))]);
//     let subnet = "10.0.0.0/24".parse().unwrap();
//     let mut rule = Rule::new(1, RuleAction::Allow(0));

//     rule.add_predicate(Predicate::InnerIpProto(vec![
//         IpProtoMatch::Exact(Protocol::TCP),
//         IpProtoMatch::Exact(Protocol::UDP),
//     ]));

//     rule.add_predicate(Predicate::Not(Box::new(Predicate::InnerDstIp4(vec![
//         Ipv4AddrMatch::Prefix(subnet),
//     ]))));

//     layer.add_rule(Direction::Out, rule);
//     assert_eq!(layer.num_rules(Direction::Out), 1);
//     assert_eq!(layer.num_rules(Direction::In), 0);

//     // There is no DataPredicate usage in this test, so ths pkt/rdr
//     // can be bogus.
//     let pkt = Packet::copy(&[0xA]);
//     let mut rdr = PacketReader::new(pkt, ());

//     // ================================================================
//     // TCP outbound
//     // ================================================================
//     let ether = EtherMeta {
//         src: priv_mac,
//         dst: dest_mac,
//         ether_type: ETHER_TYPE_IPV4
//     };
//     let ip = IpMeta::from(Ipv4Meta {
//         src: guest_ip,
//         dst: dest_ip,
//         proto: Protocol::TCP,
//     });
//     let ulp = UlpMeta::from(TcpMeta {
//         src: 5555,
//         dst: 443,
//         flags: 0,
//         seq: 0,
//         ack: 0,
//     });

//     let mut meta = PacketMeta {
//         inner_ether: Some(ether),
//         inner_ip: Some(ip),
//         ulp: Some(ulp),
//         ..Default::default()
//     };

//     let mut ras = Vec::new();
//     let mut nat_pool = NatPool::new();
//     nat_pool.add(guest_ip, public_ip, 1025..4097);
//     let resources = Resources::new();
//     resources.set_nat_pool(nat_pool);

//     let ether_meta = meta.inner_ether.as_ref().unwrap();
//     assert_eq!(ether_meta.src, priv_mac);
//     assert_eq!(ether_meta.dst, dest_mac);

//     let ip4_meta = match meta.inner_ip.as_ref().unwrap() {
//         IpMeta::Ip4(v) => v,
//         _ => panic!("expect Ipv4Meta"),
//     };

//     assert_eq!(ip4_meta.src, guest_ip);
//     assert_eq!(ip4_meta.dst, dest_ip);
//     assert_eq!(ip4_meta.proto, Protocol::TCP);

//     let tcp_meta = match meta.ulp.as_ref().unwrap() {
//         UlpMeta::Tcp(v) => v,
//         _ => panic!("expect TcpMeta"),
//     };

//     assert_eq!(tcp_meta.src, 5555);
//     assert_eq!(tcp_meta.dst, 443);
//     assert_eq!(tcp_meta.flags, 0);

//     layer.process_out(&mut meta, &mut rdr, &mut ras, &resources);

//     let ether_meta = meta.inner_ether.as_ref().unwrap();
//     assert_eq!(ether_meta.src, pub_mac);
//     assert_eq!(ether_meta.dst, dest_mac);

//     let ip4_meta = match meta.inner_ip.as_ref().unwrap() {
//         IpMeta::Ip4(v) => v,
//         _ => panic!("expect Ipv4Meta"),
//     };

//     assert_eq!(ip4_meta.src, public_ip);
//     assert_eq!(ip4_meta.dst, dest_ip);
//     assert_eq!(ip4_meta.proto, Protocol::TCP);

//     let tcp_meta = match meta.ulp.as_ref().unwrap() {
//         UlpMeta::Tcp(v) => v,
//         _ => panic!("expect TcpMeta"),
//     };

//     assert_eq!(tcp_meta.src, 4096);
//     assert_eq!(tcp_meta.dst, 443);
//     assert_eq!(tcp_meta.flags, 0);

//     // ================================================================
//     // TCP inbound
//     // ================================================================
//     let ip = IpMeta::from(Ipv4Meta {
//         src: dest_ip,
//         dst: public_ip,
//         proto: Protocol::TCP,
//     });

//     let ulp = UlpMeta::from(TcpMeta {
//         src: 443,
//         dst: 4096,
//         flags: 0,
//         seq: 0,
//         ack: 0,
//     });

//     let mut meta =
//         PacketMeta { inner_ip: Some(ip), ulp: Some(ulp), ..Default::default() };

//     let ip4_meta = match meta.inner_ip.as_ref().unwrap() {
//         IpMeta::Ip4(v) => v,
//         _ => panic!("expect Ipv4Meta"),
//     };

//     assert_eq!(ip4_meta.src, dest_ip);
//     assert_eq!(ip4_meta.dst, public_ip);
//     assert_eq!(ip4_meta.proto, Protocol::TCP);

//     let tcp_meta = match meta.ulp.as_ref().unwrap() {
//         UlpMeta::Tcp(v) => v,
//         _ => panic!("expect TcpMeta"),
//     };

//     assert_eq!(tcp_meta.src, 443);
//     assert_eq!(tcp_meta.dst, 4096);
//     assert_eq!(tcp_meta.flags, 0);

//     layer.process_in(&mut meta, &mut rdr, &mut ras, &resources);

//     let ip4_meta = match meta.inner_ip.as_ref().unwrap() {
//         IpMeta::Ip4(v) => v,
//         _ => panic!("expect Ipv4Meta"),
//     };

//     assert_eq!(ip4_meta.src, dest_ip);
//     assert_eq!(ip4_meta.dst, guest_ip);
//     assert_eq!(ip4_meta.proto, Protocol::TCP);

//     let tcp_meta = match meta.ulp.as_ref().unwrap() {
//         UlpMeta::Tcp(v) => v,
//         _ => panic!("expect TcpMeta"),
//     };

//     assert_eq!(tcp_meta.src, 443);
//     assert_eq!(tcp_meta.dst, 5555);
//     assert_eq!(tcp_meta.flags, 0);

//     // ================================================================
//     // UDP outbound
//     // ================================================================
//     let ip = IpMeta::from(Ipv4Meta {
//         src: guest_ip,
//         dst: dest_ip,
//         proto: Protocol::UDP,
//     });

//     let ulp = UlpMeta::from(UdpMeta { src: 7777, dst: 9000 });

//     let mut meta =
//         PacketMeta { inner_ip: Some(ip), ulp: Some(ulp), ..Default::default() };

//     let mut ras = Vec::new();
//     layer.process_out(&mut meta, &mut rdr, &mut ras, &resources);

//     let ip4_meta = match meta.inner_ip.as_ref().unwrap() {
//         IpMeta::Ip4(v) => v,
//         _ => panic!("expect Ipv4Meta"),
//     };

//     assert_eq!(ip4_meta.src, public_ip);
//     assert_eq!(ip4_meta.dst, dest_ip);
//     assert_eq!(ip4_meta.proto, Protocol::UDP);

//     let udp_meta = match meta.ulp.as_ref().unwrap() {
//         UlpMeta::Udp(v) => v,
//         _ => panic!("expect UdpMeta"),
//     };

//     assert_eq!(udp_meta.src, 4095);
//     assert_eq!(udp_meta.dst, 9000);

//     // ================================================================
//     // UDP inbound
//     // ================================================================
//     let ip = IpMeta::from(Ipv4Meta {
//         src: dest_ip,
//         dst: public_ip,
//         proto: Protocol::UDP,
//     });

//     let ulp = UlpMeta::from(UdpMeta { src: 9000, dst: 4095 });

//     let mut meta =
//         PacketMeta { inner_ip: Some(ip), ulp: Some(ulp), ..Default::default() };

//     let mut ras = Vec::new();
//     layer.process_in(&mut meta, &mut rdr, &mut ras, &resources);

//     let ip4_meta = match meta.inner_ip.as_ref().unwrap() {
//         IpMeta::Ip4(v) => v,
//         _ => panic!("expect Ipv4Meta"),
//     };

//     assert_eq!(ip4_meta.src, dest_ip);
//     assert_eq!(ip4_meta.dst, guest_ip);
//     assert_eq!(ip4_meta.proto, Protocol::UDP);

//     let udp_meta = match meta.ulp.as_ref().unwrap() {
//         UlpMeta::Udp(v) => v,
//         _ => panic!("expect UdpMeta"),
//     };

//     assert_eq!(udp_meta.src, 9000);
//     assert_eq!(udp_meta.dst, 7777);
// }

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use super::flow_table::FlowTable;
use super::flow_table::FlowTableDump;
use super::flow_table::StateSummary;
use super::ioctl;
use super::packet::BodyTransformError;
use super::packet::Initialized;
use super::packet::InnerFlowId;
use super::packet::Packet;
use super::packet::PacketMeta;
use super::packet::PacketRead;
use super::packet::Parsed;
use super::packet::FLOW_ID_DEFAULT;
use super::port::meta::ActionMeta;
use super::port::Transforms;
use super::rule;
use super::rule::flow_id_sdt_arg;
use super::rule::ht_probe;
use super::rule::Action;
use super::rule::ActionDesc;
use super::rule::AllowOrDeny;
use super::rule::Finalized;
use super::rule::GenBtError;
use super::rule::HdrTransformError;
use super::rule::Rule;
use super::rule::RuleDump;
use crate::ddi::time::Moment;
use crate::ExecCtx;
use crate::LogLevel;
use core::fmt;
use core::fmt::Display;
use core::num::NonZeroU32;
use core::result;
use illumos_sys_hdrs::c_char;
use opte_api::Direction;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::ffi::CString;
        use alloc::string::{String, ToString};
        use alloc::sync::Arc;
        use alloc::vec::Vec;
        use illumos_sys_hdrs::uintptr_t;
    } else {
        use std::ffi::CString;
        use std::string::{String, ToString};
        use std::sync::Arc;
        use std::vec::Vec;
    }
}

#[derive(Debug)]
pub enum LayerError {
    BodyTransform(BodyTransformError),
    FlowTableFull { layer: String, dir: Direction },
    GenDesc(rule::GenDescError),
    GenBodyTransform(GenBtError),
    GenHdrTransform(rule::GenHtError),
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

#[derive(Debug)]
pub enum LayerResult {
    Allow,
    Deny { name: String, reason: DenyReason },
    Hairpin(Packet<Initialized>),
}

impl Display for LayerResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "Allow"),
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
        self.in_flow_pair.clone()
    }
}

impl StateSummary for LftOutEntry {
    fn summary(&self) -> String {
        self.action_desc.summary()
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
    ft_in: FlowTableDump,
    ft_out: FlowTableDump,
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
        self.ft_in.add_unchecked(in_flow.clone(), action_desc.clone());
        let out_entry = LftOutEntry {
            in_flow_pair: in_flow,
            action_desc: action_desc.clone(),
        };
        self.ft_out.add_unchecked(out_flow, out_entry);
        self.count += 1;
    }

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

    fn get_in(&mut self, flow: &InnerFlowId) -> Option<ActionDescEntry> {
        match self.ft_in.get_mut(flow) {
            Some(entry) => {
                entry.hit();
                Some(entry.state().clone())
            }

            None => None,
        }
    }

    fn get_out(&mut self, flow: &InnerFlowId) -> Option<ActionDescEntry> {
        match self.ft_out.get_mut(flow) {
            Some(entry) => {
                entry.hit();
                Some(entry.state().action_desc.clone())
            }

            None => None,
        }
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

#[derive(Clone, Debug)]
pub enum ActionDescEntry {
    NoOp,
    Desc(Arc<dyn ActionDesc>),
}

impl StateSummary for ActionDescEntry {
    fn summary(&self) -> String {
        match self {
            Self::NoOp => "no-op".to_string(),
            Self::Desc(desc) => desc.summary(),
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

pub struct Layer {
    port_c: CString,
    name: String,
    name_c: CString,
    actions: Vec<Action>,
    default_in: DefaultAction,
    default_out: DefaultAction,
    ft: LayerFlowTable,
    rules_in: RuleTable,
    rules_out: RuleTable,
}

impl Layer {
    pub fn action(&self, idx: usize) -> Option<Action> {
        self.actions.get(idx).cloned()
    }

    pub fn add_rule(&mut self, dir: Direction, rule: Rule<Finalized>) {
        match dir {
            Direction::Out => self.rules_out.add(rule),
            Direction::In => self.rules_in.add(rule),
        }
    }

    /// Clear all flows from the layer's flow tables.
    pub(crate) fn clear_flows(&mut self) {
        self.ft.clear();
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
            name: self.name.clone(),
            ft_in: ftd.ft_in,
            ft_out: ftd.ft_out,
            rules_in,
            rules_out,
            default_in: self.default_in.to_string(),
            default_out: self.default_out.to_string(),
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
                let flow_arg = flow_id_sdt_arg::from(flow);
                let dir_c = CString::new(format!("{}", dir)).unwrap();
                let msg_c = CString::new(format!("{:?}", err)).unwrap();

                unsafe {
                    __dtrace_probe_gen__desc__fail(
                        self.port_c.as_ptr() as uintptr_t,
                        self.name_c.as_ptr() as uintptr_t,
                        dir_c.as_ptr() as uintptr_t,
                        &flow_arg as *const flow_id_sdt_arg as uintptr_t,
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
                let flow_arg = flow_id_sdt_arg::from(flow);
                let dir_c = CString::new(format!("{}", dir)).unwrap();
                let msg_c = CString::new(format!("{:?}", err)).unwrap();

                unsafe {
                    __dtrace_probe_gen__ht__fail(
                        self.port_c.as_ptr() as uintptr_t,
                        self.name_c.as_ptr() as uintptr_t,
                        dir_c.as_ptr() as uintptr_t,
                        &flow_arg as *const flow_id_sdt_arg as uintptr_t,
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
    }

    pub(crate) fn layer_process_entry_probe(
        &self,
        dir: Direction,
        ifid: &InnerFlowId,
    ) {
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {

                let ifid_arg = flow_id_sdt_arg::from(ifid);

                unsafe {
                    __dtrace_probe_layer__process__entry(
                        dir as uintptr_t,
                        self.port_c.as_ptr() as uintptr_t,
                        self.name_c.as_ptr() as uintptr_t,
                        &ifid_arg as *const flow_id_sdt_arg as uintptr_t,
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
                let res_str = match res {
                    Ok(v) => format!("{}", v),
                    Err(e) => format!("ERROR: {:?}", e),
                };
                let flow_b_arg = flow_id_sdt_arg::from(flow_before);
                let flow_a_arg = flow_id_sdt_arg::from(flow_after);
                let res_c = CString::new(res_str).unwrap();


                unsafe {
                    __dtrace_probe_layer__process__return(
                        dir.cstr_raw() as uintptr_t,
                        self.port_c.as_ptr() as uintptr_t,
                        self.name_c.as_ptr() as uintptr_t,
                        &flow_b_arg as *const flow_id_sdt_arg as uintptr_t,
                        &flow_a_arg as *const flow_id_sdt_arg as uintptr_t,
                        res_c.as_ptr() as uintptr_t,
                    );
                }
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
                    || ((dir, port_s), &self.name, ifid_b_s, ifid_a_s, &res_s)
                );
            } else {
                let (_, _, _, _) = (dir, flow_before, flow_after, res);
            }
        }
    }

    /// Return the name of the layer.
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn new(
        name: &str,
        port: &str,
        actions: LayerActions,
        ft_limit: NonZeroU32,
    ) -> Self {
        let port_c = CString::new(port).unwrap();
        let name_c = CString::new(name).unwrap();

        Layer {
            actions: actions.actions,
            default_in: actions.default_in,
            default_out: actions.default_out,
            name: name.to_string(),
            name_c,
            port_c: port_c.clone(),
            ft: LayerFlowTable::new(port, name, ft_limit),
            rules_in: RuleTable::new(port, name, Direction::In),
            rules_out: RuleTable::new(port, name, Direction::Out),
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
        pkt: &mut Packet<Parsed>,
        xforms: &mut Transforms,
        ameta: &mut ActionMeta,
    ) -> result::Result<LayerResult, LayerError> {
        use Direction::*;
        let flow_before = pkt.flow().clone();
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
        pkt: &mut Packet<Parsed>,
        xforms: &mut Transforms,
        ameta: &mut ActionMeta,
    ) -> result::Result<LayerResult, LayerError> {
        // We have no FlowId, thus there can be no FlowTable entry.
        if *pkt.flow() == FLOW_ID_DEFAULT {
            return self.process_in_rules(ectx, pkt, xforms, ameta);
        }

        // Do we have a FlowTable entry? If so, use it.
        match self.ft.get_in(pkt.flow()) {
            Some(ActionDescEntry::NoOp) => {
                return Ok(LayerResult::Allow);
            }

            Some(ActionDescEntry::Desc(desc)) => {
                let flow_before = *pkt.flow();
                let ht = desc.gen_ht(Direction::In);
                pkt.hdr_transform(&ht)?;
                xforms.hdr.push(ht);
                ht_probe(
                    &self.port_c,
                    &format!("{}-ft", self.name),
                    Direction::In,
                    &flow_before,
                    &pkt.flow(),
                );

                if let Some(body_segs) = pkt.body_segs() {
                    if let Some(bt) =
                        desc.gen_bt(Direction::In, pkt.meta(), &body_segs)?
                    {
                        pkt.body_transform(Direction::In, &bt)?;
                        xforms.body.push(bt);
                    }
                }

                return Ok(LayerResult::Allow);
            }

            None => {
                // XXX Flow table miss stat

                // No FlowTable entry, perhaps there is a matching Rule?
                self.process_in_rules(ectx, pkt, xforms, ameta)
            }
        }
    }

    fn process_in_rules(
        &mut self,
        ectx: &ExecCtx,
        pkt: &mut Packet<Parsed>,
        xforms: &mut Transforms,
        ameta: &mut ActionMeta,
    ) -> result::Result<LayerResult, LayerError> {
        use Direction::In;
        let mut rdr = pkt.get_body_rdr();
        let rule =
            self.rules_in.find_match(pkt.flow(), pkt.meta(), ameta, &mut rdr);
        let _ = rdr.finish();

        let action = if rule.is_none() {
            match self.default_in {
                DefaultAction::Deny => {
                    return Ok(LayerResult::Deny {
                        name: self.name.clone(),
                        reason: DenyReason::Default,
                    });
                }

                DefaultAction::Allow => &Action::Allow,
                DefaultAction::StatefulAllow => &Action::StatefulAllow,
            }
        } else {
            rule.unwrap().action()
        };

        match action {
            Action::Allow => {
                return Ok(LayerResult::Allow);
            }

            Action::StatefulAllow => {
                if self.ft.count == self.ft.limit.get() {
                    return Err(LayerError::FlowTableFull {
                        layer: self.name.clone(),
                        dir: In,
                    });
                }

                // The outbound flow ID mirrors the inbound. Remember,
                // the "top" of layer represents how the client sees
                // the traffic, and the "bottom" of the layer
                // represents how the network sees the traffic.
                let flow_out = pkt.flow().mirror();
                let desc = ActionDescEntry::NoOp;
                self.ft.add_pair(desc, pkt.flow().clone(), flow_out);
                return Ok(LayerResult::Allow);
            }

            Action::Deny => {
                self.rule_deny_probe(In, pkt.flow());
                return Ok(LayerResult::Deny {
                    name: self.name.clone(),
                    reason: DenyReason::Rule,
                });
            }

            Action::Meta(action) => match action.mod_meta(pkt.flow(), ameta) {
                Ok(res) => match res {
                    AllowOrDeny::Allow(_) => return Ok(LayerResult::Allow),

                    AllowOrDeny::Deny => {
                        return Ok(LayerResult::Deny {
                            name: self.name.clone(),
                            reason: DenyReason::Action,
                        })
                    }
                },

                Err(msg) => return Err(LayerError::ModMeta(msg)),
            },

            Action::Static(action) => {
                let ht = match action.gen_ht(In, pkt.flow(), ameta) {
                    Ok(aord) => match aord {
                        AllowOrDeny::Allow(ht) => ht,
                        AllowOrDeny::Deny => {
                            return Ok(LayerResult::Deny {
                                name: self.name.clone(),
                                reason: DenyReason::Action,
                            });
                        }
                    },

                    Err(e) => {
                        self.record_gen_ht_failure(&ectx, In, pkt.flow(), &e);
                        return Err(LayerError::GenHdrTransform(e));
                    }
                };

                let flow_before = pkt.flow().clone();
                pkt.hdr_transform(&ht)?;
                xforms.hdr.push(ht);
                ht_probe(
                    &self.port_c,
                    &format!("{}-rt", self.name),
                    In,
                    &flow_before,
                    pkt.flow(),
                );

                return Ok(LayerResult::Allow);
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
                    return Err(LayerError::FlowTableFull {
                        layer: self.name.clone(),
                        dir: In,
                    });
                }

                let desc = match action.gen_desc(pkt.flow(), pkt, ameta) {
                    Ok(aord) => match aord {
                        AllowOrDeny::Allow(desc) => desc,

                        AllowOrDeny::Deny => {
                            return Ok(LayerResult::Deny {
                                name: self.name.clone(),
                                reason: DenyReason::Action,
                            });
                        }
                    },

                    Err(e) => {
                        self.record_gen_desc_failure(&ectx, In, pkt.flow(), &e);
                        return Err(LayerError::GenDesc(e));
                    }
                };

                let flow_before = *pkt.flow();
                let ht_in = desc.gen_ht(In);
                pkt.hdr_transform(&ht_in)?;
                xforms.hdr.push(ht_in);
                ht_probe(
                    &self.port_c,
                    &format!("{}-rt", self.name),
                    Direction::In,
                    &flow_before,
                    pkt.flow(),
                );

                if let Some(body_segs) = pkt.body_segs() {
                    if let Some(bt) = desc.gen_bt(In, pkt.meta(), &body_segs)? {
                        pkt.body_transform(In, &bt)?;
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
                return Ok(LayerResult::Allow);
            }

            Action::Hairpin(action) => {
                let mut rdr = pkt.get_body_rdr();
                match action.gen_packet(pkt.meta(), &mut rdr) {
                    Ok(aord) => match aord {
                        AllowOrDeny::Allow(pkt) => {
                            let _ = rdr.finish();
                            return Ok(LayerResult::Hairpin(pkt));
                        }

                        AllowOrDeny::Deny => {
                            return Ok(LayerResult::Deny {
                                name: self.name.clone(),
                                reason: DenyReason::Action,
                            });
                        }
                    },

                    Err(e) => {
                        // XXX SDT probe, error stat, log
                        let _ = rdr.finish();
                        return Err(LayerError::GenPacket(e));
                    }
                }
            }
        }
    }

    fn process_out(
        &mut self,
        ectx: &ExecCtx,
        pkt: &mut Packet<Parsed>,
        xforms: &mut Transforms,
        ameta: &mut ActionMeta,
    ) -> result::Result<LayerResult, LayerError> {
        // We have no FlowId, thus there can be no FlowTable entry.
        if *pkt.flow() == FLOW_ID_DEFAULT {
            return self.process_out_rules(ectx, pkt, xforms, ameta);
        }

        // Do we have a FlowTable entry? If so, use it.
        match self.ft.get_out(pkt.flow()) {
            Some(ActionDescEntry::NoOp) => {
                return Ok(LayerResult::Allow);
            }

            Some(ActionDescEntry::Desc(desc)) => {
                let flow_before = pkt.flow().clone();
                let ht = desc.gen_ht(Direction::Out);
                pkt.hdr_transform(&ht)?;
                xforms.hdr.push(ht);
                ht_probe(
                    &self.port_c,
                    &format!("{}-ft", self.name),
                    Direction::Out,
                    &flow_before,
                    pkt.flow(),
                );

                if let Some(body_segs) = pkt.body_segs() {
                    if let Some(bt) =
                        desc.gen_bt(Direction::Out, pkt.meta(), &body_segs)?
                    {
                        pkt.body_transform(Direction::Out, &bt)?;
                        xforms.body.push(bt);
                    }
                }

                return Ok(LayerResult::Allow);
            }

            None => {
                // XXX Flow table miss stat

                // No FlowTable entry, perhaps there is matching Rule?
                self.process_out_rules(ectx, pkt, xforms, ameta)
            }
        }
    }

    fn process_out_rules(
        &mut self,
        ectx: &ExecCtx,
        pkt: &mut Packet<Parsed>,
        xforms: &mut Transforms,
        ameta: &mut ActionMeta,
    ) -> result::Result<LayerResult, LayerError> {
        use Direction::Out;
        let mut rdr = pkt.get_body_rdr();
        let rule =
            self.rules_out.find_match(pkt.flow(), pkt.meta(), &ameta, &mut rdr);
        let _ = rdr.finish();

        let action = if rule.is_none() {
            match self.default_out {
                DefaultAction::Deny => {
                    return Ok(LayerResult::Deny {
                        name: self.name.clone(),
                        reason: DenyReason::Default,
                    });
                }

                DefaultAction::Allow => &Action::Allow,
                DefaultAction::StatefulAllow => &Action::StatefulAllow,
            }
        } else {
            rule.unwrap().action()
        };

        match action {
            Action::Allow => {
                return Ok(LayerResult::Allow);
            }

            Action::StatefulAllow => {
                if self.ft.count == self.ft.limit.get() {
                    return Err(LayerError::FlowTableFull {
                        layer: self.name.clone(),
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
                self.ft.add_pair(
                    ActionDescEntry::NoOp,
                    flow_in,
                    pkt.flow().clone(),
                );
                return Ok(LayerResult::Allow);
            }

            Action::Deny => {
                self.rule_deny_probe(Out, pkt.flow());
                return Ok(LayerResult::Deny {
                    name: self.name.clone(),
                    reason: DenyReason::Rule,
                });
            }

            Action::Meta(action) => match action.mod_meta(pkt.flow(), ameta) {
                Ok(res) => match res {
                    AllowOrDeny::Allow(_) => return Ok(LayerResult::Allow),

                    AllowOrDeny::Deny => {
                        return Ok(LayerResult::Deny {
                            name: self.name.clone(),
                            reason: DenyReason::Action,
                        })
                    }
                },

                Err(msg) => return Err(LayerError::ModMeta(msg)),
            },

            Action::Static(action) => {
                let ht = match action.gen_ht(Out, pkt.flow(), ameta) {
                    Ok(aord) => match aord {
                        AllowOrDeny::Allow(ht) => ht,
                        AllowOrDeny::Deny => {
                            return Ok(LayerResult::Deny {
                                name: self.name.clone(),
                                reason: DenyReason::Action,
                            });
                        }
                    },

                    Err(e) => {
                        self.record_gen_ht_failure(&ectx, Out, pkt.flow(), &e);
                        return Err(LayerError::GenHdrTransform(e));
                    }
                };

                let flow_before = pkt.flow().clone();
                pkt.hdr_transform(&ht)?;
                xforms.hdr.push(ht);
                ht_probe(
                    &self.port_c,
                    &format!("{}-rt", self.name),
                    Out,
                    &flow_before,
                    pkt.flow(),
                );

                return Ok(LayerResult::Allow);
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
                    return Err(LayerError::FlowTableFull {
                        layer: self.name.clone(),
                        dir: Out,
                    });
                }

                let desc = match action.gen_desc(pkt.flow(), pkt, ameta) {
                    Ok(aord) => match aord {
                        AllowOrDeny::Allow(desc) => desc,

                        AllowOrDeny::Deny => {
                            return Ok(LayerResult::Deny {
                                name: self.name.clone(),
                                reason: DenyReason::Action,
                            });
                        }
                    },

                    Err(e) => {
                        self.record_gen_desc_failure(
                            &ectx,
                            Out,
                            pkt.flow(),
                            &e,
                        );
                        return Err(LayerError::GenDesc(e));
                    }
                };

                let flow_before = pkt.flow().clone();
                let ht_out = desc.gen_ht(Out);
                pkt.hdr_transform(&ht_out)?;
                xforms.hdr.push(ht_out);
                ht_probe(
                    &self.port_c,
                    &format!("{}-rt", self.name),
                    Out,
                    &flow_before,
                    pkt.flow(),
                );

                if let Some(body_segs) = pkt.body_segs() {
                    if let Some(bt) =
                        desc.gen_bt(Out, pkt.meta(), &body_segs)?
                    {
                        pkt.body_transform(Out, &bt)?;
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
                return Ok(LayerResult::Allow);
            }

            Action::Hairpin(action) => {
                let mut rdr = pkt.get_body_rdr();
                match action.gen_packet(pkt.meta(), &mut rdr) {
                    Ok(aord) => match aord {
                        AllowOrDeny::Allow(pkt) => {
                            let _ = rdr.finish();
                            return Ok(LayerResult::Hairpin(pkt));
                        }

                        AllowOrDeny::Deny => {
                            return Ok(LayerResult::Deny {
                                name: self.name.clone(),
                                reason: DenyReason::Action,
                            });
                        }
                    },

                    Err(e) => {
                        // XXX SDT probe, error stat, log
                        let _ = rdr.finish();
                        return Err(LayerError::GenPacket(e));
                    }
                }
            }
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
            Direction::In => self.rules_in.remove(id),
            Direction::Out => self.rules_out.remove(id),
        }
    }

    pub(crate) fn rule_deny_probe(
        &self,
        dir: Direction,
        flow_id: &InnerFlowId,
    ) {
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                let flow_arg = flow_id_sdt_arg::from(flow_id);

                unsafe {
                    __dtrace_probe_rule__deny(
                        self.port_c.as_ptr() as uintptr_t,
                        self.name_c.as_ptr() as uintptr_t,
                        dir.cstr_raw() as uintptr_t,
                        &flow_arg as *const flow_id_sdt_arg as uintptr_t,
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
    pub(crate) fn set_rules(
        &mut self,
        in_rules: Vec<Rule<Finalized>>,
        out_rules: Vec<Rule<Finalized>>,
    ) {
        self.ft.clear();
        self.rules_in.set_rules(in_rules);
        self.rules_out.set_rules(out_rules);
    }
}

#[derive(Debug)]
pub struct RuleTable {
    port_c: CString,
    layer_c: CString,
    dir: Direction,
    rules: Vec<(RuleId, Rule<rule::Finalized>)>,
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

impl<'a> RuleTable {
    // TODO Add SDT probe for rule add.
    fn add(&mut self, rule: Rule<rule::Finalized>) {
        match self.find_pos(&rule) {
            RulePlace::End => self.rules.push((self.next_id, rule)),
            RulePlace::Insert(idx) => {
                self.rules.insert(idx, (self.next_id, rule))
            }
        }
        self.next_id += 1;
    }

    fn dump(&self) -> Vec<(RuleId, RuleDump)> {
        let mut dump = Vec::new();
        for (id, r) in &self.rules {
            dump.push((*id, RuleDump::from(r)));
        }
        dump
    }

    fn find_match<'b, R>(
        &self,
        ifid: &InnerFlowId,
        pmeta: &PacketMeta,
        ameta: &ActionMeta,
        rdr: &'b mut R,
    ) -> Option<&Rule<rule::Finalized>>
    where
        R: PacketRead<'a>,
    {
        for (_, r) in &self.rules {
            if r.is_match(pmeta, ameta, rdr) {
                self.rule_match_probe(ifid, &r);
                return Some(r);
            }
        }

        self.rule_no_match_probe(self.dir, ifid);
        None
    }

    // Find the position in which to insert this rule.
    fn find_pos(&self, rule: &Rule<rule::Finalized>) -> RulePlace {
        for (i, (_, r)) in self.rules.iter().enumerate() {
            if rule.priority() < r.priority() {
                return RulePlace::Insert(i);
            }

            // Deny takes precedence at the same priority. If we are
            // adding a Deny, and one or more Deny entries already
            // exist, the new rule is added in the front. The same
            // goes for multiple non-deny entries at the same
            // priority.
            if rule.priority() == r.priority() {
                if rule.action().is_deny() || !r.action().is_deny() {
                    return RulePlace::Insert(i);
                }
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
        self.rules
            .iter()
            .find(|(_rule_id, rule)| rule == query_rule)
            .map(|(rule_id, _)| *rule_id)
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
        for (rule_idx, (rule_id, _)) in self.rules.iter().enumerate() {
            if id == *rule_id {
                let _ = self.rules.remove(rule_idx);
                return Ok(());
            }
        }

        Err(Error::RuleNotFound { id })
    }

    pub fn rule_no_match_probe(&self, dir: Direction, flow_id: &InnerFlowId) {
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                let flow_id = flow_id_sdt_arg::from(flow_id);

                let arg = rule_no_match_sdt_arg {
                    port: self.port_c.as_ptr(),
                    layer: self.layer_c.as_ptr(),
                    dir: dir.cstr_raw(),
                    flow_id: &flow_id,
                };

                unsafe {
                    __dtrace_probe_rule__no__match(
                        &arg as *const rule_no_match_sdt_arg as uintptr_t,
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                let port_s = self.port_c.to_str().unwrap();
                let layer_s = self.layer_c.to_str().unwrap();

                crate::opte_provider::rule__no__match!(
                    || (port_s, layer_s, dir, flow_id.to_string())
                );
            } else {
                let (_, _, _, _) = (&self.port_c, &self.layer_c, dir, flow_id);
            }
        }
    }

    fn rule_match_probe(
        &self,
        flow_id: &InnerFlowId,
        rule: &Rule<rule::Finalized>,
    ) {
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                let action_str = rule.action().to_string();
                let flow_id = flow_id_sdt_arg::from(flow_id);
                let action_str_c = CString::new(action_str).unwrap();
                let arg = rule_match_sdt_arg {
                    port: self.port_c.as_ptr(),
                    layer: self.layer_c.as_ptr(),
                    dir: self.dir.cstr_raw(),
                    flow_id: &flow_id,
                    rule_type: action_str_c.as_ptr(),
                };

                unsafe {
                    __dtrace_probe_rule__match(
                        &arg as *const rule_match_sdt_arg as uintptr_t,
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                let port_s = self.port_c.to_str().unwrap();
                let layer_s = self.layer_c.to_str().unwrap();
                let action_s = rule.action().to_string();

                crate::opte_provider::rule__match!(
                    || (port_s, layer_s, self.dir, flow_id.to_string(),
                        action_s)
                );
            } else {
                let (_, _) = (flow_id, rule);
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
        ifid: uintptr_t,
        msg: uintptr_t,
    );

    pub fn __dtrace_probe_gen__ht__fail(
        port: uintptr_t,
        layer: uintptr_t,
        dir: uintptr_t,
        ifid: uintptr_t,
        msg: uintptr_t,
    );

    pub fn __dtrace_probe_layer__process__entry(
        dir: uintptr_t,
        port: uintptr_t,
        name: uintptr_t,
        ifid: uintptr_t,
    );
    pub fn __dtrace_probe_layer__process__return(
        dir: uintptr_t,
        port: uintptr_t,
        name: uintptr_t,
        flow_before: uintptr_t,
        flow_after: uintptr_t,
        res: uintptr_t,
    );

    pub fn __dtrace_probe_rule__match(arg: uintptr_t);
    pub fn __dtrace_probe_rule__no__match(arg: uintptr_t);

    pub fn __dtrace_probe_rule__deny(
        port: uintptr_t,
        layer: uintptr_t,
        dir: uintptr_t,
        flow: uintptr_t,
    );
}

#[repr(C)]
pub struct rule_match_sdt_arg {
    pub port: *const c_char,
    pub layer: *const c_char,
    pub dir: *const c_char,
    pub flow_id: *const flow_id_sdt_arg,
    pub rule_type: *const c_char,
}

#[repr(C)]
pub struct rule_no_match_sdt_arg {
    pub port: *const c_char,
    pub layer: *const c_char,
    pub dir: *const c_char,
    pub flow_id: *const flow_id_sdt_arg,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn find_rule() {
        use crate::engine::headers::IpMeta;
        use crate::engine::headers::UlpMeta;
        use crate::engine::ip4::Ipv4Meta;
        use crate::engine::ip4::Protocol;
        use crate::engine::packet::MetaGroup;
        use crate::engine::packet::PacketReader;
        use crate::engine::rule;
        use crate::engine::rule::Ipv4AddrMatch;
        use crate::engine::rule::Predicate;
        use crate::engine::tcp::TcpMeta;

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

        let ip = IpMeta::from(Ipv4Meta {
            src: "10.0.0.77".parse().unwrap(),
            dst: "52.10.128.69".parse().unwrap(),
            proto: Protocol::TCP,
        });
        let ulp = UlpMeta::from(TcpMeta {
            src: 5555,
            dst: 443,
            flags: 0,
            seq: 0,
            ack: 0,
        });

        let pmeta = PacketMeta {
            outer: Default::default(),
            inner: MetaGroup {
                ip: Some(ip),
                ulp: Some(ulp),
                ..Default::default()
            },
        };

        // The pkt/rdr aren't actually used in this case.
        let pkt = Packet::copy(&[0xA]);
        let mut rdr = PacketReader::new(&pkt, ());
        let ameta = ActionMeta::new();
        let ifid = InnerFlowId::from(&pmeta);
        assert!(rule_table
            .find_match(&ifid, &pmeta, &ameta, &mut rdr)
            .is_some());
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

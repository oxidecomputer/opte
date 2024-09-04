// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Rules and actions.

use super::ether::EtherMeta;
use super::ether::EtherMod;
use super::flow_table::StateSummary;
use super::headers::EncapMeta;
use super::headers::EncapMod;
use super::headers::EncapPush;
use super::headers::HeaderAction;
use super::headers::HeaderActionError;
use super::headers::IpMeta;
use super::headers::IpMod;
use super::headers::IpPush;
use super::headers::UlpHeaderAction;
use super::ingot_packet::MsgBlk;
use super::ingot_packet::Packet2;
use super::ingot_packet::PacketHeaders;
use super::ingot_packet::PacketHeaders2;
use super::ingot_packet::ParsedMblk;
use super::packet::BodyTransform;
use super::packet::Initialized;
use super::packet::InnerFlowId;
use super::packet::Packet;
use super::packet::PacketMeta;
use super::packet::PacketRead;
use super::packet::PacketReader;
use super::packet::Parsed;
use super::port::meta::ActionMeta;
use super::predicate::DataPredicate;
use super::predicate::Predicate;
use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::fmt;
use core::fmt::Debug;
use core::fmt::Display;
use illumos_sys_hdrs::c_char;
use illumos_sys_hdrs::uintptr_t;
use ingot::types::Read;
use opte_api::Direction;
use serde::Deserialize;
use serde::Serialize;

/// A marker trait indicating a type is an entry acuired from a [`Resource`].
pub trait ResourceEntry {}

/// A marker trait indicating a type is a resource.
pub trait Resource {}

/// A mapping resource represents a shared map from a key to a shared
/// [`ResourceEntry`].
///
/// The idea being that multiple consumers can "own" the entry at once.
pub trait MappingResource: Resource {
    type Key: Clone;
    type Entry: ResourceEntry;

    /// Get the entry with the given key, if one exists.
    fn get(&self, key: &Self::Key) -> Option<Self::Entry>;

    /// Remove the entry with the given key, if one exists.
    fn remove(&self, key: &Self::Key) -> Option<Self::Entry>;

    /// Set the entry with the given key. Return the current entry, if
    /// one exists.
    fn set(&self, key: Self::Key, entry: Self::Entry) -> Option<Self::Entry>;
}

/// A finite resource represents a shared map from a key to an
/// exclusively owned [`ResourceEntry`].
///
/// The idea being that a single consumer takes ownership of the
/// [`ResourceEntry`] for some amount of time; and while that consumer
/// owns the entry no other consumer may have access to it. The
/// resource represents a finite collection of entries, and thus may
/// be exhausted at any given moment.
pub trait FiniteResource: Resource {
    type Key: Clone;
    type Entry: ResourceEntry;

    /// Obtain a new entry given the key.
    ///
    /// Callers are responsible for manually `release`ing this entry into
    /// the correct parent pool.
    ///
    /// # Errors
    ///
    /// Return an error if no entry can be mapped to this key or if
    /// the resource is exhausted.
    fn obtain_raw(&self, key: &Self::Key)
        -> Result<Self::Entry, ResourceError>;

    /// Obtain a smart handle to an entry given the key.
    ///
    /// # Errors
    ///
    /// Return an error if no entry can be mapped to this key or if
    /// the resource is exhausted.
    fn obtain(
        self: &Arc<Self>,
        key: &Self::Key,
    ) -> Result<FiniteHandle<Self>, ResourceError>
    where
        Self: Sized,
        Self::Entry: Copy,
    {
        Ok(FiniteHandle {
            key: key.clone(),
            entry: self.obtain_raw(key)?,
            pool: self.clone(),
        })
    }

    /// Release the entry back to the available resources.
    fn release(&self, key: &Self::Key, br: Self::Entry);
}

/// A smart handle which will automatically return a finite `ResourceEntry`
/// to its parent pool on drop.
pub struct FiniteHandle<Pool: FiniteResource>
where
    Pool::Entry: Copy,
{
    pub key: Pool::Key,
    pub entry: Pool::Entry,
    pool: Arc<Pool>,
}

impl<Pool: FiniteResource> Drop for FiniteHandle<Pool>
where
    Pool::Entry: Copy,
{
    fn drop(&mut self) {
        self.pool.release(&self.key, self.entry)
    }
}

/// An Action Descriptor holds the information needed to create the
/// [`HdrTransform`] which implements the desired action. An
/// ActionDesc is created by a [`StatefulAction`] implementation.
pub trait ActionDesc {
    /// Generate the [`HdrTransform`] which implements this descriptor.
    fn gen_ht(&self, dir: Direction) -> HdrTransform;

    /// Generate a body transformation.
    ///
    /// An action may optionally generate a [`BodyTransform`] in
    /// order to act on the body of the packet.
    fn gen_bt(
        &self,
        _dir: Direction,
        _meta: &PacketHeaders2,
        _payload_segs: &[&[u8]],
    ) -> Result<Option<Box<dyn BodyTransform>>, GenBtError> {
        Ok(None)
    }

    fn name(&self) -> &str;

    /// Check whether this action should be preserved after a soft-clear
    /// of the flow-table.
    ///
    /// This method, if implemented, allows an action to hold onto its original
    /// action after a rule change (i.e., preserving a pseudo-random external IP
    /// allocation).
    ///
    /// Defaults to removing the matched entry.
    fn is_valid(&self) -> bool {
        false
    }
}

impl fmt::Debug for dyn ActionDesc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "dyn ActionDesc {}", self.name())
    }
}

impl Display for dyn ActionDesc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[derive(Debug)]
pub enum ActionInitError {
    ExhaustedResources,
    ResourceError(ResourceError),
}

impl fmt::Debug for dyn StaticAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "dyn StaticAction")
    }
}

impl fmt::Debug for dyn StatefulAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "dyn StatefulAction")
    }
}

pub trait ActionSummary {
    fn summary(&self) -> String;
}

#[derive(Clone)]
pub struct IdentityDesc {
    name: String,
}

impl IdentityDesc {
    pub fn new(name: String) -> Self {
        IdentityDesc { name }
    }
}

impl ActionDesc for IdentityDesc {
    fn gen_ht(&self, _dir: Direction) -> HdrTransform {
        Default::default()
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug)]
pub struct Identity {
    name: String,
}

impl Identity {
    pub fn new(name: &str) -> Self {
        Identity { name: name.to_string() }
    }
}

impl Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Identity")
    }
}

impl StaticAction for Identity {
    fn gen_ht(
        &self,
        _dir: Direction,
        _flow_id: &InnerFlowId,
        _pkt_meta: &PacketHeaders2,
        _action_meta: &mut ActionMeta,
    ) -> GenHtResult {
        Ok(AllowOrDeny::Allow(HdrTransform::identity(&self.name)))
    }

    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        (vec![], vec![])
    }
}

pub enum PushAction<T> {
    Ignore,
    Push(T),
}

pub enum ModifyAction<T> {
    Ignore,
    Modify(T),
}

/// A collection of header transformations to take on each part of the
/// header stack.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HdrTransform {
    pub name: String,
    pub outer_ether: HeaderAction<EtherMeta, EtherMeta, EtherMod>,
    pub outer_ip: HeaderAction<IpMeta, IpPush, IpMod>,
    pub outer_encap: HeaderAction<EncapMeta, EncapPush, EncapMod>,
    pub inner_ether: HeaderAction<EtherMeta, EtherMeta, EtherMod>,
    pub inner_ip: HeaderAction<IpMeta, IpPush, IpMod>,
    // We don't support push/pop for inner_ulp.
    pub inner_ulp: UlpHeaderAction<super::headers::UlpMetaModify>,
}

impl StateSummary for Vec<HdrTransform> {
    fn summary(&self) -> String {
        self.iter().map(|ht| ht.to_string()).collect::<Vec<String>>().join(",")
    }
}

impl Display for HdrTransform {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
extern "C" {
    pub fn __dtrace_probe_ht__run(arg: uintptr_t);
}

#[repr(C)]
pub struct ht_run_sdt_arg {
    pub port: *const c_char,
    pub loc: *const c_char,
    pub dir: uintptr_t,
    pub flow_id_before: *const InnerFlowId,
    pub flow_id_after: *const InnerFlowId,
}

pub fn ht_probe(
    port: &CString,
    loc: &CStr,
    dir: Direction,
    flow_id_before: &InnerFlowId,
    flow_id_after: &InnerFlowId,
) {
    cfg_if! {
        if #[cfg(all(not(feature = "std"), not(test)))] {
            let arg = ht_run_sdt_arg {
                port: port.as_ptr(),
                loc: loc.as_ptr(),
                dir: dir as uintptr_t,
                flow_id_before,
                flow_id_after,
            };

            unsafe {
                __dtrace_probe_ht__run(
                    &arg as *const ht_run_sdt_arg as uintptr_t
                );
            }
        } else if #[cfg(feature = "usdt")] {
            let port_s = port.to_str().unwrap();
            let loc_c = loc.to_str().unwrap();
            let before_s = flow_id_before.to_string();
            let after_s = flow_id_after.to_string();

            crate::opte_provider::ht__run!(
                || (port_s, loc_c, dir, before_s, after_s)
            );
        } else {
            let (..) = (port, loc, dir, flow_id_before, flow_id_after);
        }
    }
}

impl HdrTransform {
    /// The "identity" header transformation; one which leaves the
    /// header as-is.
    pub fn identity(name: &str) -> Self {
        Self {
            name: name.to_string(),
            outer_ether: HeaderAction::Ignore,
            outer_ip: HeaderAction::Ignore,
            outer_encap: HeaderAction::Ignore,
            inner_ether: HeaderAction::Ignore,
            inner_ip: HeaderAction::Ignore,
            inner_ulp: UlpHeaderAction::Ignore,
        }
    }

    /// Run this header transformation against the passed in
    /// [`PacketMeta`], mutating it in place.
    ///
    /// # Errors
    ///
    /// If there is an [`HeaderAction::Modify`], but no metadata is
    /// present for that particular header, then a
    /// [`HdrTransformError::MissingHeader`] is returned.
    pub fn run<T: Read>(
        &self,
        meta: &mut PacketHeaders<T>,
    ) -> Result<(), HdrTransformError> {
        self.outer_ether
            .run(&mut meta.outer.ether)
            .map_err(Self::err_fn("outer ether"))?;
        self.outer_ip
            .run(&mut meta.outer.ip)
            .map_err(Self::err_fn("outer IP"))?;
        self.outer_encap
            .run(&mut meta.outer.encap)
            .map_err(Self::err_fn("outer encap"))?;
        // XXX A hack so that inner ethernet can meet the interface of
        // `HeaderAction::run().`
        let mut tmp = Some(meta.inner.ether);
        self.inner_ether.run(&mut tmp).map_err(Self::err_fn("inner ether"))?;
        meta.inner.ether = tmp.unwrap();
        self.inner_ip
            .run(&mut meta.inner.ip)
            .map_err(Self::err_fn("inner IP"))?;
        self.inner_ulp
            .run(&mut meta.inner.ulp)
            .map_err(Self::err_fn("inner ULP"))
    }

    fn err_fn(
        header: &'static str,
    ) -> impl FnOnce(HeaderActionError) -> HdrTransformError {
        move |e| -> HdrTransformError {
            match e {
                HeaderActionError::MissingHeader => {
                    HdrTransformError::MissingHeader(header)
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum HdrTransformError {
    MissingHeader(&'static str),
}

#[derive(Debug)]
pub enum ResourceError {
    Exhausted,
    NoMatch(String),
}

#[derive(Clone, Debug)]
pub enum GenDescError {
    ResourceExhausted { name: String },
    Unexpected { msg: String },
}

pub type GenDescResult = ActionResult<Arc<dyn ActionDesc>, GenDescError>;

pub trait StatefulAction: Display {
    /// Generate a an [`ActionDesc`] based on the [`InnerFlowId`] and
    /// [`ActionMeta`]. This action may also add, remove, or modify
    /// metadata to communicate data to downstream actions.
    ///
    /// # Errors
    ///
    /// * [`GenDescError::ResourceExhausted`]: This action relies on a
    /// dynamic resource which has been exhausted.
    ///
    /// * [`GenDescError::Unexpected`]: This action encountered an
    /// unexpected error while trying to generate a descriptor.
    fn gen_desc(
        &self,
        flow_id: &InnerFlowId,
        pkt: &Packet2<ParsedMblk>,
        meta: &mut ActionMeta,
    ) -> GenDescResult;

    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>);
}

#[derive(Clone, Debug)]
pub enum GenHtError {
    ResourceExhausted { name: String },
    Unexpected { msg: String },
}

pub type GenHtResult = ActionResult<HdrTransform, GenHtError>;

pub trait StaticAction: Display {
    fn gen_ht(
        &self,
        dir: Direction,
        flow_id: &InnerFlowId,
        packet_meta: &PacketHeaders2,
        action_meta: &mut ActionMeta,
    ) -> GenHtResult;

    /// Return the predicates implicit to this action.
    ///
    /// Return both the header [`Predicate`] list and
    /// [`DataPredicate`] list implicit to this action. An empty list
    /// implies there are no implicit predicates of that type.
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>);
}

pub type ModMetaResult = ActionResult<(), String>;

/// A meta action is one that's only goal is to modify the action
/// metadata in some way. That is, it has no transformation to make on
/// the packet, only add/modify/remove metadata for use by later
/// layers.
pub trait MetaAction: Display {
    /// Return the predicates implicit to this action.
    ///
    /// Return both the header [`Predicate`] list and
    /// [`DataPredicate`] list implicit to this action. An empty list
    /// implies there are no implicit predicates of that type.
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>);

    fn mod_meta(
        &self,
        flow_id: &InnerFlowId,
        meta: &mut ActionMeta,
    ) -> ModMetaResult;
}

#[derive(Debug)]
pub enum GenErr {
    BadPayload(super::packet::ReadErr),
    Malformed,
    MissingMeta,
    Unexpected(String),
}

impl From<super::packet::ReadErr> for GenErr {
    fn from(err: super::packet::ReadErr) -> Self {
        Self::BadPayload(err)
    }
}

impl From<smoltcp::wire::Error> for GenErr {
    fn from(_err: smoltcp::wire::Error) -> Self {
        Self::Malformed
    }
}

pub type GenPacketResult = ActionResult<MsgBlk, GenErr>;

/// An error while generating a [`BodyTransform`].
#[derive(Clone, Debug)]
pub enum GenBtError {
    ParseBody(String),
}

impl From<smoltcp::wire::Error> for GenBtError {
    fn from(e: smoltcp::wire::Error) -> Self {
        Self::ParseBody(format!("{}", e))
    }
}

/// A hairpin action is one that generates a new packet based on the
/// current inbound/outbound packet, and then "hairpins" that new
/// packet back to the source of the original packet. For example, you
/// could use this to hairpin an ARP Reply in response to a guest's
/// ARP request.
pub trait HairpinAction: Display {
    /// Generate a [`Packet`] to hairpin back to the source. The
    /// `meta` argument holds the packet metadata, including any
    /// modifications made by previous layers up to this point. The
    /// `rdr` argument provides a [`PacketReader`] against
    /// [`Packet<Parsed>`], with its starting position set to the
    /// beginning of the packet's payload.
    fn gen_packet(&self, meta: &PacketHeaders2) -> GenPacketResult;

    /// Return the predicates implicit to this action.
    ///
    /// Return both the header [`Predicate`] list and
    /// [`DataPredicate`] list implicit to this action. An empty list
    /// implies there are no implicit predicates of that type.
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>);
}

#[derive(Debug)]
pub enum AllowOrDeny<T> {
    Allow(T),
    Deny,
}

pub type ActionResult<T, E> = Result<AllowOrDeny<T>, E>;

#[derive(Clone)]
pub enum Action {
    /// Allow the packet to pass.
    ///
    /// This is equivalent to a [`Self::Static`] action using [`Identity`].
    Allow,

    /// Handle the packet on an individual level, outside of the usual
    /// flow processing. This results in a call to the
    /// [`super::NetworkImpl::handle_pkt()`] callback.
    ///
    /// In this case we do not treat the packet as part of a flow, but
    /// rather handle it on an individual basis. This action is
    /// terminal; upon execution there is no return to rule
    /// processing. It's at the sole discretion of the handler as to
    /// what response is taken to the matched packet.
    HandlePacket,

    /// Allow the packet to pass, creating a pair of flow table entries.
    ///
    /// This is a more efficient alternative to a [`Self::Stateful`]
    /// action using [`Identity`].
    StatefulAllow,

    /// Deny the packet, causing it to be dropped.
    Deny,

    /// This action manipulates the action metadata in some way.
    Meta(Arc<dyn MetaAction>),

    /// A static action is used to perform transformations without the
    /// need for holding a resource descriptor or creating a pair of
    /// flow table entries.
    Static(Arc<dyn StaticAction>),

    /// A stateful action is used when a hold needs to be made against
    /// a resource or a pair of flow table entries are needed (or
    /// both). E.g., a flow that needs to acquire a port for SNAT.
    Stateful(Arc<dyn StatefulAction>),

    /// A hairpin action generates a response packet and "hairpins" it
    /// back to the source.
    Hairpin(Arc<dyn HairpinAction>),
}

impl Action {
    pub fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        match self {
            Self::Allow => (vec![], vec![]),
            Self::StatefulAllow => (vec![], vec![]),
            // The entire point of a Deny action is for the consumer
            // to specify which types of packets it wants to deny,
            // which means the predicates are always purely explicit.
            Self::Deny => (vec![], vec![]),
            Self::HandlePacket => (vec![], vec![]),
            Self::Meta(act) => act.implicit_preds(),
            Self::Static(act) => act.implicit_preds(),
            Self::Stateful(act) => act.implicit_preds(),
            Self::Hairpin(act) => act.implicit_preds(),
        }
    }

    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny)
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub enum ActionDump {
    Allow,
    StatefulAllow,
    Deny,
    HandlePacket,
    Meta(String),
    Static(String),
    Stateful(String),
    Hairpin(String),
}

impl From<&Action> for ActionDump {
    fn from(action: &Action) -> Self {
        match action {
            Action::Allow => Self::Allow,
            Action::StatefulAllow => Self::StatefulAllow,
            Action::Deny => Self::Deny,
            Action::HandlePacket => Self::HandlePacket,
            Action::Meta(ma) => Self::Meta(ma.to_string()),
            Action::Static(sa) => Self::Static(sa.to_string()),
            Action::Stateful(sa) => Self::Stateful(sa.to_string()),
            Action::Hairpin(ha) => Self::Hairpin(ha.to_string()),
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "Allow"),
            Self::StatefulAllow => write!(f, "Stateful Allow"),
            Self::Deny => write!(f, "Deny"),
            Self::HandlePacket => write!(f, "Handle Packet"),
            Self::Meta(a) => write!(f, "Meta: {}", a),
            Self::Static(a) => write!(f, "Static: {}", a),
            Self::Stateful(a) => write!(f, "Stateful: {}", a),
            Self::Hairpin(a) => write!(f, "Hairpin: {}", a),
        }
    }
}

impl fmt::Debug for Action {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "todo: implement Debug for Action")
    }
}

// TODO Use const generics to make this array?
#[derive(Clone, Debug)]
pub struct RulePredicates {
    hdr_preds: Vec<Predicate>,
    data_preds: Vec<DataPredicate>,
}

impl PartialEq for RulePredicates {
    /// Rule predicates are equal when both contain identical sets of
    /// header and data predicates.
    fn eq(&self, other: &Self) -> bool {
        if self.hdr_preds.len() != other.hdr_preds.len() {
            return false;
        }

        if self.data_preds.len() != other.data_preds.len() {
            return false;
        }

        for hp in &self.hdr_preds {
            if !other.hdr_preds.contains(hp) {
                return false;
            }
        }

        for dp in &self.data_preds {
            if !other.data_preds.contains(dp) {
                return false;
            }
        }

        true
    }
}

impl Eq for RulePredicates {}

pub trait RuleState {}

#[derive(Clone, Debug)]
pub struct Ready {
    hdr_preds: Vec<Predicate>,
    data_preds: Vec<DataPredicate>,
}
impl RuleState for Ready {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finalized {
    preds: Option<RulePredicates>,
}
impl RuleState for Finalized {}

#[derive(Clone, Debug)]
pub struct Rule<S: RuleState> {
    state: S,
    action: Action,
    priority: u16,
}

impl PartialEq for Rule<Finalized> {
    fn eq(&self, other: &Self) -> bool {
        self.state.preds == other.state.preds
    }
}

impl Eq for Rule<Finalized> {}

impl<S: RuleState> Rule<S> {
    pub fn action(&self) -> &Action {
        &self.action
    }
}

impl Rule<Ready> {
    /// Create a new rule.
    ///
    /// Create a new rule with the given priority and [`Action`]. Add
    /// any implicit predicates dictated by the action. Additional
    /// predicates may be added along with the action's implicit ones.
    pub fn new(priority: u16, action: Action) -> Self {
        let (hdr_preds, data_preds) = action.implicit_preds();

        Rule { state: Ready { hdr_preds, data_preds }, action, priority }
    }

    /// Create a new rule that matches anything.
    ///
    /// The same as [`Rule::new()`] + [`Rule::clear_preds()`] with the
    /// additional effect of moving directly to the [`Finalized`]
    /// state; preventing any chance for adding a predicate. This is
    /// useful for making intentions clear that this rule is to match
    /// anything.
    pub fn match_any(priority: u16, action: Action) -> Rule<Finalized> {
        Rule { state: Finalized { preds: None }, action, priority }
    }

    /// Add a single [`Predicate`] to the end of the list.
    pub fn add_predicate(&mut self, pred: Predicate) {
        self.state.hdr_preds.push(pred);
    }

    /// Append a list of [`Predicate`]s to the existing list.
    pub fn add_predicates(&mut self, preds: Vec<Predicate>) {
        for p in preds {
            self.state.hdr_preds.push(p);
        }
    }

    /// Add a single [`DataPredicate`] to the end of the list.
    pub fn add_data_predicate(&mut self, pred: DataPredicate) {
        self.state.data_preds.push(pred)
    }

    /// Clear all header and data predicates.
    ///
    /// For the rare occasion that you want to disregard an [`Action`]'s
    /// implicit predicates.
    pub fn clear_preds(&mut self) {
        self.state.hdr_preds.clear();
        self.state.data_preds.clear();
    }

    /// Finalize the rule; locking all predicates in stone.
    pub fn finalize(self) -> Rule<Finalized> {
        let preds = if self.state.hdr_preds.is_empty()
            && self.state.data_preds.is_empty()
        {
            None
        } else {
            Some(RulePredicates {
                hdr_preds: self.state.hdr_preds,
                data_preds: self.state.data_preds,
            })
        };

        Rule {
            state: Finalized { preds },
            priority: self.priority,
            action: self.action,
        }
    }
}

impl<'a> Rule<Finalized> {
    pub fn is_match<'b>(
        &self,
        meta: &PacketHeaders2,
        action_meta: &ActionMeta,
    ) -> bool {
        #[cfg(debug_assertions)]
        {
            if let Some(preds) = &self.state.preds {
                if preds.hdr_preds.is_empty() && preds.data_preds.is_empty() {
                    panic!(
                        "bug: RulePredicates must have at least one \
                            predicate"
                    );
                }
            }
        }

        match &self.state.preds {
            // A rule with no predicates always matches.
            None => true,

            Some(preds) => {
                for p in &preds.hdr_preds {
                    if !p.is_match(meta, action_meta) {
                        return false;
                    }
                }

                for p in &preds.data_preds {
                    if !p.is_match(meta) {
                        return false;
                    }
                }

                true
            }
        }
    }

    pub fn priority(&self) -> u16 {
        self.priority
    }
}

impl From<&Rule<Finalized>> for super::ioctl::RuleDump {
    fn from(rule: &Rule<Finalized>) -> Self {
        let predicates = rule.state.preds.as_ref().map_or(vec![], |rp| {
            rp.hdr_preds.iter().map(ToString::to_string).collect()
        });
        let data_predicates = rule
            .state
            .preds
            .as_ref()
            .map_or(vec![], |rp| rp.data_preds.clone());

        super::ioctl::RuleDump {
            priority: rule.priority,
            predicates,
            data_predicates,
            action: rule.action.to_string(),
        }
    }
}

#[test]
fn rule_matching() {
    use super::ip4::Protocol;
    use crate::engine::headers::UlpMeta;
    use crate::engine::ip4::Ipv4Meta;
    use crate::engine::packet::InnerMeta;
    use crate::engine::predicate::Ipv4AddrMatch;
    use crate::engine::predicate::Predicate;
    use crate::engine::tcp::TcpMeta;

    let action = Identity::new("rule_matching");
    let mut r1 = Rule::new(1, Action::Static(Arc::new(action)));
    let src_ip = "10.11.11.100".parse().unwrap();
    let src_port = "1026".parse().unwrap();
    let dst_ip = "52.10.128.69".parse().unwrap();
    let dst_port = "443".parse().unwrap();
    // There is no DataPredicate usage in this test, so this pkt/rdr
    // can be bogus.
    let pkt = Packet::copy(&[0xA]);
    let mut rdr = pkt.get_rdr();

    let ip = IpMeta::from(Ipv4Meta {
        src: src_ip,
        dst: dst_ip,
        proto: Protocol::TCP,
        ttl: 64,
        ident: 1,
        hdr_len: 20,
        total_len: 40,
        csum: [0; 2],
    });
    let ulp = UlpMeta::from(TcpMeta {
        src: src_port,
        dst: dst_port,
        flags: 0,
        seq: 0,
        ack: 0,
        options_bytes: None,
        options_len: 0,
        window_size: 64240,
        ..Default::default()
    });

    let meta = PacketMeta {
        outer: Default::default(),
        inner: InnerMeta { ip: Some(ip), ulp: Some(ulp), ..Default::default() },
    };

    r1.add_predicate(Predicate::InnerSrcIp4(vec![Ipv4AddrMatch::Exact(
        src_ip,
    )]));
    let r1 = r1.finalize();

    let ameta = ActionMeta::new();
    assert!(r1.is_match(&meta, &ameta, &mut rdr));

    let new_src_ip = "10.11.11.99".parse().unwrap();

    let ip = IpMeta::from(Ipv4Meta {
        src: new_src_ip,
        dst: dst_ip,
        proto: Protocol::TCP,
        ttl: 64,
        ident: 1,
        hdr_len: 20,
        total_len: 40,
        csum: [0; 2],
    });
    let ulp = UlpMeta::from(TcpMeta {
        src: src_port,
        dst: dst_port,
        flags: 0,
        seq: 0,
        ack: 0,
        options_bytes: None,
        options_len: 0,
        window_size: 64240,
        ..Default::default()
    });

    let meta = PacketMeta {
        outer: Default::default(),
        inner: InnerMeta { ip: Some(ip), ulp: Some(ulp), ..Default::default() },
    };

    assert!(!r1.is_match(&meta, &ameta, &mut rdr));
}

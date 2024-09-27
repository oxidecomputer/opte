// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! A virtual switch port.

use self::meta::ActionMeta;
use super::ether::EtherMeta;
use super::flow_table::Dump;
use super::flow_table::FlowEntry;
use super::flow_table::FlowTable;
use super::flow_table::Ttl;
use super::headers::EncapPush;
use super::headers::HeaderAction;
use super::headers::IpPush;
use super::headers::UlpHeaderAction;
use super::ingot_packet::MsgBlk;
use super::ingot_packet::MsgBlkIterMut;
use super::ingot_packet::Packet2;
use super::ingot_packet::Parsed2;
use super::ingot_packet::ParsedMblk;
use super::ingot_packet::ParsedStage1;
use super::ioctl;
use super::ioctl::TcpFlowEntryDump;
use super::ioctl::TcpFlowStateDump;
use super::ioctl::UftEntryDump;
use super::layer;
use super::layer::Layer;
use super::layer::LayerError;
use super::layer::LayerResult;
use super::layer::LayerStatsSnap;
use super::layer::RuleId;
use super::packet::BodyTransform;
use super::packet::BodyTransformError;
use super::packet::Initialized;
use super::packet::InnerFlowId;
use super::packet::Packet;
use super::packet::PacketMeta;
use super::packet::Parsed;
use super::packet::FLOW_ID_DEFAULT;
use super::rule::Action;
use super::rule::CompiledTransform;
use super::rule::Finalized;
use super::rule::HdrTransform;
use super::rule::HdrTransformError;
use super::rule::Rule;
use super::tcp::TcpState;
use super::tcp::KEEPALIVE_EXPIRE_TTL;
use super::tcp::TIME_WAIT_EXPIRE_TTL;
use super::tcp_state::TcpFlowState;
use super::tcp_state::TcpFlowStateError;
use super::HdlPktAction;
use super::LightweightMeta;
use super::NetworkImpl;
use crate::d_error::DError;
#[cfg(all(not(feature = "std"), not(test)))]
use crate::d_error::LabelBlock;
use crate::ddi::kstat;
use crate::ddi::kstat::KStatNamed;
use crate::ddi::kstat::KStatProvider;
use crate::ddi::kstat::KStatU64;
use crate::ddi::sync::KMutex;
use crate::ddi::sync::KMutexType;
use crate::ddi::time::Moment;
use crate::engine::flow_table::ExpiryPolicy;
use crate::engine::ingot_packet::EmitterSpec;
use crate::engine::ingot_packet::EmittestSpec;
use crate::engine::rule::CompiledEncap;
use crate::engine::tcp::TcpMeta;
use crate::ExecCtx;
use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Display;
use core::num::NonZeroU32;
use core::result;
use core::str::FromStr;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering::SeqCst;
#[cfg(all(not(feature = "std"), not(test)))]
use illumos_sys_hdrs::uintptr_t;
use ingot::types::Read;
use kstat_macro::KStatProvider;
use opte_api::Direction;
use opte_api::MacAddr;
use opte_api::OpteError;
use zerocopy::ByteSliceMut;

pub type Result<T> = result::Result<T, OpteError>;

#[derive(Debug)]
pub enum ProcessError {
    BadState(PortState),
    BodyTransform(BodyTransformError),
    Layer(LayerError),
    HandlePkt(&'static str),
    HdrTransform(HdrTransformError),
    WriteError(super::packet::WriteError),
    MissingFlow(InnerFlowId),
    TcpFlow(TcpFlowStateError),
    FlowTableFull { kind: &'static str, limit: u64 },
}

impl From<super::HdlPktError> for ProcessError {
    fn from(e: super::HdlPktError) -> Self {
        Self::HandlePkt(e.0)
    }
}

impl From<super::packet::WriteError> for ProcessError {
    fn from(e: super::packet::WriteError) -> Self {
        Self::WriteError(e)
    }
}

impl From<BodyTransformError> for ProcessError {
    fn from(e: BodyTransformError) -> Self {
        Self::BodyTransform(e)
    }
}

impl From<HdrTransformError> for ProcessError {
    fn from(e: HdrTransformError) -> Self {
        Self::HdrTransform(e)
    }
}

/// The result of processing a packet.
///
/// * Bypass: Let this packet bypass the system; do not process it at
/// all. XXX This is probably going away as its only use is for
/// punting on traffic I didn't want to deal with yet.
///
/// * Drop: The packet has been dropped, as determined by the rules
/// or because of resource exhaustion. Included is the reason for the
/// drop.
///
/// * Modified: The packet has been modified based on its matching rules.
///
/// * Hairpin: One of the layers has determined that it should reply
/// directly with a packet of its own. In this case the original
/// packet is dropped.
#[derive(Debug, DError)]
pub enum ProcessResult {
    Bypass,
    #[leaf]
    Drop {
        reason: DropReason,
    },
    #[leaf]
    Modified(EmittestSpec),
    // TODO: it would be nice if this packet type could be user-specified, but might
    // be tricky.
    #[leaf]
    Hairpin(MsgBlk),
}

impl From<HdlPktAction> for ProcessResult {
    fn from(hpa: HdlPktAction) -> Self {
        match hpa {
            HdlPktAction::Allow => Self::Modified(todo!()),
            HdlPktAction::Deny => Self::Drop { reason: DropReason::HandlePkt },
            HdlPktAction::Hairpin(pkt) => Self::Hairpin(pkt),
        }
    }
}

enum InternalProcessResult {
    Bypass,
    Drop { reason: DropReason },
    Modified,
    Hairpin(MsgBlk),
}

impl From<HdlPktAction> for InternalProcessResult {
    fn from(hpa: HdlPktAction) -> Self {
        match hpa {
            HdlPktAction::Allow => Self::Modified,
            HdlPktAction::Deny => Self::Drop { reason: DropReason::HandlePkt },
            HdlPktAction::Hairpin(pkt) => Self::Hairpin(pkt),
        }
    }
}

/// The reason for a packet being dropped.
#[derive(Clone, Debug)]
pub enum DropReason {
    HandlePkt,
    Layer { name: &'static str, reason: layer::DenyReason },
    TcpErr,
}

/// Used to build a [`Port`].
///
/// The only way to create a [`Port`] is by way of the port builder.
/// The initial configuration of layers, rules, and actions is done
/// via the port builder. Once the configuration is complete the
/// [`Port`] is obtained by calling [`PortBuilder::create()`].
///
/// Only the port builder may add or remove layers. Once you have a
/// [`Port`] the list of layers is immutable.
pub struct PortBuilder {
    ectx: Arc<ExecCtx>,
    name: String,
    // Cache the CString version of the name for use with DTrace
    // probes.
    name_cstr: CString,
    mac: MacAddr,
    layers: KMutex<Vec<Layer>>,
}

#[derive(Clone, Debug)]
pub enum PortCreateError {
    InitStats(kstat::Error),
}

impl From<kstat::Error> for PortCreateError {
    fn from(e: kstat::Error) -> Self {
        Self::InitStats(e)
    }
}

impl Display for PortCreateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InitStats(e) => write!(f, "{}", e),
        }
    }
}

impl From<PortCreateError> for OpteError {
    fn from(e: PortCreateError) -> Self {
        Self::PortCreate(e.to_string())
    }
}

impl PortBuilder {
    /// Add a new layer to the pipeline. The position may be first,
    /// last, or relative to another layer. The position is based on
    /// the outbound direction. The first layer is the first to see
    /// a packet from the guest. The last is the last to see a packet
    /// before it is delivered to the guest.
    pub fn add_layer(
        &self,
        new_layer: Layer,
        pos: Pos,
    ) -> result::Result<(), OpteError> {
        let mut lock = self.layers.lock();

        match pos {
            Pos::Last => {
                lock.push(new_layer);
                return Ok(());
            }

            Pos::First => {
                lock.insert(0, new_layer);
                return Ok(());
            }

            Pos::Before(name) => {
                for (i, layer) in lock.iter().enumerate() {
                    if layer.name() == name {
                        lock.insert(i, new_layer);
                        return Ok(());
                    }
                }
            }

            Pos::After(name) => {
                for (i, layer) in lock.iter().enumerate() {
                    if layer.name() == name {
                        lock.insert(i + 1, new_layer);
                        return Ok(());
                    }
                }
            }
        }

        Err(OpteError::BadLayerPos {
            layer: new_layer.name().to_string(),
            pos: format!("{:?}", pos),
        })
    }

    /// Add a new `Rule` to the layer named by `layer`, if such a
    /// layer exists. Otherwise, return an error.
    pub fn add_rule(
        &self,
        layer_name: &str,
        dir: Direction,
        rule: Rule<Finalized>,
    ) -> result::Result<(), OpteError> {
        for layer in &mut *self.layers.lock() {
            if layer.name() == layer_name {
                layer.add_rule(dir, rule);
                return Ok(());
            }
        }

        Err(OpteError::LayerNotFound(layer_name.to_string()))
    }

    pub fn create<N: NetworkImpl>(
        self,
        net: N,
        uft_limit: NonZeroU32,
        tcp_limit: NonZeroU32,
    ) -> result::Result<Port<N>, PortCreateError> {
        let data = PortData {
            state: PortState::Ready,
            stats: KStatNamed::new("xde", &self.name, PortStats::new())?,
            // At this point the layer pipeline is immutable, thus we
            // move the layers out of the mutex.
            layers: self.layers.into_inner(),
            uft_in: FlowTable::new(&self.name, "uft_in", uft_limit, None),
            uft_out: FlowTable::new(&self.name, "uft_out", uft_limit, None),
            tcp_flows: FlowTable::new(
                &self.name,
                "tcp_flows",
                tcp_limit,
                Some(Box::<TcpExpiry>::default()),
            ),
        };

        Ok(Port {
            name: self.name.clone(),
            name_cstr: self.name_cstr,
            mac: self.mac,
            ectx: self.ectx,
            epoch: AtomicU64::new(1),
            net,
            data: KMutex::new(data, KMutexType::Driver),
        })
    }

    /// Return a clone of the [`Action`] defined in the given
    /// [`Layer`] at the given index. If the layer does not exist, or
    /// has no action at that index, then `None` is returned.
    pub fn layer_action(&self, layer: &str, idx: usize) -> Option<Action> {
        for l in &*self.layers.lock() {
            if l.name() == layer {
                return l.action(idx);
            }
        }

        None
    }

    /// List each [`Layer`] under this port.
    pub fn list_layers(&self) -> ioctl::ListLayersResp {
        let mut tmp = vec![];
        let lock = self.layers.lock();

        for layer in lock.iter() {
            tmp.push(ioctl::LayerDesc {
                name: layer.name().to_string(),
                rules_in: layer.num_rules(Direction::In),
                rules_out: layer.num_rules(Direction::Out),
                default_in: layer.default_action(Direction::In).to_string(),
                default_out: layer.default_action(Direction::Out).to_string(),
                flows: layer.num_flows(),
            });
        }

        ioctl::ListLayersResp { layers: tmp }
    }

    /// Return the name of the port.
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn new(
        name: &str,
        name_cstr: CString,
        mac: MacAddr,
        ectx: Arc<ExecCtx>,
    ) -> Self {
        PortBuilder {
            name: name.to_string(),
            name_cstr,
            mac,
            ectx,
            layers: KMutex::new(Vec::new(), KMutexType::Driver),
        }
    }

    /// Remove the [`Layer`] registered under `name`, if such a layer
    /// exists.
    pub fn remove_layer(&self, name: &str) {
        let mut lock = self.layers.lock();

        for (i, layer) in lock.iter().enumerate() {
            if layer.name() == name {
                let _ = lock.remove(i);
                return;
            }
        }
    }
}

/// The current state of the [`Port`].
///
/// The sequence diagram below gives an overview of how the port
/// transitions between states. A port is first either created or
/// restored via the [`PortBuilder`] methods. At that point you have a
/// [`Port`] which can then transition between various states via its
/// own methods. The digram uses the template `<current_state> --
/// <method> --> <new state>`.
///
///
/// ```text
/// PortBuilder::create() --> Ready
/// PortBuilder::restore() --> Restored
///
/// Ready -- Port::start() --> Running
/// Ready -- Port::reset() --> Ready
///
/// Restored -- Port::start() --> Running
///
/// Running -- Port::pause() --> Paused
/// Running -- Port::reset() --> Ready
///
/// Paused -- Port::start() --> Running
/// Paused -- Port::reset() --> Ready
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortState {
    /// The port is configured with layers and rules, but has no flow
    /// state. It is ready to enter the [`Self::Running`] state to
    /// start handling traffic.
    ///
    /// This state may be entered from:
    ///
    /// * [`PortBuilder::create()`]
    /// * [`Self::Running`]: The transition wipes the flow state.
    /// * [`Self::Paused`]: The transition wipes the flow state.
    Ready,

    /// The port is running and packets are free to travel across the
    /// port. Rules may be added or removed while running.
    ///
    /// This state may be entered from:
    ///
    /// * [`Self::Ready`]
    /// * [`Self::Paused`]
    /// * [`Self::Restored`]
    Running,

    /// The port is paused. The layers and rules are intact as well as
    /// the flow state. However, any inbound or outbound packets are
    /// dropped.
    ///
    /// This state may be entered from:
    ///
    /// * [`Self::Running`]
    Paused,

    /// The port has been restored from a saved state. This includes
    /// layers and rules as well as the flow state.
    ///
    /// XXX This state isn't used yet.
    ///
    /// This state may be entered from:
    ///
    /// XXX This interface doesn't exist yet, use doc syntax to link
    /// to it once it does.
    ///
    /// * PortBuilder::restore()
    Restored,
}

impl Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use PortState::*;

        let s = match self {
            Ready => "ready",
            Running => "running",
            Paused => "paused",
            Restored => "restored",
        };
        write!(f, "{}", s)
    }
}

impl FromStr for PortState {
    type Err = String;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        match s {
            "ready" => Ok(Self::Ready),
            "running" => Ok(Self::Running),
            "paused" => Ok(Self::Paused),
            "restored" => Ok(Self::Restored),
            _ => Err(format!("Bad PortState string: {s}")),
        }
    }
}

#[derive(Clone, Debug)]
pub enum DumpLayerError {
    LayerNotFound,
}

/// An entry in the Unified Flow Table.
#[derive(Clone, Debug)]
pub struct UftEntry<Id> {
    /// The flow ID for the other side.
    pair: Option<Id>,

    /// The transformations to perform.
    xforms: Arc<Transforms>,

    /// Cached flow hash to speed up route selection.
    l4_hash: u32,

    /// The port epoch upon which this entry was established. Used for
    /// invalidation when the rule set is updated.
    epoch: u64,
}

impl<Id> Dump for UftEntry<Id> {
    type DumpVal = UftEntryDump;

    fn dump(&self, hits: u64) -> Self::DumpVal {
        UftEntryDump { hits, summary: self.to_string() }
    }
}

impl<Id> Display for UftEntry<Id> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hdr = self
            .xforms
            .hdr
            .iter()
            .map(|ht| ht.to_string())
            .collect::<Vec<String>>()
            .join(",");
        let body = self
            .xforms
            .body
            .iter()
            .map(|bt| bt.to_string())
            .collect::<Vec<String>>()
            .join(",");
        write!(f, "hdr: {hdr}, body: {body}")
    }
}

/// Cumulative counters for a single [`Port`].
#[derive(KStatProvider)]
struct PortStats {
    /// The number of inbound packets marked as
    /// [`ProcessResult::Bypass`].
    in_bypass: KStatU64,

    /// The number of inbound packets dropped
    /// ([`ProcessResult::Drop`]), for one reason or another.
    in_drop: KStatU64,

    /// The number of inbound packets dropped due to the decision of
    /// the network's `handle_pkt()` callback.
    in_drop_handle_pkt: KStatU64,

    /// The number of inbound packets dropped due to the decision of a
    /// layer's rules. That is, a [`Rule`] was matched with an action
    /// value of [`Action::Deny`].
    in_drop_layer: KStatU64,

    /// The number of inbound packets dropped due to an error in the
    /// TCP state machine.
    in_drop_tcp_err: KStatU64,

    /// The number of inbound packets which generated a hairpin packet
    /// in response.
    in_hairpin: KStatU64,

    /// The number of inbound packets processed and modified by the
    /// port's pipeline.
    in_modified: KStatU64,

    /// The number of inbound packets which resulted in an error while
    /// being processed.
    in_process_err: KStatU64,

    /// The number of inbound packets which matched a UFT entry.
    in_uft_hit: KStatU64,

    /// The number of inbound packets which did not match a UFT entry
    /// and resulted in rule processing.
    in_uft_miss: KStatU64,

    /// The number of outbound packets marked as
    /// [`ProcessResult::Bypass`].
    out_bypass: KStatU64,

    /// The number of outbound packets dropped
    /// ([`ProcessResult::Drop`]), for one reason or another.
    out_drop: KStatU64,

    /// The number of outbound packets dropped due to the decision of
    /// the network's `handle_pkt()` callback.
    out_drop_handle_pkt: KStatU64,

    /// The number of outbound packets dropped due to the decision of
    /// a layer's rules. That is, a [`Rule`] was matched with an
    /// action value of [`Action::Deny`].
    out_drop_layer: KStatU64,

    /// The number of outbound packets dropped due to an error in the
    /// TCP state machine.
    out_drop_tcp_err: KStatU64,

    /// The number of outbound packets which generated a hairpin
    /// packet in response.
    out_hairpin: KStatU64,

    /// The number of outbound packets processed and modified by the
    /// port's pipeline.
    out_modified: KStatU64,

    /// The number of outbound packets which resulted in an error
    /// while being processed.
    out_process_err: KStatU64,

    /// The number of outbound packets which matched a UFT entry.
    out_uft_hit: KStatU64,

    /// The number of outbound packets which did not match a UFT entry
    /// and resulted in rule processing.
    out_uft_miss: KStatU64,
}

struct PortData {
    state: PortState,
    stats: KStatNamed<PortStats>,
    layers: Vec<Layer>,
    uft_in: FlowTable<UftEntry<InnerFlowId>>,
    uft_out: FlowTable<UftEntry<InnerFlowId>>,
    // We keep a record of the inbound UFID in the TCP flow table so
    // that we know which inbound UFT/FT entries to retire upon
    // connection termination.
    tcp_flows: FlowTable<TcpFlowEntryState>,
}

/// A virtual switch port.
///
/// The method by which links are created and traffic is processed. It
/// represents a port on a virtual switch. A port is created and
/// programmed with the intention of handling all traffic for a single
/// client on a single network. It has a name by which it is
/// identified and a single MAC address.
///
/// ### Network Implementation
///
/// The port itself has no network definition, with the exception of
/// its MAC address. It is the role of the `NetworkImpl` to define the
/// network.
///
/// ### Unified Flow Table (UFT)
///
/// The UFT is the cornerstone of OPTE. It is the primary method by
/// which flows are defined and tracked, and presents the most
/// efficient datapath possible for a given packet. The goal of OPTE
/// is to treat packets as stateful flows, not individual packets; and
/// the UFT is how it achieves that goal.
///
/// As new packets come in, the layers, rules, and actions programmed
/// by the network implementation combine to create entries in the
/// UFT. These entries map a flow ID (currently hard-coded to
/// [`InnerFlowId`]) to a set of header transformations. The idea is
/// to pay the cost of rule processing once, and then run the cached
/// header transformations against all future packets of the same
/// flow -- based on the flow ID and traffic direction.
///
/// ### TCP Flow Table
///
/// While the port does not provide a network implementation, it does
/// provide a built-in TCP flow table. This table is responsible for
/// tracking TCP flows as they transition through their states and
/// remove UFT entries as they are closed or reset.
///
/// This table is not meant to track TCP state as rigorously as an
/// operating system's TCP stack does. Ultimately, it is up to the
/// client of this port to determine what is and isn't a valid
/// segment. Rather, it's purpose is simply to keep the UFT as
/// efficient as possible by reclaiming slots immediately.
///
/// ### Epoch
///
/// Each port has an epoch, representing the number of times a rule
/// has been added, removed, or modified on any of its layers. This
/// number is how the port determines when a UFT/LFT entry is based on
/// an outdated rule set and should be invalidated and recomputed.
///
/// ### Execution Context
///
/// The `ExecCtx` provides implementations of specific features that
/// are valid for the given context the port is running in.
pub struct Port<N: NetworkImpl> {
    epoch: AtomicU64,
    ectx: Arc<ExecCtx>,
    name: String,
    // Cache the CString version of the name for use with DTrace
    // probes.
    name_cstr: CString,
    mac: MacAddr,
    net: N,
    data: KMutex<PortData>,
}

// Convert:
//
// ```
// check_state!(state, [Running, Paused])?;
// ```
//
// to:
//
//
// ```
// if *state != Running && *state != Paused {
//     Err(ProcessError::BadState(*state_guard))
// } else {
//     Ok(())
// }
// ```
macro_rules! check_state {
    ( $sg:expr, [ $( $state:expr ),* ] ) => {
        if $( $sg != $state )&&* {
            Err(OpteError::BadState(format!("{}", $sg)))
        } else {
            Ok(())
        }
    };

    // Trailing comma after state list (because check_state! call
    // spans multiple lines).
    ( $sg:expr, [ $( $state:expr ),* ], ) => {
        check_state!($sg, [$( $state ),*])
    };

    // Trailing comma in state list.
    ( $sg:expr, [ $( $state:expr ),+ ,] ) => {
        check_state!($sg, [$( $state ),*])
    };
}

impl<N: NetworkImpl> Port<N> {
    /// Return the [`NetworkImpl`] associated with this port.
    pub fn network(&self) -> &N {
        &self.net
    }

    /// Place the port in the [`PortState::Paused`] state.
    ///
    /// After completion the port can no longer process traffic or
    /// modify state.
    ///
    /// # States
    ///
    /// This command is valid for the following states:
    ///
    /// * [`PortState::Running`]
    pub fn pause(&self) -> Result<()> {
        let mut data = self.data.lock();
        check_state!(data.state, [PortState::Running])?;
        data.state = PortState::Paused;
        Ok(())
    }

    /// Place the port in the [`PortState::Running`] state.
    ///
    /// After completion the port can receive packets for processing.
    ///
    /// # States
    ///
    /// This command is valid for all states. If the port is already
    /// in the running state, this is a no op.
    pub fn start(&self) {
        self.data.lock().state = PortState::Running;
    }

    /// Reset the port.
    ///
    /// A reset wipes all accumulated Layer and Unified flow state
    /// tracking as well as TCP state tracking. But it leaves the
    /// configuration, i.e. the layers and rules, as they are.
    ///
    /// # States
    ///
    /// This command is valid for all states.
    pub fn reset(&self) {
        // It's imperative to hold the lock for the entire function so
        // that its side effects are atomic from the point of view of
        // other threads.
        let mut data = self.data.lock();
        data.state = PortState::Ready;

        // Clear all dynamic state related to the creation of flows.
        for layer in &mut data.layers {
            layer.clear_flows();
        }

        data.uft_in.clear();
        data.uft_out.clear();
        data.tcp_flows.clear();
    }

    /// Get the current [`PortState`].
    pub fn state(&self) -> PortState {
        self.data.lock().state
    }

    /// Add a new `Rule` to the layer named by `layer`.
    ///
    /// The port's epoch is moved forward; flows processed after this
    /// call will have their UFT entry invalidated and recomputed
    /// lazily on the next packet to arrive.
    ///
    /// # Errors
    ///
    /// If the layer does not exist, an error is returned.
    ///
    /// # States
    ///
    /// This command is valid for the following states:
    ///
    /// * [`PortState::Ready`]
    /// * [`PortState::Running`]
    pub fn add_rule(
        &self,
        layer_name: &str,
        dir: Direction,
        rule: Rule<Finalized>,
    ) -> Result<()> {
        let mut data = self.data.lock();
        check_state!(data.state, [PortState::Ready, PortState::Running])?;

        for layer in &mut data.layers {
            if layer.name() == layer_name {
                self.epoch.fetch_add(1, SeqCst);
                layer.add_rule(dir, rule);
                return Ok(());
            }
        }

        Err(OpteError::LayerNotFound(layer_name.to_string()))
    }

    // XXX While it's been helpful to panic on a bad packet for the
    // purposes of developement, this needs to go away before v1.
    // While an error here is probably an indication of a bug or some
    // very odd input (which is probably still a bug because we should
    // gracefully deal with whatever the network throws at us), we
    // need to NOT panic in this case. Instead, we'll want to perform
    // several steps:
    //
    // 1. Collect all the useful data that one might need to
    // understand why this event occured.
    //
    // 2. Fire a DTrace probe with pointers to this data.
    //
    // 3. Increment a kstat to indicate this even has occurred.
    //
    // 4. Send an event to FMA that includes all the data in step (1).
    //
    fn tcp_err(
        &self,
        data: &FlowTable<TcpFlowEntryState>,
        dir: Direction,
        msg: String,
        pkt: &mut Packet<Parsed>,
    ) {
        if unsafe { super::opte_panic_debug != 0 } {
            super::err!("mblk: {}", pkt.mblk_ptr_str());
            super::err!("flow: {}", pkt.flow());
            super::err!("meta: {:?}", pkt.meta());
            super::err!("flows: {:?}", data);
            todo!("bad packet: {}", msg);
        } else {
            self.tcp_err_probe(dir, Some(pkt), pkt.flow(), msg)
        }
    }

    fn tcp_err_probe(
        &self,
        dir: Direction,
        pkt: Option<&Packet<Parsed>>,
        flow: &InnerFlowId,
        msg: String,
    ) {
        let mblk_addr = pkt.map(|p| p.mblk_addr()).unwrap_or_default();
        cfg_if::cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                let msg_arg = CString::new(msg).unwrap();

                unsafe {
                    __dtrace_probe_tcp__err(
                        dir as uintptr_t,
                        self.name_cstr.as_ptr() as uintptr_t,
                        flow,
                        mblk_addr,
                        msg_arg.as_ptr() as uintptr_t,
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                let flow_s = flow.to_string();
                crate::opte_provider::tcp__err!(
                    || (dir, &self.name, flow_s, mblk_addr, &msg)
                );
            } else {
                let (..) = (dir, pkt, msg, flow, mblk_addr);
            }
        }
    }

    /// Dump the contents of the layer named `name`, if such a layer
    /// exists.
    ///
    /// # States
    ///
    /// This command is valid for any [`PortState`].
    pub fn dump_layer(&self, name: &str) -> Result<ioctl::DumpLayerResp> {
        let data = self.data.lock();

        for l in &data.layers {
            if l.name() == name {
                return Ok(l.dump());
            }
        }

        Err(OpteError::LayerNotFound(name.to_string()))
    }

    /// Dump the contents of the TCP flow connection tracking table.
    ///
    /// # States
    ///
    /// This command is valid for the following states:
    ///
    /// * [`PortState::Running`]
    /// * [`PortState::Paused`]
    /// * [`PortState::Restored`]
    pub fn dump_tcp_flows(&self) -> Result<ioctl::DumpTcpFlowsResp> {
        let data = self.data.lock();
        check_state!(
            data.state,
            [PortState::Running, PortState::Paused, PortState::Restored]
        )?;

        Ok(ioctl::DumpTcpFlowsResp { flows: data.tcp_flows.dump() })
    }

    /// Clear all entries from the Unified Flow Table (UFT).
    ///
    /// # States
    ///
    /// This command is valid for the following states.
    ///
    /// * [`PortState::Running`]
    pub fn clear_uft(&self) -> Result<()> {
        let mut data = self.data.lock();
        check_state!(data.state, [PortState::Running])?;
        data.uft_in.clear();
        data.uft_out.clear();
        Ok(())
    }

    /// Clear all entries from the Layer Flow Table (LFT) of
    /// the layer named `layer`.
    ///
    /// # States
    ///
    /// This command is valid for the following states.
    ///
    /// * [`PortState::Running`]
    pub fn clear_lft(&self, layer: &str) -> Result<()> {
        let mut data = self.data.lock();
        check_state!(data.state, [PortState::Running])?;
        data.layers
            .iter_mut()
            .find(|l| l.name() == layer)
            .ok_or_else(|| OpteError::LayerNotFound(layer.to_string()))?
            .clear_flows();
        Ok(())
    }

    /// Dump the contents of the Unified Flow Table (UFT).
    ///
    /// # States
    ///
    /// This command is valid for the following states:
    ///
    /// * [`PortState::Running`]
    /// * [`PortState::Paused`]
    /// * [`PortState::Restored`]
    pub fn dump_uft(&self) -> Result<ioctl::DumpUftResp> {
        let data = self.data.lock();

        check_state!(
            data.state,
            [PortState::Running, PortState::Paused, PortState::Restored],
        )?;

        let in_limit = data.uft_in.get_limit().get();
        let in_num_flows = data.uft_in.num_flows();
        let in_flows = data.uft_in.dump();

        let out_limit = data.uft_out.get_limit().get();
        let out_num_flows = data.uft_out.num_flows();
        let out_flows = data.uft_out.dump();

        Ok(ioctl::DumpUftResp {
            in_limit,
            in_num_flows,
            in_flows,
            out_limit,
            out_num_flows,
            out_flows,
        })
    }

    /// Expire all flows whose TTL is overdue.
    ///
    /// # States
    ///
    /// This command is valid for the following states.
    ///
    /// * [`PortState::Running`]
    pub fn expire_flows(&self) -> Result<()> {
        self.expire_flows_inner(None)
    }

    /// Expire all flows whose TTL would be overdue at the time `now`,
    /// used for testing purposes.
    ///
    /// # States
    ///
    /// This command is valid for the following states.
    ///
    /// * [`PortState::Running`]
    #[cfg(any(feature = "std", test))]
    pub fn expire_flows_at(&self, now: Moment) -> Result<()> {
        self.expire_flows_inner(Some(now))
    }

    #[inline(always)]
    fn expire_flows_inner(&self, now: Option<Moment>) -> Result<()> {
        let mut data = self.data.lock();
        let now = now.unwrap_or_else(Moment::now);
        check_state!(data.state, [PortState::Running])?;

        for l in &mut data.layers {
            l.expire_flows(now);
        }
        let _ = data.uft_in.expire_flows(now, |_| FLOW_ID_DEFAULT);
        let _ = data.uft_out.expire_flows(now, |_| FLOW_ID_DEFAULT);

        // XXX: TCP state expiry currently runs on a longer time scale than
        //      UFT entries, so we don't need to expire any extra UFT entries
        //      using the output Vec<InnerFlowId>. If this changes, i.e., we
        //      set TIME_WAIT_EXPIRE_TTL or another state-specific timer lower
        //      than 60s, we'll need to specifically expire the matching UFTs.
        let _ = data.tcp_flows.expire_flows(now, |_| FLOW_ID_DEFAULT);
        Ok(())
    }

    /// Find a rule in the specified layer and return its id.
    ///
    /// Search for a matching rule in the specified layer that has the
    /// same direction and predicates as the specified rule. If no
    /// matching rule is found, then `None` is returned.
    ///
    /// # Errors
    ///
    /// If the layer does not exist, an error is returned.
    ///
    /// # States
    ///
    /// This command is valid for any [`PortState`].
    pub fn find_rule(
        &self,
        layer_name: &str,
        dir: Direction,
        rule: &Rule<Finalized>,
    ) -> Result<Option<RuleId>> {
        let data = self.data.lock();

        for layer in &data.layers {
            if layer.name() == layer_name {
                return Ok(layer.find_rule(dir, rule));
            }
        }

        Err(OpteError::LayerNotFound(layer_name.to_string()))
    }

    /// Return a reference to the [`Action`] defined in the given
    /// [`Layer`] at the given index. If the layer does not exist, or
    /// has no action at that index, then `None` is returned.
    ///
    /// # States
    ///
    /// This command is valid for any [`PortState`].
    pub fn layer_action(&self, layer: &str, idx: usize) -> Option<Action> {
        let data = self.data.lock();
        for l in &data.layers {
            if l.name() == layer {
                return l.action(idx);
            }
        }

        None
    }

    /// Return a snapshot of the layer-level statistics.
    ///
    /// # States
    ///
    /// This command is valid for any [`PortState`].
    pub fn layer_stats_snap(&self, layer: &str) -> Option<LayerStatsSnap> {
        let data = self.data.lock();

        for l in &data.layers {
            if l.name() == layer {
                return Some(l.stats_snap());
            }
        }

        None
    }

    /// List each [`Layer`] under this port.
    ///
    /// # States
    ///
    /// This command is valid for any [`PortState`].
    pub fn list_layers(&self) -> ioctl::ListLayersResp {
        let data = self.data.lock();
        let mut tmp = vec![];

        for layer in &data.layers {
            tmp.push(ioctl::LayerDesc {
                name: layer.name().to_string(),
                rules_in: layer.num_rules(Direction::In),
                rules_out: layer.num_rules(Direction::Out),
                default_in: layer.default_action(Direction::In).to_string(),
                default_out: layer.default_action(Direction::Out).to_string(),
                flows: layer.num_flows(),
            });
        }

        ioctl::ListLayersResp { layers: tmp }
    }

    /// Return the MAC address of this port.
    pub fn mac_addr(&self) -> MacAddr {
        self.mac
    }

    /// Return the name of the port.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the name of the port as a CString.
    pub fn name_cstr(&self) -> &CString {
        &self.name_cstr
    }

    /// Process the packet.
    ///
    /// # States
    ///
    /// This command is valid only for [`PortState::Running`].
    // #[inline]
    pub fn process<'a, M>(
        &self,
        dir: Direction,
        // TODO: might want to pass in a &mut to an enum
        // which can advance to (and hold) light->full-fat metadata.
        // Then we can have our cake and eat it too.
        mut pkt: Packet2<ParsedStage1<MsgBlkIterMut<'a>, M>>,
    ) -> result::Result<ProcessResult, ProcessError>
    where
        M: LightweightMeta<<MsgBlkIterMut<'a> as Read>::Chunk>,
    {
        let flow_before = pkt.flow();

        // Packet processing is split into a few mechanisms based on
        // expected speed, based on actions and the size of required metadata:
        //
        // 1. UFT exists. Pure push/pop with simple modifications to
        //    inner ULP fields. No body transform.
        // 2. UFT exists. Flow transform could not be compiled as above.
        //    Convert to full metadata and apply saved transform list.
        // 3. No UFT exists. Walk all tables, save and apply transforms
        //    piecemeal OR produce a non-`Modified` decision.
        //
        // Generally, 1 > 2 >>> 3 in terms of rate of pps.
        // Both 1 and 2 are able to drop the port lock very quickly.
        //
        // This tiering exists because we can save space on metadata
        // when we know that we won't have mixed owned/borrowed packet
        // data, and when we don't need to keep space for absent layers.
        // The size of metadata structs is a large bottleneck on packet
        // parsing performance, so we expect that minimising it for the
        // majority of packets pays off in the limit.
        //
        // In case 1, we can also cache and reuse the same EmitSpec for
        // all hit packets.

        // (1) Check for UFT and precompiled.
        let mut data = self.data.lock();
        let epoch = self.epoch();
        check_state!(data.state, [PortState::Running])
            .map_err(|_| ProcessError::BadState(data.state))?;

        // TODO: fixup types here.
        // self.port_process_entry_probe(dir, &flow_before, epoch, &pkt);

        let mut uft: Option<&mut FlowEntry<UftEntry<InnerFlowId>>> = match dir {
            Direction::Out => data.uft_out.get_mut(&flow_before),
            Direction::In => data.uft_in.get_mut(&flow_before),
        };

        enum FastPathDecision {
            CompiledUft { tx: Arc<CompiledTransform>, l4_hash: u32 },
            Uft { tx: Arc<Transforms>, l4_hash: u32 },
            Slow,
        }

        let decision = match uft {
            // We have a valid UFT entry of some kind -- clone out the
            // saved transforms so that we can drop the lock ASAP.
            Some(entry) if entry.state().epoch == epoch => {
                entry.hit();
                let now = *entry.last_hit();

                // The Fast Path.
                let xforms = &entry.state().xforms;
                let out = if let Some(compiled) = xforms.compiled.as_ref() {
                    FastPathDecision::CompiledUft {
                        tx: Arc::clone(compiled),
                        l4_hash: entry.state().l4_hash,
                    }
                } else {
                    FastPathDecision::Uft {
                        tx: Arc::clone(xforms),
                        l4_hash: entry.state().l4_hash,
                    }
                };

                match dir {
                    Direction::In => data.stats.vals.in_uft_hit += 1,
                    Direction::Out => data.stats.vals.out_uft_hit += 1,
                }
                self.uft_hit_probe(dir, &flow_before, epoch, &now);

                out
            }

            // The entry is from a previous epoch; invalidate its UFT
            // entries and proceed to rule processing.
            Some(entry) => {
                let epoch = entry.state().epoch;
                let owned_pair = entry.state().pair;
                let (ufid_in, ufid_out) = match dir {
                    Direction::Out => (owned_pair.as_ref(), Some(&flow_before)),
                    Direction::In => (Some(&flow_before), owned_pair.as_ref()),
                };
                self.uft_invalidate(&mut data, ufid_out, ufid_in, epoch);

                FastPathDecision::Slow
            }
            None => FastPathDecision::Slow,
        };

        // (1)/(2) UFT hit without invalidation -- We know the result for stats purposes.
        match &decision {
            FastPathDecision::CompiledUft { .. }
            | FastPathDecision::Uft { .. } => {
                // XXX: Ideally the Kstat should be holding AtomicU64s, then we get
                // out of the lock sooner. Note that we don't need to *apply* a given
                // set of transforms in order to know which stats we'll modify.
                // Also, not an elegant hack!
                let dummy_res = Ok(InternalProcessResult::Modified);
                match dir {
                    Direction::In => {
                        Self::update_stats_in(&mut data.stats.vals, &dummy_res)
                    }
                    Direction::Out => {
                        Self::update_stats_out(&mut data.stats.vals, &dummy_res)
                    }
                }
            }
            _ => {}
        }

        // (1) Execute precompiled, and exit.
        if let FastPathDecision::CompiledUft { tx, l4_hash } = decision {
            drop(data);

            let len = pkt.len();
            let meta = pkt.meta_mut();
            let body_csum = if tx.checksums_dirty {
                meta.compute_body_csum()
            } else {
                None
            };
            meta.run_compiled_transform(&tx);
            if let Some(csum) = body_csum {
                meta.update_ulp_checksums(csum);
            }
            let encap_len = meta.encap_len();
            let ulp_len = (len - (encap_len as usize)) as u32;
            let rewind = match tx.encap {
                CompiledEncap::Pop => encap_len,
                _ => 0,
            };
            let out = EmittestSpec {
                spec: EmitterSpec::Fastpath(tx),
                l4_hash,
                rewind,
                ulp_len,
            };

            let flow_after = meta.flow();
            let res = Ok(ProcessResult::Modified(out));
            self.port_process_return_probe(
                dir,
                &flow_before,
                &flow_after,
                epoch,
                // &pkt,
                &res,
            );
            return res;
        }

        // (2)/(3) Full-fat metadata is required.
        let mut pkt = pkt.to_full_meta();
        let mut ameta = ActionMeta::new();

        // TODO: remove/convert to a slopath indicator?
        self.port_process_entry_probe(dir, &flow_before, epoch, &pkt);

        let res = match (&decision, dir) {
            // (2) Drop lock, then apply retrieved transform.
            // Store cached l4 hash.
            (FastPathDecision::Uft { tx, l4_hash }, _) => {
                drop(data);
                pkt.set_l4_hash(*l4_hash);
                tx.apply(&mut pkt, dir)?;
                Ok(InternalProcessResult::Modified)
            }

            // (3) Full-table processing for the packet, then drop the lock.
            // Cksum updates are the only thing left undone.
            (FastPathDecision::Slow, Direction::In) => {
                let res = self.process_in_miss(
                    &mut data,
                    epoch,
                    &mut pkt,
                    &flow_before,
                    &mut ameta,
                );
                Self::update_stats_in(&mut data.stats.vals, &res);
                drop(data);
                pkt.update_checksums();
                res
            }
            (FastPathDecision::Slow, Direction::Out) => {
                let res = self
                    .process_out_miss(&mut data, epoch, &mut pkt, &mut ameta);
                Self::update_stats_out(&mut data.stats.vals, &res);
                drop(data);
                pkt.update_checksums();
                res
            }
            _ => unreachable!(),
        };

        let flow_after = *pkt.flow();

        let res = res.map(|v| match v {
            InternalProcessResult::Bypass => ProcessResult::Bypass,
            InternalProcessResult::Drop { reason } => {
                ProcessResult::Drop { reason }
            }
            InternalProcessResult::Hairpin(v) => ProcessResult::Hairpin(v),
            InternalProcessResult::Modified => {
                let l4_hash = pkt.l4_hash();
                let emit_spec = pkt.emit_spec();

                // TODO: remove EmitSpec and have above method just spit out the new
                // variant.
                ProcessResult::Modified(EmittestSpec {
                    spec: EmitterSpec::Slowpath(emit_spec.push_spec.into()),
                    l4_hash,
                    rewind: emit_spec.rewind,
                    ulp_len: emit_spec.encapped_len as u32,
                })
            }
        });
        self.port_process_return_probe(
            dir,
            &flow_before,
            &flow_after,
            epoch,
            // &pkt,
            &res,
        );
        res
    }

    // hope and pray we find a ULP, then use that?
    pub fn thin_process(
        &self,
        dir: Direction,
        pkt: &mut Packet2<ParsedMblk>,
    ) -> result::Result<ThinProcRes, ProcessError> {
        use super::ingot_base::EthernetMut;
        use super::ingot_base::Ipv4Mut;
        use super::ingot_base::Ipv6Mut;
        use super::ingot_base::Ulp;
        use super::ingot_base::L3;
        use ingot::icmp::IcmpV4Mut;
        use ingot::icmp::IcmpV4Ref;
        use ingot::icmp::IcmpV6Mut;
        use ingot::icmp::IcmpV6Ref;
        use ingot::tcp::TcpFlags;
        use ingot::tcp::TcpMut;
        use ingot::udp::UdpMut;

        let flow_before = pkt.flow();
        // let flow_before = *pkt.flow();
        let _epoch = self.epoch.load(SeqCst);
        let mut data = self.data.lock();
        check_state!(data.state, [PortState::Running])
            .map_err(|_| ProcessError::BadState(data.state))?;

        let mut dirty_csum = false;

        // self.port_process_entry_probe(dir, &flow_before, epoch, pskt);
        // TODO: what stats? lmao
        match dir {
            Direction::Out => {
                // opte::engine::err!("looking up {:?} in outdir...", flow_before);
                let a = data.uft_out.get(&flow_before);
                let Some(a) = a else {
                    // eh. It will get recirc'd for free...
                    // opte::engine::err!("not found! Releasing!");
                    return Err(ProcessError::FlowTableFull {
                        kind: "()",
                        limit: 0,
                    });
                };
                pkt.set_l4_hash(a.state().l4_hash);
                // opte::engine::err!("found!");
                let xforms = Arc::clone(&a.state().xforms);
                Self::update_stats_out(
                    &mut data.stats.vals,
                    &Ok(InternalProcessResult::Modified),
                );
                drop(data);

                let hm = &mut pkt.meta_mut().headers;

                let mut new_eth = None;
                let mut new_ip = None;
                let mut new_encap = None;
                // opte::engine::err!("xforms {:?}!", &a.state().xforms.hdr);
                for xf in &xforms.hdr {
                    // opte::engine::err!("xf...");
                    if let HeaderAction::Push(outer_eth) = &xf.outer_ether {
                        new_eth = Some(outer_eth.clone());
                    }
                    if let HeaderAction::Push(outer_ip) = &xf.outer_ip {
                        new_ip = Some(outer_ip.clone());
                    }
                    if let HeaderAction::Push(outer_ec) = &xf.outer_encap {
                        new_encap = Some(outer_ec.clone());
                    }
                    if let HeaderAction::Modify(m) = &xf.inner_ether {
                        if let Some(src) = m.src {
                            hm.inner_eth.set_source(src);
                        }
                        if let Some(dst) = m.dst {
                            hm.inner_eth.set_destination(dst);
                        }
                    }
                    if let HeaderAction::Modify(m) = &xf.inner_ip {
                        match m {
                            super::headers::IpMod::Ip4(v4) => {
                                let Some(L3::Ipv4(ref mut v4_t)) = hm.inner_l3
                                else {
                                    return Err(ProcessError::FlowTableFull {
                                        kind: "()",
                                        limit: 0,
                                    });
                                };
                                if let Some(src) = v4.src {
                                    dirty_csum = true;
                                    v4_t.set_source(src.into());
                                }
                                if let Some(dst) = v4.dst {
                                    dirty_csum = true;
                                    v4_t.set_destination(dst.into());
                                }
                            }
                            super::headers::IpMod::Ip6(v6) => {
                                let Some(L3::Ipv6(ref mut v6_t)) = hm.inner_l3
                                else {
                                    return Err(ProcessError::FlowTableFull {
                                        kind: "()",
                                        limit: 0,
                                    });
                                };
                                if let Some(src) = v6.src {
                                    dirty_csum = true;
                                    v6_t.set_source(src.into());
                                }
                                if let Some(dst) = v6.dst {
                                    dirty_csum = true;
                                    v6_t.set_destination(dst.into());
                                }
                            }
                        }
                    }
                    if let UlpHeaderAction::Modify(m) = &xf.inner_ulp {
                        if let Some(src) = &m.generic.src_port {
                            match hm.inner_ulp {
                                Some(Ulp::Tcp(ref mut t)) => {
                                    dirty_csum = true;
                                    t.set_source(*src)
                                }
                                Some(Ulp::Udp(ref mut t)) => {
                                    dirty_csum = true;
                                    t.set_source(*src)
                                }
                                _ => {}
                            }
                        }
                        if let Some(dst) = &m.generic.dst_port {
                            match hm.inner_ulp {
                                Some(Ulp::Tcp(ref mut t)) => {
                                    dirty_csum = true;
                                    t.set_destination(*dst)
                                }
                                Some(Ulp::Udp(ref mut t)) => {
                                    dirty_csum = true;
                                    t.set_destination(*dst)
                                }
                                _ => {}
                            }
                        }
                        if let Some(flags) = &m.tcp_flags {
                            match hm.inner_ulp {
                                Some(Ulp::Tcp(ref mut t)) => {
                                    dirty_csum = true;
                                    t.set_flags(TcpFlags::from_bits_retain(
                                        *flags,
                                    ))
                                }
                                _ => {}
                            }
                        }
                        if let Some(new_id) = &m.icmp_id {
                            match hm.inner_ulp {
                                Some(Ulp::IcmpV4(ref mut pkt))
                                    if pkt.ty() == 0 || pkt.ty() == 3 =>
                                {
                                    dirty_csum = true;
                                    pkt.rest_of_hdr_mut()[..2]
                                        .copy_from_slice(&new_id.to_be_bytes())
                                }
                                Some(Ulp::IcmpV6(ref mut pkt))
                                    if pkt.ty() == 128 || pkt.ty() == 129 =>
                                {
                                    dirty_csum = true;
                                    pkt.rest_of_hdr_mut()[..2]
                                        .copy_from_slice(&new_id.to_be_bytes())
                                }
                                _ => {}
                            }
                        }
                    }
                }

                if dirty_csum {
                    // TODO: something.
                }

                match (new_eth, new_ip, new_encap) {
                    (Some(a), Some(b), Some(c)) => {
                        Ok(ThinProcRes::PushEncap(a, b, c))
                    }
                    (None, None, None) => Ok(ThinProcRes::Na),
                    _ => Err(ProcessError::FlowTableFull {
                        kind: "()",
                        limit: 0,
                    }),
                }
            }

            Direction::In => {
                let a = data.uft_in.get(&flow_before);
                let Some(a) = a else {
                    // eh.
                    return Err(ProcessError::FlowTableFull {
                        kind: "()",
                        limit: 0,
                    });
                };
                pkt.set_l4_hash(a.state().l4_hash);
                let xforms = Arc::clone(&a.state().xforms);
                Self::update_stats_in(
                    &mut data.stats.vals,
                    &Ok(InternalProcessResult::Modified),
                );
                drop(data);

                let hm = &mut pkt.meta_mut().headers;

                let mut pop_eth = false;
                let mut pop_ip = false;
                let mut pop_encap = false;
                for xf in &xforms.hdr {
                    // opte::engine::err!("xf...");
                    if let HeaderAction::Pop = &xf.outer_ether {
                        pop_eth = true;
                    }
                    if let HeaderAction::Pop = &xf.outer_ip {
                        pop_ip = true;
                    }
                    if let HeaderAction::Pop = &xf.outer_encap {
                        pop_encap = true;
                    }
                    if let HeaderAction::Modify(m) = &xf.inner_ether {
                        if let Some(src) = m.src {
                            hm.inner_eth.set_source(src);
                        }
                        if let Some(dst) = m.dst {
                            hm.inner_eth.set_destination(dst);
                        }
                    }
                    if let HeaderAction::Modify(m) = &xf.inner_ip {
                        match m {
                            super::headers::IpMod::Ip4(v4) => {
                                let Some(L3::Ipv4(ref mut v4_t)) = hm.inner_l3
                                else {
                                    return Err(ProcessError::FlowTableFull {
                                        kind: "()",
                                        limit: 0,
                                    });
                                };
                                if let Some(src) = v4.src {
                                    dirty_csum = true;
                                    v4_t.set_source(src.into());
                                }
                                if let Some(dst) = v4.dst {
                                    dirty_csum = true;
                                    v4_t.set_destination(dst.into());
                                }
                            }
                            super::headers::IpMod::Ip6(v6) => {
                                let Some(L3::Ipv6(ref mut v6_t)) = hm.inner_l3
                                else {
                                    return Err(ProcessError::FlowTableFull {
                                        kind: "()",
                                        limit: 0,
                                    });
                                };
                                if let Some(src) = v6.src {
                                    dirty_csum = true;
                                    v6_t.set_source(src.into());
                                }
                                if let Some(dst) = v6.dst {
                                    dirty_csum = true;
                                    v6_t.set_destination(dst.into());
                                }
                            }
                        }
                    }
                    if let UlpHeaderAction::Modify(m) = &xf.inner_ulp {
                        if let Some(src) = &m.generic.src_port {
                            match hm.inner_ulp {
                                Some(Ulp::Tcp(ref mut t)) => {
                                    dirty_csum = true;
                                    t.set_source(*src)
                                }
                                Some(Ulp::Udp(ref mut t)) => {
                                    dirty_csum = true;
                                    t.set_source(*src)
                                }
                                _ => {}
                            }
                        }
                        if let Some(dst) = &m.generic.dst_port {
                            match hm.inner_ulp {
                                Some(Ulp::Tcp(ref mut t)) => {
                                    dirty_csum = true;
                                    t.set_destination(*dst)
                                }
                                Some(Ulp::Udp(ref mut t)) => {
                                    dirty_csum = true;
                                    t.set_destination(*dst)
                                }
                                _ => {}
                            }
                        }
                        if let Some(flags) = &m.tcp_flags {
                            match hm.inner_ulp {
                                Some(Ulp::Tcp(ref mut t)) => {
                                    dirty_csum = true;
                                    t.set_flags(TcpFlags::from_bits_retain(
                                        *flags,
                                    ))
                                }
                                _ => {}
                            }
                        }
                        if let Some(new_id) = &m.icmp_id {
                            match hm.inner_ulp {
                                Some(Ulp::IcmpV4(ref mut pkt))
                                    if pkt.ty() == 0 || pkt.ty() == 3 =>
                                {
                                    dirty_csum = true;
                                    pkt.rest_of_hdr_mut()[..2]
                                        .copy_from_slice(&new_id.to_be_bytes())
                                }
                                Some(Ulp::IcmpV6(ref mut pkt))
                                    if pkt.ty() == 128 || pkt.ty() == 129 =>
                                {
                                    dirty_csum = true;
                                    pkt.rest_of_hdr_mut()[..2]
                                        .copy_from_slice(&new_id.to_be_bytes())
                                }
                                _ => {}
                            }
                        }
                    }
                }

                if dirty_csum {
                    // TODO: do something.
                }

                match (pop_eth, pop_ip, pop_encap) {
                    (true, true, true) => Ok(ThinProcRes::PopEncap),
                    (false, false, false) => Ok(ThinProcRes::Na),
                    _ => Err(ProcessError::FlowTableFull {
                        kind: "()",
                        limit: 0,
                    }),
                }
            }
        }
    }

    /// Remove the rule identified by the `dir`, `layer_name`, `id`
    /// combination, if such a rule exists.
    ///
    /// The port's epoch is moved forward; flows processed after this
    /// call will have their UFT entry invalidated and recomputed
    /// lazily on the next packet to arrive.
    ///
    /// # Errors
    ///
    /// If the layer does not exist, an error is returned.
    ///
    /// # States
    ///
    /// This command is valid for the following states:
    ///
    /// * [`PortState::Ready`]
    /// * [`PortState::Running`]
    pub fn remove_rule(
        &self,
        layer_name: &str,
        dir: Direction,
        id: RuleId,
    ) -> Result<()> {
        let mut data = self.data.lock();
        check_state!(data.state, [PortState::Ready, PortState::Running])?;

        for layer in &mut data.layers {
            if layer.name() == layer_name {
                match layer.remove_rule(dir, id) {
                    Err(_) => return Err(OpteError::RuleNotFound(id)),
                    Ok(()) => {
                        // XXX There is a tiny window between the rule being
                        // removed and the epoch incremented. For now we don't
                        // worry about this as a few packets getting by with
                        // the old rule set is not a major issue. But in the
                        // future we could eliminate this window by passing a
                        // reference to the epoch to `Layer::remove_rule()`
                        // and let it perform the increment.
                        // XXX(kyle) Above comment misunderstands TOCTOU --
                        //           THE TABLE IS LOCKED.
                        self.epoch.fetch_add(1, SeqCst);
                        return Ok(());
                    }
                }
            }
        }

        Err(OpteError::LayerNotFound(layer_name.to_string()))
    }

    /// For the given layer, set both the inbound and outbound rules
    /// atomically.
    ///
    /// This operation replaces the current inbound and outbound rule
    /// sets with the ones passed as argument; it is not additive.
    ///
    /// The port's epoch is moved forward; flows processed after this
    /// call will have their UFT entry invalidated and recomputed
    /// lazily on the next packet to arrive.
    ///
    /// # Errors
    ///
    /// If the layer does not exist, an error is returned.
    ///
    /// # States
    ///
    /// This command is valid for the following states:
    ///
    /// * [`PortState::Ready`]
    /// * [`PortState::Running`]
    pub fn set_rules(
        &self,
        layer_name: &str,
        in_rules: Vec<Rule<Finalized>>,
        out_rules: Vec<Rule<Finalized>>,
    ) -> Result<()> {
        let mut data = self.data.lock();
        check_state!(data.state, [PortState::Ready, PortState::Running])?;

        for layer in &mut data.layers {
            if layer.name() == layer_name {
                self.epoch.fetch_add(1, SeqCst);
                layer.set_rules(in_rules, out_rules);
                return Ok(());
            }
        }

        Err(OpteError::LayerNotFound(layer_name.to_string()))
    }

    // TODO: not dupe `set_rules`.
    pub fn set_rules_soft(
        &self,
        layer_name: &str,
        in_rules: Vec<Rule<Finalized>>,
        out_rules: Vec<Rule<Finalized>>,
    ) -> Result<()> {
        let mut data = self.data.lock();
        check_state!(data.state, [PortState::Ready, PortState::Running])?;

        for layer in &mut data.layers {
            if layer.name() == layer_name {
                self.epoch.fetch_add(1, SeqCst);
                layer.set_rules_soft(in_rules, out_rules);
                return Ok(());
            }
        }

        Err(OpteError::LayerNotFound(layer_name.to_string()))
    }

    /// Grab a snapshot of the port statistics.
    pub fn stats_snap(&self) -> PortStatsSnap {
        self.data.lock().stats.vals.snapshot()
    }

    /// Return the [`TcpState`] of a given flow.
    #[cfg(any(feature = "test-help", test))]
    pub fn tcp_state(&self, flow: &InnerFlowId) -> Option<TcpState> {
        self.data
            .lock()
            .tcp_flows
            .get(flow)
            .map(|entry| entry.state().tcp_state.tcp_state())
    }
}

#[allow(dead_code)]
#[derive(Debug)]
enum TcpMaybeClosed {
    Closed { ufid_inbound: Option<InnerFlowId> },
    NewState(TcpState),
}

impl From<TcpMaybeClosed> for TcpState {
    fn from(value: TcpMaybeClosed) -> Self {
        match value {
            TcpMaybeClosed::Closed { .. } => TcpState::Closed,
            TcpMaybeClosed::NewState(s) => s,
        }
    }
}

pub enum ThinProcRes {
    PushEncap(EtherMeta, IpPush, EncapPush),
    PopEncap,
    Na,
}

// This is a convenience wrapper for keeping the header and body
// transformations under one structure, allowing them to be passes as
// one argument.
#[derive(Clone)]
pub(crate) struct Transforms {
    pub(crate) hdr: Vec<HdrTransform>,
    pub(crate) body: Vec<Box<dyn BodyTransform>>,
    pub(crate) compiled: Option<Arc<CompiledTransform>>,
}

impl Transforms {
    fn new() -> Self {
        Self {
            hdr: Vec::with_capacity(8),
            body: Vec::with_capacity(2),
            compiled: None,
        }
    }

    #[inline]
    fn apply<T: Read>(
        &self,
        pkt: &mut Packet2<Parsed2<T>>,
        dir: Direction,
    ) -> result::Result<(), ProcessError>
    where
        T::Chunk: ByteSliceMut,
    {
        // TODO: prebake these into one transform?
        for ht in &self.hdr {
            pkt.hdr_transform(ht)?;
        }

        for bt in &self.body {
            pkt.body_transform(dir, &**bt)?;
        }

        pkt.update_checksums();

        Ok(())
    }

    #[inline]
    fn compile(mut self, checksums_dirty: bool) -> Arc<Self> {
        // Compile to a fasterpath transform iff. no body transform.
        if self.body.is_empty() {
            let mut still_permissable = true;

            let mut outer_ether = None;
            let mut outer_ip = None;
            let mut outer_encap = None;

            let mut inner_ether = None;
            let mut inner_ip = None;
            let mut inner_ulp = None;
            for transform in &self.hdr {
                if !still_permissable {
                    continue;
                }

                // TODO: refactor.

                // All outer layers must be pushed (or popped/ignored) at the same
                // time for compilation. No modifications are permissable.
                match transform.outer_ether {
                    HeaderAction::Push(p) => outer_ether = Some(p),
                    HeaderAction::Pop => {
                        outer_ether = None;
                    }
                    HeaderAction::Modify(_) => {
                        still_permissable = false;
                    }
                    HeaderAction::Ignore => {}
                }

                match transform.outer_ip {
                    HeaderAction::Push(p) => outer_ip = Some(p),
                    HeaderAction::Pop => {
                        outer_ip = None;
                    }
                    HeaderAction::Modify(_) => {
                        still_permissable = false;
                    }
                    HeaderAction::Ignore => {}
                }

                match transform.outer_encap {
                    HeaderAction::Push(p) => outer_encap = Some(p),
                    HeaderAction::Pop => {
                        outer_encap = None;
                    }
                    HeaderAction::Modify(_) => {
                        still_permissable = false;
                    }
                    HeaderAction::Ignore => {}
                }

                // Allow up to one action per ULP field, which must be modify.
                // We can't yet combine sets of `Modify` actions,
                // but the Oxide dataplane does not use this in practice.
                match &transform.inner_ether {
                    HeaderAction::Push(_) | HeaderAction::Pop => {
                        still_permissable = false;
                        continue;
                    }
                    HeaderAction::Modify(m) => {
                        still_permissable &= !inner_ether.replace(m).is_some();
                    }
                    HeaderAction::Ignore => {}
                }

                match &transform.inner_ip {
                    HeaderAction::Push(_) | HeaderAction::Pop => {
                        still_permissable = false;
                        continue;
                    }
                    HeaderAction::Modify(m) => {
                        still_permissable &= !inner_ip.replace(m).is_some();
                    }
                    HeaderAction::Ignore => {}
                }

                match &transform.inner_ulp {
                    UlpHeaderAction::Modify(m) => {
                        still_permissable &= !inner_ulp.replace(m).is_some();
                    }
                    UlpHeaderAction::Ignore => {}
                }
            }

            if still_permissable {
                let encap = match (outer_ether, outer_ip, outer_encap) {
                    (Some(eth), Some(ip), Some(enc)) => {
                        Some(CompiledEncap::Push(eth, ip, enc))
                    }
                    (None, None, None) => Some(CompiledEncap::Pop),
                    _ => None,
                };

                if let Some(encap) = encap {
                    self.compiled = Some(
                        CompiledTransform {
                            encap,
                            inner_ether: inner_ether.cloned(),
                            inner_ip: inner_ip.cloned(),
                            inner_ulp: inner_ulp.cloned(),
                            checksums_dirty,
                        }
                        .into(),
                    );
                }
            }
        }

        Arc::new(self)
    }
}

impl fmt::Debug for Transforms {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let body_strs =
            self.body.iter().map(ToString::to_string).collect::<Vec<String>>();
        f.debug_struct("Transforms")
            .field("hdr", &self.hdr)
            .field("body", &body_strs)
            .field("compiled", &self.compiled)
            .finish()
    }
}

// Keeping the private functions here just for the sake of code
// organization.
impl<N: NetworkImpl> Port<N> {
    // Process the packet against each layer in turn. If `Allow` is
    // returned, then `meta` contains the updated metadata, and `hts`
    // contains the list of header transformations to run against the
    // metadata.
    //
    // Processing may return early for several reasons.
    //
    // * Deny: A layer can choose to deny a packet, in which case the
    // packet is dropped and no further processing is done.
    //
    // * Hairpin: A layer has generated a hairpin packet.
    //
    // * Error: An error has ocurred and processing cannot continue.
    fn layers_process(
        &self,
        data: &mut PortData,
        dir: Direction,
        pkt: &mut Packet2<ParsedMblk>,
        xforms: &mut Transforms,
        ameta: &mut ActionMeta,
    ) -> result::Result<LayerResult, LayerError> {
        match dir {
            Direction::Out => {
                for layer in &mut data.layers {
                    let res =
                        layer.process(&self.ectx, dir, pkt, xforms, ameta);

                    match res {
                        Ok(LayerResult::Allow) => (),
                        ret @ Ok(LayerResult::Deny { .. }) => return ret,
                        ret @ Ok(LayerResult::Hairpin(_)) => return ret,
                        ret @ Ok(LayerResult::HandlePkt) => return ret,
                        ret @ Err(_) => return ret,
                    }
                }
            }

            Direction::In => {
                for layer in data.layers.iter_mut().rev() {
                    let res =
                        layer.process(&self.ectx, dir, pkt, xforms, ameta);

                    match res {
                        Ok(LayerResult::Allow) => (),
                        ret @ Ok(LayerResult::Deny { .. }) => return ret,
                        ret @ Ok(LayerResult::Hairpin(_)) => return ret,
                        ret @ Ok(LayerResult::HandlePkt) => return ret,
                        ret @ Err(_) => return ret,
                    }
                }
            }
        }

        Ok(LayerResult::Allow)
    }

    fn port_process_entry_probe(
        &self,
        dir: Direction,
        flow: &InnerFlowId,
        epoch: u64,
        pkt: &Packet2<ParsedMblk>,
    ) {
        cfg_if::cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                unsafe {
                    __dtrace_probe_port__process__entry(
                        dir as uintptr_t,
                        self.name_cstr.as_ptr() as uintptr_t,
                        flow,
                        epoch as uintptr_t,
                        pkt.mblk_addr(),
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                let flow_s = flow.to_string();
                crate::opte_provider::port__process__entry!(
                    || (dir, &self.name, flow_s, epoch, pkt.mblk_addr())
                );
            } else {
                let (..) = (dir, flow, epoch, pkt);
            }
        }
    }

    fn port_process_return_probe(
        &self,
        dir: Direction,
        flow_before: &InnerFlowId,
        flow_after: &InnerFlowId,
        epoch: u64,
        // pkt: &Packet2<ParsedMblk>,
        res: &result::Result<ProcessResult, ProcessError>,
    ) {
        // let flow_after = pkt.flow();
        let mblk_addr = 0; // TODO.

        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {

                // XXX This would probably be better as separate probes;
                // for now this does the trick.
                let (eb, extra_str) = match res {
                    Ok(v @ ProcessResult::Drop { reason }) => (
                        LabelBlock::from_nested(v),
                        Some(format!("{reason:?}\0"))
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

                let hp_pkt_ptr = match res {
                    Ok(ProcessResult::Hairpin(hp)) => {
                        hp.mblk_addr()
                    }
                    _ => 0,
                };

                unsafe {
                    if let Some(extra_cstr) = extra_cstr {
                        let _ = eb.append_name_raw(extra_cstr);
                    }
                    __dtrace_probe_port__process__return(
                        dir as uintptr_t,
                        self.name_cstr.as_ptr() as uintptr_t,
                        flow_before,
                        flow_after,
                        epoch as uintptr_t,
                        mblk_addr,
                        hp_pkt_ptr,
                        eb.as_ptr(),
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                let flow_b_s = flow_before.to_string();
                let flow_a_s = flow_after.to_string();
                let res_str = match res {
                    Ok(v) => format!("{:?}", v),
                    Err(e) => format!("ERROR: {:?}", e),
                };

                crate::opte_provider::port__process__return!(
                    || (
                        (dir, self.name.as_str()),
                        (flow_b_s.as_ref(), flow_a_s.as_ref()),
                        epoch,
                        mblk_addr,
                        res_str
                    )
                );
            } else {
                let (..) = (dir, flow_before, flow_after, epoch, /*pkt,*/ res);
            }
        }
    }

    /// Creates a new TCP flow state entry for a given packet.
    ///
    /// # Errors
    /// * `OpteError::MaxCapacity(_)` if the TCP flows table is full.
    /// * `ProcessError::TcpFlow(_)` if we do not have a valid transition from
    ///   `Closed` based on the packet state.
    fn create_new_tcp_entry(
        &self,
        tcp_flows: &mut FlowTable<TcpFlowEntryState>,
        tcp: &TcpMeta,
        dir: &TcpDirection,
        pkt_len: u64,
    ) -> result::Result<TcpState, ProcessError> {
        // Create a new entry and find its current state. In
        // this case it should always be `SynSent`, unless we're
        // recovering an `Established` flow.
        let mut tfs = TcpFlowState::new();

        let tcp_state = match tfs.process(
            self.name_cstr.as_c_str(),
            dir.dir(),
            dir.local_flow(),
            tcp,
        ) {
            Ok(tcp_state) => tcp_state,

            // We're intentionally not allowing through unexpected segments or
            // new flow conditions: SYN packets will always be accepted in the
            // starting states, and we have valid shortcuts back into `Established`.
            Err(e) => return Err(ProcessError::TcpFlow(e)),
        };

        if tcp_state != TcpState::Closed {
            // The inbound UFID is determined on the inbound side.
            let (ufid_out, tfes) = match *dir {
                TcpDirection::In { ufid_in, ufid_out } => (
                    ufid_out,
                    TcpFlowEntryState::new_inbound(*ufid_in, tfs, pkt_len),
                ),
                TcpDirection::Out { ufid_out } => {
                    (ufid_out, TcpFlowEntryState::new_outbound(tfs, pkt_len))
                }
            };
            match tcp_flows.add(*ufid_out, tfes) {
                Ok(_) => {}
                Err(OpteError::MaxCapacity(limit)) => {
                    return Err(ProcessError::FlowTableFull {
                        kind: "TCP",
                        limit,
                    });
                }
                Err(_) => unreachable!(
                    "Cannot return other errors from FlowTable::add"
                ),
            };
        }

        Ok(tcp_state)
    }

    /// Attempts to lookup and update TCP flowstate in response to a given
    /// packet.
    ///
    /// Unexpected TCP segments on existing connections will be allowed,
    /// but will fire DTrace probes via `Self::tcp_err_probe`.
    ///
    /// # Errors
    /// * `ProcessError::MissingFlow` if no flow currently exists.
    /// * `ProcessError::TcpFlow(NewFlow { .. })` if this packet retired
    ///   an existing TCP flow state entry.
    ///
    /// Callers which expect an existing TCP flow entry due to an existing UFT
    /// (e.g. `process_out_tcp_existing`) should respond to `NewFlow` by creating
    /// a new TCP flow table entry. Where possible, this should be done by treating
    /// a packet as a UFT miss (e.g., `process_out_miss`) and reprocessing the flow.
    fn update_tcp_entry(
        &self,
        mut data: PortDataOrSubset,
        tcp: &TcpMeta,
        dir: &TcpDirection,
        pkt_len: u64,
    ) -> result::Result<TcpMaybeClosed, ProcessError> {
        let tcp_flows = data.tcp_flows();
        let (ufid_out, ufid_in) = match *dir {
            TcpDirection::In { ufid_in, ufid_out } => (ufid_out, Some(ufid_in)),
            TcpDirection::Out { ufid_out } => (ufid_out, None),
        };

        let Some(entry) = tcp_flows.get_mut(ufid_out) else {
            return Err(ProcessError::MissingFlow(*ufid_out));
        };

        entry.hit();
        let tfes = entry.state_mut();
        match *dir {
            TcpDirection::In { .. } => {
                tfes.segs_in += 1;
                tfes.bytes_in += pkt_len;
            }
            TcpDirection::Out { .. } => {
                tfes.segs_out += 1;
                tfes.bytes_out += pkt_len;
            }
        }

        let next_state = tfes.tcp_state.process(
            self.name_cstr.as_c_str(),
            dir.dir(),
            ufid_out,
            tcp,
        );

        if let Some(ufid_in) = ufid_in {
            // We need to store the UFID of the inbound packet
            // before it was processed so that we can retire the
            // correct UFT/LFT entries upon connection
            // termination.
            tfes.inbound_ufid = Some(*ufid_in);
        }

        let ufid_inbound = if matches!(
            next_state,
            Ok(TcpState::Closed) | Err(TcpFlowStateError::NewFlow { .. })
        ) {
            // Due to order of operations, out_tcp_existing must
            // call uft_tcp_closed separately.
            let entry = tcp_flows.remove(ufid_out).unwrap();
            let state_ufid = entry.state().inbound_ufid;

            if let PortDataOrSubset::Port(data) = data {
                // The inbound side of the UFT is based on
                // the network-side of the flow (pre-processing).
                self.uft_tcp_closed(data, ufid_out, state_ufid.as_ref());
            }

            ufid_in.copied().or(state_ufid)
        } else {
            None
        };

        let next_state = match next_state {
            Ok(a) => Ok(a),
            Err(e @ TcpFlowStateError::UnexpectedSegment { state, .. }) => {
                self.tcp_err_probe(
                    dir.dir(),
                    None,
                    dir.local_flow(),
                    e.to_string(),
                );
                Ok(state)
            }
            Err(e) => Err(ProcessError::TcpFlow(e)),
        }?;

        Ok(match next_state {
            TcpState::Closed => TcpMaybeClosed::Closed { ufid_inbound },
            a => TcpMaybeClosed::NewState(a),
        })
    }

    // Process the TCP packet for the purposes of connection tracking
    // when an inbound UFT entry exists.
    fn process_in_tcp(
        &self,
        data: &mut PortData,
        pmeta: &PacketMeta,
        ufid_in: &InnerFlowId,
        pkt_len: u64,
    ) -> result::Result<TcpState, ProcessError> {
        // All TCP flows are keyed with respect to the outbound Flow
        // ID, therefore we mirror the flow. This value must represent
        // the guest-side of the flow and thus come from the passed-in
        // packet metadata that represents the post-processed packet.
        let ufid_out = InnerFlowId::from(pmeta).mirror();

        // Unwrap: We know this is a TCP packet at this point.
        //
        // XXX This will be even more foolproof in the future when
        // we've implemented the notion of FlowSet and Packet is
        // generic on header group/flow type.
        let tcp = pmeta.inner_tcp().unwrap();

        let dir = TcpDirection::In { ufid_in, ufid_out: &ufid_out };

        match self.update_tcp_entry(
            PortDataOrSubset::Port(data),
            tcp,
            &dir,
            pkt_len,
        ) {
            // We need to create a new TCP entry here because we can't call
            // `process_in_miss` on the already-modified packet.
            e @ Err(
                ProcessError::TcpFlow(TcpFlowStateError::NewFlow { .. })
                | ProcessError::MissingFlow(_),
            ) => {
                self.create_new_tcp_entry(
                    &mut data.tcp_flows,
                    tcp,
                    &dir,
                    pkt_len,
                )?;
                e.map(Into::into)
            }
            Ok(v) => Ok(v.into()),
            Err(e) => Err(e),
        }
    }

    fn process_in_miss(
        &self,
        data: &mut PortData,
        epoch: u64,
        pkt: &mut Packet2<ParsedMblk>,
        ufid_in: &InnerFlowId,
        ameta: &mut ActionMeta,
    ) -> result::Result<InternalProcessResult, ProcessError> {
        use Direction::In;

        data.stats.vals.in_uft_miss += 1;
        let mut xforms = Transforms::new();
        let res = self.layers_process(data, In, pkt, &mut xforms, ameta);
        match res {
            Ok(LayerResult::Allow) => {
                // If there is no flow ID, then do not create a UFT
                // entry.
                if *ufid_in == FLOW_ID_DEFAULT {
                    return Ok(InternalProcessResult::Modified);
                }
            }

            Ok(LayerResult::Deny { name, reason }) => {
                return Ok(InternalProcessResult::Drop {
                    reason: DropReason::Layer { name, reason },
                })
            }

            Ok(LayerResult::Hairpin(hppkt)) => {
                return Ok(InternalProcessResult::Hairpin(hppkt))
            }

            Ok(LayerResult::HandlePkt) => {
                return Ok(InternalProcessResult::from(self.net.handle_pkt(
                    In,
                    pkt,
                    &data.uft_in,
                    &data.uft_out,
                )?));
            }

            Err(e) => return Err(ProcessError::Layer(e)),
        }

        let ufid_out = pkt.flow().mirror();
        let hte = UftEntry {
            pair: Some(ufid_out),
            xforms: xforms.compile(pkt.checksums_dirty()),
            epoch,
            l4_hash: ufid_in.crc32(),
        };

        // Keep around the comment on the `None` arm
        #[allow(clippy::single_match)]
        match data.uft_out.get_mut(&ufid_out) {
            // If an outbound packet has already created an outbound
            // UFT entry, make sure to pair it to this inbound entry.
            Some(out_entry) => {
                // Remember, the inbound UFID is the flow as seen by
                // the network, before any processing is done by OPTE.
                out_entry.state_mut().pair = Some(*ufid_in);
            }

            // Ideally we would simulate the outbound flow if no
            // outbound UFT entry existed at this point as per VFP
            // §6.4.1. However, the act of "simulating" a flow hasn't
            // been implemented yet. For now we only lazily create UFT
            // outbound entries, which also means that their `pair`
            // value will be `None` in the case where the inbound
            // packet is the first one for a given flow (because OPTE
            // cannot assume symmetric UFIDs between inbound and
            // outbound).
            None => (),
        }

        // For inbound traffic the TCP flow table must be
        // checked _after_ processing take place.
        // TODO: uncork
        // if pkt.meta().is_inner_tcp() {
        //     match self.process_in_tcp(
        //         data,
        //         pkt.meta(),
        //         ufid_in,
        //         pkt.len() as u64,
        //     ) {
        //         Ok(TcpState::Closed) => Ok(InternalProcessResult::Modified { transform: todo!(), tcp_state: todo!() }),

        //         // Found existing TCP flow, or have just created a new one.
        //         Ok(_)
        //         | Err(ProcessError::TcpFlow(TcpFlowStateError::NewFlow {
        //             ..
        //         }))
        //         | Err(ProcessError::MissingFlow(_)) => {
        //             // We have a good TCP flow, create a new UFT entry.
        //             match data.uft_in.add(*ufid_in, hte) {
        //                 Ok(_) => Ok(InternalProcessResult::Modified { transform: todo!(), tcp_state: todo!() }),
        //                 Err(OpteError::MaxCapacity(limit)) => {
        //                     Err(ProcessError::FlowTableFull {
        //                         kind: "UFT",
        //                         limit,
        //                     })
        //                 }
        //                 Err(_) => unreachable!(
        //                     "Cannot return other errors from FlowTable::add"
        //                 ),
        //             }
        //         }

        //         // Unlike for existing flows, we don't allow through
        //         // unexpected packets here for now -- the `TcpState` FSM
        //         // already encodes a shortcut from `Closed` to `Established.
        //         Err(ProcessError::TcpFlow(err)) => {
        //             let e = format!("{err}");
        //             self.tcp_err(&data.tcp_flows, Direction::In, e, pkt);
        //             Ok(InternalProcessResult::Drop { reason: DropReason::TcpErr })
        //         }
        //         Err(ProcessError::FlowTableFull { kind, limit }) => {
        //             let e = format!("{kind} flow table full ({limit} entries)");
        //             self.tcp_err(&data.tcp_flows, Direction::In, e, pkt);
        //             Ok(InternalProcessResult::Drop { reason: DropReason::TcpErr })
        //         }
        //         res => unreachable!(
        //             "Cannot return other errors from \
        //             process_in_tcp, returned: {res:?}"
        //         ),
        //     }
        // } else {
        //     match data.uft_in.add(*ufid_in, hte) {
        //         Ok(_) => Ok(InternalProcessResult::Modified{ transform: todo!(), tcp_state: todo!() }),
        //         Err(OpteError::MaxCapacity(limit)) => {
        //             Err(ProcessError::FlowTableFull { kind: "UFT", limit })
        //         }
        //         Err(_) => unreachable!(
        //             "Cannot return other errors from FlowTable::add"
        //         ),
        //     }
        // }
        match data.uft_in.add(*ufid_in, hte) {
            Ok(_) => Ok(InternalProcessResult::Modified),
            Err(OpteError::MaxCapacity(limit)) => {
                Err(ProcessError::FlowTableFull { kind: "UFT", limit })
            }
            Err(_) => {
                unreachable!("Cannot return other errors from FlowTable::add")
            }
        }
    }

    #[allow(unused_variables)]
    fn uft_hit_probe(
        &self,
        dir: Direction,
        ufid: &InnerFlowId,
        epoch: u64,
        last_hit: &Moment,
    ) {
        cfg_if::cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                unsafe {
                    __dtrace_probe_uft__hit(
                        dir as uintptr_t,
                        self.name_cstr.as_ptr() as uintptr_t,
                        ufid,
                        epoch as uintptr_t,
                        last_hit.raw_millis().unwrap_or_default() as usize
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                let port_s = self.name_cstr.to_str().unwrap();
                let ufid_s = ufid.to_string();
                crate::opte_provider::uft__hit!(
                    || (dir, port_s, ufid_s, epoch, 0)
                );
            } else {
                let (_, _, _) = (dir, ufid, epoch);
            }
        }
    }

    // TODO: remove.
    fn process_in(
        &self,
        data: &mut PortData,
        epoch: u64,
        pkt: &mut Packet2<ParsedMblk>,
        ufid_in: &InnerFlowId,
        ameta: &mut ActionMeta,
    ) -> result::Result<InternalProcessResult, ProcessError> {
        use Direction::In;

        // Use the compiled UFT entry if one exists. Otherwise
        // fallback to layer processing.
        match data.uft_in.get_mut(ufid_in) {
            Some(entry) if entry.state().epoch == epoch => {
                // TODO At the moment I'm holding the UFT locks not
                // just for lookup, but for the entire duration of
                // processing. It might be better to ht.clone() or
                // Arc<HdrTransform>; that way we only hold the lock
                // for lookup.
                entry.hit();
                data.stats.vals.in_uft_hit += 1;
                self.uft_hit_probe(In, pkt.flow(), epoch, entry.last_hit());

                let transform = Some(Arc::clone(&entry.state().xforms));
                pkt.set_l4_hash(entry.state().l4_hash);

                // for ht in &entry.state().xforms.hdr {
                //     pkt.hdr_transform(ht)?;
                // }

                // for bt in &entry.state().xforms.body {
                //     pkt.body_transform(In, &**bt)?;
                // }

                // For inbound traffic the TCP flow table must be
                // checked _after_ processing take place.
                // TODO: uncork
                // if pkt.meta().is_inner_tcp() {
                //     match self.process_in_tcp(
                //         data,
                //         pkt.meta(),
                //         ufid_in,
                //         pkt.len() as u64,
                //     ) {
                //         Ok(_) => return Ok(ProcessResult::Modified),
                //         Err(ProcessError::TcpFlow(
                //             e @ TcpFlowStateError::NewFlow { .. },
                //         )) => {
                //             self.tcp_err(
                //                 &data.tcp_flows,
                //                 In,
                //                 e.to_string(),
                //                 pkt,
                //             );
                //             // We cant redo processing here like we can in `process_out`:
                //             // we already modified the packet to check TCP state.
                //             // However, we *have* deleted and replaced the TCP FSM and
                //             // removed the UFT. The next packet on this flow (SYN-ACK) will
                //             // create the UFT, reference the existing TCP flow, and increment
                //             // all other layers' stats.
                //             return Ok(ProcessResult::Modified);
                //         }
                //         Err(ProcessError::MissingFlow(flow_id)) => {
                //             let e = format!("Missing TCP flow ID: {flow_id}");
                //             self.tcp_err(
                //                 &data.tcp_flows,
                //                 Direction::In,
                //                 e,
                //                 pkt,
                //             );
                //             // If we have a UFT but no TCP flow ID, there is likely a bug
                //             // and we are now out of sync. As above we can't reprocess,
                //             // but we have regenerated the TCP entry to be less disruptive
                //             // than a drop. Remove the UFT entry on the same proviso since the
                //             // next packet to use it will regenerate it.
                //             self.uft_invalidate(
                //                 data,
                //                 None,
                //                 Some(ufid_in),
                //                 epoch,
                //             );
                //             return Ok(ProcessResult::Modified);
                //         }
                //         Err(ProcessError::TcpFlow(
                //             e @ TcpFlowStateError::UnexpectedSegment { .. },
                //         )) => {
                //             // Technically unreachable, as we filter these out in `update_tcp_entry`.
                //             // Panicking here would probably be overly fragile, however.
                //             self.tcp_err(
                //                 &data.tcp_flows,
                //                 Direction::In,
                //                 e.to_string(),
                //                 pkt,
                //             );
                //             return Ok(ProcessResult::Drop {
                //                 reason: DropReason::TcpErr,
                //             });
                //         }
                //         Err(ProcessError::FlowTableFull { kind, limit }) => {
                //             let e = format!(
                //                 "{kind} flow table full ({limit} entries)"
                //             );
                //             self.tcp_err(
                //                 &data.tcp_flows,
                //                 Direction::In,
                //                 e,
                //                 pkt,
                //             );
                //             return Ok(ProcessResult::Drop {
                //                 reason: DropReason::TcpErr,
                //             });
                //         }
                //         _ => unreachable!(
                //             "Cannot return other errors from process_in_tcp"
                //         ),
                //     }
                // } else {
                //     return Ok(ProcessResult::Modified);
                // }

                return Ok(InternalProcessResult::Modified);
            }

            // The entry is from a previous epoch; invalidate its UFT
            // entries and proceed to rule processing.
            Some(entry) => {
                let epoch = entry.state().epoch;
                let ufid_in = Some(ufid_in);
                let ufid_out = entry.state().pair;
                self.uft_invalidate(data, ufid_out.as_ref(), ufid_in, epoch);
            }

            // There is no entry; proceed to rule processing;
            None => (),
        };

        self.process_in_miss(data, epoch, pkt, ufid_in, ameta)
    }

    // Process the TCP packet for the purposes of connection tracking
    // when an outbound UFT entry exists.
    fn process_out_tcp_existing(
        &self,
        tcp_flows: &mut FlowTable<TcpFlowEntryState>,
        ufid_out: &InnerFlowId,
        pmeta: &PacketMeta,
        pkt_len: u64,
    ) -> result::Result<TcpMaybeClosed, ProcessError> {
        let tcp = pmeta.inner_tcp().unwrap();
        self.update_tcp_entry(
            PortDataOrSubset::Tcp(tcp_flows),
            tcp,
            &TcpDirection::Out { ufid_out },
            pkt_len,
        )
    }

    // Process the TCP packet for the purposes of connection tracking
    // when an outbound UFT entry was just created.
    fn process_out_tcp_new(
        &self,
        data: &mut PortData,
        ufid_out: &InnerFlowId,
        pmeta: &PacketMeta,
        pkt_len: u64,
    ) -> result::Result<TcpMaybeClosed, ProcessError> {
        let tcp = pmeta.inner_tcp().unwrap();
        let dir = TcpDirection::Out { ufid_out };

        match self.update_tcp_entry(
            PortDataOrSubset::Port(data),
            tcp,
            &dir,
            pkt_len,
        ) {
            Err(
                ProcessError::TcpFlow(TcpFlowStateError::NewFlow { .. })
                | ProcessError::MissingFlow(_),
            ) => match self.create_new_tcp_entry(
                &mut data.tcp_flows,
                tcp,
                &dir,
                pkt_len,
            ) {
                // Note: don't need to remove on this case, as create_new_tcp_entry
                // will only insert to the map if state != Closed.
                Ok(TcpState::Closed) => {
                    Ok(TcpMaybeClosed::Closed { ufid_inbound: None })
                }
                Ok(a) => Ok(TcpMaybeClosed::NewState(a)),
                Err(e) => Err(e),
            },
            other => other,
        }
    }

    fn process_out_miss(
        &self,
        data: &mut PortData,
        epoch: u64,
        pkt: &mut Packet2<ParsedMblk>,
        ameta: &mut ActionMeta,
    ) -> result::Result<InternalProcessResult, ProcessError> {
        use Direction::Out;

        data.stats.vals.out_uft_miss += 1;
        let mut tcp_closed = false;

        // For outbound traffic the TCP flow table must be checked
        // _before_ processing take place.
        // TODO: uncork
        // if pkt.meta().is_inner_tcp() {
        //     match self.process_out_tcp_new(
        //         data,
        //         pkt.flow(),
        //         pkt.meta(),
        //         pkt.len() as u64,
        //     ) {
        //         Ok(TcpMaybeClosed::Closed { ufid_inbound }) => {
        //             tcp_closed = true;
        //             self.uft_tcp_closed(
        //                 data,
        //                 pkt.flow(),
        //                 ufid_inbound.as_ref(),
        //             );
        //         }

        //         // Continue with processing.
        //         Ok(_) => (),

        //         // Unlike for existing flows, we don't allow through
        //         // unexpected packets here for now -- the `TcpState` FSM
        //         // already encodes a shortcut from `Closed` to `Established.
        //         Err(ProcessError::TcpFlow(err)) => {
        //             let e = format!("{err}");
        //             self.tcp_err(&data.tcp_flows, Out, e, pkt);
        //             return Ok(InternalProcessResult::Drop {
        //                 reason: DropReason::TcpErr,
        //             });
        //         }
        //         Err(ProcessError::MissingFlow(flow_id)) => {
        //             let e = format!("Missing TCP flow ID: {flow_id}");
        //             self.tcp_err(&data.tcp_flows, Direction::In, e, pkt);
        //             return Ok(InternalProcessResult::Drop {
        //                 reason: DropReason::TcpErr,
        //             });
        //         }
        //         Err(ProcessError::FlowTableFull { kind, limit }) => {
        //             let e = format!("{kind} flow table full ({limit} entries)");
        //             self.tcp_err(&data.tcp_flows, Direction::In, e, pkt);
        //             return Ok(InternalProcessResult::Drop {
        //                 reason: DropReason::TcpErr,
        //             });
        //         }
        //         res => unreachable!(
        //             "Cannot return other errors from process_in_tcp_new, returned: {res:?}"
        //         ),
        //     }
        // }

        let mut xforms = Transforms::new();
        let flow_before = *pkt.flow();
        let res = self.layers_process(data, Out, pkt, &mut xforms, ameta);
        // XXXX: may be hashing the wrong thing.
        let hte = UftEntry {
            pair: None,
            xforms: xforms.compile(pkt.checksums_dirty()),
            epoch,
            l4_hash: flow_before.crc32(),
        };

        match res {
            Ok(LayerResult::Allow) => {
                // If there is no Flow ID, then there is no UFT entry.
                if flow_before == FLOW_ID_DEFAULT || tcp_closed {
                    return Ok(InternalProcessResult::Modified);
                }
                match data.uft_out.add(flow_before, hte) {
                    Ok(_) => Ok(InternalProcessResult::Modified),
                    Err(OpteError::MaxCapacity(limit)) => {
                        Err(ProcessError::FlowTableFull { kind: "UFT", limit })
                    }
                    Err(_) => unreachable!(
                        "Cannot return other errors from FlowTable::add"
                    ),
                }
            }

            Ok(LayerResult::Hairpin(hppkt)) => {
                Ok(InternalProcessResult::Hairpin(hppkt))
            }

            Ok(LayerResult::Deny { name, reason }) => {
                Ok(InternalProcessResult::Drop {
                    reason: DropReason::Layer { name, reason },
                })
            }

            Ok(LayerResult::HandlePkt) => Ok(InternalProcessResult::from(
                self.net.handle_pkt(Out, pkt, &data.uft_in, &data.uft_out)?,
            )),

            Err(e) => Err(ProcessError::Layer(e)),
        }
    }

    // TODO: remove.
    fn process_out(
        &self,
        data: &mut PortData,
        epoch: u64,
        pkt: &mut Packet2<ParsedMblk>,
        ameta: &mut ActionMeta,
    ) -> result::Result<InternalProcessResult, ProcessError> {
        use Direction::Out;

        let uft_out = &mut data.uft_out;

        // Use the compiled UFT entry if one exists. Otherwise
        // fallback to layer processing.
        match uft_out.get_mut(&pkt.flow()) {
            Some(entry) if entry.state().epoch == epoch => {
                entry.hit();
                data.stats.vals.out_uft_hit += 1;
                self.uft_hit_probe(Out, pkt.flow(), epoch, entry.last_hit());

                let mut invalidated = false;
                let mut reprocess = false;
                let mut ufid_in = None;

                // TODO: find the best way to unbreak.

                // For outbound traffic the TCP flow table must be
                // checked _before_ processing take place.
                // if pkt.meta().is_inner_tcp() {
                //     match self.process_out_tcp_existing(
                //         &mut data.tcp_flows,
                //         pkt.flow(),
                //         pkt.meta(),
                //         pkt.len() as u64,
                //     ) {
                //         // Continue with processing.
                //         Ok(TcpMaybeClosed::NewState(_)) => (),

                //         Ok(TcpMaybeClosed::Closed { ufid_inbound }) => {
                //             invalidated = true;
                //             ufid_in = ufid_inbound;
                //         }

                //         Err(ProcessError::TcpFlow(
                //             e @ TcpFlowStateError::NewFlow { .. },
                //         )) => {
                //             invalidated = true;
                //             reprocess = true;
                //             self.tcp_err(
                //                 &data.tcp_flows,
                //                 Out,
                //                 e.to_string(),
                //                 pkt,
                //             );
                //         }

                //         Err(ProcessError::MissingFlow(flow_id)) => {
                //             // If we have a UFT but no TCP flow ID, there is likely a bug
                //             // and we are now out of sync. A full reprocess will be
                //             // slower for this packet but will sync up the tables again.
                //             invalidated = true;
                //             reprocess = true;
                //             let e = format!("Missing TCP flow ID: {flow_id}");
                //             self.tcp_err(
                //                 &data.tcp_flows,
                //                 Direction::In,
                //                 e,
                //                 pkt,
                //             );
                //         }

                //         Err(ProcessError::TcpFlow(
                //             e @ TcpFlowStateError::UnexpectedSegment { .. },
                //         )) => {
                //             // Technically unreachable, as we filter these out in `update_tcp_entry`.
                //             // Panicking here would probably be overly fragile, however.
                //             self.tcp_err(
                //                 &data.tcp_flows,
                //                 Direction::In,
                //                 e.to_string(),
                //                 pkt,
                //             );
                //             return Ok(ProcessResult::Drop {
                //                 reason: DropReason::TcpErr,
                //             });
                //         }

                //         _ => unreachable!(
                //             "Cannot return other errors from process_in_tcp_new"
                //         ),
                //     }
                // }

                let flow_to_invalidate = invalidated.then(|| *pkt.flow());

                // If we suspect this is a new flow, we need to not perform
                // existing transforms if we're going to behave as though we
                // have a UFT miss.
                if !reprocess {
                    let transform = Some(Arc::clone(&entry.state().xforms));
                    pkt.set_l4_hash(entry.state().l4_hash);
                    // Due to borrowing constraints from order of operations, we have
                    // to remove the UFT entry here rather than in `update_tcp_entry`.
                    // The TCP entry itself is already removed.
                    if let Some(flow_before) = flow_to_invalidate {
                        self.uft_tcp_closed(
                            data,
                            &flow_before,
                            ufid_in.as_ref(),
                        );
                    }

                    return Ok(InternalProcessResult::Modified);
                } else if let Some(flow_before) = flow_to_invalidate {
                    self.uft_tcp_closed(data, &flow_before, ufid_in.as_ref());
                }
            }

            // The entry is from a previous epoch; invalidate its UFT
            // entries and proceed to rule processing.
            Some(entry) => {
                let epoch = entry.state().epoch;
                let ufid_out = Some(pkt.flow());
                let ufid_in = entry.state().pair;
                self.uft_invalidate(data, ufid_out, ufid_in.as_ref(), epoch);
            }

            // There is no entry; proceed to layer processing.
            None => (),
        }

        self.process_out_miss(data, epoch, pkt, ameta)
    }

    fn uft_invalidate(
        &self,
        data: &mut PortData,
        ufid_out: Option<&InnerFlowId>,
        ufid_in: Option<&InnerFlowId>,
        epoch: u64,
    ) {
        if let Some(ufid_in) = ufid_in {
            data.uft_in.remove(ufid_in);
            self.uft_invalidate_probe(Direction::In, ufid_in, epoch);
        }

        if let Some(ufid_out) = ufid_out {
            data.uft_out.remove(ufid_out);
            self.uft_invalidate_probe(Direction::Out, ufid_out, epoch);
        }
    }

    fn uft_invalidate_probe(
        &self,
        dir: Direction,
        ufid: &InnerFlowId,
        epoch: u64,
    ) {
        cfg_if::cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                unsafe {
                    __dtrace_probe_uft__invalidate(
                        dir as uintptr_t,
                        self.name_cstr.as_ptr() as uintptr_t,
                        ufid,
                        epoch as uintptr_t,
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                let port_s = self.name_cstr.to_str().unwrap();
                let ufid_s = ufid.to_string();
                crate::opte_provider::uft__invalidate!(
                    || (dir, port_s, ufid_s, epoch)
                );
            } else {
                let (_, _, _) = (dir, ufid, epoch);
            }
        }
    }

    fn uft_tcp_closed(
        &self,
        data: &mut PortData,
        ufid_out: &InnerFlowId,
        ufid_in: Option<&InnerFlowId>,
    ) {
        if let Some(ufid_in) = ufid_in {
            data.uft_in.remove(ufid_in);
            self.uft_tcp_closed_probe(Direction::In, ufid_in);
        }
        data.uft_out.remove(ufid_out);
        self.uft_tcp_closed_probe(Direction::Out, ufid_out);
    }

    fn uft_tcp_closed_probe(&self, dir: Direction, ufid: &InnerFlowId) {
        cfg_if::cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                unsafe {
                    __dtrace_probe_uft__tcp__closed(
                        dir as uintptr_t,
                        self.name_cstr.as_ptr() as uintptr_t,
                        ufid,
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                let port_s = self.name_cstr.to_str().unwrap();
                let ufid_s = ufid.to_string();
                crate::opte_provider::uft__tcp__closed!(
                    || (dir, port_s, ufid_s)
                );
            } else {
                let (_, _) = (dir, ufid);
            }
        }
    }

    fn update_stats_in(
        stats: &mut PortStats,
        res: &result::Result<InternalProcessResult, ProcessError>,
    ) {
        match res {
            Ok(InternalProcessResult::Bypass) => stats.in_bypass += 1,

            Ok(InternalProcessResult::Drop { reason }) => {
                stats.in_drop += 1;

                match reason {
                    DropReason::HandlePkt => stats.in_drop_handle_pkt += 1,
                    DropReason::Layer { .. } => stats.in_drop_layer += 1,
                    DropReason::TcpErr => stats.in_drop_tcp_err += 1,
                }
            }

            Ok(InternalProcessResult::Modified) => stats.in_modified += 1,

            Ok(InternalProcessResult::Hairpin(_)) => stats.in_hairpin += 1,

            // XXX We should split the different error types out into
            // individual stats. However, I'm not sure exactly how I
            // would like to to this just yet, and I don't want to
            // hold up this stat work any longer -- better to improve
            // upon stats in follow-up work. E.g., it might make sense
            // to just have a top-level error counter in the
            // PortStats, and then also publisher LayerStats for each
            // layer along with the different error counts.
            Err(_) => stats.in_process_err += 1,
        }
    }

    fn update_stats_out(
        stats: &mut PortStats,
        res: &result::Result<InternalProcessResult, ProcessError>,
    ) {
        match res {
            Ok(InternalProcessResult::Bypass) => stats.out_bypass += 1,

            Ok(InternalProcessResult::Drop { reason }) => {
                stats.out_drop += 1;

                match reason {
                    DropReason::HandlePkt => stats.out_drop_handle_pkt += 1,
                    DropReason::Layer { .. } => stats.out_drop_layer += 1,
                    DropReason::TcpErr => stats.out_drop_tcp_err += 1,
                }
            }

            Ok(InternalProcessResult::Modified) => stats.out_modified += 1,

            Ok(InternalProcessResult::Hairpin(_)) => stats.out_hairpin += 1,

            // XXX We should split the different error types out into
            // individual stats. However, I'm not sure exactly how I
            // would like to to this just yet, and I don't want to
            // hold up this stat work any longer -- better to improve
            // upon stats in follow-up work. E.g., it might make sense
            // to just have a top-level error counter in the
            // PortStats, and then also publisher LayerStats for each
            // layer along with the different error counts.
            Err(_) => stats.out_process_err += 1,
        }
    }
}

// The follow functions are useful for validating state during
// testing. If one of these functions becomes useful outside of
// testing, then add it to the impl block above.
//
// TODO Move these to main Port impl
//
// #[cfg(test)]
impl<N: NetworkImpl> Port<N> {
    /// Return the current epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch.load(SeqCst)
    }

    /// Return the list of layer names.
    pub fn layers(&self) -> Vec<String> {
        self.data.lock().layers.iter().map(|l| l.name().to_string()).collect()
    }

    /// Get the number of flows currently in the layer and direction
    /// specified. The value `"uft"` can be used to get the number of
    /// UFT flows.
    pub fn num_flows(&self, layer: &str, dir: Direction) -> u32 {
        let data = self.data.lock();
        use Direction::*;

        match (layer, dir) {
            ("uft", In) => data.uft_in.num_flows(),
            ("uft", Out) => data.uft_out.num_flows(),
            (name, _dir) => {
                for layer in &data.layers {
                    if layer.name() == name {
                        return layer.num_flows();
                    }
                }

                panic!("layer not found: {}", name);
            }
        }
    }

    /// Return the number of rules registered for the given layer in
    /// the given direction.
    pub fn num_rules(&self, layer_name: &str, dir: Direction) -> usize {
        let data = self.data.lock();
        data.layers
            .iter()
            .find(|layer| layer.name() == layer_name)
            .map(|layer| layer.num_rules(dir))
            .unwrap_or_else(|| panic!("layer not found: {}", layer_name))
    }
}

/// Helper enum used to delay UFT entry removal in case of
/// `tcp_out_existing`.
enum PortDataOrSubset<'a> {
    Port(&'a mut PortData),
    Tcp(&'a mut FlowTable<TcpFlowEntryState>),
}

impl<'a> PortDataOrSubset<'a> {
    fn tcp_flows(&mut self) -> &mut FlowTable<TcpFlowEntryState> {
        match self {
            Self::Port(p) => &mut p.tcp_flows,
            Self::Tcp(t) => t,
        }
    }
}

/// Helper enum for encoding what UFIDs are available when
/// updating TCP flow state.
enum TcpDirection<'a> {
    In { ufid_in: &'a InnerFlowId, ufid_out: &'a InnerFlowId },
    Out { ufid_out: &'a InnerFlowId },
}

impl<'a> TcpDirection<'a> {
    fn dir(&self) -> Direction {
        match self {
            Self::In { .. } => Direction::In,
            Self::Out { .. } => Direction::Out,
        }
    }

    fn local_flow(&self) -> &InnerFlowId {
        match self {
            Self::In { ufid_in, .. } => ufid_in,
            Self::Out { ufid_out } => ufid_out,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Pos {
    Last,
    First,
    Before(&'static str),
    After(&'static str),
}

/// An entry in the TCP flow table.
#[derive(Clone, Debug)]
pub struct TcpFlowEntryState {
    // This must be the UFID of inbound traffic _as it arrives_ from
    // the network, not after it's processed.
    inbound_ufid: Option<InnerFlowId>,
    tcp_state: TcpFlowState,
    segs_in: u64,
    segs_out: u64,
    bytes_in: u64,
    bytes_out: u64,
}

impl TcpFlowEntryState {
    fn new_inbound(
        inbound_ufid: InnerFlowId,
        tcp_state: TcpFlowState,
        bytes_in: u64,
    ) -> Self {
        Self {
            inbound_ufid: Some(inbound_ufid),
            tcp_state,
            segs_in: 1,
            segs_out: 0,
            bytes_in,
            bytes_out: 0,
        }
    }

    fn new_outbound(tcp_state: TcpFlowState, bytes_out: u64) -> Self {
        Self {
            inbound_ufid: None,
            tcp_state,
            segs_in: 0,
            segs_out: 1,
            bytes_in: 0,
            bytes_out,
        }
    }
}

impl Display for TcpFlowEntryState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.inbound_ufid {
            None => write!(f, "None {}", self.tcp_state),
            Some(ufid) => write!(f, "{} {}", ufid, self.tcp_state),
        }
    }
}

impl Dump for TcpFlowEntryState {
    type DumpVal = TcpFlowEntryDump;

    fn dump(&self, hits: u64) -> TcpFlowEntryDump {
        TcpFlowEntryDump {
            hits,
            inbound_ufid: self.inbound_ufid,
            tcp_state: TcpFlowStateDump::from(self.tcp_state),
            segs_in: self.segs_in,
            segs_out: self.segs_out,
            bytes_in: self.bytes_in,
            bytes_out: self.bytes_out,
        }
    }
}

/// Expiry behaviour for TCP flows dependent on the connection FSM.
#[derive(Debug)]
pub struct TcpExpiry {
    time_wait_ttl: Ttl,
    keepalive_ttl: Ttl,
}

impl Default for TcpExpiry {
    fn default() -> Self {
        Self {
            time_wait_ttl: TIME_WAIT_EXPIRE_TTL,
            keepalive_ttl: KEEPALIVE_EXPIRE_TTL,
        }
    }
}

impl ExpiryPolicy<TcpFlowEntryState> for TcpExpiry {
    fn is_expired(
        &self,
        entry: &FlowEntry<TcpFlowEntryState>,
        now: Moment,
    ) -> bool {
        let ttl = match entry.state().tcp_state.tcp_state() {
            TcpState::TimeWait => self.time_wait_ttl,
            _ => self.keepalive_ttl,
        };
        ttl.is_expired(*entry.last_hit(), now)
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
extern "C" {
    pub fn __dtrace_probe_port__process__entry(
        dir: uintptr_t,
        port: uintptr_t,
        ifid: *const InnerFlowId,
        epoch: uintptr_t,
        pkt: uintptr_t,
    );
    pub fn __dtrace_probe_port__process__return(
        dir: uintptr_t,
        port: uintptr_t,
        flow_before: *const InnerFlowId,
        flow_after: *const InnerFlowId,
        epoch: uintptr_t,
        pkt: uintptr_t,
        hp_pkt: uintptr_t,
        err_b: *const LabelBlock<2>,
    );
    pub fn __dtrace_probe_tcp__err(
        dir: uintptr_t,
        port: uintptr_t,
        ifid: *const InnerFlowId,
        pkt: uintptr_t,
        msg: uintptr_t,
    );
    pub fn __dtrace_probe_uft__hit(
        dir: uintptr_t,
        port: uintptr_t,
        ifid: *const InnerFlowId,
        epoch: uintptr_t,
        last_hit: uintptr_t,
    );
    pub fn __dtrace_probe_uft__invalidate(
        dir: uintptr_t,
        port: uintptr_t,
        ifid: *const InnerFlowId,
        epoch: uintptr_t,
    );
    pub fn __dtrace_probe_uft__tcp__closed(
        dir: uintptr_t,
        port: uintptr_t,
        ifid: *const InnerFlowId,
    );
}

/// Metadata for inter-action communication.
pub mod meta {
    use alloc::collections::BTreeMap;
    use alloc::string::String;
    use alloc::string::ToString;

    /// A value meant to be used in the [`ActionMeta`] map.
    ///
    /// The purpose of this trait is to define the value's key as well
    /// as serialization to/from strings. These are like Display and
    /// FromStr; but here their focus is on unambiguous parsing. That
    /// is, we can't necessarily rely on a type's Display impl being
    /// good for serializing to a metadata string, but at the same
    /// time we don't want to force its Display to have to work in
    /// this constraint.
    ///
    /// A value doesn't have to implement this type; there is nothing
    /// that enforces the strings stored in [`ActionMeta`] are strings
    /// generated by this trait impl. It's just a convenient way to
    /// mark and implement values meant to be used as action metadata.
    pub trait ActionMetaValue: Sized {
        const KEY: &'static str;

        fn key(&self) -> String {
            Self::KEY.to_string()
        }

        /// Create a representation of the value to be used in
        /// [`ActionMeta`].
        fn as_meta(&self) -> String;

        /// Attempt to create a value assuming that `s` was created
        /// with [`Self::as_meta()`].
        fn from_meta(s: &str) -> Result<Self, String>;
    }

    /// The action metadata map.
    ///
    /// This metadata is accessible by all actions during layer
    /// processing and acts as a form of inter-action communication.
    /// The action metadata is nothing more than a map of string keys
    /// to string values -- their meaning is opaque to OPTE itself. It
    /// is up to the actions to decide what these strings mean.
    #[derive(Default)]
    pub struct ActionMeta {
        inner: BTreeMap<String, String>,
    }

    impl ActionMeta {
        pub fn new() -> Self {
            Self::default()
        }

        /// Clear all entries.
        pub fn clear(&mut self) {
            self.inner.clear();
        }

        /// Insert the key-value pair into the map, replacing any
        /// existing key-value pair. Return the value being replaced,
        /// or `None`.
        pub fn insert(&mut self, key: String, val: String) -> Option<String> {
            self.inner.insert(key, val)
        }

        /// Remove the key-value pair with the specified key. Return
        /// the value, or `None` if no such entry exists.
        pub fn remove(&mut self, key: &str) -> Option<String> {
            self.inner.remove(key)
        }

        /// Get a reference to the value with the given key, or `None`
        /// if no such entry exists.
        pub fn get(&self, key: &str) -> Option<&String> {
            self.inner.get(key)
        }
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! A virtual switch port.

use super::HdlPktAction;
use super::LightweightMeta;
use super::NetworkImpl;
use super::ether::Ethernet;
use super::flow_table::Dump;
use super::flow_table::FlowEntry;
use super::flow_table::FlowTable;
use super::flow_table::Ttl;
use super::geneve::GENEVE_PORT;
use super::headers::EncapPush;
use super::headers::HeaderAction;
use super::headers::IpPush;
use super::headers::UlpHeaderAction;
use super::ioctl;
use super::ioctl::TcpFlowEntryDump;
use super::ioctl::TcpFlowStateDump;
use super::ioctl::UftEntryDump;
use super::ip::L3Repr;
use super::ip::v4::Ipv4;
use super::ip::v6::Ipv6;
use super::layer;
use super::layer::Layer;
use super::layer::LayerError;
use super::layer::LayerResult;
use super::layer::LayerStatsSnap;
use super::layer::RuleId;
use super::packet::BodyTransform;
use super::packet::BodyTransformError;
use super::packet::FLOW_ID_DEFAULT;
use super::packet::FullParsed;
use super::packet::InnerFlowId;
use super::packet::LiteParsed;
use super::packet::MblkFullParsed;
use super::packet::MblkPacketData;
use super::packet::Packet;
use super::packet::Pullup;
use super::rule::Action;
use super::rule::CompiledTransform;
use super::rule::Finalized;
use super::rule::HdrTransform;
use super::rule::HdrTransformError;
use super::rule::Rule;
use super::rule::TransformFlags;
use super::tcp::KEEPALIVE_EXPIRE_TTL;
use super::tcp::TIME_WAIT_EXPIRE_TTL;
use super::tcp::TcpState;
use super::tcp_state::TcpFlowState;
use super::tcp_state::TcpFlowStateError;
use crate::ExecCtx;
use crate::d_error::DError;
#[cfg(all(not(feature = "std"), not(test)))]
use crate::d_error::LabelBlock;
use crate::ddi::kstat;
use crate::ddi::kstat::KStatNamed;
use crate::ddi::kstat::KStatProvider;
use crate::ddi::kstat::KStatU64;
use crate::ddi::mblk::MsgBlk;
use crate::ddi::mblk::MsgBlkIterMut;
use crate::ddi::sync::KMutex;
use crate::ddi::sync::KRwLock;
use crate::ddi::sync::KRwLockType;
use crate::ddi::time::Moment;
use crate::engine::flow_table::ExpiryPolicy;
use crate::engine::packet::EmitSpec;
use crate::engine::packet::PushSpec;
use crate::engine::rule::CompiledEncap;
use alloc::boxed::Box;
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
use core::str::FromStr;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering::SeqCst;
use illumos_sys_hdrs::uintptr_t;
use ingot::ethernet::Ethertype;
use ingot::geneve::Geneve;
use ingot::ip::IpProtocol;
use ingot::tcp::TcpRef;
use ingot::types::Emit;
use ingot::types::HeaderLen;
use ingot::types::Read;
use ingot::udp::Udp;
use meta::ActionMeta;
use opte_api::Direction;
use opte_api::MacAddr;
use opte_api::OpteError;
use zerocopy::ByteSlice;
use zerocopy::ByteSliceMut;

/// Metadata for inter-action communication.
pub mod meta;

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
    BadEmitSpec,
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
///   all. XXX This is probably going away as its only use is for
///   punting on traffic I didn't want to deal with yet.
///
/// * Drop: The packet has been dropped, as determined by the rules
///   or because of resource exhaustion. Included is the reason for the
///   drop.
///
/// * Modified: The packet has been modified based on its matching rules.
///
/// * Hairpin: One of the layers has determined that it should reply
///   directly with a packet of its own. In this case the original
///   packet is dropped.
#[derive(Debug, DError)]
pub enum ProcessResult {
    Bypass,
    #[leaf]
    Drop {
        reason: DropReason,
    },
    #[leaf]
    Modified(EmitSpec),
    // TODO: it would be nice if this packet type could be user-specified, but might
    // be tricky.
    #[leaf]
    Hairpin(MsgBlk),
}

impl From<HdlPktAction> for ProcessResult {
    fn from(hpa: HdlPktAction) -> Self {
        match hpa {
            // TODO: In theory HdlPacket::Allow should have an emit spec, too.
            // We are not using any op other than Hairpin, so kick that particular
            // can down the road.
            HdlPktAction::Allow => Self::Modified(EmitSpec::default()),
            HdlPktAction::Deny => Self::Drop { reason: DropReason::HandlePkt },
            HdlPktAction::Hairpin(pkt) => Self::Hairpin(pkt),
        }
    }
}

enum InternalProcessResult {
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

        let mut data = KRwLock::new(data);
        data.init(KRwLockType::Driver);

        Ok(Port {
            name: self.name.clone(),
            name_cstr: self.name_cstr,
            mac: self.mac,
            ectx: self.ectx,
            epoch: AtomicU64::new(1),
            stats: KStatNamed::new("xde", &self.name, PortStats::new())?,
            net,
            data,
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
            layers: KMutex::new(Vec::new()),
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
pub struct UftEntry<Id> {
    /// The flow ID for the other side.
    pair: KMutex<Option<Id>>,

    /// The transformations to perform.
    xforms: Arc<Transforms>,

    /// Cached flow hash to speed up route selection.
    l4_hash: u32,

    /// The port epoch upon which this entry was established. Used for
    /// invalidation when the rule set is updated.
    epoch: u64,

    /// Cached reference to a flow's TCP state, if applicable.
    /// This allows us to maintain up-to-date TCP flow table info
    tcp_flow: Option<Arc<FlowEntry<TcpFlowEntryState>>>,
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

impl<Id> fmt::Debug for UftEntry<Id> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let UftEntry { pair: _pair, xforms, l4_hash, epoch, tcp_flow } = self;

        f.debug_struct("UftEntry")
            .field("pair", &"<lock>")
            .field("xforms", xforms)
            .field("l4_hash", l4_hash)
            .field("epoch", epoch)
            .field("tcp_flow", tcp_flow)
            .finish()
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
    stats: KStatNamed<PortStats>,
    net: N,
    data: KRwLock<PortData>,
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
        let mut data = self.data.write();
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
        self.data.write().state = PortState::Running;
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
        let mut data = self.data.write();
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
        self.data.read().state
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
        let mut data = self.data.write();
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
        pkt: &mut Packet<MblkFullParsed>,
    ) {
        if unsafe { super::opte_panic_debug != 0 } {
            super::err!("mblk: {}", pkt.mblk_addr());
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
        pkt: Option<&Packet<MblkFullParsed>>,
        flow: &InnerFlowId,
        msg: String,
    ) {
        let mblk_addr = pkt.map(|p| p.mblk_addr()).unwrap_or_default();
        cfg_if::cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                let msg_arg = CString::new(msg).unwrap();

                __dtrace_probe_tcp__err(
                    dir as uintptr_t,
                    self.name_cstr.as_ptr() as uintptr_t,
                    flow,
                    mblk_addr,
                    msg_arg.as_ptr() as uintptr_t,
                );
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
        let data = self.data.read();

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
        let data = self.data.read();
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
        let mut data = self.data.write();
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
        let mut data = self.data.write();
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
        let data = self.data.read();

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
        let mut data = self.data.write();
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
        let data = self.data.read();

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
        let data = self.data.read();
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
        let data = self.data.read();

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
        let data = self.data.read();
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
    #[inline(always)]
    pub fn process<'a, M>(
        &self,
        dir: Direction,
        // TODO: might want to pass in a &mut to an enum
        // which can advance to (and hold) light->full-fat metadata.
        // My gutfeel is that there's a perf cost here -- this struct
        // is pretty large, but expressing the transform on a &mut is also
        // less than ideal.
        mut pkt: Packet<LiteParsed<MsgBlkIterMut<'a>, M>>,
    ) -> result::Result<ProcessResult, ProcessError>
    where
        M: LightweightMeta<<MsgBlkIterMut<'a> as Read>::Chunk>,
    {
        let process_start = Moment::now();
        let flow_before = pkt.flow();
        let mblk_addr = pkt.mblk_addr();

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
        //
        // Lock management here is generally optimistic -- most fastpath cases
        // take a short hold on the reader lock.
        //  - As a rule: once we determine that a packet is bound for the slow
        //    path, we hold the writer lock until the packet is processed.
        //  - When a packet arrives, look for a UFT using a reader lock.
        //    Temporarily take the write lock if that entry is unusable.
        //     - Drop writer if present and usable (fast path),
        //     - Downgrade to the slowpath holding writer.
        //  - If a UFT is held, progress TCP state based on flags.
        //    Temporarily take writer if existing TCP state was closed out.
        //     - Drop writer once flow closed, or
        //     - Downgrade to the slowpath, if this is a new flow.
        //     (Both of these cases are infrequent.)
        //  - Finalise processing holding no lock (fastpath) or writer
        //    (slowpath).
        let data = self.data.read();

        // (1) Check for UFT and precompiled.
        let mut epoch = self.epoch();
        check_state!(data.state, [PortState::Running])
            .map_err(|_| ProcessError::BadState(data.state))?;

        self.port_process_entry_probe(dir, &flow_before, epoch, mblk_addr);

        let uft: Option<Arc<FlowEntry<UftEntry<InnerFlowId>>>> = (match dir {
            Direction::Out => data.uft_out.get(&flow_before),
            Direction::In => data.uft_in.get(&flow_before),
        })
        .map(Arc::clone);

        drop(data);

        // If we have a UFT miss or invalid entry, upgrade to a write lock and
        // fetch again. This lets us use an optimistic lookup more often.
        let (uft, mut lock) = match uft {
            Some(ref entry) if entry.state().epoch == epoch => (uft, None),
            Some(_) | None => {
                let data = self.data.write();
                epoch = self.epoch();
                (
                    (match dir {
                        Direction::Out => data.uft_out.get(&flow_before),
                        Direction::In => data.uft_in.get(&flow_before),
                    })
                    .map(Arc::clone),
                    Some(data),
                )
            }
        };

        enum FastPathDecision {
            CompiledUft(Arc<FlowEntry<UftEntry<InnerFlowId>>>),
            Uft(Arc<FlowEntry<UftEntry<InnerFlowId>>>),
            Slow,
        }

        impl FastPathDecision {
            fn as_u64(&self) -> u64 {
                match self {
                    FastPathDecision::CompiledUft(_) => 1,
                    FastPathDecision::Uft(_) => 2,
                    FastPathDecision::Slow => 3,
                }
            }
        }

        // We have either committed to our (suspected valid) UFT, or refetched
        // it (may have been removed) under the write lock.
        // Revalidate the entry in the latter case.
        let mut decision = match uft {
            // We have a valid UFT entry of some kind -- clone out the saved
            // transforms so that we can drop the lock ASAP (if reacquired).
            // Recheck epoch in case we took a write lock and re-read the UFT.
            Some(entry) if lock.is_none() || entry.state().epoch == epoch => {
                // The Fast Path.
                drop(lock.take());
                let xforms = &entry.state().xforms;
                let out = if xforms.compiled.is_some() {
                    FastPathDecision::CompiledUft(entry)
                } else {
                    FastPathDecision::Uft(entry)
                };

                match dir {
                    Direction::In => self.stats.vals.in_uft_hit.incr(1),
                    Direction::Out => self.stats.vals.out_uft_hit.incr(1),
                }

                out
            }

            // The entry is *definitely* from a previous epoch; invalidate its UFT
            // entries and proceed to rule processing.
            // We will have been upgraded to a write lock if this was possible.
            Some(entry) => {
                let data = lock
                    .as_mut()
                    .expect("lock should be held on this codepath");
                let epoch = entry.state().epoch;
                let owned_pair = *entry.state().pair.lock();
                let (ufid_in, ufid_out) = match dir {
                    Direction::Out => (owned_pair.as_ref(), Some(&flow_before)),
                    Direction::In => (Some(&flow_before), owned_pair.as_ref()),
                };
                self.uft_invalidate(data, ufid_out, ufid_in, epoch);

                FastPathDecision::Slow
            }
            None => FastPathDecision::Slow,
        };

        // (1)/(2) Update UFT hit stats, validate TCP state.
        //    Whenever a TCP flow ends (or a new TCP flow unexpectedly begins
        //    with the same flow ID), we need to remove the old TCP flow state
        //    (and any attached UFTs) and *may* need to downgrade to slowpath
        //    processing for stats purposes.
        //
        //    These are fairly infrequent paths in the TCP lifecycle.
        match &decision {
            FastPathDecision::CompiledUft(entry)
            | FastPathDecision::Uft(entry) => {
                entry.hit_at(process_start);
                self.uft_hit_probe(dir, &flow_before, epoch, &process_start);

                let tcp = entry.state().tcp_flow.as_ref();
                if let Some(tcp_flow) = tcp {
                    tcp_flow.hit_at(process_start);

                    let tcp = pkt
                        .meta()
                        .inner_tcp()
                        .expect("failed to find TCP state on known TCP flow");

                    let ufid_in = match dir {
                        Direction::In => Some(&flow_before),
                        Direction::Out => None,
                    };

                    let invalidated_tcp = match tcp_flow.state().update(
                        self.name_cstr.as_c_str(),
                        tcp,
                        dir,
                        pkt.len() as u64,
                        ufid_in,
                    ) {
                        Ok(TcpState::Closed) => Some(Arc::clone(tcp_flow)),
                        Err(TcpFlowStateError::NewFlow { .. }) => {
                            let out = Some(Arc::clone(tcp_flow));
                            decision = FastPathDecision::Slow;
                            out
                        }
                        _ => None,
                    };

                    // Reacquire the writer to remove the flow if needed.
                    // Elevate lock to full scope, if we are reprocessing
                    // as well.
                    if let Some(entry) = invalidated_tcp {
                        let mut local_lock = self.data.write();

                        let flow_lock = entry.state().inner.lock();
                        let ufid_out = &flow_lock.outbound_ufid;

                        let ufid_in = flow_lock.inbound_ufid.as_ref();

                        // Because we've dropped the port lock, another packet could have
                        // also invalidated this flow and removed the entry. It could even
                        // install new UFT/TCP entries, depending on lock/process ordering.
                        //
                        // Verify that the state we want to remove still exists, and is
                        // `Arc`-identical.
                        if let Some(found_entry) =
                            local_lock.tcp_flows.get(ufid_out)
                        {
                            if Arc::ptr_eq(found_entry, &entry) {
                                self.uft_tcp_closed(
                                    &mut local_lock,
                                    ufid_out,
                                    ufid_in,
                                );
                                _ = local_lock.tcp_flows.remove(ufid_out);
                            }
                        }

                        // We've determined we're actually starting a new TCP flow (e.g.,
                        // SYN on any other state) from an existing UFT entry.
                        if matches!(decision, FastPathDecision::Slow) {
                            lock = Some(local_lock);
                        }
                    }
                }
            }
            _ => {}
        }

        // (1) Execute precompiled, and exit.
        if let FastPathDecision::CompiledUft(entry) = &decision {
            let l4_hash = entry.state().l4_hash;
            let tx = entry.state().xforms.compiled.as_ref().cloned().unwrap();

            let len = pkt.len();
            let meta = pkt.meta_mut();
            let csum_dirty = tx.checksums_dirty();

            let body_csum =
                if csum_dirty { meta.compute_body_csum() } else { None };
            meta.run_compiled_transform(&tx);
            if csum_dirty {
                meta.update_inner_checksums(body_csum);
            }
            let encap_len = meta.encap_len();
            let ulp_len = (len - (encap_len as usize)) as u32;
            let rewind = match tx.encap {
                CompiledEncap::Pop => encap_len,
                _ => 0,
            };
            let out = EmitSpec {
                mtu_unrestricted: tx.internal_destination(),
                prepend: PushSpec::Fastpath(tx),
                l4_hash,
                rewind,
                ulp_len,
            };

            let flow_after = meta.flow();
            let res = Ok(InternalProcessResult::Modified);
            match dir {
                Direction::In => {
                    self.update_stats_in(&res);
                }
                Direction::Out => {
                    self.update_stats_out(&res);
                }
            }
            let res = Ok(ProcessResult::Modified(out));
            self.port_process_return_probe(
                dir,
                &flow_before,
                &flow_after,
                epoch,
                mblk_addr,
                &res,
                decision.as_u64(),
            );
            return res;
        }

        // (2)/(3) Full-fat metadata is required.
        let mut pkt = pkt.to_full_meta();
        let mut ameta = ActionMeta::new();

        let res = match (&decision, dir) {
            // (2) Apply retrieved transform. Lock is dropped.
            // Reuse cached l4 hash.
            (FastPathDecision::Uft(entry), _) => {
                let l4_hash = entry.state().l4_hash;
                let tx = Arc::clone(&entry.state().xforms);

                pkt.set_l4_hash(l4_hash);
                tx.apply(&mut pkt, dir)?;
                Ok(InternalProcessResult::Modified)
            }

            // (3) Full-table processing for the packet, then drop the lock.
            // Cksum updates are left undone, so we perform those manually
            // outside the port lock.
            (FastPathDecision::Slow, Direction::In) => {
                let data = lock
                    .as_mut()
                    .expect("lock should be held on this codepath");

                let res = self.process_in_miss(
                    data,
                    epoch,
                    &mut pkt,
                    &flow_before,
                    &mut ameta,
                );

                drop(lock);

                pkt.update_checksums();
                res
            }
            (FastPathDecision::Slow, Direction::Out) => {
                let data = lock
                    .as_mut()
                    .expect("lock should be held on this codepath");

                let res =
                    self.process_out_miss(data, epoch, &mut pkt, &mut ameta);

                drop(lock);

                pkt.update_checksums();
                res
            }

            (FastPathDecision::CompiledUft(_), _) => unreachable!(),
        };

        let flow_after = *pkt.flow();

        match dir {
            Direction::In => self.update_stats_in(&res),
            Direction::Out => self.update_stats_out(&res),
        }

        let res = res.and_then(|v| match v {
            InternalProcessResult::Drop { reason } => {
                Ok(ProcessResult::Drop { reason })
            }
            InternalProcessResult::Hairpin(v) => Ok(ProcessResult::Hairpin(v)),
            InternalProcessResult::Modified => pkt
                .emit_spec(&ameta)
                .map_err(|_| ProcessError::BadEmitSpec)
                .map(ProcessResult::Modified),
        });
        self.port_process_return_probe(
            dir,
            &flow_before,
            &flow_after,
            epoch,
            mblk_addr,
            &res,
            decision.as_u64(),
        );
        res
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
        let mut data = self.data.write();
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
                        // XXX(kyle) This is not a concern while we have the
                        // port lock in place.
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
        let mut data = self.data.write();
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
        let mut data = self.data.write();
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
        self.stats.vals.snapshot()
    }

    /// Return the [`TcpState`] of a given flow.
    #[cfg(any(feature = "test-help", test))]
    pub fn tcp_state(&self, flow: &InnerFlowId) -> Option<TcpState> {
        self.data
            .read()
            .tcp_flows
            .get(flow)
            .map(|entry| entry.state().tcp_state())
    }
}

#[allow(dead_code)]
#[derive(Debug)]
enum TcpMaybeClosed {
    Closed { ufid_inbound: Option<InnerFlowId> },
    NewState(TcpState, Arc<FlowEntry<TcpFlowEntryState>>),
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
    fn apply<'a, T: Read + Pullup + 'a>(
        &self,
        pkt: &mut Packet<FullParsed<T>>,
        dir: Direction,
    ) -> result::Result<(), ProcessError>
    where
        T::Chunk: ByteSliceMut,
    {
        // TODO: It should be possible to combine header transforms
        // into a single operation per layer, particularly when
        // they are disjoint like we do in the Compiled case.
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
    fn compile(mut self, flags: TransformFlags) -> Arc<Self> {
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

                // All outer layers must be pushed (or popped/ignored) at the same
                // time for compilation. No modifications are permissable.
                fn store_outer_push<P: Copy, M>(
                    tx: &HeaderAction<P, M>,
                    still_permissable: &mut bool,
                    slot: &mut Option<P>,
                ) {
                    match tx {
                        HeaderAction::Push(p) => *slot = Some(*p),
                        HeaderAction::Pop => *slot = None,
                        HeaderAction::Modify(_) => *still_permissable = false,
                        HeaderAction::Ignore => {}
                    }
                }
                store_outer_push(
                    &transform.outer_ether,
                    &mut still_permissable,
                    &mut outer_ether,
                );
                store_outer_push(
                    &transform.outer_ip,
                    &mut still_permissable,
                    &mut outer_ip,
                );
                store_outer_push(
                    &transform.outer_encap,
                    &mut still_permissable,
                    &mut outer_encap,
                );

                // Allow up to one action per ULP field, which must be modify.
                // We can't yet combine sets of `Modify` actions,
                // but the Oxide dataplane does not use this in practice.
                fn store_inner_mod<'a, P, M>(
                    tx: &'a HeaderAction<P, M>,
                    still_permissable: &mut bool,
                    slot: &mut Option<&'a M>,
                ) {
                    match tx {
                        HeaderAction::Push(_) | HeaderAction::Pop => {
                            *still_permissable = false;
                        }
                        HeaderAction::Modify(m) => {
                            *still_permissable &= slot.replace(m).is_none();
                        }
                        HeaderAction::Ignore => {}
                    }
                }
                store_inner_mod(
                    &transform.inner_ether,
                    &mut still_permissable,
                    &mut inner_ether,
                );
                store_inner_mod(
                    &transform.inner_ip,
                    &mut still_permissable,
                    &mut inner_ip,
                );

                match &transform.inner_ulp {
                    UlpHeaderAction::Modify(m) => {
                        still_permissable &= inner_ulp.replace(m).is_none();
                    }
                    UlpHeaderAction::Ignore => {}
                }
            }

            if still_permissable {
                let encap = match (outer_ether, outer_ip, outer_encap) {
                    (Some(eth), Some(ip), Some(encap)) => {
                        let encap_repr = match encap {
                            EncapPush::Geneve(g) => (
                                Udp {
                                    source: g.entropy,
                                    destination: GENEVE_PORT,
                                    ..Default::default()
                                },
                                Geneve { vni: g.vni, ..Default::default() },
                            ),
                        };

                        let eth_repr = Ethernet {
                            destination: eth.dst,
                            source: eth.src,
                            ethertype: Ethertype(eth.ether_type.into()),
                        };
                        let (ip_repr, l3_extra_bytes, ip_len_offset) = match ip
                        {
                            IpPush::Ip4(v4) => (
                                L3Repr::Ipv4(Ipv4 {
                                    protocol: IpProtocol(v4.proto.into()),
                                    source: v4.src,
                                    destination: v4.dst,
                                    total_len: Ipv4::MINIMUM_LENGTH as u16,
                                    ..Default::default()
                                }),
                                Ipv4::MINIMUM_LENGTH,
                                2,
                            ),
                            IpPush::Ip6(v6) => (
                                L3Repr::Ipv6(Ipv6 {
                                    next_header: IpProtocol(v6.proto.into()),
                                    source: v6.src,
                                    destination: v6.dst,
                                    payload_len: 0,
                                    ..Default::default()
                                }),
                                0,
                                4,
                            ),
                        };

                        let encap_sz = encap_repr.packet_length();
                        let l3_len_offset =
                            eth_repr.packet_length() + ip_len_offset;

                        // UDP has a length field 4B into its header.
                        // in event of TCP, l4_len_offset is ignored.
                        let l4_len_offset = eth_repr.packet_length()
                            + ip_repr.packet_length()
                            + 4;

                        let bytes = (eth_repr, ip_repr, encap_repr).emit_vec();

                        Some(CompiledEncap::Push {
                            encap,
                            eth,
                            ip,
                            bytes,
                            l3_len_offset,
                            l3_extra_bytes,
                            l4_len_offset,
                            encap_sz,
                        })
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
                            flags,
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
        pkt: &mut Packet<MblkFullParsed>,
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

    #[inline(always)]
    fn port_process_entry_probe(
        &self,
        dir: Direction,
        flow: &InnerFlowId,
        epoch: u64,
        mblk_addr: uintptr_t,
    ) {
        cfg_if::cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                __dtrace_probe_port__process__entry(
                    dir as uintptr_t,
                    self.name_cstr.as_ptr() as uintptr_t,
                    flow,
                    epoch as uintptr_t,
                    mblk_addr,
                );
            } else if #[cfg(feature = "usdt")] {
                let flow_s = flow.to_string();
                crate::opte_provider::port__process__entry!(
                    || (dir, &self.name, flow_s, epoch, mblk_addr)
                );
            } else {
                let (..) = (dir, flow, epoch, mblk_addr);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    fn port_process_return_probe(
        &self,
        dir: Direction,
        flow_before: &InnerFlowId,
        flow_after: &InnerFlowId,
        epoch: u64,
        mblk_addr: uintptr_t,
        res: &result::Result<ProcessResult, ProcessError>,
        path: u64,
    ) {
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
                    path as uintptr_t,
                );
            } else if #[cfg(feature = "usdt")] {
                let flow_b_s = flow_before.to_string();
                let flow_a_s = flow_after.to_string();
                let res_str = match res {
                    Ok(v) => format!("{:?}", v),
                    Err(e) => format!("ERROR: {:?}", e),
                };
                let _ = path;

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
                let (..) = (dir, flow_before, flow_after, epoch, mblk_addr, res, path);
            }
        }
    }

    /// Creates a new TCP flow state entry for a given packet.
    ///
    /// # Errors
    /// * `OpteError::MaxCapacity(_)` if the TCP flows table is full.
    /// * `ProcessError::TcpFlow(_)` if we do not have a valid transition from
    ///   `Closed` based on the packet state.
    fn create_new_tcp_entry<V: ByteSlice>(
        &self,
        tcp_flows: &mut FlowTable<TcpFlowEntryState>,
        tcp: &impl TcpRef<V>,
        dir: &TcpDirection,
        pkt_len: u64,
    ) -> result::Result<TcpMaybeClosed, ProcessError> {
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
                    TcpFlowEntryState::new_inbound(
                        *ufid_out, *ufid_in, tfs, pkt_len,
                    ),
                ),
                TcpDirection::Out { ufid_out } => (
                    ufid_out,
                    TcpFlowEntryState::new_outbound(*ufid_out, tfs, pkt_len),
                ),
            };
            match tcp_flows.add_and_return(*ufid_out, tfes) {
                Ok(entry) => Ok(TcpMaybeClosed::NewState(tcp_state, entry)),
                Err(OpteError::MaxCapacity(limit)) => {
                    Err(ProcessError::FlowTableFull { kind: "TCP", limit })
                }
                Err(_) => unreachable!(
                    "Cannot return other errors from FlowTable::add"
                ),
            }
        } else {
            Ok(TcpMaybeClosed::Closed {
                ufid_inbound: match *dir {
                    TcpDirection::In { ufid_in, .. } => Some(*ufid_in),
                    TcpDirection::Out { .. } => None,
                },
            })
        }
    }

    /// Attempts to lookup and update TCP flowstate in response to a given
    /// packet from within the slowpath.
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
    fn update_tcp_entry<V: ByteSlice>(
        &self,
        data: &mut PortData,
        tcp: &impl TcpRef<V>,
        dir: &TcpDirection,
        pkt_len: u64,
    ) -> result::Result<TcpMaybeClosed, ProcessError> {
        let (ufid_out, ufid_in) = match *dir {
            TcpDirection::In { ufid_in, ufid_out } => (ufid_out, Some(ufid_in)),
            TcpDirection::Out { ufid_out } => (ufid_out, None),
        };

        let Some(entry) = data.tcp_flows.get(ufid_out) else {
            return Err(ProcessError::MissingFlow(*ufid_out));
        };
        let entry = entry.clone();

        entry.hit();
        let tfes_base = entry.state();

        let next_state = tfes_base.update(
            self.name_cstr.as_c_str(),
            tcp,
            dir.dir(),
            pkt_len,
            ufid_in,
        );

        let ufid_inbound = if matches!(
            next_state,
            Ok(TcpState::Closed) | Err(TcpFlowStateError::NewFlow { .. })
        ) {
            // Due to order of operations, out_tcp_existing must
            // call uft_tcp_closed separately.
            let entry = data.tcp_flows.remove(ufid_out).unwrap();
            let lock = entry.state().inner.lock();
            let state_ufid = lock.inbound_ufid;

            // The inbound side of the UFT is based on
            // the network-side of the flow (pre-processing).
            self.uft_tcp_closed(data, ufid_out, state_ufid.as_ref());

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
            a => TcpMaybeClosed::NewState(a, entry),
        })
    }

    // Process the TCP packet for the purposes of connection tracking
    // when an inbound UFT entry exists.
    fn process_in_tcp(
        &self,
        data: &mut PortData,
        pmeta: &MblkPacketData,
        ufid_in: &InnerFlowId,
        pkt_len: u64,
    ) -> result::Result<TcpMaybeClosed, ProcessError> {
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

        match self.update_tcp_entry(data, tcp, &dir, pkt_len) {
            // We need to create a new TCP entry here because we can't call
            // `process_in_miss` on the already-modified packet.
            Err(
                ProcessError::TcpFlow(TcpFlowStateError::NewFlow { .. })
                | ProcessError::MissingFlow(_),
            ) => self.create_new_tcp_entry(
                &mut data.tcp_flows,
                tcp,
                &dir,
                pkt_len,
            ),
            v => v,
        }
    }

    fn process_in_miss(
        &self,
        data: &mut PortData,
        epoch: u64,
        pkt: &mut Packet<MblkFullParsed>,
        ufid_in: &InnerFlowId,
        ameta: &mut ActionMeta,
    ) -> result::Result<InternalProcessResult, ProcessError> {
        use Direction::In;

        self.stats.vals.in_uft_miss.incr(1);
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
                });
            }

            Ok(LayerResult::Hairpin(hppkt)) => {
                return Ok(InternalProcessResult::Hairpin(hppkt));
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

        let mut flags = TransformFlags::empty();
        if pkt.checksums_dirty() {
            flags |= TransformFlags::CSUM_DIRTY;
        }
        if ameta.is_internal_target() {
            flags |= TransformFlags::INTERNAL_DESTINATION;
        }

        let ufid_out = pkt.flow().mirror();
        let mut hte = UftEntry {
            pair: KMutex::new(Some(ufid_out)),
            xforms: xforms.compile(flags),
            epoch,
            l4_hash: ufid_in.crc32(),
            tcp_flow: None,
        };

        // Keep around the comment on the `None` arm
        #[allow(clippy::single_match)]
        match data.uft_out.get(&ufid_out) {
            // If an outbound packet has already created an outbound
            // UFT entry, make sure to pair it to this inbound entry.
            Some(out_entry) => {
                // Remember, the inbound UFID is the flow as seen by
                // the network, before any processing is done by OPTE.

                *out_entry.state().pair.lock() = Some(*ufid_in);
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
        if pkt.meta().is_inner_tcp() {
            match self.process_in_tcp(
                data,
                pkt.meta(),
                ufid_in,
                pkt.len() as u64,
            ) {
                Ok(TcpMaybeClosed::Closed { .. }) => {
                    Ok(InternalProcessResult::Modified)
                }

                // Found existing TCP flow, or have just created a new one.
                Ok(TcpMaybeClosed::NewState(_, flow)) => {
                    // We have a good TCP flow, create a new UFT entry.
                    hte.tcp_flow = Some(flow);
                    match data.uft_in.add(*ufid_in, hte) {
                        Ok(_) => Ok(InternalProcessResult::Modified),
                        Err(OpteError::MaxCapacity(limit)) => {
                            Err(ProcessError::FlowTableFull {
                                kind: "UFT",
                                limit,
                            })
                        }
                        Err(_) => unreachable!(
                            "Cannot return other errors from FlowTable::add"
                        ),
                    }
                }

                // Unlike for existing flows, we don't allow through
                // unexpected packets here for now -- the `TcpState` FSM
                // already encodes a shortcut from `Closed` to `Established.
                Err(ProcessError::TcpFlow(err)) => {
                    let e = format!("{err}");
                    self.tcp_err(&data.tcp_flows, Direction::In, e, pkt);
                    Ok(InternalProcessResult::Drop {
                        reason: DropReason::TcpErr,
                    })
                }
                Err(ProcessError::FlowTableFull { kind, limit }) => {
                    let e = format!("{kind} flow table full ({limit} entries)");
                    self.tcp_err(&data.tcp_flows, Direction::In, e, pkt);
                    Ok(InternalProcessResult::Drop {
                        reason: DropReason::TcpErr,
                    })
                }
                res => unreachable!(
                    "Cannot return other errors from \
                    process_in_tcp, returned: {res:?}"
                ),
            }
        } else {
            match data.uft_in.add(*ufid_in, hte) {
                Ok(_) => Ok(InternalProcessResult::Modified),
                Err(OpteError::MaxCapacity(limit)) => {
                    Err(ProcessError::FlowTableFull { kind: "UFT", limit })
                }
                Err(_) => unreachable!(
                    "Cannot return other errors from FlowTable::add"
                ),
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
                __dtrace_probe_uft__hit(
                    dir as uintptr_t,
                    self.name_cstr.as_ptr() as uintptr_t,
                    ufid,
                    epoch as uintptr_t,
                    last_hit.raw_millis() as usize
                );
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

    // Process the TCP packet for the purposes of connection tracking
    // when an outbound UFT entry was just created.
    fn process_out_tcp_new(
        &self,
        data: &mut PortData,
        ufid_out: &InnerFlowId,
        pmeta: &MblkPacketData,
        pkt_len: u64,
    ) -> result::Result<TcpMaybeClosed, ProcessError> {
        let tcp = pmeta.inner_tcp().unwrap();
        let dir = TcpDirection::Out { ufid_out };

        match self.update_tcp_entry(data, tcp, &dir, pkt_len) {
            Err(
                ProcessError::TcpFlow(TcpFlowStateError::NewFlow { .. })
                | ProcessError::MissingFlow(_),
            ) => self.create_new_tcp_entry(
                &mut data.tcp_flows,
                tcp,
                &dir,
                pkt_len,
            ),
            other => other,
        }
    }

    fn process_out_miss(
        &self,
        data: &mut PortData,
        epoch: u64,
        pkt: &mut Packet<MblkFullParsed>,
        ameta: &mut ActionMeta,
    ) -> result::Result<InternalProcessResult, ProcessError> {
        use Direction::Out;

        self.stats.vals.out_uft_miss.incr(1);
        let mut tcp_closed = false;

        // For outbound traffic the TCP flow table must be checked
        // _before_ processing take place.
        let tcp_flow = if pkt.meta().is_inner_tcp() {
            match self.process_out_tcp_new(
                data,
                pkt.flow(),
                pkt.meta(),
                pkt.len() as u64,
            ) {
                Ok(TcpMaybeClosed::Closed { ufid_inbound }) => {
                    tcp_closed = true;
                    self.uft_tcp_closed(
                        data,
                        pkt.flow(),
                        ufid_inbound.as_ref(),
                    );
                    None
                }

                // Continue with processing.
                Ok(TcpMaybeClosed::NewState(_, flow)) => Some(flow),

                // Unlike for existing flows, we don't allow through
                // unexpected packets here for now -- the `TcpState` FSM
                // already encodes a shortcut from `Closed` to `Established.
                Err(ProcessError::TcpFlow(err)) => {
                    let e = format!("{err}");
                    self.tcp_err(&data.tcp_flows, Out, e, pkt);
                    return Ok(InternalProcessResult::Drop {
                        reason: DropReason::TcpErr,
                    });
                }
                Err(ProcessError::MissingFlow(flow_id)) => {
                    let e = format!("Missing TCP flow ID: {flow_id}");
                    self.tcp_err(&data.tcp_flows, Direction::In, e, pkt);
                    return Ok(InternalProcessResult::Drop {
                        reason: DropReason::TcpErr,
                    });
                }
                Err(ProcessError::FlowTableFull { kind, limit }) => {
                    let e = format!("{kind} flow table full ({limit} entries)");
                    self.tcp_err(&data.tcp_flows, Direction::In, e, pkt);
                    return Ok(InternalProcessResult::Drop {
                        reason: DropReason::TcpErr,
                    });
                }
                res => unreachable!(
                    "Cannot return other errors from process_in_tcp_new, returned: {res:?}"
                ),
            }
        } else {
            None
        };

        let mut xforms = Transforms::new();
        let flow_before = *pkt.flow();
        let res = self.layers_process(data, Out, pkt, &mut xforms, ameta);

        let mut flags = TransformFlags::empty();
        if pkt.checksums_dirty() {
            flags |= TransformFlags::CSUM_DIRTY;
        }
        if ameta.is_internal_target() {
            flags |= TransformFlags::INTERNAL_DESTINATION;
        }

        let hte = UftEntry {
            pair: KMutex::new(None),
            xforms: xforms.compile(flags),
            epoch,
            l4_hash: flow_before.crc32(),
            tcp_flow,
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
                __dtrace_probe_uft__invalidate(
                    dir as uintptr_t,
                    self.name_cstr.as_ptr() as uintptr_t,
                    ufid,
                    epoch as uintptr_t,
                );
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
                __dtrace_probe_uft__tcp__closed(
                    dir as uintptr_t,
                    self.name_cstr.as_ptr() as uintptr_t,
                    ufid,
                );
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
        &self,
        res: &result::Result<InternalProcessResult, ProcessError>,
    ) {
        let stats = &self.stats.vals;
        match res {
            Ok(InternalProcessResult::Drop { reason }) => {
                stats.in_drop.incr(1);

                match reason {
                    DropReason::HandlePkt => stats.in_drop_handle_pkt.incr(1),
                    DropReason::Layer { .. } => stats.in_drop_layer.incr(1),
                    DropReason::TcpErr => stats.in_drop_tcp_err.incr(1),
                }
            }

            Ok(InternalProcessResult::Modified) => stats.in_modified.incr(1),

            Ok(InternalProcessResult::Hairpin(_)) => stats.in_hairpin.incr(1),

            // XXX We should split the different error types out into
            // individual stats. However, I'm not sure exactly how I
            // would like to to this just yet, and I don't want to
            // hold up this stat work any longer -- better to improve
            // upon stats in follow-up work. E.g., it might make sense
            // to just have a top-level error counter in the
            // PortStats, and then also publisher LayerStats for each
            // layer along with the different error counts.
            Err(_) => stats.in_process_err.incr(1),
        }
    }

    fn update_stats_out(
        &self,
        res: &result::Result<InternalProcessResult, ProcessError>,
    ) {
        let stats = &self.stats.vals;
        match res {
            Ok(InternalProcessResult::Drop { reason }) => {
                stats.out_drop.incr(1);

                match reason {
                    DropReason::HandlePkt => stats.out_drop_handle_pkt.incr(1),
                    DropReason::Layer { .. } => stats.out_drop_layer.incr(1),
                    DropReason::TcpErr => stats.out_drop_tcp_err.incr(1),
                }
            }

            Ok(InternalProcessResult::Modified) => stats.out_modified.incr(1),

            Ok(InternalProcessResult::Hairpin(_)) => stats.out_hairpin.incr(1),

            // XXX We should split the different error types out into
            // individual stats. However, I'm not sure exactly how I
            // would like to to this just yet, and I don't want to
            // hold up this stat work any longer -- better to improve
            // upon stats in follow-up work. E.g., it might make sense
            // to just have a top-level error counter in the
            // PortStats, and then also publisher LayerStats for each
            // layer along with the different error counts.
            Err(_) => stats.out_process_err.incr(1),
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
        self.data.read().layers.iter().map(|l| l.name().to_string()).collect()
    }

    /// Get the number of flows currently in the layer and direction
    /// specified. The value `"uft"` can be used to get the number of
    /// UFT flows.
    pub fn num_flows(&self, layer: &str, dir: Direction) -> u32 {
        let data = self.data.read();
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
        let data = self.data.read();
        data.layers
            .iter()
            .find(|layer| layer.name() == layer_name)
            .map(|layer| layer.num_rules(dir))
            .unwrap_or_else(|| panic!("layer not found: {}", layer_name))
    }
}

/// Helper enum for encoding what UFIDs are available when
/// updating TCP flow state.
enum TcpDirection<'a> {
    In { ufid_in: &'a InnerFlowId, ufid_out: &'a InnerFlowId },
    Out { ufid_out: &'a InnerFlowId },
}

impl TcpDirection<'_> {
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
pub struct TcpFlowEntryStateInner {
    // We store this for the benefit of inbound flows who have UFTs
    // but which need to know their partner UFID to perform an invalidation.
    outbound_ufid: InnerFlowId,
    // This must be the UFID of inbound traffic _as it arrives_ from
    // the network, not after it's processed.
    inbound_ufid: Option<InnerFlowId>,
    tcp_state: TcpFlowState,
    segs_in: u64,
    segs_out: u64,
    bytes_in: u64,
    bytes_out: u64,
}

pub struct TcpFlowEntryState {
    inner: KMutex<TcpFlowEntryStateInner>,
}

impl TcpFlowEntryState {
    fn new_inbound(
        outbound_ufid: InnerFlowId,
        inbound_ufid: InnerFlowId,
        tcp_state: TcpFlowState,
        bytes_in: u64,
    ) -> Self {
        Self {
            inner: KMutex::new(TcpFlowEntryStateInner {
                outbound_ufid,
                inbound_ufid: Some(inbound_ufid),
                tcp_state,
                segs_in: 1,
                segs_out: 0,
                bytes_in,
                bytes_out: 0,
            }),
        }
    }

    fn new_outbound(
        outbound_ufid: InnerFlowId,
        tcp_state: TcpFlowState,
        bytes_out: u64,
    ) -> Self {
        Self {
            inner: KMutex::new(TcpFlowEntryStateInner {
                outbound_ufid,
                inbound_ufid: None,
                tcp_state,
                segs_in: 0,
                segs_out: 1,
                bytes_in: 0,
                bytes_out,
            }),
        }
    }

    fn tcp_state(&self) -> TcpState {
        let lock = self.inner.lock();
        lock.tcp_state.tcp_state()
    }

    #[inline(always)]
    fn update<V: ByteSlice>(
        &self,
        port_name: &CStr,
        tcp: &impl TcpRef<V>,
        dir: Direction,
        pkt_len: u64,
        ufid_in: Option<&InnerFlowId>,
    ) -> result::Result<TcpState, TcpFlowStateError> {
        let mut tfes = self.inner.lock();
        match dir {
            Direction::In => {
                tfes.segs_in += 1;
                tfes.bytes_in += pkt_len;
            }
            Direction::Out => {
                tfes.segs_out += 1;
                tfes.bytes_out += pkt_len;
            }
        }

        if let Some(ufid_in) = ufid_in {
            // We need to store the UFID of the inbound packet
            // before it was processed so that we can retire the
            // correct UFT/LFT entries upon connection
            // termination.
            tfes.inbound_ufid = Some(*ufid_in);
        }
        let ufid_out = tfes.outbound_ufid;
        let tcp_state = &mut tfes.tcp_state;

        tcp_state.process(port_name, dir, &ufid_out, tcp)
    }
}

impl core::fmt::Debug for TcpFlowEntryState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock();
        core::fmt::Debug::fmt(&*inner, f)
    }
}

impl Display for TcpFlowEntryStateInner {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.inbound_ufid {
            None => write!(f, "None {}", self.tcp_state),
            Some(ufid) => write!(f, "{} {}", ufid, self.tcp_state),
        }
    }
}

impl Display for TcpFlowEntryState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let inner = self.inner.lock();
        Display::fmt(&*inner, f)
    }
}

impl Dump for TcpFlowEntryStateInner {
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

impl Dump for TcpFlowEntryState {
    type DumpVal = TcpFlowEntryDump;

    fn dump(&self, hits: u64) -> TcpFlowEntryDump {
        let inner = self.inner.lock();
        inner.dump(hits)
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
        let ttl = match entry.state().tcp_state() {
            TcpState::TimeWait => self.time_wait_ttl,
            _ => self.keepalive_ttl,
        };
        ttl.is_expired(entry.last_hit(), now)
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
unsafe extern "C" {
    pub safe fn __dtrace_probe_port__process__entry(
        dir: uintptr_t,
        port: uintptr_t,
        ifid: *const InnerFlowId,
        epoch: uintptr_t,
        pkt: uintptr_t,
    );
    pub safe fn __dtrace_probe_port__process__return(
        dir: uintptr_t,
        port: uintptr_t,
        flow_before: *const InnerFlowId,
        flow_after: *const InnerFlowId,
        epoch: uintptr_t,
        pkt: uintptr_t,
        hp_pkt: uintptr_t,
        err_b: *const LabelBlock<2>,
        path: uintptr_t,
    );
    pub safe fn __dtrace_probe_tcp__err(
        dir: uintptr_t,
        port: uintptr_t,
        ifid: *const InnerFlowId,
        pkt: uintptr_t,
        msg: uintptr_t,
    );
    pub safe fn __dtrace_probe_uft__hit(
        dir: uintptr_t,
        port: uintptr_t,
        ifid: *const InnerFlowId,
        epoch: uintptr_t,
        last_hit: uintptr_t,
    );
    pub safe fn __dtrace_probe_uft__invalidate(
        dir: uintptr_t,
        port: uintptr_t,
        ifid: *const InnerFlowId,
        epoch: uintptr_t,
    );
    pub safe fn __dtrace_probe_uft__tcp__closed(
        dir: uintptr_t,
        port: uintptr_t,
        ifid: *const InnerFlowId,
    );
}

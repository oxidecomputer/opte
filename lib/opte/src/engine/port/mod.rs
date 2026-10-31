// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! A virtual switch port.

use super::HdlPktAction;
use super::LightweightMeta;
use super::NetworkImpl;
use super::ether::Ethernet;
use super::flow_table::Dump;
use super::flow_table::FlowEntry;
use super::flow_table::FlowTable;
use super::flow_table::Ttl;
use super::headers::EncapMeta;
use super::headers::HeaderAction;
use super::headers::IpPush;
use super::headers::SizeHoldingEncap;
use super::headers::UlpHeaderAction;
use super::ip::L3Repr;
use super::ip::v6::Ipv6;
use super::layer;
use super::layer::Layer;
use super::layer::LayerError;
use super::layer::LayerResult;
use super::layer::LayerStatsSnap;
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
use super::rule::PresavedMeoi;
use super::rule::Rule;
use super::rule::TransformFlags;
use super::tcp::INCIPIENT_EXPIRE_TTL;
use super::tcp::KEEPALIVE_EXPIRE_TTL;
use super::tcp::TIME_WAIT_EXPIRE_TTL;
use super::tcp_state::TcpFlowState;
use super::tcp_state::TcpFlowStateError;
use crate::ExecCtx;
use crate::api::DumpLayerResp;
use crate::api::DumpTcpFlowsResp;
use crate::api::DumpUftResp;
use crate::api::TcpFlowEntryDump;
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
use crate::ddi::sync::KRwLockWriteGuard;
use crate::ddi::time::Moment;
use crate::engine::HdlErrAction;
use crate::engine::flow_table::EvictionPriority;
use crate::engine::flow_table::ExpiryPolicy;
use crate::engine::flow_table::FLOW_DEF_TTL;
use crate::engine::flow_table::FlowEntryInfo;
use crate::engine::flow_table::FlowState;
use crate::engine::flow_table::FlowTableAddError;
use crate::engine::flow_table::FlowTableGetError;
use crate::engine::flow_table::util;
use crate::engine::headers::Valid;
use crate::engine::layer::LayerSpec;
use crate::engine::packet::EmitSpec;
use crate::engine::packet::PushSpec;
use crate::engine::rule::CompiledEncap;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;
use c8str::C8Str;
use core::ffi::CStr;
use core::fmt;
use core::fmt::Display;
use core::num::NonZeroU16;
use core::num::NonZeroU32;
use core::ops::Deref;
use core::result;
use core::str::FromStr;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;
#[cfg(any(feature = "std", test))]
use core::time::Duration;
use illumos_sys_hdrs::uintptr_t;
use ingot::ethernet::Ethertype;
use ingot::tcp::TcpRef;
use ingot::types::Emit;
use ingot::types::HeaderLen;
use ingot::types::Read;
use meta::ActionMeta;
use opte_api::Direction;
use opte_api::LayerDesc;
use opte_api::ListLayersResp;
use opte_api::MacAddr;
use opte_api::OpteError;
use opte_api::RuleId;
use opte_api::TcpFlowStateDump;
use opte_api::TcpState;
use opte_api::UftEntryDump;
use zerocopy::ByteSlice;
use zerocopy::ByteSliceMut;

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
    FlowTableFull {
        kind: &'static str,
        limit: u64,
    },
    LftChildrenFull,
    /// Another packet with the same flow ID and direction created a UFT entry
    /// whilst this packet was traversing the slowpath.
    ///
    /// This indicates a misbehaving NIC or guest, which is placing packets
    /// from a single flow on several queues such that several may
    /// simultaneously receive slowpath processing.
    FlowRace,
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

impl From<FlowTableGetError> for ProcessError {
    fn from(value: FlowTableGetError) -> Self {
        match value {
            FlowTableGetError::LivenessFull => {
                ProcessError::Layer(LayerError::EntryTooBusy)
            }
        }
    }
}

/// The result of processing a packet.
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
    #[leaf]
    Drop { reason: DropReason },
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
    name: Arc<C8Str>,
    mac: MacAddr,
    layers: Vec<LayerSpec>,
    mtu: Option<NonZeroU32>,
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
            Self::InitStats(e) => write!(f, "{e}"),
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
        &mut self,
        new_layer: LayerSpec,
        pos: Pos,
    ) -> result::Result<(), OpteError> {
        match pos {
            Pos::Last => {
                self.layers.push(new_layer);
                return Ok(());
            }

            Pos::First => {
                self.layers.insert(0, new_layer);
                return Ok(());
            }

            Pos::Before(name) => {
                for (i, layer) in self.layers.iter().enumerate() {
                    if layer.name() == name {
                        self.layers.insert(i, new_layer);
                        return Ok(());
                    }
                }
            }

            Pos::After(name) => {
                for (i, layer) in self.layers.iter().enumerate() {
                    if layer.name() == name {
                        self.layers.insert(i + 1, new_layer);
                        return Ok(());
                    }
                }
            }
        }

        Err(OpteError::BadLayerPos {
            layer: new_layer.name().to_string(),
            pos: format!("{pos:?}"),
        })
    }

    /// Add a new `Rule` to the layer named by `layer`, if such a
    /// layer exists. Otherwise, return an error.
    pub fn add_rule(
        &mut self,
        layer_name: &str,
        dir: Direction,
        rule: Rule<Finalized>,
    ) -> result::Result<(), OpteError> {
        for layer in &mut self.layers {
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
        let uft_in =
            FlowTable::new(Arc::clone(&self.name), "uft_in", uft_limit, None);
        let uft_out =
            FlowTable::new(Arc::clone(&self.name), "uft_out", uft_limit, None);
        let tcp_flows = FlowTable::new(
            Arc::clone(&self.name),
            "tcp_flows",
            tcp_limit,
            Some(Arc::<TcpExpiry>::default()),
        );

        let stats = PortStats::new();
        stats.in_uft_capacity.set(u64::from(uft_in.get_limit().get()));
        stats.out_uft_capacity.set(u64::from(uft_out.get_limit().get()));
        stats.tcp_capacity.set(u64::from(tcp_flows.get_limit().get()));

        let stats = KStatNamed::new("xde", self.name.as_str(), stats)?;

        Ok(Port {
            mac: self.mac,
            ectx: self.ectx,
            epoch: 1,
            stats,
            net,
            mtu: self.mtu,

            state: PortState::Ready,
            layers: self
                .layers
                .into_iter()
                .map(|v| v.into_layer(Arc::clone(&self.name)))
                .collect(),
            uft_in: KRwLock::new(uft_in),
            uft_out: KRwLock::new(uft_out),
            tcp_flows: KRwLock::new(tcp_flows),

            name: self.name,
        })
    }

    /// Return a clone of the [`Action`] defined in the given
    /// `Layer` at the given index. If the layer does not exist, or
    /// has no action at that index, then `None` is returned.
    pub fn layer_action(&self, layer: &str, idx: usize) -> Option<Action> {
        for l in &self.layers {
            if l.name() == layer {
                return l.action(idx);
            }
        }

        None
    }

    /// Return the name of the port.
    pub fn name(&self) -> &Arc<C8Str> {
        &self.name
    }

    pub fn new(
        name: Arc<C8Str>,
        mac: MacAddr,
        ectx: Arc<ExecCtx>,
        mtu: Option<NonZeroU32>,
    ) -> Self {
        PortBuilder { name, mac, ectx, layers: Vec::new(), mtu }
    }

    /// Remove the `Layer` registered under `name`, if such a layer
    /// exists.
    pub fn remove_layer(&mut self, name: &str) {
        for (i, layer) in self.layers.iter().enumerate() {
            if layer.name() == name {
                let _ = self.layers.remove(i);
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
        write!(f, "{s}")
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

/// Operations that the main flow identifier type for a given [`NetworkImpl`]
/// must support.
// This should live in `opte::api`, but we don't want to introduce an
// API version change until this is something that *can* actually be specified
// on a per-port basis.
pub trait FlowId:
    fmt::Display
    + fmt::Debug
    + Send
    + Sync
    + Copy
    + Eq
    + Ord
    + core::hash::Hash
    + 'static
{
}
impl FlowId for InnerFlowId {}

/// An entry in the Unified Flow Table.
pub struct UftEntry<Id: FlowId> {
    /// The flow ID for the other side.
    pair: KMutex<Option<Id>>,

    /// The transformations to perform.
    xforms: Arc<Transforms>,

    /// Cached flow hash to speed up route selection.
    l4_hash: u32,

    /// Have all referenced `FlowEntry` elements been marked ready?
    ready: AtomicBool,

    /// The port epoch upon which this entry was established. Used for
    /// invalidation when the rule set is updated.
    epoch: u64,

    /// Cached reference to a flow's TCP state, if applicable.
    /// This allows us to maintain up-to-date TCP flow table info without
    /// performing a second lookup on the flowhash.
    tcp_flow: Option<Weak<FlowEntry<TcpFlowEntryState>>>,

    /// The set of all LFT entries which this UFT was created from.
    parents: Vec<Arc<dyn FlowEntryInfo>>,
}

impl<Id: FlowId> UftEntry<Id> {
    /// Returns whether this flow entry has a weak reference to a given TCP
    /// flow state entry.
    fn uses_tcp_flow(&self, tcp: &Arc<FlowEntry<TcpFlowEntryState>>) -> bool {
        let their_ptr = Arc::as_ptr(tcp);
        self.tcp_flow
            .as_ref()
            .map(Weak::as_ptr)
            .map(|my_ptr| core::ptr::addr_eq(my_ptr, their_ptr))
            .unwrap_or_default()
    }
}

impl<Id: FlowId> Dump for UftEntry<Id> {
    type DumpVal = UftEntryDump;

    fn dump(&self, hits: u64) -> Self::DumpVal {
        UftEntryDump { hits, summary: self.to_string() }
    }
}

impl<Id: FlowId> Display for UftEntry<Id> {
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

impl<Id: FlowId> fmt::Debug for UftEntry<Id> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let UftEntry {
            pair: _pair,
            xforms,
            l4_hash,
            epoch,
            tcp_flow,
            parents,
            ready,
        } = self;

        f.debug_struct("UftEntry")
            .field("pair", &"<lock>")
            .field("xforms", xforms)
            .field("l4_hash", l4_hash)
            .field("ready", ready)
            .field("epoch", epoch)
            .field("tcp_flow", tcp_flow)
            .field("parents", parents)
            .finish()
    }
}

impl<Id: FlowId> FlowState for UftEntry<Id> {
    fn parents(&self) -> impl Iterator<Item = Arc<dyn FlowEntryInfo>> {
        self.parents.iter().map(Arc::clone)
    }
}

// This impl Drop is required to safely handle the case where we attempt to
// create and install a UFT entry, but fail during installation. This moves all
// flow entries that were created on a given slow path walk to the `Ready` state,
// and is a NO-OP on any entries which are already `Ready` or `Dead .
impl<Id: FlowId> Drop for UftEntry<Id> {
    fn drop(&mut self) {
        if !self.ready.load(Ordering::Relaxed) {
            for parent in &self.parents {
                parent.mark_ready();
            }

            if let Some(tcp) = self.tcp_flow.as_ref().and_then(Weak::upgrade) {
                tcp.mark_ready();
            }
        }
    }
}

/// Cumulative counters for a single [`Port`].
#[derive(KStatProvider)]
struct PortStats {
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

    /// The number of inbound packets which resulted were dropped due to
    /// overfilling an LFT's list of tracked children.
    in_child_capacity_err: KStatU64,

    /// The number of inbound packets which matched a UFT entry.
    in_uft_hit: KStatU64,

    /// The number of inbound packets which did not match a UFT entry
    /// and resulted in rule processing.
    in_uft_miss: KStatU64,

    /// The number of flows currently contained in the inbound UFT.
    in_uft_flows: KStatU64,

    /// The maximum number of flows the inbound UFT can hold.
    in_uft_capacity: KStatU64,

    /// The number of entries in the inbound UFT which have been evicted
    /// in favour of a new entry.
    in_uft_evictions: KStatU64,

    /// The number of inbound packets which were larger than the MTU
    /// without valid offload state.
    in_oversize: KStatU64,

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

    /// The number of inbound packets which resulted were dropped due to
    /// overfilling an LFT's list of tracked children.
    out_child_capacity_err: KStatU64,

    /// The number of outbound packets which matched a UFT entry.
    out_uft_hit: KStatU64,

    /// The number of outbound packets which did not match a UFT entry
    /// and resulted in rule processing.
    out_uft_miss: KStatU64,

    /// The number of flows currently contained in the outbound UFT.
    out_uft_flows: KStatU64,

    /// The maximum number of flows the outbound UFT can hold.
    out_uft_capacity: KStatU64,

    /// The number of entries in the outbound UFT which have been evicted
    /// in favour of a new entry.
    out_uft_evictions: KStatU64,

    /// The number of outbound packets which were larger than the MTU
    /// without valid offload state.
    out_oversize: KStatU64,

    /// The number of flows currently contained in the TCP state table.
    tcp_flows: KStatU64,

    /// The maximum number of flows the TCP state table can hold.
    tcp_capacity: KStatU64,

    /// The number of entries in the TCP state table which have been evicted
    /// in favour of a new entry.
    tcp_evictions: KStatU64,
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
    epoch: u64,
    ectx: Arc<ExecCtx>,
    name: Arc<C8Str>,
    mac: MacAddr,
    stats: KStatNamed<PortStats>,
    net: N,
    mtu: Option<NonZeroU32>,

    state: PortState,
    layers: Vec<Layer>,
    uft_in: KRwLock<FlowTable<UftEntry<InnerFlowId>>>,
    uft_out: KRwLock<FlowTable<UftEntry<InnerFlowId>>>,
    // We keep a record of the inbound UFID in the TCP flow table so
    // that we know which inbound UFT/FT entries to retire upon
    // connection termination.
    tcp_flows: KRwLock<FlowTable<TcpFlowEntryState>>,
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
    pub fn pause(&mut self) -> Result<()> {
        check_state!(self.state, [PortState::Running])?;
        self.state = PortState::Paused;
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
    pub fn start(&mut self) {
        self.state = PortState::Running;
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
    pub fn reset(&mut self) {
        // By holding &mut self here, we know that have exclusive access
        // to all inner state. It's imperative to do so, such that this
        // function's side effects are atomic from the point of view of
        // other threads.
        self.state = PortState::Ready;

        // Clear all dynamic state related to the creation of flows.
        for layer in &self.layers {
            layer.clear_flows();
        }

        self.uft_in.write().clear();
        self.uft_out.write().clear();
        self.tcp_flows.write().clear();

        self.stats.vals.out_uft_flows.set(0);
        self.stats.vals.in_uft_flows.set(0);
        self.stats.vals.tcp_flows.set(0);
    }

    /// Get the current [`PortState`].
    pub fn state(&self) -> PortState {
        self.state
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
        &mut self,
        layer_name: &str,
        dir: Direction,
        rule: Rule<Finalized>,
    ) -> Result<()> {
        check_state!(self.state, [PortState::Ready, PortState::Running])?;

        let layer = self.layer_mut_result(layer_name)?;
        layer.add_rule(dir, rule);
        self.epoch += 1;

        Ok(())
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
                let msg_arg = c8str::C8String::from_string(msg).unwrap();

                __dtrace_probe_tcp__err(
                    dir as uintptr_t,
                    self.name.as_ptr() as uintptr_t,
                    flow,
                    mblk_addr,
                    msg_arg.as_ptr() as uintptr_t,
                );
            } else if #[cfg(feature = "usdt")] {
                let flow_s = flow.to_string();
                crate::opte_provider::tcp__err!(
                    || (dir, self.name.as_str(), flow_s, mblk_addr, &msg)
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
    pub fn dump_layer(&self, name: &str) -> Result<DumpLayerResp> {
        self.layer_result(name).map(Layer::dump)
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
    pub fn dump_tcp_flows(&self) -> Result<DumpTcpFlowsResp> {
        check_state!(
            self.state,
            [PortState::Running, PortState::Paused, PortState::Restored]
        )?;

        Ok(DumpTcpFlowsResp { flows: self.tcp_flows.read().dump() })
    }

    /// Clear all entries from the Unified Flow Table (UFT).
    ///
    /// # States
    ///
    /// This command is valid for the following states.
    ///
    /// * [`PortState::Running`]
    pub fn clear_uft(&self) -> Result<()> {
        check_state!(self.state, [PortState::Running])?;
        {
            let mut uft = self.uft_in.write();
            uft.clear();
            self.stats.vals.in_uft_flows.set(0);
        }
        {
            let mut uft = self.uft_out.write();
            uft.clear();
            self.stats.vals.out_uft_flows.set(0);
        }
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
        check_state!(self.state, [PortState::Running])?;

        self.layer_result(layer).map(Layer::clear_flows)
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
    pub fn dump_uft(&self) -> Result<DumpUftResp> {
        check_state!(
            self.state,
            [PortState::Running, PortState::Paused, PortState::Restored],
        )?;

        let (in_limit, in_num_flows, in_flows) = {
            let uft_in = self.uft_in.read();
            (uft_in.get_limit().get(), uft_in.num_flows(), uft_in.dump())
        };

        let (out_limit, out_num_flows, out_flows) = {
            let uft_out = self.uft_out.read();
            (uft_out.get_limit().get(), uft_out.num_flows(), uft_out.dump())
        };

        Ok(DumpUftResp {
            in_limit,
            in_num_flows,
            in_flows,
            out_limit,
            out_num_flows,
            out_flows,
        })
    }

    /// Return the current epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
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
        let now = now.unwrap_or_else(Moment::now);
        check_state!(self.state, [PortState::Running])?;

        // Run expiry in reverse order of dependencies here.
        //
        // The presence of a higher-level entry prevents us from using the timer
        // to expire any entry which it depends upon, and we propagate the
        // last_hit time of each entry down to its children during expiry.
        //
        // A TCP state entry or UFT may in turn reference any number of LFT
        // hits, so we visit those first to maximise the likelihood that we can
        // clear up as many entries as possible.
        {
            let mut tcp = self.tcp_flows.write();
            tcp.expire_flows(now);
            self.stats.vals.tcp_flows.set(u64::from(tcp.num_flows()));
        }

        {
            let mut uft = self.uft_in.write();
            uft.expire_flows(now);
            self.stats.vals.in_uft_flows.set(u64::from(uft.num_flows()));
        }

        {
            let mut uft = self.uft_out.write();
            uft.expire_flows(now);
            self.stats.vals.out_uft_flows.set(u64::from(uft.num_flows()));
        }

        for layer in &self.layers {
            layer.expire_flows(now);
        }

        Ok(())
    }

    /// Use the function `f` to probabilistically mark flows as being ready
    /// for expiry by offsetting their timestamps into the past.
    ///
    /// `f` should return true for a flow which we want to mark (and mark its
    /// children as) expirable.
    #[cfg(any(feature = "std", test))]
    pub fn inject_expiry(&self, mut f: impl FnMut() -> bool) {
        let now = Moment::now();
        let before = now - Duration::from_secs(61);
        let further_still = before - Duration::from_secs(61);

        for dir in [Direction::In, Direction::Out] {
            let map = match dir {
                Direction::In => &self.uft_in,
                Direction::Out => &self.uft_out,
            };
            let map = map.read();
            for (_, entry) in map.iter() {
                let tcp =
                    entry.state().tcp_flow.as_ref().and_then(|v| v.upgrade());
                if !f() {
                    entry.hit_at(now);
                    if let Some(tcp) = tcp {
                        tcp.hit_at(now);
                    }
                    continue;
                }
                entry.hit_at(before);
                if let Some(tcp) = tcp {
                    tcp.hit_at(before);
                }
                for parent in &entry.state().parents {
                    parent.inherit_last_hit_force(further_still);
                }
            }
        }
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
        self.layer_result(layer_name).map(|layer| layer.find_rule(dir, rule))
    }

    /// Return a reference to the layer `name`, if present.
    fn layer(&self, name: &str) -> Option<&Layer> {
        self.layers.iter().find(|l| l.name() == name)
    }

    /// Return a reference to the layer `name`, if present.
    ///
    /// Allocates an [`OpteError::LayerNotFound`] error on a miss.
    fn layer_result(&self, name: &str) -> Result<&Layer> {
        self.layer(name).ok_or_else(|| OpteError::LayerNotFound(name.into()))
    }

    /// Return a reference to the layer `name`, if present.
    fn layer_mut(&mut self, name: &str) -> Option<&mut Layer> {
        self.layers.iter_mut().find(|l| l.name() == name)
    }

    /// Return a reference to the layer `name`, if present.
    ///
    /// Allocates an [`OpteError::LayerNotFound`] error on a miss.
    fn layer_mut_result(&mut self, name: &str) -> Result<&mut Layer> {
        self.layer_mut(name)
            .ok_or_else(|| OpteError::LayerNotFound(name.into()))
    }

    /// Return a reference to the [`Action`] defined in the given
    /// `Layer` at the given index. If the layer does not exist, or
    /// has no action at that index, then `None` is returned.
    ///
    /// # States
    ///
    /// This command is valid for any [`PortState`].
    pub fn layer_action(
        &self,
        layer_name: &str,
        action_idx: usize,
    ) -> Option<Action> {
        self.layer(layer_name).and_then(|layer| layer.action(action_idx))
    }

    /// Return the list of layer names.
    pub fn layers(&self) -> Vec<String> {
        self.layers.iter().map(|l| l.name().to_string()).collect()
    }

    /// Return a snapshot of the layer-level statistics.
    ///
    /// # States
    ///
    /// This command is valid for any [`PortState`].
    pub fn layer_stats_snap(&self, layer_name: &str) -> Option<LayerStatsSnap> {
        self.layer(layer_name).map(Layer::stats_snap)
    }

    /// List each `Layer` under this port.
    ///
    /// # States
    ///
    /// This command is valid for any [`PortState`].
    pub fn list_layers(&self) -> ListLayersResp {
        let mut tmp = Vec::with_capacity(self.layers.len());

        for layer in &self.layers {
            tmp.push(LayerDesc {
                name: layer.name().to_string(),
                rules_in: layer.num_rules(Direction::In),
                rules_out: layer.num_rules(Direction::Out),
                default_in: layer.default_action(Direction::In).to_string(),
                default_out: layer.default_action(Direction::Out).to_string(),
                flows: layer.num_flows(),
            });
        }

        ListLayersResp { layers: tmp }
    }

    /// Return the MAC address of this port.
    pub fn mac_addr(&self) -> MacAddr {
        self.mac
    }

    /// Return the name of the port.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Return the name of the port as a CString.
    pub fn name_cstr(&self) -> &CStr {
        self.name.as_c_str()
    }

    /// Get the number of flows currently in the layer and direction
    /// specified. The value `"uft"` can be used to get the number of
    /// UFT flows.
    #[cfg(any(feature = "std", test))]
    pub fn num_flows(&self, layer_name: &str, dir: Direction) -> u32 {
        match (layer_name, dir) {
            ("uft", Direction::In) => self.uft_in.read().num_flows(),
            ("uft", Direction::Out) => self.uft_out.read().num_flows(),
            (name, _dir) => self
                .layer(name)
                .map(|layer| layer.num_flows())
                .expect("layer not found: {name}"),
        }
    }

    /// Return the number of rules registered for the given layer in
    /// the given direction.
    #[cfg(any(feature = "std", test))]
    pub fn num_rules(&self, layer_name: &str, dir: Direction) -> usize {
        self.layer(layer_name)
            .map(|layer| layer.num_rules(dir))
            .expect("layer not found: {layer_name}")
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
        // expected speed, determined by the actions we need to take and the
        // format of metadata required:
        //
        // 1. UFT exists. Pure push/pop with simple modifications to
        //    inner ULP fields. No body transform.
        // 2. UFT exists. Flow transform could not be compiled as above.
        //    Convert to full metadata and apply saved transform list.
        // 3. No UFT exists. Walk all tables, save and apply transforms
        //    piecemeal OR produce a non-`Modified` decision.
        //
        // Generally, 1 > 2 >>> 3 in terms of rate of pps.
        // Both 1 and 2 are able to drop the UFT lock very quickly and avoid
        // interaction with any other layers or tables.
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
        // The basis of lock management here is that we hold at most *one*
        // table lock at a time (read or write), and rely on liveness data of
        // each flow entry to determine whether an entry remains valid. Flow
        // entries, however, have their own locked state which we may also need
        // access to at the same time as a layer at various points. This is
        // mainly relevant during TCP flow expiry in the midst of
        // `update_tcp_entry_slowpath` and the final registration of all LFTs
        // with their higher-level flow entries in `associate_lfts_upstack`.
        // The lock order we have here is, holding at most one of each:
        //
        // layer/flow table -> uft inner -> tcp inner -> lft lifetime
        //
        // The goal is to take only a read lock on the relevant UFT, and fall
        // back to write locks whenever we have invalid state which must be
        // removed or we need to traverse the slowpath.

        // (1) Check for UFT and precompiled.
        let epoch = self.epoch();
        check_state!(self.state, [PortState::Running])
            .map_err(|_| ProcessError::BadState(self.state))?;

        self.port_process_entry_probe(dir, &flow_before, epoch, mblk_addr);

        let uft = match dir {
            Direction::Out => &self.uft_out,
            Direction::In => &self.uft_in,
        };

        let uft_entry = uft.read().get(&flow_before).map(Arc::clone);

        // Packets which are larger than the guest is able to receive may
        // require bespoke handling by the `NetworkImpl`. If this is the case
        // we make the packet ineligible for path (1). The exception to this is
        // the presence of LRO/GRO flags, which suggest that multiple sub-MTU
        // packets have been combined on its behalf and it is willing/able to
        // resplit these if required.
        //
        // This needs to happen for both fast/slow-path traffic.
        let oversize = self
            .mtu
            .map(|mtu| {
                if pkt.large_offload() {
                    false
                } else {
                    let inner_bytes = pkt
                        .len()
                        .saturating_sub(usize::from(pkt.meta().encap_len()))
                        .saturating_sub(
                            // OPTE's parser structure requires inner ethernet
                            // to be present, and we do not support VLANs.
                            ingot::ethernet::Ethernet::MINIMUM_LENGTH,
                        );

                    usize::try_from(mtu.get())
                        .expect("usize is expected to be >= 32b")
                        < inner_bytes
                }
            })
            .unwrap_or(false);

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

        // If the entry is from a prior table configuration, mark it as invalid
        // and demote ourselves to the slowpath.
        let mut decision = match uft_entry {
            Some(entry)
                if !entry.is_killed() && entry.state().epoch == epoch =>
            {
                // The Fast Path.
                let xforms = &entry.state().xforms;
                let out = if !oversize && xforms.compiled.is_some() {
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
            Some(ref entry) => {
                // The entry is *definitely* from a previous epoch; invalidate
                // its UFT entries and proceed to rule processing.
                let owned_pair = *entry.state().pair.lock();
                let (ufid_in, ufid_out) = {
                    match dir {
                        Direction::Out => {
                            (owned_pair.as_ref(), Some(&flow_before))
                        }
                        Direction::In => {
                            (Some(&flow_before), owned_pair.as_ref())
                        }
                    }
                };
                self.uft_invalidate(ufid_out, ufid_in);
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
                match tcp.map(|v| v.upgrade()) {
                    // This is a TCP flow, and the flow entry is still active.
                    Some(Some(tcp_flow)) => {
                        tcp_flow.hit_at(process_start);

                        let tcp = pkt.meta().inner_tcp().expect(
                            "failed to find TCP state on known TCP flow",
                        );

                        let tcp_dir = match dir {
                            Direction::In => TcpDirection::In {
                                ufid_in: &flow_before,
                                ufid_out: tcp_flow.id(),
                            },
                            Direction::Out => {
                                TcpDirection::Out { ufid_out: &flow_before }
                            }
                        };

                        let invalidated_tcp = match self
                            .update_installed_tcp_state(
                                tcp_flow.as_ref(),
                                tcp,
                                &tcp_dir,
                                pkt.len() as u64,
                            ) {
                            Ok(TcpState::Closed) => Some(tcp_flow),
                            Err(TcpNewFlowNeeded) => {
                                decision = FastPathDecision::Slow;
                                Some(tcp_flow)
                            }
                            _ => None,
                        };

                        // The TCP flow has been advanced to a terminal state
                        // and needs to be removed. Acquire the write lock and
                        // attempt to do so.
                        if let Some(tcp_entry) = invalidated_tcp {
                            let ufid_out = tcp_entry.id();
                            let removed_entry = {
                                let mut tcp_lock = self.tcp_flows.write();

                                // There is every possibility that a packet in
                                // the other direction of the same flow has
                                // also performed a removal. It may have
                                // installed new UFT/TCP entries!
                                //
                                // Verify that the state we want to remove still
                                // exists, and is `Arc`-identical.
                                if let Some(found_entry) =
                                    tcp_lock.get(ufid_out)
                                    && Arc::ptr_eq(found_entry, &tcp_entry)
                                {
                                    let el = tcp_lock.remove(ufid_out);
                                    self.stats
                                        .vals
                                        .tcp_flows
                                        .set(u64::from(tcp_lock.num_flows()));
                                    el
                                } else {
                                    None
                                }
                            };

                            if let Some(el) = removed_entry {
                                self.uft_tcp_closed(el);
                            }
                        }
                    }
                    // The TCP flow this UFT is associated with is gone.
                    // Fallback to the slowpath, where we will regenerate it or
                    // acquire a new entry if one is present.
                    Some(None) => {
                        entry.mark_dead();
                        decision = FastPathDecision::Slow;
                    }
                    // There is no TCP flow.
                    None => {}
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

        if oversize {
            (match dir {
                Direction::In => &self.stats.vals.in_oversize,
                Direction::Out => &self.stats.vals.out_oversize,
            })
            .incr(1);

            match self.net.handle_oversize(dir, &mut pkt)? {
                HdlErrAction::ContinueProcessing => {}
                HdlErrAction::Deny => {
                    let res = Ok(ProcessResult::Drop {
                        reason: DropReason::HandlePkt,
                    });

                    (match dir {
                        Direction::In => &self.stats.vals.in_drop,
                        Direction::Out => &self.stats.vals.out_drop,
                    })
                    .incr(1);

                    self.port_process_return_probe(
                        dir,
                        &flow_before,
                        &flow_before,
                        epoch,
                        mblk_addr,
                        &res,
                        decision.as_u64(),
                    );

                    return res;
                }
                HdlErrAction::Hairpin(msg_blk) => {
                    let res = Ok(ProcessResult::Hairpin(msg_blk));

                    (match dir {
                        Direction::In => &self.stats.vals.in_hairpin,
                        Direction::Out => &self.stats.vals.out_hairpin,
                    })
                    .incr(1);

                    self.port_process_return_probe(
                        dir,
                        &flow_before,
                        &flow_before,
                        epoch,
                        mblk_addr,
                        &res,
                        decision.as_u64(),
                    );
                    return res;
                }
            }
        }

        let res = match (&decision, dir) {
            // (2) Apply retrieved transform. Reuse cached l4 hash.
            (FastPathDecision::Uft(entry), _) => {
                pkt.set_l4_hash(entry.state().l4_hash);
                entry.state().xforms.apply(&mut pkt, dir)?;
                Ok(InternalProcessResult::Modified)
            }

            // (3) Full-table processing for the packet.
            (FastPathDecision::Slow, Direction::In) => {
                self.process_in_miss(epoch, &mut pkt, &flow_before, &mut ameta)
            }
            (FastPathDecision::Slow, Direction::Out) => {
                self.process_out_miss(epoch, &mut pkt, &flow_before, &mut ameta)
            }

            (FastPathDecision::CompiledUft(_), _) => unreachable!(),
        };

        let flow_after = *pkt.flow();

        match dir {
            Direction::In => self.update_stats_in(&res),
            Direction::Out => self.update_stats_out(&res),
        }

        match res {
            Ok(InternalProcessResult::Modified) => {}
            _ => {
                // If we denied the packet or hit an error, we may still
                // have generated new LFTs on a slowpath walk. We need to
                // mark these as having been finalised.
                //
                // For packets which have been explicitly dropped, what we
                // *want* to do here is slightly different. Any LFT entries
                // which are in a `Larval` state should be explicitly removed
                // from their table. This gets us a roundabout solution to
                // #867 -- i.e., firewall-denied packets will _release their
                // claim on a NAT table entry_. However that requires
                // intrusive enough changes that it should be its own PR.
                // The redesign of the locking and use of `Larval` states is
                // done to allow that soon.
                for lft in pkt.take_lfts() {
                    lft.mark_ready();
                }
            }
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
        &mut self,
        layer_name: &str,
        dir: Direction,
        id: RuleId,
    ) -> Result<()> {
        check_state!(self.state, [PortState::Ready, PortState::Running])?;

        let layer = self.layer_mut_result(layer_name)?;
        layer.remove_rule(dir, id)?;
        self.epoch += 1;

        Ok(())
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
        &mut self,
        layer_name: &str,
        in_rules: Vec<Rule<Finalized>>,
        out_rules: Vec<Rule<Finalized>>,
    ) -> Result<()> {
        check_state!(self.state, [PortState::Ready, PortState::Running])?;

        let layer = self.layer_mut_result(layer_name)?;
        layer.set_rules(in_rules, out_rules);
        self.epoch += 1;

        Ok(())
    }

    // TODO: not dupe `set_rules`.
    pub fn set_rules_soft(
        &mut self,
        layer_name: &str,
        in_rules: Vec<Rule<Finalized>>,
        out_rules: Vec<Rule<Finalized>>,
    ) -> Result<()> {
        check_state!(self.state, [PortState::Ready, PortState::Running])?;

        let layer = self.layer_mut_result(layer_name)?;
        layer.set_rules_soft(in_rules, out_rules);
        self.epoch += 1;

        Ok(())
    }

    /// Grab a snapshot of the port statistics.
    pub fn stats_snap(&self) -> PortStatsSnap {
        self.stats.vals.snapshot()
    }

    /// Return the [`TcpState`] of a given flow.
    #[cfg(any(feature = "test-help", test))]
    pub fn tcp_state(&self, flow: &InnerFlowId) -> Option<TcpState> {
        self.tcp_flows.read().get(flow).map(|entry| entry.state().tcp_state())
    }

    /// Test helper for single-threaded execution to verify that all flows
    /// in the port are `Ready` or `Dead`.
    ///
    /// Larval flows cannot be allowed to persist after a packet is done
    /// processing. The fact that they are 'in use' means that they cannot
    /// be evicted or expired, and any attempt to use them will fail under
    /// the assumption that packet processing is still ongoing.
    ///
    /// Panics if any flows are `Larval`.
    #[cfg(any(feature = "test-help", test))]
    pub fn verify_no_larval(&self) {
        for (k, v) in self.uft_in.read().iter() {
            v.verify_not_larval("uft", k, Some(Direction::In));
        }
        for (k, v) in self.uft_out.read().iter() {
            v.verify_not_larval("uft", k, Some(Direction::Out));
        }
        for (k, v) in self.tcp_flows.read().iter() {
            v.verify_not_larval("tcp", k, None);
        }
        for layer in &self.layers {
            layer.verify_no_larval();
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
enum TcpMaybeClosed {
    Closed(Option<Arc<FlowEntry<TcpFlowEntryState>>>),
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
                fn store_outer_push<P: Clone, M>(
                    tx: &HeaderAction<P, M>,
                    still_permissable: &mut bool,
                    slot: &mut Option<Valid<P>>,
                ) {
                    match tx {
                        HeaderAction::Push(p) => *slot = Some(p.clone()),
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
                        let encap = EncapMeta::from(encap.into_inner());

                        let eth_repr = Ethernet {
                            destination: eth.dst,
                            source: eth.src,
                            ethertype: Ethertype(eth.ether_type.into()),
                        };
                        let eth_len = eth_repr.packet_length();

                        let ip_repr = L3Repr::from(&ip);
                        let ip_len = ip_repr.packet_length();
                        let (ulp, l3_extra_bytes, ip_len_offset) = match &*ip {
                            IpPush::Ip4(v4) => (v4.proto, ip_len, 2),
                            IpPush::Ip6(v6) => {
                                (v6.proto, ip_len - Ipv6::MINIMUM_LENGTH, 4)
                            }
                        };
                        let l3_len_offset = eth_len + ip_len_offset;

                        // UDP has a length field 4B into its header.
                        // in event of TCP, l4_len_offset is ignored.
                        let l4_len_offset = eth_repr.packet_length()
                            + ip_repr.packet_length()
                            + 4;

                        let encap_sz = encap.packet_length();
                        let tun_sz = encap.tunnel_len();

                        let bytes = (
                            eth_repr,
                            ip_repr,
                            // Sizes will be filled later using offset info.
                            SizeHoldingEncap { encapped_len: 0, meta: &encap },
                        )
                            .emit_vec();

                        let meoi = PresavedMeoi {
                            l2hlen: u8::try_from(eth_len)
                                .expect("14B < u8::MAX"),
                            l3proto: eth_repr.ethertype.0,
                            l3hlen: u16::try_from(ip_len).expect(
                                "IPv4 is bounded, IPv6 validates to <= 65535",
                            ),
                            l4proto: ulp.into(),
                            tunhlen: u16::try_from(tun_sz)
                                .expect("Geneve is bounded to 260B"),
                        };

                        Some(CompiledEncap::Push {
                            encap,
                            eth: *eth,
                            ip: ip.into_inner(),
                            bytes,
                            l3_len_offset,
                            l3_extra_bytes,
                            l4_len_offset,
                            encap_sz,
                            meoi,
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
    // returned, then `meta` contains the updated metadata, and `xforms`
    // contains the list of all transformations to run against the
    // packet, including header and body transformations.
    //
    // Processing may return early for several reasons.
    //
    // * Deny: A layer can choose to deny a packet, in which case the
    // packet is dropped and no further processing is done.
    //
    // * Hairpin: A layer has generated a hairpin packet.
    //
    // * HandlePkt: The network impl decided to handle the packet directly,
    // rather than going through the usual layer actions. This results in
    // calling `NetworkImpl::handle_pkt()` on the packet.
    //
    // * Error: An error has ocurred and processing cannot continue.
    fn layers_process(
        &self,
        dir: Direction,
        pkt: &mut Packet<MblkFullParsed>,
        xforms: &mut Transforms,
        ameta: &mut ActionMeta,
    ) -> result::Result<LayerResult, LayerError> {
        match dir {
            Direction::Out => {
                for layer in &self.layers {
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
                for layer in self.layers.iter().rev() {
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
                    self.name.as_ptr() as uintptr_t,
                    flow,
                    epoch as uintptr_t,
                    mblk_addr,
                );
            } else if #[cfg(feature = "usdt")] {
                let flow_s = flow.to_string();
                crate::opte_provider::port__process__entry!(
                    || (dir, self.name.as_str(), flow_s, epoch, mblk_addr)
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
                    Err(e) => (Ok(LabelBlock::new()), Some(format!("ERROR: {e:?}\0"))),
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
                    self.name.as_ptr() as uintptr_t,
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
                    Ok(v) => format!("{v:?}"),
                    Err(e) => format!("ERROR: {e:?}"),
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
            self.name_cstr(),
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
                Ok(entry) => {
                    // Evictions are detected in the same manner as in
                    // `new_uft_kstat`: if the flow count has not changed
                    // in response to a successful add, then `entry` has
                    // evicted another flow.
                    let n_flows = u64::from(tcp_flows.num_flows());
                    let old_count = self.stats.vals.tcp_flows.val();
                    self.stats.vals.tcp_flows.set(n_flows);

                    if n_flows == old_count {
                        self.stats.vals.tcp_evictions.incr(1);
                    }

                    Ok(TcpMaybeClosed::NewState(tcp_state, entry))
                }
                Err(FlowTableAddError::MaxCapacity(limit)) => {
                    Err(ProcessError::FlowTableFull { kind: "TCP", limit })
                }
                Err(FlowTableAddError::Existing) => {
                    unreachable!(
                        "callers must have verified that there was no entry"
                    )
                }
            }
        } else {
            Ok(TcpMaybeClosed::Closed(None))
        }
    }

    /// Lookup and update TCP flow state in response to a given packet from
    /// within the slowpath.
    ///
    /// Unexpected TCP segments on existing connections will be allowed,
    /// but will fire DTrace probes via `Self::tcp_err_probe`.
    ///
    /// Any flow entry returned via `TcpMaybeClosed::NewState` will have
    /// a hold registered.
    ///
    /// # Errors
    /// * `ProcessError::Layer(LayerError::EntryTooBusy)` if too many
    ///   slowpath threads place a hold on the same flow entry.
    fn update_tcp_entry_slowpath<V: ByteSlice>(
        &self,
        tcp: &impl TcpRef<V>,
        dir: &TcpDirection,
        pkt_len: u64,
    ) -> result::Result<TcpMaybeClosed, ProcessError> {
        let ufid_out = match dir {
            TcpDirection::In { ufid_out, .. } => *ufid_out,
            TcpDirection::Out { ufid_out } => *ufid_out,
        };

        // This `loop` deserves some explanation. This *will* terminate in at
        // most two iterations, but because we have parallel readers/writers
        // we have a set of operations that need to be possibly retried under
        // escalating lock levels.
        //
        // The goal is to find a TCP entry for ufid_out. If one is present,
        // move its state forward. If that state is terminal, remove the
        // entry. If we need to insert a new state, because of an earlier miss
        // or because the TSP state was advanced back to the beginning, do so.
        //
        // However! We start with a read lock, because that's the polite thing
        // to do, reply traffic can make good use of it, and the cleanup task
        // may be able to check whether it *needs* to operate with a read lock
        // first. This introduces a window where the table state can change
        // before we complete an upgrade to a write lock.
        //
        // To run through the cases we handle here:
        //
        // (1) - We succeed on the read-lookup, progress the flow to a non-
        //       terminal state, then exit.
        // (2) - We fail on the read-lookup, and take the write lock. We repeat
        //       the lookup, fail again, and create and insert our new state.
        // (3) - We succeed on the lookup, progress the flow, and move to a
        //       terminal state. We take the write lock and check that the
        //       entry in the map is still the one we operated on.
        //       We remove it, and create a new entry if required.
        // (4) - As (3), but the entry matching our ufid_out is *not* ours. We
        //       replay our state transition on the newly found state and then
        //       modify the table state as needed.
        // (5) - As (2), but we find a match after taking the write lock.
        //       We handle all state as in the successful cases (1)/(3).
        let mut write_lock: Option<KRwLockWriteGuard<FlowTable<_>>> = None;
        let mut entry = None;

        loop {
            entry = if let Some(v) = entry.take() {
                // We have upgraded to a write lock, and are starting with
                // another state that we need to try and use.
                Some(v)
            } else {
                // We're here either at the start of processing, or because
                // the initial lookup failed. In the former case we will take
                // a short read lock, and in the latter we will have a write
                // lock already.
                let read_lock = if write_lock.is_none() {
                    Some(self.tcp_flows.read())
                } else {
                    None
                };

                let table = match (read_lock.as_ref(), write_lock.as_ref()) {
                    (Some(v), None) => v.deref(),
                    (None, Some(v)) => v.deref(),
                    _ => unreachable!(
                        "we can only hold either the read or write lock"
                    ),
                };

                match table.get_and_hold(ufid_out)? {
                    Some(v) => {
                        v.hit();
                        Some(v.clone())
                    }
                    None => {
                        drop(read_lock);

                        // If we never saw an entry, we need to grab the
                        // writelock and retry from initial lookup to be
                        // sure no one beat us to it before we create a
                        // new one.
                        if write_lock.is_none() {
                            write_lock = Some(self.tcp_flows.write());
                            continue;
                        }

                        None
                    }
                }
            };

            // If we've found some TCP state, advance its state machine and
            // see whether it needs to be invalidated from a write lock.
            if let Some(e) = entry {
                let next_state = self.update_installed_tcp_state(
                    e.as_ref(),
                    tcp,
                    dir,
                    pkt_len,
                );

                if e.is_killed() {
                    // We've moved to `Closed`, or determined that we've
                    // jumped back to the start of the TCP state machine
                    // and require a new flow entry. Remove the old entry.
                    if write_lock.is_none() {
                        write_lock = Some(self.tcp_flows.write());
                    }
                    let table = write_lock.as_mut().expect("just set to Some");

                    match table.get(ufid_out) {
                        Some(curr_entry) if Arc::ptr_eq(&e, curr_entry) => {
                            _ = table.remove(ufid_out).unwrap();

                            self.stats
                                .vals
                                .tcp_flows
                                .set(u64::from(table.num_flows()));
                        }
                        Some(e) if !e.is_killed() => {
                            // Someone else has inserted another TCP flow state
                            // entry in the same key slot during our lock upgrade.
                            // Retry, updating and binding ourself to this state
                            // entry instead, if possible.
                            entry = Some(Arc::clone(e));
                            continue;
                        }
                        _ => {}
                    };
                }

                match next_state {
                    Err(TcpNewFlowNeeded) => {}
                    Ok(TcpState::Closed) => {
                        break Ok(TcpMaybeClosed::Closed(Some(e)));
                    }
                    Ok(v) => break Ok(TcpMaybeClosed::NewState(v, e)),
                }
            };

            // We need to create new TCP state -- we are guaranteed a write lock
            // at this point.
            break self.create_new_tcp_entry(
                write_lock.as_mut().unwrap(),
                tcp,
                dir,
                pkt_len,
            );
        }
    }

    // Process the TCP packet for the purposes of connection tracking
    // when an inbound UFT entry exists.
    fn process_in_tcp(
        &self,
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

        self.update_tcp_entry_slowpath(tcp, &dir, pkt_len)
    }

    /// Process an inbound packet which does not have a UFT entry.
    ///
    /// This is called when we miss a lookup into the UFT for a packet. It
    /// applies the transformations from each individual layer flow table, and
    /// then possibly compiles the resulting transformation into a new UFT
    /// entry.
    fn process_in_miss(
        &self,
        epoch: u64,
        pkt: &mut Packet<MblkFullParsed>,
        ufid_in: &InnerFlowId,
        ameta: &mut ActionMeta,
    ) -> result::Result<InternalProcessResult, ProcessError> {
        use Direction::In;

        self.stats.vals.in_uft_miss.incr(1);
        let mut xforms = Transforms::new();
        let res = self.layers_process(In, pkt, &mut xforms, ameta);
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
                return Ok(InternalProcessResult::from(
                    self.net.handle_pkt(In, pkt)?,
                ));
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

        pkt.update_checksums();

        let ufid_out = pkt.flow().mirror();

        let mut hte = UftEntry {
            pair: KMutex::new(Some(ufid_out)),
            xforms: xforms.compile(flags),
            epoch,
            l4_hash: ufid_in.crc32(),
            tcp_flow: None,
            parents: pkt.take_lfts(),
            ready: false.into(),
        };

        // Keep around the comment on the `None` arm
        #[allow(clippy::single_match)]
        match self.uft_out.read().get(&ufid_out) {
            // If an outbound packet has already created an outbound
            // UFT entry, make sure to pair it to this inbound entry.
            Some(out_entry) if !out_entry.is_killed() => {
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
            _ => {}
        }

        // For inbound traffic the TCP flow table must be
        // checked _after_ processing take place.
        if pkt.meta().is_inner_tcp() {
            match self.process_in_tcp(pkt.meta(), ufid_in, pkt.len() as u64) {
                Ok(TcpMaybeClosed::Closed(removed)) => {
                    if let Some(removed) = removed {
                        self.uft_tcp_closed(removed);
                    }
                    Ok(InternalProcessResult::Modified)
                }

                // Found existing TCP flow, or have just created a new one.
                Ok(TcpMaybeClosed::NewState(_, flow)) => {
                    // We have a good TCP flow, create a new UFT entry.
                    hte.tcp_flow = Some(Arc::downgrade(&flow));

                    let mut uft_in = self.uft_in.write();
                    match uft_in.add(*ufid_in, hte) {
                        Ok(v) => {
                            self.new_uft_kstat(In, &mut uft_in);
                            match associate_lfts_upstack(
                                &v,
                                Direction::In,
                                &mut uft_in,
                            ) {
                                Ok(_) => Ok(InternalProcessResult::Modified),
                                Err(FlowTableAddError::MaxCapacity(_)) => {
                                    Err(ProcessError::LftChildrenFull)
                                }
                                Err(_) => unreachable!(
                                    "UFT association can only fail due to capacity checks."
                                ),
                            }
                        }
                        Err(FlowTableAddError::MaxCapacity(limit)) => {
                            Err(ProcessError::FlowTableFull {
                                kind: "UFT",
                                limit,
                            })
                        }
                        Err(FlowTableAddError::Existing) => {
                            Err(ProcessError::FlowRace)
                        }
                    }
                }

                // Unlike for existing flows, we don't allow through
                // unexpected packets here for now -- the `TcpState` FSM
                // already encodes a shortcut from `Closed` to `Established.
                Err(ProcessError::TcpFlow(err)) => {
                    let e = format!("{err}");
                    self.tcp_err_probe(Direction::In, Some(pkt), ufid_in, e);
                    Ok(InternalProcessResult::Drop {
                        reason: DropReason::TcpErr,
                    })
                }
                Err(ProcessError::FlowTableFull { kind, limit }) => {
                    let e = format!("{kind} flow table full ({limit} entries)");
                    self.tcp_err_probe(Direction::In, Some(pkt), ufid_in, e);
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
            let mut uft_in = self.uft_in.write();
            match uft_in.add(*ufid_in, hte) {
                Ok(v) => {
                    self.new_uft_kstat(In, &mut uft_in);
                    match associate_lfts_upstack(&v, Direction::In, &mut uft_in)
                    {
                        Ok(_) => Ok(InternalProcessResult::Modified),
                        Err(FlowTableAddError::MaxCapacity(_)) => {
                            Err(ProcessError::LftChildrenFull)
                        }
                        Err(_) => unreachable!(
                            "UFT association can only fail due to capacity checks."
                        ),
                    }
                }
                Err(FlowTableAddError::MaxCapacity(limit)) => {
                    Err(ProcessError::FlowTableFull { kind: "UFT", limit })
                }
                Err(FlowTableAddError::Existing) => Err(ProcessError::FlowRace),
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
                    self.name.as_ptr() as uintptr_t,
                    ufid,
                    epoch as uintptr_t,
                    last_hit.raw_millis() as usize
                );
            } else if #[cfg(feature = "usdt")] {
                let port_s = self.name.to_str();
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
    fn process_out_tcp(
        &self,
        ufid_out: &InnerFlowId,
        pmeta: &MblkPacketData,
        pkt_len: u64,
    ) -> result::Result<TcpMaybeClosed, ProcessError> {
        let tcp = pmeta.inner_tcp().unwrap();
        let dir = TcpDirection::Out { ufid_out };

        self.update_tcp_entry_slowpath(tcp, &dir, pkt_len)
    }

    /// Process an outbound packet which does not have a UFT entry.
    fn process_out_miss(
        &self,
        epoch: u64,
        pkt: &mut Packet<MblkFullParsed>,
        ufid_out: &InnerFlowId,
        ameta: &mut ActionMeta,
    ) -> result::Result<InternalProcessResult, ProcessError> {
        use Direction::Out;

        self.stats.vals.out_uft_miss.incr(1);
        let mut tcp_closed = false;

        // For outbound traffic the TCP flow table must be checked
        // _before_ processing take place.
        let tcp_flow_full = if pkt.meta().is_inner_tcp() {
            match self.process_out_tcp(ufid_out, pkt.meta(), pkt.len() as u64) {
                Ok(TcpMaybeClosed::Closed(removed)) => {
                    tcp_closed = true;
                    if let Some(removed) = removed {
                        self.uft_tcp_closed(removed);
                    }
                    None
                }

                // Continue with processing.
                Ok(TcpMaybeClosed::NewState(_, flow)) => Some(flow),

                // Unlike for existing flows, we don't allow through
                // unexpected packets here for now -- the `TcpState` FSM
                // already encodes a shortcut from `Closed` to `Established.
                Err(ProcessError::TcpFlow(err)) => {
                    let e = format!("{err}");
                    self.tcp_err_probe(Out, Some(pkt), ufid_out, e);
                    return Ok(InternalProcessResult::Drop {
                        reason: DropReason::TcpErr,
                    });
                }
                Err(ProcessError::MissingFlow(flow_id)) => {
                    let e = format!("Missing TCP flow ID: {flow_id}");
                    self.tcp_err_probe(Out, Some(pkt), ufid_out, e);
                    return Ok(InternalProcessResult::Drop {
                        reason: DropReason::TcpErr,
                    });
                }
                Err(ProcessError::FlowTableFull { kind, limit }) => {
                    let e = format!("{kind} flow table full ({limit} entries)");
                    self.tcp_err_probe(Out, Some(pkt), ufid_out, e);
                    return Ok(InternalProcessResult::Drop {
                        reason: DropReason::TcpErr,
                    });
                }
                res => unreachable!(
                    "Cannot return other errors from process_out_tcp, returned: {res:?}"
                ),
            }
        } else {
            None
        };

        let mut xforms = Transforms::new();
        let res = self.layers_process(Out, pkt, &mut xforms, ameta);

        let tcp_flow = tcp_flow_full.as_ref().map(Arc::downgrade);

        let mut flags = TransformFlags::empty();
        if pkt.checksums_dirty() {
            flags |= TransformFlags::CSUM_DIRTY;
        }
        if ameta.is_internal_target() {
            flags |= TransformFlags::INTERNAL_DESTINATION;
        }

        pkt.update_checksums();

        match res {
            Ok(LayerResult::Allow) => {
                // If there is no Flow ID, then there is no UFT entry.
                // Equally, if we had a TCP entry that we moved to closed,
                // then we should not create a UFT entry (as there should
                // be no other packets it could handle).
                if *ufid_out == FLOW_ID_DEFAULT || tcp_closed {
                    return Ok(InternalProcessResult::Modified);
                }

                let hte = UftEntry {
                    pair: KMutex::new(None),
                    xforms: xforms.compile(flags),
                    epoch,
                    l4_hash: ufid_out.crc32(),
                    tcp_flow,
                    parents: pkt.take_lfts(),
                    ready: false.into(),
                };

                let mut uft_out = self.uft_out.write();

                match uft_out.add(*ufid_out, hte) {
                    Ok(v) => {
                        self.new_uft_kstat(Out, &mut uft_out);
                        match associate_lfts_upstack(
                            &v,
                            Direction::Out,
                            &mut uft_out,
                        ) {
                            Ok(_) => Ok(InternalProcessResult::Modified),
                            Err(FlowTableAddError::MaxCapacity(_)) => {
                                Err(ProcessError::LftChildrenFull)
                            }
                            Err(_) => unreachable!(
                                "UFT association can only fail due to capacity checks."
                            ),
                        }
                    }
                    Err(FlowTableAddError::MaxCapacity(limit)) => {
                        Err(ProcessError::FlowTableFull { kind: "UFT", limit })
                    }
                    Err(FlowTableAddError::Existing) => {
                        Err(ProcessError::FlowRace)
                    }
                }
            }

            Ok(LayerResult::Hairpin(hppkt)) => {
                tcp_flow_full.inspect(|v| v.mark_ready());
                Ok(InternalProcessResult::Hairpin(hppkt))
            }

            Ok(LayerResult::Deny { name, reason }) => {
                tcp_flow_full.inspect(|v| v.mark_ready());
                Ok(InternalProcessResult::Drop {
                    reason: DropReason::Layer { name, reason },
                })
            }

            Ok(LayerResult::HandlePkt) => {
                tcp_flow_full.inspect(|v| v.mark_ready());
                Ok(InternalProcessResult::from(self.net.handle_pkt(Out, pkt)?))
            }

            Err(e) => {
                tcp_flow_full.inspect(|v| v.mark_ready());
                Err(ProcessError::Layer(e))
            }
        }
    }

    fn new_uft_kstat(
        &self,
        dir: Direction,
        uft: &mut FlowTable<UftEntry<InnerFlowId>>,
    ) {
        let vals = &self.stats.vals;
        let (flow_stat, evict_stat) = match dir {
            Direction::In => (&vals.in_uft_flows, &vals.in_uft_evictions),
            Direction::Out => (&vals.out_uft_flows, &vals.out_uft_evictions),
        };

        // This function is called in response to a successful addition of a UFT.
        // If the flow count is unchanged, then we know another entry was evicted
        // in favour of the new one.
        //
        // Because we hold the write lock, no one else will alter this value.
        let n_flows = u64::from(uft.num_flows());
        let old_count = flow_stat.val();
        flow_stat.set(n_flows);

        if n_flows == old_count {
            evict_stat.incr(1);
        }
    }

    /// Remove a pair of in/out flows if their epoch differs from that of the
    /// port itself.
    ///
    /// This must not be called with any flow table/layer locks held.
    fn uft_invalidate(
        &self,
        ufid_out: Option<&InnerFlowId>,
        ufid_in: Option<&InnerFlowId>,
    ) {
        let epoch = self.epoch;

        if let Some(ufid_in) = ufid_in {
            let mut uft = self.uft_in.write();
            uft.remove_if(*ufid_in, |v| {
                v.is_killed() || v.state().epoch != epoch
            });
            self.stats.vals.in_uft_flows.set(u64::from(uft.num_flows()));
            self.uft_invalidate_probe(Direction::In, ufid_in, epoch);
        }

        if let Some(ufid_out) = ufid_out {
            let mut uft = self.uft_out.write();
            uft.remove_if(*ufid_out, |v| {
                v.is_killed() || v.state().epoch != epoch
            });
            self.stats.vals.out_uft_flows.set(u64::from(uft.num_flows()));
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
                    self.name.as_ptr() as uintptr_t,
                    ufid,
                    epoch as uintptr_t,
                );
            } else if #[cfg(feature = "usdt")] {
                let port_s = self.name.to_str();
                let ufid_s = ufid.to_string();
                crate::opte_provider::uft__invalidate!(
                    || (dir, port_s, ufid_s, epoch)
                );
            } else {
                let (_, _, _) = (dir, ufid, epoch);
            }
        }
    }

    /// Remove any UFT entries for flows which are connected to `removed`,
    /// a TCP flow which has been killed.
    ///
    /// This method must now be called whilst holding *any* table locks.
    fn uft_tcp_closed(&self, removed: Arc<FlowEntry<TcpFlowEntryState>>) {
        if let Some(ufid_in) = removed.state().inner.lock().inbound_ufid {
            let mut uft = self.uft_in.write();
            if let Some(found_entry) = uft.get(&ufid_in)
                && found_entry.state().uses_tcp_flow(&removed)
            {
                uft.remove(&ufid_in);
                self.stats.vals.in_uft_flows.set(u64::from(uft.num_flows()));
                self.uft_tcp_closed_probe(Direction::In, &ufid_in);
            }
        }

        {
            let ufid_out = removed.id();
            let mut uft = self.uft_out.write();
            if let Some(found_entry) = uft.get(ufid_out)
                && found_entry.state().uses_tcp_flow(&removed)
            {
                uft.remove(ufid_out);
                self.stats.vals.out_uft_flows.set(u64::from(uft.num_flows()));
                self.uft_tcp_closed_probe(Direction::Out, ufid_out);
            }
        }
    }

    fn uft_tcp_closed_probe(&self, dir: Direction, ufid: &InnerFlowId) {
        cfg_if::cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                __dtrace_probe_uft__tcp__closed(
                    dir as uintptr_t,
                    self.name.as_ptr() as uintptr_t,
                    ufid,
                );
            } else if #[cfg(feature = "usdt")] {
                let port_s = self.name.to_str();
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

            Err(ProcessError::LftChildrenFull) => {
                stats.in_process_err.incr(1);
                stats.in_child_capacity_err.incr(1);
            }

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

            Err(ProcessError::LftChildrenFull) => {
                stats.out_process_err.incr(1);
                stats.out_child_capacity_err.incr(1);
            }

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

    #[inline(always)]
    /// Update a live TCP flow state entry in response to an arriving packet.
    /// Returns the new TCP FSM state, and marks the flow entry as `Dead` if
    /// the flow is moved to a terminal state or an error occurs.
    ///
    /// Returns an error if this packet marks the start of a new flow.
    fn update_installed_tcp_state<V: ByteSlice>(
        &self,
        el: &FlowEntry<TcpFlowEntryState>,
        tcp: &impl TcpRef<V>,
        dir: &TcpDirection,
        pkt_len: u64,
    ) -> result::Result<TcpState, TcpNewFlowNeeded> {
        let tcp_flow = el.state();
        let mut tfes = tcp_flow.inner.lock();
        match dir {
            TcpDirection::In { ufid_in, .. } => {
                tfes.segs_in += 1;
                tfes.bytes_in += pkt_len;

                // We need to store the UFID of the inbound packet
                // before it was processed so that we can retire the
                // correct UFT/LFT entries upon connection
                // termination.
                tfes.inbound_ufid = Some(**ufid_in);
            }
            TcpDirection::Out { .. } => {
                tfes.segs_out += 1;
                tfes.bytes_out += pkt_len;
            }
        }

        let tcp_state = &mut tfes.tcp_state;

        // `mark_dead` will lock `tcp_flow.inner` to access the list of
        // parents attached to the flow lifetime. We need to release our lock
        // if we need to make the flow as terminated.
        match tcp_state.process(self.name_cstr(), dir.dir(), el.id(), tcp) {
            Ok(TcpState::Closed) => {
                drop(tfes);
                el.mark_dead();
                Ok(TcpState::Closed)
            }
            Ok(v) => Ok(v),
            Err(TcpFlowStateError::NewFlow { .. }) => {
                drop(tfes);
                el.mark_dead();
                Err(TcpNewFlowNeeded)
            }
            Err(e @ TcpFlowStateError::UnexpectedSegment { state, .. }) => {
                self.tcp_err_probe(
                    dir.dir(),
                    None,
                    dir.local_flow(),
                    e.to_string(),
                );
                Ok(state)
            }
        }
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
pub struct TcpFlowEntryStateInner<Id: FlowId> {
    // This must be the UFID of inbound traffic _as it arrives_ from
    // the network, not after it's processed.
    //
    // The outbound UFID is stored in the outer `FlowEntry`.
    inbound_ufid: Option<Id>,
    tcp_state: TcpFlowState,
    segs_in: u64,
    segs_out: u64,
    bytes_in: u64,
    bytes_out: u64,

    inbound_parents: Vec<Arc<dyn FlowEntryInfo>>,
    outbound_parents: Vec<Arc<dyn FlowEntryInfo>>,
}

pub(super) struct TcpFlowEntryState {
    inner: KMutex<TcpFlowEntryStateInner<InnerFlowId>>,
}

impl TcpFlowEntryState {
    fn new_inbound(
        inbound_ufid: InnerFlowId,
        tcp_state: TcpFlowState,
        bytes_in: u64,
    ) -> Self {
        Self {
            inner: KMutex::new(TcpFlowEntryStateInner {
                inbound_ufid: Some(inbound_ufid),
                tcp_state,
                segs_in: 1,
                segs_out: 0,
                bytes_in,
                bytes_out: 0,

                inbound_parents: vec![],
                outbound_parents: vec![],
            }),
        }
    }

    fn new_outbound(tcp_state: TcpFlowState, bytes_out: u64) -> Self {
        Self {
            inner: KMutex::new(TcpFlowEntryStateInner {
                inbound_ufid: None,
                tcp_state,
                segs_in: 0,
                segs_out: 1,
                bytes_in: 0,
                bytes_out,

                inbound_parents: vec![],
                outbound_parents: vec![],
            }),
        }
    }

    fn tcp_state(&self) -> TcpState {
        let lock = self.inner.lock();
        lock.tcp_state.tcp_state()
    }
}

/// The caller must construct a new TCP flow entry for this packet.
struct TcpNewFlowNeeded;

/// Install all parent-child links between a UFT entry, the LFT entries which
/// underpin it, and the TCP flow state entry if present.
fn associate_lfts_upstack(
    uft: &Arc<FlowEntry<UftEntry<InnerFlowId>>>,
    dir: Direction,
    _table_hold: &mut FlowTable<UftEntry<InnerFlowId>>,
) -> core::result::Result<(), FlowTableAddError> {
    // `_table_hold` exists purely so that we can prove, for `process`, that
    // a UFT read will *never* see a UFT entry in a larval state.
    uft.mark_ready();
    uft.state().ready.store(true, Ordering::Relaxed);

    // The goal here is to provide each LFT hit with three children where
    // possible. These are each UFT entry and, when it exists, the TCP flow
    // entry. What this means in practice is that while either is present, the
    // LFTs should be immune to timer-driven expiry. They are *not* immune to
    // explicit eviction.
    //
    // We don't arrange the UFT as a parent of the TCP flow entry because
    // this would cause the existence of the flow table entry to hold the UFT
    // entry in place even if the flow is mostly idle. This also sets us up for
    // being able to have different eviction policies, table sizes, and timers
    // on the UFT to keep it a small cache without breaking flows.
    //
    // All of the LFT entries, and the TCP entry, have a hold on their state
    // placed by the packet. While this is in place, no thread will attempt
    // to check the eviction score of (and certainly not evict) any of these
    // entries. We remove the holds once the parent/child lists of each are in
    // a consistent state.
    let uft_dyn: Arc<dyn FlowEntryInfo> = Arc::clone(uft) as _;
    for lft in &uft.state().parents {
        lft.push_child(&uft_dyn)?;
    }

    if let Some(tcp) = uft.state().tcp_flow.as_ref().and_then(Weak::upgrade) {
        let tcp_dyn: Arc<dyn FlowEntryInfo> = Arc::clone(&tcp) as _;
        let mut parents = uft.state().parents.clone();
        let mut inner = tcp.state().inner.lock();
        let new_parent_slot = match dir {
            Direction::In => &mut inner.inbound_parents,
            Direction::Out => &mut inner.outbound_parents,
        };

        core::mem::swap(new_parent_slot, &mut parents);
        let old_parents = parents;
        for old_lft in old_parents {
            old_lft.remove_child(&tcp_dyn);
        }
        for new_lft in new_parent_slot {
            new_lft.push_child(&tcp_dyn)?;
        }

        tcp.mark_ready();
    }

    // Now that each LFT has all its parent-child relationships set up,
    // eviction/expiry calculations will correctly function. Mark them
    // as visible.
    for lft in &uft.state().parents {
        lft.mark_ready();
    }

    Ok(())
}

impl core::fmt::Debug for TcpFlowEntryState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock();
        core::fmt::Debug::fmt(&*inner, f)
    }
}

impl<Id: FlowId> Display for TcpFlowEntryStateInner<Id> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.inbound_ufid {
            None => write!(f, "None {}", self.tcp_state),
            Some(ufid) => write!(f, "{ufid} {}", self.tcp_state),
        }
    }
}

impl Display for TcpFlowEntryState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let inner = self.inner.lock();
        Display::fmt(&*inner, f)
    }
}

impl Dump for TcpFlowEntryState {
    type DumpVal = TcpFlowEntryDump;

    fn dump(&self, hits: u64) -> Self::DumpVal {
        let inner = self.inner.lock();
        TcpFlowEntryDump {
            hits,
            inbound_ufid: inner.inbound_ufid,
            tcp_state: TcpFlowStateDump::from(inner.tcp_state),
            segs_in: inner.segs_in,
            segs_out: inner.segs_out,
            bytes_in: inner.bytes_in,
            bytes_out: inner.bytes_out,
        }
    }
}

impl FlowState for TcpFlowEntryState {
    fn parents(&self) -> impl Iterator<Item = Arc<dyn FlowEntryInfo>> {
        let inner = self.inner.lock();
        inner
            .inbound_parents
            .clone()
            .into_iter()
            .chain(inner.outbound_parents.clone())
    }
}

/// Expiry behaviour for TCP flows dependent on the connection FSM.
#[derive(Debug)]
pub struct TcpExpiry {
    incipient_ttl: Ttl,
    quiescent_ttl: Ttl,
    keepalive_ttl: Ttl,
}

impl Default for TcpExpiry {
    fn default() -> Self {
        Self {
            incipient_ttl: INCIPIENT_EXPIRE_TTL,
            quiescent_ttl: TIME_WAIT_EXPIRE_TTL,
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
            TcpState::TimeWait
            | TcpState::CloseWait
            | TcpState::FinWait1
            | TcpState::FinWait2 => self.quiescent_ttl,
            TcpState::SynSent
            | TcpState::SynRcvd
            | TcpState::Listen
            | TcpState::LastAck => self.incipient_ttl,
            TcpState::Established => self.keepalive_ttl,
            TcpState::Closed => Ttl::new_seconds(0),
        };
        ttl.is_expired(entry.last_hit(), now)
    }

    fn eviction_priority(
        &self,
        entry: &FlowEntry<TcpFlowEntryState>,
        now: Moment,
    ) -> Option<EvictionPriority> {
        const MIDPOINT_TO_EXPIRY: u64 = 2;
        let incipient_midpoint =
            self.incipient_ttl.as_milliseconds() / MIDPOINT_TO_EXPIRY;

        // We divide evictable non-closed flows into two priority spaces here:
        //
        // * Established flows are evictable at the minimum priority after a
        //   certain age.
        // * Incipient/quiescent flows scale along
        //   MISBEHAVED_MIN..MISBEHAVED_MAX according to how long they have been
        //   in a misbehaved state (up to their expiry time).
        //
        // This ensures that we will evict misbehaved flows in non-established
        // states before well-behaved but inactive flows.
        const MISBEHAVED_MIN: NonZeroU16 = NonZeroU16::MIN.saturating_add(1);
        const MISBEHAVED_MAX: NonZeroU16 =
            NonZeroU16::new(NonZeroU16::MAX.get() - 1).unwrap();

        let delta = now.delta_as_millis(entry.last_hit());
        match entry.state().tcp_state() {
            TcpState::TimeWait
            | TcpState::CloseWait
            | TcpState::FinWait1
            | TcpState::FinWait2 => match delta {
                // We can remain in a closing state for quite some time. We need
                // to be willing to evict such entries from this cache fairly
                // quickly, but leave them in place for the ~120s when we are
                // not under pressure.
                a if a > self.incipient_ttl.as_milliseconds() => {
                    Some(EvictionPriority::Evictable(
                        util::priority_lerp(
                            self.incipient_ttl.as_milliseconds(),
                            MISBEHAVED_MIN,
                            self.quiescent_ttl.as_milliseconds(),
                            MISBEHAVED_MAX,
                            delta,
                        )
                        .expect("start < end"),
                    ))
                }
                _ => Some(EvictionPriority::Protected),
            },
            TcpState::SynSent
            | TcpState::SynRcvd
            | TcpState::Listen
            | TcpState::LastAck => match delta {
                // Ordinarily we will expire flows in these states quickly. If
                // we are under table pressure, we can allow them to be
                // explicitly selected for removal faster.
                a if a > incipient_midpoint => {
                    Some(EvictionPriority::Evictable(
                        util::priority_lerp(
                            incipient_midpoint,
                            MISBEHAVED_MIN,
                            self.incipient_ttl.as_milliseconds(),
                            MISBEHAVED_MAX,
                            delta,
                        )
                        .expect("start < end"),
                    ))
                }
                _ => Some(EvictionPriority::Protected),
            },
            // Allow established flows to be evicted on the same time scale as
            // UFT/LFT expiry, but if we are not under pressure then we aim to
            // keep the LFTs in place even while the flow is inactive.
            TcpState::Established
                if delta >= FLOW_DEF_TTL.as_milliseconds() =>
            {
                Some(EvictionPriority::Evictable(NonZeroU16::MIN))
            }
            TcpState::Established => Some(EvictionPriority::Protected),
            TcpState::Closed => {
                Some(EvictionPriority::Evictable(NonZeroU16::MAX))
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::PortInfo;
    use crate::engine::packet::AddrPair;
    use c8str::C8String;
    use core::time::Duration;
    use ingot::tcp::TcpFlags;

    #[test]
    fn opening_tcp_eviction_prio_increases_over_time() {
        let flowid = InnerFlowId {
            proto: ingot::ip::IpProtocol::TCP.0,
            addrs: AddrPair::V4 {
                src: "192.168.2.10".parse().unwrap(),
                dst: "76.76.21.21".parse().unwrap(),
            },
            proto_info: PortInfo { src_port: 37890, dst_port: 443 }.into(),
        };

        let dummy_tcp_hdr =
            ingot::tcp::Tcp { flags: TcpFlags::SYN, ..Default::default() };

        let mut state = TcpFlowState::new();
        state
            .process::<&[u8]>(
                c"myport",
                Direction::Out,
                &flowid,
                &dummy_tcp_hdr,
            )
            .unwrap();
        let tcp_state = TcpFlowEntryState::new_outbound(state, 52);

        let policy = Arc::<TcpExpiry>::default();
        let mut ft = FlowTable::new(
            Arc::from(
                C8String::from_string("myport").unwrap().into_boxed_c8_str(),
            ),
            "tcp",
            16.try_into().unwrap(),
            Some(policy.clone()),
        );

        let fe = ft.add(flowid, tcp_state).unwrap();
        let t0 = fe.last_hit();
        let t_bad = INCIPIENT_EXPIRE_TTL.as_milliseconds() / 2;
        let t_fullbad = INCIPIENT_EXPIRE_TTL.as_milliseconds();

        let mut prio = policy.eviction_priority(&fe, t0);
        assert_eq!(prio, Some(EvictionPriority::Protected));

        for ms_inc in (0..=10_000).step_by(50) {
            let t_curr = t0 + Duration::from_millis(ms_inc);
            let new_prio = policy.eviction_priority(&fe, t_curr);

            if ms_inc <= t_bad || ms_inc > t_fullbad {
                assert_eq!(new_prio, prio);
            } else {
                assert!(new_prio > prio);
            }

            prio = new_prio;
        }
    }

    #[test]
    fn established_tcp_eviction_prio_unchanging() {
        let flowid = InnerFlowId {
            proto: ingot::ip::IpProtocol::TCP.0,
            addrs: AddrPair::V4 {
                src: "192.168.2.10".parse().unwrap(),
                dst: "76.76.21.21".parse().unwrap(),
            },
            proto_info: PortInfo { src_port: 37890, dst_port: 443 }.into(),
        };

        let dummy_tcp_hdr =
            ingot::tcp::Tcp { flags: TcpFlags::SYN, ..Default::default() };
        let dummy_reply_tcp_hdr = ingot::tcp::Tcp {
            flags: TcpFlags::SYN | TcpFlags::ACK,
            ..Default::default()
        };

        let mut state = TcpFlowState::new();
        state
            .process::<&[u8]>(
                c"myport",
                Direction::Out,
                &flowid,
                &dummy_tcp_hdr,
            )
            .unwrap();
        state
            .process::<&[u8]>(
                c"myport",
                Direction::In,
                &flowid.mirror(),
                &dummy_reply_tcp_hdr,
            )
            .unwrap();
        let tcp_state = TcpFlowEntryState::new_outbound(state, 52);

        let policy = Arc::<TcpExpiry>::default();
        let mut ft = FlowTable::new(
            Arc::from(
                C8String::from_string("myport").unwrap().into_boxed_c8_str(),
            ),
            "tcp",
            16.try_into().unwrap(),
            Some(policy.clone()),
        );

        let fe = ft.add(flowid, tcp_state).unwrap();
        let t0 = fe.last_hit();

        for ms_inc in (0..=1_000_000).step_by(1_000) {
            let t_curr = t0 + Duration::from_millis(ms_inc);

            let expt = if ms_inc < FLOW_DEF_TTL.as_milliseconds() {
                Some(EvictionPriority::Protected)
            } else {
                Some(EvictionPriority::Evictable(NonZeroU16::MIN))
            };
            assert_eq!(policy.eviction_priority(&fe, t_curr), expt);
        }
    }
}

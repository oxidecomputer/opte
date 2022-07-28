// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

/// A virtual switch port.
use core::fmt::{self, Display};
use core::num::NonZeroU32;
use core::result;
use core::sync::atomic::{AtomicU64, Ordering::SeqCst};

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::{String, ToString};
        use alloc::sync::Arc;
        use alloc::vec::Vec;
        use super::rule::flow_id_sdt_arg;
        use illumos_ddi_dki::uintptr_t;
    } else {
        use std::string::{String, ToString};
        use std::sync::Arc;
        use std::vec::Vec;
    }
}

use super::ether::EtherAddr;
use super::flow_table::{FlowTable, StateSummary};
use super::ioctl;
use super::layer::{
    InnerFlowId, Layer, LayerError, LayerResult, RuleId, FLOW_ID_DEFAULT,
};
use super::packet::{Initialized, Packet, PacketMeta, PacketState, Parsed};
use super::rule::{ht_probe, Action, Finalized, Rule, HT};
use super::sync::{KMutex, KMutexType};
use super::tcp::TcpState;
use super::tcp_state::TcpFlowState;
use super::time::Moment;
use crate::api::{Direction, OpteError};
use crate::{CString, ExecCtx};

pub type Result<T> = result::Result<T, OpteError>;

#[derive(Debug)]
pub enum ProcessError {
    BadState(PortState),
    Layer(LayerError),
    WriteError(super::packet::WriteError),
}

impl From<super::packet::WriteError> for ProcessError {
    fn from(e: super::packet::WriteError) -> Self {
        Self::WriteError(e)
    }
}

/// The result of processing a packet.
///
/// * Bypass: Let this packet bypass the system; do not process it at
/// all. XXX This is probably going away as its only use is for
/// punting on traffic I didn't want to deal with yet.
///
/// * Drop: The packet has beend dropped, as determined by the rules
/// or because of resource exhaustion. Included is the reason for the
/// drop.
///
/// * Modified: The packet has been modified based on its matching rules.
///
/// * Hairpin: One of the layers has determined that it should reply
/// directly with a packet of its own. In this case the original
/// packet is dropped.
#[derive(Debug)]
pub enum ProcessResult {
    Bypass,
    Drop { reason: DropReason },
    Modified,
    Hairpin(Packet<Initialized>),
}

/// The reason for a packet being dropped.
#[derive(Clone, Debug)]
pub enum DropReason {
    Layer { name: String },
    TcpClosed,
    TcpErr,
}

pub struct PortBuilder {
    ectx: Arc<ExecCtx>,
    name: String,
    // Cache the CString version of the name for use with DTrace
    // probes.
    name_cstr: CString,
    mac: EtherAddr,
    layers: KMutex<Vec<Layer>>,
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
        for layer in &*self.layers.lock() {
            if layer.name() == layer_name {
                layer.add_rule(dir, rule);
                return Ok(());
            }
        }

        Err(OpteError::LayerNotFound(layer_name.to_string()))
    }

    pub fn create(self, uft_limit: NonZeroU32, tcp_limit: NonZeroU32) -> Port {
        Port {
            name: self.name.clone(),
            name_cstr: self.name_cstr,
            mac: self.mac,
            ectx: self.ectx,
            state: KMutex::new(PortState::Ready, KMutexType::Driver),
            epoch: AtomicU64::new(1),
            // At this point the layer pipeline is immutable, thus we
            // move the layers out of the mutex.
            layers: self.layers.into_inner(),
            uft_in: KMutex::new(
                FlowTable::new(&self.name, "uft_in", uft_limit, None),
                KMutexType::Driver,
            ),
            uft_out: KMutex::new(
                FlowTable::new(&self.name, "uft_out", uft_limit, None),
                KMutexType::Driver,
            ),
            tcp_flows: KMutex::new(
                FlowTable::new(&self.name, "tcp_flows", tcp_limit, None),
                KMutexType::Driver,
            ),
        }
    }

    /// Return a clone of the [`Action`] defined in the given
    /// [`Layer`] at the given index. If the layer does not exist, or
    /// has no action at that index, then `None` is returned.
    pub fn layer_action(&self, layer: &str, idx: usize) -> Option<Action> {
        for l in &*self.layers.lock() {
            if l.name() == layer {
                return l.action(idx).cloned();
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
        mac: EtherAddr,
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
/// ```
/// PortBuilder::create() -> Ready
/// PortBuilder::restore() -> Restored
///
/// Ready -- mc_start() --> Running
///
/// Restored -- mc_start() --> Running
///
/// Running -- pause --> Paused
/// Running -- mc_stop() --> Ready
///
/// Paused -- unpause --> Running
/// Paused -- mc_stop() --> Ready
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortState {
    /// The port is configured with layers and rules, but has no flow
    /// state. It is ready to enter the [`Running`] state to start
    /// handling traffic.
    ///
    /// This state may be entered from:
    ///
    /// * [`PortBuilder::create()`]
    /// * [`Self::Running`]: The transition wipes the flow state.
    /// * [`Self::Stopped`]: The transition wipes the flow state.
    Ready,

    /// The port is running and packets are free to travel across the
    /// port. Rules may be added or removed while running.
    ///
    /// This state may be entered from:
    ///
    /// * [`Self::Ready`]
    /// * [`Self::Stopped`]
    /// * [`Self::Restored`]
    Running,

    /// The port is paused. The layers and rules are intact as well as
    /// the flow state. However, any inbound or outbound packets are
    /// dropped.
    ///
    /// XXX This state isn't used yet; and I don't actually quite yet
    /// know how we want to do this. E.g., perhaps pause/resume should
    /// really be a mac abstraction with defined callbacks?
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
    /// * [`PortBuilder::restore()`]
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

#[derive(Clone, Debug)]
pub enum DumpLayerError {
    LayerNotFound,
}

#[derive(Clone, Debug)]
pub struct HtEntry {
    hts: Vec<HT>,
    // The port epoch upon which this entry was established. Used for
    // invalidation when the rule set is updated.
    epoch: u64,
}

impl StateSummary for HtEntry {
    fn summary(&self) -> String {
        self.hts
            .iter()
            .map(|ht| ht.to_string())
            .collect::<Vec<String>>()
            .join(",")
    }
}

pub struct Port {
    state: KMutex<PortState>,
    epoch: AtomicU64,
    ectx: Arc<ExecCtx>,
    name: String,
    // Cache the CString version of the name for use with DTrace
    // probes.
    name_cstr: CString,
    mac: EtherAddr,
    layers: Vec<Layer>,
    uft_in: KMutex<FlowTable<HtEntry>>,
    uft_out: KMutex<FlowTable<HtEntry>>,
    // We keep a record of the inbound UFID in the TCP flow table so
    // that we know which inbound UFT/FT entries to retire upon
    // connection termination.
    tcp_flows: KMutex<FlowTable<TcpFlowEntryState>>,
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
        if $( *$sg != $state )&&* {
            Err(OpteError::BadState)
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

impl Port {
    /// Place the port in the [`PortState::Running`] state.
    ///
    /// After completion the port can receive packets for processing.
    ///
    /// # States
    ///
    /// This command is valid for all states. If the port is already
    /// in the running state, this is a no op.
    pub fn start(&self) {
        let mut state = self.state.lock();
        *state = PortState::Running;
    }

    /// Reset the port.
    ///
    /// A reset wipes all accumulated Layer and Unified flow state
    /// tracking as well as TCP state tracking. But it leaves the
    /// configuration, i.e. the layers and rules, as they are.
    pub fn reset(&self) {
        // It's imperative to hold the lock for the entire function so
        // that its side effects are atomic from the point of view of
        // other threads.
        let mut state = self.state.lock();
        *state = PortState::Ready;

        // Clear all dynamic state related to the creation of flows.
        for layer in &*self.layers {
            layer.clear_flows();
        }

        self.clear_uft();
        self.tcp_flows.lock().clear();
    }

    /// Get the current [`PortState`].
    pub fn state(&self) -> PortState {
        *self.state.lock()
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
    /// * [`PortState::Paused`]
    /// * [`PortState::Ready`]
    /// * [`PortState::Running`]
    pub fn add_rule(
        &self,
        layer_name: &str,
        dir: Direction,
        rule: Rule<Finalized>,
    ) -> Result<()> {
        let state = self.state.lock();
        check_state!(
            state,
            [PortState::Ready, PortState::Running, PortState::Paused]
        )?;

        for layer in &*self.layers {
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
        dir: Direction,
        msg: String,
        pkt: &mut Packet<Parsed>,
        ifid: &InnerFlowId,
    ) {
        if unsafe { super::opte_panic_debug != 0 } {
            super::err(format!("mblk: {}", pkt.mblk_ptr_str()));
            super::err(format!("ifid: {}", ifid));
            super::err(format!("meta: {:?}", pkt.meta()));
            super::err(format!("flows: {:?}", *self.tcp_flows.lock(),));
            todo!("bad packet: {}", msg);
        } else {
            self.tcp_err_probe(dir, ifid, pkt, msg)
        }
    }

    fn tcp_err_probe(
        &self,
        dir: Direction,
        ifid: &InnerFlowId,
        pkt: &Packet<Parsed>,
        msg: String,
    ) {
        cfg_if::cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                let ifid_arg = flow_id_sdt_arg::from(ifid);
                let msg_arg = CString::new(msg).unwrap();

                unsafe {
                    __dtrace_probe_tcp__err(
                        dir.cstr_raw() as uintptr_t,
                        self.name_cstr.as_ptr() as uintptr_t,
                        &ifid_arg as *const flow_id_sdt_arg as uintptr_t,
                        pkt.mblk_addr(),
                        msg_arg.as_ptr() as uintptr_t,
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                let ifid_s = ifid.to_string();
                crate::opte_provider::tcp__err!(
                    || (dir, &self.name, ifid_s, pkt.mblk_addr(), &msg)
                );
            } else {
                let (_, _, _, _) = (dir, ifid, pkt, msg);
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
        for l in &*self.layers {
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
        let state = self.state.lock();
        check_state!(
            state,
            [PortState::Running, PortState::Paused, PortState::Restored]
        )?;

        Ok(ioctl::DumpTcpFlowsResp { flows: self.tcp_flows.lock().dump() })
    }

    /// Clear all entries from the Unified Flow Table (UFT).
    ///
    /// # States
    ///
    /// This command is valid for all states. In the case of
    /// [`PortState::Ready`], there cannot possibly be any UFT entries
    /// to clear; however, it causes no harm to allow calling this
    /// function in said state in order to make the ergonomics better.
    pub fn clear_uft(&self) {
        self.uft_in.lock().clear();
        self.uft_out.lock().clear();
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
        let state = self.state.lock();

        check_state!(
            state,
            [PortState::Running, PortState::Paused, PortState::Restored],
        )?;

        let in_lock = self.uft_in.lock();
        let uft_in_limit = in_lock.get_limit().get();
        let uft_in_num_flows = in_lock.num_flows();
        let uft_in = in_lock.dump();
        drop(in_lock);

        let out_lock = self.uft_out.lock();
        let uft_out_limit = out_lock.get_limit().get();
        let uft_out_num_flows = out_lock.num_flows();
        let uft_out = out_lock.dump();
        drop(out_lock);

        Ok(ioctl::DumpUftResp {
            uft_in_limit,
            uft_in_num_flows,
            uft_in,
            uft_out_limit,
            uft_out_num_flows,
            uft_out,
        })
    }

    /// Expire all flows whose TTL is overdue as of `now`.
    ///
    /// # States
    ///
    /// This command is valid for all states. In the case of
    /// [`PortState::Ready`], there cannot possibly be any flows to
    /// expire; however, it causes no harm to allow calling this
    /// function in said state in order to make the ergonomics better.
    pub fn expire_flows(&self, now: Moment) {
        for l in &self.layers {
            l.expire_flows(now);
        }
        let _ =
            self.uft_in.lock().expire_flows(now, |_| FLOW_ID_DEFAULT.clone());
        let _ =
            self.uft_out.lock().expire_flows(now, |_| FLOW_ID_DEFAULT.clone());
    }

    /// Return a reference to the [`Action`] defined in the given
    /// [`Layer`] at the given index. If the layer does not exist, or
    /// has no action at that index, then `None` is returned.
    ///
    /// # States
    ///
    /// This command is valid for any [`PortState`].
    pub fn layer_action(&self, layer: &str, idx: usize) -> Option<&Action> {
        for l in &*self.layers {
            if l.name() == layer {
                return l.action(idx);
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
        let mut tmp = vec![];

        for layer in &*self.layers {
            tmp.push(ioctl::LayerDesc {
                name: layer.name().to_string(),
                rules_in: layer.num_rules(Direction::In),
                rules_out: layer.num_rules(Direction::Out),
                flows: layer.num_flows(),
            });
        }

        ioctl::ListLayersResp { layers: tmp }
    }

    /// Return the MAC address of this port.
    pub fn mac_addr(&self) -> EtherAddr {
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
    pub fn process(
        &self,
        dir: Direction,
        pkt: &mut Packet<Parsed>,
        lmeta: &mut meta::Meta,
        rsrcs: &resources::Resources,
    ) -> result::Result<ProcessResult, ProcessError> {
        // XXX Yes, we are holding this mutex on all admin calls as
        // well. This means admin and datapath block each other --
        // this is not great. Given that we only have the `mc_start()`
        // and `mc_stop()` transitions to worry about, we drop the lock
        // directly after checking the state, as we know there is no
        // chance for a state transition unless the client is closing
        // its handle to us. However, this brings up a much larger
        // area of concern that needs to be figured out: and that is
        // how to perform serialization/synchronization between admin
        // commands and datapath. E.g., mac deals with these concerns
        // via the "mac perimeter" along with per-CPU reference
        // counting and flags. Given that OPTE is currently meant to
        // only run as part of a mac provider, it is already taking
        // advantage of some of this synchronization implicitly.
        // However, the admin ioctls (via DLD) are currently not
        // holding the mac perimeter, and thus present an area for
        // problems. Furthermore, how do we want to do pause/resume,
        // save/restore? Should these be first class operations in the
        // mac framework? If not, are there other mac APIs we need to
        // properly support pause/resume in OPTE while still playing
        // nicely with mac?
        let state = self.state.lock();
        check_state!(state, [PortState::Running])
            .map_err(|_| ProcessError::BadState(*state))?;
        drop(state);

        let ifid = InnerFlowId::from(pkt.meta());
        let epoch = self.epoch.load(SeqCst);
        self.port_process_entry_probe(dir, &ifid, epoch, &pkt);
        let res = match dir {
            Direction::Out => self.process_out(&ifid, epoch, pkt, lmeta, rsrcs),
            Direction::In => self.process_in(&ifid, epoch, pkt, lmeta, rsrcs),
        };
        self.port_process_return_probe(dir, &ifid, epoch, &pkt, &res);
        // XXX If this is a Hairpin result there is no need for this call.
        pkt.emit_headers()?;
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
    /// * [`PortState::Paused`]
    /// * [`PortState::Ready`]
    /// * [`PortState::Running`]
    pub fn remove_rule(
        &self,
        layer_name: &str,
        dir: Direction,
        id: RuleId,
    ) -> Result<()> {
        let state = self.state.lock();
        check_state!(
            state,
            [PortState::Paused, PortState::Ready, PortState::Running]
        )?;

        for layer in &self.layers {
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
    /// * [`PortState::Paused`]
    /// * [`PortState::Ready`]
    /// * [`PortState::Running`]
    pub fn set_rules(
        &self,
        layer_name: &str,
        in_rules: Vec<Rule<Finalized>>,
        out_rules: Vec<Rule<Finalized>>,
    ) -> Result<()> {
        let state = self.state.lock();
        check_state!(
            state,
            [PortState::Paused, PortState::Ready, PortState::Running]
        )?;

        for layer in &self.layers {
            if layer.name() == layer_name {
                self.epoch.fetch_add(1, SeqCst);
                layer.set_rules(in_rules, out_rules);
                return Ok(());
            }
        }

        Err(OpteError::LayerNotFound(layer_name.to_string()))
    }
}

enum TcpMaybeClosed {
    Closed { ufid_inbound: Option<InnerFlowId> },
    NewState(TcpState),
}

// Keeping the private functions here just for the sake of code
// organization.
impl Port {
    // Process the packet against each layer in turn. If `Allow` is
    // returned, then `meta` contains the updated metadata, and `hts`
    // contains the list of HTs run against the metadata.
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
        dir: Direction,
        ifid: &InnerFlowId,
        pkt: &mut Packet<Parsed>,
        hts: &mut Vec<HT>,
        lmeta: &mut meta::Meta,
        rsrcs: &resources::Resources,
    ) -> result::Result<LayerResult, LayerError> {
        match dir {
            Direction::Out => {
                for layer in &self.layers {
                    let res = layer
                        .process(&self.ectx, dir, ifid, pkt, hts, lmeta, rsrcs);

                    match res {
                        Ok(LayerResult::Allow) => (),
                        ret @ Ok(LayerResult::Deny { .. }) => return ret,
                        ret @ Ok(LayerResult::Hairpin(_)) => return ret,
                        ret @ Err(_) => return ret,
                    }
                }
            }

            Direction::In => {
                for layer in self.layers.iter().rev() {
                    let res = layer
                        .process(&self.ectx, dir, ifid, pkt, hts, lmeta, rsrcs);

                    match res {
                        Ok(LayerResult::Allow) => (),
                        ret @ Ok(LayerResult::Deny { .. }) => return ret,
                        ret @ Ok(LayerResult::Hairpin(_)) => return ret,
                        ret @ Err(_) => return ret,
                    }
                }
            }
        }

        return Ok(LayerResult::Allow);
    }

    fn port_process_entry_probe(
        &self,
        dir: Direction,
        ifid: &InnerFlowId,
        epoch: u64,
        pkt: &Packet<impl PacketState>,
    ) {
        cfg_if::cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                let ifid_arg = flow_id_sdt_arg::from(ifid);

                unsafe {
                    __dtrace_probe_port__process__entry(
                        dir.cstr_raw() as uintptr_t,
                        self.name_cstr.as_ptr() as uintptr_t,
                        &ifid_arg as *const flow_id_sdt_arg as uintptr_t,
                        epoch as uintptr_t,
                        pkt.mblk_addr(),
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                let ifid_s = ifid.to_string();
                crate::opte_provider::port__process__entry!(
                    || (dir, &self.name, ifid_s, epoch, pkt.mblk_addr())
                );
            } else {
                let (_, _, _, _) = (dir, ifid, epoch, pkt);
            }
        }
    }

    fn port_process_return_probe(
        &self,
        dir: Direction,
        ifid: &InnerFlowId,
        epoch: u64,
        pkt: &Packet<impl PacketState>,
        res: &result::Result<ProcessResult, ProcessError>,
    ) {
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                let ifid_arg = flow_id_sdt_arg::from(ifid);
                // XXX This would probably be better as separate probes;
                // for now this does the trick.
                let res_str = match res {
                    Ok(v) => format!("{:?}", v),
                    Err(e) => format!("ERROR: {:?}", e),
                };
                let res_arg = cstr_core::CString::new(res_str).unwrap();
                let hp_pkt_ptr = match res {
                    Ok(ProcessResult::Hairpin(hp)) => {
                        hp.mblk_addr()
                    }
                    _ => 0,
                };

                unsafe {
                    __dtrace_probe_port__process__return(
                        dir.cstr_raw() as uintptr_t,
                        self.name_cstr.as_ptr() as uintptr_t,
                        &ifid_arg as *const flow_id_sdt_arg as uintptr_t,
                        epoch as uintptr_t,
                        pkt.mblk_addr(),
                        hp_pkt_ptr,
                        res_arg.as_ptr() as uintptr_t,
                    );
                }

            } else if #[cfg(feature = "usdt")] {
                let ifid_s = ifid.to_string();
                let res_str = match res {
                    Ok(v) => format!("{:?}", v),
                    Err(e) => format!("ERROR: {:?}", e),
                };

                crate::opte_provider::port__process__return!(
                    || (dir, &self.name, ifid_s, epoch, pkt.mblk_addr(), res_str)
                );
            } else {
                let (_, _, _, _, _) = (dir, ifid, epoch, pkt, res);
            }
        }
    }

    // Process the TCP packet for the purposes of connection tracking
    // when an inbound UFT entry exists.
    fn process_in_tcp_existing(
        &self,
        pmeta: &PacketMeta,
    ) -> result::Result<TcpState, String> {
        use Direction::In;

        // All TCP flows are keyed with respect to the outbound Flow
        // ID, therefore we mirror the flow. This value must represent
        // the guest-sdie of the flow and thus come from the passed-in
        // packet metadata that represents the post-processed packet.
        let ufid_out = InnerFlowId::from(pmeta).mirror();

        // Unwrap: We know this is a TCP packet at this point.
        //
        // XXX This will be even more foolproof in the future when
        // we've implemented the notion of FlowSet and Packet is
        // generic on header group/flow type.
        let tcp = pmeta.inner_tcp().unwrap();
        let mut lock = self.tcp_flows.lock();

        match lock.get_mut(&ufid_out) {
            Some(entry) => {
                let tfes = entry.state_mut();

                match tfes.tcp_state.process(In, &ufid_out, tcp) {
                    Ok(tcp_state) => {
                        if tcp_state == TcpState::Closed {
                            let entry = lock.remove(&ufid_out).unwrap();
                            drop(lock);
                            let ufid_in = entry.state().inbound_ufid.as_ref();
                            self.uft_tcp_closed(&ufid_out, ufid_in);
                        }

                        Ok(tcp_state)
                    }

                    Err(e) => Err(e),
                }
            }

            None => Err(format!("TCP flow missing: {}", ufid_out)),
        }
    }

    // Process the TCP packet for the purposes of connection tracking
    // when an inbound UFT entry was just created.
    fn process_in_tcp_new(
        &self,
        ufid_in: &InnerFlowId,
        pmeta: &PacketMeta,
    ) -> result::Result<TcpState, String> {
        use Direction::In;

        // All TCP flows are keyed with respect to the outbound Flow
        // ID, therefore we mirror the flow. This value must represent
        // the guest-sdie of the flow and thus come from the passed-in
        // packet metadata that represents the post-processed packet.
        let ufid_out = InnerFlowId::from(pmeta).mirror();

        // Unwrap: We know this is a TCP packet at this point.
        //
        // XXX This will be even more foolproof in the future when
        // we've implemented the notion of FlowSet and Packet is
        // generic on header group/flow type.
        let tcp = pmeta.inner_tcp().unwrap();
        let mut lock = self.tcp_flows.lock();

        match lock.get_mut(&ufid_out) {
            Some(entry) => {
                let tfes = entry.state_mut();

                let res = match tfes.tcp_state.process(In, &ufid_out, &tcp) {
                    Ok(tcp_state) => {
                        if tcp_state == TcpState::Closed {
                            let entry = lock.remove(&ufid_out).unwrap();
                            drop(lock);
                            // The inbound side of the UFT is based on
                            // the network-side of the flow (pre-processing).
                            let ufid_in = entry.state().inbound_ufid.as_ref();
                            self.uft_tcp_closed(&ufid_out, ufid_in);
                            return Ok(tcp_state);
                        }

                        Ok(tcp_state)
                    }

                    Err(e) => Err(e),
                };

                // We need to store the UFID of the inbound packet
                // before it was processed so that we can retire the
                // correct UFT/LFT entries upon connection
                // termination.
                tfes.inbound_ufid = Some(ufid_in.clone());
                res
            }

            None => {
                let mut tfs = TcpFlowState::new(self.name_cstr.clone());
                let res = tfs.process(Direction::In, &ufid_out, &tcp);

                let tcp_state = match res {
                    Ok(TcpState::Closed) => return Ok(TcpState::Closed),
                    Ok(tcp_state) => tcp_state,
                    Err(e) => return Err(e),
                };

                let tfes = TcpFlowEntryState {
                    // This must be the UFID of inbound traffic _as it
                    // arrives_, not after it's processed.
                    inbound_ufid: Some(ufid_in.clone()),
                    tcp_state: tfs,
                };

                // TODO kill unwrap
                lock.add(ufid_out.clone(), tfes).unwrap();
                Ok(tcp_state)
            }
        }
    }

    fn process_in_miss(
        &self,
        ufid_in: &InnerFlowId,
        epoch: u64,
        pkt: &mut Packet<Parsed>,
        lmeta: &mut meta::Meta,
        rsrcs: &resources::Resources,
    ) -> result::Result<ProcessResult, ProcessError> {
        use Direction::In;

        let mut hts = Vec::new();
        let res = self.layers_process(In, ufid_in, pkt, &mut hts, lmeta, rsrcs);
        match res {
            Ok(LayerResult::Allow) => {
                // If there is no flow ID, then do not create a UFT
                // entry.
                if *ufid_in == FLOW_ID_DEFAULT {
                    return Ok(ProcessResult::Modified);
                }
            }

            Ok(LayerResult::Deny { name }) => {
                return Ok(ProcessResult::Drop {
                    reason: DropReason::Layer { name },
                })
            }

            Ok(LayerResult::Hairpin(hppkt)) => {
                return Ok(ProcessResult::Hairpin(hppkt))
            }

            Err(e) => return Err(ProcessError::Layer(e)),
        }

        let hte = HtEntry { hts, epoch };

        // For inbound traffic the TCP flow table must be
        // checked _after_ processing take place.
        if pkt.meta().is_inner_tcp() {
            match self.process_in_tcp_new(ufid_in, pkt.meta()) {
                Ok(TcpState::Closed) => {
                    return Ok(ProcessResult::Modified);
                }

                Ok(_) => {
                    // We have a good TCP flow, create a new UFT entry.
                    //
                    // TODO kill unwrap
                    self.uft_in.lock().add(ufid_in.clone(), hte).unwrap();
                    return Ok(ProcessResult::Modified);
                }

                Err(e) => {
                    self.tcp_err(In, e, pkt, ufid_in);
                    return Ok(ProcessResult::Drop {
                        reason: DropReason::TcpErr,
                    });
                }
            }
        } else {
            // TODO kill unwrap
            self.uft_in.lock().add(ufid_in.clone(), hte).unwrap();
        }

        Ok(ProcessResult::Modified)
    }

    fn process_in(
        &self,
        ufid_in: &InnerFlowId,
        epoch: u64,
        pkt: &mut Packet<Parsed>,
        lmeta: &mut meta::Meta,
        rsrcs: &resources::Resources,
    ) -> result::Result<ProcessResult, ProcessError> {
        use Direction::In;

        // Use the compiled UFT entry if one exists. Otherwise
        // fallback to layer processing.
        let mut lock = self.uft_in.lock();
        match lock.get_mut(ufid_in) {
            Some(entry) if entry.state().epoch == epoch => {
                // TODO At the moment I'm holding the UFT locks not
                // just for lookup, but for the entire duration of
                // processing. It might be better to ht.clone() or
                // Arc<HT>; that way we only hold the lock for lookup.
                entry.hit();
                for ht in &entry.state().hts {
                    ht.run(pkt.meta_mut());
                    // Guest-side flow id.
                    let gfid_in = InnerFlowId::from(pkt.meta());
                    ht_probe(&self.name_cstr, "UFT-in", In, ufid_in, &gfid_in);
                }
                drop(entry);
                drop(lock);

                // For inbound traffic the TCP flow table must be
                // checked _after_ processing take place.
                if pkt.meta().is_inner_tcp() {
                    match self.process_in_tcp_existing(pkt.meta()) {
                        Ok(_) => return Ok(ProcessResult::Modified),
                        Err(e) => {
                            self.tcp_err(In, e, pkt, ufid_in);
                            return Ok(ProcessResult::Drop {
                                reason: DropReason::TcpErr,
                            });
                        }
                    }
                } else {
                    return Ok(ProcessResult::Modified);
                }
            }

            // The entry is from a previous epoch; mark it for removal
            // and proceed to rule processing.
            Some(entry) => {
                let epoch = entry.state().epoch;
                drop(entry);
                drop(lock);
                let gfid_in = InnerFlowId::from(pkt.meta());
                let ufid_out = gfid_in.mirror();
                self.uft_invalidate(&ufid_out, ufid_in, epoch);
            }

            // There is no entry; proceed to rule processing;
            None => drop(lock),
        };

        self.process_in_miss(ufid_in, epoch, pkt, lmeta, rsrcs)
    }

    // Process the TCP packet for the purposes of connection tracking
    // when an outbound UFT entry exists.
    fn process_out_tcp_existing(
        &self,
        ufid_out: &InnerFlowId,
        pmeta: &PacketMeta,
    ) -> result::Result<TcpMaybeClosed, String> {
        let mut lock = self.tcp_flows.lock();

        match lock.get_mut(ufid_out) {
            Some(entry) => {
                let tfes = entry.state_mut();
                let tcp = pmeta.inner_tcp().unwrap();
                let res = tfes.tcp_state.process(Direction::Out, ufid_out, tcp);

                match res {
                    Ok(tcp_state) => {
                        if tcp_state == TcpState::Closed {
                            let entry = lock.remove(&ufid_out).unwrap();
                            return Ok(TcpMaybeClosed::Closed {
                                ufid_inbound: entry
                                    .state()
                                    .inbound_ufid
                                    .clone(),
                            });
                        }

                        Ok(TcpMaybeClosed::NewState(tcp_state))
                    }

                    // TODO SDT probe for rejected packet.
                    Err(e) => Err(e),
                }
            }

            None => Err(format!("TCP flow missing: {}", ufid_out)),
        }
    }

    // Process the TCP packet for the purposes of connection tracking
    // when an outbound UFT entry was just created.
    fn process_out_tcp_new(
        &self,
        ufid_out: &InnerFlowId,
        pmeta: &PacketMeta,
    ) -> result::Result<TcpMaybeClosed, String> {
        let tcp = pmeta.inner_tcp().unwrap();
        let mut lock = self.tcp_flows.lock();

        let tcp_state = match lock.get_mut(ufid_out) {
            // We may have already created a TCP flow entry
            // due to an inbound packet.
            Some(entry) => {
                let tfes = entry.state_mut();
                let res =
                    tfes.tcp_state.process(Direction::Out, &ufid_out, &tcp);

                match res {
                    Ok(tcp_state) => tcp_state,
                    Err(e) => return Err(e),
                }
            }

            None => {
                // Create a new entry and find its current state. In
                // this case it should always be `SynSent` as a flow
                // would have already existed in the `SynRcvd` case.
                let mut tfs = TcpFlowState::new(self.name_cstr.clone());

                let tcp_state =
                    match tfs.process(Direction::Out, &ufid_out, &tcp) {
                        Ok(tcp_state) => tcp_state,
                        Err(e) => return Err(e),
                    };

                // The inbound UFID is determined on the inbound side.
                let tfes =
                    TcpFlowEntryState { inbound_ufid: None, tcp_state: tfs };

                // TODO kill unwrap
                lock.add(ufid_out.clone(), tfes).unwrap();
                tcp_state
            }
        };

        if tcp_state == TcpState::Closed {
            let entry = lock.remove(&ufid_out).unwrap();
            return Ok(TcpMaybeClosed::Closed {
                ufid_inbound: entry.state().inbound_ufid.clone(),
            });
        }

        Ok(TcpMaybeClosed::NewState(tcp_state))
    }

    fn process_out_miss(
        &self,
        ufid_out: &InnerFlowId,
        epoch: u64,
        pkt: &mut Packet<Parsed>,
        lmeta: &mut meta::Meta,
        rsrcs: &resources::Resources,
    ) -> result::Result<ProcessResult, ProcessError> {
        use Direction::Out;

        let mut tcp_closed = false;

        // For outbound traffic the TCP flow table must be checked
        // _before_ processing take place.
        if pkt.meta().is_inner_tcp() {
            match self.process_out_tcp_new(ufid_out, pkt.meta()) {
                Ok(TcpMaybeClosed::Closed { ufid_inbound }) => {
                    tcp_closed = true;
                    self.uft_tcp_closed(ufid_out, ufid_inbound.as_ref());
                }

                // Continue with processing.
                Ok(_) => (),

                Err(e) => {
                    self.tcp_err(Out, e, pkt, ufid_out);
                    return Ok(ProcessResult::Drop {
                        reason: DropReason::TcpErr,
                    });
                }
            }
        }

        let mut hts = Vec::new();
        let res =
            self.layers_process(Out, ufid_out, pkt, &mut hts, lmeta, rsrcs);
        let hte = HtEntry { hts, epoch };

        match res {
            Ok(LayerResult::Allow) => {
                // If there is no Flow ID, then there is no UFT entry.
                if *ufid_out == FLOW_ID_DEFAULT || tcp_closed {
                    return Ok(ProcessResult::Modified);
                }

                // TODO kill unwrap
                self.uft_out.lock().add(ufid_out.clone(), hte).unwrap();
                Ok(ProcessResult::Modified)
            }

            Ok(LayerResult::Hairpin(hppkt)) => {
                Ok(ProcessResult::Hairpin(hppkt))
            }

            Ok(LayerResult::Deny { name }) => {
                Ok(ProcessResult::Drop { reason: DropReason::Layer { name } })
            }

            Err(e) => Err(ProcessError::Layer(e)),
        }
    }

    fn process_out(
        &self,
        ufid_out: &InnerFlowId,
        epoch: u64,
        pkt: &mut Packet<Parsed>,
        lmeta: &mut meta::Meta,
        rsrcs: &resources::Resources,
    ) -> result::Result<ProcessResult, ProcessError> {
        use Direction::Out;

        // Use the compiled UFT entry if one exists. Otherwise
        // fallback to layer processing.
        let mut lock = self.uft_out.lock();
        match lock.get_mut(ufid_out) {
            Some(entry) if entry.state().epoch == epoch => {
                entry.hit();
                let mut invalidated = false;
                let mut ufid_in = None;

                // For outbound traffic the TCP flow table must be
                // checked _before_ processing take place.
                if pkt.meta().is_inner_tcp() {
                    match self.process_out_tcp_existing(ufid_out, pkt.meta()) {
                        Ok(TcpMaybeClosed::Closed { ufid_inbound }) => {
                            invalidated = true;
                            ufid_in = ufid_inbound;
                        }

                        // Continue with processing.
                        Ok(_) => (),

                        Err(e) => {
                            self.tcp_err(Out, e, pkt, ufid_out);
                            return Ok(ProcessResult::Drop {
                                reason: DropReason::TcpErr,
                            });
                        }
                    }
                }

                for ht in &entry.state().hts {
                    ht.run(pkt.meta_mut());
                    // Network-side flow id.
                    let nfid_out = InnerFlowId::from(pkt.meta());
                    ht_probe(
                        &self.name_cstr,
                        "UFT-out",
                        Out,
                        ufid_out,
                        &nfid_out,
                    );
                }

                drop(entry);
                drop(lock);

                if invalidated {
                    self.uft_tcp_closed(ufid_out, ufid_in.as_ref());
                }

                return Ok(ProcessResult::Modified);
            }

            // The entry is from a previous epoch; mark it for removal
            // and proceed to rule processing.
            Some(entry) => {
                let epoch = entry.state().epoch;
                drop(entry);
                drop(lock);
                // Network-side flow id.
                let nfid_out = InnerFlowId::from(pkt.meta());
                let ufid_in = nfid_out.mirror();
                self.uft_invalidate(ufid_out, &ufid_in, epoch);
            }

            // There is no entry; proceed to layer processing.
            None => drop(lock),
        }

        self.process_out_miss(ufid_out, epoch, pkt, lmeta, rsrcs)
    }

    fn uft_invalidate(
        &self,
        ufid_out: &InnerFlowId,
        ufid_in: &InnerFlowId,
        epoch: u64,
    ) {
        let mut uft_in = self.uft_in.lock();
        let mut uft_out = self.uft_out.lock();
        uft_in.remove(ufid_in);
        uft_out.remove(ufid_out);
        drop(uft_out);
        drop(uft_in);
        self.uft_invalidate_probe(Direction::In, ufid_in, epoch);
        self.uft_invalidate_probe(Direction::Out, ufid_out, epoch);
    }

    fn uft_invalidate_probe(
        &self,
        dir: Direction,
        ufid: &InnerFlowId,
        epoch: u64,
    ) {
        cfg_if::cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                let ufid_arg = flow_id_sdt_arg::from(ufid);

                unsafe {
                    __dtrace_probe_uft__invalidate(
                        dir.cstr_raw() as uintptr_t,
                        self.name_cstr.as_ptr() as uintptr_t,
                        &ufid_arg as *const flow_id_sdt_arg as uintptr_t,
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
        ufid_out: &InnerFlowId,
        ufid_in: Option<&InnerFlowId>,
    ) {
        let mut uft_in = self.uft_in.lock();
        let mut uft_out = self.uft_out.lock();
        if ufid_in.is_some() {
            uft_in.remove(&ufid_in.unwrap());
            self.uft_tcp_closed_probe(Direction::In, &ufid_in.unwrap());
        }
        uft_out.remove(ufid_out);
        drop(uft_out);
        drop(uft_in);
        self.uft_tcp_closed_probe(Direction::Out, ufid_out);
    }

    fn uft_tcp_closed_probe(&self, dir: Direction, ufid: &InnerFlowId) {
        cfg_if::cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                let ufid_arg = flow_id_sdt_arg::from(ufid);

                unsafe {
                    __dtrace_probe_uft__tcp__closed(
                        dir.cstr_raw() as uintptr_t,
                        self.name_cstr.as_ptr() as uintptr_t,
                        &ufid_arg as *const flow_id_sdt_arg as uintptr_t,
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                let port_s = self.name_cstr.to_str().unwrap();
                let ufid_s = ufid.to_string();
                crate::opte_provider::uft__tcp__closed!(
                    || (dir, port_s, ifid_s)
                );
            } else {
                let (_, _) = (dir, ufid);
            }
        }
    }
}

// The follow functions are useful for validating state during
// testing. If one of these functions becomes useful outside of
// testing, then add it to the impl block above.
#[cfg(test)]
impl Port {
    /// Get the number of flows currently in the layer and direction
    /// specified. The value `"uft"` can be used to get the number of
    /// UFT flows.
    pub fn num_flows(&self, layer: &str, dir: Direction) -> u32 {
        use Direction::*;

        match (layer, dir) {
            ("uft", In) => self.uft_in.lock().num_flows(),
            ("uft", Out) => self.uft_out.lock().num_flows(),
            (name, _dir) => {
                for layer in &self.layers {
                    if layer.name() == name {
                        return layer.num_flows();
                    }
                }

                panic!("layer not found: {}", name);
            }
        }
    }

    pub fn num_rules(&self, layer: &str, dir: Direction) -> u32 {
        match (layer, dir) {
            (name, dir) => {
                for layer in &self.layers {
                    if layer.name() == name {
                        return layer.num_rules(dir) as u32;
                    }
                }

                panic!("layer not found: {}", name);
            }
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

#[derive(Clone, Debug)]
pub struct TcpFlowEntryState {
    inbound_ufid: Option<InnerFlowId>,
    tcp_state: TcpFlowState,
}

impl StateSummary for TcpFlowEntryState {
    fn summary(&self) -> String {
        match &self.inbound_ufid {
            None => format!("None {}", self.tcp_state),
            Some(ufid) => format!("{} {}", ufid, self.tcp_state),
        }
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
extern "C" {
    pub fn __dtrace_probe_port__process__entry(
        dir: uintptr_t,
        port: uintptr_t,
        ifid: uintptr_t,
        epoch: uintptr_t,
        pkt: uintptr_t,
    );
    pub fn __dtrace_probe_port__process__return(
        dir: uintptr_t,
        port: uintptr_t,
        ifid: uintptr_t,
        epoch: uintptr_t,
        pkt: uintptr_t,
        hp_pkt: uintptr_t,
        res: uintptr_t,
    );
    pub fn __dtrace_probe_tcp__err(
        dir: uintptr_t,
        port: uintptr_t,
        ifid: uintptr_t,
        pkt: uintptr_t,
        msg: uintptr_t,
    );
    pub fn __dtrace_probe_uft__invalidate(
        dir: uintptr_t,
        port: uintptr_t,
        ifid: uintptr_t,
        epoch: uintptr_t,
    );
    pub fn __dtrace_probe_uft__tcp__closed(
        dir: uintptr_t,
        port: uintptr_t,
        ifid: uintptr_t,
    );
}

/// Metadata which may be accessed and modified by any [`Action`][a]
/// as a method of inter-action communication.
///
/// This metadata is a heterogeneous map of values, keyed by their
/// type.
///
/// [a]: crate::rule::Action
pub mod meta {
    #[derive(Debug)]
    pub enum Error {
        AlreadyExists,
    }

    pub struct Meta {
        inner: anymap::Map<dyn anymap::any::Any + Send + Sync>,
    }

    impl Meta {
        pub fn new() -> Self {
            Meta { inner: anymap::Map::new() }
        }

        /// Add a new value to the metadata.
        ///
        /// # Errors
        ///
        /// Return an error if a value of this type already exists.
        pub fn add<V>(&mut self, val: V) -> Result<(), Error>
        where
            V: 'static + Send + Sync,
        {
            if self.inner.contains::<V>() {
                return Err(Error::AlreadyExists);
            }

            self.inner.insert(val);
            Ok(())
        }

        /// Clear all entries.
        pub fn clear(&mut self) {
            self.inner.clear();
        }

        /// Add the value to the map, replacing any existing value.
        /// Return the current value, if one exists.
        pub fn replace<V>(&mut self, val: V) -> Option<V>
        where
            V: 'static + Send + Sync,
        {
            self.inner.insert(val)
        }

        /// Remove the value with the specified type.
        pub fn remove<V>(&mut self) -> Option<V>
        where
            V: 'static + Send + Sync,
        {
            self.inner.remove::<V>()
        }

        /// Get a shared reference to the value with the specified
        /// type.
        pub fn get<V>(&self) -> Option<&V>
        where
            V: 'static + Send + Sync,
        {
            self.inner.get::<V>()
        }

        /// Get a unique reference to the value with specified type.
        pub fn get_mut<V>(&mut self) -> Option<&mut V>
        where
            V: 'static + Send + Sync,
        {
            self.inner.get_mut::<V>()
        }
    }
}

pub mod resources {
    use crate::engine::rule::Resource;

    #[derive(Debug)]
    pub enum Error {
        AlreadyExists,
    }

    /// A map of the available [`Resource`] types.
    pub struct Resources {
        inner: anymap::Map<dyn anymap::any::Any + Send + Sync>,
    }

    impl Resources {
        pub fn new() -> Self {
            Resources { inner: anymap::Map::new() }
        }

        /// Add a new [`Resource`].
        ///
        /// # Errors
        ///
        /// Return an error if a resource of this type already exists.
        pub fn add<V>(&mut self, val: V) -> Result<(), Error>
        where
            V: 'static + Resource + Send + Sync,
        {
            if self.inner.contains::<V>() {
                return Err(Error::AlreadyExists);
            }

            self.inner.insert(val);
            Ok(())
        }

        /// Clear all entries.
        #[cfg(test)]
        pub fn clear(&mut self) {
            self.inner.clear();
        }

        /// Remove the [`Resoruce`].
        pub fn remove<V>(&mut self) -> Option<V>
        where
            V: 'static + Resource + Send + Sync,
        {
            self.inner.remove::<V>()
        }

        /// Get a shared reference to the [`Resource`].
        pub fn get<V>(&self) -> Option<&V>
        where
            V: 'static + Resource + Send + Sync,
        {
            self.inner.get::<V>()
        }
    }
}

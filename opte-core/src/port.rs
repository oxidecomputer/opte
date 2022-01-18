use core::convert::TryFrom;
use core::result;

/// A virtual switch port.
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::string::{String, ToString};
#[cfg(any(feature = "std", test))]
use std::string::{String, ToString};
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::vec::Vec;
#[cfg(any(feature = "std", test))]
use std::vec::Vec;

#[cfg(all(not(feature = "std"), not(test)))]
use illumos_ddi_dki::hrtime_t;
#[cfg(any(feature = "std", test))]
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::ether::{EtherAddr, ETHER_TYPE_ARP, ETHER_TYPE_IPV4};
use crate::flow_table::{FlowEntryDump, FlowTable, StateSummary};
use crate::headers::IpMeta;
use crate::ioctl::CmdResp;
use crate::ip4::Protocol;
use crate::layer::{
    self, InnerFlowId, Layer, LayerError, LayerResult, RuleId, FLOW_ID_DEFAULT
};
use crate::packet::{Initialized, Packet, PacketMeta, Parsed};
use crate::rule::{ht_fire_probe, Action, Finalized, Rule, HT};
use crate::sync::{KMutex, KMutexType};
use crate::tcp::TcpState;
use crate::tcp_state::{self, TcpFlowState};
use crate::{CString, Direction};

use illumos_ddi_dki::uintptr_t;

pub const UFT_DEF_MAX_ENTIRES: u32 = 8192;

#[derive(Clone, Debug)]
pub enum Error {
    BadLayerPos { name: String, pos: Pos },
    LayerNotFound { name: String },
    RuleNotFound { layer: String, dir: Direction, id: RuleId }
}

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum ProcessError {
    Layer(LayerError),
    // ResourceError(ResourceError),
    WriteError(crate::packet::WriteError),
}

impl From<crate::packet::WriteError> for ProcessError {
    fn from(e: crate::packet::WriteError) -> Self {
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
/// or because of resource exhaustion.
///
/// * Modified: The packet has been modified based on its matching rules.
///
/// * Hairpin: One of the layers has determined that it should reply
/// directly with a packet of its own. In this case the original
/// packet is dropped.
#[derive(Debug)]
pub enum ProcessResult {
    Bypass,
    Drop,
    Modified,
    Hairpin(Packet<Initialized>),
}

pub trait PortState {}

pub struct Inactive {
    layers: KMutex<Vec<Layer>>,
}

pub struct Active {
    // TODO: Could I use const generics here in order to use array instead?
    layers: Vec<Layer>,
    uft_in: KMutex<FlowTable<Vec<HT>>>,
    uft_out: KMutex<FlowTable<Vec<HT>>>,
    // We keep a record of the inbound UFID in the TCP flow table so
    // that we know which inbound UFT/FT entries to retire upon
    // connection termination.
    tcp_flows: KMutex<FlowTable<TcpFlowEntryState>>,
}

impl PortState for Inactive {}
impl PortState for Active {}


pub struct Port<S: PortState> {
    state: S,
    name: String,
    mac: EtherAddr,
}

impl<S: PortState> Port<S> {
    pub fn mac_addr(&self) -> EtherAddr {
        self.mac
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Clone, Debug)]
pub enum AddLayerError {
    BadLayerPos(Pos),
}

impl Port<Inactive> {
    pub fn activate(self) -> Port<Active> {
        Port {
            state: Active {
                // An active port's layer pipeline is immutable, thus
                // we move the layers out of the mutex.
                layers: self.state.layers.into_inner(),
                uft_in: KMutex::new(
                    FlowTable::new(
                        "uft-in".to_string(),
                        Some(UFT_DEF_MAX_ENTIRES)
                    ),
                    KMutexType::Driver,
                ),
                uft_out: KMutex::new(
                    FlowTable::new(
                        "uft-out".to_string(),
                        Some(UFT_DEF_MAX_ENTIRES)
                    ),
                    KMutexType::Driver,
                ),
                tcp_flows: KMutex::new(
                    FlowTable::new(
                        "tcp-flows".to_string(),
                        Some(UFT_DEF_MAX_ENTIRES)
                    ),
                    KMutexType::Driver,
                ),

            },
            name: self.name,
            mac: self.mac,
        }
    }

    /// Add a new layer to the pipeline. The position may be first,
    /// last, or relative to another layer. The position is based on
    /// the outbound direction. The first layer is the first to see
    /// a packet from the guest. The last is the last to see a packet
    /// before it is delivered to the guest.
    pub fn add_layer(
        &self,
        new_layer: Layer,
        pos: Pos
    ) -> result::Result<(), AddLayerError> {
        let mut lock = self.state.layers.lock();

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

        Err(AddLayerError::BadLayerPos(pos))
    }

    pub fn new(name: String, mac: EtherAddr) -> Self {
        Port {
            state: Inactive {
                layers: KMutex::new(Vec::new(), KMutexType::Driver),
            },
            name,
            mac,
        }
    }

    /// Remove the [`Layer`] registered under `name`, if such a layer
    /// exists.
    pub fn remove_layer(&self, name: &str) {
        let mut lock = self.state.layers.lock();

        for (i, layer) in lock.iter().enumerate() {
            if layer.name() == name {
                let _ = lock.remove(i);
                return;
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum AddRuleError {
    LayerNotFound,
}

#[derive(Clone, Debug)]
pub enum DumpLayerError {
    LayerNotFound,
}

#[derive(Clone, Debug)]
pub enum RemoveRuleError {
    LayerNotFound,
    RuleNotFound,
}

impl Port<Active> {
    /// Add a new `Rule` to the layer named by `layer`, if such a
    /// layer exists. Otherwise, return an error.
    pub fn add_rule(
        &self,
        layer_name: &str,
        dir: Direction,
        rule: Rule<Finalized>,
    ) -> result::Result<(), AddRuleError> {
        for layer in &*self.state.layers {
            if layer.name() == layer_name {
                layer.add_rule(dir, rule);
                return Ok(());
            }
        }

        Err(AddRuleError::LayerNotFound)
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
    fn bad_packet_err(
        &self,
        msg: String,
        ptr: uintptr_t,
        ifid: &InnerFlowId
    ) -> ! {
        crate::dbg(format!("ptr: {:x}", ptr));
        crate::dbg(format!("ifid: {}", ifid));
        // crate::dbg(format!("meta: {:?}", meta));
        crate::dbg(format!(
            "flows: {:?}",
            *self.state.tcp_flows.lock(),
        ));
        todo!("bad packet: {}", msg);
    }

    /// Dump the contents of the layer named `name`, if such a layer
    /// exists.
    pub fn dump_layer(
        &self,
        name: &str
    ) -> result::Result<layer::DumpLayerResp, DumpLayerError> {
        for l in &*self.state.layers {
            if l.name() == name {
                return Ok(l.dump());
            }
        }

        Err(DumpLayerError::LayerNotFound)
    }

    /// Dump the contents of the TCP flow connection tracking table.
    pub fn dump_tcp_flows(&self) -> DumpTcpFlowsResp {
        DumpTcpFlowsResp { flows: self.state.tcp_flows.lock().dump() }
    }

    /// Dump the contents of the Unified Flow Table.
    pub fn dump_uft(&self) -> DumpUftResp {
        let in_lock = self.state.uft_in.lock();
        let uft_in_limit = in_lock.get_limit();
        let uft_in_num_flows = in_lock.num_flows();
        let uft_in = in_lock.dump();
        drop(in_lock);

        let out_lock = self.state.uft_out.lock();
        let uft_out_limit = out_lock.get_limit();
        let uft_out_num_flows = out_lock.num_flows();
        let uft_out = out_lock.dump();
        drop(out_lock);

        DumpUftResp {
            uft_in_limit,
            uft_in_num_flows,
            uft_in,
            uft_out_limit,
            uft_out_num_flows,
            uft_out,
        }
    }

    /// Expire all flows whose TTL is overdue as of `now`.
    #[cfg(all(not(feature = "std"), not(test)))]
    pub fn expire_flows(&self, now: hrtime_t) {
        for l in &self.state.layers {
            l.expire_flows(now);
        }
        self.state.uft_in.lock().expire_flows(now);
        self.state.uft_out.lock().expire_flows(now);
    }

    #[cfg(any(feature = "std", test))]
    pub fn expire_flows(&self, now: Instant) {
        for l in &self.state.layers {
            l.expire_flows(now);
        }
        self.state.uft_in.lock().expire_flows(now);
        self.state.uft_out.lock().expire_flows(now);
    }

    pub fn layer_action(&self, layer: &str, idx: usize) -> Option<&Action> {
        for l in &*self.state.layers {
            if l.name() == layer {
                return l.action(idx);
            }
        }

        None
    }

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
        pkt: &mut Packet<Parsed>,
        hts: &mut Vec<HT>,
        meta: &mut meta::Meta,
    ) -> result::Result<LayerResult, LayerError> {
        match dir {
            Direction::Out => {
                for layer in &self.state.layers {
                    match layer.process(dir, pkt, hts, meta) {
                        Ok(LayerResult::Allow) => (),
                        ret @ Ok(LayerResult::Deny) => return ret,
                        ret @ Ok(LayerResult::Hairpin(_)) => return ret,
                        ret @ Err(_) => return ret,
                    }
                }
            }

            Direction::In => {
                for layer in self.state.layers.iter().rev() {
                    match layer.process(dir, pkt, hts, meta) {
                        Ok(LayerResult::Allow) => (),
                        ret @ Ok(LayerResult::Deny) => return ret,
                        ret @ Ok(LayerResult::Hairpin(_)) => return ret,
                        ret @ Err(_) => return ret,
                    }
                }
            }
        }

        return Ok(LayerResult::Allow);
    }

    /// Process the packet.
    pub fn process(
        &self,
        dir: Direction,
        pkt: &mut Packet<Parsed>,
        ptr: uintptr_t,
    ) -> std::result::Result<ProcessResult, ProcessError> {
        port_process_entry_probe(dir, &self.name);
        let mut meta = meta::Meta::new();
        let res = match dir {
            Direction::Out => self.process_out(pkt, ptr, &mut meta),
            Direction::In => self.process_in(pkt, ptr, &mut meta),
        };
        port_process_return_probe(dir, &self.name);
        pkt.emit_headers()?;
        res
    }

    // Process the TCP packet for the purposes of connection tracking
    // when an inbound UFT entry exists.
    //
    // NOTE: This function is for internal use only, and thus returns
    // a standard Result type.
    fn process_in_tcp_existing(
        &self,
        meta: &PacketMeta,
    ) -> std::result::Result<TcpState, String> {
        // All TCP flows are keyed with respect to the outbound Flow
        // ID, therefore we take the dual.
        let ifid_after = InnerFlowId::try_from(meta).unwrap().dual();
        let tcp = meta.inner_tcp().unwrap();
        let mut lock = self.state.tcp_flows.lock();

        let tcp_state = match lock.get_mut(&ifid_after) {
            Some((_, entry)) => {
                let tfes = entry.get_state_mut();

                if tfes.tcp_state.get_tcp_state() == TcpState::Closed {
                    tcp_state::tcp_flow_drop_probe(
                        &ifid_after,
                        &tfes.tcp_state,
                        Direction::In,
                        tcp.flags,
                    );

                    return Ok(TcpState::Closed);
                }

                // The connection may have transitioned to CLOSED, but
                // we don't remove its entry here. That happens as
                // part of the expiration logic.
                let res = tfes.tcp_state.process(
                    Direction::In,
                    &ifid_after,
                    tcp
                );

                match res {
                    Ok(tcp_state) => tcp_state,
                    Err(e) => return Err(e),
                }
            }

            None => return Err(format!("TCP flow missing: {}", ifid_after)),
        };

        Ok(tcp_state)
    }

    // Process the TCP packet for the purposes of connection tracking
    // when an inbound UFT entry was just created.
    //
    // NOTE: This function is for internal use only, and thus returns
    // a standard Result type.
    fn process_in_tcp_new(
        &self,
        ifid: &InnerFlowId,
        meta: &PacketMeta,
    ) -> std::result::Result<TcpState, String> {
        // All TCP flows are keyed with respect to the outbound Flow
        // ID, therefore we take the dual.
        let ifid_after = InnerFlowId::try_from(meta).unwrap().dual();
        let mut lock = self.state.tcp_flows.lock();
        let tcp = meta.inner_tcp().unwrap();

        let tcp_state = match lock.get_mut(&ifid_after) {
            // We may have already created a TCP flow entry due to an
            // outbound packet, in that case simply fill in the
            // inbound UFID for expiration purposes.
            Some((_, entry)) => {
                let tfes = entry.get_state_mut();

                if tfes.tcp_state.get_tcp_state() == TcpState::Closed {
                     tcp_state::tcp_flow_drop_probe(
                        &ifid_after,
                        &tfes.tcp_state,
                        Direction::In,
                        tcp.flags,
                    );

                    return Ok(TcpState::Closed);
                }

                let res = tfes.tcp_state.process(
                    Direction::In,
                    &ifid_after,
                    &tcp
                );

                let tcp_state = match res {
                    Ok(tcp_state) => tcp_state,
                    Err(e) => return Err(e),
                };

                // We need to store the UFID of the inbound packet
                // before it was processed so that we can retire the
                // correct UFT/LFT entries upon connection
                // termination.
                if tfes.inbound_ufid.is_none() {
                    tfes.inbound_ufid = Some(*ifid);
                }

                tcp_state
            }

            None => {
                // Add a new flow entry in the `Listen` state, we'll
                // wait for the outgoing SYN+ACK to transition to
                // `SynRcvd`.
                let tfs =
                    TcpFlowState::new(TcpState::Listen, None, Some(tcp.seq));

                // TODO Deal with error.
                let tfes = TcpFlowEntryState {
                    // This must be the UFID of inbound traffic _as it
                    // arrives_, not after it's processed.
                    inbound_ufid: Some(*ifid),
                    tcp_state: tfs,
                };
                lock.add(ifid_after, tfes);

                TcpState::Listen
            }
        };

        Ok(tcp_state)
    }

    pub fn process_in(
        &self,
        pkt: &mut Packet<Parsed>,
        ptr: uintptr_t,
        meta: &mut meta::Meta,
    ) -> result::Result<ProcessResult, ProcessError> {
        let ifid = InnerFlowId::try_from(pkt.meta()).unwrap();

        // There is no FlowId, thus there can be no use of the UFT.
        if ifid == FLOW_ID_DEFAULT {
            let mut hts = Vec::new();
            let res = self.layers_process(
                Direction::In,
                pkt,
                &mut hts,
                meta,
            );

            match res {
                Ok(LayerResult::Allow) => {
                    return Ok(ProcessResult::Modified);
                }

                Ok(LayerResult::Hairpin(hppkt)) => {
                    return Ok(ProcessResult::Hairpin(hppkt));
                }

                Ok(LayerResult::Deny) => return Ok(ProcessResult::Drop),

                Err(e) => return Err(ProcessError::Layer(e)),
            }
        }

        // Use the compiled UFT entry if one exists. Otherwise
        // fallback to layer processing.
        match self.state.uft_in.lock().get_mut(&ifid) {
            Some((_, entry)) => {
                entry.hit();
                for ht in entry.get_state() {
                    ht.run(pkt.meta_mut());
                    let ifid_after = InnerFlowId::try_from(pkt.meta()).unwrap();
                    ht_fire_probe("UFT", Direction::In, &ifid, &ifid_after);
                }

                // For inbound traffic the TCP flow table must be
                // checked _after_ processing take place.
                if pkt.meta().is_inner_tcp() {
                    match self.process_in_tcp_existing(pkt.meta()) {
                        // Drop any data that comes in after close.
                        Ok(TcpState::Closed) => {
                            return Ok(ProcessResult::Drop);
                        }

                        Ok(_) => {
                            return Ok(ProcessResult::Modified);
                        }

                        Err(e) => {
                            self.bad_packet_err(e, ptr, &ifid);
                        }
                    }
                }

                return Ok(ProcessResult::Modified);
            }

            None => (),
        }

        let mut hts = Vec::new();
        let res = self.layers_process(
            Direction::In,
            pkt,
            &mut hts,
            meta
        );

        match res {
            Ok(LayerResult::Allow) => {
                self.state.uft_in.lock().add(ifid, hts);

                // For inbound traffic the TCP flow table must be
                // checked _after_ processing take place.
                if pkt.meta().is_inner_tcp() {
                    match self.process_in_tcp_new(&ifid, pkt.meta()) {
                        // Drop any data that comes in after close.
                        Ok(TcpState::Closed) => {
                            return Ok(ProcessResult::Drop);
                        }

                        Ok(_) => {
                            return Ok(ProcessResult::Modified);
                        }

                        Err(e) => {
                            self.bad_packet_err(e, ptr, &ifid);
                        }
                    }
                }

                Ok(ProcessResult::Modified)
            }

            Ok(LayerResult::Deny) => Ok(ProcessResult::Drop),

            Ok(LayerResult::Hairpin(hppkt)) => {
                Ok(ProcessResult::Hairpin(hppkt))
            }

            Err(e) => Err(ProcessError::Layer(e)),
        }
    }

    // Process the TCP packet for the purposes of connection tracking
    // when an outbound UFT entry exists.
    //
    // NOTE: This function is for internal use only, and thus returns
    // a standard Result type.
    fn process_out_tcp_existing(
        &self,
        ifid: &InnerFlowId,
        meta: &PacketMeta,
    ) -> std::result::Result<TcpState, String> {
        let mut lock = self.state.tcp_flows.lock();

        let tcp_state = match lock.get_mut(&ifid) {
            Some((_, entry)) => {
                let tfes = entry.get_state_mut();
                let tcp = meta.inner_tcp().unwrap();

                if tfes.tcp_state.get_tcp_state() == TcpState::Closed {
                    tcp_state::tcp_flow_drop_probe(
                        &ifid,
                        &tfes.tcp_state,
                        Direction::Out,
                        tcp.flags,
                    );

                    return Ok(TcpState::Closed);
                }

                // The connection may have transitioned to CLOSED, but
                // we don't remove its entry here. That happens as
                // part of the expiration logic.
                let res = tfes.tcp_state.process(Direction::Out, ifid, tcp);
                match res {
                    Ok(tcp_state) => tcp_state,

                    // TODO SDT probe for rejected packet.
                    Err(e) => return Err(e),
                }
            }

            None => return Err(format!("TCP flow missing: {}", ifid)),
        };

        Ok(tcp_state)
    }

    // Process the TCP packet for the purposes of connection tracking
    // when an outbound UFT entry was just created.
    //
    // NOTE: This function is for internal use only, and thus returns
    // a standard Result type.
    fn process_out_tcp_new(
        &self,
        ifid: InnerFlowId,
        meta: &PacketMeta,
    ) -> std::result::Result<TcpState, String> {
        let tcp = meta.inner_tcp().unwrap();
        let mut lock = self.state.tcp_flows.lock();

        let tcp_state = match lock.get_mut(&ifid) {
            // We may have already created a TCP flow entry
            // due to an inbound packet.
            Some((_, entry)) => {
                let tfes = entry.get_state_mut();

                if tfes.tcp_state.get_tcp_state() == TcpState::Closed {
                    tcp_state::tcp_flow_drop_probe(
                        &ifid,
                        &tfes.tcp_state,
                        Direction::Out,
                        tcp.flags,
                    );

                    return Ok(TcpState::Closed);
                }

                let res = tfes.tcp_state.process(Direction::Out, &ifid, &tcp);
                match res {
                    Ok(tcp_state) => tcp_state,

                    // TODO SDT probe for rejected packet
                    Err(e) => return Err(e),
                }
            }

            None => {
                // Create a new entry and find its current state. In
                // this case it should always be `SynSent` as a flow
                // would have already existed in the `SynRcvd` case.
                let mut tfs =
                    TcpFlowState::new(TcpState::Closed, Some(tcp.seq), None);

                let tcp_state = match tfs.process(Direction::Out, &ifid, &tcp) {
                    Ok(tcp_state) => tcp_state,

                    // TODO SDT probe for rejected packet.
                    Err(e) => return Err(e),
                };

                // The inbound UFID is determined on the inbound side.
                //
                // TODO Deal with error.
                let tfes =
                    TcpFlowEntryState { inbound_ufid: None, tcp_state: tfs };

                lock.add(ifid, tfes);
                tcp_state
            }
        };

        Ok(tcp_state)
    }

    pub fn process_out(
        &self,
        pkt: &mut Packet<Parsed>,
        ptr: uintptr_t,
        meta: &mut meta::Meta,
    ) -> result::Result<ProcessResult, ProcessError> {
        let etype = pkt.meta().inner.ether.as_ref().unwrap().ether_type;

        // TODO: Deal with non-IPv4/ARP, for now we let all
        // non-IPv4/ARP proceed untouched.
        if etype != ETHER_TYPE_IPV4 && etype != ETHER_TYPE_ARP {
            return Ok(ProcessResult::Bypass);
        }

        // TODO: Deal with IGMP, for now we let IGMP pass through
        // untouched.
        if let Some(IpMeta::Ip4(ip4)) = &pkt.meta().inner.ip {
            if ip4.proto == Protocol::IGMP {
                return Ok(ProcessResult::Bypass);
            }
        }

        let ifid = InnerFlowId::try_from(pkt.meta()).unwrap();

        // There is no FlowId, thus there can be no use of the UFT.
        if ifid == FLOW_ID_DEFAULT {
            let mut hts = Vec::new();
            let res = self.layers_process(
                Direction::Out,
                pkt,
                &mut hts,
                meta,
            );

            match res {
                Ok(LayerResult::Allow) => {
                    return Ok(ProcessResult::Modified);
                }

                Ok(LayerResult::Hairpin(hppkt)) => {
                    return Ok(ProcessResult::Hairpin(hppkt));
                }

                Ok(LayerResult::Deny) => return Ok(ProcessResult::Drop),
                Err(e) => return Err(ProcessError::Layer(e)),
            }
        }

        // Use the compiled UFT entry if one exists. Otherwise
        // fallback to layer processing.
        match self.state.uft_out.lock().get_mut(&ifid) {
            Some((_, entry)) => {
                entry.hit();

                // For outbound traffic the TCP flow table must be
                // checked _before_ processing take place.
                if pkt.meta().is_inner_tcp() {
                    match self.process_out_tcp_existing(&ifid, pkt.meta()) {
                        Err(e) => {
                            self.bad_packet_err(e, ptr, &ifid);
                        }

                        // Drop any data that comes in after close.
                        Ok(TcpState::Closed) => return Ok(ProcessResult::Drop),

                        // Continue with processing.
                        Ok(_) => (),
                    }
                }

                for ht in entry.get_state() {
                    ht.run(pkt.meta_mut());
                    let ifid_after = InnerFlowId::try_from(pkt.meta()).unwrap();
                    ht_fire_probe("UFT", Direction::Out, &ifid, &ifid_after);
                }

                return Ok(ProcessResult::Modified);
            }

            // Continue with processing.
            None => (),
        }

        // For outbound traffic the TCP flow table must be checked
        // _before_ processing take place.
        if pkt.meta().is_inner_tcp() {
            match self.process_out_tcp_new(ifid, pkt.meta()) {
                Err(e) => {
                    self.bad_packet_err(e, ptr, &ifid);
                }

                // Drop any data that comes in after close.
                Ok(TcpState::Closed) => return Ok(ProcessResult::Drop),

                // Continue with processing.
                Ok(_) => (),
            }
        }

        let mut hts = Vec::new();
        let res = self.layers_process(
            Direction::Out,
            pkt,
            &mut hts,
            meta,
        );

        match res {
            Ok(LayerResult::Allow) => {
                self.state.uft_out.lock().add(ifid, hts);
                Ok(ProcessResult::Modified)
            }

            Ok(LayerResult::Hairpin(hppkt)) => {
                Ok(ProcessResult::Hairpin(hppkt))
            }

            Ok(LayerResult::Deny) => Ok(ProcessResult::Drop),
            Err(e) => Err(ProcessError::Layer(e)),
        }
    }

    /// Remove the rule identified by the `dir`, `layer_name`, `id`
    /// combination, if such a rule exists.
    pub fn remove_rule(
        &self,
        layer_name: &str,
        dir: Direction,
        id: RuleId,
    ) -> result::Result<(), RemoveRuleError> {
        for layer in &self.state.layers {
            if layer.name() == layer_name {
                if layer.remove_rule(dir, id).is_err() {
                    return Err(RemoveRuleError::RuleNotFound);
                }
            }
        }

        Err(RemoveRuleError::LayerNotFound)
    }
}

// The follow functions are useful for validating state during
// testing. If one of these functions becomes useful outside of
// testing, then add it to the impl block above.
#[cfg(test)]
impl Port<Active> {
    /// Get the number of flows currently in the layer and direction
    /// specified. The value `"uft"` can be used to get the number of
    /// UFT flows.
    pub fn num_flows(&self, layer: &str, dir: Direction) -> u32 {
        use Direction::*;

        match (layer, dir) {
            ("uft", In) => self.state.uft_in.lock().num_flows(),
            ("uft", Out) => self.state.uft_out.lock().num_flows(),
            (name, dir) => {
                for layer in &self.state.layers {
                    if layer.name() == name {
                        return layer.num_flows(dir);
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TcpFlowEntryState {
    inbound_ufid: Option<InnerFlowId>,
    tcp_state: TcpFlowState,
}

impl StateSummary for TcpFlowEntryState {
    fn summary(&self) -> String {
        match self.inbound_ufid {
            None => format!("None {}", self.tcp_state),
            Some(ufid) => format!("{} {}", ufid, self.tcp_state),
        }
    }
}

#[cfg(any(feature = "std", test))]
pub unsafe fn __dtrace_probe_port__process__entry(
    _dir: uintptr_t,
    _arg: uintptr_t,
) {
    ()
}

#[cfg(any(feature = "std", test))]
pub unsafe fn __dtrace_probe_port__process__return(
    _dir: uintptr_t,
    _arg: uintptr_t,
) {
    ()
}

#[cfg(all(not(feature = "std"), not(test)))]
extern "C" {
    pub fn __dtrace_probe_port__process__entry(dir: uintptr_t, arg: uintptr_t);

    pub fn __dtrace_probe_port__process__return(dir: uintptr_t, arg: uintptr_t);
}

pub fn port_process_entry_probe(dir: Direction, name: &str) {
    let name_c = CString::new(name).unwrap();

    unsafe {
        __dtrace_probe_port__process__entry(
            dir as uintptr_t,
            name_c.as_ptr() as uintptr_t,
        );
    }
}

pub fn port_process_return_probe(dir: Direction, name: &str) {
    let name_c = CString::new(name).unwrap();

    unsafe {
        __dtrace_probe_port__process__return(
            dir as uintptr_t,
            name_c.as_ptr() as uintptr_t,
        );
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpUftReq {
    pub port_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpUftResp {
    pub uft_in_limit: u32,
    pub uft_in_num_flows: u32,
    pub uft_in: Vec<(InnerFlowId, FlowEntryDump)>,
    pub uft_out_limit: u32,
    pub uft_out_num_flows: u32,
    pub uft_out: Vec<(InnerFlowId, FlowEntryDump)>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpTcpFlowsReq {
    pub port_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpTcpFlowsResp {
    pub flows: Vec<(InnerFlowId, FlowEntryDump)>,
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
        inner: anymap::Map<dyn anymap::any::Any + Send + Sync>
    }

    impl Meta {
        pub fn new() -> Self {
            Meta { inner: anymap::Map::new() }
        }

        pub fn add<V>(&mut self, val: V) -> Result<(), Error>
        where
            V: 'static + Send + Sync
        {
            if self.inner.contains::<V>() {
                return Err(Error::AlreadyExists);
            }

            self.inner.insert(val);
            Ok(())
        }

        pub fn remove<V>(&mut self) -> Option<V>
        where
            V: 'static + Send + Sync
        {
            self.inner.remove::<V>()
        }

        pub fn get<V>(&mut self) -> Option<&V>
        where
            V: 'static + Send + Sync
        {
            self.inner.get::<V>()
        }

        pub fn get_mut<V>(&mut self) -> Option<&mut V>
        where
            V: 'static + Send + Sync
        {
            self.inner.get_mut::<V>()
        }
    }
}

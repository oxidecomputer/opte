/// A virtual switch port.
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::prelude::v1::*;
#[cfg(any(feature = "std", test))]
use std::prelude::v1::*;

#[cfg(all(not(feature = "std"), not(test)))]
use illumos_ddi_dki::hrtime_t;
#[cfg(any(feature = "std", test))]
use std::time::Instant;

use std::convert::TryFrom;

use serde::{Deserialize, Serialize};

use crate::ether::EtherAddr;
use crate::flow_table::{FlowEntryDump, FlowTable, StateSummary};
use crate::headers::IpMeta;
use crate::input::PacketReader;
use crate::ip4::{Ipv4Addr, Protocol};
use crate::layer::{InnerFlowId, Layer, LayerDumpResp};
use crate::nat::NatPool;
use crate::parse::{parse, PacketMeta};
use crate::rule::{ht_fire_probe, Resources, Rule, HT};
use crate::sync::{KMutex, KMutexType};
use crate::tcp::TcpState;
use crate::tcp_state::{self, TcpFlowState};
use crate::{CString, Direction};

use illumos_ddi_dki::uintptr_t;

pub const UFT_DEF_MAX_ENTIRES: u32 = 8192;

pub struct Port {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    mac: EtherAddr,
    // TODO: Eventually the IP will be sepcified at the time of Port
    // creation. But right now OPTE is welded into viona and we can't
    // get this information until after the Port has been created.
    ip: KMutex<Option<Ipv4Addr>>,
    layers: KMutex<Vec<Layer>>,
    resources: Resources,
    uft_in: KMutex<FlowTable<Vec<HT>>>,
    uft_out: KMutex<FlowTable<Vec<HT>>>,
    // We keep a record of the inbound UFID in the TCP flow table so
    // that we know which inbound UFT/FT entries to retire upon
    // connection termination.
    tcp_flows: KMutex<FlowTable<TcpFlowEntryState>>,
}

impl Port {
    // TODO Maybe Pipeline should be merged in Port?

    /// Add a new layer to the pipeline. The position may be first,
    /// last, or relative to another layer. The position is based on
    /// the outbound direction. The first layer is the first to see
    /// a packet from the guest. The last is the last to see a packet
    /// before it is delivered to the guest.
    pub fn add_layer(&self, layer: Layer, pos: Pos) {
        let mut lock = self.layers.lock().unwrap();

        match pos {
            Pos::Last => {
                lock.push(layer);
                return;
            }

            Pos::First => {
                lock.insert(0, layer);
                return;
            }

            Pos::Before(name) => {
                for (i, i_layer) in lock.iter().enumerate() {
                    crate::dbg(format!(
                        "Pos::Before comparing {} to {}",
                        name,
                        i_layer.get_name()
                    ));

                    if layer.get_name() == name {
                        lock.insert(i, layer);
                        return;
                    }
                }
            }

            Pos::After(name) => {
                for (i, i_layer) in lock.iter().enumerate() {
                    crate::dbg(format!(
                        "Pos::After comparing {} to {}",
                        name,
                        i_layer.get_name()
                    ));

                    if i_layer.get_name() == name {
                        lock.insert(i + 1, layer);
                        return;
                    }
                }
            }
        }

        panic!("bad position for layer: {}", layer.get_name());
    }

    /// Add a new `Rule` to the layer named by `layer`, if such a
    /// layer exists. Otherwise, return an error.
    pub fn add_rule(
        &self,
        layer_name: &str,
        dir: Direction,
        rule: Rule,
    ) -> Result<(), String> {
        for layer in &*self.layers.lock().unwrap() {
            if layer.get_name() == layer_name {
                layer.add_rule(dir, rule);
                return Ok(());
            }
        }

        Err(format!("layer {} not found", layer_name))
    }

    /// Dump the contents of the layer named `name`, if such a layer
    /// exists.
    pub fn dump_layer(&self, name: &str) -> Option<LayerDumpResp> {
        for l in &*self.layers.lock().unwrap() {
            if l.get_name() == name {
                return Some(l.dump());
            }
        }

        None
    }

    /// Dump the contents of the TCP flow connection tracking table.
    pub fn dump_tcp_flows(&self) -> TcpFlowsDumpResp {
        TcpFlowsDumpResp { flows: self.tcp_flows.lock().unwrap().dump() }
    }

    /// Dump the contents of the Unified Flow Table.
    pub fn dump_uft(&self) -> UftDumpResp {
        let in_lock = self.uft_in.lock().unwrap();
        let uft_in_limit = in_lock.get_limit();
        let uft_in_num_flows = in_lock.num_flows();
        let uft_in = in_lock.dump();
        drop(in_lock);

        let out_lock = self.uft_out.lock().unwrap();
        let uft_out_limit = out_lock.get_limit();
        let uft_out_num_flows = out_lock.num_flows();
        let uft_out = out_lock.dump();
        drop(out_lock);

        UftDumpResp {
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
        for l in &*self.layers.lock().unwrap() {
            l.expire_flows(now);
        }
        self.uft_in.lock().unwrap().expire_flows(now);
        self.uft_out.lock().unwrap().expire_flows(now);
    }

    #[cfg(any(feature = "std", test))]
    pub fn expire_flows(&self, now: Instant) {
        for l in &*self.layers.lock().unwrap() {
            l.expire_flows(now);
        }
        self.uft_in.lock().unwrap().expire_flows(now);
        self.uft_out.lock().unwrap().expire_flows(now);
    }

    // Process the packet metadata against each layer in turn. If any
    // layer rejects the packet it will return `Deny`, causing
    // immediate return of `Deny` from this function. Otherwise,
    // `Allow` is returned, `meta` contains the updated metadata, and
    // `hts` contains the list of HTs run against the metadata.
    fn layers_process(
        &self,
        dir: Direction,
        meta: &mut PacketMeta,
        hts: &mut Vec<HT>,
        resources: &Resources,
    ) -> ProcessResult {
        match dir {
            Direction::Out => {
                for layer in &*self.layers.lock().unwrap() {
                    match layer.process(dir, meta, hts, resources) {
                        ProcessResult::Allow => (),
                        ret @ ProcessResult::Deny => return ret,
                    }
                }
            }

            Direction::In => {
                for layer in self.layers.lock().unwrap().iter().rev() {
                    match layer.process(dir, meta, hts, resources) {
                        ProcessResult::Allow => (),
                        ret @ ProcessResult::Deny => return ret,
                    }
                }
            }
        }

        return ProcessResult::Allow;
    }

    pub fn new(name: String, mac: EtherAddr) -> Self {
        let resources = Resources::new();
        let layers = KMutex::new(Vec::new(), KMutexType::Driver);
        let ip = KMutex::new(None, KMutexType::Driver);
        let uft_in = KMutex::new(
            FlowTable::new("uft-in".to_string(), Some(UFT_DEF_MAX_ENTIRES)),
            KMutexType::Driver,
        );
        let uft_out = KMutex::new(
            FlowTable::new("uft-out".to_string(), Some(UFT_DEF_MAX_ENTIRES)),
            KMutexType::Driver,
        );

        let tcp_flows = KMutex::new(
            FlowTable::new("tcp-flows".to_string(), Some(UFT_DEF_MAX_ENTIRES)),
            KMutexType::Driver,
        );

        Port { name, mac, ip, layers, resources, uft_in, uft_out, tcp_flows }
    }

    /// Process the packet represented by the bytes returned by `rdr`.
    pub fn process<R>(
        &self,
        dir: Direction,
        rdr: &mut R,
        ptr: uintptr_t,
    ) -> Option<PacketMeta>
    where
        R: PacketReader,
    {
        port_process_entry_probe(dir, &self.name);
        let res = match dir {
            Direction::Out => self.process_out(rdr, ptr),
            Direction::In => self.process_in(rdr, ptr),
        };
        port_process_return_probe(dir, &self.name);
        res
    }

    // Process the TCP packet for the purposes of connection tracking
    // when an inbound UFT entry exists.
    fn process_in_tcp_existing(
        &self,
        meta: PacketMeta,
    ) -> Result<(TcpState, PacketMeta), String> {
        // All TCP flows are keyed with respect to the outbound Flow
        // ID, therefore we take the dual.
        let ifid_after = InnerFlowId::try_from(&meta).unwrap().dual();
        let mut lock = self.tcp_flows.lock().unwrap();

        let tcp_state = match lock.get_mut(&ifid_after) {
            Some((_, entry)) => {
                let tfes = entry.get_state_mut();

                if tfes.tcp_state.get_tcp_state() == TcpState::Closed {
                    let tcp = tcp_state::get_tcp_meta(&meta);
                    tcp_state::tcp_flow_drop_probe(
                        &ifid_after,
                        &tfes.tcp_state,
                        Direction::In,
                        tcp.flags,
                    );

                    return Ok((TcpState::Closed, meta));
                }

                // The connection may have transitioned to CLOSED, but
                // we don't remove its entry here. That happens as
                // part of the expiration logic.
                let res = tfes.tcp_state.process(Direction::In, &meta);
                match res {
                    Ok(tcp_state) => tcp_state,
                    Err(e) => return Err(e),
                }
            }

            None => return Err(format!("TCP flow missing: {}", ifid_after)),
        };

        Ok((tcp_state, meta))
    }

    // Process the TCP packet for the purposes of connection tracking
    // when an inbound UFT entry was just created.
    fn process_in_tcp_new(
        &self,
        ifid: InnerFlowId,
        meta: PacketMeta,
    ) -> Result<(TcpState, PacketMeta), String> {
        // All TCP flows are keyed with respect to the outbound Flow
        // ID, therefore we take the dual.
        let ifid_after = InnerFlowId::try_from(&meta).unwrap().dual();
        let mut lock = self.tcp_flows.lock().unwrap();

        let tcp_state = match lock.get_mut(&ifid_after) {
            // We may have already created a TCP flow entry due to an
            // outbound packet, in that case simply fill in the
            // inbound UFID for expiration purposes.
            Some((_, entry)) => {
                let tfes = entry.get_state_mut();

                if tfes.tcp_state.get_tcp_state() == TcpState::Closed {
                    let tcp = tcp_state::get_tcp_meta(&meta);
                    tcp_state::tcp_flow_drop_probe(
                        &ifid_after,
                        &tfes.tcp_state,
                        Direction::In,
                        tcp.flags,
                    );

                    return Ok((TcpState::Closed, meta));
                }

                let res = tfes.tcp_state.process(Direction::In, &meta);
                let tcp_state = match res {
                    Ok(tcp_state) => tcp_state,
                    Err(e) => return Err(e),
                };

                // We need to store the UFID of the inbound packet
                // before it was processed so that we can retire the
                // correct UFT/LFT entries upon connection
                // termination.
                if tfes.inbound_ufid.is_none() {
                    tfes.inbound_ufid = Some(ifid);
                }

                tcp_state
            }

            None => {
                // Add a new flow entry in the `Listen` state, we'll
                // wait for the outgoing SYN+ACK to transition to
                // `SynRcvd`.
                let tcp = crate::tcp_state::get_tcp_meta(&meta);
                let tfs =
                    TcpFlowState::new(TcpState::Listen, None, Some(tcp.seq));

                // TODO Deal with error.
                let tfes = TcpFlowEntryState {
                    // This must be the UFID of inbound traffic _as it
                    // arrives_, not after it's processed.
                    inbound_ufid: Some(ifid),
                    tcp_state: tfs,
                };
                lock.add(ifid_after, tfes);

                TcpState::Listen
            }
        };

        Ok((tcp_state, meta))
    }

    pub fn process_in<R>(
        &self,
        rdr: &mut R,
        ptr: uintptr_t,
    ) -> Option<PacketMeta>
    where
        R: PacketReader,
    {
        let mut meta = parse(rdr);
        let ifid = InnerFlowId::try_from(&meta).unwrap();

        // Use the compiled UFT entry if one exists. Oterhwise
        // fallback to layer processing.
        match self.uft_in.lock().unwrap().get_mut(&ifid) {
            Some((_, entry)) => {
                entry.hit();
                for ht in entry.get_state() {
                    ht.run(&mut meta);
                    let ifid_after = InnerFlowId::try_from(&meta).unwrap();

                    ht_fire_probe("UFT", Direction::In, &ifid, &ifid_after);
                }

                // For inbound traffic the TCP flow table must be
                // checked _after_ processing take place.
                if let Some(IpMeta::Ip4(ip4)) = &meta.inner_ip {
                    if ip4.proto == Protocol::TCP {
                        match self.process_in_tcp_existing(meta) {
                            // Drop any data that comes in after close.
                            Ok((TcpState::Closed, _meta)) => return None,

                            Ok((_, meta)) => return Some(meta),

                            Err(e) => {
                                crate::dbg(format!("ptr: {:x}", ptr));
                                crate::dbg(format!("ifid: {}", ifid));
                                // crate::dbg(format!("meta: {:?}", meta));
                                crate::dbg(format!(
                                    "flows: {:?}",
                                    *self.tcp_flows.lock().unwrap()
                                ));
                                panic!("bad packet: {}", e);
                            }
                        }
                    }
                }

                return Some(meta);
            }

            None => (),
        }

        let mut hts = Vec::new();
        let res = self.layers_process(
            Direction::In,
            &mut meta,
            &mut hts,
            &self.resources,
        );

        match res {
            ProcessResult::Allow => {
                self.uft_in.lock().unwrap().add(ifid, hts);

                // For inbound traffic the TCP flow table must be
                // checked _after_ processing take place.
                if let Some(IpMeta::Ip4(ip4)) = &meta.inner_ip {
                    if ip4.proto == Protocol::TCP {
                        match self.process_in_tcp_new(ifid, meta) {
                            // Drop any data that comes in after close.
                            Ok((TcpState::Closed, _meta)) => return None,

                            Ok((_, meta)) => return Some(meta),

                            Err(e) => {
                                crate::dbg(format!("ptr: {:x}", ptr));
                                crate::dbg(format!("ifid: {}", ifid));
                                // crate::dbg(format!("meta: {:?}", meta));
                                crate::dbg(format!(
                                    "flows: {:?}",
                                    *self.tcp_flows.lock().unwrap()
                                ));
                                panic!("bad packet: {}", e);
                            }
                        }
                    }
                }

                Some(meta)
            }

            ProcessResult::Deny => None,
        }
    }

    // Process the TCP packet for the purposes of connection tracking
    // when an oubound UFT entry exists.
    fn process_out_tcp_existing(
        &self,
        ifid: &InnerFlowId,
        meta: &PacketMeta,
    ) -> Result<TcpState, String> {
        let tcp_state = match self.tcp_flows.lock().unwrap().get_mut(&ifid) {
            Some((_, entry)) => {
                let tfes = entry.get_state_mut();

                if tfes.tcp_state.get_tcp_state() == TcpState::Closed {
                    let tcp = tcp_state::get_tcp_meta(&meta);
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
                let res = tfes.tcp_state.process(Direction::Out, meta);
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
    fn process_out_tcp_new(
        &self,
        ifid: InnerFlowId,
        meta: &PacketMeta,
    ) -> Result<TcpState, String> {
        let mut lock = self.tcp_flows.lock().unwrap();
        let tcp_state = match lock.get_mut(&ifid) {
            // We may have already created a TCP flow entry
            // due to an inbound packet.
            Some((_, entry)) => {
                let tfes = entry.get_state_mut();

                if tfes.tcp_state.get_tcp_state() == TcpState::Closed {
                    let tcp = tcp_state::get_tcp_meta(&meta);
                    tcp_state::tcp_flow_drop_probe(
                        &ifid,
                        &tfes.tcp_state,
                        Direction::Out,
                        tcp.flags,
                    );

                    return Ok(TcpState::Closed);
                }

                let res = tfes.tcp_state.process(Direction::Out, &meta);
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
                let tcp = crate::tcp_state::get_tcp_meta(&meta);
                let mut tfs =
                    TcpFlowState::new(TcpState::Closed, Some(tcp.seq), None);

                let tcp_state = match tfs.process(Direction::Out, &meta) {
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

    pub fn process_out<R>(
        &self,
        rdr: &mut R,
        ptr: uintptr_t,
    ) -> Option<PacketMeta>
    where
        R: PacketReader,
    {
        let mut meta = parse(rdr);

        // TODO: Deal with IGMP, for now we just let IGMP pass through
        // untouched.
        if let Some(IpMeta::Ip4(ip4)) = &meta.inner_ip {
            if ip4.proto == Protocol::IGMP {
                return Some(meta);
                // return ProcessResult::Allow;
            }
        }

        let ifid = InnerFlowId::try_from(&meta).unwrap();

        // Use the compiled UFT entry if one exists. Oterhwise
        // fallback to layer processing.
        match self.uft_out.lock().unwrap().get_mut(&ifid) {
            Some((_, entry)) => {
                entry.hit();

                // For outbound traffic the TCP flow table must be
                // checked _before_ processing take place.
                if let Some(IpMeta::Ip4(ip4)) = &meta.inner_ip {
                    if ip4.proto == Protocol::TCP {
                        match self.process_out_tcp_existing(&ifid, &meta) {
                            Err(e) => {
                                crate::dbg(format!("ptr: {:x}", ptr));
                                crate::dbg(format!("ifid: {}", ifid));
                                // crate::dbg(format!("meta: {:?}", meta));
                                crate::dbg(format!(
                                    "flows: {:?}",
                                    *self.tcp_flows.lock().unwrap()
                                ));
                                panic!("bad packet: {}", e);
                            }

                            // Drop any data that comes in after close.
                            Ok(TcpState::Closed) => return None,

                            Ok(_) => (),
                        }
                    }
                }

                for ht in entry.get_state() {
                    ht.run(&mut meta);
                    let ifid_after = InnerFlowId::try_from(&meta).unwrap();

                    ht_fire_probe("UFT", Direction::Out, &ifid, &ifid_after);
                }

                return Some(meta);
            }

            None => (),
        }

        // For outbound traffic the TCP flow table must be checked
        // _before_ processing take place.
        if let Some(IpMeta::Ip4(ip4)) = &meta.inner_ip {
            if ip4.proto == Protocol::TCP {
                match self.process_out_tcp_new(ifid, &meta) {
                    Err(e) => {
                        crate::dbg(format!("ptr: {:x}", ptr));
                        crate::dbg(format!("ifid: {}", ifid));
                        // crate::dbg(format!("meta: {:?}", meta));
                        crate::dbg(format!(
                            "flows: {:?}",
                            *self.tcp_flows.lock().unwrap()
                        ));
                        panic!("bad packet: {}", e);
                    }

                    // Drop any data that comes in after close.
                    Ok(TcpState::Closed) => return None,

                    Ok(_) => (),
                }
            }
        }

        let mut hts = Vec::new();
        let res = self.layers_process(
            Direction::Out,
            &mut meta,
            &mut hts,
            &self.resources,
        );

        match res {
            ProcessResult::Allow => {
                self.uft_out.lock().unwrap().add(ifid, hts);
                Some(meta)
            }

            ProcessResult::Deny => None,
        }
    }

    /// Remove the rule identified by the `dir`, `layer_name`, `id`
    /// combination, if such a rule exists.
    pub fn remove_rule(
        &self,
        layer_name: &str,
        dir: Direction,
        id: u64,
    ) -> Result<(), String> {
        for layer in &*self.layers.lock().unwrap() {
            if layer.get_name() == layer_name {
                return layer.remove_rule(dir, id);
            }
        }

        Err(format!("layer {} not found", layer_name))
    }

    pub fn set_ip(&self, ip: Ipv4Addr) {
        self.ip.lock().unwrap().replace(ip);
    }

    pub fn set_nat_pool(&self, pool: NatPool) {
        self.resources.set_nat_pool(pool);
    }
}

// The follow functions are useful for validating state during
// testing. If one of these functions becomes useful outside of
// testing, then add it to the impl block above.
#[cfg(test)]
impl Port {
    /// Get the number of flows curently in the layer and direction
    /// specified. The value `"uft"` can be used to get the number of
    /// UFT flows.
    pub fn num_flows(&self, layer: &str, dir: Direction) -> u32 {
        use Direction::*;

        match (layer, dir) {
            ("uft", In) => self.uft_in.lock().unwrap().num_flows(),
            ("uft", Out) => self.uft_out.lock().unwrap().num_flows(),
            (name, dir) => {
                for layer in &*self.layers.lock().unwrap() {
                    if layer.get_name() == name {
                        return layer.num_flows(dir);
                    }
                }

                panic!("layer not found: {}", name);
            }
        }
    }
}

pub enum Pos {
    Last,
    First,
    Before(&'static str),
    After(&'static str),
}

pub enum ProcessResult {
    Allow,
    Deny,
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
pub struct UftDumpReq {
    pub unused: (),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UftDumpResp {
    pub uft_in_limit: u32,
    pub uft_in_num_flows: u32,
    pub uft_in: Vec<(InnerFlowId, FlowEntryDump)>,
    pub uft_out_limit: u32,
    pub uft_out_num_flows: u32,
    pub uft_out: Vec<(InnerFlowId, FlowEntryDump)>,
}

#[derive(Deserialize, Serialize)]
pub struct TcpFlowsDumpReq {
    pub req: (),
}

#[derive(Deserialize, Serialize)]
pub struct TcpFlowsDumpResp {
    pub flows: Vec<(InnerFlowId, FlowEntryDump)>,
}

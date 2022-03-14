use core::convert::TryFrom;
use core::fmt::{self, Display};
use core::mem;
use core::result;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::string::{String, ToString};
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::sync::Arc;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::vec::Vec;
#[cfg(any(feature = "std", test))]
use std::string::{String, ToString};
#[cfg(any(feature = "std", test))]
use std::sync::Arc;
#[cfg(any(feature = "std", test))]
use std::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::flow_table::FlowTable;
use crate::headers::{IpAddr, IpMeta, UlpMeta};
use crate::ioctl;
use crate::ip4::{Ipv4Addr, Protocol};
use crate::packet::{Initialized, Packet, PacketMeta, PacketRead, Parsed};
use crate::port::meta::Meta;
use crate::rule::{
    self, flow_id_sdt_arg, ht_fire_probe, Action, ActionDesc, Rule, RuleDump,
    HT,
};
use crate::sync::{KMutex, KMutexType};
use crate::{CString, Direction, ExecCtx, LogLevel};

use illumos_ddi_dki::{c_char, uintptr_t};

#[cfg(all(not(feature = "std"), not(test)))]
use illumos_ddi_dki::hrtime_t;
#[cfg(any(feature = "std", test))]
use std::time::Instant;

#[derive(Debug)]
pub enum LayerError {
    GenDesc(rule::GenDescError),
    GenHt(rule::GenHtError),
    GenPacket(rule::GenErr),
}

#[derive(Debug)]
pub enum LayerResult {
    Allow,
    Deny { name: String },
    Hairpin(Packet<Initialized>),
}

impl Display for LayerResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use LayerResult::*;

        let rstr = match self {
            Allow => "Allow".to_string(),
            Deny { name } => format!("Deny: {}", name),
            Hairpin(_) => "Hairpin".to_string(),
        };
        write!(f, "{}", &rstr)
    }
}

pub type RuleId = u64;

pub enum Error {
    RuleNotFound { id: RuleId },
}

pub type Result<T> = result::Result<T, Error>;

pub struct Layer {
    port_name: String,
    name: String,
    actions: Vec<Action>,
    ft_in: KMutex<FlowTable<Arc<dyn ActionDesc>>>,
    ft_out: KMutex<FlowTable<Arc<dyn ActionDesc>>>,
    rules_in: KMutex<RuleTable>,
    rules_out: KMutex<RuleTable>,
}

impl Layer {
    pub fn action(&self, idx: usize) -> Option<&Action> {
        self.actions.get(idx)
    }

    pub fn add_rule(&self, dir: Direction, rule: Rule<rule::Finalized>) {
        match dir {
            Direction::Out => self.rules_out.lock().add(rule),
            Direction::In => self.rules_in.lock().add(rule),
        }
    }

    pub fn dump(&self) -> ioctl::DumpLayerResp {
        let rules_in = self.rules_in.lock().dump();
        let rules_out = self.rules_out.lock().dump();
        let ft_in = self.ft_in.lock().dump();
        let ft_out = self.ft_out.lock().dump();
        ioctl::DumpLayerResp {
            name: self.name.clone(),
            ft_in,
            ft_out,
            rules_in,
            rules_out,
        }
    }

    fn gen_desc_fail_probe(
        &self,
        dir: Direction,
        ifid: &InnerFlowId,
        err: &rule::GenDescError,
    ) {
        let flow_id = flow_id_sdt_arg::from(ifid);
        let port_c = CString::new(format!("{}", self.port_name)).unwrap();
        let layer_c = CString::new(format!("{}", self.name)).unwrap();
        let dir_c = CString::new(format!("{}", dir)).unwrap();
        let msg_c = CString::new(format!("{:?}", err)).unwrap();

        unsafe {
            __dtrace_probe_gen__desc__fail(
                port_c.as_ptr() as uintptr_t,
                layer_c.as_ptr() as uintptr_t,
                dir_c.as_ptr() as uintptr_t,
                &flow_id as *const flow_id_sdt_arg as uintptr_t,
                msg_c.as_ptr() as uintptr_t,
            );
        }
    }

    fn gen_ht_fail_probe(
        &self,
        dir: Direction,
        ifid: &InnerFlowId,
        err: &rule::GenHtError,
    ) {
        let flow_id = flow_id_sdt_arg::from(ifid);
        let port_c = CString::new(format!("{}", self.port_name)).unwrap();
        let layer_c = CString::new(format!("{}", self.name)).unwrap();
        let dir_c = CString::new(format!("{}", dir)).unwrap();
        let msg_c = CString::new(format!("{:?}", err)).unwrap();

        unsafe {
            __dtrace_probe_gen__ht__fail(
                port_c.as_ptr() as uintptr_t,
                layer_c.as_ptr() as uintptr_t,
                dir_c.as_ptr() as uintptr_t,
                &flow_id as *const flow_id_sdt_arg as uintptr_t,
                msg_c.as_ptr() as uintptr_t,
            );
        }
    }

    #[cfg(all(not(feature = "std"), not(test)))]
    pub fn expire_flows(&self, now: hrtime_t) {
        self.ft_in.lock().expire_flows(now);
        self.ft_out.lock().expire_flows(now);
    }

    #[cfg(any(feature = "std", test))]
    pub fn expire_flows(&self, now: Instant) {
        self.ft_in.lock().expire_flows(now);
        self.ft_out.lock().expire_flows(now);
    }

    /// Return the name of the layer.
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn new(name: &str, port_name: &str, actions: Vec<Action>) -> Self {
        Layer {
            actions,
            name: name.to_string(),
            port_name: port_name.to_string(),
            ft_in: KMutex::new(
                FlowTable::new(name.to_string(), None),
                KMutexType::Driver,
            ),
            ft_out: KMutex::new(
                FlowTable::new(name.to_string(), None),
                KMutexType::Driver,
            ),
            rules_in: KMutex::new(
                RuleTable::new(name.to_string(), Direction::In),
                KMutexType::Driver,
            ),
            rules_out: KMutex::new(
                RuleTable::new(name.to_string(), Direction::Out),
                KMutexType::Driver,
            ),
        }
    }

    pub fn num_flows(&self, dir: Direction) -> u32 {
        match dir {
            Direction::Out => self.ft_out.lock().num_flows(),
            Direction::In => self.ft_in.lock().num_flows(),
        }
    }

    pub fn num_rules(&self, dir: Direction) -> usize {
        match dir {
            Direction::Out => self.rules_out.lock().num_rules(),
            Direction::In => self.rules_in.lock().num_rules(),
        }
    }

    pub fn process(
        &self,
        ectx: &ExecCtx,
        dir: Direction,
        pkt: &mut Packet<Parsed>,
        hts: &mut Vec<HT>,
        meta: &mut Meta,
    ) -> result::Result<LayerResult, LayerError> {
        let ifid = InnerFlowId::try_from(pkt.meta()).unwrap();
        layer_process_entry_probe(dir, &self.name, &ifid);
        let res = match dir {
            Direction::Out => self.process_out(ectx, pkt, &ifid, hts, meta),
            Direction::In => self.process_in(ectx, pkt, &ifid, hts, meta),
        };
        layer_process_return_probe(dir, &self.name, &ifid, &res);
        res
    }

    fn process_in(
        &self,
        ectx: &ExecCtx,
        pkt: &mut Packet<Parsed>,
        ifid: &InnerFlowId,
        hts: &mut Vec<HT>,
        meta: &mut Meta,
    ) -> result::Result<LayerResult, LayerError> {
        // We have no FlowId, thus there can be no FlowTable entry.
        if *ifid == FLOW_ID_DEFAULT {
            return self.process_in_rules(ectx, ifid, pkt, hts, meta);
        }

        // Do we have a FlowTable entry? If so, use it.
        if let Some((_, entry)) = self.ft_in.lock().get_mut(&ifid) {
            entry.hit();
            let desc = entry.get_state();
            let ht = desc.gen_ht(Direction::In);
            hts.push(ht.clone());

            ht.run(pkt.meta_mut());

            let ifid_after = InnerFlowId::try_from(pkt.meta()).unwrap();
            ht_fire_probe(
                &format!("{}-ft", self.name),
                Direction::In,
                &ifid,
                &ifid_after,
            );

            // if let Some(ctx) = state.ra.ctx {
            //     ctx.exec(pkt.meta(), &mut [0; 0])
            //         .expect("failed action context exec()");
            // };

            return Ok(LayerResult::Allow);
        }

        // XXX Flow table miss stat

        // No FlowTable entry, perhaps there is a matching Rule?
        self.process_in_rules(ectx, ifid, pkt, hts, meta)
    }

    fn process_in_rules(
        &self,
        ectx: &ExecCtx,
        ifid: &InnerFlowId,
        pkt: &mut Packet<Parsed>,
        hts: &mut Vec<HT>,
        meta: &mut Meta,
    ) -> result::Result<LayerResult, LayerError> {
        let lock = self.rules_in.lock();

        let mut rdr = pkt.get_body_rdr();
        let rule = lock.find_match(pkt.meta(), &mut rdr);
        let _ = rdr.finish();

        if rule.is_none() {
            // Currently a `Layer` is not expected to define a total
            // function over the set of all possible input. Rather it
            // can define rules over a subset of the input and
            // anything that doesn't match will be allowed implicitly.
            // We could `Deny` by default, but it will require that
            // these types of layers define a final rule which matches
            // all packets and returns `Allow`. We could also set a
            // flag at Layer creation to determines if it
            // allows/denies by default.
            return Ok(LayerResult::Allow);
        }

        match rule.unwrap().action() {
            Action::Deny => {
                rule_deny_probe(&self.name, Direction::In, ifid);
                return Ok(LayerResult::Deny { name: self.name.clone() });
            }

            Action::Meta(action) => {
                action.mod_meta(ifid, meta);
                return Ok(LayerResult::Allow);
            }

            Action::Static(action) => {
                let ht = match action.gen_ht(Direction::Out, ifid, meta) {
                    Ok(ht) => ht,
                    Err(e) => {
                        self.record_gen_ht_failure(
                            &ectx,
                            Direction::Out,
                            &ifid,
                            &e,
                        );
                        return Err(LayerError::GenHt(e));
                    }
                };

                hts.push(ht.clone());

                ht.run(pkt.meta_mut());

                let ifid_after = InnerFlowId::try_from(pkt.meta()).unwrap();

                ht_fire_probe(
                    &format!("{}-rt", self.name),
                    Direction::In,
                    &ifid,
                    &ifid_after,
                );

                return Ok(LayerResult::Allow);
            }

            Action::Stateful(action) => {
                let desc = match action.gen_desc(&ifid, meta) {
                    Ok(d) => d,

                    Err(e) => {
                        self.record_gen_desc_failure(
                            &ectx,
                            Direction::In,
                            &ifid,
                            &e,
                        );
                        return Err(LayerError::GenDesc(e));
                    }
                };

                let ht_in = desc.gen_ht(Direction::In);
                hts.push(ht_in.clone());

                self.ft_in.lock().add(ifid.clone(), desc.clone());

                ht_in.run(pkt.meta_mut());

                let ifid_after = InnerFlowId::try_from(pkt.meta()).unwrap();

                ht_fire_probe(
                    &format!("{}-rt", self.name),
                    Direction::In,
                    &ifid,
                    &ifid_after,
                );

                // The outbound FlowId must be calculated _after_
                // the header transposition. Remember, the two
                // flow tables act as duals of each other, and the
                // HT might change how the other side of this
                // layer sees this flow.
                let out_ifid =
                    InnerFlowId::try_from(pkt.meta()).unwrap().dual();
                self.ft_out.lock().add(out_ifid, desc);

                // if let Some(ctx) = ra_in.ctx {
                //     ctx.exec(flow_id, &mut [0; 0]);
                // }

                return Ok(LayerResult::Allow);
            }

            Action::Hairpin(action) => {
                let mut rdr = pkt.get_body_rdr();
                match action.gen_packet(pkt.meta(), &mut rdr) {
                    Ok(pkt) => {
                        let _ = rdr.finish();
                        return Ok(LayerResult::Hairpin(pkt));
                    }

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
        &self,
        ectx: &ExecCtx,
        pkt: &mut Packet<Parsed>,
        ifid: &InnerFlowId,
        hts: &mut Vec<HT>,
        meta: &mut Meta,
    ) -> result::Result<LayerResult, LayerError> {
        // We have no FlowId, thus there can be no FlowTable entry.
        if *ifid == FLOW_ID_DEFAULT {
            return self.process_out_rules(ectx, ifid, pkt, hts, meta);
        }

        // Do we have a FlowTable entry? If so, use it.
        if let Some((_, entry)) = self.ft_out.lock().get_mut(&ifid) {
            entry.hit();
            let desc = entry.get_state();
            let ht = desc.gen_ht(Direction::Out);
            hts.push(ht.clone());

            ht.run(pkt.meta_mut());

            let ifid_after = InnerFlowId::try_from(pkt.meta()).unwrap();
            ht_fire_probe(
                &format!("{}-ft", self.name),
                Direction::Out,
                &ifid,
                &ifid_after,
            );

            // XXX I believe the `ra` field is from when a rule's
            // state consisted of a RuleAction, but I changed it to be
            // an action descriptor quite a ways back.
            //
            // if let Some(ctx) = state.ra.ctx {
            //     ctx.exec(flow_id, &mut [0; 0])
            //         .expect("failed action context exec()");
            // };

            return Ok(LayerResult::Allow);
        }

        // No FlowTable entry, perhaps there is matching Rule?
        self.process_out_rules(ectx, &ifid, pkt, hts, meta)
    }

    fn process_out_rules(
        &self,
        ectx: &ExecCtx,
        ifid: &InnerFlowId,
        pkt: &mut Packet<Parsed>,
        hts: &mut Vec<HT>,
        meta: &mut Meta,
    ) -> result::Result<LayerResult, LayerError> {
        let lock = self.rules_out.lock();
        let mut rdr = pkt.get_body_rdr();
        let rule = lock.find_match(pkt.meta(), &mut rdr);
        let _ = rdr.finish();

        if rule.is_none() {
            // Currently `Layer` is not expected to define a total
            // function over the set of all possible input. Rather it
            // can define rules over a subset of the input and
            // anything that doesn't match will be allowed implicitly.
            // We could `Deny` by default, but it will require that
            // these types of layers define a final rule which matches
            // all packets and returns `Allow`. We could also set a
            // flag at Layer creation to determines if it
            // allows/denies by default.
            return Ok(LayerResult::Allow);
        }

        match rule.unwrap().action() {
            Action::Deny => {
                rule_deny_probe(&self.name, Direction::Out, ifid);
                return Ok(LayerResult::Deny { name: self.name.clone() });
            }

            Action::Meta(action) => {
                action.mod_meta(ifid, meta);
                return Ok(LayerResult::Allow);
            }

            Action::Static(action) => {
                let ht = match action.gen_ht(Direction::Out, ifid, meta) {
                    Ok(ht) => ht,
                    Err(e) => {
                        self.record_gen_ht_failure(
                            &ectx,
                            Direction::Out,
                            &ifid,
                            &e,
                        );
                        return Err(LayerError::GenHt(e));
                    }
                };

                hts.push(ht.clone());

                ht.run(pkt.meta_mut());

                let ifid_after = InnerFlowId::try_from(pkt.meta()).unwrap();

                ht_fire_probe(
                    &format!("{}-rt", self.name),
                    Direction::Out,
                    &ifid,
                    &ifid_after,
                );

                return Ok(LayerResult::Allow);
            }

            Action::Stateful(action) => {
                let desc = match action.gen_desc(&ifid, meta) {
                    Ok(d) => d,

                    Err(e) => {
                        self.record_gen_desc_failure(
                            &ectx,
                            Direction::Out,
                            &ifid,
                            &e,
                        );
                        return Err(LayerError::GenDesc(e));
                    }
                };

                let ht_out = desc.gen_ht(Direction::Out);
                hts.push(ht_out.clone());

                self.ft_out.lock().add(ifid.clone(), desc.clone());

                ht_out.run(pkt.meta_mut());

                let ifid_after = InnerFlowId::try_from(pkt.meta()).unwrap();

                ht_fire_probe(
                    &format!("{}-rt", self.name),
                    Direction::Out,
                    &ifid,
                    &ifid_after,
                );

                // The inbound FlowId must be calculated _after_
                // the header transposition. Remember, the two
                // flow tables act as duals of each other, and the
                // HT might change how the other side of this
                // layer sees this flow.
                let in_ifid = InnerFlowId::try_from(pkt.meta()).unwrap().dual();
                self.ft_in.lock().add(in_ifid, desc);

                // if let Some(ctx) = ra_out2.ctx {
                //     ctx.exec(flow_id, &mut [0; 0]);
                // }

                return Ok(LayerResult::Allow);
            }

            Action::Hairpin(action) => {
                let mut rdr = pkt.get_body_rdr();
                match action.gen_packet(pkt.meta(), &mut rdr) {
                    Ok(new_pkt) => {
                        let _ = rdr.finish();
                        return Ok(LayerResult::Hairpin(new_pkt));
                    }

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
        ifid: &InnerFlowId,
        err: &rule::GenDescError,
    ) {
        // XXX increment stat
        ectx.log.log(
            LogLevel::Error,
            &format!(
                "failed to generate descriptor for stateful action: {} {:?}",
                ifid, err
            ),
        );
        self.gen_desc_fail_probe(dir, ifid, err);
    }

    fn record_gen_ht_failure(
        &self,
        ectx: &ExecCtx,
        dir: Direction,
        ifid: &InnerFlowId,
        err: &rule::GenHtError,
    ) {
        // XXX increment stat
        ectx.log.log(
            LogLevel::Error,
            &format!(
                "failed to generate HT for static action: {} {:?}",
                ifid, err
            ),
        );
        self.gen_ht_fail_probe(dir, ifid, err);
    }

    pub fn remove_rule(&self, dir: Direction, id: RuleId) -> Result<()> {
        match dir {
            Direction::In => self.rules_in.lock().remove(id),
            Direction::Out => self.rules_out.lock().remove(id),
        }
    }
}

pub static FLOW_ID_DEFAULT: InnerFlowId = InnerFlowId {
    proto: Protocol::Reserved,
    src_ip: IpAddr::Ip4(Ipv4Addr::new([0; 4])),
    src_port: 0,
    dst_ip: IpAddr::Ip4(Ipv4Addr::new([0; 4])),
    dst_port: 0,
};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct InnerFlowId {
    pub proto: Protocol,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl InnerFlowId {
    pub fn dual(mut self) -> Self {
        mem::swap(&mut self.src_ip, &mut self.dst_ip);
        mem::swap(&mut self.src_port, &mut self.dst_port);
        self
    }
}

impl Display for InnerFlowId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}:{}",
            self.proto, self.src_ip, self.src_port, self.dst_ip, self.dst_port,
        )
    }
}

impl TryFrom<&PacketMeta> for InnerFlowId {
    type Error = String;

    fn try_from(meta: &PacketMeta) -> result::Result<Self, Self::Error> {
        let (proto, src_ip, dst_ip) = match &meta.inner.ip {
            Some(IpMeta::Ip4(ip4)) => {
                (ip4.proto, IpAddr::Ip4(ip4.src), IpAddr::Ip4(ip4.dst))
            }
            Some(IpMeta::Ip6(ip6)) => {
                (ip6.proto, IpAddr::Ip6(ip6.src), IpAddr::Ip6(ip6.dst))
            }
            None => (
                Protocol::Reserved,
                IpAddr::Ip4(Ipv4Addr::new([0; 4])),
                IpAddr::Ip4(Ipv4Addr::new([0; 4])),
            ),
        };

        let (src_port, dst_port) = match &meta.inner.ulp {
            Some(UlpMeta::Tcp(tcp)) => (tcp.src, tcp.dst),
            Some(UlpMeta::Udp(udp)) => (udp.src, udp.dst),
            None => (0, 0),
        };

        Ok(InnerFlowId { proto, src_ip, src_port, dst_ip, dst_port })
    }
}

// TODO move this into Layer itself.
#[derive(Debug)]
pub struct RuleTable {
    layer: String,
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
        meta: &PacketMeta,
        rdr: &'b mut R,
    ) -> Option<&Rule<rule::Finalized>>
    where
        R: PacketRead<'a>,
    {
        for (_, r) in &self.rules {
            if r.is_match(meta, rdr) {
                rule_match_probe(
                    &self.layer,
                    self.dir,
                    &InnerFlowId::try_from(meta).unwrap(),
                    &r,
                );
                return Some(r);
            }
        }

        rule_no_match_probe(
            &self.layer,
            self.dir,
            &InnerFlowId::try_from(meta).unwrap(),
        );

        None
    }

    // Find the position in which to insert this rule.
    fn find_pos(&self, rule: &Rule<rule::Finalized>) -> RulePlace {
        for (i, (_, r)) in self.rules.iter().enumerate() {
            if rule.priority < r.priority {
                return RulePlace::Insert(i);
            }

            // Deny takes precedence at the same priority. If we are
            // adding a Deny, and one or more Deny entries already
            // exist, the new rule is added in the front. The same
            // goes for multiple non-deny entries at the same
            // priority.
            if rule.priority == r.priority {
                if rule.action().is_deny() || !r.action().is_deny() {
                    return RulePlace::Insert(i);
                }
            }
        }

        RulePlace::End
    }

    fn new(layer: String, dir: Direction) -> Self {
        Self { layer, dir, rules: vec![], next_id: 0 }
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
}

#[cfg(any(feature = "std", test))]
pub unsafe fn __dtrace_probe_layer__process__entry(
    _dir: uintptr_t,
    _name: uintptr_t,
    _ifid: uintptr_t,
) {
    ()
}

#[cfg(any(feature = "std", test))]
pub unsafe fn __dtrace_probe_layer__process__return(
    _dir: uintptr_t,
    _name: uintptr_t,
    _ifid: uintptr_t,
    _res: uintptr_t,
) {
    ()
}

#[cfg(all(not(feature = "std"), not(test)))]
extern "C" {
    pub fn __dtrace_probe_layer__process__entry(
        dir: uintptr_t,
        name: uintptr_t,
        ifid: uintptr_t,
    );

    pub fn __dtrace_probe_layer__process__return(
        dir: uintptr_t,
        name: uintptr_t,
        ifid: uintptr_t,
        res: uintptr_t,
    );
}

pub fn layer_process_entry_probe(
    dir: Direction,
    name: &str,
    ifid: &InnerFlowId,
) {
    let name_c = CString::new(name).unwrap();
    let ifid_arg = flow_id_sdt_arg::from(ifid);

    unsafe {
        __dtrace_probe_layer__process__entry(
            dir as uintptr_t,
            name_c.as_ptr() as uintptr_t,
            &ifid_arg as *const flow_id_sdt_arg as uintptr_t,
        );
    }
}

pub fn layer_process_return_probe(
    dir: Direction,
    name: &str,
    ifid: &InnerFlowId,
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
            let dir_c = match dir {
                Direction::In => CString::new("in").unwrap(),
                Direction::Out => CString::new("out").unwrap(),
            };
            let name_c = CString::new(name).unwrap();
            let ifid_arg = flow_id_sdt_arg::from(ifid);
            let res_c = CString::new(res_str).unwrap();

            unsafe {
                __dtrace_probe_layer__process__return(
                    dir_c.as_ptr() as uintptr_t,
                    name_c.as_ptr() as uintptr_t,
                    &ifid_arg as *const flow_id_sdt_arg as uintptr_t,
                    res_c.as_ptr() as uintptr_t,
                );
            }
        } else if #[cfg(feature = "usdt")] {
            use std::arch::asm;
            // XXX This would probably be better as separate probes;
            // for now this does the trick.
            let res_str = match res {
                Ok(v) => format!("{}", v),
                Err(e) => format!("ERROR: {:?}", e),
            };
            crate::opte_provider::layer_process_return!(
                || (dir, name, ifid, &res_str)
            );
        } else {
            let (_, _, _, _) = (dir, name, ifid, res);
        }
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
extern "C" {
    pub fn __dtrace_probe_rule__match(arg: uintptr_t);
}

#[repr(C)]
pub struct rule_match_sdt_arg {
    pub layer: *const c_char,
    pub dir: *const c_char,
    pub flow_id: *const flow_id_sdt_arg,
    pub rule_type: *const c_char,
}

pub fn rule_match_probe(
    layer: &str,
    dir: Direction,
    flow_id: &InnerFlowId,
    rule: &Rule<rule::Finalized>,
) {
    cfg_if! {
        if #[cfg(all(not(feature = "std"), not(test)))] {
            let action_str = rule.action().to_string();
            let layer_c = CString::new(layer).unwrap();
            let dir_c = match dir {
                Direction::In => CString::new("in").unwrap(),
                Direction::Out => CString::new("out").unwrap(),
            };
            let flow_id = flow_id_sdt_arg::from(flow_id);
            let action_str_c = CString::new(action_str).unwrap();

            let arg = rule_match_sdt_arg {
                layer: layer_c.as_ptr(),
                dir: dir_c.as_ptr(),
                flow_id: &flow_id,
                rule_type: action_str_c.as_ptr(),
            };

            unsafe {
                __dtrace_probe_rule__match(
                    &arg as *const rule_match_sdt_arg as uintptr_t,
                );
            }
        } else if #[cfg(feature = "usdt")] {
            use std::arch::asm;
            let action_str = rule.action().to_string();
            crate::opte_provider::rule__match!(
                || (layer, dir, flow_id.to_string(), action_str)
            );
        } else {
            let (_, _, _, _) = (layer, dir, flow_id, rule);
        }
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
extern "C" {
    pub fn __dtrace_probe_rule__no__match(arg: uintptr_t);
}

#[repr(C)]
pub struct rule_no_match_sdt_arg {
    pub layer: *const c_char,
    pub dir: *const c_char,
    pub flow_id: *const flow_id_sdt_arg,
}

pub fn rule_no_match_probe(layer: &str, dir: Direction, flow_id: &InnerFlowId) {
    cfg_if! {
        if #[cfg(all(not(feature = "std"), not(test)))] {
            let layer_c = CString::new(layer).unwrap();
            let dir_c = match dir {
                Direction::In => CString::new("in").unwrap(),
                Direction::Out => CString::new("out").unwrap(),
            };
            let flow_id = flow_id_sdt_arg::from(flow_id);

            let arg = rule_no_match_sdt_arg {
                layer: layer_c.as_ptr(),
                dir: dir_c.as_ptr(),
                flow_id: &flow_id,
            };

            unsafe {
                __dtrace_probe_rule__no__match(
                    &arg as *const rule_no_match_sdt_arg as uintptr_t,
                );
            }
        } else if #[cfg(feature = "usdt")] {
            use std::arch::asm;
            crate::opte_provider::rule__no__match!(
                || (layer, dir, flow_id.to_string())
            );
        } else {
            let (_, _, _) = (layer, dir, flow_id);
        }
    }
}

// We mark all the std-built probes as `unsafe`, not because they are,
// but in order to stay consistent with the externs, which are
// implicitly unsafe. This also keeps the compiler from throwing up a
// warning for every probe callsite when compiling with std.
//
// TODO In the future we could have these std versions of the probes
// modify some global state so that unit/functional tests can verify
// that they fire when expected. We could also wire them up as USDTs,
// allowing someone to inspect a test with DTrace.
#[cfg(any(feature = "std", test))]
pub unsafe fn __dtrace_probe_rule__deny(_arg: uintptr_t) {
    ()
}

#[cfg(all(not(feature = "std"), not(test)))]
extern "C" {
    pub fn __dtrace_probe_rule__deny(arg: uintptr_t);
}

#[repr(C)]
pub struct rule_deny_sdt_arg {
    pub layer: *const c_char,
    pub dir: *const c_char,
    pub flow_id: *const flow_id_sdt_arg,
}

pub fn rule_deny_probe(layer: &str, dir: Direction, flow_id: &InnerFlowId) {
    let layer_c = CString::new(layer).unwrap();
    let dir_c = match dir {
        Direction::In => CString::new("in").unwrap(),
        Direction::Out => CString::new("out").unwrap(),
    };
    let flow_id = flow_id_sdt_arg::from(flow_id);

    let arg = rule_deny_sdt_arg {
        // TODO: Sigh, I'm only doing this because some
        // platforms define c_char as u8, and I want to be
        // able to run unit tests on those other platforms.
        #[cfg(all(not(feature = "std"), not(test)))]
        layer: layer_c.as_ptr(),
        #[cfg(any(feature = "std", test))]
        layer: layer_c.as_ptr() as *const u8 as *const c_char,
        #[cfg(all(not(feature = "std"), not(test)))]
        dir: dir_c.as_ptr(),
        #[cfg(any(feature = "std", test))]
        dir: dir_c.as_ptr() as *const u8 as *const c_char,
        flow_id: &flow_id,
    };

    unsafe {
        __dtrace_probe_rule__deny(
            &arg as *const rule_deny_sdt_arg as uintptr_t,
        );
    }
}

#[cfg(any(feature = "std", test))]
pub unsafe fn __dtrace_probe_gen__desc__fail(
    _port: uintptr_t,
    _layer: uintptr_t,
    _dir: uintptr_t,
    _ifid: uintptr_t,
    _msg: uintptr_t,
) {
    ()
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
}

#[cfg(any(feature = "std", test))]
pub unsafe fn __dtrace_probe_gen__ht__fail(
    _port: uintptr_t,
    _layer: uintptr_t,
    _dir: uintptr_t,
    _ifid: uintptr_t,
    _msg: uintptr_t,
) {
    ()
}

#[cfg(all(not(feature = "std"), not(test)))]
extern "C" {
    pub fn __dtrace_probe_gen__ht__fail(
        port: uintptr_t,
        layer: uintptr_t,
        dir: uintptr_t,
        ifid: uintptr_t,
        msg: uintptr_t,
    );
}

#[test]
fn find_rule() {
    use crate::headers::{IpMeta, UlpMeta};
    use crate::ip4::Ipv4Meta;
    use crate::packet::{MetaGroup, PacketReader};
    use crate::rule::{self, Ipv4AddrMatch, Predicate};
    use crate::tcp::TcpMeta;

    let mut rule_table = RuleTable::new("test".to_string(), Direction::Out);
    let rule = Rule::new(
        1,
        Action::Static(Arc::new(rule::Identity::new("find_rule"))),
    );
    let cidr = "10.0.0.0/24".parse().unwrap();
    let rule = rule.add_predicate(Predicate::InnerSrcIp4(vec![
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

    let meta = PacketMeta {
        outer: Default::default(),
        inner: MetaGroup { ip: Some(ip), ulp: Some(ulp), ..Default::default() },
    };

    // The pkt/rdr aren't actually used in this case.
    let pkt = Packet::copy(&[0xA]);
    let mut rdr = PacketReader::new(&pkt, ());
    assert!(rule_table.find_match(&meta, &mut rdr).is_some());
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

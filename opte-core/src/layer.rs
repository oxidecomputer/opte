use core::fmt::{self, Display};
use core::mem;
use core::result;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::{String, ToString};
        use alloc::sync::Arc;
        use alloc::vec::Vec;
        use illumos_ddi_dki::uintptr_t;
    } else {
        use std::string::{String, ToString};
        use std::sync::Arc;
        use std::vec::Vec;
    }
}

use serde::{Deserialize, Serialize};

use crate::api::Ipv4Addr;
use crate::flow_table::FlowTable;
use crate::headers::{IpAddr, IpMeta, UlpMeta};
use crate::ioctl;
use crate::ip4::{self, Protocol};
use crate::packet::{Initialized, Packet, PacketMeta, PacketRead, Parsed};
use crate::port::meta::Meta;
use crate::rule::{
    self, flow_id_sdt_arg, ht_probe, Action, ActionDesc, Rule, RuleDump, HT,
};
use crate::sync::{KMutex, KMutexType};
use crate::time::Moment;
use crate::{CString, Direction, ExecCtx, LogLevel};

use illumos_ddi_dki::c_char;

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
    port_c: CString,
    name: String,
    name_c: CString,
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
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                let flow_id = flow_id_sdt_arg::from(ifid);
                let dir_c = CString::new(format!("{}", dir)).unwrap();
                let msg_c = CString::new(format!("{:?}", err)).unwrap();

                unsafe {
                    __dtrace_probe_gen__desc__fail(
                        self.port_c.as_ptr() as uintptr_t,
                        self.name_c.as_ptr() as uintptr_t,
                        dir_c.as_ptr() as uintptr_t,
                        &flow_id as *const flow_id_sdt_arg as uintptr_t,
                        msg_c.as_ptr() as uintptr_t,
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                use std::arch::asm;

                let port_s = self.port_c.to_str().unwrap();
                let name_s = self.name_c.to_str().unwrap();
                let flow_s = ifid.to_string();
                let msg_s = format!("{:?}", err);

                crate::opte_provider::gen__desc__fail!(
                    || (port_s, name_s, dir, flow_s, msg_s)
                );
            } else {
                let (_, _, _, _, _) =
                    (&self.port_c, &self.name_c, dir, ifid, err);
            }
        }
    }

    fn gen_ht_fail_probe(
        &self,
        dir: Direction,
        ifid: &InnerFlowId,
        err: &rule::GenHtError,
    ) {
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                let flow_id = flow_id_sdt_arg::from(ifid);
                let dir_c = CString::new(format!("{}", dir)).unwrap();
                let msg_c = CString::new(format!("{:?}", err)).unwrap();

                unsafe {
                    __dtrace_probe_gen__ht__fail(
                        self.port_c.as_ptr() as uintptr_t,
                        self.name_c.as_ptr() as uintptr_t,
                        dir_c.as_ptr() as uintptr_t,
                        &flow_id as *const flow_id_sdt_arg as uintptr_t,
                        msg_c.as_ptr() as uintptr_t,
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                use std::arch::asm;

                let port_s = self.port_c.to_str().unwrap();
                let flow_s = ifid.to_string();
                let err_s = format!("{:?}", err);

                crate::opte_provider::gen__ht__fail!(
                    || (port_s, &self.name, dir, flow_s, err_s)
                );
            } else {
                let (_, _, _) = (dir, ifid, err);
            }
        }
    }

    pub fn expire_flows(&self, now: Moment) {
        self.ft_in.lock().expire_flows(now);
        self.ft_out.lock().expire_flows(now);
    }

    pub fn layer_process_entry_probe(
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
                use std::arch::asm;

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
                let ifid_arg = flow_id_sdt_arg::from(ifid);
                let res_c = CString::new(res_str).unwrap();

                unsafe {
                    __dtrace_probe_layer__process__return(
                        dir.cstr_raw() as uintptr_t,
                        self.port_c.as_ptr() as uintptr_t,
                        self.name_c.as_ptr() as uintptr_t,
                        &ifid_arg as *const flow_id_sdt_arg as uintptr_t,
                        res_c.as_ptr() as uintptr_t,
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                use std::arch::asm;

                let port_s = self.port_c.to_str().unwrap();
                let ifid_s = ifid.to_string();
                // XXX This would probably be better as separate probes;
                // for now this does the trick.
                let res_s = match res {
                    Ok(v) => format!("{}", v),
                    Err(e) => format!("ERROR: {:?}", e),
                };
                crate::opte_provider::layer__process__return!(
                    || (dir, port_s, &self.name, ifid_s, &res_s)
                );
            } else {
                let (_, _, _) = (dir, ifid, res);
            }
        }
    }

    /// Return the name of the layer.
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn new(name: &str, port: &str, actions: Vec<Action>) -> Self {
        let port_c = CString::new(port).unwrap();
        let name_c = CString::new(name).unwrap();

        Layer {
            actions,
            name: name.to_string(),
            name_c,
            port_c: port_c.clone(),
            ft_in: KMutex::new(
                FlowTable::new(port, &format!("{}_in", name), None, None),
                KMutexType::Driver,
            ),
            ft_out: KMutex::new(
                FlowTable::new(port, &format!("{}_out", name), None, None),
                KMutexType::Driver,
            ),
            rules_in: KMutex::new(
                RuleTable::new(port, name, Direction::In),
                KMutexType::Driver,
            ),
            rules_out: KMutex::new(
                RuleTable::new(port, name, Direction::Out),
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
        let ifid = InnerFlowId::from(pkt.meta());
        self.layer_process_entry_probe(dir, &ifid);
        let res = match dir {
            Direction::Out => self.process_out(ectx, pkt, &ifid, hts, meta),
            Direction::In => self.process_in(ectx, pkt, &ifid, hts, meta),
        };
        self.layer_process_return_probe(dir, &ifid, &res);
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
        if let Some(entry) = self.ft_in.lock().get_mut(&ifid) {
            entry.hit();
            let desc = entry.state();
            let ht = desc.gen_ht(Direction::In);
            hts.push(ht.clone());

            ht.run(pkt.meta_mut());

            let ifid_after = InnerFlowId::from(pkt.meta());
            ht_probe(
                &self.port_c,
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
                self.rule_deny_probe(Direction::In, ifid);
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

                let ifid_after = InnerFlowId::from(pkt.meta());

                ht_probe(
                    &self.port_c,
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

                // TODO kill unwrap
                self.ft_in.lock().add(ifid.clone(), desc.clone()).unwrap();

                ht_in.run(pkt.meta_mut());

                let ifid_after = InnerFlowId::from(pkt.meta());

                ht_probe(
                    &self.port_c,
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
                let out_ifid = InnerFlowId::from(pkt.meta()).dual();
                // TODO okay time to deal with the fallout of this
                // returning an error and see how the info percolates
                // up the processing chain.
                //
                // TODO#2 On second thought this bleeds into a whole
                // thing about restructuring the various error types.
                // While putting everything in OpteError is certainly
                // conveinent it feels like it might lose some
                // fidelity in places. It might be that we want a
                // handful of different error types like admin vs.
                // processing or maybe just allow some of the more
                // specific error types around layer processing to
                // nest into the OpteError type. But at this very
                // moment I need to get some other stuff done to
                // unblock other work. So for now I've marked all this
                // places with `TODO kill unwrap` and should be the
                // first thing I come back to after unbloking others.
                //
                // TODO kill unwrap
                self.ft_out.lock().add(out_ifid, desc).unwrap();

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
        if let Some(entry) = self.ft_out.lock().get_mut(&ifid) {
            entry.hit();
            let desc = entry.state();
            let ht = desc.gen_ht(Direction::Out);
            hts.push(ht.clone());

            ht.run(pkt.meta_mut());

            let ifid_after = InnerFlowId::from(pkt.meta());
            ht_probe(
                &self.port_c,
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
                self.rule_deny_probe(Direction::Out, ifid);
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

                let ifid_after = InnerFlowId::from(pkt.meta());

                ht_probe(
                    &self.port_c,
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

                // TODO kill unwrap
                self.ft_out.lock().add(ifid.clone(), desc.clone()).unwrap();

                ht_out.run(pkt.meta_mut());

                let ifid_after = InnerFlowId::from(pkt.meta());

                ht_probe(
                    &self.port_c,
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
                let in_ifid = InnerFlowId::from(pkt.meta()).dual();
                // TODO kill unwrap
                self.ft_in.lock().add(in_ifid, desc).unwrap();

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

    pub fn rule_deny_probe(&self, dir: Direction, flow_id: &InnerFlowId) {
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
                use std::arch::asm;

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
}

pub static FLOW_ID_DEFAULT: InnerFlowId = InnerFlowId {
    proto: Protocol::Reserved,
    src_ip: IpAddr::Ip4(ip4::IPV4_ANY_ADDR),
    src_port: 0,
    dst_ip: IpAddr::Ip4(ip4::IPV4_ANY_ADDR),
    dst_port: 0,
};

#[derive(
    Clone,
    Debug,
    Default,
    Deserialize,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
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

impl From<&PacketMeta> for InnerFlowId {
    fn from(meta: &PacketMeta) -> Self {
        let (proto, src_ip, dst_ip) = match &meta.inner.ip {
            Some(IpMeta::Ip4(ip4)) => {
                (ip4.proto, IpAddr::Ip4(ip4.src), IpAddr::Ip4(ip4.dst))
            }
            Some(IpMeta::Ip6(ip6)) => {
                (ip6.proto, IpAddr::Ip6(ip6.src), IpAddr::Ip6(ip6.dst))
            }
            None => (
                Protocol::Reserved,
                IpAddr::Ip4(Ipv4Addr::from([0; 4])),
                IpAddr::Ip4(Ipv4Addr::from([0; 4])),
            ),
        };

        let (src_port, dst_port) = match &meta.inner.ulp {
            Some(UlpMeta::Tcp(tcp)) => (tcp.src, tcp.dst),
            Some(UlpMeta::Udp(udp)) => (udp.src, udp.dst),
            None => (0, 0),
        };

        InnerFlowId { proto, src_ip, src_port, dst_ip, dst_port }
    }
}

// TODO move this into Layer itself.
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
        meta: &PacketMeta,
        rdr: &'b mut R,
    ) -> Option<&Rule<rule::Finalized>>
    where
        R: PacketRead<'a>,
    {
        for (_, r) in &self.rules {
            if r.is_match(meta, rdr) {
                self.rule_match_probe(&InnerFlowId::from(meta), &r);
                return Some(r);
            }
        }

        self.rule_no_match_probe(self.dir, &InnerFlowId::from(meta));
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
                use std::arch::asm;

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
                use std::arch::asm;

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
        ifid: uintptr_t,
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

#[test]
fn find_rule() {
    use crate::headers::{IpMeta, UlpMeta};
    use crate::ip4::Ipv4Meta;
    use crate::packet::{MetaGroup, PacketReader};
    use crate::rule::{self, Ipv4AddrMatch, Predicate};
    use crate::tcp::TcpMeta;

    let mut rule_table = RuleTable::new("port", "test", Direction::Out);
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

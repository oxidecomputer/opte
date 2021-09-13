#[cfg(all(not(feature = "std"), not(test)))]
use alloc::prelude::v1::*;
#[cfg(any(feature = "std", test))]
use std::prelude::v1::*;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::sync::Arc;
#[cfg(any(feature = "std", test))]
use std::sync::Arc;

use std::convert::TryFrom;
use std::fmt::{self, Display};
use std::mem;

use serde::{Deserialize, Serialize};

use crate::flow_table::{FlowEntryDump, FlowTable};
use crate::headers::{IpMeta, UlpMeta};
use crate::ip4::{Ipv4Addr, Protocol};
use crate::packet::{
    Initialized, Packet, PacketMeta, PacketRead, PacketReader, Parsed,
};
use crate::rule::{
    flow_id_sdt_arg, ht_fire_probe, Action, ActionDesc, Resources, Rule,
    RuleAction, RuleDump, HT,
};
use crate::sync::{KMutex, KMutexType};
use crate::{CString, Direction};

use illumos_ddi_dki::{c_char, uintptr_t};

#[cfg(all(not(feature = "std"), not(test)))]
use illumos_ddi_dki::hrtime_t;
#[cfg(any(feature = "std", test))]
use std::time::Instant;

pub enum LayerResult {
    Allow,
    Deny,
    Hairpin(Packet<Initialized>),
}

pub struct Layer {
    name: String,
    actions: Vec<Action>,
    ft_in: KMutex<FlowTable<Arc<dyn ActionDesc>>>,
    ft_out: KMutex<FlowTable<Arc<dyn ActionDesc>>>,
    rules_in: KMutex<RuleTable>,
    rules_out: KMutex<RuleTable>,
}

impl Layer {
    pub fn add_rule(&self, dir: Direction, rule: Rule) {
        match dir {
            Direction::Out => self.rules_out.lock().unwrap().add(rule),
            Direction::In => self.rules_in.lock().unwrap().add(rule),
        }
    }

    pub fn dump(&self) -> LayerDumpResp {
        let rules_in = self.rules_in.lock().unwrap().dump();
        let rules_out = self.rules_out.lock().unwrap().dump();
        let ft_in = self.ft_in.lock().unwrap().dump();
        let ft_out = self.ft_out.lock().unwrap().dump();
        LayerDumpResp {
            name: self.name.clone(),
            ft_in,
            ft_out,
            rules_in,
            rules_out,
        }
    }

    #[cfg(all(not(feature = "std"), not(test)))]
    pub fn expire_flows(&self, now: hrtime_t) {
        self.ft_in.lock().unwrap().expire_flows(now);
        self.ft_out.lock().unwrap().expire_flows(now);
    }

    #[cfg(any(feature = "std", test))]
    pub fn expire_flows(&self, now: Instant) {
        self.ft_in.lock().unwrap().expire_flows(now);
        self.ft_out.lock().unwrap().expire_flows(now);
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn new<S>(name: S, actions: Vec<Action>) -> Self
    where
        S: AsRef<str> + ToString,
    {
        Layer {
            actions,
            name: name.to_string(),
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

    pub fn num_rules(&self, dir: Direction) -> usize {
        match dir {
            Direction::Out => self.rules_out.lock().unwrap().num_rules(),
            Direction::In => self.rules_in.lock().unwrap().num_rules(),
        }
    }

    pub fn process(
        &self,
        dir: Direction,
        meta: &mut PacketMeta,
        rdr: &mut PacketReader<Parsed, ()>,
        hts: &mut Vec<HT>,
        resources: &Resources,
    ) -> LayerResult {
        layer_process_entry_probe(dir, &self.name);
        let res = match dir {
            Direction::Out => self.process_out(meta, rdr, hts, resources),
            Direction::In => self.process_in(meta, rdr, hts, resources),
        };
        layer_process_return_probe(dir, &self.name);
        res
    }

    fn process_in(
        &self,
        meta: &mut PacketMeta,
        rdr: &mut PacketReader<Parsed, ()>,
        hts: &mut Vec<HT>,
        resources: &Resources,
    ) -> LayerResult {
        let ifid = InnerFlowId::try_from(&*meta).unwrap();

        // We have no FlowId, thus there can be no FlowTable entry.
        if ifid == FLOW_ID_DEFAULT {
            return self.process_in_rules(ifid, meta, rdr, hts, resources);
        }

        // Do we have a FlowTable entry? If so, use it.
        if let Some((_, entry)) = self.ft_in.lock().unwrap().get_mut(&ifid) {
            entry.hit();
            let desc = entry.get_state();
            let ht = desc.gen_ht(Direction::In);
            hts.push(ht.clone());

            ht.run(meta);

            let ifid_after = InnerFlowId::try_from(&*meta).unwrap();
            ht_fire_probe(
                &format!("{}-ft", self.name),
                Direction::In,
                &ifid,
                &ifid_after,
            );

            // if let Some(ctx) = state.ra.ctx {
            //     ctx.exec(meta, resources, &mut [0; 0])
            //         .expect("failed action context exec()");
            // };

            return LayerResult::Allow;
        }

        // No FlowTable entry, perhaps there is a matching Rule?
        self.process_in_rules(ifid, meta, rdr, hts, resources)
    }

    fn process_in_rules(
        &self,
        ifid: InnerFlowId,
        meta: &mut PacketMeta,
        rdr: &mut PacketReader<Parsed, ()>,
        hts: &mut Vec<HT>,
        resources: &Resources,
    ) -> LayerResult {
        let lock = self.rules_in.lock().unwrap();
        if let Some(rule) = lock.find_match(meta, rdr) {
            match &rule.action {
                RuleAction::Deny => {
                    rule_deny_probe(&self.name, Direction::In, &ifid);
                    return LayerResult::Deny;
                }

                RuleAction::Allow(idx) => {
                    match &self.actions[*idx] {
                        Action::Static(action) => {
                            let ht = action.gen_ht(Direction::In, ifid);
                            hts.push(ht.clone());

                            ht.run(meta);

                            let ifid_after =
                                InnerFlowId::try_from(&*meta).unwrap();

                            ht_fire_probe(
                                &format!("{}-rt", self.name),
                                Direction::In,
                                &ifid,
                                &ifid_after,
                            );

                            return LayerResult::Allow;
                        }

                        Action::Stateful(action) => {
                            // TODO deal with failure
                            let desc = action.gen_desc(ifid, resources);
                            let ht_in = desc.gen_ht(Direction::In);
                            hts.push(ht_in.clone());

                            self.ft_in.lock().unwrap().add(ifid, desc.clone());

                            ht_in.run(meta);

                            let ifid_after =
                                InnerFlowId::try_from(&*meta).unwrap();

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
                                InnerFlowId::try_from(&*meta).unwrap().dual();
                            self.ft_out.lock().unwrap().add(out_ifid, desc);

                            // if let Some(ctx) = ra_in.ctx {
                            //     ctx.exec(flow_id, resources, &mut [0; 0]);
                            // }

                            return LayerResult::Allow;
                        }

                        Action::Hairpin(action) => {
                            match action.gen_packet(meta, rdr) {
                                Ok(pkt) => {
                                    return LayerResult::Hairpin(pkt);
                                }

                                Err(e) => {
                                    panic!("failed to gen_packet: {:?}", e);
                                }
                            }
                        }
                    }
                }
            }
        }

        // TODO: Currently a `Layer` is not expected to define a total
        // function over the set of all possible input. Rather it can
        // define rules over a subset of the input and anything that
        // doesn't match will be allowed implicitly. We could `Deny`
        // by default, but it will require that these types of layers
        // define a final rule which matches all packets and returns
        // `Allow`. We could also set a flag at Layer creation to
        // determines if it allows/denies by default.
        return LayerResult::Allow;
    }

    fn process_out(
        &self,
        meta: &mut PacketMeta,
        rdr: &mut PacketReader<Parsed, ()>,
        hts: &mut Vec<HT>,
        resources: &Resources,
    ) -> LayerResult {
        let ifid = InnerFlowId::try_from(&*meta).unwrap();

        // We have no FlowId, thus there can be no FlowTable entry.
        if ifid == FLOW_ID_DEFAULT {
            return self.process_out_rules(ifid, meta, rdr, hts, resources);
        }

        // Do we have a FlowTable entry? If so, use it.
        if let Some((_, entry)) = self.ft_out.lock().unwrap().get_mut(&ifid) {
            entry.hit();
            let desc = entry.get_state();
            let ht = desc.gen_ht(Direction::Out);
            hts.push(ht.clone());

            ht.run(meta);

            let ifid_after = InnerFlowId::try_from(&*meta).unwrap();
            ht_fire_probe(
                &format!("{}-ft", self.name),
                Direction::Out,
                &ifid,
                &ifid_after,
            );

            // if let Some(ctx) = state.ra.ctx {
            //     ctx.exec(flow_id, resources, &mut [0; 0])
            //         .expect("failed action context exec()");
            // };

            return LayerResult::Allow;
        }

        // No FlowTable entry, perhaps there is matching Rule?
        self.process_out_rules(ifid, meta, rdr, hts, resources)
    }

    fn process_out_rules(
        &self,
        ifid: InnerFlowId,
        meta: &mut PacketMeta,
        rdr: &mut PacketReader<Parsed, ()>,
        hts: &mut Vec<HT>,
        resources: &Resources,
    ) -> LayerResult {
        let lock = self.rules_out.lock().unwrap();

        if let Some(rule) = lock.find_match(meta, rdr) {
            match &rule.action {
                RuleAction::Deny => {
                    rule_deny_probe(&self.name, Direction::Out, &ifid);
                    return LayerResult::Deny;
                }

                RuleAction::Allow(idx) => {
                    match &self.actions[*idx] {
                        Action::Static(action) => {
                            let ht = action.gen_ht(Direction::Out, ifid);
                            hts.push(ht.clone());

                            ht.run(meta);

                            let ifid_after =
                                InnerFlowId::try_from(&*meta).unwrap();

                            ht_fire_probe(
                                &format!("{}-rt", self.name),
                                Direction::Out,
                                &ifid,
                                &ifid_after,
                            );

                            return LayerResult::Allow;
                        }

                        Action::Stateful(action) => {
                            // TODO deal with failure
                            let desc = action.gen_desc(ifid, resources);
                            let ht_out = desc.gen_ht(Direction::Out);
                            hts.push(ht_out.clone());

                            self.ft_out.lock().unwrap().add(ifid, desc.clone());

                            ht_out.run(meta);

                            let ifid_after =
                                InnerFlowId::try_from(&*meta).unwrap();

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
                            let in_ifid =
                                InnerFlowId::try_from(&*meta).unwrap().dual();
                            self.ft_in.lock().unwrap().add(in_ifid, desc);

                            // if let Some(ctx) = ra_out2.ctx {
                            //     ctx.exec(flow_id, resources, &mut [0; 0]);
                            // }

                            return LayerResult::Allow;
                        }

                        Action::Hairpin(action) => {
                            match action.gen_packet(meta, rdr) {
                                Ok(pkt) => {
                                    return LayerResult::Hairpin(pkt);
                                }

                                Err(e) => {
                                    // TODO SDT probe
                                    // TODO error stat
                                    todo!("failed to gen_packet: {:?}", e);
                                }
                            }
                        }
                    }
                }
            }
        }

        // TODO: Currently a `Layer` is not expected to define a total
        // function over the set of all possible input. Rather it can
        // define rules over a subset of the input and anything that
        // doesn't match will be allowed implicitly. We could `Deny`
        // by default, but it will require that these types of layers
        // define a final rule which matches all packets and returns
        // `Allow`. We could also set a flag at Layer creation to
        // determines if it allows/denies by default.
        return LayerResult::Allow;
    }

    pub fn remove_rule(&self, dir: Direction, id: u64) -> Result<(), String> {
        let res = match dir {
            Direction::In => self.rules_in.lock().unwrap().remove(id),
            Direction::Out => self.rules_out.lock().unwrap().remove(id),
        };

        match res {
            Ok(_) => Ok(()),

            Err(RuleRemoveErr::NotFound) => {
                Err(format!("rule {} not found", id))
            }
        }
    }
}

// The follow functions are useful for validating state during
// testing. If one of these functions becomes useful outside of
// testing, then add it to the impl block above.
#[cfg(test)]
impl Layer {
    pub fn num_flows(&self, dir: Direction) -> u32 {
        match dir {
            Direction::Out => self.ft_out.lock().unwrap().num_flows(),
            Direction::In => self.ft_in.lock().unwrap().num_flows(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum IpAddr {
    Ip4(Ipv4Addr),
    // TODO replace with real type at some point.
    Ip6([u8; 16]),
}

impl Default for IpAddr {
    fn default() -> Self {
        IpAddr::Ip4(Default::default())
    }
}

impl Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IpAddr::Ip4(ip4) => write!(f, "{}", ip4),
            IpAddr::Ip6(_) => write!(f, "<IPv6 addr>"),
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

#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize,
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

impl TryFrom<&PacketMeta> for InnerFlowId {
    type Error = String;

    fn try_from(meta: &PacketMeta) -> Result<Self, Self::Error> {
        let (proto, src_ip, dst_ip) = match &meta.inner_ip {
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

        let (src_port, dst_port) = match &meta.ulp {
            Some(UlpMeta::Tcp(tcp)) => (tcp.src, tcp.dst),
            Some(UlpMeta::Udp(udp)) => (udp.src, udp.dst),
            // TODO Still need to pull the ULP src/dst from the ICMP
            // Destination Unreachable message, hopefully the 666
            // gives it away. But we don't really need this until we
            // are concerned with NAT'ing DU messages back to the
            // guest.
            Some(UlpMeta::IcmpDu(_icmp)) => (666, 666),
            // ICMP Echo has an identifier to act as the source port,
            // but nothing to act as the dest port. We use zero to
            // stand in for the dest port, as its value really doesn't
            // matter in this case -- we just need something to
            // complete the FlowId.
            Some(UlpMeta::IcmpEcho(icmp)) => (icmp.id, 0),
            // TODO Still need to pull the ULP src/dst from the ICMP
            // Redirect message, hopefully the 777 gives it away.
            Some(UlpMeta::IcmpRedirect(_icmp)) => (777, 777),

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
    rules: Vec<(u64, Rule)>,
    next_id: u64,
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

impl RuleTable {
    // TODO Add SDT probe for rule add.
    fn add(&mut self, rule: Rule) {
        match self.find_pos(&rule) {
            RulePlace::End => self.rules.push((self.next_id, rule)),
            RulePlace::Insert(idx) => {
                self.rules.insert(idx, (self.next_id, rule))
            }
        }
        self.next_id += 1;
    }

    fn dump(&self) -> Vec<(u64, RuleDump)> {
        let mut dump = Vec::new();
        for (id, r) in &self.rules {
            dump.push((*id, RuleDump::from(r)));
        }
        dump
    }

    fn find_match<R>(&self, meta: &PacketMeta, rdr: &mut R) -> Option<&Rule>
    where
        R: PacketRead,
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

    // Determine either a) if the Rule already exists or b) if it
    // doesn't, the position in which to insert the rule.
    fn find_pos(&self, rule: &Rule) -> RulePlace {
        for (i, (_, r)) in self.rules.iter().enumerate() {
            if rule.priority < r.priority {
                return RulePlace::Insert(i);
            }

            // Deny takes precedence at the same priority. If we are
            // adding a Deny, and one or more Deny entries already
            // exist, the new rule is added in the front. The same
            // goes for multiple Allow entries at the same priority.
            if rule.priority == r.priority {
                match (&rule.action, &r.action) {
                    (RuleAction::Deny, _) | (_, RuleAction::Allow(_)) => {
                        return RulePlace::Insert(i);
                    }

                    _ => (),
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
    fn remove(&mut self, id: u64) -> Result<(), RuleRemoveErr> {
        for (rule_idx, (rule_id, _)) in self.rules.iter().enumerate() {
            if id == *rule_id {
                let _ = self.rules.remove(rule_idx);
                return Ok(());
            }
        }

        Err(RuleRemoveErr::NotFound)
    }
}

#[cfg(any(feature = "std", test))]
pub unsafe fn __dtrace_probe_layer__process__entry(
    _dir: uintptr_t,
    _name: uintptr_t,
) {
    ()
}

#[cfg(any(feature = "std", test))]
pub unsafe fn __dtrace_probe_layer__process__return(
    _dir: uintptr_t,
    _name: uintptr_t,
) {
    ()
}

#[cfg(all(not(feature = "std"), not(test)))]
extern "C" {
    pub fn __dtrace_probe_layer__process__entry(
        dir: uintptr_t,
        name: uintptr_t,
    );

    pub fn __dtrace_probe_layer__process__return(
        dir: uintptr_t,
        name: uintptr_t,
    );
}

pub fn layer_process_entry_probe(dir: Direction, name: &str) {
    let name_c = CString::new(name).unwrap();

    unsafe {
        __dtrace_probe_layer__process__entry(
            dir as uintptr_t,
            name_c.as_ptr() as uintptr_t,
        );
    }
}

pub fn layer_process_return_probe(dir: Direction, name: &str) {
    let name_c = CString::new(name).unwrap();

    unsafe {
        __dtrace_probe_layer__process__return(
            dir as uintptr_t,
            name_c.as_ptr() as uintptr_t,
        );
    }
}

#[cfg(any(feature = "std", test))]
pub unsafe fn __dtrace_probe_rule__match(_arg: uintptr_t) {
    ()
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
    rule: &Rule,
) {
    let layer_c = CString::new(layer).unwrap();
    let dir_c = match dir {
        Direction::In => CString::new("in").unwrap(),
        Direction::Out => CString::new("out").unwrap(),
    };
    let flow_id = flow_id_sdt_arg::from(flow_id);
    let rule_type_c = match rule.action {
        RuleAction::Allow(idx) => {
            CString::new(format!("allow({})", idx)).unwrap()
        }

        RuleAction::Deny => CString::new("deny").unwrap(),
    };

    let arg = rule_match_sdt_arg {
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
        #[cfg(all(not(feature = "std"), not(test)))]
        rule_type: rule_type_c.as_ptr(),
        #[cfg(any(feature = "std", test))]
        rule_type: rule_type_c.as_ptr() as *const u8 as *const c_char,
    };

    unsafe {
        __dtrace_probe_rule__match(
            &arg as *const rule_match_sdt_arg as uintptr_t,
        );
    }
}

#[cfg(any(feature = "std", test))]
pub unsafe fn __dtrace_probe_rule__no__match(_arg: uintptr_t) {
    ()
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
    let layer_c = CString::new(layer).unwrap();
    let dir_c = match dir {
        Direction::In => CString::new("in").unwrap(),
        Direction::Out => CString::new("out").unwrap(),
    };
    let flow_id = flow_id_sdt_arg::from(flow_id);

    let arg = rule_no_match_sdt_arg {
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
        __dtrace_probe_rule__no__match(
            &arg as *const rule_no_match_sdt_arg as uintptr_t,
        );
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

#[test]
fn find_rule() {
    use crate::headers::{IpMeta, Ipv4Meta, TcpMeta, UlpMeta};
    use crate::rule::{Ipv4AddrMatch, Predicate};

    let mut rule_table = RuleTable::new("test".to_string(), Direction::Out);
    let mut rule = Rule::new(1, RuleAction::Allow(0));
    let cidr = "10.0.0.0/24".parse().unwrap();
    rule.add_predicate(Predicate::InnerSrcIp4(vec![Ipv4AddrMatch::Prefix(
        cidr,
    )]));

    rule_table.add(rule);

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

    let meta =
        PacketMeta { inner_ip: Some(ip), ulp: Some(ulp), ..Default::default() };
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

// ================================================================
// ioctl interface
// ================================================================

/// Dump various information about a `Layer` for use in debugging or
/// administrative purposes.
///
/// * The Layer name.
/// * The inbound and outbound rule tables.
/// * The inbound and outbound flow tables.
///
/// *name*: The name of the `Layer` to dump.
#[derive(Debug, Deserialize, Serialize)]
pub struct LayerDumpReq {
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LayerDumpResp {
    pub name: String,
    pub rules_in: Vec<(u64, RuleDump)>,
    pub rules_out: Vec<(u64, RuleDump)>,
    pub ft_in: Vec<(InnerFlowId, FlowEntryDump)>,
    pub ft_out: Vec<(InnerFlowId, FlowEntryDump)>,
}

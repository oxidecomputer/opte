// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use super::headers::{UlpGenericModify, UlpHeaderAction, UlpMetaModify};
use super::ip4::Ipv4Meta;
use super::layer::InnerFlowId;
use super::port::meta::ActionMeta;
use super::rule::{
    self, ActionDesc, AllowOrDeny, DataPredicate, FiniteResource, HdrTransform,
    Predicate, Resource, ResourceEntry, ResourceError, StatefulAction,
};
use crate::ddi::sync::{KMutex, KMutexType};
use core::fmt;
use core::ops::RangeInclusive;
use opte_api::{Direction, Ipv4Addr};

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::collections::btree_map::BTreeMap;
        use alloc::string::ToString;
        use alloc::sync::Arc;
        use alloc::vec::Vec;
    } else {
        use std::collections::btree_map::BTreeMap;
        use std::string::ToString;
        use std::sync::Arc;
        use std::vec::Vec;
    }
}

#[derive(Clone, Copy)]
pub struct NatPoolEntry {
    ip: Ipv4Addr,
    port: u16,
}

impl ResourceEntry for NatPoolEntry {}

pub struct NatPool {
    // Map private IP to public IP + free list of ports
    free_list:
        KMutex<BTreeMap<Ipv4Addr, (Ipv4Addr, RangeInclusive<u16>, Vec<u16>)>>,
}

impl NatPool {
    pub fn add(
        &self,
        priv_ip: Ipv4Addr,
        pub_ip: Ipv4Addr,
        pub_ports: RangeInclusive<u16>,
    ) {
        let free_list = pub_ports.clone().collect();
        self.free_list.lock().insert(priv_ip, (pub_ip, pub_ports, free_list));
    }

    pub fn num_avail(&self, priv_ip: Ipv4Addr) -> Result<usize, ResourceError> {
        match self.free_list.lock().get(&priv_ip) {
            Some((_, _, ports)) => Ok(ports.len()),
            _ => Err(ResourceError::NoMatch(priv_ip.to_string())),
        }
    }

    pub fn mapping(
        &self,
        priv_ip: Ipv4Addr,
    ) -> Option<(Ipv4Addr, RangeInclusive<u16>)> {
        self.free_list
            .lock()
            .get(&priv_ip)
            .map(|(pub_ip, range, _)| (pub_ip.clone(), range.clone()))
    }

    pub fn new() -> Self {
        NatPool { free_list: KMutex::new(BTreeMap::new(), KMutexType::Driver) }
    }

    // A helper function to verify correct operation during testing.
    #[cfg(test)]
    fn verify_available(
        &self,
        priv_ip: Ipv4Addr,
        pub_ip: Ipv4Addr,
        pub_port: u16,
    ) -> bool {
        match self.free_list.lock().get(&priv_ip) {
            Some((pip, _, free_list)) => {
                if pub_ip != *pip {
                    return false;
                }

                for p in free_list {
                    if pub_port == *p {
                        return true;
                    }
                }

                false
            }

            None => false,
        }
    }
}

impl Resource for NatPool {}

impl FiniteResource for NatPool {
    type Key = Ipv4Addr;
    type Entry = NatPoolEntry;

    fn obtain(&self, priv_ip: &Ipv4Addr) -> Result<Self::Entry, ResourceError> {
        match self.free_list.lock().get_mut(&priv_ip) {
            Some((ip, _, ports)) => {
                if ports.len() == 0 {
                    return Err(ResourceError::Exhausted);
                }

                Ok(Self::Entry { ip: *ip, port: ports.pop().unwrap() })
            }

            None => Err(ResourceError::NoMatch(priv_ip.to_string())),
        }
    }

    fn release(&self, priv_ip: &Ipv4Addr, entry: Self::Entry) {
        match self.free_list.lock().get_mut(&priv_ip) {
            Some((_ip, _, ports)) => {
                ports.push(entry.port);
            }

            None => {
                panic!("cannot release port to unknown mapping: {}", priv_ip);
            }
        }
    }
}

#[derive(Clone)]
pub struct SNat4 {
    priv_ip: Ipv4Addr,
    ip_pool: Arc<NatPool>,
}

impl SNat4 {
    pub fn new(addr: Ipv4Addr, ip_pool: Arc<NatPool>) -> Self {
        SNat4 { priv_ip: addr.into(), ip_pool }
    }
}

impl fmt::Display for SNat4 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (pub_ip, ports) = self.ip_pool.mapping(self.priv_ip).unwrap();
        write!(f, "{}:{}-{}", pub_ip, ports.start(), ports.end())
    }
}

impl StatefulAction for SNat4 {
    fn gen_desc(
        &self,
        flow_id: &InnerFlowId,
        _meta: &mut ActionMeta,
    ) -> rule::GenDescResult {
        let pool = &self.ip_pool;
        let priv_port = flow_id.src_port;
        match pool.obtain(&self.priv_ip) {
            Ok(nat) => {
                let desc = SNat4Desc {
                    pool: pool.clone(),
                    priv_ip: self.priv_ip,
                    priv_port: priv_port,
                    nat,
                };

                Ok(AllowOrDeny::Allow(Arc::new(desc)))
            }

            // XXX This needs improving.
            Err(_e) => Err(rule::GenDescError::ResourceExhausted {
                name: "SNAT Pool".to_string(),
            }),
        }
    }

    // XXX we should be able to set implicit predicates if we add an
    // IpCidr field to describe which subnet the client is on; but for
    // now just keep the predicates fully explicit.
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        (vec![], vec![])
    }
}

#[derive(Clone)]
pub struct SNat4Desc {
    pool: Arc<NatPool>,
    nat: NatPoolEntry,
    priv_ip: Ipv4Addr,
    priv_port: u16,
}

pub const SNAT4_NAME: &'static str = "SNAT4";

impl ActionDesc for SNat4Desc {
    fn gen_ht(&self, dir: Direction) -> HdrTransform {
        match dir {
            // Outbound traffic needs it's source IP and source port
            Direction::Out => HdrTransform {
                name: SNAT4_NAME.to_string(),
                inner_ip: Ipv4Meta::modify(Some(self.nat.ip), None, None),
                inner_ulp: UlpHeaderAction::Modify(UlpMetaModify {
                    generic: UlpGenericModify {
                        src_port: Some(self.nat.port),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
                ..Default::default()
            },

            // Inbound traffic needs its destination IP and
            // destination port mapped back to the private values that
            // the guest expects to see.
            Direction::In => HdrTransform {
                name: SNAT4_NAME.to_string(),
                inner_ip: Ipv4Meta::modify(None, Some(self.priv_ip), None),
                inner_ulp: UlpHeaderAction::Modify(UlpMetaModify {
                    generic: UlpGenericModify {
                        dst_port: Some(self.priv_port),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
                ..Default::default()
            },
        }
    }

    fn name(&self) -> &str {
        SNAT4_NAME
    }
}

impl Drop for SNat4Desc {
    fn drop(&mut self) {
        self.pool.release(&self.priv_ip, self.nat);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn snat4_desc_lifecycle() {
        use crate::engine::ether::{EtherMeta, ETHER_TYPE_IPV4};
        use crate::engine::headers::{IpMeta, UlpMeta};
        use crate::engine::ip4::Protocol;
        use crate::engine::packet::{MetaGroup, PacketMeta};
        use crate::engine::tcp::TcpMeta;
        use opte_api::MacAddr;

        let priv_mac = MacAddr::from([0x02, 0x08, 0x20, 0xd8, 0x35, 0xcf]);
        let dest_mac = MacAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d]);
        let priv_ip = "10.0.0.220".parse().unwrap();
        let priv_port = "4999".parse().unwrap();
        let pub_ip = "52.10.128.69".parse().unwrap();
        let pub_port = "8765".parse().unwrap();
        let outside_ip = "76.76.21.21".parse().unwrap();
        let outside_port = 80;

        let pool = Arc::new(NatPool::new());
        pool.add(priv_ip, pub_ip, 8765..=8765);
        let snat = SNat4::new(priv_ip, pool.clone());
        let mut action_meta = ActionMeta::new();
        assert!(pool.verify_available(priv_ip, pub_ip, pub_port));

        // ================================================================
        // Build the packet metadata
        // ================================================================
        let ether = EtherMeta {
            src: priv_mac,
            dst: dest_mac,
            ether_type: ETHER_TYPE_IPV4,
        };
        let ip = IpMeta::from(Ipv4Meta {
            src: priv_ip,
            dst: outside_ip,
            proto: Protocol::TCP,
        });
        let ulp = UlpMeta::from(TcpMeta {
            src: priv_port,
            dst: outside_port,
            flags: 0,
            seq: 0,
            ack: 0,
        });

        let mut pmo = PacketMeta {
            outer: Default::default(),
            inner: MetaGroup {
                ether: Some(ether),
                ip: Some(ip),
                ulp: Some(ulp),
                ..Default::default()
            },
        };

        // ================================================================
        // Verify descriptor generation.
        // ================================================================
        let flow_out = InnerFlowId::from(&pmo);
        let desc = match snat.gen_desc(&flow_out, &mut action_meta) {
            Ok(AllowOrDeny::Allow(desc)) => desc,
            _ => panic!("expected AllowOrDeny::Allow(desc) result"),
        };
        assert!(!pool.verify_available(priv_ip, pub_ip, pub_port));

        // ================================================================
        // Verify outbound header transformation
        // ================================================================
        let out_ht = desc.gen_ht(Direction::Out);
        out_ht.run(&mut pmo).unwrap();

        let ether_meta = pmo.inner.ether.as_ref().unwrap();
        assert_eq!(ether_meta.src, priv_mac);
        assert_eq!(ether_meta.dst, dest_mac);

        let ip4_meta = match pmo.inner.ip.as_ref().unwrap() {
            IpMeta::Ip4(v) => v,
            _ => panic!("expect Ipv4Meta"),
        };

        assert_eq!(ip4_meta.src, pub_ip);
        assert_eq!(ip4_meta.dst, outside_ip);
        assert_eq!(ip4_meta.proto, Protocol::TCP);

        let tcp_meta = match pmo.inner.ulp.as_ref().unwrap() {
            UlpMeta::Tcp(v) => v,
            _ => panic!("expect TcpMeta"),
        };

        assert_eq!(tcp_meta.src, pub_port);
        assert_eq!(tcp_meta.dst, outside_port);
        assert_eq!(tcp_meta.flags, 0);

        // ================================================================
        // Verify inbound header transformation.
        // ================================================================
        let ether = EtherMeta {
            src: dest_mac,
            dst: priv_mac,
            ether_type: ETHER_TYPE_IPV4,
        };
        let ip = IpMeta::from(Ipv4Meta {
            src: outside_ip,
            dst: pub_ip,
            proto: Protocol::TCP,
        });
        let ulp = UlpMeta::from(TcpMeta {
            src: outside_port,
            dst: pub_port,
            flags: 0,
            seq: 0,
            ack: 0,
        });

        let mut pmi = PacketMeta {
            outer: Default::default(),
            inner: MetaGroup {
                ether: Some(ether),
                ip: Some(ip),
                ulp: Some(ulp),
                ..Default::default()
            },
        };

        let in_ht = desc.gen_ht(Direction::In);
        in_ht.run(&mut pmi).unwrap();

        let ether_meta = pmi.inner.ether.as_ref().unwrap();
        assert_eq!(ether_meta.src, dest_mac);
        assert_eq!(ether_meta.dst, priv_mac);

        let ip4_meta = match pmi.inner.ip.as_ref().unwrap() {
            IpMeta::Ip4(v) => v,
            _ => panic!("expect Ipv4Meta"),
        };

        assert_eq!(ip4_meta.src, outside_ip);
        assert_eq!(ip4_meta.dst, priv_ip);
        assert_eq!(ip4_meta.proto, Protocol::TCP);

        let tcp_meta = match pmi.inner.ulp.as_ref().unwrap() {
            UlpMeta::Tcp(v) => v,
            _ => panic!("expect TcpMeta"),
        };

        assert_eq!(tcp_meta.src, outside_port);
        assert_eq!(tcp_meta.dst, priv_port);
        assert_eq!(tcp_meta.flags, 0);

        // ================================================================
        // Drop the descriptor and verify the IP/port resource is
        // handed back to the pool.
        // ================================================================
        drop(desc);
        assert!(pool.verify_available(priv_ip, pub_ip, pub_port));
    }

    #[test]
    fn nat_mappings() {
        let pool = NatPool::new();
        let priv1 = "192.168.2.8".parse::<Ipv4Addr>().unwrap();
        let priv2 = "192.168.2.33".parse::<Ipv4Addr>().unwrap();
        let public = "52.10.128.69".parse().unwrap();

        pool.add(priv1, public, 1025..=4096);
        pool.add(priv2, public, 4097..=8192);

        assert_eq!(pool.num_avail(priv1).unwrap(), 3072);
        let npe1 = match pool.obtain(&priv1) {
            Ok(npe) => npe,
            _ => panic!("failed to obtain mapping"),
        };
        assert_eq!(pool.num_avail(priv1).unwrap(), 3071);
        assert_eq!(npe1.ip, public);
        assert!(npe1.port >= 1025);
        assert!(npe1.port <= 4096);

        assert_eq!(pool.num_avail(priv2).unwrap(), 4096);
        let npe2 = match pool.obtain(&priv2) {
            Ok(npe) => npe,
            _ => panic!("failed to obtain mapping"),
        };
        assert_eq!(pool.num_avail(priv2).unwrap(), 4095);
        assert_eq!(npe2.ip, public);
        assert!(npe2.port >= 4097);
        assert!(npe2.port <= 8192);

        pool.release(&priv1, npe1);
        assert_eq!(pool.num_avail(priv1).unwrap(), 3072);
        pool.release(&priv2, npe2);
        assert_eq!(pool.num_avail(priv2).unwrap(), 4096);
    }
}

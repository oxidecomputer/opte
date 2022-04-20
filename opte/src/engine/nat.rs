use core::fmt;
use core::ops::Range;

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

use super::headers::{UlpGenericModify, UlpHeaderAction, UlpMetaModify};
use super::ip4::Ipv4Meta;
use super::layer::InnerFlowId;
use super::port::meta::Meta;
use super::rule::{
    self, ActionDesc, DataPredicate, Predicate, ResourceError, StatefulAction,
    HT,
};
use super::sync::{KMutex, KMutexType};
use crate::api::{Direction, Ipv4Addr, MacAddr};

pub struct NatPool {
    // Map private IP to public IP + free list of ports
    free_list: KMutex<BTreeMap<Ipv4Addr, (Ipv4Addr, Range<u16>, Vec<u16>)>>,
}

impl NatPool {
    pub fn add(
        &mut self,
        priv_ip: Ipv4Addr,
        pub_ip: Ipv4Addr,
        pub_ports: Range<u16>,
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

    pub fn mapping(&self, priv_ip: Ipv4Addr) -> Option<(Ipv4Addr, Range<u16>)> {
        self.free_list
            .lock()
            .get(&priv_ip)
            .map(|(pub_ip, range, _)| (pub_ip.clone(), range.clone()))
    }

    pub fn new() -> Self {
        NatPool { free_list: KMutex::new(BTreeMap::new(), KMutexType::Driver) }
    }

    pub fn obtain(
        &self,
        priv_ip: Ipv4Addr,
    ) -> Result<(Ipv4Addr, u16), ResourceError> {
        match self.free_list.lock().get_mut(&priv_ip) {
            Some((ip, _, ports)) => {
                if ports.len() == 0 {
                    return Err(ResourceError::Exhausted);
                }

                Ok((*ip, ports.pop().unwrap()))
            }

            None => Err(ResourceError::NoMatch(priv_ip.to_string())),
        }
    }

    // TODO Add a range to the mapping and verify this port a) isn't
    // already in the free list and b) is within the range. I might
    // want to take things a step further, and have a Resource trait
    // which has obtain and release functions. The obtain function
    // would take some type that has the ObtainArg marker trait and
    // would return a BorrowedResource. The release function would
    // take a BorrowedResource and return nothing.
    pub fn release(&mut self, priv_ip: Ipv4Addr, p: (Ipv4Addr, u16)) {
        match self.free_list.lock().get_mut(&priv_ip) {
            Some((_ip, _, ports)) => {
                let (_, pub_port) = p;
                ports.push(pub_port);
            }

            None => {
                panic!("cannot release port to unknown mapping: {}", priv_ip);
            }
        }
    }
}

#[derive(Clone)]
pub struct DynNat4 {
    priv_ip: Ipv4Addr,
    ip_pool: Arc<NatPool>,
}

impl DynNat4 {
    pub fn new(addr: Ipv4Addr, ip_pool: Arc<NatPool>) -> Self {
        DynNat4 { priv_ip: addr.into(), ip_pool }
    }
}

impl fmt::Display for DynNat4 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (pub_ip, ports) = self.ip_pool.mapping(self.priv_ip).unwrap();
        write!(f, "{}:{}-{}", pub_ip, ports.start, ports.end)
    }
}

impl StatefulAction for DynNat4 {
    fn gen_desc(
        &self,
        flow_id: &InnerFlowId,
        _meta: &mut Meta,
    ) -> rule::GenDescResult {
        let pool = &self.ip_pool;
        let priv_port = flow_id.src_port;
        match pool.obtain(self.priv_ip) {
            Ok((pub_ip, pub_port)) => {
                let desc = DynNat4Desc {
                    priv_ip: self.priv_ip,
                    priv_port: priv_port,
                    pub_ip,
                    pub_port,
                };

                Ok(Arc::new(desc))
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

#[derive(Clone, Debug)]
pub struct DynNat4Desc {
    pub_ip: Ipv4Addr,
    pub_port: u16,
    priv_ip: Ipv4Addr,
    priv_port: u16,
}

pub const DYN_NAT4_NAME: &'static str = "dyn-nat4";

impl ActionDesc for DynNat4Desc {
    fn fini(&self) {
        todo!("implement fini() for DynNat4Desc");
    }

    fn gen_ht(&self, dir: Direction) -> HT {
        match dir {
            // Outbound traffic needs it's source IP and source port
            Direction::Out => HT {
                name: DYN_NAT4_NAME.to_string(),
                inner_ip: Ipv4Meta::modify(Some(self.pub_ip), None, None),
                inner_ulp: UlpHeaderAction::Modify(UlpMetaModify {
                    generic: UlpGenericModify {
                        src_port: Some(self.pub_port),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
                ..Default::default()
            },

            // Inbound traffic needs its destination IP and
            // destination port mapped back to the private values that
            // the guest expects to see.
            Direction::In => HT {
                name: DYN_NAT4_NAME.to_string(),
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
        DYN_NAT4_NAME
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn dyn_nat4_ht() {
        use crate::engine::ether::{EtherMeta, ETHER_TYPE_IPV4};
        use crate::engine::headers::{IpMeta, UlpMeta};
        use crate::engine::ip4::Protocol;
        use crate::engine::packet::{MetaGroup, PacketMeta};
        use crate::engine::tcp::TcpMeta;

        let priv_mac = MacAddr::from([0x02, 0x08, 0x20, 0xd8, 0x35, 0xcf]);
        let dest_mac = MacAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d]);
        let priv_ip = "10.0.0.220".parse().unwrap();
        let priv_port = "4999".parse().unwrap();
        let pub_ip = "52.10.128.69".parse().unwrap();
        let pub_port = "8765".parse().unwrap();
        let outside_ip = "76.76.21.21".parse().unwrap();

        let nat = DynNat4Desc { pub_ip, pub_port, priv_ip, priv_port };

        // TODO test in_ht
        let out_ht = nat.gen_ht(Direction::Out);

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
            dst: 80,
            flags: 0,
            seq: 0,
            ack: 0,
        });

        let mut meta = PacketMeta {
            outer: Default::default(),
            inner: MetaGroup {
                ether: Some(ether),
                ip: Some(ip),
                ulp: Some(ulp),
                ..Default::default()
            },
        };

        let ether_meta = meta.inner.ether.as_ref().unwrap();
        assert_eq!(ether_meta.src, priv_mac);
        assert_eq!(ether_meta.dst, dest_mac);

        out_ht.run(&mut meta);

        let ether_meta = meta.inner.ether.as_ref().unwrap();
        assert_eq!(ether_meta.dst, dest_mac);

        let ip4_meta = match meta.inner.ip.as_ref().unwrap() {
            IpMeta::Ip4(v) => v,
            _ => panic!("expect Ipv4Meta"),
        };

        assert_eq!(ip4_meta.src, pub_ip);
        assert_eq!(ip4_meta.dst, outside_ip);
        assert_eq!(ip4_meta.proto, Protocol::TCP);

        let tcp_meta = match meta.inner.ulp.as_ref().unwrap() {
            UlpMeta::Tcp(v) => v,
            _ => panic!("expect TcpMeta"),
        };

        assert_eq!(tcp_meta.src, 8765);
        assert_eq!(tcp_meta.dst, 80);
        assert_eq!(tcp_meta.flags, 0);
    }

    #[test]
    fn nat_mappings() {
        let mut pool = NatPool::new();
        let priv1 = "192.168.2.8".parse::<Ipv4Addr>().unwrap();
        let priv2 = "192.168.2.33".parse::<Ipv4Addr>().unwrap();
        let public = "52.10.128.69".parse().unwrap();

        pool.add(priv1, public, 1025..4096);
        pool.add(priv2, public, 4096..8192);

        assert_eq!(pool.num_avail(priv1).unwrap(), 3071);
        let (mip1, mport1) = match pool.obtain(priv1) {
            Ok((ip, port)) => (ip, port),
            _ => panic!("failed to obtain mapping"),
        };
        assert_eq!(pool.num_avail(priv1).unwrap(), 3070);
        assert_eq!(mip1, public);
        assert!(mport1 >= 1025);
        assert!(mport1 < 4096);

        assert_eq!(pool.num_avail(priv2).unwrap(), 4096);
        let (mip2, mport2) = match pool.obtain(priv2) {
            Ok((ip, port)) => (ip, port),
            _ => panic!("failed to obtain mapping"),
        };
        assert_eq!(pool.num_avail(priv2).unwrap(), 4095);
        assert_eq!(mip2, public);
        assert!(mport2 >= 4096);
        assert!(mport2 < 8192);

        pool.release(priv1, (mip1, mport1));
        assert_eq!(pool.num_avail(priv1).unwrap(), 3071);
        pool.release(priv2, (mip2, mport2));
        assert_eq!(pool.num_avail(priv2).unwrap(), 4096);
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Types for working with IP Source NAT, both IPv4 and IPv6.

use super::headers::{UlpGenericModify, UlpHeaderAction, UlpMetaModify};
use super::ip4::Ipv4Meta;
use super::ip6::Ipv6Meta;
use super::layer::InnerFlowId;
use super::port::meta::ActionMeta;
use super::rule::{
    self, ActionDesc, AllowOrDeny, DataPredicate, FiniteResource, HdrTransform,
    Predicate, Resource, ResourceEntry, ResourceError, StatefulAction,
};
use crate::ddi::sync::{KMutex, KMutexType};
use core::fmt;
use core::ops::RangeInclusive;
use opte_api::{Direction, IpAddr, Ipv4Addr, Ipv6Addr};

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

/// A single entry in the NAT pool, describing the public IP and port used to
/// NAT a private address.
#[derive(Clone, Copy)]
pub struct NatPoolEntry {
    ip: IpAddr,
    port: u16,
}

// A public IP and port range for NAT. Includes the list of all possible ports
// and those that are free.
#[derive(Debug, Clone)]
struct PortList {
    // The public IP address to which a private IP is mapped
    ip: IpAddr,
    // The list of all possible ports available in the NAT pool
    ports: RangeInclusive<u16>,
    // The list of unused / free ports in the pool
    free_ports: Vec<u16>,
}

impl ResourceEntry for NatPoolEntry {}

/// A mapping from private IP addresses to a public IP and a port range used for
/// NAT-ing connections.
pub struct NatPool {
    // Map private IP to public IP + free list of ports
    free_list: KMutex<BTreeMap<IpAddr, PortList>>,
}

mod private {
    pub trait Ip: Into<super::IpAddr> {}
    impl Ip for super::Ipv4Addr {}
    impl Ip for super::Ipv6Addr {}
}
/// A marker trait for IP addresses of a concrete protocol version.
///
/// This can be used to constrain generic types to the same IP address version,
/// but of either IPv4 or IPv6.
pub trait ConcreteIpAddr: private::Ip {}
impl<T> ConcreteIpAddr for T where T: private::Ip {}

impl NatPool {
    /// Add a new mapping from private IP to public IP and ports.
    pub fn add<T: ConcreteIpAddr>(
        &self,
        priv_ip: T,
        pub_ip: T,
        pub_ports: RangeInclusive<u16>,
    ) {
        let free_ports = pub_ports.clone().collect();
        let entry =
            PortList { ip: pub_ip.into(), ports: pub_ports, free_ports };
        self.free_list.lock().insert(priv_ip.into(), entry);
    }

    /// Return the number of available ports for a given private IP address.
    pub fn num_avail(&self, priv_ip: IpAddr) -> Result<usize, ResourceError> {
        match self.free_list.lock().get(&priv_ip) {
            Some(PortList { free_ports, .. }) => Ok(free_ports.len()),
            _ => Err(ResourceError::NoMatch(priv_ip.to_string())),
        }
    }

    /// Return the mapping from a private IP to the public IP and port range.
    pub fn mapping(
        &self,
        priv_ip: IpAddr,
    ) -> Option<(IpAddr, RangeInclusive<u16>)> {
        self.free_list
            .lock()
            .get(&priv_ip)
            .map(|PortList { ip, ports, .. }| (ip.clone(), ports.clone()))
    }

    /// Create a new NAT pool, with no entries.
    pub fn new() -> Self {
        NatPool { free_list: KMutex::new(BTreeMap::new(), KMutexType::Driver) }
    }

    // A helper function to verify correct operation during testing.
    #[cfg(test)]
    fn verify_available<T: ConcreteIpAddr>(
        &self,
        priv_ip: T,
        pub_ip: T,
        pub_port: u16,
    ) -> bool {
        match self.free_list.lock().get(&priv_ip.into()) {
            Some(PortList { ip, free_ports, .. }) => {
                if pub_ip.into() != *ip {
                    return false;
                }
                free_ports.contains(&pub_port)
            }
            None => false,
        }
    }
}

impl Resource for NatPool {}

impl FiniteResource for NatPool {
    type Key = IpAddr;
    type Entry = NatPoolEntry;

    fn obtain(&self, priv_ip: &IpAddr) -> Result<Self::Entry, ResourceError> {
        match self.free_list.lock().get_mut(&priv_ip) {
            Some(PortList { ip, free_ports, .. }) => {
                if let Some(port) = free_ports.pop() {
                    Ok(Self::Entry { ip: *ip, port })
                } else {
                    Err(ResourceError::Exhausted)
                }
            }

            None => Err(ResourceError::NoMatch(priv_ip.to_string())),
        }
    }

    fn release(&self, priv_ip: &IpAddr, entry: Self::Entry) {
        match self.free_list.lock().get_mut(&priv_ip) {
            Some(PortList { free_ports, .. }) => {
                free_ports.push(entry.port);
            }

            None => {
                panic!("cannot release port to unknown mapping: {}", priv_ip);
            }
        }
    }
}

/// A NAT pool mapping provided for Source NAT (only outbound connections).
#[derive(Clone)]
pub struct SNat {
    priv_ip: IpAddr,
    ip_pool: Arc<NatPool>,
}

impl SNat {
    pub fn new(addr: IpAddr, ip_pool: Arc<NatPool>) -> Self {
        SNat { priv_ip: addr, ip_pool }
    }
}

impl fmt::Display for SNat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (pub_ip, ports) = self.ip_pool.mapping(self.priv_ip).unwrap();
        match pub_ip {
            IpAddr::Ip4(ip4) => {
                write!(f, "{}:{}-{}", ip4, ports.start(), ports.end())
            }
            IpAddr::Ip6(ip6) => {
                write!(f, "[{}]:{}-{}", ip6, ports.start(), ports.end())
            }
        }
    }
}

impl StatefulAction for SNat {
    fn gen_desc(
        &self,
        flow_id: &InnerFlowId,
        _meta: &mut ActionMeta,
    ) -> rule::GenDescResult {
        let pool = &self.ip_pool;
        let priv_port = flow_id.src_port;
        match pool.obtain(&self.priv_ip) {
            Ok(nat) => {
                let desc = SNatDesc {
                    pool: pool.clone(),
                    priv_ip: self.priv_ip,
                    priv_port: priv_port,
                    nat,
                };

                Ok(AllowOrDeny::Allow(Arc::new(desc)))
            }
            Err(ResourceError::Exhausted) => {
                Err(rule::GenDescError::ResourceExhausted {
                    name: "SNAT Pool (exhausted)".to_string(),
                })
            }
            Err(ResourceError::NoMatch(ip)) => {
                Err(rule::GenDescError::Unexpected {
                    msg: format!("SNAT pool (no match: {})", ip),
                })
            }
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
pub struct SNatDesc {
    pool: Arc<NatPool>,
    nat: NatPoolEntry,
    priv_ip: IpAddr,
    priv_port: u16,
}

pub const SNAT_NAME: &'static str = "SNAT";

impl ActionDesc for SNatDesc {
    fn gen_ht(&self, dir: Direction) -> HdrTransform {
        match dir {
            // Outbound traffic needs its source IP and source port
            Direction::Out => {
                let inner_ip = match self.nat.ip {
                    IpAddr::Ip4(ip) => Ipv4Meta::modify(Some(ip), None, None),
                    IpAddr::Ip6(ip) => Ipv6Meta::modify(Some(ip), None, None),
                };
                HdrTransform {
                    name: SNAT_NAME.to_string(),
                    inner_ip: inner_ip,
                    inner_ulp: UlpHeaderAction::Modify(UlpMetaModify {
                        generic: UlpGenericModify {
                            src_port: Some(self.nat.port),
                            ..Default::default()
                        },
                        ..Default::default()
                    }),
                    ..Default::default()
                }
            }

            // Inbound traffic needs its destination IP and
            // destination port mapped back to the private values that
            // the guest expects to see.
            Direction::In => {
                let inner_ip = match self.priv_ip {
                    IpAddr::Ip4(ip) => Ipv4Meta::modify(None, Some(ip), None),
                    IpAddr::Ip6(ip) => Ipv6Meta::modify(None, Some(ip), None),
                };
                HdrTransform {
                    name: SNAT_NAME.to_string(),
                    inner_ip: inner_ip,
                    inner_ulp: UlpHeaderAction::Modify(UlpMetaModify {
                        generic: UlpGenericModify {
                            dst_port: Some(self.priv_port),
                            ..Default::default()
                        },
                        ..Default::default()
                    }),
                    ..Default::default()
                }
            }
        }
    }

    fn name(&self) -> &str {
        SNAT_NAME
    }
}

impl Drop for SNatDesc {
    fn drop(&mut self) {
        self.pool.release(&self.priv_ip, self.nat);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_nat_pool_different_ip_types() {
        let pool = NatPool::new();

        let ipv4: Ipv4Addr = "172.30.0.1".parse().unwrap();
        let pub_ipv4 = "76.76.21.21".parse().unwrap();
        let ipv6: Ipv6Addr = "fd00::1".parse().unwrap();
        let pub_ipv6 = "2001:db8::1".parse().unwrap();

        assert!(pool.mapping(ipv4.into()).is_none());
        assert!(pool.mapping(ipv6.into()).is_none());

        pool.add(ipv4, pub_ipv4, 0..=4096);
        assert!(pool.mapping(ipv4.into()).is_some());
        assert!(pool.mapping(ipv6.into()).is_none());

        pool.add(ipv6, pub_ipv6, 0..=4096);
        assert!(pool.mapping(ipv4.into()).is_some());
        assert!(pool.mapping(ipv6.into()).is_some());
    }

    #[test]
    fn snat4_desc_lifecycle() {
        use crate::engine::ether::{EtherMeta, ETHER_TYPE_IPV4};
        use crate::engine::headers::{IpMeta, UlpMeta};
        use crate::engine::ip4::Protocol;
        use crate::engine::packet::{MetaGroup, PacketMeta};
        use crate::engine::tcp::TcpMeta;
        use opte_api::{Ipv4Addr, MacAddr};

        let priv_mac = MacAddr::from([0x02, 0x08, 0x20, 0xd8, 0x35, 0xcf]);
        let dest_mac = MacAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d]);
        let priv_ipv4: Ipv4Addr = "10.0.0.220".parse().unwrap();
        let priv_ip = IpAddr::from(priv_ipv4);
        let priv_port = "4999".parse().unwrap();
        let pub_ip: Ipv4Addr = "52.10.128.69".parse().unwrap();
        let pub_port = "8765".parse().unwrap();
        let outside_ip: Ipv4Addr = "76.76.21.21".parse().unwrap();
        let outside_port = 80;

        let pool = Arc::new(NatPool::new());
        pool.add(priv_ipv4, pub_ip, 8765..=8765);
        let snat = SNat::new(priv_ip, pool.clone());
        let mut action_meta = ActionMeta::new();
        assert!(pool.verify_available(priv_ipv4, pub_ip, pub_port));

        // ================================================================
        // Build the packet metadata
        // ================================================================
        let ether = EtherMeta {
            src: priv_mac,
            dst: dest_mac,
            ether_type: ETHER_TYPE_IPV4,
        };
        let ip = IpMeta::from(Ipv4Meta {
            src: priv_ipv4,
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
        assert!(!pool.verify_available(priv_ipv4, pub_ip, pub_port));

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
        assert_eq!(ip4_meta.dst, priv_ipv4);
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
        assert!(pool.verify_available(priv_ipv4, pub_ip, pub_port));
    }

    #[test]
    fn nat_mappings() {
        let pool = NatPool::new();
        let priv1_ip = "192.168.2.8".parse::<Ipv4Addr>().unwrap();
        let priv1 = IpAddr::Ip4(priv1_ip);
        let priv2_ip = "192.168.2.33".parse::<Ipv4Addr>().unwrap();
        let priv2 = IpAddr::Ip4(priv2_ip);
        let public_ip = "52.10.128.69".parse().unwrap();
        let public = IpAddr::Ip4(public_ip);

        pool.add(priv1_ip, public_ip, 1025..=4096);
        pool.add(priv2_ip, public_ip, 4097..=8192);

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

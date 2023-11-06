// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Types for working with IP Source NAT, both IPv4 and IPv6.

use super::headers::HeaderAction;
use super::headers::IpMod;
use super::headers::UlpGenericModify;
use super::headers::UlpHeaderAction;
use super::headers::UlpMetaModify;
use super::packet::BodyTransform;
use super::packet::InnerFlowId;
use super::packet::Packet;
use super::packet::PacketMeta;
use super::packet::Parsed;
use super::port::meta::ActionMeta;
use super::predicate::DataPredicate;
use super::predicate::Predicate;
use super::rule::ActionDesc;
use super::rule::AllowOrDeny;
use super::rule::FiniteResource;
use super::rule::GenBtError;
use super::rule::GenDescError;
use super::rule::GenDescResult;
use super::rule::HdrTransform;
use super::rule::Resource;
use super::rule::ResourceEntry;
use super::rule::ResourceError;
use super::rule::StatefulAction;
use crate::ddi::sync::KMutex;
use crate::ddi::sync::KMutexType;
use crate::engine::icmp::QueryEcho;
use alloc::boxed::Box;
use alloc::collections::btree_map::BTreeMap;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Display;
use core::marker::PhantomData;
use core::ops::RangeInclusive;
use opte_api::Direction;
use opte_api::IpAddr;
use opte_api::Ipv4Addr;
use opte_api::Ipv6Addr;
use opte_api::Protocol;
use smoltcp::wire::Icmpv4Message;
use smoltcp::wire::Icmpv6Message;

/// A single entry in the NAT pool, describing the public IP and port used to
/// NAT a private address.
#[derive(Clone, Copy)]
pub struct NatPoolEntry<T: ConcreteIpAddr> {
    ip: T,
    port: u16,
}

// A public IP and port range for NAT. Includes the list of all possible ports
// and those that are free.
#[derive(Debug, Clone)]
struct PortList<T: ConcreteIpAddr> {
    // The public IP address to which a private IP is mapped
    ip: T,
    // The list of all possible ports available in the NAT pool
    ports: RangeInclusive<u16>,
    // The list of unused / free ports in the pool
    free_ports: Vec<u16>,
}

impl<T: ConcreteIpAddr> ResourceEntry for NatPoolEntry<T> {}

/// A mapping from private IP addresses to a public IP and a port range used for
/// NAT-ing connections.
pub struct NatPool<T: ConcreteIpAddr> {
    // Map private IP to public IP + free list of ports
    free_list: KMutex<BTreeMap<T, PortList<T>>>,
}

impl<T: ConcreteIpAddr> Default for NatPool<T> {
    fn default() -> Self {
        Self::new()
    }
}

mod private {
    use opte_api::Protocol;

    pub trait Ip: Into<super::IpAddr> {
        const MESSAGE_PROTOCOL: Protocol;
    }

    impl Ip for super::Ipv4Addr {
        const MESSAGE_PROTOCOL: Protocol = Protocol::ICMP;
    }

    impl Ip for super::Ipv6Addr {
        const MESSAGE_PROTOCOL: Protocol = Protocol::ICMPv6;
    }
}
/// A marker trait for IP addresses of a concrete protocol version.
///
/// This can be used to constrain generic types to the same IP address version,
/// but of either IPv4 or IPv6.
pub trait ConcreteIpAddr: private::Ip + Copy + Clone + Display + Ord {}
impl<T: Copy + Clone + Display + Ord> ConcreteIpAddr for T where T: private::Ip {}

impl<T: ConcreteIpAddr> NatPool<T> {
    /// Add a new mapping from private IP to public IP and ports.
    pub fn add(&self, priv_ip: T, pub_ip: T, pub_ports: RangeInclusive<u16>) {
        let free_ports = pub_ports.clone().collect();
        let entry = PortList { ip: pub_ip, ports: pub_ports, free_ports };
        self.free_list.lock().insert(priv_ip, entry);
    }

    /// Return the number of available ports for a given private IP address.
    pub fn num_avail(&self, priv_ip: T) -> Result<usize, ResourceError> {
        match self.free_list.lock().get(&priv_ip) {
            Some(PortList { free_ports, .. }) => Ok(free_ports.len()),
            _ => Err(ResourceError::NoMatch(priv_ip.to_string())),
        }
    }

    /// Return the mapping from a private IP to the public IP and port range.
    pub fn mapping(&self, priv_ip: T) -> Option<(T, RangeInclusive<u16>)> {
        self.free_list
            .lock()
            .get(&priv_ip)
            .map(|PortList { ip, ports, .. }| (*ip, ports.clone()))
    }

    /// Create a new NAT pool, with no entries.
    pub fn new() -> Self {
        NatPool { free_list: KMutex::new(BTreeMap::new(), KMutexType::Driver) }
    }

    // A helper function to verify correct operation during testing.
    #[cfg(test)]
    fn verify_available(&self, priv_ip: T, pub_ip: T, pub_port: u16) -> bool {
        match self.free_list.lock().get(&priv_ip) {
            Some(PortList { ip, free_ports, .. }) => {
                if pub_ip != *ip {
                    return false;
                }
                free_ports.contains(&pub_port)
            }
            None => false,
        }
    }
}

impl<T: ConcreteIpAddr> Resource for NatPool<T> {}

impl<T: ConcreteIpAddr> FiniteResource for NatPool<T> {
    type Key = T;
    type Entry = NatPoolEntry<T>;

    fn obtain(&self, priv_ip: &T) -> Result<Self::Entry, ResourceError> {
        match self.free_list.lock().get_mut(priv_ip) {
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

    fn release(&self, priv_ip: &T, entry: Self::Entry) {
        match self.free_list.lock().get_mut(priv_ip) {
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
pub struct SNat<T: ConcreteIpAddr> {
    priv_ip: T,
    ip_pool: Arc<NatPool<T>>,
}

enum GenIcmpErr<T: Display> {
    MetaNotFound,
    NotRequest(T),
}

impl<T: Display> From<GenIcmpErr<T>> for GenDescError {
    fn from(val: GenIcmpErr<T>) -> Self {
        GenDescError::Unexpected {
            msg: match val {
                GenIcmpErr::MetaNotFound => {
                    "No ICMP metadata found despite Protocol::ICMP".to_string()
                }
                GenIcmpErr::NotRequest(v) => {
                    format!("Expected ICMP Echo Request, found: {}", v)
                }
            },
        }
    }
}

impl<T: ConcreteIpAddr + 'static> SNat<T> {
    pub fn new(addr: T, ip_pool: Arc<NatPool<T>>) -> Self {
        SNat { priv_ip: addr, ip_pool }
    }

    // A helper method for generating an SNAT + ICMP(v6) action descriptor.
    fn gen_icmp_desc(
        &self,
        nat: NatPoolEntry<T>,
        pkt: &Packet<Parsed>,
    ) -> GenDescResult {
        let meta = pkt.meta();

        let echo_ident = match T::MESSAGE_PROTOCOL {
            Protocol::ICMP => {
                let icmp = meta
                    .inner_icmp()
                    .ok_or(GenIcmpErr::<Icmpv4Message>::MetaNotFound)?;
                if icmp.msg_type != Icmpv4Message::EchoRequest.into() {
                    Err(GenIcmpErr::NotRequest(icmp.msg_type))?;
                }

                icmp.echo_id()
            }
            Protocol::ICMPv6 => {
                let icmp6 = meta
                    .inner_icmp6()
                    .ok_or(GenIcmpErr::<Icmpv6Message>::MetaNotFound)?;
                if icmp6.msg_type != Icmpv6Message::EchoRequest.into() {
                    Err(GenIcmpErr::NotRequest(icmp6.msg_type))?;
                }

                icmp6.echo_id()
            }
            _ => Err(GenDescError::Unexpected {
                msg:
                    "Mistakenly called gen_icmp_desc on non Protocol::ICMP(v6)."
                        .to_string(),
            })?,
        }
        .ok_or(GenDescError::Unexpected {
            msg: "No ICMP(v6) echo ID found in metadata".to_string(),
        })?;

        let desc = SNatIcmpEchoDesc {
            pool: self.ip_pool.clone(),
            priv_ip: self.priv_ip,
            nat,
            echo_ident,
        };

        Ok(AllowOrDeny::Allow(Arc::new(desc)))
    }
}

impl Display for SNat<Ipv4Addr> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (pub_ip, ports) = self.ip_pool.mapping(self.priv_ip).unwrap();
        write!(f, "{}:{}-{}", pub_ip, ports.start(), ports.end())
    }
}

impl Display for SNat<Ipv6Addr> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (pub_ip, ports) = self.ip_pool.mapping(self.priv_ip).unwrap();
        write!(f, "[{}]:{}-{}", pub_ip, ports.start(), ports.end())
    }
}

impl<T: ConcreteIpAddr + 'static> StatefulAction for SNat<T>
where
    SNat<T>: Display,
{
    fn gen_desc(
        &self,
        flow_id: &InnerFlowId,
        pkt: &Packet<Parsed>,
        _meta: &mut ActionMeta,
    ) -> GenDescResult {
        let pool = &self.ip_pool;
        let priv_port = flow_id.src_port;
        match pool.obtain(&self.priv_ip) {
            Ok(nat) if flow_id.proto == T::MESSAGE_PROTOCOL => {
                self.gen_icmp_desc(nat, pkt)
            }

            Ok(nat) => {
                let desc = SNatDesc {
                    pool: pool.clone(),
                    priv_ip: self.priv_ip,
                    priv_port,
                    nat,
                };

                Ok(AllowOrDeny::Allow(Arc::new(desc)))
            }

            Err(ResourceError::Exhausted) => {
                Err(GenDescError::ResourceExhausted {
                    name: "SNAT Pool (exhausted)".to_string(),
                })
            }

            Err(ResourceError::NoMatch(ip)) => Err(GenDescError::Unexpected {
                msg: format!("SNAT pool (no match: {})", ip),
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
pub struct SNatDesc<T: ConcreteIpAddr> {
    pool: Arc<NatPool<T>>,
    nat: NatPoolEntry<T>,
    priv_ip: T,
    priv_port: u16,
}

pub const SNAT_NAME: &str = "SNAT";

impl<T: ConcreteIpAddr> ActionDesc for SNatDesc<T> {
    fn gen_ht(&self, dir: Direction) -> HdrTransform {
        match dir {
            // Outbound traffic needs its source IP and source port
            Direction::Out => {
                let ip = IpMod::new_src(self.nat.ip.into());

                HdrTransform {
                    name: SNAT_NAME.to_string(),
                    inner_ip: HeaderAction::Modify(ip, PhantomData),
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
                let ip = IpMod::new_dst(self.priv_ip.into());

                HdrTransform {
                    name: SNAT_NAME.to_string(),
                    inner_ip: HeaderAction::Modify(ip, PhantomData),
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

impl<T: ConcreteIpAddr> Drop for SNatDesc<T> {
    fn drop(&mut self) {
        self.pool.release(&self.priv_ip, self.nat);
    }
}

#[derive(Clone)]
pub struct SNatIcmpEchoDesc<T: ConcreteIpAddr> {
    pool: Arc<NatPool<T>>,
    nat: NatPoolEntry<T>,
    priv_ip: T,
    echo_ident: u16,
}

pub const SNAT_ICMP_ECHO_NAME: &str = "SNAT_ICMP_ECHO";

impl<T: ConcreteIpAddr> ActionDesc for SNatIcmpEchoDesc<T> {
    // SNAT needs to generate a payload transform for ICMP traffic in
    // order to treat the Echo Identifier as a psuedo ULP port.
    fn gen_ht(&self, dir: Direction) -> HdrTransform {
        match dir {
            // Outbound traffic needs its source IP rewritten, and its
            // 'source port' placed into the ICMP echo ID field.
            Direction::Out => {
                let ip = IpMod::new_src(self.nat.ip.into());

                HdrTransform {
                    name: SNAT_NAME.to_string(),
                    inner_ip: HeaderAction::Modify(ip, PhantomData),
                    inner_ulp: UlpHeaderAction::Modify(UlpMetaModify {
                        icmp_id: Some(self.nat.port),
                        ..Default::default()
                    }),
                    ..Default::default()
                }
            }

            // Inbound traffic needs its destination IP and
            // destination port mapped back to the private values that
            // the guest expects to see.
            Direction::In => {
                let ip = IpMod::new_dst(self.priv_ip.into());

                HdrTransform {
                    name: SNAT_NAME.to_string(),
                    inner_ip: HeaderAction::Modify(ip, PhantomData),
                    inner_ulp: UlpHeaderAction::Modify(UlpMetaModify {
                        icmp_id: Some(self.echo_ident),
                        ..Default::default()
                    }),
                    ..Default::default()
                }
            }
        }
    }

    fn gen_bt(
        &self,
        _dir: Direction,
        _meta: &PacketMeta,
        _payload_segs: &[&[u8]],
    ) -> Result<Option<Box<dyn BodyTransform>>, GenBtError> {
        Ok(None)
    }

    fn name(&self) -> &str {
        SNAT_ICMP_ECHO_NAME
    }
}

impl<T: ConcreteIpAddr> Drop for SNatIcmpEchoDesc<T> {
    fn drop(&mut self) {
        self.pool.release(&self.priv_ip, self.nat);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_nat_pool_different_ip_types() {
        let pool4 = NatPool::new();
        let pool6 = NatPool::new();

        let ipv4: Ipv4Addr = "172.30.0.1".parse().unwrap();
        let pub_ipv4 = "76.76.21.21".parse().unwrap();
        let ipv6: Ipv6Addr = "fd00::1".parse().unwrap();
        let pub_ipv6 = "2001:db8::1".parse().unwrap();

        assert!(pool4.mapping(ipv4).is_none());
        assert!(pool6.mapping(ipv6).is_none());

        pool4.add(ipv4, pub_ipv4, 0..=4096);
        assert!(pool4.mapping(ipv4).is_some());

        pool6.add(ipv6, pub_ipv6, 0..=4096);
        assert!(pool6.mapping(ipv6).is_some());
    }

    #[test]
    fn snat4_desc_lifecycle() {
        use crate::engine::ether::EtherHdr;
        use crate::engine::ether::EtherMeta;
        use crate::engine::ether::EtherType;
        use crate::engine::headers::IpMeta;
        use crate::engine::headers::UlpMeta;
        use crate::engine::ip4::Ipv4Hdr;
        use crate::engine::ip4::Ipv4Meta;
        use crate::engine::ip4::Protocol;
        use crate::engine::tcp::TcpMeta;
        use crate::engine::GenericUlp;
        use opte_api::Ipv4Addr;
        use opte_api::MacAddr;

        let priv_mac = MacAddr::from([0x02, 0x08, 0x20, 0xd8, 0x35, 0xcf]);
        let dest_mac = MacAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d]);
        let priv_ip: Ipv4Addr = "10.0.0.220".parse().unwrap();
        let priv_port = "4999".parse().unwrap();
        let pub_ip: Ipv4Addr = "52.10.128.69".parse().unwrap();
        let pub_port = "8765".parse().unwrap();
        let outside_ip: Ipv4Addr = "76.76.21.21".parse().unwrap();
        let outside_port = 80;

        let pool = Arc::new(NatPool::new());
        pool.add(priv_ip, pub_ip, 8765..=8765);
        let snat = SNat::new(priv_ip, pool.clone());
        let mut action_meta = ActionMeta::new();
        assert!(pool.verify_available(priv_ip, pub_ip, pub_port));

        // ================================================================
        // Build the packet
        // ================================================================
        let body = vec![];
        let tcp =
            TcpMeta { src: priv_port, dst: outside_port, ..Default::default() };
        let ip4 = Ipv4Meta {
            src: priv_ip,
            dst: outside_ip,
            proto: Protocol::TCP,
            total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len() + body.len()) as u16,
            ..Default::default()
        };
        let eth = EtherMeta {
            ether_type: EtherType::Ipv4,
            src: priv_mac,
            dst: dest_mac,
        };
        let pkt_len = EtherHdr::SIZE + usize::from(ip4.total_len);
        let mut pkt = Packet::alloc_and_expand(pkt_len);
        let mut wtr = pkt.seg0_wtr();
        eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
        ip4.emit(wtr.slice_mut(ip4.hdr_len()).unwrap());
        tcp.emit(wtr.slice_mut(tcp.hdr_len()).unwrap());
        wtr.write(&body).unwrap();
        let mut pkt = pkt.parse(Direction::Out, GenericUlp {}).unwrap();
        pkt.compute_checksums();

        // ================================================================
        // Verify descriptor generation.
        // ================================================================
        let flow_out = InnerFlowId::from(pkt.meta());
        let desc = match snat.gen_desc(&flow_out, &pkt, &mut action_meta) {
            Ok(AllowOrDeny::Allow(desc)) => desc,
            _ => panic!("expected AllowOrDeny::Allow(desc) result"),
        };
        assert!(!pool.verify_available(priv_ip, pub_ip, pub_port));

        // ================================================================
        // Verify outbound header transformation
        // ================================================================
        let out_ht = desc.gen_ht(Direction::Out);
        out_ht.run(pkt.meta_mut()).unwrap();

        let pmo = pkt.meta();
        let ether_meta = pmo.inner.ether;
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
        let body = vec![];
        let tcp =
            TcpMeta { src: outside_port, dst: priv_port, ..Default::default() };
        let ip4 = Ipv4Meta {
            src: outside_ip,
            dst: priv_ip,
            proto: Protocol::TCP,
            total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len() + body.len()) as u16,
            ..Default::default()
        };
        let eth = EtherMeta {
            ether_type: EtherType::Ipv4,
            src: dest_mac,
            dst: priv_mac,
        };
        let pkt_len = EtherHdr::SIZE + usize::from(ip4.total_len);
        let mut pkt = Packet::alloc_and_expand(pkt_len);
        let mut wtr = pkt.seg0_wtr();
        eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
        ip4.emit(wtr.slice_mut(ip4.hdr_len()).unwrap());
        tcp.emit(wtr.slice_mut(tcp.hdr_len()).unwrap());
        wtr.write(&body).unwrap();
        let mut pkt = pkt.parse(Direction::In, GenericUlp {}).unwrap();
        pkt.compute_checksums();

        let in_ht = desc.gen_ht(Direction::In);
        in_ht.run(pkt.meta_mut()).unwrap();

        let pmi = pkt.meta();
        let ether_meta = pmi.inner.ether;
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
        let external_ip = "52.10.128.69".parse().unwrap();

        pool.add(priv1, external_ip, 1025..=4096);
        pool.add(priv2, external_ip, 4097..=8192);

        assert_eq!(pool.num_avail(priv1).unwrap(), 3072);
        let npe1 = match pool.obtain(&priv1) {
            Ok(npe) => npe,
            _ => panic!("failed to obtain mapping"),
        };
        assert_eq!(pool.num_avail(priv1).unwrap(), 3071);
        assert_eq!(npe1.ip, external_ip);
        assert!(npe1.port >= 1025);
        assert!(npe1.port <= 4096);

        assert_eq!(pool.num_avail(priv2).unwrap(), 4096);
        let npe2 = match pool.obtain(&priv2) {
            Ok(npe) => npe,
            _ => panic!("failed to obtain mapping"),
        };
        assert_eq!(pool.num_avail(priv2).unwrap(), 4095);
        assert_eq!(npe2.ip, external_ip);
        assert!(npe2.port >= 4097);
        assert!(npe2.port <= 8192);

        pool.release(&priv1, npe1);
        assert_eq!(pool.num_avail(priv1).unwrap(), 3072);
        pool.release(&priv2, npe2);
        assert_eq!(pool.num_avail(priv2).unwrap(), 4096);
    }
}

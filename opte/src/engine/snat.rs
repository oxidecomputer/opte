// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Types for working with IP Source NAT, both IPv4 and IPv6.

use super::ether::EtherMeta;
use super::headers::UlpGenericModify;
use super::headers::UlpHeaderAction;
use super::headers::UlpMetaModify;
use super::ip4::Ipv4Meta;
use super::ip6::Ipv6Meta;
use super::packet::BodyTransform;
use super::packet::BodyTransformError;
use super::packet::InnerFlowId;
use super::packet::Packet;
use super::packet::PacketMeta;
use super::packet::Parsed;
use super::port::meta::ActionMeta;
use super::rule::ActionDesc;
use super::rule::AllowOrDeny;
use super::rule::DataPredicate;
use super::rule::FiniteResource;
use super::rule::GenBtError;
use super::rule::GenDescError;
use super::rule::GenDescResult;
use super::rule::HdrTransform;
use super::rule::Predicate;
use super::rule::Resource;
use super::rule::ResourceEntry;
use super::rule::ResourceError;
use super::rule::StatefulAction;
use crate::ddi::sync::KMutex;
use crate::ddi::sync::KMutexType;
use core::fmt;
use core::fmt::Display;
use core::ops::RangeInclusive;
use opte_api::Direction;
use opte_api::IpAddr;
use opte_api::Ipv4Addr;
use opte_api::Ipv6Addr;
use opte_api::MacAddr;
use opte_api::Protocol;
use smoltcp::wire::Icmpv4Message;
use smoltcp::wire::Icmpv4Packet;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::boxed::Box;
        use alloc::collections::btree_map::BTreeMap;
        use alloc::string::ToString;
        use alloc::sync::Arc;
        use alloc::vec::Vec;
    } else {
        use std::boxed::Box;
        use std::collections::btree_map::BTreeMap;
        use std::string::ToString;
        use std::sync::Arc;
        use std::vec::Vec;
    }
}

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

mod private {
    pub trait Ip: Into<super::IpAddr> {}
    impl Ip for super::Ipv4Addr {}
    impl Ip for super::Ipv6Addr {}
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
            .map(|PortList { ip, ports, .. }| (ip.clone(), ports.clone()))
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

    fn release(&self, priv_ip: &T, entry: Self::Entry) {
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
    priv_ip: Ipv4Addr,
    ip_pool: Arc<NatPool<Ipv4Addr>>,
    // XXX-EXT-IP
    phys_gw_mac: Option<MacAddr>,
}

impl SNat {
    pub fn new(
        addr: Ipv4Addr,
        ip_pool: Arc<NatPool<Ipv4Addr>>,
        phys_gw_mac: Option<MacAddr>,
    ) -> Self {
        SNat { priv_ip: addr, ip_pool, phys_gw_mac }
    }

    // A helper method for generating an SNAT + ICMP action descriptor.
    fn gen_icmp_desc(
        &self,
        nat: NatPoolEntry<Ipv4Addr>,
        pkt: &Packet<Parsed>,
    ) -> GenDescResult {
        if let Some(body_segs) = pkt.body_segs() {
            let icmp = match Icmpv4Packet::new_checked(body_segs[0]) {
                Ok(icmp) => icmp,
                Err(e) => {
                    return Err(GenDescError::Unexpected {
                        msg: format!("Failed to parse ICMP: {}", e),
                    });
                }
            };

            if icmp.msg_type() != Icmpv4Message::EchoRequest {
                return Err(GenDescError::Unexpected {
                    msg: format!(
                        "Expected ICMP Echo Request, found: {}",
                        icmp.msg_type()
                    ),
                });
            }

            let desc = SNatIcmpEchoDesc {
                pool: self.ip_pool.clone(),
                priv_ip: self.priv_ip,
                nat,
                // Panic: We know this is safe because we make it here
                // only if this ICMP message is an Echo Request.
                echo_ident: icmp.echo_ident(),
                phys_gw_mac: self.phys_gw_mac,
            };

            Ok(AllowOrDeny::Allow(Arc::new(desc)))
        } else {
            Err(GenDescError::Unexpected { msg: format!("No ICMP body found") })
        }
    }
}

impl Display for SNat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (pub_ip, ports) = self.ip_pool.mapping(self.priv_ip).unwrap();
        write!(f, "{}:{}-{}", pub_ip, ports.start(), ports.end())
    }
}

impl StatefulAction for SNat {
    fn gen_desc(
        &self,
        flow_id: &InnerFlowId,
        pkt: &Packet<Parsed>,
        _meta: &mut ActionMeta,
    ) -> GenDescResult {
        let pool = &self.ip_pool;
        let priv_port = flow_id.src_port;
        match pool.obtain(&self.priv_ip.into()) {
            Ok(nat) => match flow_id.proto {
                Protocol::ICMP => self.gen_icmp_desc(nat, pkt),

                _ => {
                    let desc = SNatDesc {
                        pool: pool.clone(),
                        priv_ip: self.priv_ip.into(),
                        priv_port: priv_port,
                        phys_gw_mac: self.phys_gw_mac,
                        nat,
                    };

                    Ok(AllowOrDeny::Allow(Arc::new(desc)))
                }
            },

            Err(ResourceError::Exhausted) => {
                return Err(GenDescError::ResourceExhausted {
                    name: "SNAT Pool (exhausted)".to_string(),
                });
            }

            Err(ResourceError::NoMatch(ip)) => {
                return Err(GenDescError::Unexpected {
                    msg: format!("SNAT pool (no match: {})", ip),
                });
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
pub struct SNat6 {
    priv_ip: Ipv6Addr,
    ip_pool: Arc<NatPool<Ipv6Addr>>,
    // XXX-EXT-IP
    phys_gw_mac: Option<MacAddr>,
}

impl SNat6 {
    pub fn new(
        addr: Ipv6Addr,
        ip_pool: Arc<NatPool<Ipv6Addr>>,
        phys_gw_mac: Option<MacAddr>,
    ) -> Self {
        SNat6 { priv_ip: addr, ip_pool, phys_gw_mac }
    }
}

impl StatefulAction for SNat6 {
    fn gen_desc(
        &self,
        flow_id: &InnerFlowId,
        _pkt: &Packet<Parsed>,
        _meta: &mut ActionMeta,
    ) -> GenDescResult {
        let pool = &self.ip_pool;
        let priv_port = flow_id.src_port;
        match pool.obtain(&self.priv_ip) {
            Ok(nat) => {
                let desc = SNatDesc {
                    pool: pool.clone(),
                    priv_ip: self.priv_ip.into(),
                    priv_port: priv_port,
                    phys_gw_mac: self.phys_gw_mac,
                    nat,
                };

                Ok(AllowOrDeny::Allow(Arc::new(desc)))
            }

            Err(ResourceError::Exhausted) => {
                return Err(GenDescError::ResourceExhausted {
                    name: "SNAT Pool (exhausted)".to_string(),
                });
            }

            Err(ResourceError::NoMatch(ip)) => {
                return Err(GenDescError::Unexpected {
                    msg: format!("SNAT pool (no match: {})", ip),
                });
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

impl Display for SNat6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (pub_ip, ports) = self.ip_pool.mapping(self.priv_ip).unwrap();
        write!(f, "[{}]:{}-{}", pub_ip, ports.start(), ports.end())
    }
}

#[derive(Clone)]
pub struct SNatDesc<T: ConcreteIpAddr> {
    pool: Arc<NatPool<T>>,
    nat: NatPoolEntry<T>,
    priv_ip: T,
    priv_port: u16,
    // XXX-EXT-IP
    phys_gw_mac: Option<MacAddr>,
}

pub const SNAT_NAME: &'static str = "SNAT";

impl ActionDesc for SNatDesc<Ipv4Addr> {
    fn gen_ht(&self, dir: Direction) -> HdrTransform {
        match dir {
            // Outbound traffic needs its source IP and source port
            Direction::Out => {
                let mut ht = HdrTransform {
                    name: SNAT_NAME.to_string(),
                    inner_ip: Ipv4Meta::modify(Some(self.nat.ip), None, None),
                    inner_ulp: UlpHeaderAction::Modify(UlpMetaModify {
                        generic: UlpGenericModify {
                            src_port: Some(self.nat.port),
                            ..Default::default()
                        },
                        ..Default::default()
                    }),
                    ..Default::default()
                };

                // XXX-EXT-IP hack to rewrite destination MAC adress
                // from virtual gateway addr to the real gateway addr
                // on the same subnet as the external IP.
                if self.phys_gw_mac.is_some() {
                    ht.inner_ether = EtherMeta::modify(
                        None,
                        Some(self.phys_gw_mac.unwrap()),
                    );
                }

                ht
            }

            // Inbound traffic needs its destination IP and
            // destination port mapped back to the private values that
            // the guest expects to see.
            Direction::In => HdrTransform {
                name: SNAT_NAME.to_string(),
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
        SNAT_NAME
    }
}

impl ActionDesc for SNatDesc<Ipv6Addr> {
    fn gen_ht(&self, dir: Direction) -> HdrTransform {
        match dir {
            // Outbound traffic needs its source IP and source port
            Direction::Out => {
                let mut ht = HdrTransform {
                    name: SNAT_NAME.to_string(),
                    inner_ip: Ipv6Meta::modify(Some(self.nat.ip), None, None),
                    inner_ulp: UlpHeaderAction::Modify(UlpMetaModify {
                        generic: UlpGenericModify {
                            src_port: Some(self.nat.port),
                            ..Default::default()
                        },
                        ..Default::default()
                    }),
                    ..Default::default()
                };

                // XXX-EXT-IP hack to rewrite destination MAC adress
                // from virtual gateway addr to the real gateway addr
                // on the same subnet as the external IP.
                if self.phys_gw_mac.is_some() {
                    ht.inner_ether = EtherMeta::modify(
                        None,
                        Some(self.phys_gw_mac.unwrap()),
                    );
                }

                ht
            }

            // Inbound traffic needs its destination IP and
            // destination port mapped back to the private values that
            // the guest expects to see.
            Direction::In => HdrTransform {
                name: SNAT_NAME.to_string(),
                inner_ip: Ipv6Meta::modify(None, Some(self.priv_ip), None),
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
        SNAT_NAME
    }
}

impl<T: ConcreteIpAddr> Drop for SNatDesc<T> {
    fn drop(&mut self) {
        self.pool.release(&self.priv_ip, self.nat);
    }
}

#[derive(Clone)]
pub struct SNatIcmpEchoDesc {
    pool: Arc<NatPool<Ipv4Addr>>,
    nat: NatPoolEntry<Ipv4Addr>,
    priv_ip: Ipv4Addr,
    echo_ident: u16,
    // XXX-EXT-IP
    phys_gw_mac: Option<MacAddr>,
}

pub const SNAT_ICMP_ECHO_NAME: &'static str = "SNAT_ICMP_ECHO";

impl ActionDesc for SNatIcmpEchoDesc {
    fn gen_ht(&self, dir: Direction) -> HdrTransform {
        match dir {
            // Outbound traffic needs its source IP and source port
            Direction::Out => {
                let mut ht = HdrTransform {
                    name: SNAT_NAME.to_string(),
                    inner_ip: Ipv4Meta::modify(Some(self.nat.ip), None, None),
                    ..Default::default()
                };

                // XXX-EXT-IP hack to rewrite destination MAC adress
                // from virtual gateway addr to the real gateway addr
                // on the same subnet as the external IP.
                if self.phys_gw_mac.is_some() {
                    ht.inner_ether = EtherMeta::modify(
                        None,
                        Some(self.phys_gw_mac.unwrap()),
                    );
                }

                ht
            }

            // Inbound traffic needs its destination IP and
            // destination port mapped back to the private values that
            // the guest expects to see.
            Direction::In => HdrTransform {
                name: SNAT_NAME.to_string(),
                inner_ip: Ipv4Meta::modify(None, Some(self.priv_ip), None),
                ..Default::default()
            },
        }
    }

    // SNAT needs to generate a payload transform for ICMP traffic in
    // order to treat the Echo Identifier as a psuedo ULP port.
    fn gen_bt(
        &self,
        _dir: Direction,
        _meta: &PacketMeta,
        _payload_segs: &[&[u8]],
    ) -> Result<Option<Box<dyn BodyTransform>>, GenBtError> {
        Ok(Some(Box::new(SNatIcmpEchoBt::new(self.echo_ident, self.nat))))
    }

    fn name(&self) -> &str {
        SNAT_ICMP_ECHO_NAME
    }
}

impl Drop for SNatIcmpEchoDesc {
    fn drop(&mut self) {
        self.pool.release(&self.priv_ip.into(), self.nat);
    }
}

/// Perform SNAT for ICMP Echo/Reply messages, treating the Identifier
/// as a source port.
#[derive(Clone)]
pub struct SNatIcmpEchoBt {
    ident: u16,
    nat: NatPoolEntry<Ipv4Addr>,
}

impl SNatIcmpEchoBt {
    pub fn new(ident: u16, nat: NatPoolEntry<Ipv4Addr>) -> Self {
        Self { ident, nat }
    }
}

impl BodyTransform for SNatIcmpEchoBt {
    fn run(
        &self,
        dir: Direction,
        body: &mut [&mut [u8]],
    ) -> Result<(), BodyTransformError> {
        use Icmpv4Message::EchoReply;
        use Icmpv4Message::EchoRequest;

        let mut icmp = Icmpv4Packet::new_checked(&mut *body[0])?;

        match (icmp.msg_type(), dir) {
            (EchoReply | EchoRequest, Direction::Out) => {
                // Panic: We know this is safe because we make it here
                // only if this ICMP message is an Echo/Reply.
                icmp.set_echo_ident(self.nat.port);
            }

            (EchoReply | EchoRequest, Direction::In) => {
                // Panic: We know this is safe because we make it here
                // only if this ICMP message is an Echo/Reply.
                icmp.set_echo_ident(self.ident);
            }

            (_, _) => {
                return Err(BodyTransformError::UnexpectedBody(format!(
                    "Expected ICMP Echo/Reply, found: {}",
                    icmp.msg_type()
                )));
            }
        }

        icmp.fill_checksum();
        Ok(())
    }
}

impl Display for SNatIcmpEchoBt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ICMP Echo Ident/SNAT {} <=> {}", self.ident, self.nat.port)
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
        use crate::engine::checksum::HeaderChecksum;
        use crate::engine::ether::EtherHdr;
        use crate::engine::ether::EtherType;
        use crate::engine::headers::IpMeta;
        use crate::engine::headers::UlpMeta;
        use crate::engine::ip4::Ipv4Hdr;
        use crate::engine::ip4::Protocol;
        use crate::engine::ip4::UlpCsumOpt;
        use crate::engine::tcp::TcpHdr;
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
        let snat = SNat::new(priv_ip, pool.clone(), None);
        let mut action_meta = ActionMeta::new();
        assert!(pool.verify_available(priv_ip, pub_ip, pub_port));

        // ================================================================
        // Build the packet
        // ================================================================
        let body = vec![];
        let mut tcp = TcpHdr::new(priv_port, outside_port);
        let mut ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, priv_ip, outside_ip);
        ip4.compute_hdr_csum();
        let tcp_csum =
            ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
        tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
        let eth = EtherHdr::new(EtherType::Ipv4, priv_mac, dest_mac);
        let mut bytes = vec![];
        bytes.extend_from_slice(&eth.as_bytes());
        bytes.extend_from_slice(&ip4.as_bytes());
        bytes.extend_from_slice(&tcp.as_bytes());
        bytes.extend_from_slice(&body);
        let mut pkt = Packet::copy(&bytes).parse().unwrap();

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
        let body = vec![];
        let mut tcp = TcpHdr::new(outside_port, priv_port);
        let mut ip4 = Ipv4Hdr::new_tcp(&mut tcp, &body, outside_ip, priv_ip);
        ip4.compute_hdr_csum();
        let tcp_csum =
            ip4.compute_ulp_csum(UlpCsumOpt::Full, &tcp.as_bytes(), &body);
        tcp.set_csum(HeaderChecksum::from(tcp_csum).bytes());
        let eth = EtherHdr::new(EtherType::Ipv4, dest_mac, priv_mac);
        let mut bytes = vec![];
        bytes.extend_from_slice(&eth.as_bytes());
        bytes.extend_from_slice(&ip4.as_bytes());
        bytes.extend_from_slice(&tcp.as_bytes());
        bytes.extend_from_slice(&body);
        let mut pkt = Packet::copy(&bytes).parse().unwrap();

        let in_ht = desc.gen_ht(Direction::In);
        in_ht.run(pkt.meta_mut()).unwrap();

        let pmi = pkt.meta();
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

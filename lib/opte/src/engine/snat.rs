// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Types for working with IP Source NAT, both IPv4 and IPv6.

use super::headers::HeaderAction;
use super::headers::IpMod;
use super::headers::UlpGenericModify;
use super::headers::UlpHeaderAction;
use super::headers::UlpMetaModify;
use super::packet::InnerFlowId;
use super::packet::MblkFullParsed;
use super::packet::Packet;
use super::port::meta::ActionMeta;
use super::predicate::DataPredicate;
use super::predicate::Predicate;
use super::rule::ActionDesc;
use super::rule::AllowOrDeny;
use super::rule::FiniteHandle;
use super::rule::FiniteResource;
use super::rule::GenDescError;
use super::rule::GenDescResult;
use super::rule::HdrTransform;
use super::rule::Resource;
use super::rule::ResourceEntry;
use super::rule::ResourceError;
use super::rule::StatefulAction;
use crate::api::IcmpInfo;
use crate::api::L4Info;
use crate::api::PortInfo;
use crate::ddi::sync::KMutex;
use crate::engine::freelist::Freelist;
use crate::engine::icmp::QueryEcho;
use crate::engine::nat::ExternalIpTag;
use alloc::collections::btree_map::BTreeMap;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Display;
use core::ops::RangeInclusive;
use ingot::icmp::IcmpV4Ref;
use ingot::icmp::IcmpV4Type;
use ingot::icmp::IcmpV6Ref;
use ingot::icmp::IcmpV6Type;
use opte_api::Direction;
use opte_api::IpAddr;
use opte_api::Ipv4Addr;
use opte_api::Ipv6Addr;
use opte_api::Protocol;

/// A single entry in the NAT pool, describing the public IP and port used to
/// NAT a private address.
#[derive(Clone, Copy, Debug, PartialEq)]
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
    // The freelist of ports.
    free_ports: Freelist,
}

impl<T: ConcreteIpAddr> ResourceEntry for NatPoolEntry<T> {}

/// A mapping from private IP addresses to a public IP and a port range used for
/// NAT-ing connections.
pub struct NatPool<T: ConcreteIpAddr> {
    // Map private IP to public IP + free list of ports
    // TODO: consider KRWlock + ringbuf of free_ports?
    free_list: KMutex<BTreeMap<T, PortList<T>>>,
}

impl<T: ConcreteIpAddr> Default for NatPool<T> {
    fn default() -> Self {
        Self::new()
    }
}

type SNatAlloc<T> = FiniteHandle<NatPool<T>>;

mod private {
    use opte_api::Protocol;

    pub trait Ip: Into<super::IpAddr> + Send + Sync {
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
        let free_ports = Freelist::new(pub_ports);
        let entry = PortList { ip: pub_ip, free_ports };
        // TODO-robustness: We probably want to handle overwrites here, rather
        // than ignoring them.
        self.free_list.lock().insert(priv_ip, entry);
    }

    /// Return the number of available ports for a given private IP address.
    pub fn num_avail(&self, priv_ip: T) -> Result<usize, ResourceError> {
        match self.free_list.lock().get(&priv_ip) {
            Some(PortList { free_ports, .. }) => Ok(free_ports.n_free()),
            _ => Err(ResourceError::NoMatch(priv_ip.to_string())),
        }
    }

    /// Return the mapping from a private IP to the public IP and port range.
    pub fn mapping(&self, priv_ip: T) -> Option<(T, RangeInclusive<u16>)> {
        self.free_list.lock().get(&priv_ip).map(
            |PortList { ip, free_ports }| (*ip, free_ports.ports().clone()),
        )
    }

    /// Create a new NAT pool, with no entries.
    pub fn new() -> Self {
        NatPool { free_list: KMutex::new(BTreeMap::new()) }
    }

    // A helper function to verify correct operation during testing.
    #[cfg(test)]
    fn verify_available(&self, priv_ip: T, pub_ip: T, pub_port: u16) -> bool {
        match self.free_list.lock().get(&priv_ip) {
            Some(PortList { ip, free_ports }) => {
                if pub_ip != *ip {
                    return false;
                }
                free_ports.is_free(pub_port)
            }
            None => false,
        }
    }
}

impl<T: ConcreteIpAddr> Resource for NatPool<T> {}

impl<T: ConcreteIpAddr> FiniteResource for NatPool<T> {
    type Key = T;
    type Entry = NatPoolEntry<T>;

    fn obtain_raw(&self, priv_ip: &T) -> Result<Self::Entry, ResourceError> {
        match self.free_list.lock().get_mut(priv_ip) {
            Some(PortList { ip, free_ports, .. }) => {
                let port = free_ports.take_next()?;
                Ok(Self::Entry { ip: *ip, port })
            }

            None => Err(ResourceError::NoMatch(priv_ip.to_string())),
        }
    }

    fn reclaim_raw(
        &self,
        priv_ip: &T,
        entry: NatPoolEntry<T>,
    ) -> Result<(), ResourceError> {
        match self.free_list.lock().get_mut(priv_ip) {
            Some(PortList { ip, free_ports }) => {
                if *ip != entry.ip {
                    return Err(ResourceError::NoMatch(format!(
                        "IP: {}",
                        entry.ip
                    )));
                }
                free_ports.take(entry.port)
            }
            None => Err(ResourceError::NoMatch(format!("IP: {}", priv_ip))),
        }
    }

    fn release(&self, priv_ip: &T, entry: Self::Entry) {
        match self.free_list.lock().get_mut(priv_ip) {
            Some(PortList { free_ports, .. }) => {
                let was_freed =
                    free_ports.free(entry.port).expect("a port in range");
                debug_assert!(
                    was_freed,
                    "port {} was double-freed",
                    entry.port
                );
            }

            None => {
                panic!("cannot release port to unknown mapping: {priv_ip}");
            }
        }
    }
}

/// A NAT pool mapping provided for Source NAT (only outbound connections).
#[derive(Clone)]
pub struct SNat<T: ConcreteIpAddr> {
    priv_ip: T,

    // Each ULP has its own pool of SNAT ports to allocate, as flow-keys are already
    // disambiguated since the UFT 5-tuple includes protocol information.
    // We store separate NAT pools instead of implementing NatPool::Key = (Protocol, T)
    // (and having multiple freelists in `PortList`) to prevent us from needing to
    // include protocol in the generated `ActionDesc`.
    tcp_pool: Arc<NatPool<T>>,
    udp_pool: Arc<NatPool<T>>,
    icmp_pool: Arc<NatPool<T>>,
}

enum GenIcmpErr {
    MetaNotFound,
}

impl From<GenIcmpErr> for GenDescError {
    fn from(val: GenIcmpErr) -> Self {
        GenDescError::Unexpected {
            msg: match val {
                GenIcmpErr::MetaNotFound => {
                    "No ICMP metadata found despite Protocol::ICMP".to_string()
                }
            },
        }
    }
}

impl<T: ConcreteIpAddr + 'static> SNat<T> {
    /// Construct a new SNAT pool which maps from the private `addr`.
    ///
    /// The mapping starts as empty, without any public IPs or ports to map the
    /// private address to. They must be added with [`SNat<T>::add`].
    pub fn new(addr: T) -> Self {
        SNat {
            priv_ip: addr,
            tcp_pool: Default::default(),
            udp_pool: Default::default(),
            icmp_pool: Default::default(),
        }
    }

    /// Add a mapping from our private IP to the provided public IP and ports.
    pub fn add(&self, pub_ip: T, pub_ports: RangeInclusive<u16>) {
        let pools = [&self.tcp_pool, &self.udp_pool, &self.icmp_pool];
        for pool in pools {
            pool.add(self.priv_ip, pub_ip, pub_ports.clone())
        }
    }

    /// A helper method for generating an SNAT + ICMP(v6) action descriptor.
    ///
    /// Only echo requests will be admitted, as these a) signify a new flow,
    /// and b) are SNAT-compatible via their Echo ID parameter. All other ICMP
    /// packets are explicitly dropped.
    fn gen_icmp_desc(
        &self,
        nat: SNatAlloc<T>,
        pkt: &Packet<MblkFullParsed>,
    ) -> GenDescResult {
        let meta = pkt.meta();

        let echo_ident = match T::MESSAGE_PROTOCOL {
            Protocol::ICMP => {
                let icmp = meta.inner_icmp().ok_or(GenIcmpErr::MetaNotFound)?;

                Ok(if icmp.ty() == IcmpV4Type::ECHO_REQUEST {
                    icmp.echo_id()
                } else {
                    None
                })
            }
            Protocol::ICMPv6 => {
                let icmp6 =
                    meta.inner_icmp6().ok_or(GenIcmpErr::MetaNotFound)?;

                Ok(if icmp6.ty() == IcmpV6Type::ECHO_REQUEST {
                    icmp6.echo_id()
                } else {
                    None
                })
            }
            _ => Err(GenDescError::Unexpected {
                msg: "Mistakenly called gen_icmp_desc on non ICMP(v6)."
                    .to_string(),
            }),
        }?;

        if let Some(echo_ident) = echo_ident {
            Ok(AllowOrDeny::Allow(Arc::new(SNatIcmpEchoDesc {
                nat,
                echo_ident,
            })))
        } else {
            Ok(AllowOrDeny::Deny)
        }
    }
}

impl Display for SNat<Ipv4Addr> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Here and below: all ULP-specific pools have the same SNAT mappings.
        match self.tcp_pool.mapping(self.priv_ip) {
            Some((pub_ip, ports)) => {
                write!(f, "{pub_ip}:{}-{}", ports.start(), ports.end())
            }
            None => write!(f, "None"),
        }
    }
}

impl Display for SNat<Ipv6Addr> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.tcp_pool.mapping(self.priv_ip) {
            Some((pub_ip, ports)) => {
                write!(f, "[{pub_ip}]:{}-{}", ports.start(), ports.end())
            }
            None => write!(f, "None"),
        }
    }
}

impl<T: ConcreteIpAddr + 'static> StatefulAction for SNat<T>
where
    SNat<T>: Display,
{
    fn gen_desc(
        &self,
        flow_id: &InnerFlowId,
        pkt: &Packet<MblkFullParsed>,
        _meta: &ActionMeta,
    ) -> GenDescResult {
        let proto = flow_id.protocol();
        let priv_port = match flow_id.l4_info() {
            Some(L4Info::Ports(PortInfo { src_port, .. })) => Ok(*src_port),
            Some(L4Info::Icmpv4(IcmpInfo { id, .. })) => Ok(*id),
            Some(L4Info::Icmpv6(IcmpInfo { id, .. })) => Ok(*id),
            _ => Err(GenDescError::Unexpected {
                msg: format!("SNAT pool (unexpected ULP: {proto})"),
            }),
        }?;
        let is_icmp = proto == T::MESSAGE_PROTOCOL;
        let pool = match proto {
            Protocol::TCP => &self.tcp_pool,
            Protocol::UDP => &self.udp_pool,
            _ if is_icmp => &self.icmp_pool,
            proto => {
                return Err(GenDescError::Unexpected {
                    msg: format!("SNAT pool (unexpected ULP: {proto})"),
                });
            }
        };

        match pool.obtain(&self.priv_ip) {
            Ok(nat) => {
                if is_icmp {
                    self.gen_icmp_desc(nat, pkt)
                } else {
                    let desc = SNatDesc { priv_port, nat };
                    Ok(AllowOrDeny::Allow(Arc::new(desc)))
                }
            }

            Err(ResourceError::Exhausted) => {
                Err(GenDescError::ResourceExhausted {
                    name: "SNAT Pool (exhausted)".to_string(),
                })
            }

            Err(ResourceError::NoMatch(item)) => {
                Err(GenDescError::Unexpected {
                    msg: format!("SNAT pool (no match: {item})"),
                })
            }

            // NOTE: This should never happen because `InUse` is only returned
            // by calls to `FiniteResource::restore()`, not `obtain()`.
            Err(ResourceError::InUse(item)) => Err(GenDescError::Unexpected {
                msg: format!("SNAT pool (resource in use: {item})"),
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

pub struct SNatDesc<T: ConcreteIpAddr> {
    nat: SNatAlloc<T>,
    priv_port: u16,
}

pub const SNAT_NAME: &str = "SNAT";

impl<T: ConcreteIpAddr> ActionDesc for SNatDesc<T> {
    fn gen_ht(&self, dir: Direction, meta: &mut ActionMeta) -> HdrTransform {
        match dir {
            // Outbound traffic needs its source IP and source port
            Direction::Out => {
                let ip = IpMod::new_src(self.nat.entry.ip.into());

                meta.insert_typed(&ExternalIpTag);

                HdrTransform {
                    name: SNAT_NAME.to_string(),
                    inner_ip: HeaderAction::Modify(ip),
                    inner_ulp: UlpHeaderAction::Modify(UlpMetaModify {
                        generic: UlpGenericModify {
                            src_port: Some(self.nat.entry.port),
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
                let ip = IpMod::new_dst(self.nat.key.into());

                HdrTransform {
                    name: SNAT_NAME.to_string(),
                    inner_ip: HeaderAction::Modify(ip),
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

// NOTE: we may or may not want to fuse with `SNatDesc` using an
// `enum PrivatePort` or similar -- depends on what the best way is
// to handle body transforms of nested ICMP like OPTE#369.
pub struct SNatIcmpEchoDesc<T: ConcreteIpAddr> {
    nat: SNatAlloc<T>,
    echo_ident: u16,
}

pub const SNAT_ICMP_ECHO_NAME: &str = "SNAT_ICMP_ECHO";

impl<T: ConcreteIpAddr> ActionDesc for SNatIcmpEchoDesc<T> {
    // SNAT needs to generate an additional transform for ICMP traffic in
    // order to treat the Echo Identifier as a psuedo ULP port.
    fn gen_ht(&self, dir: Direction, meta: &mut ActionMeta) -> HdrTransform {
        match dir {
            // Outbound traffic needs its source IP rewritten, and its
            // 'source port' placed into the ICMP echo ID field.
            Direction::Out => {
                let ip = IpMod::new_src(self.nat.entry.ip.into());

                meta.insert_typed(&ExternalIpTag);

                HdrTransform {
                    name: SNAT_NAME.to_string(),
                    inner_ip: HeaderAction::Modify(ip),
                    inner_ulp: UlpHeaderAction::Modify(UlpMetaModify {
                        icmp_id: Some(self.nat.entry.port),
                        ..Default::default()
                    }),
                    ..Default::default()
                }
            }

            // Inbound traffic needs its destination IP and
            // destination port mapped back to the private values that
            // the guest expects to see.
            Direction::In => {
                let ip = IpMod::new_dst(self.nat.key.into());

                HdrTransform {
                    name: SNAT_NAME.to_string(),
                    inner_ip: HeaderAction::Modify(ip),
                    inner_ulp: UlpHeaderAction::Modify(UlpMetaModify {
                        icmp_id: Some(self.echo_ident),
                        ..Default::default()
                    }),
                    ..Default::default()
                }
            }
        }
    }

    fn name(&self) -> &str {
        SNAT_ICMP_ECHO_NAME
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ddi::mblk::MsgBlk;
    use crate::engine::ether::Ethernet;
    use crate::engine::ether::EthernetRef;
    use crate::engine::ip::v4::Ipv4;
    use crate::engine::ip::v4::Ipv4Ref;
    use ingot::ethernet::Ethertype;
    use ingot::ip::IpProtocol;
    use ingot::tcp::Tcp;
    use ingot::tcp::TcpFlags;
    use ingot::tcp::TcpRef;
    use ingot::types::HeaderLen;

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

        let snat = SNat::new(priv_ip);
        snat.add(pub_ip, 8765..=8765);
        let mut action_meta = ActionMeta::new();
        assert!(snat.tcp_pool.verify_available(priv_ip, pub_ip, pub_port));

        // ================================================================
        // Build the packet
        // ================================================================
        let body: Vec<u8> = vec![];
        let tcp = Tcp {
            source: priv_port,
            destination: outside_port,
            ..Default::default()
        };
        let ip4 = Ipv4 {
            source: priv_ip,
            destination: outside_ip,
            protocol: IpProtocol::TCP,
            total_len: (Ipv4::MINIMUM_LENGTH + (&tcp, &body).packet_length())
                as u16,
            ..Default::default()
        };
        let eth = Ethernet {
            destination: dest_mac,
            source: priv_mac,
            ethertype: Ethertype::IPV4,
        };

        let mut pkt_m = MsgBlk::new_ethernet_pkt((&eth, &ip4, &tcp, &body));
        let mut pkt = Packet::parse_outbound(pkt_m.iter_mut(), GenericUlp {})
            .unwrap()
            .to_full_meta();
        pkt.compute_checksums();

        // ================================================================
        // Verify descriptor generation.
        // ================================================================
        let flow_out = InnerFlowId::from(pkt.meta());
        let desc = match snat.gen_desc(&flow_out, &pkt, &action_meta) {
            Ok(AllowOrDeny::Allow(desc)) => desc,
            _ => panic!("expected AllowOrDeny::Allow(desc) result"),
        };
        assert!(!snat.tcp_pool.verify_available(priv_ip, pub_ip, pub_port));

        // ================================================================
        // Verify outbound header transformation
        // ================================================================
        let out_ht = desc.gen_ht(Direction::Out, &mut action_meta);
        out_ht.run(pkt.meta_mut()).unwrap();

        let pmo = pkt.meta();
        let ether_meta = pmo.inner_ether();
        assert_eq!(ether_meta.source(), priv_mac);
        assert_eq!(ether_meta.destination(), dest_mac);

        let ip4_meta = match pmo.inner_ip4() {
            Some(v) => v,
            _ => panic!("expect Ipv4Meta"),
        };

        assert_eq!(ip4_meta.source(), pub_ip);
        assert_eq!(ip4_meta.destination(), outside_ip);
        assert_eq!(ip4_meta.protocol(), IpProtocol::TCP);

        let tcp_meta = match pmo.inner_tcp() {
            Some(v) => v,
            _ => panic!("expect TcpMeta"),
        };

        assert_eq!(tcp_meta.source(), pub_port);
        assert_eq!(tcp_meta.destination(), outside_port);
        assert_eq!(tcp_meta.flags(), TcpFlags::empty());

        // ================================================================
        // Verify inbound header transformation.
        // ================================================================
        let tcp = Tcp {
            source: outside_port,
            destination: pub_port,
            ..Default::default()
        };
        let ip4 = Ipv4 {
            source: outside_ip,
            destination: pub_ip,
            protocol: IpProtocol::TCP,
            total_len: (Ipv4::MINIMUM_LENGTH + (&tcp, &body).packet_length())
                as u16,
            ..Default::default()
        };
        let eth = Ethernet {
            destination: priv_mac,
            source: dest_mac,
            ethertype: Ethertype::IPV4,
        };

        let mut pkt_m = MsgBlk::new_ethernet_pkt((&eth, &ip4, &tcp, &body));
        let mut pkt = Packet::parse_inbound(pkt_m.iter_mut(), GenericUlp {})
            .unwrap()
            .to_full_meta();
        pkt.compute_checksums();

        let in_ht = desc.gen_ht(Direction::In, &mut action_meta);
        in_ht.run(pkt.meta_mut()).unwrap();

        let pmi = pkt.meta();
        let ether_meta = pmi.inner_ether();
        assert_eq!(ether_meta.source(), dest_mac);
        assert_eq!(ether_meta.destination(), priv_mac);

        let ip4_meta = match pmi.inner_ip4() {
            Some(v) => v,
            _ => panic!("expect Ipv4Meta"),
        };

        assert_eq!(ip4_meta.source(), outside_ip);
        assert_eq!(ip4_meta.destination(), priv_ip);
        assert_eq!(ip4_meta.protocol(), IpProtocol::TCP);

        let tcp_meta = match pmi.inner_tcp() {
            Some(v) => v,
            _ => panic!("expect TcpMeta"),
        };

        assert_eq!(tcp_meta.source(), outside_port);
        assert_eq!(tcp_meta.destination(), priv_port);
        assert_eq!(tcp_meta.flags(), TcpFlags::empty());

        // ================================================================
        // Verify other ULPs are unaffected.
        // ================================================================
        assert!(snat.udp_pool.verify_available(priv_ip, pub_ip, pub_port));
        assert!(snat.icmp_pool.verify_available(priv_ip, pub_ip, pub_port));

        // ================================================================
        // Drop the descriptor and verify the IP/port resource is
        // handed back to the pool.
        // ================================================================
        drop(desc);
        assert!(snat.tcp_pool.verify_available(priv_ip, pub_ip, pub_port));
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
        let npe1 = match pool.obtain_raw(&priv1) {
            Ok(npe) => npe,
            _ => panic!("failed to obtain mapping"),
        };
        assert_eq!(pool.num_avail(priv1).unwrap(), 3071);
        assert_eq!(npe1.ip, external_ip);
        assert!(npe1.port >= 1025);
        assert!(npe1.port <= 4096);

        assert_eq!(pool.num_avail(priv2).unwrap(), 4096);
        let npe2 = match pool.obtain_raw(&priv2) {
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

    struct RestoreTestContext {
        private_ips: [Ipv4Addr; 2],
        port_ranges: [RangeInclusive<u16>; 2],
        external_ip: Ipv4Addr,
        original_pool: Arc<NatPool<Ipv4Addr>>,
        restore_pool: Arc<NatPool<Ipv4Addr>>,
    }

    impl RestoreTestContext {
        fn new() -> Self {
            let private_ips = [
                "192.168.2.8".parse::<Ipv4Addr>().unwrap(),
                "192.168.2.33".parse::<Ipv4Addr>().unwrap(),
            ];
            let port_ranges = [1025..=4096, 4097..=8192];
            let external_ip = "52.10.128.69".parse().unwrap();

            let original_pool = Arc::new(NatPool::new());
            original_pool.add(
                private_ips[0],
                external_ip,
                port_ranges[0].clone(),
            );
            original_pool.add(
                private_ips[1],
                external_ip,
                port_ranges[1].clone(),
            );

            let restore_pool = Arc::new(NatPool::new());
            restore_pool.add(
                private_ips[0],
                external_ip,
                port_ranges[0].clone(),
            );

            Self {
                private_ips,
                port_ranges,
                external_ip,
                original_pool,
                restore_pool,
            }
        }

        fn obtain_from_original(
            &self,
            n_to_take: usize,
        ) -> Vec<FiniteHandle<NatPool<Ipv4Addr>>> {
            (0..n_to_take)
                .map(|_| {
                    self.original_pool
                        .obtain(&self.private_ips[0])
                        .expect("able to obtain handle from original pool")
                })
                .collect()
        }
    }

    #[test]
    fn can_restore_previously_obtained_mapping() {
        let ctx = RestoreTestContext::new();

        // Take a few handles out of the pool.
        //
        // This is pretty important. The NatPool type pops entries off the back,
        // i.e., starting with the highest port. So obtaining one entry and
        // restoring one are hard to tell apart with an empty pool.
        let n_avail = ctx.original_pool.num_avail(ctx.private_ips[0]).unwrap();
        assert_eq!(n_avail, ctx.port_ranges[0].len());
        let n_to_take = 10;
        let original_handles = ctx.obtain_from_original(n_to_take);
        let handle1 = original_handles.last().unwrap();
        assert_eq!(
            n_avail - n_to_take,
            ctx.original_pool.num_avail(ctx.private_ips[0]).unwrap()
        );

        // Since we've previously obtained the entry on the original pool, it
        // should be "restorable" on the new pool too.
        assert_eq!(
            n_avail,
            ctx.restore_pool.num_avail(ctx.private_ips[0]).unwrap()
        );
        let restored_handle =
            ctx.restore_pool.reclaim(&handle1.key, handle1.entry).expect(
                "should be able to restore previous entry in an empty pool",
            );
        assert_eq!(
            n_avail - 1,
            ctx.restore_pool.num_avail(ctx.private_ips[0]).unwrap()
        );
        assert_eq!(handle1.key, restored_handle.key);
        assert_eq!(handle1.entry, restored_handle.entry);

        // But we shouldn't be able to restore it a second time
        let Err(err) = ctx.restore_pool.reclaim(&handle1.key, handle1.entry)
        else {
            panic!("unexpected success restoring handle a second time");
        };
        std::assert_matches!(err, ResourceError::InUse(_));
        assert_eq!(
            n_avail - 1,
            ctx.restore_pool.num_avail(ctx.private_ips[0]).unwrap()
        );
    }

    #[test]
    fn cannot_restore_mapping_restore_pool_does_not_have() {
        let ctx = RestoreTestContext::new();

        // Create a handle, from the _second_ private IP.
        let Ok(unrestorable) = ctx.original_pool.obtain(&ctx.private_ips[1])
        else {
            panic!("should be able to obtain handle from pool");
        };

        // The new pool doesn't have this private IP at all.
        let Err(err) =
            ctx.restore_pool.reclaim(&unrestorable.key, unrestorable.entry)
        else {
            panic!("unexpected success restoring missing mapping");
        };
        std::assert_matches!(err, ResourceError::NoMatch(_));

        // Also check that we can't restore something with the right key, but
        // that's outside the port range.
        let key = ctx.private_ips[0];
        let Err(err) = ctx
            .restore_pool
            .reclaim(&key, NatPoolEntry { ip: ctx.external_ip, port: 12000 })
        else {
            panic!(
                "unexpected success restoring handle with out of range port"
            );
        };
        std::assert_matches!(err, ResourceError::NoMatch(_));

        // And that we can't restore an otherwise valid entry, but which points
        // at the wrong external IP.
        let bad_ip = "1.1.1.1".parse().unwrap();
        let Err(err) = ctx
            .restore_pool
            .reclaim(&key, NatPoolEntry { ip: bad_ip, port: 2000 })
        else {
            panic!("unexpected success restoring handle with bad external IP");
        };
        std::assert_matches!(err, ResourceError::NoMatch(_));
    }

    #[test]
    fn obtain_never_yields_restored_mapping() {
        let ctx = RestoreTestContext::new();

        // Obtain a mapping from the pool, and restore it on the new pool.
        let Ok(original_handle) = ctx.original_pool.obtain(&ctx.private_ips[0])
        else {
            panic!("should be able to obtain handle from new pool");
        };
        let Ok(restored_handle) = ctx
            .restore_pool
            .reclaim(&ctx.private_ips[0], original_handle.entry)
        else {
            panic!("should be able to restore handle from new pool");
        };

        // Obtaining new resources from the pool should never yield the mapping
        // we restored. We need to keep references to the handles around in a
        // container so they don't release themselves to the pool right away.
        let n_avail = ctx.restore_pool.num_avail(ctx.private_ips[0]).unwrap();
        let mut drained_handles = Vec::with_capacity(n_avail);
        while let Ok(handle) = ctx.restore_pool.obtain(&original_handle.key) {
            assert_ne!(handle.entry, restored_handle.entry);
            drained_handles.push(handle);
        }
        assert_eq!(drained_handles.len(), n_avail);
        assert_eq!(ctx.restore_pool.num_avail(ctx.private_ips[0]).unwrap(), 0);
    }

    #[test]
    fn can_obtain_restored_handle_after_drop() {
        let ctx = RestoreTestContext::new();

        // Take a few handles out of the original pool.
        let n_avail = ctx.original_pool.num_avail(ctx.private_ips[0]).unwrap();
        assert_eq!(n_avail, ctx.port_ranges[0].len());
        let n_to_take = 10;
        let original_handles = ctx.obtain_from_original(n_to_take);
        let original_handle = original_handles.last().unwrap();
        assert_eq!(
            n_avail - n_to_take,
            ctx.original_pool.num_avail(ctx.private_ips[0]).unwrap()
        );

        // Restore the last handle in the new pool.
        let Ok(restored_handle) = ctx
            .restore_pool
            .reclaim(&ctx.private_ips[0], original_handle.entry)
        else {
            panic!("should be able to restore handle from restore pool");
        };

        let n_original_avail =
            ctx.original_pool.num_avail(ctx.private_ips[0]).unwrap();
        let n_restored_avail =
            ctx.restore_pool.num_avail(ctx.private_ips[0]).unwrap();

        // Now if we drop the restored handle, we should be able to obtain it
        // again. The counts of available entries should go up by one in the
        // restored pool, but not change in the original pool.
        drop(restored_handle);
        assert_eq!(
            ctx.restore_pool.num_avail(ctx.private_ips[0]).unwrap(),
            n_restored_avail + 1
        );
        assert_eq!(
            ctx.original_pool.num_avail(ctx.private_ips[0]).unwrap(),
            n_original_avail,
        );

        // We should need to obtain `n_to_take` items before we get to the one
        // we released.
        let mut held = Vec::with_capacity(n_to_take);
        for _ in 0..n_to_take {
            let newest = ctx
                .restore_pool
                .obtain(&ctx.private_ips[0])
                .expect("able to obtain entry");
            held.push(newest);
        }
        let newest = held.last().unwrap();
        assert_eq!(newest.key, original_handle.key);
        assert_eq!(newest.entry, original_handle.entry);
    }
}

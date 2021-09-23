use crate::ether::{EtherAddr, EtherMeta};
use crate::headers::{HeaderAction, IcmpEchoMeta, Ipv4Meta, TcpMeta, UdpMeta};
use crate::ip4::Ipv4Addr;
use crate::layer::InnerFlowId;
use crate::rule::{
    ActionDesc, ResourceError, Resources, StatefulAction, UlpHdrAction, HT,
};
use crate::Direction;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::sync::Arc;
#[cfg(any(feature = "std", test))]
use std::sync::Arc;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::collections::btree_map::BTreeMap;
#[cfg(any(feature = "std", test))]
use std::collections::btree_map::BTreeMap;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::prelude::v1::*;

use std::ops::Range;
use std::prelude::v1::*;

pub struct NatPool {
    // Map private IP to public IP + free list of ports
    free_list: BTreeMap<Ipv4Addr, (Ipv4Addr, Vec<u16>)>,
}

impl NatPool {
    pub fn add(
        &mut self,
        priv_ip: Ipv4Addr,
        pub_ip: Ipv4Addr,
        pub_ports: Range<u16>,
    ) {
        let free_list = pub_ports.clone().collect();
        self.free_list.insert(priv_ip, (pub_ip, free_list));
    }

    pub fn num_avail(&self, priv_ip: Ipv4Addr) -> Result<usize, ResourceError> {
        match self.free_list.get(&priv_ip) {
            Some((_, ports)) => Ok(ports.len()),
            _ => Err(ResourceError::NoMatch(priv_ip.to_string())),
        }
    }

    pub fn new() -> Self {
        NatPool { free_list: BTreeMap::new() }
    }

    pub fn obtain(
        &mut self,
        priv_ip: Ipv4Addr,
    ) -> Result<(Ipv4Addr, u16), ResourceError> {
        match self.free_list.get_mut(&priv_ip) {
            Some((ip, ports)) => {
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
        match self.free_list.get_mut(&priv_ip) {
            Some((_ip, ports)) => {
                let (_, pub_port) = p;
                ports.push(pub_port);
            }

            None => {
                panic!("cannot release port to unknown mapping: {}", priv_ip);
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct DynNat4 {
    layer: String,
    priv_ip: Ipv4Addr,
    priv_mac: EtherAddr,
    pub_mac: EtherAddr,
}

impl DynNat4 {
    pub fn new(
        layer: String,
        addr: Ipv4Addr,
        priv_mac: EtherAddr,
        pub_mac: EtherAddr,
    ) -> Self {
        DynNat4 { layer, priv_ip: addr.into(), priv_mac, pub_mac }
    }
}

impl StatefulAction for DynNat4 {
    fn gen_desc(
        &self,
        flow_id: InnerFlowId,
        resources: &Resources,
    ) -> Arc<dyn ActionDesc> {
        let pool = &resources.nat_pool;
        let priv_port = flow_id.src_port;
        let mut lock = pool.lock().unwrap();
        match lock.as_mut().unwrap().obtain(self.priv_ip) {
            Ok((pub_ip, pub_port)) => {
                let desc = DynNat4Desc {
                    priv_mac: self.priv_mac,
                    priv_ip: self.priv_ip,
                    priv_port: priv_port,
                    pub_mac: self.pub_mac,
                    pub_ip,
                    pub_port,
                };
                // TODO replace this with SDT probe
                // println!("desc: {:?}", desc);
                Arc::new(desc)
            }

            Err(e) => {
                todo!("return error on resource acquisition failure: {:?}", e);
                // return Err(ActionInitError::ResourceError(e)),
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct DynNat4Desc {
    pub_mac: EtherAddr,
    pub_ip: Ipv4Addr,
    pub_port: u16,
    priv_mac: EtherAddr,
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
            Direction::Out => {
                HT {
                    name: DYN_NAT4_NAME.to_string(),
                    inner_ether: EtherMeta::modify(Some(self.pub_mac), None),
                    inner_ip: Ipv4Meta::modify(Some(self.pub_ip), None, None),
                    ulp: UlpHdrAction {
                        // TODO Implement NAT support for DU messages.
                        icmp_du: HeaderAction::Ignore,
                        icmp_echo: IcmpEchoMeta::modify(Some(self.pub_port)),
                        tcp: TcpMeta::modify(Some(self.pub_port), None, None),
                        udp: UdpMeta::modify(Some(self.pub_port), None),
                    },
                    ..Default::default()
                }
            }

            Direction::In => {
                HT {
                    name: DYN_NAT4_NAME.to_string(),
                    inner_ether: EtherMeta::modify(None, Some(self.priv_mac)),
                    inner_ip: Ipv4Meta::modify(None, Some(self.priv_ip), None),
                    ulp: UlpHdrAction {
                        // TODO Implement NAT support for DU messages.
                        icmp_du: HeaderAction::Ignore,
                        icmp_echo: IcmpEchoMeta::modify(Some(self.priv_port)),
                        tcp: TcpMeta::modify(None, Some(self.priv_port), None),
                        udp: UdpMeta::modify(None, Some(self.priv_port)),
                    },
                    ..Default::default()
                }
            }
        }
    }

    fn name(&self) -> &str {
        DYN_NAT4_NAME
    }
}

#[test]
fn dyn_nat4_ht() {
    use crate::ether::ETHER_TYPE_IPV4;
    use crate::headers::{IpMeta, UlpMeta};
    use crate::ip4::Protocol;
    use crate::packet::PacketMeta;

    let priv_mac = EtherAddr::from([0x02, 0x08, 0x20, 0xd8, 0x35, 0xcf]);
    let pub_mac = EtherAddr::from([0xa8, 0x40, 0x25, 0x00, 0x00, 0x63]);
    let dest_mac = EtherAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d]);
    let priv_ip = "10.0.0.220".parse().unwrap();
    let priv_port = "4999".parse().unwrap();
    let pub_ip = "52.10.128.69".parse().unwrap();
    let pub_port = "8765".parse().unwrap();
    let outside_ip = "76.76.21.21".parse().unwrap();

    let nat =
        DynNat4Desc { pub_mac, pub_ip, pub_port, priv_mac, priv_ip, priv_port };

    // TODO test in_ht
    let out_ht = nat.gen_ht(Direction::Out);

    let ether =
        EtherMeta { src: priv_mac, dst: dest_mac, ether_type: ETHER_TYPE_IPV4 };
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
        inner_ether: Some(ether),
        inner_ip: Some(ip),
        ulp: Some(ulp),
        ..Default::default()
    };

    let ether_meta = meta.inner_ether.as_ref().unwrap();
    assert_eq!(ether_meta.src, priv_mac);
    assert_eq!(ether_meta.dst, dest_mac);

    out_ht.run(&mut meta);

    let ether_meta = meta.inner_ether.as_ref().unwrap();
    assert_eq!(ether_meta.src, pub_mac);
    assert_eq!(ether_meta.dst, dest_mac);

    let ip4_meta = match meta.inner_ip.as_ref().unwrap() {
        IpMeta::Ip4(v) => v,
        _ => panic!("expect Ipv4Meta"),
    };

    assert_eq!(ip4_meta.src, pub_ip);
    assert_eq!(ip4_meta.dst, outside_ip);
    assert_eq!(ip4_meta.proto, Protocol::TCP);

    let tcp_meta = match meta.ulp.as_ref().unwrap() {
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

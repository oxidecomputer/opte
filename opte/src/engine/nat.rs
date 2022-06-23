// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use core::fmt;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::ToString;
        use alloc::sync::Arc;
        use alloc::vec::Vec;
    } else {
        use std::string::ToString;
        use std::sync::Arc;
        use std::vec::Vec;
    }
}

use super::ether::EtherMeta;
use super::ip4::Ipv4Meta;
use super::layer::InnerFlowId;
use super::port::meta::Meta;
use super::rule::{
    self, ActionDesc, AllowOrDeny, DataPredicate, Predicate, StatefulAction, HT,
};
use crate::api::{Direction, Ipv4Addr, MacAddr};

#[derive(Clone)]
pub struct Nat4 {
    priv_ip: Ipv4Addr,
    public_ip: Ipv4Addr,
}

impl Nat4 {
    pub fn new(priv_ip: Ipv4Addr, public_ip: Ipv4Addr) -> Self {
        Self { priv_ip: priv_ip.into(), public_ip: public_ip.into() }
    }
}

impl fmt::Display for Nat4 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} <=> {}", self.priv_ip, self.public_ip)
    }
}

impl StatefulAction for Nat4 {
    fn gen_desc(
        &self,
        _flow_id: &InnerFlowId,
        meta: &mut Meta,
    ) -> rule::GenDescResult {
        let mac_addr = meta.get::<MacAddr>();
        let desc = Nat4Desc {
            priv_ip: self.priv_ip,
            public_ip: self.public_ip,
            // XXX-EXT-IP This is assuming ext_ip_hack and will only
            // allow for inbound connections, this will not work for
            // outbound. If we want that we'll want to actually query
            // the native router/ARP table.
            src_mac: mac_addr.cloned(),
        };
        Ok(AllowOrDeny::Allow(Arc::new(desc)))
    }

    // XXX we should be able to set implicit predicates if we add an
    // IpCidr field to describe which subnet the client is on; but for
    // now just keep the predicates fully explicit.
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        (vec![], vec![])
    }
}

#[derive(Clone)]
pub struct Nat4Desc {
    priv_ip: Ipv4Addr,
    public_ip: Ipv4Addr,
    // XXX-EXT-IP
    src_mac: Option<MacAddr>,
}

pub const NAT4_NAME: &'static str = "NAT4";

impl ActionDesc for Nat4Desc {
    fn gen_ht(&self, dir: Direction) -> HT {
        match dir {
            Direction::Out => {
                let mut ht = HT {
                    name: NAT4_NAME.to_string(),
                    inner_ip: Ipv4Meta::modify(
                        Some(self.public_ip),
                        None,
                        None,
                    ),
                    ..Default::default()
                };

                // XXX-EXT-IP hack to rewrite destination MAC adress
                // from virtual gateway addr to actual address that
                // initiated connection.
                if self.src_mac.is_some() {
                    ht.inner_ether = EtherMeta::modify(None, self.src_mac);
                }
                ht
            }

            Direction::In => HT {
                name: NAT4_NAME.to_string(),
                inner_ip: Ipv4Meta::modify(None, Some(self.priv_ip), None),
                ..Default::default()
            },
        }
    }

    fn name(&self) -> &str {
        NAT4_NAME
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn nat4_rewrite() {
        use crate::api::MacAddr;
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
        let outside_ip = "76.76.21.21".parse().unwrap();
        let outside_port = 80;
        let nat = Nat4::new(priv_ip, pub_ip);
        let mut port_meta = Meta::new();

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
        let desc = match nat.gen_desc(&flow_out, &mut port_meta) {
            Ok(AllowOrDeny::Allow(desc)) => desc,
            _ => panic!("expected AllowOrDeny::Allow(desc) result"),
        };

        // ================================================================
        // Verify outbound header transformation
        // ================================================================
        let out_ht = desc.gen_ht(Direction::Out);
        out_ht.run(&mut pmo);

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

        assert_eq!(tcp_meta.src, priv_port);
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
            dst: priv_port,
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
        in_ht.run(&mut pmi);

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
    }
}

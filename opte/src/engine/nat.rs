// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! 1:1 NAT.

use super::headers::HeaderAction;
use super::headers::IpMod;
use super::ip4::Ipv4Mod;
use super::ip6::Ipv6Mod;
use super::packet::InnerFlowId;
use super::packet::Packet;
use super::packet::Parsed;
use super::port::meta::ActionMeta;
use super::predicate::DataPredicate;
use super::predicate::Predicate;
use super::rule;
use super::rule::ActionDesc;
use super::rule::AllowOrDeny;
use super::rule::HdrTransform;
use super::rule::StatefulAction;
use crate::engine::snat::ConcreteIpAddr;
use core::fmt;
use core::marker::PhantomData;
use opte_api::Direction;
use opte_api::IpAddr;

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

/// A mapping from a private to external IP address for NAT.
#[derive(Debug, Clone, Copy)]
pub struct Nat {
    priv_ip: IpAddr,
    external_ip: IpAddr,
}

impl Nat {
    /// Create a new NAT mapping from a private to public IP address.
    pub fn new<T: ConcreteIpAddr>(priv_ip: T, external_ip: T) -> Self {
        Self { priv_ip: priv_ip.into(), external_ip: external_ip.into() }
    }
}

impl fmt::Display for Nat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} <=> {}", self.priv_ip, self.external_ip)
    }
}

impl StatefulAction for Nat {
    fn gen_desc(
        &self,
        _flow_id: &InnerFlowId,
        _pkt: &Packet<Parsed>,
        _meta: &mut ActionMeta,
    ) -> rule::GenDescResult {
        let desc =
            NatDesc { priv_ip: self.priv_ip, external_ip: self.external_ip };
        Ok(AllowOrDeny::Allow(Arc::new(desc)))
    }

    // XXX we should be able to set implicit predicates if we add an
    // IpCidr field to describe which subnet the client is on; but for
    // now just keep the predicates fully explicit.
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        (vec![], vec![])
    }
}

/// An action descriptor for a NAT action.
#[derive(Debug, Clone, Copy)]
pub struct NatDesc {
    priv_ip: IpAddr,
    external_ip: IpAddr,
}

pub const NAT_NAME: &'static str = "NAT";

impl ActionDesc for NatDesc {
    fn gen_ht(&self, dir: Direction) -> HdrTransform {
        match dir {
            Direction::Out => {
                let ip = match self.external_ip {
                    IpAddr::Ip4(ipv4) => IpMod::from(Ipv4Mod {
                        src: Some(ipv4),
                        ..Default::default()
                    }),
                    IpAddr::Ip6(ipv6) => IpMod::from(Ipv6Mod {
                        src: Some(ipv6),
                        ..Default::default()
                    }),
                };

                HdrTransform {
                    name: NAT_NAME.to_string(),
                    inner_ip: HeaderAction::Modify(ip, PhantomData),
                    ..Default::default()
                }
            }

            Direction::In => {
                let ip = match self.priv_ip {
                    IpAddr::Ip4(ipv4) => IpMod::from(Ipv4Mod {
                        dst: Some(ipv4),
                        ..Default::default()
                    }),
                    IpAddr::Ip6(ipv6) => IpMod::from(Ipv6Mod {
                        dst: Some(ipv6),
                        ..Default::default()
                    }),
                };
                HdrTransform {
                    name: NAT_NAME.to_string(),
                    inner_ip: HeaderAction::Modify(ip, PhantomData),
                    ..Default::default()
                }
            }
        }
    }

    fn name(&self) -> &str {
        NAT_NAME
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::engine::ether::EtherMeta;
    use crate::engine::GenericUlp;
    use opte_api::Direction::*;

    #[test]
    fn nat4_rewrite() {
        use crate::engine::ether::EtherHdr;
        use crate::engine::ether::EtherType;
        use crate::engine::headers::IpMeta;
        use crate::engine::headers::UlpMeta;
        use crate::engine::ip4::Ipv4Hdr;
        use crate::engine::ip4::Ipv4Meta;
        use crate::engine::ip4::Protocol;
        use crate::engine::tcp::TcpMeta;
        use opte_api::MacAddr;

        let priv_mac = MacAddr::from([0xA8, 0x40, 0x25, 0xF0, 0x00, 0x01]);
        let dest_mac = MacAddr::from([0xA8, 0x40, 0x25, 0xFF, 0x77, 0x77]);
        let priv_ip = "10.0.0.220".parse().unwrap();
        let priv_port = "4999".parse().unwrap();
        let pub_ip = "52.10.128.69".parse().unwrap();
        let outside_ip = "76.76.21.21".parse().unwrap();
        let outside_port = 80;
        let nat = Nat::new(priv_ip, pub_ip);
        let mut ameta = ActionMeta::new();

        // ================================================================
        // Build the packet metadata
        // ================================================================
        let body = vec![];
        let tcp =
            TcpMeta { src: priv_port, dst: outside_port, ..Default::default() };
        let mut ip4 = Ipv4Meta {
            src: priv_ip,
            dst: outside_ip,
            proto: Protocol::TCP,
            total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len() + body.len()) as u16,
            ..Default::default()
        };
        ip4.compute_hdr_csum();
        let eth = EtherMeta {
            ether_type: EtherType::Ipv4,
            src: priv_mac,
            dst: dest_mac,
        };
        let mut pkt = Packet::alloc_and_expand(128);
        let mut wtr = pkt.seg0_wtr();
        eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
        ip4.emit(wtr.slice_mut(ip4.hdr_len()).unwrap());
        tcp.emit(wtr.slice_mut(tcp.hdr_len()).unwrap());
        wtr.write(&body).unwrap();
        let mut pkt = pkt.parse(Out, GenericUlp {}).unwrap();

        // ================================================================
        // Verify descriptor generation.
        // ================================================================
        let flow_out = InnerFlowId::from(pkt.meta());
        let desc = match nat.gen_desc(&flow_out, &pkt, &mut ameta) {
            Ok(AllowOrDeny::Allow(desc)) => desc,
            _ => panic!("expected AllowOrDeny::Allow(desc) result"),
        };

        // ================================================================
        // Verify outbound header transformation
        // ================================================================
        let out_ht = desc.gen_ht(Direction::Out);
        let mut pmo = pkt.meta_mut();
        out_ht.run(&mut pmo).unwrap();

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

        assert_eq!(tcp_meta.src, priv_port);
        assert_eq!(tcp_meta.dst, outside_port);
        assert_eq!(tcp_meta.flags, 0);

        // ================================================================
        // Verify inbound header transformation.
        // ================================================================
        let body = vec![];
        let tcp =
            TcpMeta { src: outside_port, dst: priv_port, ..Default::default() };
        let mut ip4 = Ipv4Meta {
            src: outside_ip,
            dst: priv_ip,
            proto: Protocol::TCP,
            total_len: (Ipv4Hdr::BASE_SIZE + tcp.hdr_len() + body.len()) as u16,
            ..Default::default()
        };
        ip4.compute_hdr_csum();
        let eth = EtherMeta {
            dst: priv_mac,
            src: dest_mac,
            ether_type: EtherType::Ipv4,
        };
        let mut pkt = Packet::alloc_and_expand(128);
        let mut wtr = pkt.seg0_wtr();
        eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
        ip4.emit(wtr.slice_mut(ip4.hdr_len()).unwrap());
        tcp.emit(wtr.slice_mut(tcp.hdr_len()).unwrap());
        wtr.write(&body).unwrap();
        let mut pkt = pkt.parse(Out, GenericUlp {}).unwrap();

        let mut pmi = pkt.meta_mut();
        let in_ht = desc.gen_ht(Direction::In);
        in_ht.run(&mut pmi).unwrap();

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
    }
}

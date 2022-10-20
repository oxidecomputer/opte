// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use super::ether::EtherMeta;
use super::ip4::Ipv4Meta;
use super::ip6::Ipv6Meta;
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
use opte_api::Direction;
use opte_api::IpAddr;
use opte_api::MacAddr;

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
    // XXX-EXT-IP Remove
    phys_gw_mac: Option<MacAddr>,
}

impl Nat {
    /// Create a new NAT mapping from a private to public IP address.
    pub fn new<T: ConcreteIpAddr>(
        priv_ip: T,
        external_ip: T,
        phys_gw_mac: Option<MacAddr>,
    ) -> Self {
        Self {
            priv_ip: priv_ip.into(),
            external_ip: external_ip.into(),
            phys_gw_mac,
        }
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
        let desc = NatDesc {
            priv_ip: self.priv_ip,
            external_ip: self.external_ip,
            // XXX-EXT-IP This is assuming ext_ip_hack. All packets
            // outbound for IG will have their dest mac rewritten to
            // go to physical gateway, which will then properly route
            // the destination IP.
            phys_gw_mac: self.phys_gw_mac.clone(),
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

/// An action descriptor for a NAT action.
#[derive(Debug, Clone, Copy)]
pub struct NatDesc {
    priv_ip: IpAddr,
    external_ip: IpAddr,
    // XXX-EXT-IP
    phys_gw_mac: Option<MacAddr>,
}

pub const NAT_NAME: &'static str = "NAT";

impl ActionDesc for NatDesc {
    fn gen_ht(&self, dir: Direction) -> HdrTransform {
        match dir {
            Direction::Out => {
                let inner_ip = match self.external_ip {
                    IpAddr::Ip4(ipv4) => {
                        Ipv4Meta::modify(Some(ipv4), None, None)
                    }
                    IpAddr::Ip6(ipv6) => {
                        Ipv6Meta::modify(Some(ipv6), None, None)
                    }
                };
                let mut ht = HdrTransform {
                    name: NAT_NAME.to_string(),
                    inner_ip,
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

            Direction::In => {
                let inner_ip = match self.priv_ip {
                    IpAddr::Ip4(ipv4) => {
                        Ipv4Meta::modify(None, Some(ipv4), None)
                    }
                    IpAddr::Ip6(ipv6) => {
                        Ipv6Meta::modify(None, Some(ipv6), None)
                    }
                };
                HdrTransform {
                    name: NAT_NAME.to_string(),
                    inner_ip,
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

    #[test]
    fn nat4_rewrite() {
        use crate::engine::checksum::HeaderChecksum;
        use crate::engine::ether::EtherHdr;
        use crate::engine::ether::EtherType;
        use crate::engine::headers::IpMeta;
        use crate::engine::headers::UlpMeta;
        use crate::engine::ip4::Ipv4Hdr;
        use crate::engine::ip4::Protocol;
        use crate::engine::ip4::UlpCsumOpt;
        use crate::engine::tcp::TcpHdr;
        use opte_api::MacAddr;

        let priv_mac = MacAddr::from([0xA8, 0x40, 0x25, 0xF0, 0x00, 0x01]);
        let dest_mac = MacAddr::from([0xA8, 0x40, 0x25, 0xFF, 0x77, 0x77]);
        let priv_ip = "10.0.0.220".parse().unwrap();
        let priv_port = "4999".parse().unwrap();
        let pub_ip = "52.10.128.69".parse().unwrap();
        let outside_ip = "76.76.21.21".parse().unwrap();
        let outside_port = 80;
        let gw_mac = MacAddr::from([0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d]);
        let nat = Nat::new(priv_ip, pub_ip, Some(gw_mac));
        let mut ameta = ActionMeta::new();

        // ================================================================
        // Build the packet metadata
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

        let ether_meta = pmo.inner.ether.as_ref().unwrap();
        assert_eq!(ether_meta.src, priv_mac);
        assert_eq!(ether_meta.dst, gw_mac);

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

        let mut pmi = pkt.meta_mut();
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
    }
}

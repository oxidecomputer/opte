// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! 1:1 NAT.

use super::headers::HeaderAction;
use super::headers::IpMod;
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
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::hash::Hash;
use core::marker::PhantomData;
use crc32fast::Hasher;
use itertools::Itertools;
use opte_api::Direction;
use opte_api::IpAddr;

/// A trait which allows a VPC implementation to specify how NAT actions
/// can be re-verified after a rule change.
///
/// This is needed for outbound flows in particular, as the flow id and opaque
/// action alone don't allow us to see the chosen external IpAddr. For the inbound
/// case, the gateway layer can successfully rematch if needed but reusing this
/// mechanism is the most sensible approach.
pub trait VerifyAddr: alloc::fmt::Debug + Send + Sync {
    fn is_addr_valid(&self, addr: &IpAddr) -> bool;
}

/// A mapping from a private to one of several external IP addresses for NAT.
#[derive(Debug, Clone)]
pub struct OutboundNat {
    priv_ip: IpAddr,
    // TODO: possibly remove Vec on ephemeral IP.
    external_ips: Vec<IpAddr>,

    verifier: Arc<dyn VerifyAddr>,
}

impl OutboundNat {
    /// Create a new NAT mapping from a private to public IP address.
    pub fn new<T: ConcreteIpAddr>(
        priv_ip: T,
        external_ips: &[T],
        verifier: Arc<impl VerifyAddr + 'static>,
    ) -> Self {
        let external_ips = external_ips.iter().copied().map(T::into).collect();
        Self { priv_ip: priv_ip.into(), external_ips, verifier }
    }
}

impl fmt::Display for OutboundNat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} <=> ", self.priv_ip)?;

        if self.external_ips.len() > 1 {
            write!(f, "{{")?;
        }

        write!(f, "{}", self.external_ips.iter().format(","))?;

        if self.external_ips.len() > 1 {
            write!(f, "}}")?;
        }

        Ok(())
    }
}

impl StatefulAction for OutboundNat {
    fn gen_desc(
        &self,
        flow_id: &InnerFlowId,
        _pkt: &Packet<Parsed>,
        _meta: &mut ActionMeta,
    ) -> rule::GenDescResult {
        // When we have several external IPs at our disposal, we are
        // to use them equally.
        let ip_idx = match self.external_ips.len() {
            0 => {
                return Err(rule::GenDescError::Unexpected {
                    msg: "Outbound NAT: no external IP addresses specified"
                        .into(),
                })
            }
            1 => 0,
            n => {
                // XXX: Is this (CRC32) the right choice of hash algo?
                let mut hasher = Hasher::new();
                flow_id.hash(&mut hasher);
                hasher.finalize() as usize % n
            }
        };

        Ok(AllowOrDeny::Allow(Arc::new(NatDesc {
            priv_ip: self.priv_ip,
            external_ip: self.external_ips[ip_idx],
            verifier: self.verifier.clone(),
        })))
    }

    // XXX we should be able to set implicit predicates if we add an
    // IpCidr field to describe which subnet the client is on; but for
    // now just keep the predicates fully explicit.
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        (vec![], vec![])
    }
}

/// A NAT mapping which preserves affinity with the external IP that a port
/// received a packet on.
pub struct InboundNat {
    priv_ip: IpAddr,
    verifier: Arc<dyn VerifyAddr>,
}

impl InboundNat {
    /// Create a new NAT mapping from a private to public IP address.
    pub fn new<T: ConcreteIpAddr>(
        priv_ip: T,
        verifier: Arc<impl VerifyAddr + 'static>,
    ) -> Self {
        Self { priv_ip: priv_ip.into(), verifier }
    }
}

impl fmt::Display for InboundNat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} <=> (external)", self.priv_ip)
    }
}

impl StatefulAction for InboundNat {
    fn gen_desc(
        &self,
        flow_id: &InnerFlowId,
        _pkt: &Packet<Parsed>,
        _meta: &mut ActionMeta,
    ) -> rule::GenDescResult {
        // We rely on the attached predicates to filter out IPs which are *not*
        // registered to this port.
        Ok(AllowOrDeny::Allow(Arc::new(NatDesc {
            priv_ip: self.priv_ip,
            external_ip: flow_id.dst_ip(),
            verifier: self.verifier.clone(),
        })))
    }

    // XXX we should be able to set implicit predicates if we add an
    // IpCidr field to describe which subnet the client is on; but for
    // now just keep the predicates fully explicit.
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        (vec![], vec![])
    }
}

/// An action descriptor for a NAT action.
#[derive(Debug, Clone)]
pub struct NatDesc {
    priv_ip: IpAddr,
    external_ip: IpAddr,
    verifier: Arc<dyn VerifyAddr>,
}

pub const NAT_NAME: &str = "NAT";

impl ActionDesc for NatDesc {
    fn gen_ht(&self, dir: Direction) -> HdrTransform {
        match dir {
            Direction::Out => {
                let ip = IpMod::new_src(self.external_ip);

                HdrTransform {
                    name: NAT_NAME.to_string(),
                    inner_ip: HeaderAction::Modify(ip, PhantomData),
                    ..Default::default()
                }
            }

            Direction::In => {
                let ip = IpMod::new_dst(self.priv_ip);

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

    fn is_valid(&self) -> bool {
        self.verifier.is_addr_valid(&self.external_ip)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::engine::ether::EtherMeta;
    use crate::engine::GenericUlp;
    use opte_api::Direction::*;

    #[derive(Debug)]
    struct DummyVerify;

    impl VerifyAddr for DummyVerify {
        fn is_addr_valid(&self, _addr: &IpAddr) -> bool {
            true
        }
    }

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
        let nat = OutboundNat::new(priv_ip, &[pub_ip], DummyVerify.into());
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
        let pmo = pkt.meta_mut();
        out_ht.run(pmo).unwrap();

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

        let pmi = pkt.meta_mut();
        let in_ht = desc.gen_ht(Direction::In);
        in_ht.run(pmi).unwrap();

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

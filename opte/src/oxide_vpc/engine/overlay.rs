// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! The Oxide Network VPC Overlay.
//!
//! This implements the Oxide Network VPC Overlay.
use core::fmt;

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

use serde::{Deserialize, Serialize};

use super::router::RouterTargetInternal;
use crate::api::{CmdOk, Direction, Ipv4Addr, MacAddr, OpteError};
use crate::engine::ether::{EtherMeta, ETHER_TYPE_IPV6};
use crate::engine::geneve::{GeneveMeta, Vni, GENEVE_PORT};
use crate::engine::headers::{HeaderAction, IpAddr};
use crate::engine::ip4::Protocol;
use crate::engine::ip6::{Ipv6Addr, Ipv6Meta};
use crate::engine::layer::{InnerFlowId, Layer};
use crate::engine::port::meta::Meta;
use crate::engine::port::{PortBuilder, Pos};
use crate::engine::rule::{
    self, Action, AllowOrDeny, DataPredicate, Predicate, Rule, StaticAction, HT,
};
use crate::engine::sync::{KMutex, KMutexType};
use crate::engine::udp::UdpMeta;
use crate::oxide_vpc::api::{GuestPhysAddr, PhysNet};
use crate::oxide_vpc::PortCfg;

pub const OVERLAY_LAYER_NAME: &'static str = "overlay";

pub fn setup(
    pb: &PortBuilder,
    cfg: &PortCfg,
) -> core::result::Result<(), OpteError> {
    // Action Index 0
    let encap = Action::Static(Arc::new(EncapAction::new(
        cfg.bsvc_addr,
        cfg.phys_ip,
        cfg.vni,
    )));

    // Action Index 1
    let decap = Action::Static(Arc::new(DecapAction::new()));

    let layer = Layer::new(OVERLAY_LAYER_NAME, pb.name(), vec![encap, decap]);
    let encap_rule = Rule::match_any(1, layer.action(0).unwrap().clone());
    layer.add_rule(Direction::Out, encap_rule);
    let decap_rule = Rule::match_any(1, layer.action(1).unwrap().clone());
    layer.add_rule(Direction::In, decap_rule);
    // NOTE The First/Last positions cannot fail; perhaps I should
    // improve the API to avoid the unwrap().
    pb.add_layer(layer, Pos::Last)
}

pub const DECAP_NAME: &'static str = "decap";
pub const ENCAP_NAME: &'static str = "encap";

/// A [`StaticAction`] to encapsulate a packet for the purpose of
/// implementing the Oxide VPC overlay network.
///
/// This action maps the Virtual IP (VIP) to its physical location. In
/// the case of a guest-to-guest packet the physical location is
/// another sled in the Oxide Physical Network. In the case of a
/// guest-to-external (whether external be a host on the Internet or
/// in the customer's network) the physical location is Boundary
/// Services. In both cases there is a [`PhysNet`] value that
/// identifies the physical location; it is comprised of three pieces
/// of data.
///
/// 1. Inner frame MAC address
///
/// 2. Outer frame IPv6 address
///
/// 3. Geneve VNI
///
/// The "physical" MAC address of a guest is the same as its virtual
/// one. We configure the guests in such a way that all destinations
/// are off link and must route through the gateway (OPTE). This
/// implies that the inner frame destination MAC address coming from
/// the guest is always some sentinel value representing the virtual
/// gateway. OPTE uses the [`PhysNet`] MAC address to rewrite this
/// inner frame destination.
///
/// In the case of Boundary Services things are a bit different with
/// regard to the inner frame MAC address. It shouldn't need to care
/// about this address, as Boundary Services doesn't really have a
/// presence on the VPC network. Rather, OPTE and Boundary Services
/// work together to implement the external side of the guest's
/// gateway. When a packet reaches the edge, Boundary Services decaps
/// the outer frame, stores some state, and then rewrites the inner
/// frame MAC addresses to values the exist in the external network.
/// For this reason, there is no need for Boundary Services to have a
/// MAC address on the VPC, and therefore has no need for that part of
/// [`PhysNet`]. We only need the IPv6 ULA address and VNI to address
/// Boundary Services.
///
/// XXX Perhaps use a separate type for the Boundary Services addr.
///
/// The outer frame IPv6 address of a guest is the ULA of the sled it
/// currently lives on. The Oxide Physical Network takes care of
/// routing this ULA correctly.
///
/// The outer frame IPv6 address of Boundary Services is some ULA on
/// the physical network, told to us during port creation.
///
/// The VNI of a guest is its VPC identifier. The VNI of Boundary
/// Services is just a dedicated, cordoned off VNI explicitly for the
/// purposes of talking to Boundary Services.
///
/// XXX The outer MAC addresses are zero'd out. Currently xde fills
/// these out. However, the plan is to create a virtual switch
/// abstraction in OPTE and have interfaces for querying the system
/// for route/MAC address info.
///
/// This action uses the [`Virt2Phys`] resource to map the virtual
/// destination to the physical location. These mappings are
/// determined by Nexus and pushed down to individual OPTE instances.
/// The mapping itself is available through the port metadata passes
/// as argument to the [`StaticAction`] callback.
pub struct EncapAction {
    bsvc_addr: PhysNet,
    // The physical IPv6 ULA of the server that hosts this guest
    // sending data.
    phys_ip_src: Ipv6Addr,
    vni: Vni,
}

impl EncapAction {
    pub fn new(bsvc_addr: PhysNet, phys_ip_src: Ipv6Addr, vni: Vni) -> Self {
        Self { bsvc_addr, phys_ip_src, vni }
    }
}

impl fmt::Display for EncapAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Encap")
    }
}

impl StaticAction for EncapAction {
    fn gen_ht(
        &self,
        // The encap action is only used for outgoing.
        _dir: Direction,
        flow_id: &InnerFlowId,
        meta: &mut Meta,
    ) -> rule::GenHtResult {
        let v2p = match meta.get::<Arc<Virt2Phys>>() {
            Some(v2p) => v2p,
            // This should never happen. If it does, then the driver
            // forgot to add the Virt2Phys metadata before processing.
            None => {
                return Err(rule::GenHtError::Unexpected {
                    msg: format!("no Virt2Phys metadata entry found"),
                })
            }
        };

        // The router layer determines a RouterTarget and stores it in
        // the meta map. We need to map this virtual target to a
        // physical one.
        let target = match meta.get::<RouterTargetInternal>() {
            Some(val) => val,
            None => {
                // This should never happen. The router should always
                // write an entry. However, we currently have no way
                // to enforce this in the type system, and thus must
                // account for this situation.
                return Err(rule::GenHtError::Unexpected {
                    msg: format!("no RouterTarget metadata entry found"),
                });
            }
        };

        let phys_target = match target {
            RouterTargetInternal::InternetGateway => self.bsvc_addr,

            RouterTargetInternal::Ip(virt_ip) => match v2p.get(&virt_ip) {
                Some(phys) => PhysNet {
                    ether: phys.ether.into(),
                    ip: phys.ip,
                    vni: self.vni,
                },

                // The router target has specified a VPC IP we do not
                // currently know about; this could be for two
                // reasons:
                //
                // 1. No such IP currently exists in the guest's VPC.
                //
                // 2. The destination IP exists in the guest's VPC,
                //    but we do not yet have a mapping for it.
                //
                // We cannot differentiate these cases from the point
                // of view of this code without more information from
                // the control plane; rather we drop the packet. If we
                // are dealing with scenario (2), the control plane
                // should eventually provide us with a mapping.
                None => return Ok(AllowOrDeny::Deny),
            },

            RouterTargetInternal::VpcSubnet(_) => {
                match v2p.get(&flow_id.dst_ip) {
                    Some(phys) => PhysNet {
                        ether: phys.ether.into(),
                        ip: phys.ip,
                        vni: self.vni,
                    },

                    // The guest is attempting to contact a VPC IP we
                    // do not currently know about; this could be for
                    // two reasons:
                    //
                    // 1. No such IP currently exists in the guest's VPC.
                    //
                    // 2. The destination IP exists in the guest's
                    //    VPC, but we do not yet have a mapping for
                    //    it.
                    //
                    // We cannot differentiate these cases from the
                    // point of view of this code without more
                    // information from the control plane; rather we
                    // drop the packet. If we are dealing with
                    // scenario (2), the control plane should
                    // eventually provide us with a mapping.
                    None => return Ok(AllowOrDeny::Deny),
                }
            }
        };

        Ok(AllowOrDeny::Allow(HT {
            name: ENCAP_NAME.to_string(),
            // We leave the outer src/dst up to the driver.
            outer_ether: EtherMeta::push(
                MacAddr::ZERO,
                MacAddr::ZERO,
                ETHER_TYPE_IPV6,
            ),
            outer_ip: Ipv6Meta::push(
                self.phys_ip_src,
                phys_target.ip.into(),
                Protocol::UDP,
            ),
            outer_ulp: UdpMeta::push(
                // XXX Geneve uses the UDP source port as a
                // flow label value for the purposes of ECMP
                // -- a hash of the 5-tuple. However, when
                // using Geneve in IPv6 one could also choose
                // to use the IPv6 Flow Label field, which has
                // 4 more bits of entropy and could be argued
                // to be more fit for this purpose. As we know
                // that our physical network is always IPv6,
                // perhaps we should just use that? For now I
                // defer the choice and leave this hard-coded.
                7777,
                GENEVE_PORT,
            ),
            outer_encap: GeneveMeta::push(phys_target.vni.into()),
            inner_ether: EtherMeta::modify(
                None,
                Some(phys_target.ether.into()),
            ),
            ..Default::default()
        }))
    }

    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        (vec![], vec![])
    }
}

pub struct DecapAction {}

/// A [`StaticAction`] representing the act of decapsulating a packet
/// for the purpose of implementing an overlay network.
impl DecapAction {
    pub fn new() -> Self {
        Self {}
    }
}

impl fmt::Display for DecapAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Decap")
    }
}

impl StaticAction for DecapAction {
    fn gen_ht(
        &self,
        // The decap action is only used for ingoing.
        _dir: Direction,
        _flow_id: &InnerFlowId,
        _meta: &mut Meta,
    ) -> rule::GenHtResult {
        Ok(AllowOrDeny::Allow(HT {
            name: DECAP_NAME.to_string(),
            outer_ether: HeaderAction::Pop,
            outer_ip: HeaderAction::Pop,
            outer_ulp: HeaderAction::Pop,
            outer_encap: HeaderAction::Pop,
            ..Default::default()
        }))
    }

    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        (vec![], vec![])
    }
}

pub struct VpcMappings {
    inner: KMutex<BTreeMap<Vni, Arc<Virt2Phys>>>,
}

impl VpcMappings {
    pub fn add(&self, vip: IpAddr, phys: PhysNet) -> Arc<Virt2Phys> {
        let guest_phys = GuestPhysAddr { ether: phys.ether, ip: phys.ip };
        let mut lock = self.inner.lock();

        match lock.get(&phys.vni) {
            Some(v2p) => {
                v2p.set(vip, guest_phys);
                v2p.clone()
            }

            None => {
                let v2p = Arc::new(Virt2Phys::new());
                v2p.set(vip, guest_phys);
                lock.insert(phys.vni, v2p.clone());
                v2p
            }
        }
    }

    pub fn dump(&self) -> DumpVirt2PhysResp {
        let mut mappings = Vec::new();
        let lock = self.inner.lock();

        for (vni, v2p) in lock.iter() {
            mappings.push(VpcMapResp {
                vni: *vni,
                ip4: v2p.dump_ip4(),
                ip6: v2p.dump_ip6(),
            });
        }

        DumpVirt2PhysResp { mappings }
    }

    pub fn new() -> Self {
        VpcMappings { inner: KMutex::new(BTreeMap::new(), KMutexType::Driver) }
    }
}

/// A mapping from virtual IPs to physical location.
pub struct Virt2Phys {
    // XXX Wrapping these in a mutex is definitely a terrible idea (in
    // terms of lock contention as this resource is actually shared by
    // all ports); but for purposes of dev this is fine for now.
    // However, before v1 we'll want something like a shadow copy and
    // atomic pointer swap or perhaps some CoW/persistent data
    // strcuture that can be efficiently and safely updated. However,
    // there is another problem that needs to be solved here: when a
    // mapping is **MODIFIED** we need to invalidate any UFT/LFT entry
    // that makes use of this virtual destination (for all Ports).
    // That means updating the generation number of all Ports anytme
    // an entry is **MODIFIED**.
    ip4: KMutex<BTreeMap<Ipv4Addr, GuestPhysAddr>>,
    ip6: KMutex<BTreeMap<Ipv6Addr, GuestPhysAddr>>,
}

pub const VIRT_2_PHYS_NAME: &'static str = "Virt2Phys";

impl Virt2Phys {
    pub fn get(&self, vip: &IpAddr) -> Option<GuestPhysAddr> {
        match vip {
            IpAddr::Ip4(ip4) => self.ip4.lock().get(ip4).cloned(),
            IpAddr::Ip6(ip6) => self.ip6.lock().get(ip6).cloned(),
        }
    }

    pub fn dump_ip4(&self) -> Vec<(Ipv4Addr, GuestPhysAddr)> {
        let mut ip4 = Vec::new();
        for (vip, gaddr) in self.ip4.lock().iter() {
            ip4.push((*vip, *gaddr));
        }
        ip4
    }

    pub fn dump_ip6(&self) -> Vec<(Ipv6Addr, GuestPhysAddr)> {
        let mut ip6 = Vec::new();
        for (vip, gaddr) in self.ip6.lock().iter() {
            ip6.push((*vip, *gaddr));
        }
        ip6
    }

    pub fn set(&self, vip: IpAddr, phys: GuestPhysAddr) {
        match vip {
            IpAddr::Ip4(ip4) => self.ip4.lock().insert(ip4, phys),
            IpAddr::Ip6(ip6) => self.ip6.lock().insert(ip6, phys),
        };
    }

    pub fn new() -> Self {
        Virt2Phys {
            ip4: KMutex::new(BTreeMap::new(), KMutexType::Driver),
            ip6: KMutex::new(BTreeMap::new(), KMutexType::Driver),
        }
    }
}

#[repr(C)]
#[derive(Debug, Deserialize, Serialize)]
pub struct DumpVirt2PhysReq {
    pub unused: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VpcMapResp {
    pub vni: Vni,
    pub ip4: Vec<(Ipv4Addr, GuestPhysAddr)>,
    pub ip6: Vec<(Ipv6Addr, GuestPhysAddr)>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DumpVirt2PhysResp {
    pub mappings: Vec<VpcMapResp>,
}

impl CmdOk for DumpVirt2PhysResp {}

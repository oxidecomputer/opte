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

use serde::Deserialize;
use serde::Serialize;

use super::router::RouterTargetInternal;
use crate::api::BoundaryServices;
use crate::api::GuestPhysAddr;
use crate::api::PhysNet;
use crate::api::VpcCfg;
use opte::api::CmdOk;
use opte::api::Direction;
use opte::api::Ipv4Addr;
use opte::api::MacAddr;
use opte::api::OpteError;
use opte::ddi::sync::KMutex;
use opte::ddi::sync::KMutexType;
use opte::engine::ether::EtherMeta;
use opte::engine::ether::ETHER_TYPE_IPV6;
use opte::engine::geneve::GeneveMeta;
use opte::engine::geneve::Vni;
use opte::engine::geneve::GENEVE_PORT;
use opte::engine::headers::HeaderAction;
use opte::engine::headers::IpAddr;
use opte::engine::ip4::Protocol;
use opte::engine::ip6::Ipv6Addr;
use opte::engine::ip6::Ipv6Meta;
use opte::engine::layer::DefaultAction;
use opte::engine::layer::Layer;
use opte::engine::layer::LayerActions;
use opte::engine::packet::InnerFlowId;
use opte::engine::packet::PacketMeta;
use opte::engine::port::meta::ActionMeta;
use opte::engine::port::meta::ActionMetaValue;
use opte::engine::port::PortBuilder;
use opte::engine::port::Pos;
use opte::engine::predicate::DataPredicate;
use opte::engine::predicate::Predicate;
use opte::engine::rule::Action;
use opte::engine::rule::AllowOrDeny;
use opte::engine::rule::GenHtError;
use opte::engine::rule::GenHtResult;
use opte::engine::rule::HdrTransform;
use opte::engine::rule::MappingResource;
use opte::engine::rule::Resource;
use opte::engine::rule::ResourceEntry;
use opte::engine::rule::Rule;
use opte::engine::rule::StaticAction;
use opte::engine::udp::UdpMeta;

pub const OVERLAY_LAYER_NAME: &'static str = "overlay";

pub fn setup(
    pb: &PortBuilder,
    cfg: &VpcCfg,
    v2p: Arc<Virt2Phys>,
    ft_limit: core::num::NonZeroU32,
) -> core::result::Result<(), OpteError> {
    // Action Index 0
    let encap = Action::Static(Arc::new(EncapAction::new(
        cfg.boundary_services,
        cfg.phys_ip,
        cfg.vni,
        v2p,
    )));

    // Action Index 1
    let decap = Action::Static(Arc::new(DecapAction::new()));

    let actions = LayerActions {
        actions: vec![encap, decap],
        default_in: DefaultAction::Deny,
        default_out: DefaultAction::Deny,
    };

    let mut layer =
        Layer::new(OVERLAY_LAYER_NAME, pb.name(), actions, ft_limit);
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
    boundary_services: PhysNet,
    // The physical IPv6 ULA of the server that hosts this guest
    // sending data.
    phys_ip_src: Ipv6Addr,
    vni: Vni,
    v2p: Arc<Virt2Phys>,
}

impl EncapAction {
    pub fn new(
        boundary_services: BoundaryServices,
        phys_ip_src: Ipv6Addr,
        vni: Vni,
        v2p: Arc<Virt2Phys>,
    ) -> Self {
        Self {
            boundary_services: PhysNet {
                ether: boundary_services.mac,
                ip: boundary_services.ip,
                vni: boundary_services.vni,
            },
            phys_ip_src,
            vni,
            v2p,
        }
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
        _pkt_meta: &PacketMeta,
        action_meta: &mut ActionMeta,
    ) -> GenHtResult {
        // The router layer determines a RouterTarget and stores it in
        // the meta map. We need to map this virtual target to a
        // physical one.
        let target_str = match action_meta.get(RouterTargetInternal::KEY) {
            Some(val) => val,
            None => {
                // This should never happen. The router should always
                // write an entry. However, we currently have no way
                // to enforce this in the type system, and thus must
                // account for this situation.
                return Err(GenHtError::Unexpected {
                    msg: format!("no RouterTarget metadata entry found"),
                });
            }
        };

        let target = match RouterTargetInternal::from_meta(target_str) {
            Ok(val) => val,
            Err(e) => {
                return Err(GenHtError::Unexpected {
                    msg: format!(
                        "failed to parse metadata entry '{}': {}",
                        target_str, e
                    ),
                });
            }
        };

        let phys_target = match target {
            RouterTargetInternal::InternetGateway => self.boundary_services,

            RouterTargetInternal::Ip(virt_ip) => match self.v2p.get(&virt_ip) {
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
                match self.v2p.get(&flow_id.dst_ip) {
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

        Ok(AllowOrDeny::Allow(HdrTransform {
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

pub const ACTION_META_VNI: &str = "vni";

impl StaticAction for DecapAction {
    fn gen_ht(
        &self,
        // The decap action is only used for inbound.
        _dir: Direction,
        _flow_id: &InnerFlowId,
        pkt_meta: &PacketMeta,
        action_meta: &mut ActionMeta,
    ) -> GenHtResult {
        match &pkt_meta.outer.encap {
            Some(geneve) => {
                action_meta.insert(
                    ACTION_META_VNI.to_string(),
                    geneve.vni.to_string(),
                );
            }

            // This should be impossible. Non-encapsulated traffic
            // should never make it here if the mac flow subsystem is
            // doing its job. However, we take a defensive approach
            // instead of risking panic.
            None => {
                return Err(GenHtError::Unexpected {
                    msg: "no encap header found".to_string(),
                });
            }
        }

        Ok(AllowOrDeny::Allow(HdrTransform {
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
    /// Add a new mapping from VIP to [`PhysNet`], returning a pointer
    /// to the [`Virt2Phys`] this mapping belongs to.
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

    /// Iterate all VPC mappings and produce a [`DumpVirt2PhysResp`].
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

    /// Map a given VIP to its VNI.
    ///
    /// This assumes a given VIP can only live in one of the VNIs
    /// visible to this particular guest interface (port). This
    /// assumption is enforced by the control plane; making sure that
    /// peered VPCs do not overlap their VIP ranges.
    pub fn ip_to_vni(&self, vip: &IpAddr) -> Option<Vni> {
        for (vni, v2p) in self.inner.lock().iter() {
            if v2p.get(vip).is_some() {
                return Some(*vni);
            }
        }

        None
    }

    pub fn new() -> Self {
        VpcMappings { inner: KMutex::new(BTreeMap::new(), KMutexType::Driver) }
    }
}

/// A mapping from virtual IPs to physical location.
pub struct Virt2Phys {
    // XXX We need to implement some sort of invalidation mechanism
    // for when a mapping is modified. The easiest way to do this is
    // to bump the port's epoch whenever a write is made to the table,
    // but that forces all ports to recompute all flows; it's the
    // largest hammer we have in the toolbox. A better solution is to
    // finally implement the "simulation" feature that VFP talks
    // about; which they use both for flow pairing and for
    // invalidation (they call it reconciliation).
    //
    // https://github.com/oxidecomputer/opte/issues/221
    ip4: KMutex<BTreeMap<Ipv4Addr, GuestPhysAddr>>,
    ip6: KMutex<BTreeMap<Ipv6Addr, GuestPhysAddr>>,
}

pub const VIRT_2_PHYS_NAME: &'static str = "Virt2Phys";

impl Virt2Phys {
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

    pub fn new() -> Self {
        Virt2Phys {
            ip4: KMutex::new(BTreeMap::new(), KMutexType::Driver),
            ip6: KMutex::new(BTreeMap::new(), KMutexType::Driver),
        }
    }
}

impl Resource for Virt2Phys {}
impl ResourceEntry for GuestPhysAddr {}

impl MappingResource for Virt2Phys {
    type Key = IpAddr;
    type Entry = GuestPhysAddr;

    fn get(&self, vip: &Self::Key) -> Option<Self::Entry> {
        match vip {
            IpAddr::Ip4(ip4) => self.ip4.lock().get(ip4).cloned(),
            IpAddr::Ip6(ip6) => self.ip6.lock().get(ip6).cloned(),
        }
    }

    fn remove(&self, vip: &Self::Key) -> Option<Self::Entry> {
        match vip {
            IpAddr::Ip4(ip4) => self.ip4.lock().remove(ip4),
            IpAddr::Ip6(ip6) => self.ip6.lock().remove(ip6),
        }
    }

    fn set(&self, vip: Self::Key, phys: GuestPhysAddr) -> Option<Self::Entry> {
        match vip {
            IpAddr::Ip4(ip4) => self.ip4.lock().insert(ip4, phys),
            IpAddr::Ip6(ip6) => self.ip6.lock().insert(ip6, phys),
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

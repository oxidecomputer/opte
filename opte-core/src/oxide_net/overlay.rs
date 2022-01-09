#[cfg(all(not(feature = "std"), not(test)))]
use alloc::boxed::Box;
#[cfg(any(feature = "std", test))]
use std::boxed::Box;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::collections::btree_map::BTreeMap;
#[cfg(any(feature = "std", test))]
use std::collections::btree_map::BTreeMap;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::string::{String, ToString};
#[cfg(any(feature = "std", test))]
use std::string::{String, ToString};
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::sync::Arc;
#[cfg(any(feature = "std", test))]
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::ether::{EtherAddr, EtherMeta, ETHER_TYPE_IPV6};
use crate::headers::{HeaderAction, IpAddr};
use crate::geneve::{GeneveMeta, Vni, GENEVE_PORT};
use crate::ip4::{Ipv4Addr, Protocol};
use crate::ip6::{Ipv6Addr, Ipv6Meta};
use crate::layer::{InnerFlowId, Layer};
use crate::oxide_net::router::RouterTarget;
use crate::port::{self, Inactive, Port, Pos};
use crate::port::meta::{Meta};
use crate::rule::{
    self, Action, ActionDesc, HT, Rule, RuleAction, StatefulAction
};
use crate::sync::{KMutex, KMutexType};
use crate::udp::UdpMeta;
use crate::Direction;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct PhysNet {
    pub ether: EtherAddr,
    pub ip: Ipv6Addr,
    pub vni: Vni
}

pub fn setup(
    port: &mut Port<Inactive>,
    cfg: &OverlayConfig,
    v2p: Arc<Virt2Phys>,
) -> port::Result<()> {
    // Action Index 0
    let encap_decap = Action::Stateful(
        Box::new(EncapDecapAction::new(
            "encap".to_string(),
            cfg.boundary_services,
            cfg.phys_mac_src,
            cfg.phys_mac_dst,
            cfg.phys_ip_src,
            v2p,
        ))
    );

    let layer = Layer::new("overlay", vec![encap_decap]);
    let encap_decap_rule = Rule::new(1, RuleAction::Allow(0));
    layer.add_rule(Direction::Out, encap_decap_rule.clone().match_any());
    // XXX Currently this will decap any outer 5-tuple and pass along
    // the inner frame. Should this be the case? Is there any type of
    // validation of the outer frame that should occur?
    layer.add_rule(Direction::In, encap_decap_rule.match_any());
    port.add_layer(layer, Pos::Last)
}

#[derive(Clone, Debug)]
pub struct EncapDecapDesc {
    inner_mac_dest: EtherAddr,
    phys_ip_src: Ipv6Addr,
    phys_ip_dst: Ipv6Addr,
    phys_mac_src: EtherAddr,
    phys_mac_dst: EtherAddr,
    vni: Vni,
}

pub const DECAP_NAME: &'static str = "decap";
pub const ENCAP_NAME: &'static str = "encap";
pub const ENCAP_DECAP_NAME: &'static str = "encap/decap";

impl ActionDesc for EncapDecapDesc {
    // There's no cleanup needed.
    fn fini(&self) {}

    fn gen_ht(&self, dir: Direction) -> HT {
        match dir {
            Direction::Out => {
                HT {
                    name: ENCAP_NAME.to_string(),
                    outer_ether: EtherMeta::push(
                        self.phys_mac_src,
                        self.phys_mac_dst,
                        ETHER_TYPE_IPV6,
                    ),
                    outer_ip: Ipv6Meta::push(
                        self.phys_ip_src,
                        self.phys_ip_dst,
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
                        GENEVE_PORT
                    ),
                    outer_encap: GeneveMeta::push(self.vni),
                    inner_ether: EtherMeta::modify(
                        None,
                        Some(self.inner_mac_dest)
                    ),
                    ..Default::default()
                }
            },

            Direction::In => {
                HT {
                    name: DECAP_NAME.to_string(),
                    outer_ether: HeaderAction::Pop,
                    outer_ip: HeaderAction::Pop,
                    outer_ulp: HeaderAction::Pop,
                    outer_encap: HeaderAction::Pop,
                    ..Default::default()
                }
            }
        }
    }

    fn name(&self) -> &str {
        ENCAP_DECAP_NAME
    }
}

/// A [`StatefulAction`] representing the act of encapsulating and
/// decapsulating a packet for the purpose of implementing an overlay
/// network.
///
/// NOTE: Currently the encapsulation is hard-coded to use Geneve.
///
/// This action maps the virtual destination to its physical location.
/// In the case of a guest-to-guest packet the physical destination is
/// another sled in the Oxide Physical Network. In the case of a
/// guest-to-external-network (whether external be the Internet or the
/// customer's network) the physical destination is Boundary Services.
/// In both cases there is a [`PhysNet`] value that identifies the
/// physical location: MAC address + IPv6 address + VNI.
///
/// The physical MAC address of a guest is the same as its virtual
/// one. We configure the guests in such a way that every destination
/// is off link and must be routed through their gateway (OPTE). That
/// means the destination MAC address coming from the guest is always
/// some sentinel value representing this virtual gateway. OPTE uses
/// the [`PhysNet`] MAC address to rewrite the destinaton. This allows
/// the receiving sled to steer the incoming traffic to isolated
/// receive queues based on the inner destination MAC address.
///
/// The physical IPv6 of a guest is the ULA of the sled it currently
/// lives on. The Oxide Physical Network takes care of routing this
/// ULA correctly.
///
/// The VNI is either the destination VPC identifier or the VNI of
/// Boundary Services.
///
/// XXX This leaves us with the outer Ethernet Frame still to be
/// filled out. That is an area of active development. Either OPTE
/// will use some query mechanism into the physical routing service to
/// determine NIC egress; or some layer between OPTE and mac will take
/// hold of the IPv6+Geneve packet and fill out the Ethernet Frame.
/// For now the outer frame information will be provided statically at
/// the [`Port`] level and stashed as `phys_mac_{src,dst}`.
///
/// This action uses the [`Virt2Phys`] resource to map the vritual
/// destination to the physical location. These mappings are
/// determined by Nexus and pushed down to individual OPTE instances.
pub struct EncapDecapAction {
    name: String,
    // The physical address of boundary services.
    boundary_services: PhysNet,
    phys_mac_src: EtherAddr,
    phys_mac_dst: EtherAddr,
    // The physical IPv6 ULA of the server that hosts this guest
    // sending data.
    phys_ip_src: Ipv6Addr,
    v2p: Arc<Virt2Phys>,
}

impl EncapDecapAction {
    pub fn new(
        name: String,
        boundary_services: PhysNet,
        phys_mac_src: EtherAddr,
        phys_mac_dst: EtherAddr,
        phys_ip_src: Ipv6Addr,
        v2p: Arc<Virt2Phys>,
    ) -> EncapDecapAction {
        EncapDecapAction {
            name,
            boundary_services,
            phys_mac_src,
            phys_mac_dst,
            phys_ip_src,
            v2p
        }
    }
}

impl StatefulAction for EncapDecapAction {
    fn gen_desc(
        &self,
        flow_id: InnerFlowId,
        meta: &mut Meta,
    ) -> rule::GenDescResult {

        // XXX Actually implement the router layer. For now this is
        // hard-coded to work with one unit test.
        meta.add(RouterTarget::Ip(IpAddr::Ip4("52.10.128.69".parse().unwrap())))
            .expect("Ipv4 type already exists");

        // The router layer determines a RouterTarget and stores it in
        // the meta map. We need to map this virtual target to a
        // physical one.
        let virt_target = match meta.get::<RouterTarget>() {
            Some(val) => val,
            None => {
                // This should never happen. The Oxide Network's
                // router layer should always write an entry. However,
                // we currently have no way to enforce this in the
                // type system, and thus must account for this
                // situation.
                return Err(rule::GenDescError::Unexpected {
                    msg: format!("no RouterTarget metadata entry found")
                });
            }
        };

        // Given the virtual target, determine its physical mapping.
        let phys = match virt_target {
            RouterTarget::Drop => {
                todo!("should we even make it here?");
            }

            RouterTarget::InternetGateway => {
                self.boundary_services.clone()
            }

            RouterTarget::Ip(virt_ip) => {
                match self.v2p.get(virt_ip) {
                    Some(val) => val,
                    None => {
                        // XXX log, stat, SDT probe
                        return Err(rule::GenDescError::Unexpected {
                            msg: format!("no v2p mapping for {}", virt_ip)
                        });
                    }
                }
            }

            RouterTarget::VpcSubnet(_) => {
                match self.v2p.get(&flow_id.dst_ip) {
                    Some(val) => val,
                    None => {
                        // XXX log, stat, SDT probe
                        return Err(rule::GenDescError::Unexpected {
                            msg: format!(
                                "no v2p mapping for {}",
                                flow_id.dst_ip
                            )
                        });
                    }
                }
            }
        };

        Ok(Arc::new(EncapDecapDesc {
            inner_mac_dest: phys.ether,
            phys_mac_src: self.phys_mac_src,
            phys_mac_dst: self.phys_mac_dst,
            phys_ip_src: self.phys_ip_src,
            phys_ip_dst: phys.ip,
            vni: phys.vni,
        }))
    }
}

/// A mapping from virtual IPs to physical location.
pub struct Virt2Phys {
    name: &'static str,
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
    ip4: KMutex<BTreeMap<Ipv4Addr, PhysNet>>,
    ip6: KMutex<BTreeMap<Ipv6Addr, PhysNet>>,
}

pub const VIRT_2_PHYS_NAME: &'static str = "Virt2Phys";

impl Virt2Phys {
    fn get(&self, vip: &IpAddr) -> Option<PhysNet> {
        match vip {
            IpAddr::Ip4(ip4) => self.ip4.lock().get(ip4).cloned(),
            IpAddr::Ip6(ip6) => self.ip6.lock().get(ip6).cloned(),
        }
    }

    pub fn set(&self, vip: IpAddr, phys: PhysNet) {
        match vip {
            IpAddr::Ip4(ip4) => self.ip4.lock().insert(ip4, phys),
            IpAddr::Ip6(ip6) => self.ip6.lock().insert(ip6, phys),
        };
    }

    pub fn new() -> Self {
        Virt2Phys {
            name: VIRT_2_PHYS_NAME,
            ip4: KMutex::new(BTreeMap::new(), KMutexType::Driver),
            ip6: KMutex::new(BTreeMap::new(), KMutexType::Driver),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OverlayConfig {
    pub boundary_services: PhysNet,
    pub vni: Vni,
    // NOTE: The phys_mac_{src,dst} currently stand in for the
    // physical routing service. The src should be the host NIC MAC
    // address, and the dst should be the physical gateway MAC address
    // on your home/lab network.
    pub phys_mac_src: EtherAddr,
    pub phys_mac_dst: EtherAddr,
    pub phys_ip_src: Ipv6Addr,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SetOverlayReq {
    pub port_name: String,
    pub cfg: OverlayConfig,
}

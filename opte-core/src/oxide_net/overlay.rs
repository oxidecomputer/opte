//! The Oxide Network VPC Overlay.
//!
//! This implements the Oxide Network VPC Overlay.
use core::fmt;

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
use crate::geneve::{GeneveMeta, Vni, GENEVE_PORT};
use crate::headers::{HeaderAction, IpAddr};
use crate::ioctl::{self, CmdErr};
use crate::ip4::{Ipv4Addr, Protocol};
use crate::ip6::{Ipv6Addr, Ipv6Meta};
use crate::layer::{InnerFlowId, Layer};
use crate::oxide_net::router::RouterTarget;
use crate::port::{self, Port, Pos};
use crate::port::meta::Meta;
use crate::rule::{self, Action, HT, Rule, StaticAction};
use crate::sync::{KMutex, KMutexType};
use crate::udp::UdpMeta;
use crate::Direction;

pub const OVERLAY_LAYER_NAME: &'static str = "overlay";

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct PhysNet {
    pub ether: EtherAddr,
    pub ip: Ipv6Addr,
    pub vni: Vni
}

pub fn setup(
    port: &Port<port::Inactive>,
    cfg: &OverlayCfg,
    v2p: Arc<Virt2Phys>,
) {
    // Action Index 0
    let encap = Action::Static(
        Arc::new(EncapAction::new(
            cfg.boundary_services,
            cfg.phys_mac_src,
            cfg.phys_mac_dst,
            cfg.phys_ip_src,
            v2p,
        ))
    );

    // Action Index 1
    let decap = Action::Static(Arc::new(DecapAction::new()));

    let layer = Layer::new(OVERLAY_LAYER_NAME, port.name(), vec![encap, decap]);
    let encap_rule = Rule::new(1, layer.action(0).unwrap().clone());
    layer.add_rule(Direction::Out, encap_rule.clone().match_any());
    let decap_rule = Rule::new(1, layer.action(1).unwrap().clone());
    layer.add_rule(Direction::In, decap_rule.match_any());
    // NOTE The First/Last positions cannot fail; perhaps I should
    // improve the API to avoid the unwrap().
    port.add_layer(layer, Pos::Last).unwrap();
}

pub const DECAP_NAME: &'static str = "decap";
pub const ENCAP_NAME: &'static str = "encap";

/// A [`StaticAction`] representing the act of encapsulating a packet
/// for the purpose of implementing an overlay network.
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
pub struct EncapAction {
    // The physical address of boundary services.
    boundary_services: PhysNet,
    phys_mac_src: EtherAddr,
    phys_mac_dst: EtherAddr,
    // The physical IPv6 ULA of the server that hosts this guest
    // sending data.
    phys_ip_src: Ipv6Addr,
    v2p: Arc<Virt2Phys>,
}

impl EncapAction {
    pub fn new(
        boundary_services: PhysNet,
        phys_mac_src: EtherAddr,
        phys_mac_dst: EtherAddr,
        phys_ip_src: Ipv6Addr,
        v2p: Arc<Virt2Phys>,
    ) -> Self {
        Self {
            boundary_services,
            phys_mac_src,
            phys_mac_dst,
            phys_ip_src,
            v2p
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
        flow_id: InnerFlowId,
        meta: &mut Meta,
    ) -> rule::GenHtResult {
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
                return Err(rule::GenHtError::Unexpected {
                    msg: format!("no RouterTarget metadata entry found")
                });
            }
        };

        // Given the virtual target, determine its physical mapping.
        let phys_target = match virt_target {
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
                        return Err(rule::GenHtError::Unexpected {
                            msg: format!("no v2p mapping for {}", virt_ip)
                        });
                    }
                }
            }

            RouterTarget::VpcSubnet(_) => {
                match self.v2p.get(&flow_id.dst_ip) {
                    Some(val) => val,
                    None => {
                        return Err(rule::GenHtError::Unexpected {
                            msg: format!(
                                "no v2p mapping for {}",
                                flow_id.dst_ip
                            )
                        });
                    }
                }
            }
        };

        Ok(HT {
            name: ENCAP_NAME.to_string(),
            outer_ether: EtherMeta::push(
                self.phys_mac_src,
                // XXX The outer ethernet dest should be the MAC
                // address of the sidecar switch/router. But, for the
                // time being, in order to get two guests talking via
                // the overlay network we can fake it out by relying
                // on the internal L2 switch inside every illumos mac
                // instance (sometimes referred to as "mac loopback").
                // By placing both guests's VNICs on the same mac you
                // can rely on the underlying mac to switch the frame
                // for you, without actally needing anything to route
                // the packet. This is a stopgap until I can better
                // understand standing up our physical network
                // implementation. The actual value here should be
                // `self.phys_mac_dst`.
                //
                // self.phys_mac_dst,
                phys_target.ether,
                ETHER_TYPE_IPV6,
            ),
            outer_ip: Ipv6Meta::push(
                self.phys_ip_src,
                phys_target.ip,
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
            outer_encap: GeneveMeta::push(phys_target.vni),
            inner_ether: EtherMeta::modify(
                None,
                Some(phys_target.ether)
            ),
            ..Default::default()
        })
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
        _flow_id: InnerFlowId,
        _meta: &mut Meta,
    ) -> rule::GenHtResult {
        Ok(HT {
            name: DECAP_NAME.to_string(),
            outer_ether: HeaderAction::Pop,
            outer_ip: HeaderAction::Pop,
            outer_ulp: HeaderAction::Pop,
            outer_encap: HeaderAction::Pop,
            ..Default::default()
        })
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
            ip4: KMutex::new(BTreeMap::new(), KMutexType::Driver),
            ip6: KMutex::new(BTreeMap::new(), KMutexType::Driver),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OverlayCfg {
    pub boundary_services: PhysNet,
    pub vni: Vni,
    // NOTE: The phys_mac_{src,dst} currently stand in for the
    // physical routing service. The src should be the host NIC MAC
    // address, and the dst should be the physical gateway MAC address
    // on your home/lab network. However, as the mac layer doesn't
    // currently have the ability to steer packets based on inner
    // frame, we use the MAC address of the guest/VNIC for the moment.
    pub phys_mac_src: EtherAddr,
    pub phys_mac_dst: EtherAddr,
    pub phys_ip_src: Ipv6Addr,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SetOverlayReq {
    pub port_name: String,
    pub cfg: OverlayCfg,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SetOverlayError {
    PortError(ioctl::PortError),
}

impl CmdErr for SetOverlayError {}

impl From<ioctl::PortError> for SetOverlayError {
    fn from(e: ioctl::PortError) -> Self {
        Self::PortError(e)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SetVirt2PhysReq {
    pub vip: IpAddr,
    pub phys: PhysNet,
}

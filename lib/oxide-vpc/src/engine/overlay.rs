// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! The Oxide Network VPC Overlay.
//!
//! This implements the Oxide Network VPC Overlay.
use super::geneve::OxideOptions;
use super::router::RouterTargetInternal;
use crate::api::DEFAULT_MULTICAST_VNI;
use crate::api::DumpVirt2BoundaryResp;
use crate::api::DumpVirt2PhysResp;
use crate::api::GuestPhysAddr;
use crate::api::PhysNet;
use crate::api::Replication;
use crate::api::TunnelEndpoint;
use crate::api::V2bMapResp;
use crate::api::VpcMapResp;
use crate::cfg::VpcCfg;
use crate::engine::geneve::OxideOptionType;
use crate::engine::geneve::ValidOxideOption;
use alloc::borrow::Cow;
use alloc::collections::BTreeSet;
use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;
use opte::api::Direction;
use opte::api::Ipv4Addr;
use opte::api::Ipv4Cidr;
use opte::api::MacAddr;
use opte::api::MulticastUnderlay;
use opte::api::OpteError;
use opte::ddi::sync::KMutex;
use opte::ddi::sync::KMutexGuard;
use opte::ddi::sync::KRwLock;
use opte::engine::ether::EtherMeta;
use opte::engine::ether::EtherMod;
use opte::engine::ether::EtherType;
use opte::engine::geneve::ArbitraryGeneveOption;
use opte::engine::geneve::GENEVE_OPT_CLASS_OXIDE;
use opte::engine::geneve::GeneveMetaRef;
use opte::engine::geneve::GenevePush;
use opte::engine::geneve::Vni;
use opte::engine::headers::EncapPush;
use opte::engine::headers::HeaderAction;
use opte::engine::headers::IpAddr;
use opte::engine::headers::IpCidr;
use opte::engine::headers::IpPush;
use opte::engine::headers::Valid;
use opte::engine::ip::v4::Protocol;
use opte::engine::ip::v6::Ipv6Addr;
use opte::engine::ip::v6::Ipv6Cidr;
use opte::engine::ip::v6::Ipv6Push;
use opte::engine::layer::DefaultAction;
use opte::engine::layer::Layer;
use opte::engine::layer::LayerActions;
use opte::engine::nat::ExternalIpTag;
use opte::engine::packet::InnerFlowId;
use opte::engine::packet::MblkPacketData;
use opte::engine::port::PortBuilder;
use opte::engine::port::Pos;
use opte::engine::port::meta::ActionMeta;
use opte::engine::port::meta::ActionMetaValue;
use opte::engine::predicate::DataPredicate;
use opte::engine::predicate::Predicate;
use opte::engine::rule::Action;
use opte::engine::rule::AllowOrDeny;
use opte::engine::rule::GenHtError;
use opte::engine::rule::GenHtResult;
use opte::engine::rule::HdrTransform;
use opte::engine::rule::MappingResource;
use opte::engine::rule::MetaAction;
use opte::engine::rule::ModMetaResult;
use opte::engine::rule::Resource;
use opte::engine::rule::ResourceEntry;
use opte::engine::rule::Rule;
use opte::engine::rule::StaticAction;
use poptrie::Poptrie;

pub const OVERLAY_LAYER_NAME: &str = "overlay";

pub fn setup(
    pb: &PortBuilder,
    cfg: &VpcCfg,
    v2p: Arc<Virt2Phys>,
    m2p: Arc<Mcast2Phys>,
    v2b: Arc<Virt2Boundary>,
    ft_limit: core::num::NonZeroU32,
) -> core::result::Result<(), OpteError> {
    // Action Index 0
    let encap = Action::Static(Arc::new(EncapAction::new(
        cfg.phys_ip,
        cfg.vni,
        v2p,
        m2p,
        v2b,
    )));

    // Action Index 1
    let decap = Action::Static(Arc::new(DecapAction::new()));

    // Action Index 2 - Multicast VNI validator
    let vni_validator =
        Action::Meta(Arc::new(MulticastVniValidator::new(cfg.vni)));

    let actions = LayerActions {
        actions: vec![encap, decap, vni_validator],
        default_in: DefaultAction::Deny,
        default_out: DefaultAction::Deny,
    };

    let mut layer =
        Layer::new(OVERLAY_LAYER_NAME, pb.name(), actions, ft_limit);

    // Outbound: encapsulation (priority 1)
    let encap_rule = Rule::match_any(1, layer.action(0).unwrap());
    layer.add_rule(Direction::Out, encap_rule);

    // Inbound: decapsulation (priority 1 - runs first, sets ACTION_META_VNI)
    let decap_rule = Rule::match_any(1, layer.action(1).unwrap());
    layer.add_rule(Direction::In, decap_rule);

    // Inbound: VNI validation (priority 2 - runs after decap)
    let vni_check_rule = Rule::match_any(2, layer.action(2).unwrap());
    layer.add_rule(Direction::In, vni_check_rule);

    // NOTE The First/Last positions cannot fail; perhaps I should
    // improve the API to avoid the unwrap().
    pb.add_layer(layer, Pos::Last)
}

pub const DECAP_NAME: &str = "decap";
pub const ENCAP_NAME: &str = "encap";

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
    // The physical IPv6 ULA of the server that hosts this guest
    // sending data.
    phys_ip_src: Ipv6Addr,
    vni: Vni,
    v2p: Arc<Virt2Phys>,
    m2p: Arc<Mcast2Phys>,
    v2b: Arc<Virt2Boundary>,
}

impl EncapAction {
    pub fn new(
        phys_ip_src: Ipv6Addr,
        vni: Vni,
        v2p: Arc<Virt2Phys>,
        m2p: Arc<Mcast2Phys>,
        v2b: Arc<Virt2Boundary>,
    ) -> Self {
        Self { phys_ip_src, vni, v2p, m2p, v2b }
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
        pkt_meta: &MblkPacketData,
        action_meta: &mut ActionMeta,
    ) -> GenHtResult {
        let f_hash = flow_id.crc32();
        let dst_ip = flow_id.dst_ip();

        // Multicast traffic is detected by checking if the inner
        // destination IP is a multicast address. Multicast operates at the fleet
        // level (cross-VPC) and doesn't go through VPC routing, so router
        // metadata is not required in that case.
        let is_mcast_addr = dst_ip.is_multicast();

        let (is_internal, phys_target, is_mcast) = if is_mcast_addr {
            // Multicast traffic: use M2P mapping to get the multicast underlay address.
            // Fleet-level multicast mappings are stored in the dedicated `m2p`.
            match self.m2p.get(&dst_ip) {
                Some(underlay) => (
                    true,
                    PhysNet {
                        // Outer MAC filled in by XDE
                        ether: MacAddr::ZERO,
                        ip: underlay.addr(),
                        vni: Vni::new(DEFAULT_MULTICAST_VNI).unwrap(),
                    },
                    true,
                ),
                None => {
                    // No M2P mapping configured for this multicast group; deny.
                    return Ok(AllowOrDeny::Deny);
                }
            }
        } else {
            // Non-multicast traffic: process through router target.

            // The router layer determines a RouterTarget and stores it in
            // the meta map. We need to map this virtual target to a
            // physical one.
            let target = action_meta
                .get_typed::<RouterTargetInternal>()
                .map_err(|e| GenHtError::Unexpected { msg: e.to_string() })?;

            let sent_from_eip =
                action_meta.get_typed::<ExternalIpTag>().is_ok();

            let recipient = match target {
                RouterTargetInternal::Ip(virt_ip) => virt_ip,
                _ => dst_ip,
            };

            match target {
                // Currently, traffic directed at either attached external subnets or
                // the external IPs of any other port always go through the V2B table.
                // This requires a hairpin through the customer network, but provides
                // strong isolation which some customers require.
                //
                // In future we may want this to be a tunable property of the VPC. In this
                // case we would require an extra table/poptrie per VPC, containing all
                // external CIDR blocks visible across the VPC. We would then:
                //  * resolve `recipient` against this table when going via an IGW,
                //    pulling the address of the owner's primary NIC.
                //  * if found, resolve the primary NIC address against the V2P instead of
                //    the V2B.
                //  * Possibly add the Geneve external packet tag to the packet, esp. if
                //    crossing VPC boundaries.
                // This obviously works well for attached subnets, but for EIPs and FIPs
                // we'll have quite a few /32 or /128 routing table entries which can't
                // be aggregated unless adjacent external IPs point to the same instance
                // (and this would probably be harmed further by SNAT allocation causing
                // fragmentation).
                //
                // It's a possible optimisation, but it'd need more thought.
                RouterTargetInternal::InternetGateway(_) => {
                    match self.v2b.get(&recipient) {
                        Some(phys) if sent_from_eip => {
                            // Hash the packet onto a route target. This is a very
                            // rudimentary mechanism. Should level-up to an ECMP
                            // algorithm with well known statistical properties.
                            let hash = f_hash as usize;
                            let target =
                                match phys.iter().nth(hash % phys.len()) {
                                    Some(target) => target,
                                    None => return Ok(AllowOrDeny::Deny),
                                };
                            (
                                false,
                                PhysNet {
                                    ether: MacAddr::from(TUNNEL_ENDPOINT_MAC),
                                    ip: target.ip,
                                    vni: target.vni,
                                },
                                false,
                            )
                        }

                        // Sending traffic to boundary services *requires* that
                        // it is originated from an external IP.
                        _ => return Ok(AllowOrDeny::Deny),
                    }
                }

                RouterTargetInternal::Ip(_)
                | RouterTargetInternal::VpcSubnet(_) => {
                    match self.v2p.get(&recipient) {
                        Some(phys) if !sent_from_eip => (
                            true,
                            PhysNet {
                                ether: phys.ether,
                                ip: phys.ip,
                                vni: self.vni,
                            },
                            false,
                        ),

                        // We have either attempted to forward traffic to a
                        // private IP/subnet from an external IP, or we failed
                        // to lookup the intended VPC IP.
                        //
                        // The former case can only occur when the guest is
                        // sending traffic from an attached external subnet.
                        //
                        // The latter case could arise for two reasons:
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
                        _ => return Ok(AllowOrDeny::Deny),
                    }
                }
            }
        };
        action_meta.set_internal_target(is_internal);

        static GENEVE_MSS_SIZE_OPT_BODY: &[u8] = &[0; size_of::<u32>()];
        static GENEVE_MSS_SIZE_OPT: ArbitraryGeneveOption =
            ArbitraryGeneveOption {
                option_class: GENEVE_OPT_CLASS_OXIDE,
                option_type: OxideOptionType::Mss as u8,
                data: Cow::Borrowed(GENEVE_MSS_SIZE_OPT_BODY),
            };

        // For multicast originated from this host, we seed the multicast Geneve
        // option with `External` replication. XDE will then select the actual
        // replication per next hop based on the rack-wide forwarding table
        // (mcast_fwd), which tells the switch which ports to replicate to
        // (external, underlay, or bifurcated).
        //
        // Local same-sled delivery to subscribed guests is always performed by
        // OPTE, independent of the replication mode (not an access control mechanism).
        //
        // The first byte encodes Replication in the top 2 bits:
        //   External=0x00, Underlay=0x40, Both=0x80, Reserved=0xC0
        const REPLICATION_EXTERNAL_BYTE: u8 =
            (Replication::External as u8) << 6;
        static GENEVE_MCAST_OPT_BODY: &[u8] = &[
            REPLICATION_EXTERNAL_BYTE, // Top 2 bits encode replication strategy
            0x00,
            0x00,
            0x00, // Reserved bytes
        ];
        static GENEVE_MCAST_OPT: ArbitraryGeneveOption =
            ArbitraryGeneveOption {
                option_class: GENEVE_OPT_CLASS_OXIDE,
                option_type: OxideOptionType::Multicast as u8,
                data: Cow::Borrowed(GENEVE_MCAST_OPT_BODY),
            };

        // For multicast, derive the outer MAC from the IPv6 address per RFC 2464.
        // For unicast, XDE fills in the MAC via routing table lookup.
        let outer_mac = if is_mcast {
            phys_target.ip.unchecked_multicast_mac()
        } else {
            MacAddr::ZERO
        };

        let tfrm = HdrTransform {
            name: ENCAP_NAME.to_string(),
            // We leave the outer src/dst up to the driver.
            // In the multicast case we can, however, derive this.
            outer_ether: HeaderAction::Push(
                Valid::validated(EtherMeta {
                    dst: outer_mac,
                    src: MacAddr::ZERO,
                    ether_type: EtherType::Ipv6,
                })
                .expect("Ethernet validation is infallible"),
            ),
            outer_ip: HeaderAction::Push({
                let ip_push = IpPush::from(Ipv6Push {
                    src: self.phys_ip_src,
                    dst: phys_target.ip,
                    proto: Protocol::UDP,
                    exts: Cow::Borrowed(&[]),
                });
                Valid::validated(ip_push)?
            }),
            // XXX Geneve uses the UDP source port as a flow label
            // value for the purposes of ECMP -- a hash of the
            // 5-tuple. However, when using Geneve in IPv6 one could
            // also choose to use the IPv6 Flow Label field, which has
            // 4 more bits of entropy and could be argued to be more
            // fit for this purpose. As we know that our physical
            // network is always IPv6, perhaps we should just use
            // that? For now I defer the choice and leave this
            // hard-coded.
            //
            // (kyle) -- I think we should use both, mainly because
            // we can expose the extra entropy to devices which can use it.
            // We may want flow id to be symmetric, however...
            // It's worth keeping in mind that Chelsio's RSS picks us a ring
            // based on Toeplitz hash of the 5-tuple, so we need to write into
            // there regardless. I don't believe it *looks* at v6 flowid.
            outer_encap: HeaderAction::Push(Valid::validated(
                EncapPush::from(GenevePush {
                    vni: phys_target.vni,
                    entropy: flow_id.crc32() as u16,
                    options: match (
                        pkt_meta.is_inner_tcp() && is_internal,
                        is_mcast,
                    ) {
                        // Allocate space in which we can include the TCP MSS, when
                        // needed during MSS boosting. It's theoretically doable to
                        // gate this on seeing an unexpectedly high/low MSS option
                        // in the TCP handshake, but there are problems in doing so:
                        // * The MSS for the flow is negotiated, but the UFT entry
                        //   containing this transform does not know the other side.
                        // * UFT invalidation means we may rerun this transform in
                        //   the middle of a flow.
                        // So, emit it unconditionally for VPC-internal TCP traffic,
                        // which could need the original MSS to be carried when LSO
                        // is in use.
                        (true, false) => Cow::Borrowed(core::slice::from_ref(
                            &GENEVE_MSS_SIZE_OPT,
                        )),
                        (false, true) => Cow::Borrowed(core::slice::from_ref(
                            &GENEVE_MCAST_OPT,
                        )),
                        (false, false) => Cow::Borrowed(&[]),
                        // We do not support TCP over multicast delivery.
                        // Multicast replication semantics conflict with TCP's
                        // connection/ordering guarantees, so deny this case.
                        (true, true) => {
                            return Ok(AllowOrDeny::Deny);
                        }
                    },
                }),
            )?),

            // For unicast, rewrite inner destination MAC to the target's physical MAC.
            //
            // For multicast, rewrite inner dest MAC to the RFC-compliant multicast
            // MAC (RFC 1112 for IPv4, RFC 2464 for IPv6). This ensures Tx loopback
            // delivery to local subscribers via `guest_loopback()` has the correct
            // MAC for gateway layer validation, which requires `EtherAddrMatch::Multicast`.
            //
            // Note on Rx path: Incoming multicast packets from the underlay are
            // handled differently. `DecapAction` only pops outer headers (doesn't
            // modify inner MACs), and XDE's `handle_mcast_rx()` performs MAC
            // normalization because 1) packets arrive with arbitrary inner MACs
            // from remote hosts and 2) multicast subscription routing is
            // handled in XDE, not OPTE.
            inner_ether: HeaderAction::Modify(EtherMod {
                dst: if is_mcast {
                    // Sanity: if this path is taken, the destination IP must be multicast.
                    debug_assert!(dst_ip.is_multicast());
                    dst_ip.multicast_mac()
                } else {
                    Some(phys_target.ether)
                },
                ..Default::default()
            }),
            ..Default::default()
        };

        Ok(AllowOrDeny::Allow(tfrm))
    }

    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        (vec![], vec![])
    }
}

/// Tag a packet with the VNI it will be sent on, or that was recorded in
/// encapsulation.
#[derive(Debug)]
pub(crate) struct VniTag(pub Vni);

impl ActionMetaValue for VniTag {
    const KEY: &'static str = "vni";

    fn as_meta(&self) -> Cow<'static, str> {
        self.0.to_string().into()
    }

    fn from_meta(s: &str) -> Result<Self, String> {
        Vni::from_str(s).map_err(|e| e.to_string()).map(Self)
    }
}

#[derive(Default)]
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
        // The decap action is only used for inbound.
        _dir: Direction,
        _flow_id: &InnerFlowId,
        pkt_meta: &MblkPacketData,
        action_meta: &mut ActionMeta,
    ) -> GenHtResult {
        let mut is_external = false;

        let vni = match pkt_meta.outer_geneve() {
            Some(g) => {
                let vni = g.vni();
                for opt in OxideOptions::from_meta(g) {
                    let Ok(opt) = opt else { break };
                    if let Some(ValidOxideOption::External) = opt.option.known()
                    {
                        is_external = true;
                        break;
                    }
                }
                vni
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
        };

        // We only conditionally add this metadata because the
        // `Address::VNI` filter uses it to select VPC-originated
        // traffic.
        // External packets carry an extra Geneve tag from the
        // switch during NAT -- if found, `oxide_external_packet`
        // is filled.
        if !is_external {
            action_meta.insert_typed(&VniTag(vni));
        }

        Ok(AllowOrDeny::Allow(HdrTransform {
            name: DECAP_NAME.to_string(),
            outer_ether: HeaderAction::Pop,
            outer_ip: HeaderAction::Pop,
            outer_encap: HeaderAction::Pop,
            ..Default::default()
        }))
    }

    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        (vec![], vec![])
    }
}

/// Validate VNI for inbound multicast traffic in the overlay layer.
///
/// All outbound multicast packets are currently encapsulated with VNI 77
/// (DEFAULT_MULTICAST_VNI) for fleet-wide delivery. See [`EncapAction::gen_ht`].
///
/// ## Validation Policy on Rx Path
/// This validator accepts multicast packets with either of two VNI values:
/// - **VNI 77 (DEFAULT_MULTICAST_VNI)**: Fleet-wide multicast, accepted by all
///   ports regardless of VPC. This enables rack-wide multicast delivery.
/// - **Guest's VPC VNI**: Enables per-VPC multicast isolation **in the future**.
///
/// The validator enforces VPC isolation by rejecting multicast packets with
/// VNI values that don't match either the fleet-wide VNI or this port's VPC.
struct MulticastVniValidator {
    my_vni: Vni,
}

impl MulticastVniValidator {
    fn new(vni: Vni) -> Self {
        Self { my_vni: vni }
    }
}

impl MetaAction for MulticastVniValidator {
    fn mod_meta(
        &self,
        flow: &InnerFlowId,
        action_meta: &mut ActionMeta,
    ) -> ModMetaResult {
        // Only validate if this is multicast traffic
        if !flow.dst_ip().is_multicast() {
            return Ok(AllowOrDeny::Allow(()));
        }

        // Check VNI from action metadata (set by DecapAction)
        if let Ok(VniTag(pkt_vni)) = action_meta.get_typed() {
            let mcast_vni = Vni::new(DEFAULT_MULTICAST_VNI).unwrap();
            // Allow if VNI matches this VPC or fleet-wide multicast VNI
            if pkt_vni == self.my_vni || pkt_vni == mcast_vni {
                return Ok(AllowOrDeny::Allow(()));
            }
            // VNI mismatch or parse error - deny
            return Ok(AllowOrDeny::Deny);
        }
        // No VNI in metadata means external packet - allow
        // (external packets don't have ACTION_META_VNI set per DecapAction logic)
        Ok(AllowOrDeny::Allow(()))
    }

    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        (vec![], vec![])
    }
}

impl fmt::Display for MulticastVniValidator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "mcast-vni-validator")
    }
}

pub struct VpcMappings {
    inner: KMutex<BTreeMap<Vni, Arc<Virt2Phys>>>,
}

impl VpcMappings {
    /// Generate a new mapping struct.
    pub fn new() -> Self {
        Self { inner: KMutex::new(BTreeMap::new()) }
    }

    /// Add a new mapping from VIP to [`PhysNet`], returning a pointer
    /// to the [`Virt2Phys`] this mapping belongs to.
    pub fn add(&self, vip: IpAddr, phys: PhysNet) -> Arc<Virt2Phys> {
        // We convert to GuestPhysAddr because it saves us from
        // redundant storage of the VNI.
        let guest_phys = GuestPhysAddr::from(phys);
        let mut lock = self.inner.lock();

        let v2p = lock.entry(phys.vni).or_default();
        v2p.set(vip, guest_phys);

        v2p.clone()
    }

    /// Delete the mapping for the given VIP in the given VNI.
    ///
    /// Return the existing entry, if there is one.
    pub fn del(&self, vip: &IpAddr, phys: &PhysNet) -> Option<PhysNet> {
        match self.inner.lock().get(&phys.vni) {
            Some(v2p) => v2p.remove(vip).map(|guest_phys| PhysNet {
                ether: guest_phys.ether,
                ip: guest_phys.ip,
                vni: phys.vni,
            }),

            None => None,
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
}

impl Default for VpcMappings {
    fn default() -> Self {
        Self::new()
    }
}

// XXX: Should these not be RwLocks? This is a really unfortunate degree of
//      contention for multiple ports in the slowpath to block one another.
//      (Not common by any means, but needless when it does occur!)

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

/// A mapping from virtual IPs to boundary services addresses.
pub struct Virt2Boundary {
    // The BTreeMap-based representation of the v2b table is a representation
    // that is easily updated.
    ip4: KMutex<BTreeMap<Ipv4Cidr, BTreeSet<TunnelEndpoint>>>,
    ip6: KMutex<BTreeMap<Ipv6Cidr, BTreeSet<TunnelEndpoint>>>,

    // The Poptrie-based representation of the v2b table is a data structure
    // optimized for fast query times. It's not easily updated in-place. It's
    // rebuilt each time an update is made. The heuristic being applied here is
    // we expect table churn to be highly-infrequent compared to lookups.
    // Lookups may happen millions of times per second and and we want those to
    // be as fast as possible. At the time of writing, poptrie is the fastest
    // LPM lookup data structure known to the author.
    //
    // The poptrie is under an read-write lock to allow multiple concurrent
    // readers. When we update we hold the lock just long enough to do a swap
    // with a poptrie that was pre-built out of band.
    pt4: KRwLock<Poptrie<BTreeSet<TunnelEndpoint>>>,
    pt6: KRwLock<Poptrie<BTreeSet<TunnelEndpoint>>>,
}

/// A mapping from inner multicast destination IPs to underlay multicast groups.
///
/// Validation is enforced at the API boundary (see xde.rs set_m2p_hdlr) to ensure
/// only valid admin-local IPv6 multicast addresses (ff04::/16) are stored.
pub struct Mcast2Phys {
    ip4: KMutex<BTreeMap<Ipv4Addr, MulticastUnderlay>>,
    ip6: KMutex<BTreeMap<Ipv6Addr, MulticastUnderlay>>,
}

pub const TUNNEL_ENDPOINT_MAC: [u8; 6] = [0xA8, 0x40, 0x25, 0x77, 0x77, 0x77];

impl Virt2Boundary {
    pub fn dump_ip4(&self) -> Vec<(Ipv4Cidr, BTreeSet<TunnelEndpoint>)> {
        self.ip4
            .lock()
            .iter()
            .map(|(vip, baddr)| (*vip, baddr.clone()))
            .collect()
    }

    pub fn dump_ip6(&self) -> Vec<(Ipv6Cidr, BTreeSet<TunnelEndpoint>)> {
        self.ip6
            .lock()
            .iter()
            .map(|(vip, baddr)| (*vip, baddr.clone()))
            .collect()
    }

    pub fn dump(&self) -> DumpVirt2BoundaryResp {
        DumpVirt2BoundaryResp {
            mappings: V2bMapResp { ip4: self.dump_ip4(), ip6: self.dump_ip6() },
        }
    }

    pub fn new() -> Self {
        Virt2Boundary {
            ip4: KMutex::new(BTreeMap::new()),
            ip6: KMutex::new(BTreeMap::new()),
            pt4: KRwLock::new(Poptrie::default()),
            pt6: KRwLock::new(Poptrie::default()),
        }
    }
}

impl Default for Virt2Boundary {
    fn default() -> Self {
        Self::new()
    }
}

impl Resource for Virt2Boundary {}
impl ResourceEntry for PhysNet {}

// NOTE: this is almost but not quite a MappingResource. Here the keys are of a
// different type than the query argument. Keys are prefixes and query arguments
// are IPs. The mapping resource trait requires that the keys and query
// arguments be of the same type.
impl Virt2Boundary {
    pub fn get(&self, vip: &IpAddr) -> Option<BTreeSet<TunnelEndpoint>> {
        match vip {
            IpAddr::Ip4(ip4) => self.pt4.read().match_v4(u32::from(*ip4)),
            IpAddr::Ip6(ip6) => self.pt6.read().match_v6(u128::from(*ip6)),
        }
    }

    pub fn remove<I: IntoIterator<Item = TunnelEndpoint>>(
        &self,
        vip: IpCidr,
        tep: I,
    ) -> Option<BTreeSet<TunnelEndpoint>> {
        match vip {
            IpCidr::Ip4(ip4) => {
                let mut tbl = self.ip4.lock();
                let (clear, orig) = match tbl.get_mut(&ip4) {
                    Some(entry) => {
                        let orig = entry.clone();
                        for t in tep.into_iter() {
                            entry.remove(&t);
                        }
                        (entry.is_empty(), Some(orig))
                    }
                    None => (false, None),
                };
                if clear {
                    tbl.remove(&ip4);
                }
                self.update_poptrie_v4(&tbl);
                orig
            }
            IpCidr::Ip6(ip6) => {
                let mut tbl = self.ip6.lock();
                let (clear, orig) = match tbl.get_mut(&ip6) {
                    Some(entry) => {
                        let orig = entry.clone();
                        for t in tep.into_iter() {
                            entry.remove(&t);
                        }
                        (entry.is_empty(), Some(orig))
                    }
                    None => (false, None),
                };
                if clear {
                    tbl.remove(&ip6);
                }
                self.update_poptrie_v6(&tbl);
                orig
            }
        }
    }

    pub fn set<I: IntoIterator<Item = TunnelEndpoint>>(
        &self,
        vip: IpCidr,
        tep: I,
    ) -> Option<BTreeSet<TunnelEndpoint>> {
        match vip {
            IpCidr::Ip4(ip4) => {
                let mut tbl = self.ip4.lock();
                let result = match tbl.get_mut(&ip4) {
                    Some(entry) => {
                        let orig = entry.clone();
                        entry.extend(tep);
                        Some(orig)
                    }
                    None => tbl.insert(ip4, tep.into_iter().collect()),
                };
                self.update_poptrie_v4(&tbl);
                result
            }
            IpCidr::Ip6(ip6) => {
                let mut tbl = self.ip6.lock();
                let result = match tbl.get_mut(&ip6) {
                    Some(entry) => {
                        let orig = entry.clone();
                        entry.extend(tep);
                        Some(orig)
                    }
                    None => tbl.insert(ip6, tep.into_iter().collect()),
                };
                self.update_poptrie_v6(&tbl);
                result
            }
        }
    }

    fn update_poptrie_v4(
        &self,
        tree: &KMutexGuard<BTreeMap<Ipv4Cidr, BTreeSet<TunnelEndpoint>>>,
    ) {
        let table = poptrie::Ipv4RoutingTable(
            tree.iter()
                .map(|(k, v)| ((k.ip().bytes(), k.prefix_len()), v.clone()))
                .collect(),
        );
        *self.pt4.write() = poptrie::Poptrie::from(table);
    }

    fn update_poptrie_v6(
        &self,
        tree: &KMutexGuard<BTreeMap<Ipv6Cidr, BTreeSet<TunnelEndpoint>>>,
    ) {
        let table = poptrie::Ipv6RoutingTable(
            tree.iter()
                .map(|(k, v)| ((k.ip().bytes(), k.prefix_len()), v.clone()))
                .collect(),
        );
        *self.pt6.write() = poptrie::Poptrie::from(table);
    }
}

pub const VIRT_2_PHYS_NAME: &str = "Virt2Phys";

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
            ip4: KMutex::new(BTreeMap::new()),
            ip6: KMutex::new(BTreeMap::new()),
        }
    }
}

impl Default for Virt2Phys {
    fn default() -> Self {
        Self::new()
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

impl Mcast2Phys {
    /// Create a new empty multicast-to-physical mapping table.
    pub fn new() -> Self {
        Self {
            ip4: KMutex::new(BTreeMap::new()),
            ip6: KMutex::new(BTreeMap::new()),
        }
    }

    /// Dump all IPv4 overlay multicast group to underlay IPv6 multicast mappings.
    pub fn dump_ip4(&self) -> Vec<(Ipv4Addr, Ipv6Addr)> {
        self.ip4
            .lock()
            .iter()
            .map(|(vip, mcast)| (*vip, mcast.addr()))
            .collect()
    }

    /// Dump all IPv6 overlay multicast group to underlay IPv6 multicast mappings.
    pub fn dump_ip6(&self) -> Vec<(Ipv6Addr, Ipv6Addr)> {
        self.ip6
            .lock()
            .iter()
            .map(|(vip, mcast)| (*vip, mcast.addr()))
            .collect()
    }
}

impl Default for Mcast2Phys {
    fn default() -> Self {
        Self::new()
    }
}

impl Resource for Mcast2Phys {}

impl MappingResource for Mcast2Phys {
    type Key = IpAddr;
    type Entry = MulticastUnderlay;

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

    fn set(&self, vip: Self::Key, mcast: Self::Entry) -> Option<Self::Entry> {
        match vip {
            IpAddr::Ip4(ip4) => self.ip4.lock().insert(ip4, mcast),
            IpAddr::Ip6(ip6) => self.ip6.lock().insert(ip6, mcast),
        }
    }
}

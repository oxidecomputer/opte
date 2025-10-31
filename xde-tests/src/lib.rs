// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use opte_ioctl::OpteHdl;
use oxide_vpc::api::AddFwRuleReq;
use oxide_vpc::api::AddRouterEntryReq;
use oxide_vpc::api::Address;
use oxide_vpc::api::ClearMcast2PhysReq;
use oxide_vpc::api::ClearMcastForwardingReq;
use oxide_vpc::api::DEFAULT_MULTICAST_VNI;
use oxide_vpc::api::DhcpCfg;
use oxide_vpc::api::Direction;
use oxide_vpc::api::ExternalIpCfg;
use oxide_vpc::api::Filters;
use oxide_vpc::api::FirewallAction;
use oxide_vpc::api::FirewallRule;
use oxide_vpc::api::IpAddr;
use oxide_vpc::api::IpCfg;
use oxide_vpc::api::IpCidr;
use oxide_vpc::api::Ipv4Addr;
use oxide_vpc::api::Ipv4Cfg;
use oxide_vpc::api::Ipv6Addr;
use oxide_vpc::api::Ipv6Cfg;
use oxide_vpc::api::MacAddr;
use oxide_vpc::api::McastSubscribeReq;
use oxide_vpc::api::McastUnsubscribeReq;
use oxide_vpc::api::PhysNet;
use oxide_vpc::api::Ports;
use oxide_vpc::api::RouterClass;
use oxide_vpc::api::RouterTarget;
use oxide_vpc::api::SNat4Cfg;
use oxide_vpc::api::SNat6Cfg;
use oxide_vpc::api::SetMcast2PhysReq;
use oxide_vpc::api::SetMcastForwardingReq;
use oxide_vpc::api::SetVirt2PhysReq;
use oxide_vpc::api::Vni;
use oxide_vpc::api::VpcCfg;
use rand::Rng;
use std::cell::RefCell;
use std::collections::HashSet;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use zone::Zlogin;
pub use ztest::*;

/// The IPv4 overlay network used in all tests.
pub const OVERLAY_NET: &str = "10.0.0.0/24";
/// The IPv4 overlay OPTE gateway used in all tests.
pub const OVERLAY_GW: &str = "10.0.0.254";
/// The IPv6 overlay network used in all tests.
pub const OVERLAY_NET_V6: &str = "fd00::/64";
/// The IPv6 overlay OPTE gateway used in all tests.
pub const OVERLAY_GW_V6: &str = "fd00::254";

/// This is a wrapper around the ztest::Zone object that encapsulates common
/// logic needed for running the OPTE tests zones used in this test suite.
pub struct OpteZone {
    pub zone: Zone,
}

impl OpteZone {
    /// Create a new zone with the given name, underlying zfs instance and set
    /// of interfaces. In illumos parlance, the interfaces are data link
    /// devices.
    fn new(name: &str, zfs: &Zfs, ifx: &[&str], brand: &str) -> Result<Self> {
        let zone = Zone::new(name, brand, zfs, ifx, &[])?;
        Ok(Self { zone })
    }

    /// Wait for the network to come up, then set up the IPv4 overlay network.
    fn setup(&self, devname: &str, addr: String) -> Result<()> {
        self.zone.wait_for_network()?;
        // Configure IPv4 via DHCP
        self.zone
            .zexec(&format!("ipadm create-addr -t -T dhcp {devname}/test"))?;
        self.zone.zexec(&format!("route add -iface {OVERLAY_GW} {addr}"))?;
        self.zone.zexec(&format!("route add {OVERLAY_NET} {OVERLAY_GW}"))?;
        Ok(())
    }

    /// Wait for the network to come up, then set up dual-stack (IPv4 + IPv6) overlay network.
    fn setup_dualstack(
        &self,
        devname: &str,
        ipv4_addr: String,
        ipv6_addr: String,
    ) -> Result<()> {
        self.zone.wait_for_network()?;
        // Configure IPv4 via DHCP
        self.zone
            .zexec(&format!("ipadm create-addr -t -T dhcp {devname}/testv4"))?;
        self.zone
            .zexec(&format!("route add -iface {OVERLAY_GW} {ipv4_addr}"))?;
        self.zone.zexec(&format!("route add {OVERLAY_NET} {OVERLAY_GW}"))?;

        // Configure IPv6 with static address
        // Use addrconf first to enable IPv6 on the interface, then add static address
        self.zone.zexec(&format!(
            "ipadm create-addr -t -T addrconf {devname}/addrconf"
        ))?;
        // Small delay to let addrconf initialize
        std::thread::sleep(Duration::from_millis(500));
        self.zone.zexec(&format!(
            "ipadm create-addr -t -T static -a {ipv6_addr}/64 {devname}/testv6"
        ))?;
        self.zone.zexec(&format!(
            "route add -inet6 -iface {OVERLAY_GW_V6} {ipv6_addr}"
        ))?;
        self.zone.zexec(&format!(
            "route add -inet6 {OVERLAY_NET_V6} {OVERLAY_GW_V6}"
        ))?;
        Ok(())
    }
}

/// This is a wrapper around an OPTE port configuration. It provides a number of
/// methods to streamline test-suite-specific OPTE configuration. It also
/// deletes itself from the underlying OPTE kernel module state when dropped.
pub struct OptePort {
    name: String,
    cfg: VpcCfg,
    mcast_subscriptions: RefCell<Vec<IpAddr>>,
}

impl OptePort {
    /// Create a new OPTE port with the provided `name`. The `private_ip` and
    /// `guest_mac` parameters represent the ip/mac combo in a VM instance. The
    /// `phys_ip` is the underlay address this port will use for sourcing
    /// encapsulated traffic.
    pub fn new(
        name: &str,
        private_ip: &str,
        guest_mac: &str,
        phys_ip: &str,
    ) -> Result<Self> {
        let cfg = VpcCfg {
            ip_cfg: IpCfg::Ipv4(Ipv4Cfg {
                vpc_subnet: OVERLAY_NET.parse().unwrap(),
                private_ip: private_ip.parse().unwrap(),
                gateway_ip: OVERLAY_GW.parse().unwrap(),
                external_ips: ExternalIpCfg {
                    snat: Some(SNat4Cfg {
                        external_ip: "1.2.3.4".parse().unwrap(),
                        ports: 1000..=2000,
                    }),
                    ephemeral_ip: None,
                    floating_ips: vec![],
                },
            }),
            guest_mac: guest_mac.parse().unwrap(),
            gateway_mac: "a8:40:25:00:00:01".parse().unwrap(),
            vni: Vni::new(DEFAULT_MULTICAST_VNI).unwrap(),
            phys_ip: phys_ip.parse().unwrap(),
        };
        let adm = OpteHdl::open()?;
        adm.create_xde(name, cfg.clone(), DhcpCfg::default(), false)?;
        Ok(OptePort {
            name: name.into(),
            cfg,
            mcast_subscriptions: RefCell::new(Vec::new()),
        })
    }

    /// Create a new OPTE port with dual-stack (IPv4 + IPv6) support.
    pub fn new_dualstack(
        name: &str,
        private_ip_v4: &str,
        private_ip_v6: &str,
        guest_mac: &str,
        phys_ip: &str,
    ) -> Result<Self> {
        let cfg = VpcCfg {
            ip_cfg: IpCfg::DualStack {
                ipv4: Ipv4Cfg {
                    vpc_subnet: OVERLAY_NET.parse().unwrap(),
                    private_ip: private_ip_v4.parse().unwrap(),
                    gateway_ip: OVERLAY_GW.parse().unwrap(),
                    external_ips: ExternalIpCfg {
                        snat: Some(SNat4Cfg {
                            external_ip: "1.2.3.4".parse().unwrap(),
                            ports: 1000..=2000,
                        }),
                        ephemeral_ip: None,
                        floating_ips: vec![],
                    },
                },
                ipv6: Ipv6Cfg {
                    vpc_subnet: OVERLAY_NET_V6.parse().unwrap(),
                    private_ip: private_ip_v6.parse().unwrap(),
                    gateway_ip: OVERLAY_GW_V6.parse().unwrap(),
                    external_ips: ExternalIpCfg {
                        snat: Some(SNat6Cfg {
                            external_ip: "2001:db8::1".parse().unwrap(),
                            ports: 4097..=8192,
                        }),
                        ephemeral_ip: None,
                        floating_ips: vec![],
                    },
                },
            },
            guest_mac: guest_mac.parse().unwrap(),
            gateway_mac: "a8:40:25:00:00:01".parse().unwrap(),
            vni: Vni::new(DEFAULT_MULTICAST_VNI).unwrap(),
            phys_ip: phys_ip.parse().unwrap(),
        };
        let adm = OpteHdl::open()?;
        adm.create_xde(name, cfg.clone(), DhcpCfg::default(), false)?;
        Ok(OptePort {
            name: name.into(),
            cfg,
            mcast_subscriptions: RefCell::new(Vec::new()),
        })
    }

    /// Add an overlay routing entry to this port.
    pub fn add_router_entry(&self, dest: &str) -> Result<()> {
        let adm = OpteHdl::open()?;
        adm.add_router_entry(&AddRouterEntryReq {
            port_name: self.name.clone(),
            dest: IpCidr::Ip4(format!("{}/32", dest).parse().unwrap()),
            target: RouterTarget::Ip(dest.parse().unwrap()),
            class: RouterClass::System,
        })?;
        Ok(())
    }

    /// Allow all traffic through the overlay firewall.
    pub fn fw_allow_all(&self) -> Result<()> {
        let adm = OpteHdl::open()?;
        let mut filters = Filters::new();
        filters.set_hosts(Address::Any);
        filters.set_ports(Ports::Any);
        adm.add_firewall_rule(&AddFwRuleReq {
            port_name: self.name.clone(),
            rule: FirewallRule {
                direction: Direction::In,
                action: FirewallAction::Allow,
                priority: 0,
                filters,
            },
        })?;

        Ok(())
    }

    /// Return the guest mac as an array of bytes.
    pub fn mac(&self) -> [u8; 6] {
        self.cfg.guest_mac.bytes()
    }

    /// Return the guest IPv4 address as a string.
    pub fn ip(&self) -> String {
        match &self.cfg.ip_cfg {
            IpCfg::Ipv4(cfg) => cfg.private_ip.to_string(),
            IpCfg::DualStack { ipv4, .. } => ipv4.private_ip.to_string(),
            _ => panic!("expected ipv4 or dualstack guest"),
        }
    }

    /// Return the guest IPv6 address as a string (for dual-stack ports).
    pub fn ipv6(&self) -> Option<String> {
        match &self.cfg.ip_cfg {
            IpCfg::DualStack { ipv6, .. } => Some(ipv6.private_ip.to_string()),
            _ => None,
        }
    }

    /// Return the source underlay address.
    pub fn underlay_ip(&self) -> std::net::Ipv6Addr {
        self.cfg.phys_ip.into()
    }

    /// Return the port name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Subscribe this port to a multicast group.
    /// Automatically tracks the subscription for cleanup on drop.
    pub fn subscribe_multicast(&self, group: IpAddr) -> Result<()> {
        let adm = OpteHdl::open()?;
        adm.mcast_subscribe(&McastSubscribeReq {
            port_name: self.name.clone(),
            group,
        })?;
        self.mcast_subscriptions.borrow_mut().push(group);
        Ok(())
    }

    /// Unsubscribe this port from a multicast group.
    pub fn unsubscribe_multicast(&self, group: IpAddr) -> Result<()> {
        let adm = OpteHdl::open()?;
        adm.mcast_unsubscribe(&McastUnsubscribeReq {
            port_name: self.name.clone(),
            group,
        })?;
        self.mcast_subscriptions.borrow_mut().retain(|g| *g != group);
        Ok(())
    }

    /// Add a multicast router entry for this port.
    pub fn add_multicast_router_entry(&self, cidr: IpCidr) -> Result<()> {
        let adm = OpteHdl::open()?;
        adm.add_router_entry(&AddRouterEntryReq {
            port_name: self.name.clone(),
            dest: cidr,
            target: RouterTarget::Multicast(cidr),
            class: RouterClass::System,
        })?;
        Ok(())
    }

    /// Allow multicast CIDR through the overlay firewall for the given direction.
    pub fn allow_cidr(&self, cidr: IpCidr, direction: Direction) -> Result<()> {
        let adm = OpteHdl::open()?;
        adm.allow_cidr(&self.name, cidr, direction)?;
        Ok(())
    }
}

impl Drop for OptePort {
    /// When this port is dropped, remove it from the underlying xde device.
    fn drop(&mut self) {
        let adm = match OpteHdl::open() {
            Ok(adm) => adm,
            Err(e) => {
                eprintln!("failed to open xde device on drop: {}", e);
                return;
            }
        };

        // Clean up multicast subscriptions
        let subscriptions = self.mcast_subscriptions.borrow().clone();
        for group in subscriptions {
            if let Err(e) = adm.mcast_unsubscribe(&McastUnsubscribeReq {
                port_name: self.name.clone(),
                group,
            }) {
                let name = &self.name;
                eprintln!(
                    "failed to unsubscribe {name} from multicast group {group}: {e}"
                );
            }
        }

        if let Err(e) = adm.delete_xde(&self.name) {
            eprintln!("failed to delete xde on drop: {e}");
        }
    }
}

/// This is resource handle for an xde device. It provides a few convenience
/// methods for setting up global OPTE properties. It also removes the xde
/// driver from the kernel when dropped. This is helpful for cleaning things up
/// after a test run.
pub struct Xde {}

impl Xde {
    /// Set the underlay data links that all OPTE ports will use.
    fn set_xde_underlay(dev0: &str, dev1: &str) -> Result<()> {
        let adm = OpteHdl::open()?;
        adm.set_xde_underlay(dev0, dev1)?;
        Ok(())
    }

    /// Set the virtual to physical port mappings that all OPTE ports will use.
    fn set_v2p(vip: &str, ether: &str, ip: &str) -> Result<()> {
        let adm = OpteHdl::open()?;
        adm.set_v2p(&SetVirt2PhysReq {
            vip: vip.parse().unwrap(),
            phys: PhysNet {
                ether: ether.parse().unwrap(),
                ip: ip.parse().unwrap(),
                vni: Vni::new(DEFAULT_MULTICAST_VNI).unwrap(),
            },
        })?;
        Ok(())
    }
}
impl Drop for Xde {
    fn drop(&mut self) {
        // Clear underlay to release references to simnet/vnic devices,
        // allowing their cleanup to proceed. Driver remains loaded.
        if let Ok(adm) = OpteHdl::open() {
            let _ = adm.clear_xde_underlay();
        }
    }
}

/// Helper to run `snoop` and ensure it doesn't outlive the test.
///
/// This avoids leaked `snoop` processes pinning DLPI devices (causing EBUSY)
/// when tests time out.
pub struct SnoopGuard {
    child: Option<Child>,
}

impl SnoopGuard {
    /// Start a `snoop` capture on `dev_name` with the provided BPF-like `filter`.
    /// Captures a single packet (`-c 1`) and dumps hex output (`-x0`).
    /// Uses `-r` to disable name resolution for deterministic numeric output.
    pub fn start(dev_name: &str, filter: &str) -> anyhow::Result<Self> {
        let child = Command::new("pfexec")
            .args(&[
                "snoop", "-r", "-d", dev_name, "-c", "1", "-P", "-x0", filter,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        Ok(Self { child: Some(child) })
    }

    /// Wait for completion with a timeout. Returns stdout if successful.
    pub fn wait_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> anyhow::Result<std::process::Output> {
        let deadline = Instant::now() + timeout;

        loop {
            let child = self.child.as_mut().expect("child already taken");
            match child.try_wait()? {
                Some(_status) => {
                    // Child exited; collect output.
                    let child = self.child.take().expect("child already taken");
                    return Ok(child.wait_with_output()?);
                }
                None => {
                    if Instant::now() >= deadline {
                        // Timed out; kill snoop so it doesn't hold interfaces open.
                        let _ = child.kill();
                        let _ = child.wait();
                        bail!("snoop capture timed out");
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
}

impl Drop for SnoopGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            if let Ok(None) = child.try_wait() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

/// Global multicast group state that cleans up M2P mappings and forwarding
/// entries on drop. Port-specific subscriptions are handled automatically by
/// OptePort::drop().
///
/// Use this to set up multicast groups in tests. Port subscriptions should use
/// `port.subscribe_multicast(group)` which tracks cleanup automatically.
pub struct MulticastGroup {
    pub group: IpAddr,
    pub underlay: Ipv6Addr,
    pub vni: Vni,
}

impl MulticastGroup {
    pub fn new(group: IpAddr, underlay: Ipv6Addr, vni: Vni) -> Result<Self> {
        let hdl = OpteHdl::open()?;
        hdl.set_m2p(&SetMcast2PhysReq { group, underlay, vni })?;
        Ok(Self { group, underlay, vni })
    }

    /// Set multicast forwarding entries for this group.
    pub fn set_forwarding(
        &self,
        next_hops: Vec<(
            oxide_vpc::api::NextHopV6,
            oxide_vpc::api::Replication,
        )>,
    ) -> Result<()> {
        let hdl = OpteHdl::open()?;
        hdl.set_mcast_fwd(&SetMcastForwardingReq {
            group: self.group,
            next_hops,
        })?;
        Ok(())
    }
}

impl Drop for MulticastGroup {
    fn drop(&mut self) {
        let Ok(hdl) = OpteHdl::open() else {
            eprintln!("failed to open xde device for multicast cleanup");
            return;
        };

        // Clear forwarding entry
        let group = self.group;
        if let Err(e) =
            hdl.clear_mcast_fwd(&ClearMcastForwardingReq { group: self.group })
        {
            eprintln!("failed to clear multicast forwarding for {group}: {e}");
        }

        // Clear M2P mapping
        if let Err(e) = hdl.clear_m2p(&ClearMcast2PhysReq {
            group: self.group,
            underlay: self.underlay,
            vni: self.vni,
        }) {
            eprintln!("failed to clear M2P mapping for {group}: {e}");
        }
    }
}

/// An individual zone connected to an OPTE port.
// Note: these fields have a *very* sensitive drop order.
pub struct TestNode {
    pub zone: OpteZone,
    pub port: OptePort,
}

impl TestNode {
    /// Return an executable command targeting this zone.
    pub fn command(&self, cmd: &str) -> Command {
        let z = Zlogin::new(&self.zone.zone.name);
        z.as_command(cmd)
    }
}

/// A topology of local zones interconnected with simlinks over
/// an OPTE dataplane.
// Note: these fields have a *very* sensitive drop order.
// Rust drops fields in declaration order. Zones must drop FIRST (to release
// references to network devices), then network infrastructure can clean up.
// Drop order: nodes -> null_ports -> v6_routes -> xde -> lls -> vnics -> simnet -> zfs
pub struct Topology {
    pub nodes: Vec<TestNode>,
    pub null_ports: Vec<OptePort>,
    pub v6_routes: Vec<RouteV6>,
    pub xde: Xde,
    pub lls: Vec<LinkLocal>,
    pub vnics: Vec<Vnic>,
    pub simnet: Option<SimnetLink>,
    pub zfs: Arc<Zfs>,
}

/// This is an xde loopback topology. There are two zones, each with a vnic
/// sitting atop an opte device. The opte device uses a pair of simnet
/// devices as underlay links. These simnet devices are connected to each
/// other.
///
///         zone a
///     #============#
///     | *--------* |    *-------*
///     | | vopte0 |------| opte0 |         *------*
///     | *--------* |    *-------*      +--| sim0 |--+
///     #============#       |  *-----*  |  *------*  |
///                          +--| xde |--+            |
///     #============#       |  *-----*  |  *------*  |
///     | *--------* |    *-------*      +--| sim1 |--+
///     | | vopte1 |------| opte1 |         *------*
///     | *--------* |    *-------*
///     #============#
///         zone b
///
/// The following system of overlay/underlay routes is set up
///
/// 10.0.0.1 -> fd44::/64 via sim1
/// 10.0.0.2 -> fd77::/64 via sim0
///
/// Zone a has an overlay address of 10.0.0.1 and zone b has an overlay
/// address of 10.0.0.2. This means that OPTE will encap/decap packets to
/// and from the vopte devices, the underlying routes on the host will lead
/// xde to select the correct simnet device. Then the simnet setup will
/// forward the packet to it's adjacent peer, which then makes it's way back
/// to OPTE and then to the adjacent vopte device. This is a nice little
/// sanity checker to make sure basic opte/xde functionality is working - and
/// that we're not hitting things like debug asserts in the OS.
pub fn two_node_topology(brand: &str) -> Result<Topology> {
    two_node_topology_named(brand, "a", "b")
}

pub fn two_node_topology_named(
    brand: &str,
    zone_a_name: &str,
    zone_b_name: &str,
) -> Result<Topology> {
    // Create the "underlay loopback". With simnet device pairs, any packet that
    // goes in one is forwarded to the other. In the topology depicted above,
    // this means that anything vopte0 sends, will be encapsulated onto the
    // underlay by opte0, sent to sim0 (more on the routing that makes that
    // happen later), is forwarded to sim1, is decapsulated by opte1 and then
    // sent to vopte1.
    let sim = SimnetLink::new("xde_test_sim0", "xde_test_sim1")?;
    let vn0 = Vnic::new("xde_test_vnic0", &sim.end_a)?;
    let vn1 = Vnic::new("xde_test_vnic1", &sim.end_b)?;
    let ll0 = LinkLocal::new(&vn0.name, "ll")?;
    let ll1 = LinkLocal::new(&vn1.name, "ll")?;

    Xde::set_xde_underlay(&vn0.name, &vn1.name)?;
    // TODO this is a sort of force unset underlay until we have an unset
    // underlay command. When this object drops it will remove the xde driver.
    // If we do not do this, xde will hold references to the simnet devices
    // preventing us from cleaning them up after this test.
    let xde = Xde {};

    // Set up the virtual to physical mapptings for this test run.
    Xde::set_v2p("10.0.0.1", "a8:40:25:ff:00:01", "fd44::1")?;
    Xde::set_v2p("10.0.0.2", "a8:40:25:ff:00:02", "fd77::1")?;

    // Create the first OPTE port with the provided overlay/underlay parameters.
    let opte0 =
        OptePort::new("opte0", "10.0.0.1", "a8:40:25:ff:00:01", "fd44::1")?;
    opte0.add_router_entry("10.0.0.2")?;
    opte0.fw_allow_all()?;

    // Add a host route to the underlay address of opte0, through the link local
    // address of sim0 as a nexthop through sim1. This is facilitating the flow
    // of traffic from opte1 to opte0. When a packet enters opte1 (from vopte1)
    // destined for 10.0.0.1, opte will look up the v2p mapping which points to
    // fd44::1. That is the underlay address of opte0. The route below says:
    // that address is reachable through the sim1 interface, with a nexthop of
    // the sim0 interface. In the diagram above, that is the "upward" direction
    // of our simnet underlay loopback. The xde device uses the kernel's routing
    // tables to determine which underlay device to use. With this route in
    // place, packets going to the underlay address of opte0, will always go in
    // sim1 and out sim0.
    println!("adding underlay route 0");
    let r0 =
        RouteV6::new(opte0.underlay_ip(), 64, ll0.ip, Some(vn1.name.clone()))?;

    // Create the second OPTE port with the provided overlay/underlay parameters.
    let opte1 =
        OptePort::new("opte1", "10.0.0.2", "a8:40:25:ff:00:02", "fd77::1")?;
    opte1.add_router_entry("10.0.0.1")?;
    opte1.fw_allow_all()?;

    // See the comment for _r0 above. This is doing the same thing, but in
    // reverse to create the "downward" direction of the simnet underlay
    // loopback.
    println!("adding underlay route 1");
    let r1 =
        RouteV6::new(opte1.underlay_ip(), 64, ll1.ip, Some(vn0.name.clone()))?;

    // Set up a zfs pool for our test zones.
    let zfs = Arc::new(Zfs::new("opte2node")?);

    // Create a pair of zones to simulate our VM instances.
    println!("start zone {zone_a_name}");
    let a = OpteZone::new(zone_a_name, &zfs, &[&opte0.name], brand)?;
    println!("start zone {zone_b_name}");
    let b = OpteZone::new(zone_b_name, &zfs, &[&opte1.name], brand)?;

    println!("setup zone {zone_a_name}");
    a.setup(&opte0.name, opte0.ip())?;

    println!("setup zone {zone_b_name}");
    b.setup(&opte1.name, opte1.ip())?;

    Ok(Topology {
        nodes: vec![
            TestNode { zone: a, port: opte0 },
            TestNode { zone: b, port: opte1 },
        ],
        null_ports: vec![],
        v6_routes: vec![r0, r1],
        xde,
        lls: vec![ll0, ll1],
        vnics: vec![vn0, vn1],
        simnet: Some(sim),
        zfs,
    })
}

pub fn two_node_topology_dualstack(brand: &str) -> Result<Topology> {
    two_node_topology_dualstack_named(brand, "a", "b")
}

pub fn two_node_topology_dualstack_named(
    brand: &str,
    zone_a_name: &str,
    zone_b_name: &str,
) -> Result<Topology> {
    let sim = SimnetLink::new("xde_test_sim0", "xde_test_sim1")?;
    let vn0 = Vnic::new("xde_test_vnic0", &sim.end_a)?;
    let vn1 = Vnic::new("xde_test_vnic1", &sim.end_b)?;
    let ll0 = LinkLocal::new(&vn0.name, "ll")?;
    let ll1 = LinkLocal::new(&vn1.name, "ll")?;

    Xde::set_xde_underlay(&vn0.name, &vn1.name)?;
    let xde = Xde {};

    // Set up v2p mappings (same as IPv4-only version)
    Xde::set_v2p("10.0.0.1", "a8:40:25:ff:00:01", "fd44::1")?;
    Xde::set_v2p("10.0.0.2", "a8:40:25:ff:00:02", "fd77::1")?;

    // Create dual-stack OPTE ports
    let opte0 = OptePort::new_dualstack(
        "opte0",
        "10.0.0.1",
        "fd00::1",
        "a8:40:25:ff:00:01",
        "fd44::1",
    )?;
    opte0.add_router_entry("10.0.0.2")?;
    opte0.fw_allow_all()?;

    println!("adding underlay route 0");
    let r0 =
        RouteV6::new(opte0.underlay_ip(), 64, ll0.ip, Some(vn1.name.clone()))?;

    let opte1 = OptePort::new_dualstack(
        "opte1",
        "10.0.0.2",
        "fd00::2",
        "a8:40:25:ff:00:02",
        "fd77::1",
    )?;
    opte1.add_router_entry("10.0.0.1")?;
    opte1.fw_allow_all()?;

    println!("adding underlay route 1");
    let r1 =
        RouteV6::new(opte1.underlay_ip(), 64, ll1.ip, Some(vn0.name.clone()))?;

    let zfs = Arc::new(Zfs::new("opte2node")?);

    println!("start zone {zone_a_name}");
    let a = OpteZone::new(zone_a_name, &zfs, &[&opte0.name], brand)?;
    println!("start zone {zone_b_name}");
    let b = OpteZone::new(zone_b_name, &zfs, &[&opte1.name], brand)?;

    println!("setup zone {zone_a_name}");
    a.setup_dualstack(&opte0.name, opte0.ip(), "fd00::1".to_string())?;

    println!("setup zone {zone_b_name}");
    b.setup_dualstack(&opte1.name, opte1.ip(), "fd00::2".to_string())?;

    Ok(Topology {
        nodes: vec![
            TestNode { zone: a, port: opte0 },
            TestNode { zone: b, port: opte1 },
        ],
        null_ports: vec![],
        v6_routes: vec![r0, r1],
        xde,
        lls: vec![ll0, ll1],
        vnics: vec![vn0, vn1],
        simnet: Some(sim),
        zfs,
    })
}

pub fn three_node_topology(brand: &str) -> Result<Topology> {
    three_node_topology_named(brand, "a", "b", "c")
}

pub fn three_node_topology_named(
    brand: &str,
    zone_a_name: &str,
    zone_b_name: &str,
    zone_c_name: &str,
) -> Result<Topology> {
    // Create three-node topology for testing multicast fanout
    let sim = SimnetLink::new("xde_test_sim0", "xde_test_sim1")?;
    let vn0 = Vnic::new("xde_test_vnic0", &sim.end_a)?;
    let vn1 = Vnic::new("xde_test_vnic1", &sim.end_b)?;
    let ll0 = LinkLocal::new(&vn0.name, "ll")?;
    let ll1 = LinkLocal::new(&vn1.name, "ll")?;

    Xde::set_xde_underlay(&vn0.name, &vn1.name)?;
    let xde = Xde {};

    // Set up V2P mappings for three nodes
    Xde::set_v2p("10.0.0.1", "a8:40:25:ff:00:01", "fd44::1")?;
    Xde::set_v2p("10.0.0.2", "a8:40:25:ff:00:02", "fd77::1")?;
    Xde::set_v2p("10.0.0.3", "a8:40:25:ff:00:03", "fd88::1")?;

    // Create three OPTE ports
    let opte0 =
        OptePort::new("opte0", "10.0.0.1", "a8:40:25:ff:00:01", "fd44::1")?;
    opte0.add_router_entry("10.0.0.2")?;
    opte0.add_router_entry("10.0.0.3")?;
    opte0.fw_allow_all()?;

    let opte1 =
        OptePort::new("opte1", "10.0.0.2", "a8:40:25:ff:00:02", "fd77::1")?;
    opte1.add_router_entry("10.0.0.1")?;
    opte1.add_router_entry("10.0.0.3")?;
    opte1.fw_allow_all()?;

    let opte2 =
        OptePort::new("opte2", "10.0.0.3", "a8:40:25:ff:00:03", "fd88::1")?;
    opte2.add_router_entry("10.0.0.1")?;
    opte2.add_router_entry("10.0.0.2")?;
    opte2.fw_allow_all()?;

    println!("adding underlay route 0");
    let r0 =
        RouteV6::new(opte0.underlay_ip(), 64, ll0.ip, Some(vn1.name.clone()))?;

    println!("adding underlay route 1");
    let r1 =
        RouteV6::new(opte1.underlay_ip(), 64, ll1.ip, Some(vn0.name.clone()))?;

    println!("adding underlay route 2");
    let r2 =
        RouteV6::new(opte2.underlay_ip(), 64, ll1.ip, Some(vn0.name.clone()))?;

    let zfs = Arc::new(Zfs::new("opte3node")?);

    println!("start zone {zone_a_name}");
    let a = OpteZone::new(zone_a_name, &zfs, &[&opte0.name], brand)?;
    println!("start zone {zone_b_name}");
    let b = OpteZone::new(zone_b_name, &zfs, &[&opte1.name], brand)?;
    println!("start zone {zone_c_name}");
    let c = OpteZone::new(zone_c_name, &zfs, &[&opte2.name], brand)?;

    println!("setup zone {zone_a_name}");
    a.setup(&opte0.name, opte0.ip())?;

    println!("setup zone {zone_b_name}");
    b.setup(&opte1.name, opte1.ip())?;

    println!("setup zone {zone_c_name}");
    c.setup(&opte2.name, opte2.ip())?;

    Ok(Topology {
        nodes: vec![
            TestNode { zone: a, port: opte0 },
            TestNode { zone: b, port: opte1 },
            TestNode { zone: c, port: opte2 },
        ],
        null_ports: vec![],
        v6_routes: vec![r0, r1, r2],
        xde,
        lls: vec![ll0, ll1],
        vnics: vec![vn0, vn1],
        simnet: Some(sim),
        zfs,
    })
}

#[derive(Copy, Clone)]
pub struct PortInfo {
    pub ip: IpAddr,
    pub mac: MacAddr,
    pub underlay_addr: Ipv6Addr,
}

pub const ZONE_A_PORT: PortInfo = PortInfo {
    ip: IpAddr::Ip4(Ipv4Addr::from_const([10, 0, 0, 1])),
    mac: MacAddr::from_const([0xa8, 0x40, 0x25, 0xff, 0x00, 0x01]),
    underlay_addr: Ipv6Addr::from_const([
        0xfd44, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001,
    ]),
};

pub const ZONE_B_PORT: PortInfo = PortInfo {
    ip: IpAddr::Ip4(Ipv4Addr::from_const([10, 0, 0, 2])),
    mac: MacAddr::from_const([0xa8, 0x40, 0x25, 0xff, 0x00, 0x02]),
    underlay_addr: Ipv6Addr::from_const([
        0xfd77, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001,
    ]),
};

/// Return a link-local address attached to a device `link_name`,
/// assuming that address is named `<link_name>/ll`.
pub fn get_linklocal_addr(link_name: &str) -> Result<std::net::Ipv6Addr> {
    let target_addr = format!("{link_name}/ll");
    let out = Command::new("ipadm")
        .arg("show-addr")
        .arg(target_addr.clone())
        .output()?;

    let text = std::str::from_utf8(&out.stdout)?;

    if !out.status.success() || text.lines().count() == 1 {
        bail!("could not find address {target_addr}");
    }

    let mut maybe_addr = text
        .lines()
        .nth(1)
        .ok_or(anyhow!("expected to find entry line for IP"))?
        .split_whitespace()
        .last()
        .ok_or(anyhow!("expected to find column for IP"))?;

    // remove iface qualifier on link-local addr.
    if maybe_addr.contains('%') {
        maybe_addr = maybe_addr.split('%').next().unwrap()
    }

    Ok(maybe_addr.parse()?)
}

/// Creates a single node zone on this machine and assigns it an OPTE
/// VNIC.
pub fn single_node_over_real_nic(
    underlay: &[String; 2],
    my_info: PortInfo,
    peers: &[PortInfo],
    null_port_count: u32,
    brand: &str,
) -> Result<Topology> {
    Xde::set_xde_underlay(&underlay[0], &underlay[1])?;
    let xde = Xde {};

    let max_macs = (1 << 20) - peers.len() - 1;
    if null_port_count > max_macs as u32 {
        bail!(
            "Cannot allocate {null_port_count} ports: \
            Oxide MAC space admits {max_macs} accounting for peers"
        );
    }

    let mut null_ports = vec![];

    // This is an absurd preallocation (~6MiB?) -- but it is deterministic,
    // and if we want to test A Lot of ports then we can.
    let forbidden_macs: HashSet<_> =
        (&[my_info]).iter().chain(peers).map(|v| v.mac).collect();
    let mut usable_macs: Vec<MacAddr> = (0..(1 << 20))
        .filter_map(|n: u32| {
            let raw = n.to_be_bytes();
            let my_mac = MacAddr::from_const([
                0xa8,
                0x40,
                0x25,
                0xf0 + (raw[1] & 0xf),
                raw[2],
                raw[3],
            ]);

            if forbidden_macs.contains(&my_mac) { None } else { Some(my_mac) }
        })
        .collect();

    // Create any null ports before our actual one, to get worst-case
    // lookups in the linear case.
    let underlay_addr = my_info.underlay_addr.to_string();
    let mut rng = rand::rng();
    while null_ports.len() as u32 != null_port_count {
        let i = rng.random_range(0..usable_macs.len());
        let taken_mac = usable_macs.swap_remove(i).to_string();

        // VIP reuse is not an issue, we aren't using these ports for communication.
        null_ports.push(OptePort::new(
            &format!("opte{}", null_ports.len()),
            &"172.20.0.1",
            &taken_mac,
            &underlay_addr,
        )?);
    }

    let ip = my_info.ip.to_string();
    let mac = my_info.mac.to_string();
    Xde::set_v2p(&ip, &mac, &underlay_addr)?;

    let opte = OptePort::new(
        &format!("opte{}", null_ports.len()),
        &ip,
        &mac,
        &underlay_addr,
    )?;

    let v6_routes = vec![];
    for peer in peers {
        let ip = peer.ip.to_string();
        let mac = peer.mac.to_string();
        let underlay_addr = peer.underlay_addr.to_string();
        Xde::set_v2p(&ip, &mac, &underlay_addr)?;
        opte.add_router_entry(&ip)?;
    }

    opte.fw_allow_all()?;

    // Set up a zfs pool for our test zones.
    let zfs = Arc::new(Zfs::new("opte1node")?);

    println!("start zone");
    let a = OpteZone::new("a", &zfs, &[&opte.name], brand)?;

    std::thread::sleep(Duration::from_secs(30));

    println!("setup zone");
    a.setup(&opte.name, opte.ip())?;

    Ok(Topology {
        nodes: vec![TestNode { zone: a, port: opte }],
        null_ports,
        v6_routes,
        xde,
        lls: vec![],
        vnics: vec![],
        simnet: None,
        zfs,
    })
}

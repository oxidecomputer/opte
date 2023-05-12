use anyhow::Result;
use opteadm::OpteAdm;
use oxide_vpc::api::{
    AddRouterEntryReq, Address, BoundaryServices, Direction, Filters,
    FirewallAction, FirewallRule, IpCfg, IpCidr, Ipv4Cfg, PhysNet, Ports,
    RouterTarget, SNat4Cfg, SetVirt2PhysReq, Vni, VpcCfg,
};
use std::env;
use std::process::Command;
use ztest::*;

/// This is a wrapper around the ztest::Zone object that encapsulates common
/// logic needed for running the OPTE tests zones used in this test suite.
struct OpteZone<'a> {
    _zfs: &'a Zfs,
    zone: Zone,
}

impl<'a> OpteZone<'a> {
    /// Create a new zone with the given name, underlying zfs instance and set
    /// of interfaces. In illumos parlance, the interfaces are data link
    /// devices.
    fn new(name: &str, zfs: &'a Zfs, ifx: &[&'a str]) -> Result<Self> {
        // If we're running in CI, use the omicron1 zone, because that's whats
        // there. If this is running locally, use a sparse zone which is much
        // easier to set up on a regular Helios dev box.
        let brand = match env::var("BUILDOMAT_JOB_ID") {
            Ok(_) => "omicron1",
            _ => "sparse",
        };
        let zone = Zone::new(name, brand, zfs, ifx)?;
        Ok(Self { _zfs: zfs, zone })
    }

    /// Wait for the network to come up, then set up the overlay network.
    fn setup(&self, devname: &str, addr: String) -> Result<()> {
        self.zone.wait_for_network()?;
        self.zone
            .zexec(&format!("ipadm create-addr -t -T dhcp {}/test", devname))?;
        self.zone.zexec(&format!("route add -iface 10.0.0.254 {}", addr))?;
        self.zone.zexec("route add 10.0.0.0/24 10.0.0.254")?;
        Ok(())
    }
}

/// This is a wrapper around an OPTE port configuration. It provides a number of
/// methods to streamline test-suite-specific OPTE configuration. It also
/// deletes itself from the underlying OPTE kernel module state when dropped.
struct OptePort {
    name: String,
    cfg: VpcCfg,
}

impl OptePort {
    /// Create a new OPTE port with the provided `name`. The `private_ip` and
    /// `guest_mac` parameters represent the ip/mac combo in a VM instance. The
    /// `phys_ip` is the underlay address this port will use for sourcing
    /// encapsulated traffic.
    fn new(
        name: &str,
        private_ip: &str,
        guest_mac: &str,
        phys_ip: &str,
    ) -> Result<Self> {
        let cfg = VpcCfg {
            ip_cfg: IpCfg::Ipv4(Ipv4Cfg {
                vpc_subnet: "10.0.0.0/24".parse().unwrap(),
                private_ip: private_ip.parse().unwrap(),
                gateway_ip: "10.0.0.254".parse().unwrap(),
                snat: Some(SNat4Cfg {
                    external_ip: "1.2.3.4".parse().unwrap(),
                    ports: 1000..=2000,
                }),
                external_ips: None,
            }),
            guest_mac: guest_mac.parse().unwrap(),
            gateway_mac: "a8:40:25:00:00:01".parse().unwrap(),
            vni: Vni::new(1701u32).unwrap(),
            phys_ip: phys_ip.parse().unwrap(),
            boundary_services: BoundaryServices {
                ip: "fd00:99::1".parse().unwrap(),
                vni: Vni::new(99u32).unwrap(),
                mac: "00:00:00:00:00:00".parse().unwrap(),
            },
            domain_list: Vec::new(),
        };
        let adm = OpteAdm::open(OpteAdm::XDE_CTL)?;
        adm.create_xde(name, cfg.clone(), false)?;
        Ok(OptePort { name: name.into(), cfg })
    }

    /// Add an overlay routing entry to this port.
    fn add_router_entry(&self, dest: &str) -> Result<()> {
        let adm = OpteAdm::open(OpteAdm::XDE_CTL)?;
        adm.add_router_entry(&AddRouterEntryReq {
            port_name: self.name.clone(),
            dest: IpCidr::Ip4(format!("{}/32", dest).parse().unwrap()),
            target: RouterTarget::Ip(dest.parse().unwrap()),
        })?;
        Ok(())
    }

    /// Allow all traffic through the overlay firewall.
    fn fw_allow_all(&self) -> Result<()> {
        let adm = OpteAdm::open(OpteAdm::XDE_CTL)?;
        let mut filters = Filters::new();
        filters.set_hosts(Address::Any);
        filters.set_ports(Ports::Any);
        adm.add_firewall_rule(
            &self.name,
            &FirewallRule {
                direction: Direction::In,
                action: FirewallAction::Allow,
                priority: 0,
                filters,
            },
        )?;
        Ok(())
    }

    /// Return the guest mac as an array of bytes.
    fn mac(&self) -> [u8; 6] {
        self.cfg.guest_mac.bytes()
    }

    /// Return the guest IP address as a string.
    fn ip(&self) -> String {
        match &self.cfg.ip_cfg {
            IpCfg::Ipv4(cfg) => cfg.private_ip.to_string(),
            _ => panic!("expected ipv4 gueset"),
        }
    }

    /// Return the source underlay address.
    fn underlay_ip(&self) -> std::net::Ipv6Addr {
        self.cfg.phys_ip.into()
    }
}

impl Drop for OptePort {
    /// When this port is dropped, remove it from the underlying xde device.
    fn drop(&mut self) {
        let adm = match OpteAdm::open(OpteAdm::XDE_CTL) {
            Ok(adm) => adm,
            Err(e) => {
                eprintln!("failed to open xde device on drop: {}", e);
                return;
            }
        };
        if let Err(e) = adm.delete_xde(&self.name) {
            eprintln!("failed to delete xde on drop: {}", e);
        }
    }
}

/// This is resource handle for an xde device. It provides a few convenience
/// methods for setting up global OPTE properties. It also removes the xde
/// driver from the kernel when dropped. This is helpful for cleaning things up
/// after a test run.
struct Xde {}

impl Xde {
    /// Set the underlay data links that all OPTE ports will use.
    fn set_xde_underlay(dev0: &str, dev1: &str) -> Result<()> {
        let adm = OpteAdm::open(OpteAdm::XDE_CTL)?;
        adm.set_xde_underlay(dev0, dev1)?;
        Ok(())
    }

    /// Set the virtual to physical port mappings that all OPTE ports will use.
    fn set_v2p(vip: &str, ether: &str, ip: &str) -> Result<()> {
        let adm = OpteAdm::open(OpteAdm::XDE_CTL)?;
        adm.set_v2p(&SetVirt2PhysReq {
            vip: vip.parse().unwrap(),
            phys: PhysNet {
                ether: ether.parse().unwrap(),
                ip: ip.parse().unwrap(),
                vni: Vni::new(1701u32).unwrap(),
            },
        })?;
        Ok(())
    }
}
impl Drop for Xde {
    /// When this object is dropped, remove the xde kernel module from the
    /// underlying system.
    fn drop(&mut self) {
        let mut cmd = Command::new("pfexec");
        cmd.args(["rem_drv", "xde"]);
        if let Err(e) = cmd.output() {
            eprintln!("failed to remove xde driver: {}", e);
        }
    }
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
/// 10.0.0.1 -> fd47::/74 via sim1
/// 10.0.0.2 -> fd74::/74 via sim0
///
/// Zone a has an overlay address of 10.0.0.1 and zone b has an overlay
/// address of 10.0.0.2. This means that OPTE will encap/decap packets to
/// and from the vopte devices, the underlying routes on the host will lead
/// xde to select the correct simnet device. Then the simnet setup will
/// forward the packet to it's adjacent peer, which then makes it's way back
/// to OPTE and then to the adjacent vopte device. This is a nice little
/// sanity checker to make sure basic opte/xde functionality is working - and
/// that we're not hitting things like debug asserts in the OS.
#[test]
fn test_xde_loopback() -> Result<()> {
    // Create the "underlay loopback". With simnet device pairs, any packet that
    // goes in one is forwarded to the other. In the topology depicted above,
    // this means that anything vopte0 sends, will be encapsulated onto the
    // underlay by opte0, sent to sim0 (more on the routing that makes that
    // happen later), is forwarded to sim1, is decapsulated by opte1 and then
    // sent to vopte1.
    let sim = SimnetLink::new("sim0", "sim1")?;
    let ll0 = LinkLocal::new(&sim.end_a, "ll")?;
    let ll1 = LinkLocal::new(&sim.end_b, "ll")?;

    Xde::set_xde_underlay(&sim.end_a, &sim.end_b)?;
    // TODO this is a sort of force unset underlay until we have an unset
    // underlay command. When this object drops it will remove the xde driver.
    // If we do not do this, xde will hold references to the simnet devices
    // preventing us from cleaning them up after this test.
    let _xde = Xde {};

    // Set up the virtual to physical mapptings for this test run.
    Xde::set_v2p("10.0.0.1", "a8:40:25:ff:00:01", "fd47::1")?;
    Xde::set_v2p("10.0.0.2", "a8:40:25:ff:00:02", "fd74::1")?;

    // Create the first OPTE port with the provided overlay/underlay parameters.
    let opte0 =
        OptePort::new("opte0", "10.0.0.1", "a8:40:25:ff:00:01", "fd47::1")?;
    opte0.add_router_entry("10.0.0.2")?;
    opte0.fw_allow_all()?;

    // Add a host route to the underlay address of opte0, through the link local
    // address of sim0 as a nexthop through sim1. This is facilitating the flow
    // of traffic from opte1 to opte0. When a packet enters opte1 (from vopte1)
    // destined for 10.0.0.1, opte will look up the v2p mapping which points to
    // fd47::1. That is the underlay address of opte0. The route below says:
    // that address is reachable through the sim1 interface, with a nexthop of
    // the sim0 interface. In the diagram above, that is the "upward" direction
    // of our simnet underlay loopback. The xde device uses the kernel's routing
    // tables to determine which underlay device to use. With this route in
    // place, packets going to the underlay address of opte0, will always go in
    // sim1 and out sim0.
    println!("adding underlay route 0");
    let _r0 = RouteV6::new(opte0.underlay_ip(), 64, ll0.ip, Some(sim.end_b))?;

    // Create the second OPTE port with the provided overlay/underlay parameters.
    let opte1 =
        OptePort::new("opte1", "10.0.0.2", "a8:40:25:ff:00:02", "fd74::1")?;
    opte1.add_router_entry("10.0.0.1")?;
    opte1.fw_allow_all()?;

    // See the comment for _r0 above. This is doing the same thing, but in
    // reverse to create the "downward" direction of the simnet underlay
    // loopback.
    println!("adding underlay route 1");
    let _r1 = RouteV6::new(opte1.underlay_ip(), 64, ll1.ip, Some(sim.end_a))?;

    // Create a few vnics atop our OPTE devices.
    let vopte0 = Vnic::with_mac("vopte0", "opte0", opte0.mac())?;
    let vopte1 = Vnic::with_mac("vopte1", "opte1", opte1.mac())?;

    // Set up a zfs pool for our test zones.
    let zfs = Zfs::new("opte2node")?;

    // Create a pair of zones to simulate our VM instances.
    println!("start zone a");
    let a = OpteZone::new("a", &zfs, &[&vopte0.name])?;
    println!("start zone b");
    let b = OpteZone::new("b", &zfs, &[&vopte1.name])?;

    println!("setup zone a");
    a.setup(&vopte0.name, opte0.ip())?;

    println!("setup zone b");
    b.setup(&vopte1.name, opte1.ip())?;

    // Now we should be able to ping b from a on the overlay.
    a.zone.zexec(&format!("ping {}", opte1.ip()))?;

    Ok(())
}

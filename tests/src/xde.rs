use anyhow::Result;
use opteadm::OpteAdm;
use oxide_vpc::api::{
    AddRouterEntryReq, Address, BoundaryServices, Direction, Filters,
    FirewallAction, FirewallRule, IpCfg, IpCidr, Ipv4Cfg, PhysNet, Ports,
    RouterTarget, SNat4Cfg, SetVirt2PhysReq, Vni, VpcCfg,
};
use ztest::*;

struct OpteZone<'a> {
    _zfs: &'a Zfs,
    zone: Zone,
}

impl<'a> OpteZone<'a> {
    fn new(name: &str, zfs: &'a Zfs, ifx: &[&'a str]) -> Result<Self> {
        let zone = Zone::new(name, zfs, ifx)?;
        Ok(Self { _zfs: zfs, zone })
    }

    fn setup(&self, devname: &str, addr: String) -> Result<()> {
        self.zone.wait_for_network()?;
        self.zone
            .zexec(&format!("ipadm create-addr -t -T dhcp {}/test", devname))?;
        self.zone.zexec(&format!("route add -iface 10.0.0.254 {}", addr))?;
        self.zone.zexec("route add 10.0.0.0/24 10.0.0.254")?;
        Ok(())
    }
}

struct OpteDev {
    name: String,
    cfg: VpcCfg,
}

impl OpteDev {
    fn set_xde_underlay(dev0: &str, dev1: &str) -> Result<()> {
        let adm = OpteAdm::open(OpteAdm::XDE_CTL)?;
        adm.set_xde_underlay(dev0, dev1)?;
        Ok(())
    }

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
        Ok(OpteDev { name: name.into(), cfg })
    }

    fn add_router_entry(&self, dest: &str) -> Result<()> {
        let adm = OpteAdm::open(OpteAdm::XDE_CTL)?;
        adm.add_router_entry(&AddRouterEntryReq {
            port_name: self.name.clone(),
            dest: IpCidr::Ip4(format!("{}/32", dest).parse().unwrap()),
            target: RouterTarget::Ip(dest.parse().unwrap()),
        })?;
        Ok(())
    }

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

    fn mac(&self) -> [u8; 6] {
        self.cfg.guest_mac.bytes()
    }

    fn ip(&self) -> String {
        match &self.cfg.ip_cfg {
            IpCfg::Ipv4(cfg) => cfg.private_ip.to_string(),
            _ => panic!("expected ipv4 gueset"),
        }
    }

    fn underlay_ip(&self) -> std::net::Ipv6Addr {
        self.cfg.phys_ip.into()
    }
}

impl Drop for OpteDev {
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

#[test]
fn test_xde_loopback() -> Result<()> {
    // This is an xde loopback topology. There are two zones, each with a vnic
    // sitting atop an opte device. The opte device uses a pair of simnet
    // devices as underlay links. These simnet devices are connected to each
    // other.
    //
    //         zone a
    //     #============#                *------*
    //     | *--------* |            +---| sim0 |
    //     | | vopte0 |----+         |   *------*
    //     | *--------* |  |         |        |
    //     #============#  |   *-------*      |
    //                     +---| opte0 |      |
    //     #============#  |   *-------*      |
    //     | *--------* |  |         |        |
    //     | | vopte1 |----+         |   *------*
    //     | *--------* |            +---| sim1 |
    //     #============#                *------*
    //         zone b
    //
    // The following system of overlay/underlay routes is set up
    //
    // 10.0.0.1 -> fd47::/74 via sim1
    // 10.0.0.2 -> fd74::/74 via sim0
    //
    // Zone a has an overlay address of 10.0.0.1 and zone b has an overlay
    // address of 10.0.0.2. This means that OPTE will encap/decap packets to
    // and from the vopte devices, the underlying routes on the host will lead
    // xde to select the correct simnet device. Then the simnet setup will
    // forward the packet to it's adjacent peer, which then makes it's way back
    // to OPTE and then to the adjacent vopte device. This is a nice little
    // sanity checker to make sure basic opte/xde functionality is working - and
    // that we're not hitting things like debug asserts in the OS.

    let sim = SimnetLink::new("sim0", "sim1")?;
    let ll0 = LinkLocal::new(&sim.end_a, "ll")?;
    let ll1 = LinkLocal::new(&sim.end_b, "ll")?;

    OpteDev::set_xde_underlay(&sim.end_a, &sim.end_b)?;

    OpteDev::set_v2p("10.0.0.1", "a8:40:25:ff:00:01", "fd47::1")?;
    OpteDev::set_v2p("10.0.0.2", "a8:40:25:ff:00:02", "fd74::1")?;

    let opte0 =
        OpteDev::new("opte0", "10.0.0.1", "a8:40:25:ff:00:01", "fd47::1")?;
    opte0.add_router_entry("10.0.0.2")?;
    opte0.fw_allow_all()?;

    println!("adding underlay route 0");
    let _r0 = RouteV6::new(opte0.underlay_ip(), 64, ll0.ip, Some(sim.end_b))?;

    let opte1 =
        OpteDev::new("opte1", "10.0.0.2", "a8:40:25:ff:00:02", "fd74::1")?;
    opte1.add_router_entry("10.0.0.1")?;
    opte1.fw_allow_all()?;

    println!("adding underlay route 1");
    let _r1 = RouteV6::new(opte1.underlay_ip(), 64, ll1.ip, Some(sim.end_a))?;

    let vopte0 = Vnic::with_mac("vopte0", "opte0", opte0.mac())?;
    let vopte1 = Vnic::with_mac("vopte1", "opte1", opte1.mac())?;

    let zfs = Zfs::new("opte2node")?;

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

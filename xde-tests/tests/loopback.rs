// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

use anyhow::Result;
use opte_ioctl::OpteHdl;
use oxide_vpc::api::ClearVirt2PhysReq;
use oxide_vpc::api::Ipv4Addr;
use oxide_vpc::api::Ipv6Addr;
use oxide_vpc::api::MacAddr;
use oxide_vpc::api::PhysNet;
use oxide_vpc::api::SetVirt2PhysReq;
use oxide_vpc::api::Vni;
use xde_tests::TEST_VPC_VNI;

#[test]
fn test_xde_loopback() -> Result<()> {
    let mut topol = xde_tests::two_node_topology()?;

    // Now we should be able to ping b from a on the overlay.
    _ = &topol.nodes[0]
        .zone
        .zone
        .zexec(&format!("ping {}", topol.nodes[1].port.ip()))?;

    let hdl = OpteHdl::open()?;

    // A clear request sent with an outdated underlay address for node b must
    // leave b's mapping intact and keep b reachable.
    let peer: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_phys: Ipv6Addr = "fd77::1".parse().unwrap();
    hdl.clear_v2p(&ClearVirt2PhysReq {
        vip: peer.into(),
        phys: phys("a8:40:25:ff:00:02", "fd99::1"),
    })?;
    assert_eq!(v2p_lookup(&hdl, peer)?, Some(peer_phys));
    let ping = topol.nodes[0].command(&format!("ping {peer}")).output()?;
    assert!(ping.status.success(), "ping {peer} failed: {ping:?}");

    // Map node a's VIP to another sled, like Nexus does after a migration,
    // and then tear down a's port.
    let vip: Ipv4Addr = "10.0.0.1".parse().unwrap();
    let moved = phys("a8:40:25:ff:00:01", "fd99::1");
    hdl.set_v2p(&SetVirt2PhysReq { vip: vip.into(), phys: moved })?;

    let node = topol.nodes.remove(0);
    let port_name = node.port.name().to_string();
    drop(node);

    let ports = hdl.list_ports()?.ports;
    let found = v2p_lookup(&hdl, vip)?;
    hdl.clear_v2p(&ClearVirt2PhysReq { vip: vip.into(), phys: moved })?;

    assert!(
        ports.iter().all(|p| p.name != port_name),
        "{port_name} still present after teardown: {ports:?}"
    );
    assert_eq!(found, Some(moved.ip));

    Ok(())
}

fn phys(ether: &str, ip: &str) -> PhysNet {
    PhysNet {
        ether: ether.parse::<MacAddr>().unwrap(),
        ip: ip.parse::<Ipv6Addr>().unwrap(),
        vni: Vni::new(TEST_VPC_VNI).unwrap(),
    }
}

fn v2p_lookup(hdl: &OpteHdl, vip: Ipv4Addr) -> Result<Option<Ipv6Addr>> {
    let vni = Vni::new(TEST_VPC_VNI)?;
    Ok(hdl
        .dump_v2p()?
        .mappings
        .into_iter()
        .filter(|m| m.vni == vni)
        .flat_map(|m| m.ip4)
        .find(|(ip, _)| *ip == vip)
        .map(|(_, guest_phys)| guest_phys.ip))
}

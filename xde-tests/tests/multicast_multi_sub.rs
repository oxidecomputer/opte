// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! XDE multicast multiple subscriber tests.

use anyhow::Context;
use anyhow::Result;
use opte_ioctl::OpteHdl;
use opte_test_utils::geneve_verify;
use oxide_vpc::api::DEFAULT_MULTICAST_VNI;
use oxide_vpc::api::IpCidr;
use oxide_vpc::api::Ipv4Addr;
use oxide_vpc::api::Ipv6Addr;
use oxide_vpc::api::NextHopV6;
use oxide_vpc::api::Replication;
use oxide_vpc::api::Vni;
use std::time::Duration;
use xde_tests::MulticastGroup;
use xde_tests::SnoopGuard;

#[test]
fn test_multicast_multiple_local_subscribers() -> Result<()> {
    // Create 3-node topology to test local fanout
    let topol = xde_tests::three_node_topology_named(
        "omicron1", "mlsa", "mlsb", "mlsc",
    )?;

    // IPv4 multicast group: 224.1.2.3
    let mcast_group = Ipv4Addr::from([224, 1, 2, 3]);
    const MCAST_PORT: u16 = 9999;
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    // M2P mapping - use admin-scoped IPv6 multicast per Omicron constraints
    let mcast_underlay = Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 3,
    ]);

    // Set up multicast state with automatic cleanup on drop
    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay, vni)?;

    // Node B's underlay address for forwarding
    let node_b_underlay = Ipv6Addr::from([
        0xfd, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
    ]);

    // Set up multicast forwarding with External replication
    // This will deliver to all local subscribers in the same VNI
    mcast.set_forwarding(vec![(
        NextHopV6::new(node_b_underlay, vni),
        Replication::External,
    )])?;

    // Allow IPv4 multicast traffic via Multicast target and subscribe to the group
    let mcast_cidr = IpCidr::Ip4("224.0.0.0/4".parse().unwrap());
    for node in &topol.nodes {
        node.port.add_multicast_router_entry(mcast_cidr)?;
        node.port.subscribe_multicast(mcast_group.into())?;
    }

    // Start snoops on nodes B and C using SnoopGuard
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let dev_name_c = topol.nodes[2].port.name().to_string();
    let filter = format!("udp and ip dst {mcast_group} and port {MCAST_PORT}");

    let mut snoop_b = SnoopGuard::start(&dev_name_b, &filter)?;
    let mut snoop_c = SnoopGuard::start(&dev_name_c, &filter)?;

    // Also snoop underlay to verify NO underlay forwarding with External mode
    let underlay_dev = "xde_test_sim1";
    let mut snoop_underlay =
        SnoopGuard::start(underlay_dev, "ip6 and udp port 6081")?;

    // Send multicast packet from node A
    let payload = "fanout test";
    let send_cmd =
        format!("echo '{payload}' | nc -u -w1 {mcast_group} {MCAST_PORT}");
    topol.nodes[0]
        .zone
        .zone
        .zexec(&send_cmd)
        .context("Failed to send multicast UDP packet")?;

    // Wait for both snoops to capture packets
    let snoop_output_b = snoop_b
        .wait_with_timeout(Duration::from_secs(5))
        .context("Timeout waiting for snoop on node B")?;
    let snoop_output_c = snoop_c
        .wait_with_timeout(Duration::from_secs(5))
        .context("Timeout waiting for snoop on node C")?;

    // Verify both nodes received the packet
    let stdout_b = String::from_utf8_lossy(&snoop_output_b.stdout);
    assert!(
        snoop_output_b.status.success() && stdout_b.contains("UDP"),
        "Expected to capture multicast UDP packet on node B, snoop output:\n{stdout_b}"
    );

    let stdout_c = String::from_utf8_lossy(&snoop_output_c.stdout);
    assert!(
        snoop_output_c.status.success() && stdout_c.contains("UDP"),
        "Expected to capture multicast UDP packet on node C, snoop output:\n{stdout_c}"
    );

    // Verify NO underlay forwarding (External mode = local-only)
    if let Ok(output) = snoop_underlay.wait_with_timeout(Duration::from_secs(2))
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "External mode should NOT forward to underlay, but captured:\n{stdout}"
        );
    }

    Ok(())
}

#[test]
fn test_multicast_underlay_replication() -> Result<()> {
    // Create 2-node topology to test Underlay replication mode
    let topol = xde_tests::two_node_topology_named("omicron1", "ura", "urb")?;

    // IPv4 multicast group
    let mcast_group = Ipv4Addr::from([224, 1, 2, 4]);
    const MCAST_PORT: u16 = 9999;
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    // M2P mapping - use admin-scoped IPv6 multicast per Omicron constraints
    let mcast_underlay = Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 4,
    ]);

    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay, vni)?;

    // Debug: dump V2P/M2P mappings to verify M2P is set correctly
    let hdl = OpteHdl::open()?;
    let v2p_dump = hdl.dump_v2p()?;
    println!("\n=== V2P/M2P Mappings ===");
    for vpc_map in &v2p_dump.mappings {
        println!("  VNI {}: ", vpc_map.vni.as_u32());
        println!("    Unicast IPv4 mappings: {:?}", vpc_map.ip4);
        println!("    Multicast IPv4 mappings: {:?}", vpc_map.mcast_ip4);
        println!("    Multicast IPv6 mappings: {:?}", vpc_map.mcast_ip6);
    }
    println!("=== End V2P/M2P Mappings ===\n");

    // Node B's underlay address
    let node_b_underlay = Ipv6Addr::from([
        0xfd, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
    ]);

    // Set up multicast forwarding with Underlay replication ONLY
    // This should forward to underlay but NOT deliver to local ports
    mcast.set_forwarding(vec![(
        NextHopV6::new(node_b_underlay, vni),
        Replication::Underlay,
    )])?;

    // Allow IPv4 multicast traffic via Multicast target
    //
    // Note: We deliberately do NOT subscribe any nodes to verify that Underlay mode
    // forwards to underlay regardless of local subscription state (zero subscribers)
    let mcast_cidr = IpCidr::Ip4("224.0.0.0/4".parse().unwrap());
    for node in &topol.nodes {
        node.port.add_multicast_router_entry(mcast_cidr)?;
    }

    // Add IPv6 multicast route for admin-scoped multicast (ff04::/16)
    // This tells the kernel to route multicast packets through the underlay interface
    let route_add_result = std::process::Command::new("pfexec")
        .args(&[
            "route",
            "add",
            "-inet6",
            "ff04::/16",
            "-interface",
            "xde_test_vnic0",
        ])
        .output()
        .context("Failed to add IPv6 multicast route")?;
    if !route_add_result.status.success() {
        println!(
            "Warning: Failed to add IPv6 multicast route: {}",
            String::from_utf8_lossy(&route_add_result.stderr)
        );
    }

    // Start snoop on the UNDERLAY simnet device (not the OPTE port)
    // to verify the packet is forwarded to the underlay
    let underlay_dev = "xde_test_sim1"; // Underlay device
    let mut snoop_underlay =
        SnoopGuard::start(underlay_dev, "ip6 and udp port 6081")?; // Geneve port

    // Debug: dump forwarding table to verify configuration
    let mfwd = hdl.dump_mcast_fwd()?;
    println!("\n=== Multicast forwarding table (Underlay test) ===");
    for entry in &mfwd.entries {
        println!(
            "  Group: {:?}, Next hops: {:?}",
            entry.group, entry.next_hops
        );
    }

    // Also snoop node B's OPTE port to verify NO local delivery with Underlay mode
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let filter_local =
        format!("udp and ip dst {mcast_group} and port {MCAST_PORT}");
    let mut snoop_local = SnoopGuard::start(&dev_name_b, &filter_local)?;

    // Clear UFT right before sending to ensure fresh flow computation
    hdl.clear_uft(topol.nodes[0].port.name())?;

    // Send multicast packet from node A
    let payload = "underlay test";
    let send_cmd =
        format!("echo '{payload}' | nc -u -w1 {mcast_group} {MCAST_PORT}");
    topol.nodes[0]
        .zone
        .zone
        .zexec(&send_cmd)
        .context("Failed to send multicast UDP packet")?;

    // Wait for snoop to capture the underlay packet
    let snoop_output_underlay = snoop_underlay
        .wait_with_timeout(Duration::from_secs(5))
        .context("Timeout waiting for snoop on underlay")?;

    // Verify packet was forwarded to underlay
    let stdout_underlay =
        String::from_utf8_lossy(&snoop_output_underlay.stdout);

    assert!(
        snoop_output_underlay.status.success()
            && stdout_underlay.contains("UDP"),
        "Expected to capture Geneve packet on underlay, snoop output:\n{stdout_underlay}"
    );

    // Verify Geneve header fields (VNI, outer IPv6 dst, replication mode)
    let hex_str = geneve_verify::extract_snoop_hex(&stdout_underlay)
        .expect("Failed to extract hex from snoop output");

    let packet_bytes = geneve_verify::parse_snoop_hex(&hex_str)
        .expect("Failed to parse hex string");

    let geneve_info = geneve_verify::parse_geneve_packet(&packet_bytes)
        .expect("Failed to parse Geneve packet");

    assert_eq!(
        geneve_info.vni, vni,
        "Geneve VNI should be DEFAULT_MULTICAST_VNI ({})",
        DEFAULT_MULTICAST_VNI
    );
    assert_eq!(
        geneve_info.outer_ipv6_dst, mcast_underlay,
        "Outer IPv6 dst should be multicast underlay address"
    );
    assert_eq!(
        geneve_info.replication,
        Some(Replication::Underlay),
        "Geneve replication mode should be Underlay"
    );

    // Verify NO local delivery (Underlay mode = remote-only)
    if let Ok(output) = snoop_local.wait_with_timeout(Duration::from_secs(2)) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "Underlay mode should NOT deliver locally, but captured:\n{stdout}"
        );
    }

    Ok(())
}

#[test]
fn test_multicast_all_replication() -> Result<()> {
    // Create 3-node topology to test All replication mode (bifurcated delivery)
    let topol =
        xde_tests::three_node_topology_named("omicron1", "ara", "arb", "arc")?;

    // IPv4 multicast group
    let mcast_group = Ipv4Addr::from([224, 1, 2, 5]);
    const MCAST_PORT: u16 = 9999;
    let vni = Vni::new(DEFAULT_MULTICAST_VNI)?;

    // M2P mapping - use admin-scoped IPv6 multicast per Omicron constraints
    let mcast_underlay = Ipv6Addr::from([
        0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        224, 1, 2, 5,
    ]);

    let mcast = MulticastGroup::new(mcast_group.into(), mcast_underlay, vni)?;

    // Node B's underlay address for underlay forwarding
    let node_b_underlay = Ipv6Addr::from([
        0xfd, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
    ]);

    // Set up multicast forwarding with All replication
    // This should deliver BOTH to local subscribers AND forward to underlay
    mcast.set_forwarding(vec![(
        NextHopV6::new(node_b_underlay, vni),
        Replication::All,
    )])?;

    // Allow IPv4 multicast traffic via Multicast target and subscribe to the group
    let mcast_cidr = IpCidr::Ip4("224.0.0.0/4".parse().unwrap());
    for node in &topol.nodes {
        node.port.add_multicast_router_entry(mcast_cidr)?;
        node.port.subscribe_multicast(mcast_group.into())?;
    }

    // Start snoop on node B (local delivery) and underlay (underlay forwarding)
    let dev_name_b = topol.nodes[1].port.name().to_string();
    let filter_local =
        format!("udp and ip dst {mcast_group} and port {MCAST_PORT}");
    let mut snoop_local = SnoopGuard::start(&dev_name_b, &filter_local)?;

    let underlay_dev = "xde_test_sim1";
    let mut snoop_underlay =
        SnoopGuard::start(underlay_dev, "ip6 and udp port 6081")?;

    // Send multicast packet from node A
    let payload = "all replication test";
    let send_cmd =
        format!("echo '{payload}' | nc -u -w1 {mcast_group} {MCAST_PORT}");
    topol.nodes[0]
        .zone
        .zone
        .zexec(&send_cmd)
        .context("Failed to send multicast UDP packet")?;

    // Wait for both snoops to capture packets
    let snoop_output_local = snoop_local
        .wait_with_timeout(Duration::from_secs(5))
        .context("Timeout waiting for local delivery snoop")?;
    let snoop_output_underlay = snoop_underlay
        .wait_with_timeout(Duration::from_secs(5))
        .context("Timeout waiting for underlay snoop")?;

    // Verify local delivery happened
    let stdout_local = String::from_utf8_lossy(&snoop_output_local.stdout);
    assert!(
        snoop_output_local.status.success() && stdout_local.contains("UDP"),
        "Expected local delivery to node B, snoop output:\n{stdout_local}"
    );

    // Verify underlay forwarding happened
    let stdout_underlay =
        String::from_utf8_lossy(&snoop_output_underlay.stdout);
    assert!(
        snoop_output_underlay.status.success()
            && stdout_underlay.contains("UDP"),
        "Expected underlay forwarding, snoop output:\n{stdout_underlay}"
    );

    Ok(())
}

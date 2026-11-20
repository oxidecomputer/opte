// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Basic tests that we can manipulate port state.

use anyhow::Context as _;
use anyhow::Result;
use opte_ioctl::InnerFlowId;
use opte_ioctl::OpteHdl;
use opte_test_utils::Ipv4Addr;
use opte_test_utils::Protocol;
use oxide_vpc::api::AddrPair;
use oxide_vpc::api::L4Info;
use oxide_vpc::api::PortState;

fn port_state(port_name: &str) -> Result<PortState> {
    OpteHdl::open()
        .context("opening OPTE handle")?
        .state(port_name)
        .context("getting OPTE port state")
        .map(|r| r.state)
}

fn pause(port_name: &str) -> Result<()> {
    OpteHdl::open()
        .context("opening OPTE handle")?
        .pause(port_name)
        .context("pausing port")
        .map(|_| ())
}

fn reset(port_name: &str) -> Result<()> {
    OpteHdl::open()
        .context("opening OPTE handle")?
        .reset(port_name)
        .context("resetting port")
        .map(|_| ())
}

fn resume(port_name: &str) -> Result<()> {
    OpteHdl::open()
        .context("opening OPTE handle")?
        .resume(port_name)
        .context("resuming port")
        .map(|_| ())
}

struct LayerFlows {
    ft_in: Vec<InnerFlowId>,
    ft_out: Vec<InnerFlowId>,
}

fn layer_flows(port_name: &str, layer: &str) -> Result<LayerFlows> {
    OpteHdl::open()
        .context("opening OPTE handle")?
        .dump_layer(port_name, layer)
        .with_context(|| format!("dumping {layer} layer"))
        .map(|r| LayerFlows {
            ft_in: r.ft_in.into_iter().map(|(f, _)| f).collect(),
            ft_out: r.ft_out.into_iter().map(|(f, _)| f).collect(),
        })
}

/// Which side of the flow-table entry we're searching for in tests below.
#[derive(Clone, Copy, Debug)]
enum Orientation {
    /// The way the packet is sent.
    ///
    /// Check the source IP / port against the flow's source, and the
    /// destination IP / port against the flow's destination.
    Forward,
    /// The other way.
    ///
    /// Check the destination IP / port against the flow's source, and the
    /// source IP / port against the flow's destination.
    Backward,
}

/// Return `true` if `flow` has one half of a stateful pair with the provided
/// addresses.
fn has_udp_pair_half(
    flow: &InnerFlowId,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    orientation: Orientation,
) -> bool {
    let AddrPair::V4 { src, dst } = flow.addrs else {
        return false;
    };
    if Protocol::from(flow.proto) != Protocol::UDP {
        return false;
    };
    let Some(L4Info::Ports(ports)) = flow.l4_info() else {
        return false;
    };
    match orientation {
        Orientation::Forward => {
            src == src_ip && dst == dst_ip && ports.dst_port == dst_port
        }
        Orientation::Backward => {
            src == dst_ip && dst == src_ip && ports.src_port == dst_port
        }
    }
}

fn has_udp_pair(
    forward_flows: &[InnerFlowId],
    backward_flows: &[InnerFlowId],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> (bool, bool) {
    let check = |flows: &[InnerFlowId], ori| {
        flows
            .iter()
            .any(|flow| has_udp_pair_half(flow, src_ip, dst_ip, dst_port, ori))
    };
    (
        check(forward_flows, Orientation::Forward),
        check(backward_flows, Orientation::Backward),
    )
}

// Smoke test that we can manipulate port state through the ioctls, and that the
// state / flows updates appropriately.
#[test]
fn can_manipulate_port_state() -> Result<()> {
    let topology = xde_tests::two_node_topology()?;

    // State for both ports should be running now.
    let states: Vec<_> = topology
        .nodes
        .iter()
        .map(|node| port_state(node.port.name()).unwrap())
        .collect();
    assert_eq!(states.len(), topology.nodes.len());
    assert!(
        states.iter().all(|s| matches!(s, PortState::Running)),
        "All ports should be running"
    );

    // Send some packets between them, and check that the dynamic state like
    // flow tables has been updated.
    let src_node = &topology.nodes[0];
    let dst_node = &topology.nodes[1];
    let src_ip = src_node.port.ip();
    let dst_ip = dst_node.port.ip();
    const SUCCESSFUL_DST_PORT: u16 = 10000;
    const FAILED_DST_PORT: u16 = 10001;
    const RESUMED_DST_PORT: u16 = 10002;
    src_node
        .zone
        .send_udp_v4(src_ip, dst_ip, SUCCESSFUL_DST_PORT, "some data")
        .expect("able to send a UDP packet from src to dst zones");

    // Check that the sending zone and receiving zone both have an entry for the
    // packet. The orientations should be reversed, but it should be in both.
    let src_flows = layer_flows(src_node.port.name(), "firewall").unwrap();
    let dst_flows = layer_flows(dst_node.port.name(), "firewall").unwrap();
    assert_eq!(
        has_udp_pair(
            &src_flows.ft_out,
            &src_flows.ft_in,
            src_ip,
            dst_ip,
            SUCCESSFUL_DST_PORT,
        ),
        (true, true),
        "Sending port should have both an inbound and outbound \
        firewall flow-table entry for the UDP packet we just sent"
    );
    assert_eq!(
        has_udp_pair(
            &dst_flows.ft_in,
            &dst_flows.ft_out,
            src_ip,
            dst_ip,
            SUCCESSFUL_DST_PORT
        ),
        (true, true),
        "Receiving port should have both an inbound and outbound \
        firewall flow-table entry for the UDP packet we just sent"
    );

    // Pause one port, and confirm that attempting to send drops the packet.
    pause(src_node.port.name()).unwrap();
    assert_eq!(port_state(src_node.port.name()).unwrap(), PortState::Paused);
    src_node
        .zone
        .send_udp_v4(src_ip, dst_ip, FAILED_DST_PORT, "some data")
        .expect("able to send a UDP packet from src to dst zones");
    let src_flows = layer_flows(src_node.port.name(), "firewall").unwrap();
    let dst_flows = layer_flows(dst_node.port.name(), "firewall").unwrap();
    assert_eq!(
        has_udp_pair(
            &src_flows.ft_out,
            &src_flows.ft_in,
            src_ip,
            dst_ip,
            FAILED_DST_PORT,
        ),
        (false, false),
        "Sending port should have no firewall flow-table entries \
        for a packet sent after it was paused."
    );
    assert_eq!(
        has_udp_pair(
            &dst_flows.ft_in,
            &dst_flows.ft_out,
            src_ip,
            dst_ip,
            FAILED_DST_PORT,
        ),
        (false, false),
        "Receiving port should have no firewall flow-table entries. \
        Its partner is paused and cannot send traffic."
    );

    // Sanity check that we can pause an already-paused port.
    assert!(
        pause(src_node.port.name()).is_ok(),
        "Pausing a paused port should be a no-op",
    );

    // Reset the source port, and confirm that all state is gone.
    reset(src_node.port.name()).unwrap();
    assert_eq!(port_state(src_node.port.name()).unwrap(), PortState::Ready);
    let src_flows = layer_flows(src_node.port.name(), "firewall").unwrap();
    assert!(src_flows.ft_in.is_empty());
    assert!(src_flows.ft_out.is_empty());
    assert!(
        pause(src_node.port.name()).is_err(),
        "Should not be able to pause a port we just reset",
    );

    // Resume the port, and assert that it can send traffic again.
    resume(src_node.port.name()).unwrap();
    assert_eq!(port_state(src_node.port.name()).unwrap(), PortState::Running);
    src_node
        .zone
        .send_udp_v4(src_ip, dst_ip, RESUMED_DST_PORT, "some data")
        .expect("able to send a UDP packet from src to dst zones");
    let src_flows = layer_flows(src_node.port.name(), "firewall").unwrap();
    let dst_flows = layer_flows(dst_node.port.name(), "firewall").unwrap();
    assert_eq!(
        has_udp_pair(
            &src_flows.ft_out,
            &src_flows.ft_in,
            src_ip,
            dst_ip,
            RESUMED_DST_PORT,
        ),
        (true, true),
        "Sending port should have firewall flow-table entries \
        again after resuming the port"
    );
    assert_eq!(
        has_udp_pair(
            &dst_flows.ft_in,
            &dst_flows.ft_out,
            src_ip,
            dst_ip,
            RESUMED_DST_PORT,
        ),
        (true, true),
        "Receiving port should have firewall flow-table entries \
        again after resuming the port"
    );

    // Resuming multiple times is fine.
    resume(src_node.port.name()).expect("Should be able to resume() anytime");

    Ok(())
}

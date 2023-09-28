use anyhow::Result;

#[test]
fn test_xde_loopback() -> Result<()> {
    let topol = xde_tests::two_node_topology()?;

    // Now we should be able to ping b from a on the overlay.
    &topol.nodes[0]
        .zone
        .zone
        .zexec(&format!("ping {}", &topol.nodes[1].port.ip()))?;

    Ok(())
}

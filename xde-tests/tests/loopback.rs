// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use anyhow::Result;

#[test]
fn test_xde_loopback() -> Result<()> {
    let topol = xde_tests::two_node_topology()?;

    // Now we should be able to ping b from a on the overlay.
    _ = &topol.nodes[0]
        .zone
        .zone
        .zexec(&format!("ping {}", &topol.nodes[1].port.ip()))?;

    Ok(())
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

use anyhow::Result;
use anyhow::anyhow;
use std::process::Command;

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=../../.git/HEAD");

    let commit_count_out =
        Command::new("git").args(["rev-list", "--count", "HEAD"]).output()?;

    if commit_count_out.status.success() {
        let commit_count: u64 =
            std::str::from_utf8(&commit_count_out.stdout)?.trim().parse()?;

        std::fs::write(
            std::env::var("OUT_DIR").unwrap() + "/gen.rs",
            format!(
                "\
// This file is autogenerated by build.rs -- do not edit!

/// Number of git commits present at build time, used for OPTE versioning.
pub const COMMIT_COUNT: u64 = {commit_count};
"
            ),
        )?;

        Ok(())
    } else {
        let utf8_err = std::str::from_utf8(&commit_count_out.stderr).ok();
        Err(anyhow!("Git commit count was unsuccessful: {utf8_err:?}"))
    }
}

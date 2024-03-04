// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Utilities used in `cargo kbench`.

use anyhow::Result;
use serde::Deserialize;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;
use workload::IperfConfig;

pub mod measurement;
pub mod remote;
pub mod workload;

/// Blocks until a user types the phrase 'exit' on Stdin.
pub fn loop_til_exit() {
    let mut cmd = String::new();
    loop {
        match std::io::stdin().read_line(&mut cmd) {
            Ok(_) if &cmd == "exit\n" => {
                break;
            }
            Ok(_) => {
                println!("wanted exit: saw {cmd:?}");
                cmd.clear();
            }
            _ => {
                break;
            }
        }
    }
}

/// Ensure the current process is running as root, or elevate using
/// pfexec if needed.
pub fn elevate() -> Result<()> {
    if nix::unistd::Uid::current().is_root() {
        Ok(())
    } else {
        let my_args = std::env::args();
        let mut elevated = Command::new("pfexec").args(my_args).spawn()?;
        let exit_code = elevated.wait()?;
        std::process::exit(exit_code.code().unwrap_or(1))
    }
}

/// Print the given multiline string as a formatted box of text.
pub fn print_banner(text: &str) {
    let max_len = text.lines().map(str::len).max().unwrap_or_default();

    println!("###{:->max_len$}###", "");
    for line in text.lines() {
        println!(":::{line:^max_len$}:::");
    }
    println!("###{:->max_len$}###", "");
}

/// Chown a directory to the original user before pfexec was used (which is
/// unchanged in the env_var USER).
pub fn give_ownership() -> Result<()> {
    let Ok(user) = std::env::var("USER") else { return Ok(()) };

    let criterion_path = cargo_target_directory()
        .unwrap_or_else(|| Path::new(".").to_path_buf())
        .join("criterion");
    let outputs = [output_base_dir(), criterion_path.as_path()];

    for path in outputs {
        let _ = Command::new("chown").args(["-R", &user]).arg(path).output()?;
    }

    Ok(())
}

/// Configures where outputs are stored under various run modes.
#[derive(Debug, Clone)]
pub enum OutputConfig<'a> {
    Iperf(&'a IperfConfig),
    InSitu(&'a str),
}

impl OutputConfig<'_> {
    /// Name of an experiment, used for storing different workloads
    /// and measurement types in distinct directories.
    pub fn benchmark_group(&self) -> String {
        match self {
            Self::Iperf(i) => i.benchmark_group(),
            Self::InSitu(s) => format!("in-situ/{s}"),
        }
    }

    /// Title to use in a flamegraph built from a set of measurements.
    pub fn title(&self) -> String {
        match self {
            Self::Iperf(i) => i.title(),
            Self::InSitu(s) => format!("Local flamegraph -- {s}"),
        }
    }
}

impl<'a> From<&'a IperfConfig> for OutputConfig<'a> {
    fn from(value: &'a IperfConfig) -> Self {
        Self::Iperf(value)
    }
}

// XXX: lifted verbatim from criterion
/// Returns the Cargo target directory, possibly calling `cargo metadata` to
/// figure it out.
pub fn cargo_target_directory() -> Option<PathBuf> {
    #[derive(Deserialize)]
    struct Metadata {
        target_directory: PathBuf,
    }

    std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from).or_else(|| {
        let output = Command::new(std::env::var_os("CARGO")?)
            .args(["metadata", "--format-version", "1"])
            .output()
            .ok()?;
        let metadata: Metadata = serde_json::from_slice(&output.stdout).ok()?;
        Some(metadata.target_directory)
    })
}

pub static OUT_DIR: OnceLock<PathBuf> = OnceLock::new();

pub fn output_base_dir() -> &'static Path {
    OUT_DIR
        .get_or_init(|| {
            let mut out = cargo_target_directory()
                .unwrap_or_else(|| Path::new(".").to_path_buf());
            out.push("xde-bench");
            out
        })
        .as_path()
}

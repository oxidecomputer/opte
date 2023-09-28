// What do we need?

// Config modes:
// - Spin up inner zone with iperf3 client.
// - Spin up (optional) local iperf3 server.
// - Spin up secondary zone with iperf3 server (VM<->VM).
//
// Do we also want to work on a rack-aware

// What do we want?
// - Run DTrace in host, focus on kernel module.
// - Export iPerf run stats, collect.

// Want topo:
/*
+--------+

*/

use anyhow::Result;
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use std::net::IpAddr;
use std::process::Command;
#[cfg(target_os = "illumos")]
use ztest::*;

#[derive(Clone, Subcommand)]
enum Experiment {
    /// Benchmark iPerf from a single zone to an existing server.
    ///
    ///
    SingleZone {
        iperf_server: IpAddr,

        /// Test.
        #[arg(short, long, value_enum, default_value_t=CreateMode::Dont)]
        passthrough: CreateMode,

        #[command(flatten)]
        _waste: IgnoredExtras,
    },
    /// Benchmark iPerf between two local zones.
    ZoneToZone {
        #[command(flatten)]
        _waste: IgnoredExtras,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum CreateMode {
    Dont,
    Do,
    DoWithPassthrough,
}

#[derive(Parser)]
#[clap(bin_name = "xde")]
struct ConfigInput {
    // Nested here in case of shared options.
    #[command(subcommand)]
    command: Experiment,
}

#[derive(Clone, Default, Parser)]
#[clap(bin_name = "xde")]
struct IgnoredExtras {
    // `cargo bench` passes in the --bench flag, we need to accept it.
    #[arg(long, hide = true)]
    bench: bool,
}

#[cfg(not(target_os = "illumos"))]
fn main() -> Result<()> {
    // Parse args etc. so that we can verify command-line functionality
    // on non-illumos hosts if needed.
    let _cfg = ConfigInput::parse();

    anyhow::bail!("This benchmark must be run on Helios!")
}

// Needed for us to just `cargo bench` easily.
fn elevate() -> Result<()> {
    let curr_user_run = Command::new("whoami").output()?;
    if !curr_user_run.status.success() {
        let as_utf = std::str::from_utf8(&curr_user_run.stderr);
        anyhow::bail!("Failed to get current user: {:?}", as_utf);
    }

    match std::str::from_utf8(&curr_user_run.stdout) {
        Ok("root\n") => Ok(()),
        Ok(_) => {
            let my_args = std::env::args();
            let mut elevated = Command::new("pfexec").args(my_args).spawn()?;
            let exit_code = elevated.wait()?;
            std::process::exit(exit_code.code().unwrap_or(1))
        }
        Err(_) => anyhow::bail!("`whoami` did not return a valid UTF user."),
    }
}

fn print_banner(text: &str) {
    let max_len = text.lines().map(str::len).max().unwrap_or_default();

    println!("###{:->max_len$}###", "");
    for line in text.lines() {
        println!(":::{line:^max_len$}:::");
    }
    println!("###{:->max_len$}###", "");
}

/// Ensure that the XDE kernel module is present.
fn ensure_xde() -> Result<()> {
    let run = Command::new("add_drv").arg("xde").output()?;

    if run.status.success() {
        Ok(())
    } else {
        let out_msg = std::str::from_utf8(&run.stderr)
            .map_err(|_| anyhow::anyhow!("Failed to parse add_drv output."))?;

        if out_msg.contains("is already installed") {
            Ok(())
        } else {
            anyhow::bail!("`add_drv xde` failed: {out_msg}")
        }
    }
}

#[cfg(target_os = "illumos")]
fn zone_to_zone() -> Result<()> {
    ensure_xde()?;

    print_banner("Building test topology... please wait! (120s)");
    let topol = xde_tests::two_node_topology()?;
    print_banner("Topology built!");

    // TODO: start expts in here.
    // WANT: json output, parsing, etc.
    //       begin dtrace in local, iperf -c in host 0.
    //       Probably want to cat all stack traces together, same for histos.
    //       RW distinction doesn't mean much here: we'll be seeing both anyhow.
    for node in &topol.nodes {
        node.zone.zone.zexec(&format!("which iperf"))?;
    }

    Ok(())
}

#[cfg(target_os = "illumos")]
fn main() -> Result<()> {
    elevate()?;

    let cfg = ConfigInput::parse();

    match cfg.command {
        Experiment::SingleZone { iperf_server: _server, .. } => todo!(),
        Experiment::ZoneToZone { .. } => zone_to_zone(),
    }
}

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

use anyhow::Result;
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use serde::Deserialize;
use std::fs;
use std::fs::File;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::OnceLock;
use std::time::Duration;
#[cfg(target_os = "illumos")]
use ztest::*;

// XXX: lifted verbatim from criterion
/// Returns the Cargo target directory, possibly calling `cargo metadata` to
/// figure it out.
fn cargo_target_directory() -> Option<PathBuf> {
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

static OUT_DIR: OnceLock<PathBuf> = OnceLock::new();
static WS_ROOT: OnceLock<PathBuf> = OnceLock::new();

fn output_base_dir() -> &'static Path {
    OUT_DIR
        .get_or_init(|| {
            let mut out = cargo_target_directory()
                .unwrap_or_else(|| Path::new(".").to_path_buf());
            out.push("xde-bench");
            out
        })
        .as_path()
}

fn ws_root() -> &'static Path {
    WS_ROOT
        .get_or_init(|| {
            let mut out = cargo_target_directory()
                .unwrap_or_else(|| Path::new(".").to_path_buf());
            out.push("..");
            out
        })
        .as_path()
}

#[derive(Clone, Subcommand)]
/// iPerf-driven benchmark harness for OPTE.
enum Experiment {
    /// Benchmark iPerf from a single zone to an existing server
    /// on another physical node.
    ///
    /// This should forward packets over a NIC:
    Remote {
        /// Listen address of an external iPerf server.
        iperf_server: IpAddr,

        /// Test.
        #[arg(short, long, value_enum, default_value_t=CreateMode::Dont)]
        opte_create: CreateMode,

        #[command(flatten)]
        _waste: IgnoredExtras,
    },
    /// Benchmark iPerf between two local zones.
    ///
    /// This will not accurately test NIC behaviour, but can be
    /// illustrative of how packet handling times fit in relative to
    /// other mac costs.
    Local {
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
    // Nested here in case of shared options, and to catch --bench.
    #[command(subcommand)]
    command: Experiment,

    #[command(flatten)]
    _waste: IgnoredExtras,
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

#[derive(Clone, Debug)]
struct DtraceOutput {
    pub stack_path: PathBuf,
    pub histo_path: PathBuf,
}

fn run_local_dtraces(out_dir: PathBuf) -> Result<(Vec<Child>, DtraceOutput)> {
    fs::create_dir_all(&out_dir)?;

    let dtraces = ws_root().join("dtrace");
    let histo_path = out_dir.join("histos.out");
    let Some(histo_path_str) = histo_path.to_str() else {
        anyhow::bail!("Illegal utf8 in histogram path.")
    };
    // dtrace -L $MYDIR/lib -I $MYDIR -Cqs $MYDIR/${script}.d
    // let histo = Command::new("./opte-trace")
    //     .args(["opte-count-cycles.d", "-o", histo_path_str])
    let histo = Command::new("dtrace")
        .args([
            "-L",
            "lib",
            "-I",
            ".",
            "-Cqs",
            "opte-count-cycles.d",
            "-o",
            histo_path_str,
        ])
        .current_dir(dtraces)
        .spawn()?;

    // pfexec dtrace -x stackframes=100 -n 'profile-201us /arg0/ { @[stack()] = count(); } tick-120s { exit(0); }' -o out.stacks
    let stack_path = out_dir.join("raw.stacks");
    let Some(stack_path_str) = stack_path.to_str() else {
        anyhow::bail!("Illegal utf8 in histogram path.")
    };
    let stack = Command::new("dtrace")
        .args([
            "-x", "stackframes=100",
            "-n",
            "profile-201us /arg0/ { @[stack()] = count(); } tick-120s { exit(0); }",
            "-o", stack_path_str,
        ])
        .spawn()?;

    Ok((vec![histo, stack], DtraceOutput { histo_path, stack_path }))
}

fn spawn_local_dtraces(
    expt_location: impl AsRef<Path>,
) -> (Sender<()>, Receiver<Result<DtraceOutput>>) {
    let (kill_tx, kill_rx) = mpsc::channel();
    let (out_tx, out_rx) = mpsc::channel();

    let expt_location = expt_location.as_ref().to_path_buf();

    std::thread::spawn(move || {
        let out_dir = output_base_dir().join(expt_location);

        out_tx.send(match run_local_dtraces(out_dir) {
            Ok((children, result)) => {
                let _ = kill_rx.recv();

                for mut child in children {
                    // child.kill();
                    println!("Interrupting...");
                    let upgrade = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(child.id() as i32),
                        nix::sys::signal::Signal::SIGINT,
                    )
                    .is_err();
                    if upgrade {
                        println!("...killing...");
                        child.kill();
                    }
                    child.wait();
                }

                Ok(result)
            }
            Err(e) => Err(e),
        });
    });

    (kill_tx, out_rx)
}

#[cfg(target_os = "illumos")]
fn zone_to_zone() -> Result<()> {
    ensure_xde()?;

    print_banner("Building test topology... please wait! (120s)");
    let topol = xde_tests::two_node_topology()?;
    print_banner("Topology built!");

    let iperf_sess = topol.nodes[1].command("iperf -s").spawn()?;
    let target_ip = topol.nodes[1].port.ip();

    // TEST FOR NOW
    let (kill, done) = spawn_local_dtraces("testtest");

    std::thread::sleep(Duration::from_secs(10));

    &topol.nodes[0]
        .zone
        .zone
        .zexec(&format!("ping {}", &topol.nodes[1].port.ip()))?;

    // TODO: start expts in here.
    // WANT: json output, parsing, etc.
    //       begin dtrace in local, iperf -c in host 0.
    //       Probably want to cat all stack traces together, same for histos.
    //       RW distinction doesn't mean much here: we'll be seeing both anyhow.
    // for node in &topol.nodes {
    //     node.zone.zone.zexec(&format!("which iperf"))?;
    // }
    // let iperf_out = topol.nodes[0].zone.zone.zexec(&format!("iperf -c {target_ip} -J"))?;
    print_banner("iPerf done...\nAwating out files...");
    let _ = kill.send(());
    println!("got: {:?}", done.recv());
    print_banner("done!");

    Ok(())
}

#[cfg(target_os = "illumos")]
fn main() -> Result<()> {
    elevate()?;

    let cfg = ConfigInput::parse();

    match cfg.command {
        Experiment::Remote { iperf_server: _server, .. } => todo!(),
        Experiment::Local { .. } => zone_to_zone(),
    }
}

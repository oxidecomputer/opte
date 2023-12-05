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
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use criterion::Criterion;
use opte_bench::dtrace::DTraceHisto;
use opte_bench::iperf::Output;
use rand::distributions::Distribution;
use rand::distributions::WeightedIndex;
use rand::thread_rng;
use rand::Rng;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::OnceLock;
use std::time::Duration;

#[cfg(not(target_os = "illumos"))]
fn main() -> Result<()> {
    // Parse args etc. so that we can verify command-line functionality
    // on non-illumos hosts if needed.
    let _cfg = ConfigInput::parse();

    anyhow::bail!("This benchmark must be run on Helios!")
}

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
        /// Only run end-of-benchmark processing.
        #[arg(short, long)]
        no_bench: bool,

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

fn check_deps() -> Result<()> {
    let dep_map = [
        ("iperf", "iperf"),
        ("stackcollapse.pl", "flamegraph"),
        ("flamegraph.pl", "flamegraph"),
    ];

    let mut missing_progs = vec![];
    let mut missing_pkgs = HashSet::new();

    for (prog, pkg) in dep_map {
        if Command::new("which")
            .arg(prog)
            .output()
            .map_err(|_| ())
            .and_then(|out| if out.status.success() { Ok(()) } else { Err(()) })
            .is_err()
        {
            missing_progs.push(prog);
            missing_pkgs.insert(pkg);
        }
    }

    if missing_progs.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(
            "Could not find program(s) [{}]: \
            check path, or 'pfexec pkg install {}'",
            missing_progs.join(", "),
            missing_pkgs.into_iter().collect::<Vec<_>>().join(" "),
        )
    }
}

#[derive(Clone, Debug)]
struct DtraceOutput {
    pub stack_path: PathBuf,
    pub histo_path: PathBuf,
    pub out_dir: PathBuf,
}

fn run_local_dtraces(out_dir: PathBuf) -> Result<(Vec<Child>, DtraceOutput)> {
    fs::create_dir_all(&out_dir)?;
    let dtraces = ws_root().join("dtrace");

    // Default dtrace behaviour here is to append; which we don't want.
    let histo_path = out_dir.join("histos.out");
    if let Err(e) = fs::remove_file(&histo_path) {
        eprintln!("Failed to remove {histo_path:?}: {e}");
    }
    let Some(histo_path_str) = histo_path.to_str() else {
        anyhow::bail!("Illegal utf8 in histogram path.")
    };
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

    // Ditto for stack tracing.
    let stack_path = out_dir.join("raw.stacks");
    if let Err(e) = fs::remove_file(&stack_path) {
        eprintln!("Failed to remove {stack_path:?}: {e}");
    }
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

    Ok((vec![histo, stack], DtraceOutput { histo_path, stack_path, out_dir }))
}

fn spawn_local_dtraces(
    expt_location: impl AsRef<Path>,
) -> (Sender<()>, Receiver<Result<DtraceOutput>>) {
    let (kill_tx, kill_rx) = mpsc::channel();
    let (out_tx, out_rx) = mpsc::channel();

    let expt_location = expt_location.as_ref().to_path_buf();

    std::thread::spawn(move || {
        let out_dir = output_base_dir().join(expt_location);

        let _ = out_tx.send(match run_local_dtraces(out_dir) {
            Ok((children, result)) => {
                let _ = kill_rx.recv();

                // Need to manually ctrl-c and await EACH process.
                for mut child in children {
                    let upgrade = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(child.id() as i32),
                        nix::sys::signal::Signal::SIGINT,
                    )
                    .is_err();
                    if upgrade {
                        println!("...killing...");
                        let _ = child.kill();
                    }
                    let _ = child.wait();
                }

                Ok(result)
            }
            Err(e) => Err(e),
        });
    });

    (kill_tx, out_rx)
}

fn build_flamegraph(
    stack_file: impl AsRef<Path>,
    out_dir: impl AsRef<Path>,
    rx_name: Option<&str>,
    tx_name: Option<&str>,
) -> Result<()> {
    let fold_path = out_dir.as_ref().join("stacks.folded");
    let fold_space = File::create(&fold_path)?;

    let stack_status = Command::new("stackcollapse.pl")
        .arg(stack_file.as_ref().as_os_str())
        .stdout(Stdio::from(fold_space))
        .status()?;
    if !stack_status.success() {
        anyhow::bail!("Failed to collapse stack traces.")
    }

    let terms = [
        ("xde_rx", rx_name.unwrap_or("rx")),
        ("xde_mc_tx", tx_name.unwrap_or("tx")),
    ];

    for (tracked_fn, out_name) in terms {
        let grepped_name = out_dir.as_ref().join(format!("{out_name}.folded"));
        let grepped = File::create(&grepped_name)?;
        let grep_status = Command::new("grep")
            .arg(tracked_fn)
            .arg(fold_path.as_os_str())
            .stdout(Stdio::from(grepped))
            .status()?;
        if !grep_status.success() {
            anyhow::bail!("Failed to grep stack trace for {tracked_fn}.")
        }

        let flame_name = out_dir.as_ref().join(format!("{out_name}.svg"));
        let flame_file = File::create(&flame_name)?;
        let flame_status = Command::new("flamegraph.pl")
            .arg(grepped_name.as_os_str())
            .stdout(Stdio::from(flame_file))
            .status()?;
        if !flame_status.success() {
            anyhow::bail!("Failed to create flamegraph for {tracked_fn}.")
        }
    }

    Ok(())
}

#[cfg(target_os = "illumos")]
fn zone_to_zone() -> Result<()> {
    // add_drv xde.
    ensure_xde()?;

    print_banner("Building test topology... (120s)");
    let topol = xde_tests::two_node_topology()?;
    print_banner("Topology built!");

    // Create iPerf server on one zone.
    // This will be implicitly closed on exit, I guess.
    let _iperf_sess = topol.nodes[1].command("iperf -s").spawn()?;
    let target_ip = topol.nodes[1].port.ip();

    print_banner("iPerf spawned!\nWaiting... (10s)");
    std::thread::sleep(Duration::from_secs(10));
    print_banner("Go!");

    // Ping for good luck / to verify reachability.
    let _ = &topol.nodes[0]
        .zone
        .zone
        .zexec(&format!("ping {}", &topol.nodes[1].port.ip()))?;

    // Begin dtrace sessions in global zone.
    let (kill, done) = spawn_local_dtraces("iperf-tcp");

    // Begin a handful of iPerf client sessions, dtrace will cat
    // all stack traces/times together.
    let mut outputs = vec![];
    let max = 3;
    for i in 0..3 {
        // XXX: Want to run one of the dtraces at a time?
        //      Looks like histo-timing has a noticeable cost on BW.
        print!("Run {i}/{max}...");
        let iperf_done = topol.nodes[0]
            .command(&format!("iperf -c {target_ip} -J"))
            .output()?;
        let iperf_out = std::str::from_utf8(&iperf_done.stdout)?;
        let parsed_out: Output = serde_json::from_str(&iperf_out)?;
        println!("{}Mbps", parsed_out.end.sum_sent.bits_per_second / 1e6);
        outputs.push(parsed_out);
    }

    // Close dtrace.
    print_banner("iPerf done...\nAwaiting out files...");
    let _ = kill.send(());
    print_banner("done!");
    process_output(done.recv()??)
}

fn zone_to_zone_dummy() -> Result<()> {
    let out_dir = output_base_dir().join("iperf-tcp");
    let histo_path = out_dir.join("histos.out");
    let stack_path = out_dir.join("raw.stacks");
    let outdata = DtraceOutput { histo_path, stack_path, out_dir };

    process_output(outdata)
}

fn process_output(outdata: DtraceOutput) -> Result<()> {
    build_flamegraph(&outdata.stack_path, &outdata.out_dir, None, None)?;

    let histos = DTraceHisto::from_path(&outdata.histo_path, 256)?;

    for histo in histos {
        let label = histo.label.clone().unwrap();
        let mut c =
            Criterion::default().measurement_time(Duration::from_secs(20));

        let mut rng = thread_rng();
        let idx =
            WeightedIndex::new(histo.buckets.iter().map(|x| x.1)).unwrap();

        let mut c = c.benchmark_group("iperf-tcp/local");
        c.bench_function(&label, move |b| {
            b.iter_custom(|iters| {
                (0..iters)
                    .map(|_| {
                        let chosen_bucket = idx.sample(&mut rng);
                        let sample = &histo.buckets[chosen_bucket].0;

                        // uniformly distribute within bucket.
                        Duration::from_nanos(
                            rng.gen_range(
                                *sample..*sample + histo.bucket_width,
                            ),
                        )
                    })
                    .sum()
            })
        });
    }

    Ok(())
}

#[cfg(target_os = "illumos")]
fn main() -> Result<()> {
    elevate()?;
    check_deps()?;

    let cfg = ConfigInput::parse();

    match cfg.command {
        Experiment::Remote { iperf_server: _server, .. } => todo!(),
        Experiment::Local { no_bench, .. } => {
            if no_bench {
                zone_to_zone_dummy()
            } else {
                zone_to_zone()
            }
        }
    }
}
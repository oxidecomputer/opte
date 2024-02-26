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
use itertools::Itertools;
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
use std::io::Read;
use std::io::Write;
use std::net::Ipv6Addr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
#[cfg(target_os = "illumos")]
use xde_tests::get_linklocal_addr;
#[cfg(target_os = "illumos")]
use xde_tests::RouteV6;
#[cfg(target_os = "illumos")]
use xde_tests::Topology;

const DEFAULT_PORT: u16 = 0x1dee;

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
    /// This should forward packets over a NIC, using the `underlay_nics`
    /// argument. Your underlay NICS *must* have an MTU significantly
    /// larger than 1500, and have ipv6 link locals e.g. igb0/ll.
    Remote {
        /// Listen address/hostname of a `cargo kbench server` instance
        /// for route exchange.
        iperf_server: String,

        #[command(flatten)]
        opte_create: OpteCreateParams,

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
    /// Run an iPerf server in an OPTE-connected zone for back-to-back
    /// testing.
    ///
    /// Your underlay NICS *must* have an MTU significantly larger
    /// than 1500, and have ipv6 link local addresses e.g. igb0/ll.
    Server {
        #[command(flatten)]
        opte_create: OpteCreateParams,

        #[command(flatten)]
        _waste: IgnoredExtras,
    },
    /// Record rx/tx dtrace samples from the currently running system
    /// to produce flamegraphs and density plots.
    ///
    /// This assumes you already have an `xde` device loaded, a valid
    /// underlay set, and have traffic you aim to measure produced by
    /// another means.
    InSitu {
        experiment_name: String,

        #[command(flatten)]
        _waste: IgnoredExtras,
    },
    /// Wipe out any leftover state if a test/server run ends poorly.
    ///
    /// This will remove the 'vopte0' adapter, 'a' zone, and the XDE
    /// driver.
    Cleanup {
        #[command(flatten)]
        _waste: IgnoredExtras,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum CreateMode {
    Dont,
    Do,
}

#[derive(Clone, Parser)]
struct OpteCreateParams {
    /// Names of two interfaces to bind to XDE as underlay NICs.
    #[arg(
        short,
        long,
        number_of_values(2),
        value_delimiter=',',
        default_values_t=["igb0".to_string(), "igb1".to_string()]
    )]
    underlay_nics: Vec<String>,

    /// Port used for server-to-bench instance communication.
    #[arg(
        short,
        long,
        default_value_t=DEFAULT_PORT,
    )]
    port: u16,
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
    enum Dep {
        Program,
        File,
    }
    let dep_map = [
        (Dep::Program, "iperf", "iperf"),
        (Dep::Program, "stackcollapse.pl", "flamegraph"),
        (Dep::Program, "flamegraph.pl", "flamegraph"),
        (Dep::Program, "demangle", "demangle"),
        (Dep::File, "/usr/lib/brand/sparse", "sparse"),
    ];

    let mut missing_progs = vec![];
    let mut missing_pkgs = HashSet::new();

    for (dep_type, prog, pkg) in dep_map {
        let missing_dep = match dep_type {
            Dep::Program => Command::new("which")
                .arg(prog)
                .output()
                .map_err(|_| ())
                .and_then(
                    |out| if out.status.success() { Ok(()) } else { Err(()) },
                )
                .is_err(),
            Dep::File => !Path::new(prog).exists(),
        };
        if missing_dep {
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
    config: &OutputConfig,
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

        let mut grep_status = Command::new("grep")
            .arg(tracked_fn)
            .arg(fold_path.as_os_str())
            .stdout(Stdio::piped())
            .spawn()?;

        let dem_status = Command::new("demangle")
            .stdin(grep_status.stdout.take().unwrap())
            .stdout(Stdio::from(grepped))
            .status()?;

        if !dem_status.success() {
            anyhow::bail!("Failed to grep stack trace for {tracked_fn}.")
        }

        let flame_name = out_dir.as_ref().join(format!("{out_name}.svg"));
        let flame_file = File::create(&flame_name)?;
        let flame_status = Command::new("flamegraph.pl")
            .args(["--title", &config.title()])
            .args(["--subtitle", &format!("Stacks containing: {tracked_fn}")])
            .args(["--fonttype", "Berkeley Mono,Fira Mono,monospace"])
            .args(["--width", "1600"])
            .arg(grepped_name.as_os_str())
            .stdout(Stdio::from(flame_file))
            .status()?;
        if !flame_status.success() {
            eprintln!("Failed to create flamegraph for {tracked_fn}.")
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

    for expt in base_experiments("local") {
        test_iperf(&topol, &target_ip, &expt)?
    }

    Ok(())
}

fn dtrace_only(experiment_name: &str) -> Result<()> {
    // Begin dtrace sessions in global zone.
    let (kill, done) = spawn_local_dtraces(experiment_name);

    print_banner("DTrace running...\nType 'exit' to finish.");
    loop_til_exit();

    // Close dtrace.
    print_banner("iPerf done...\nAwaiting out files...");
    let _ = kill.send(());
    print_banner("done!");
    process_output(&OutputConfig::InSitu(experiment_name), done.recv()??)?;

    Ok(())
}

#[derive(Debug)]
struct Routes {
    lls: Vec<Ipv6Addr>,
    underlay: Ipv6Addr,
}

#[cfg(target_os = "illumos")]
fn send_routes_client(
    route: &Routes,
    host: &str,
    params: &OpteCreateParams,
) -> Result<(TcpStream, Vec<RouteV6>)> {
    println!("Connecting to {host}...");
    let mut client = TcpStream::connect((host, params.port))?;
    println!("Connected!");
    client.set_nodelay(true)?;

    let v6_routes = exchange_routes(route, &mut client, &params.underlay_nics)?;
    Ok((client, v6_routes))
}

#[cfg(target_os = "illumos")]
fn exchange_routes(
    route: &Routes,
    client: &mut TcpStream,
    underlay_nics: &[String],
) -> Result<Vec<RouteV6>> {
    send_routes(route, client)?;
    let new_routes = recv_routes(client)?;

    println!("peer owns connected lls {:?}", new_routes.lls);

    // ping the received link locals over our underlay and prime NDP.
    for nic in underlay_nics {
        for ip in &new_routes.lls {
            // attempt to ping each ll over each NIC: failure is okay,
            // but we need to do this to set up our NDP entries for route
            // insertion.
            // e.g., ping -Ainet6 -n -i igb1 -c 1 fe80::a236:9fff:fe0c:25b7 1
            Command::new("ping")
                .args(["-Ainet6", "-n", "-i", nic.as_str(), "-c", "1"])
                .arg(ip.to_string())
                .arg("1")
                .output()?;
        }
    }

    // Leave ample time to also *be* pinged if necessary.
    // I'm finding that the server can be caught with entries
    // in state DELAYED, otherwise.
    println!("lls pinged, awating ndp stabilising...");
    std::thread::sleep(Duration::from_secs(10));

    let ndp_data = Command::new("ndp").arg("-an").output()?;

    let ndp_parse = std::str::from_utf8(&ndp_data.stdout)?;

    let mut routes = vec![];
    let mut nics_used = HashSet::new();
    for line in ndp_parse.lines() {
        let mut els = line.split_whitespace();

        let Some(nic) = els.next() else {
            continue;
        };
        let nic = nic.to_string();

        let Some(_mac) = els.next() else {
            continue;
        };

        let Some(_type) = els.next() else {
            continue;
        };

        let Some(status) = els.next() else {
            continue;
        };

        let Some(addr) = els.next() else {
            continue;
        };

        if !underlay_nics.contains(&nic) {
            continue;
        }

        if status != "REACHABLE" {
            continue;
        }

        let Ok(gw_ip) = addr.parse::<Ipv6Addr>() else {
            continue;
        };

        if new_routes.lls.contains(&gw_ip) {
            println!(
                "installing {}/64->{gw_ip} via {nic}",
                new_routes.underlay
            );
            routes.push(RouteV6::new(
                new_routes.underlay,
                64,
                gw_ip,
                Some(nic.to_string()),
            )?);
            nics_used.insert(nic.to_string());
        }
    }

    if nics_used.len() < 2 {
        eprintln!("only found routes to other side over {nics_used:?}. multipath may be degraded.")
    }

    Ok(routes)
}

fn send_routes(route: &Routes, client: &mut TcpStream) -> Result<()> {
    client.write_all(&(route.lls.len() as u64).to_be_bytes())?;
    for ll in &route.lls {
        client.write_all(&ll.octets())?;
    }
    client.write_all(&route.underlay.octets())?;

    Ok(())
}

fn recv_routes(client: &mut TcpStream) -> Result<Routes> {
    let mut buf = [0u8; std::mem::size_of::<Ipv6Addr>()];

    client.read_exact(&mut buf[..8])?;
    let len = u64::from_be_bytes(buf[..8].try_into()?);
    let mut lls = Vec::with_capacity(len.try_into()?);
    for _ in 0..len {
        client.read_exact(&mut buf[..])?;
        lls.push(Ipv6Addr::from(buf));
    }
    client.read_exact(&mut buf[..])?;
    let underlay = Ipv6Addr::from(buf);

    Ok(Routes { lls, underlay })
}

#[cfg(target_os = "illumos")]
fn over_nic(params: &OpteCreateParams, host: &str) -> Result<()> {
    // add_drv xde.
    ensure_xde()?;

    let lls: Vec<Ipv6Addr> = params
        .underlay_nics
        .iter()
        .map(String::as_str)
        .map(get_linklocal_addr)
        .collect::<Result<_>>()?;

    let to_send =
        Routes { lls, underlay: xde_tests::ZONE_B_PORT.underlay_addr.into() };

    let (_sess, _routes) = send_routes_client(&to_send, host, params)?;

    print_banner(&format!(
        "Creating XDE device on NICS {}",
        params.underlay_nics.iter().join(",")
    ));
    let topol = xde_tests::single_node_over_real_nic(
        (&params.underlay_nics[..2]).try_into().unwrap(),
        xde_tests::ZONE_B_PORT,
        &[xde_tests::ZONE_A_PORT],
    )?;
    print_banner("Topology built!");

    let target_ip = xde_tests::ZONE_A_PORT.ip;

    // Ping for good luck / to verify reachability.
    let _ = &topol.nodes[0].zone.zone.zexec(&format!("ping {}", &target_ip))?;

    // uncomment to enter the zone safely for testing.
    // loop_til_exit();

    for expt in base_experiments("over-nic") {
        test_iperf(&topol, &target_ip.to_string(), &expt)?
    }

    Ok(())
}

#[derive(Debug, Clone)]
enum IperfMode {
    ClientSend,
    ServerSend,
    // TODO: need an updated illumos package.
    //       we can build and install locally and just call
    //       /usr/local/iperf3 if need be.
    BiDir,
}

impl std::fmt::Display for IperfMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            IperfMode::ClientSend => "Client->Server",
            IperfMode::ServerSend => "Server->Client",
            IperfMode::BiDir => "Bidirectional",
        })
    }
}

impl Default for IperfMode {
    fn default() -> Self {
        Self::ClientSend
    }
}

#[derive(Debug, Clone)]
enum IperfProto {
    Tcp,
    Udp {
        /// Target bandwidth in MiB/s.
        bw: f64,
        /// Size of the UDP send buffer.
        ///
        /// Should be under 1500 due to dont_fragment.
        pkt_sz: usize,
    },
}

impl std::fmt::Display for IperfProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IperfProto::Tcp => f.write_str("TCP"),
            IperfProto::Udp { bw, pkt_sz } => {
                write!(f, "UDP({pkt_sz}B, {bw}MiB/s)")
            }
        }
    }
}

impl Default for IperfProto {
    fn default() -> Self {
        Self::Tcp
    }
}

#[derive(Debug, Clone)]
enum OutputConfig<'a> {
    Iperf(&'a IperfConfig),
    InSitu(&'a str),
}

impl OutputConfig<'_> {
    fn benchmark_group(&self) -> String {
        match self {
            Self::Iperf(i) => i.benchmark_group(),
            Self::InSitu(s) => format!("in-situ/{s}"),
        }
    }

    fn title(&self) -> String {
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

#[derive(Debug, Clone)]
struct IperfConfig {
    use_dtrace: bool,
    n_iters: usize,
    mode: IperfMode,
    proto: IperfProto,
    expt_name: String,
}

impl Default for IperfConfig {
    fn default() -> Self {
        Self {
            use_dtrace: true,
            n_iters: 10,
            mode: IperfMode::default(),
            proto: IperfProto::default(),
            expt_name: "unspec".into(),
        }
    }
}

impl IperfConfig {
    fn cmd_str(&self, target_ip: &str) -> String {
        let proto_str;
        let proto_segment = match self.proto {
            IperfProto::Tcp => "",
            IperfProto::Udp { bw, pkt_sz } => {
                proto_str = format!("-u --length {pkt_sz} -b {bw}M");
                proto_str.as_str()
            }
        };
        let dir_segment = match self.mode {
            IperfMode::ClientSend => "",
            IperfMode::ServerSend => "-R",
            IperfMode::BiDir => "--bidir",
        };

        // XXX: Setting several parallel streams because we don't
        //      really have packet-wise ECMP yet from ddm -- the
        //      P-values won't change, so the flowkey remains the same.
        format!("iperf -c {target_ip} -J -P 8 {proto_segment} {dir_segment}")
    }

    fn benchmark_group(&self) -> String {
        format!(
            "iperf-{}/{}/{}",
            match self.proto {
                IperfProto::Tcp => "tcp",
                IperfProto::Udp { .. } => "udp",
            },
            self.expt_name,
            match self.mode {
                IperfMode::ClientSend => "c2s",
                IperfMode::ServerSend => "s2c",
                IperfMode::BiDir => "bidir",
            }
        )
    }

    fn title(&self) -> String {
        format!("iperf3 ({}) -- {}", self.mode, self.proto)
    }
}

// XXX: want these as json somewhere, with command line options
//      to choose which are run.
fn base_experiments(expt_name: &str) -> Vec<IperfConfig> {
    let base =
        IperfConfig { expt_name: expt_name.to_string(), ..Default::default() };
    vec![
        // no dtrace: raw speeds.
        IperfConfig {
            use_dtrace: false,
            n_iters: 5,
            mode: IperfMode::ClientSend,
            ..base.clone()
        },
        IperfConfig {
            use_dtrace: false,
            n_iters: 5,
            mode: IperfMode::ServerSend,
            ..base.clone()
        },
        // dtrace: collect all the stats!
        IperfConfig { mode: IperfMode::ClientSend, ..base.clone() },
        IperfConfig { mode: IperfMode::ServerSend, ..base.clone() },
    ]
}

#[cfg(target_os = "illumos")]
fn test_iperf(
    topol: &Topology,
    target_ip: &str,
    config: &IperfConfig,
) -> Result<()> {
    print_banner(
        format!("Running experiment\n{}", config.benchmark_group()).as_str(),
    );

    // Begin dtrace sessions in global zone.
    let dt_handles = config
        .use_dtrace
        .then(|| spawn_local_dtraces(config.benchmark_group()));

    let my_cmd = config.cmd_str(target_ip);

    // Begin a handful of iPerf client sessions, dtrace will cat
    // all stack traces/times together.
    let mut outputs = vec![];
    for i in 1..(config.n_iters + 1) {
        print!("Run {i}/{}...", config.n_iters);
        let iperf_done = topol.nodes[0].command(&my_cmd).output()?;
        let iperf_out = std::str::from_utf8(&iperf_done.stdout)?;
        let parsed_out: Output =
            serde_json::from_str(iperf_out).map_err(|e| {
                eprintln!("json {e:?}");
                println!("\n\n{iperf_out}\n\n");
                e
            })?;
        println!("{}Mbps", parsed_out.end.sum_sent.bits_per_second / 1e6);
        outputs.push(parsed_out);
    }

    // XXX: We don't currently have a way to just pass in straight
    //      throughput numbers to criterion. I'd like to take the time
    //      to flesh that out, but eyeballing the tput numbers will maybe
    //      suffice for v1.
    if let Some((kill, done)) = dt_handles {
        // Close dtrace.
        print_banner("iPerf done...\nAwaiting out files...");
        let _ = kill.send(());
        print_banner("done!");
        process_output(&(config.into()), done.recv()??)?;
    }

    Ok(())
}

fn zone_to_zone_dummy() -> Result<()> {
    let out_dir = output_base_dir().join("iperf-tcp");
    let histo_path = out_dir.join("histos.out");
    let stack_path = out_dir.join("raw.stacks");
    let outdata = DtraceOutput { histo_path, stack_path, out_dir };

    let cfg = IperfConfig::default();
    process_output(&(&cfg).into(), outdata)
}

fn process_output(config: &OutputConfig, outdata: DtraceOutput) -> Result<()> {
    build_flamegraph(
        config,
        &outdata.stack_path,
        &outdata.out_dir,
        None,
        None,
    )?;

    let histos = DTraceHisto::from_path(&outdata.histo_path, 256)?;

    for histo in histos {
        let label = histo.label.clone().unwrap();
        let mut c =
            Criterion::default().measurement_time(Duration::from_secs(20));

        let mut rng = thread_rng();
        let idx =
            WeightedIndex::new(histo.buckets.iter().map(|x| x.1)).unwrap();

        let mut c = c.benchmark_group(config.benchmark_group());
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

fn loop_til_exit() {
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

#[cfg(target_os = "illumos")]
fn host_iperf(params: &OpteCreateParams) -> Result<()> {
    // add_drv xde.
    ensure_xde()?;

    let listener = TcpListener::bind(("0.0.0.0", params.port))?;

    let lls: Vec<Ipv6Addr> = params
        .underlay_nics
        .iter()
        .map(String::as_str)
        .map(get_linklocal_addr)
        .collect::<Result<_>>()?;

    let to_send =
        Routes { lls, underlay: xde_tests::ZONE_A_PORT.underlay_addr.into() };

    print_banner(&format!(
        "Creating XDE device on NICS {}",
        params.underlay_nics.iter().join(",")
    ));
    let topol = xde_tests::single_node_over_real_nic(
        (&params.underlay_nics[..2]).try_into().unwrap(),
        xde_tests::ZONE_A_PORT,
        &[xde_tests::ZONE_B_PORT],
    )?;

    print_banner("topology created, spawning iPerf.\ntype 'exit' to exit.");
    let _iperf_sess = topol.nodes[0].command("iperf -s").spawn()?;

    let kill_switch: Arc<AtomicBool> = Arc::default();
    let remote_ks = kill_switch.clone();
    let underlay_nics = Arc::new(params.underlay_nics.clone());
    let handle = std::thread::spawn(move || {
        server_loop(listener, Arc::new(to_send), underlay_nics, remote_ks)
    });

    loop_til_exit();

    kill_switch.store(true, Ordering::Relaxed);

    handle.join().unwrap();

    Ok(())
}

fn server_loop(
    listener: TcpListener,
    route: Arc<Routes>,
    underlay_nics: Arc<Vec<String>>,
    kill_switch: Arc<AtomicBool>,
) {
    listener.set_nonblocking(true).unwrap();
    loop {
        if kill_switch.load(Ordering::Relaxed) {
            break;
        }

        match listener.accept() {
            Ok((sess, _addr)) => {
                let _ = sess.set_nodelay(true);
                let route = route.clone();
                let kill_switch = kill_switch.clone();
                let underlay = underlay_nics.clone();
                std::thread::spawn(move || {
                    server_session(sess, route, underlay, kill_switch)
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => {
                eprintln!("failed to open stream for listener: {e:?}");
            }
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}

fn server_session(
    mut stream: TcpStream,
    route: Arc<Routes>,
    underlay_nics: Arc<Vec<String>>,
    kill_switch: Arc<AtomicBool>,
) {
    #[cfg(target_os = "illumos")]
    let _rx_routes =
        exchange_routes(&route, &mut stream, &underlay_nics).unwrap();

    stream.set_nonblocking(true).unwrap();

    let mut buf = [0u8; 16];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                break;
            }
            Ok(_) => {
                eprintln!("received extra data from {:?}", stream.peer_addr());
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {
                break;
            }
        }

        if kill_switch.load(Ordering::Relaxed) {
            break;
        }

        std::thread::sleep(Duration::from_millis(100));
    }
}

fn cleanup_detritus() -> Result<()> {
    // NOTE: We're not really caring about the success of these
    // operations, just to do them all in (approximately) the
    // correct sequence.

    println!("stopping zones...");
    Command::new("zoneadm").args(["-z", "a", "halt"]).output()?;

    println!("deleting zones...");
    Command::new("zoneadm").args(["-z", "a", "uninstall"]).output()?;

    println!("deleting vnics...");
    Command::new("dladm").args(["delete-vnic", "vopte0"]).output()?;

    println!("deleting opte port...");
    Command::new("opteadm").args(["delete-xde", "opte0"]).output()?;

    println!("removing underlay binding...");
    Command::new("rem_drv").arg("xde").output()?;

    Ok(())
}

fn give_ownership() -> Result<()> {
    let Ok(user) = std::env::var("USER") else { return Ok(()) };

    let criterion_path = cargo_target_directory()
        .unwrap_or_else(|| Path::new(".").to_path_buf())
        .join("criterion");
    let outputs = [output_base_dir(), criterion_path.as_path()];

    for path in outputs {
        let a = Command::new("chown").args(["-R", &user]).arg(path).output()?;
    }

    Ok(())
}

#[cfg(target_os = "illumos")]
fn main() -> Result<()> {
    elevate()?;
    check_deps()?;

    let cfg = ConfigInput::parse();

    match cfg.command {
        Experiment::Remote { iperf_server, opte_create, .. } => {
            over_nic(&opte_create, &iperf_server)?;
            give_ownership()
        }
        Experiment::Local { no_bench, .. } => {
            if no_bench {
                zone_to_zone_dummy()?;
            } else {
                zone_to_zone()?;
            }
            give_ownership()
        }
        Experiment::Server { opte_create, .. } => host_iperf(&opte_create),
        Experiment::InSitu { experiment_name, .. } => {
            dtrace_only(&experiment_name)?;
            give_ownership()
        }
        Experiment::Cleanup { .. } => cleanup_detritus(),
    }
}

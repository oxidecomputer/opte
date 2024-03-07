// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use anyhow::Result;
use clap::Parser;
use clap::Subcommand;
use itertools::Itertools;
use opte_bench::iperf::Output;
use opte_bench::kbench::measurement::*;
use opte_bench::kbench::remote::*;
use opte_bench::kbench::workload::*;
use opte_bench::kbench::*;
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
#[cfg(target_os = "illumos")]
use xde_tests::get_linklocal_addr;
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

#[cfg(target_os = "illumos")]
fn main() -> Result<()> {
    opte_bench::kbench::elevate()?;

    let cfg = ConfigInput::parse();

    match cfg.command {
        Experiment::Remote { iperf_server, opte_create, pause, .. } => {
            check_deps(true, true)?;
            over_nic(&opte_create, &iperf_server, pause)?;
            give_ownership()
        }
        Experiment::Local { no_bench, .. } => {
            check_deps(true, !no_bench)?;
            if no_bench {
                zone_to_zone_dummy()?;
            } else {
                zone_to_zone()?;
            }
            give_ownership()
        }
        Experiment::Server { opte_create, .. } => {
            check_deps(false, true)?;
            host_iperf(&opte_create)
        }
        Experiment::InSitu {
            experiment_name,
            capture_mode,
            dont_process,
            ..
        } => {
            check_deps(!dont_process, false)?;
            dtrace_only(&experiment_name, capture_mode, dont_process)?;
            give_ownership()
        }
        Experiment::Cleanup { .. } => {
            check_deps(false, false)?;
            cleanup_detritus()
        }
    }
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

        /// Pauses before running experiments from a zone, allowing
        /// a window of time to access the zone using `zlogin a`.
        #[arg(short, long)]
        pause: bool,

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

        /// Which measurement program should be run.
        #[arg(short, long, default_value = "dtrace")]
        capture_mode: Instrumentation,

        /// Control whether flamegraphs and criterion outputs should
        /// be generated.
        #[arg(short, long)]
        dont_process: bool,

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

fn check_deps(process_flamegraph: bool, iperf_based: bool) -> Result<()> {
    #[derive(Copy, Clone)]
    enum Dep {
        Program,
        File,
    }
    let mut dep_map = vec![];
    if process_flamegraph {
        dep_map.extend_from_slice(&[
            (Dep::Program, "/opt/ooce/sbin/stackcollapse.pl", "flamegraph"),
            (Dep::Program, "/opt/ooce/sbin/flamegraph.pl", "flamegraph"),
            (Dep::Program, "demangle", "demangle"),
        ]);
    }
    if iperf_based {
        dep_map.extend_from_slice(&[
            (Dep::Program, "iperf", "iperf"),
            (Dep::File, "/usr/lib/brand/sparse", "sparse"),
        ]);
    }

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

fn dtrace_only(
    experiment_name: &str,
    capture_mode: Instrumentation,
    dont_process: bool,
) -> Result<()> {
    // Begin dtrace sessions in global zone.
    let waiters = match capture_mode {
        Instrumentation::None => None,
        Instrumentation::Dtrace => {
            let a = spawn_local_instrument(
                experiment_name,
                capture_mode,
                Default::default(),
            );
            print_banner("DTrace running...\nType 'exit' to finish.");
            loop_til_exit();
            Some(a)
        }
        Instrumentation::Lockstat => {
            // TODO: prompt.
            let duration = Duration::from_secs(20);
            Some(spawn_local_instrument(
                experiment_name,
                capture_mode,
                duration,
            ))
        }
    };

    let dtrace_out = if let Some((kill, done)) = waiters {
        // Close dtrace.
        print_banner("Awaiting out files...");
        let _ = kill.send(());
        print_banner("done!");

        done.recv()??
    } else {
        let out_dir = output_base_dir().join(experiment_name);
        let histo_path = out_dir.join("histos.out");
        let stack_path = out_dir.join("raw.stacks");
        DtraceOutput { histo_path, stack_path, out_dir }
    };

    if !dont_process && !matches!(capture_mode, Instrumentation::Lockstat) {
        process_output(&OutputConfig::InSitu(experiment_name), dtrace_out)?;
    }

    Ok(())
}

#[cfg(target_os = "illumos")]
fn over_nic(params: &OpteCreateParams, host: &str, pause: bool) -> Result<()> {
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

    let (_sess, _routes) =
        send_routes_client(&to_send, host, params.port, &params.underlay_nics)?;

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
    if pause {
        print_banner("Holding, type 'exit' to begin measurement.");
        loop_til_exit();
    }

    for expt in base_experiments("over-nic") {
        test_iperf(&topol, &target_ip.to_string(), &expt)?
    }

    Ok(())
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
    let dt_handles = match config.instrumentation {
        Instrumentation::Dtrace => Some(spawn_local_instrument(
            config.benchmark_group(),
            config.instrumentation,
            Default::default(),
        )),
        Instrumentation::Lockstat => Some(spawn_local_instrument(
            config.benchmark_group(),
            config.instrumentation,
            Duration::from_secs(11) * (config.n_iters as u32 + 1),
        )),
        Instrumentation::None => None,
    };

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
        if !matches!(config.instrumentation, Instrumentation::Lockstat) {
            process_output(&(config.into()), done.recv()??)?;
        }
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

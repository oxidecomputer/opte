// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

use super::*;
use crate::dtrace::DTraceHisto;
use clap::ValueEnum;
use criterion::Criterion;
use rand::Rng;
use rand::distr::weighted::WeightedIndex;
use rand::distr::Distribution;
use rand::rng;
use std::fs;
use std::fs::File;
use std::process::Child;
use std::process::Stdio;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::time::Duration;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Instrumentation {
    None,
    Dtrace,
    Lockstat,
}

impl std::fmt::Display for Instrumentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug)]
pub struct DtraceOutput {
    pub stack_path: PathBuf,
    pub histo_path: PathBuf,
    pub out_dir: PathBuf,
}

pub static DTRACE_STACK_PROG: &str =
    include_str!("../../../dtrace/opte-count-cycles.d");

pub fn run_local_dtraces(
    out_dir: PathBuf,
) -> Result<(Vec<Child>, DtraceOutput)> {
    fs::create_dir_all(&out_dir)?;

    // Default dtrace behaviour here is to append; which we don't want.
    let histo_path = out_dir.join("histos.out");
    let _ = fs::remove_file(&histo_path);
    let Some(histo_path_str) = histo_path.to_str() else {
        anyhow::bail!("Illegal utf8 in histogram path.")
    };
    let histo = Command::new("dtrace")
        .args([
            "-qn",
            DTRACE_STACK_PROG.replace('\n', "").as_str(),
            "-o",
            histo_path_str,
        ])
        .spawn()?;

    // Ditto for stack tracing.
    let stack_path = out_dir.join("raw.stacks");
    let _ = fs::remove_file(&stack_path);
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

pub fn run_local_lockstat(
    out_dir: PathBuf,
    duration: Duration,
) -> Result<(Vec<Child>, DtraceOutput)> {
    fs::create_dir_all(&out_dir)?;

    // Default dtrace behaviour here is to append; which we don't want.
    let out_path = out_dir.join("lockstat.out");
    let _ = fs::remove_file(&out_path);
    let Some(out_path_str) = out_path.to_str() else {
        anyhow::bail!("Illegal utf8 in histogram path.")
    };
    let histo = Command::new("lockstat")
        .args([
            "-h",
            "-o",
            out_path_str,
            "sleep",
            &format!("{}", duration.as_secs()),
        ])
        .spawn()?;

    let stack_path = out_dir.join("_.ignore");

    Ok((
        vec![histo],
        DtraceOutput { histo_path: out_path, stack_path, out_dir },
    ))
}

pub fn spawn_local_instrument(
    expt_location: impl AsRef<Path>,
    to_run: Instrumentation,
    est_duration: Duration,
) -> (Sender<()>, Receiver<Result<DtraceOutput>>) {
    let (kill_tx, kill_rx) = mpsc::channel();
    let (out_tx, out_rx) = mpsc::channel();

    let expt_location = expt_location.as_ref().to_path_buf();

    std::thread::spawn(move || {
        let out_dir = output_base_dir().join(expt_location);

        let (spawned, should_sigint) = match to_run {
            Instrumentation::Dtrace => (run_local_dtraces(out_dir), true),
            Instrumentation::Lockstat => {
                (run_local_lockstat(out_dir, est_duration), false)
            }
            Instrumentation::None => unreachable!(),
        };

        let _ = out_tx.send(match spawned {
            Ok((children, result)) => {
                let _ = kill_rx.recv();

                // Need to manually ctrl-c and await EACH process,
                // in the dtrace case. Lockstat is set on a timer.
                for mut child in children {
                    if should_sigint {
                        let upgrade = nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(child.id() as i32),
                            nix::sys::signal::Signal::SIGINT,
                        )
                        .is_err();
                        if upgrade {
                            println!("...killing...");
                            let _ = child.kill();
                        }
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

pub fn build_flamegraph(
    config: &OutputConfig,
    stack_file: impl AsRef<Path>,
    out_dir: impl AsRef<Path>,
    rx_name: Option<&str>,
    tx_name: Option<&str>,
) -> Result<()> {
    let fold_path = out_dir.as_ref().join("stacks.folded");
    let fold_space = File::create(&fold_path)?;

    let stack_status = Command::new("/opt/ooce/sbin/stackcollapse.pl")
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
        let flame_status = Command::new("/opt/ooce/sbin/flamegraph.pl")
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

pub fn process_output(
    config: &OutputConfig,
    outdata: DtraceOutput,
) -> Result<()> {
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

        let mut rng = rng();
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
                        Duration::from_nanos(rng.random_range(
                            *sample..*sample + histo.bucket_width,
                        ))
                    })
                    .sum()
            })
        });
    }

    Ok(())
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use anyhow::Context;
use anyhow::Result;
use cargo_metadata::Metadata;
use clap::Args;
use clap::Parser;
use std::io::Write;
use std::process::Command;
use std::sync::OnceLock;

static METADATA: OnceLock<Metadata> = OnceLock::new();
fn cargo_meta() -> &'static Metadata {
    METADATA
        .get_or_init(|| cargo_metadata::MetadataCommand::new().exec().unwrap())
}

const KMOD_TARGET: &str = "x86_64-unknown-unknown";
const LINK_TARGET: &str = "i686-unknown-illumos";

/// Development functions for OPTE.
#[derive(Debug, Parser)]
enum Xtask {
    Build(BuildOptions),

    /// Build and install the XDE kernel driver.
    Install {
        /// Install from an illumos package file rather than ...
        #[arg(long)]
        from_package: bool,

        /// Skips building opteadm and XDE.
        #[arg(long)]
        skip_build: bool,

        #[command(flatten)]
        build: BuildOptions,
    },

    /// Build the XDE kernel driver and produce an illumos package.
    Package {
        #[command(flatten)]
        build: BuildOptions,

        /// Skips building opteadm and XDE.
        #[arg(long)]
        skip_build: bool,
    },
}

#[derive(Debug, Args)]
struct BuildOptions {
    /// Disable building/packaging debug bits for both `opteadm`
    /// and the XDE module.
    #[arg(long)]
    release_only: bool,
}

fn main() -> anyhow::Result<()> {
    let cmd = Xtask::parse();
    // TODO: gate some of these to illumos only.
    match cmd {
        Xtask::Build(b) => cmd_build(b.release_only),
        Xtask::Install { from_package, skip_build, build } => {
            if !skip_build {
                cmd_build(!from_package || build.release_only)?;
            }

            if !elevate(
                "install xde kernel module",
                if skip_build { &[] } else { &["--skip-build"] },
            )? {
                return Ok(());
            }

            if from_package {
                cmd_package(build.release_only)?;
            } else {
                raw_install()?;
            }

            Ok(())
        }
        Xtask::Package { build, skip_build } => {
            if !skip_build {
                cmd_build(build.release_only)?;
            }

            cmd_package(build.release_only)
        }
    }
}

fn elevate(operation: &str, extra_args: &[&str]) -> Result<bool> {
    let curr_user_run = Command::new("whoami").output()?;
    if !curr_user_run.status.success() {
        let as_utf = std::str::from_utf8(&curr_user_run.stderr);
        anyhow::bail!("Failed to get current user: {:?}", as_utf);
    }

    match std::str::from_utf8(&curr_user_run.stdout) {
        Ok("root\n") => Ok(true),
        Ok(_) => {
            print!("Command requires admin privileges to {operation}. Continue? [yY] ");
            std::io::stdout().flush()?;

            let mut resp = String::new();
            std::io::stdin().read_line(&mut resp)?;
            match resp.as_str() {
                "y\n" | "Y\n" => {
                    let my_args = std::env::args();
                    let mut elevated = Command::new("pfexec")
                        .args(my_args)
                        .args(extra_args)
                        .spawn()?;
                    let exit_code = elevated.wait()?;
                    std::process::exit(exit_code.code().unwrap_or(1));
                }
                _ => {
                    println!("Exiting...")
                }
            }

            Ok(false)
        }
        Err(_) => anyhow::bail!("`whoami` did not return a valid UTF user."),
    }
}

fn cmd_build(release_only: bool) -> Result<()> {
    let modes = if release_only { &[false][..] } else { &[true, false] };

    for release_mode in modes {
        BuildTarget::OpteAdm.build(*release_mode)?;
        BuildTarget::Xde.build(*release_mode)?;
    }

    Ok(())
}

fn cmd_package(_release_only: bool) -> Result<()> {
    let meta = cargo_meta();

    // XXX: should this be RIIR'd?
    Command::new("bash")
        .arg("build.sh")
        .current_dir(meta.workspace_root.join("pkg"))
        .output_nocapture()?;

    Ok(())
}

fn raw_install() -> Result<()> {
    let meta = cargo_meta();

    // NOTE: we don't need to actually check this one, it'll return a
    // failure code even if we don't care about it.
    Command::new("rem_drv").arg("xde").output()?;

    let mut kmod_dir = meta.target_directory.clone();
    kmod_dir.extend(&[KMOD_TARGET, "release", "xde"]);

    let opteadm_dir = meta.target_directory.join("release/opteadm");

    let mut link_dir = meta.target_directory.clone();
    link_dir.extend(&[LINK_TARGET, "release", "libxde_link.so"]);

    std::fs::copy(kmod_dir, "/kernel/drv/amd64/xde")?;
    std::fs::copy(opteadm_dir, "/opt/oxide/opte/bin/opteadm")?;
    std::fs::copy(link_dir, "/usr/lib/devfsadm/linkmod/SUNW_xde_link.so")?;

    Ok(())
}

enum BuildTarget {
    OpteAdm,
    Xde,
}

fn build_cargo_bin(
    target: &[&str],
    release: bool,
    cwd: Option<&str>,
    current_cargo: bool,
) -> Result<()> {
    let meta = cargo_meta();

    let mut dir = meta.workspace_root.clone();
    if let Some(cwd) = cwd {
        dir.push(cwd);
    }

    let mut command = if current_cargo {
        let cargo =
            std::env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
        Command::new(&cargo)
    } else {
        Command::new("cargo")
    };

    command.arg("build");
    command.args(target);
    if release {
        command.arg("--release");
    }

    let mut dir = meta.workspace_root.clone().into_std_path_buf();
    if let Some(cwd) = cwd {
        dir.push(cwd);
    }

    // XDE + XDE-link need to use nightly.
    if !current_cargo {
        command.env_remove("RUSTUP_TOOLCHAIN");
    }

    command.current_dir(dir);

    command.output_nocapture().context(format!(
        "failed to build {:?}",
        if target.is_empty() {
            cwd.unwrap_or("<unnamed>")
        } else {
            target[target.len() - 1]
        }
    ))
}

impl BuildTarget {
    fn build(&self, debug: bool) -> Result<()> {
        let profile = if debug { "debug" } else { "release" };
        match self {
            Self::OpteAdm => {
                println!("Building opteadm ({profile}).");
                build_cargo_bin(&["--bin", "opteadm"], !debug, None, true)
            }
            Self::Xde => {
                println!("Building xde ({profile}).");
                let meta = cargo_meta();
                build_cargo_bin(&[], !debug, Some("xde"), false)?;

                let (folder, out_name) = if debug {
                    ("debug", "xde.dbg")
                } else {
                    ("release", "xde")
                };
                let target_dir = meta
                    .target_directory
                    .join(format!("{KMOD_TARGET}/{folder}"));

                println!("Linking xde kmod...");
                Command::new("ld")
                    .args([
                        "-ztype=kmod",
                        "-Ndrv/mac",
                        "-Ndrv/ip",
                        "-Nmisc/mac",
                        "-Nmisc/dls",
                        "-Nmisc/dld",
                        "-z",
                        "allextract",
                        &format!("{target_dir}/xde.a"),
                        "-o",
                        &format!("{target_dir}/{out_name}"),
                    ])
                    .output_nocapture()
                    .context("failed to link XDE kernel module")?;

                build_cargo_bin(&[], !debug, Some("xde/xde-link"), false)?;

                // verify no panicking in the devfsadm plugin
                let nm_output = Command::new("nm")
                    .arg(meta.target_directory.join(format!(
                        "i686-unknown-illumos/{folder}/libxde_link.so"
                    )))
                    .output()?;

                if nm_output.status.success() {
                    if std::str::from_utf8(&nm_output.stdout)?
                        .contains("panicking")
                    {
                        anyhow::bail!("ERROR: devfsadm plugin may panic!")
                    } else {
                        Ok(())
                    }
                } else {
                    anyhow::bail!("failed to run `nm`")
                }
            }
        }
    }
}

trait CommandNoCapture {
    fn output_nocapture(&mut self) -> Result<()>;
}

impl CommandNoCapture for Command {
    fn output_nocapture(&mut self) -> Result<()> {
        let status = self
            .spawn()
            .context("failed to spawn child cargo invocation")?
            .wait()
            .context("failed to await child cargo invocation")?;

        if status.success() {
            Ok(())
        } else {
            anyhow::bail!("failed to run (status {status})")
        }
    }
}

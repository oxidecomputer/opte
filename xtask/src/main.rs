// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

use anyhow::Context;
use anyhow::Result;
use cargo_metadata::Metadata;
use clap::Args;
use clap::Parser;
use clap::ValueEnum;
use std::collections::BTreeSet;
use std::fmt;
use std::io::Write;
use std::path::PathBuf;
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
    /// Build the XDE kernel module.
    Build {
        /// The artefacts to be built.
        #[clap(default_values_t = [BuildTarget::All])]
        targets: Vec<BuildTarget>,

        #[command(flatten)]
        build: BuildOptions,
    },

    /// Build and install the XDE kernel module.
    Install {
        /// Install from an illumos package file rather than by copying
        /// the drivers into place.
        #[arg(long)]
        from_package: bool,

        /// Override any package freeze held in place by omicron.
        ///
        /// No-op if `from_package` is not specified.
        #[arg(long, requires = "from_package")]
        force_package_unfreeze: bool,

        /// Skips building opteadm and XDE.
        #[arg(long)]
        skip_build: bool,

        #[command(flatten)]
        build: BuildOptions,
    },

    /// Build the XDE kernel module and produce an illumos package.
    Package {
        #[command(flatten)]
        build: BuildOptions,

        /// Skips building opteadm and XDE.
        #[arg(long)]
        skip_build: bool,
    },

    /// Format the repository with `rustfmt`.
    Fmt,
}

#[derive(Debug, Args)]
struct BuildOptions {
    /// Disable building/packaging debug bits for both `opteadm`
    /// and the XDE module.
    #[arg(long, default_value_t = Profile::Release)]
    profile: Profile,
}

fn main() -> anyhow::Result<()> {
    let cmd = Xtask::parse();
    // TODO: gate some of these to illumos only.
    match cmd {
        Xtask::Build { targets, build } => cmd_build(targets, build.profile),
        Xtask::Install {
            from_package,
            force_package_unfreeze,
            skip_build,
            build,
        } => {
            if !skip_build {
                cmd_build(vec![BuildTarget::All], build.profile)?;
            }

            let pkg_info = if from_package {
                Some(cmd_package(!skip_build, build.profile)?)
            } else {
                None
            };

            if !elevate(
                "install xde kernel module",
                if skip_build { &[] } else { &["--skip-build"] },
            )? {
                return Ok(());
            }

            if let Some((a, version)) = pkg_info {
                if force_package_unfreeze {
                    Command::new("pkg")
                        .args(["unfreeze", "opte"])
                        .output_nocapture()?;
                }

                Command::new("pkg")
                    .args([
                        "install",
                        "-g",
                        a.parent().unwrap().to_str().unwrap(),
                        &format!("opte@{version}"),
                    ])
                    .output_nocapture()
                    .context(
                        "failed to install opte, \
                        add `--force-package-unfreeze` if package \
                        is frozen",
                    )?;
            } else {
                raw_install()?;
            }

            Ok(())
        }
        Xtask::Package { build, skip_build } => {
            if !skip_build {
                cmd_build(vec![BuildTarget::All], build.profile)?;
            }

            let (p_path, _) = cmd_package(true, build.profile)?;

            println!(
                "Successfully built package {}.",
                p_path.to_str().unwrap()
            );

            Ok(())
        }
        Xtask::Fmt => {
            let meta = cargo_meta();

            // This is explicitly `cargo` rather than CARGO as we might
            // be swapping toolchains to do this from the current cargo.
            Command::new("cargo")
                .arg(format!("+{}", get_current_nightly_toolchain()?))
                .args(["fmt", "--all"])
                .env_remove("RUSTUP_TOOLCHAIN")
                .current_dir(&meta.workspace_root)
                .output_nocapture()?;

            Ok(())
        }
    }
}

fn get_current_nightly_toolchain() -> Result<String> {
    let meta = cargo_meta();
    let toolchain_full: toml::Value =
        toml::from_str(&std::fs::read_to_string(
            meta.workspace_root.join("xde/rust-toolchain.toml"),
        )?)?;

    toolchain_full
        .get("toolchain")
        .and_then(|v| v.get("channel"))
        .ok_or_else(|| {
            anyhow::anyhow!("xde did not contain info on a pinned nightly")
        })?
        .as_str()
        .ok_or_else(|| {
            anyhow::anyhow!("toolchain channel was not a valid string")
        })
        .map(|s| s.to_string())
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
            print!(
                "Command requires admin privileges to {operation}. Continue? [yY] "
            );
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

fn cmd_build(targets: Vec<BuildTarget>, profile: Profile) -> Result<()> {
    let modes: &[_] = match profile {
        Profile::All => &[PkgProfile::Release, PkgProfile::Debug],
        Profile::Release => &[PkgProfile::Release],
        Profile::Debug => &[PkgProfile::Debug],
    };

    let mut unique_targets: BTreeSet<_> = targets.into_iter().collect();
    if unique_targets.remove(&BuildTarget::All) {
        unique_targets.insert(BuildTarget::OpteAdm);
        unique_targets.insert(BuildTarget::Xde);
        unique_targets.insert(BuildTarget::XdeLink);
    }

    for release_mode in modes {
        for target in &unique_targets {
            target.build(*release_mode)?;
        }
    }

    Ok(())
}

fn cmd_package(
    do_package: bool,
    profile: Profile,
) -> Result<(PathBuf, String)> {
    let meta = cargo_meta();
    let pkg_dir = meta.workspace_root.join("pkg");

    if profile == Profile::Debug {
        anyhow::bail!(
            "`package` only supports the profiles 'release' or 'all'"
        );
    }

    if do_package {
        // XXX: I'm happy today for this to remain as a bash script,
        //      given that it would be very verbose to xtask-ify.
        let mut cmd = Command::new("bash");

        if profile == Profile::Release {
            cmd.env("RELEASE_ONLY", "1");
        }

        cmd.arg("build.sh")
            .current_dir(meta.workspace_root.join(&pkg_dir))
            .output_nocapture()?;
    }

    // Find a matching p5p.
    // XXX: I appreciate we could simplify this by depending on
    //      opteadm as a lib, but then we have to work to make
    //      some subset of it compile on non-illumos platforms.
    let dir_entries = std::fs::read_dir(pkg_dir.join("packages/repo"))?;
    for entry in dir_entries {
        let entry = entry?;
        let path = entry.path();

        let Some(stem) = path.file_stem() else {
            continue;
        };
        let Some(ext) = path.extension() else {
            continue;
        };
        let prefix = "opte-";
        match (stem.to_str(), ext.to_str()) {
            (Some(stem), Some("p5p")) if stem.starts_with(prefix) => {
                let package_vers = stem[prefix.len()..].to_string();
                return Ok((path, package_vers));
            }
            _ => {}
        }
    }

    anyhow::bail!("failed to find output package name")
}

fn raw_install() -> Result<()> {
    let meta = cargo_meta();

    // NOTE: we don't need to actually check either command, they'll
    // return a failure code even if we don't care about it.
    // Opteadm may not even be installed/accessible, so also allow it to
    // fail to run at all.
    let _ = Command::new("/opt/oxide/opte/bin/opteadm")
        .arg("clear-xde-underlay")
        .output();

    Command::new("rem_drv").arg("xde").output()?;

    let mut conf_path = meta.workspace_root.clone();
    conf_path.extend(&["xde", "xde.conf"]);

    let mut kmod_dir = meta.target_directory.clone();
    kmod_dir.extend(&[KMOD_TARGET, "release-lto", "xde"]);

    let opteadm_dir = meta.target_directory.join("release/opteadm");

    let mut link_dir = meta.target_directory.clone();
    link_dir.extend(&[LINK_TARGET, "release", "libxde_link.so"]);

    std::fs::copy(conf_path, "/kernel/drv/xde.conf")?;
    std::fs::copy(kmod_dir, "/kernel/drv/amd64/xde")?;
    std::fs::create_dir_all("/opt/oxide/opte/bin")?;
    std::fs::copy(opteadm_dir, "/opt/oxide/opte/bin/opteadm")?;
    std::fs::copy(link_dir, "/usr/lib/devfsadm/linkmod/SUNW_xde_link.so")?;

    Command::new("add_drv")
        .arg("-m")
        .arg("'xde 0755 root sys'")
        .arg("xde")
        .output_nocapture()
        .context("add xde driver")?;

    Ok(())
}

#[derive(
    Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, ValueEnum,
)]
enum Profile {
    All,
    Debug,
    Release,
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::All => "all",
            Self::Debug => "debug",
            Self::Release => "release",
        })
    }
}

#[derive(Copy, Clone, Debug)]
enum PkgProfile {
    Debug,
    Release,
}

#[derive(Copy, Clone, Debug)]
enum RustProfile {
    Debug,
    Release,
    ReleaseLto,
}

impl RustProfile {
    const fn name(self) -> &'static str {
        match self {
            RustProfile::Debug => "dev",
            RustProfile::Release => "release",
            RustProfile::ReleaseLto => "release-lto",
        }
    }

    const fn folder(self) -> &'static str {
        match self {
            RustProfile::Debug => "debug",
            RustProfile::Release => "release",
            RustProfile::ReleaseLto => "release-lto",
        }
    }
}

#[derive(
    Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, ValueEnum,
)]
enum BuildTarget {
    All,
    OpteAdm,
    Xde,
    XdeLink,
}

impl fmt::Display for BuildTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::All => "all",
            Self::OpteAdm => "opteadm",
            Self::Xde => "xde",
            Self::XdeLink => "xde-link",
        })
    }
}

fn build_cargo_bin(
    target: &[&str],
    profile: &str,
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
        Command::new(cargo)
    } else {
        Command::new("cargo")
    };

    command.arg("build");
    command.args(target);
    command.args(["--profile", profile]);

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
    const fn rust_profile(self, profile: PkgProfile) -> RustProfile {
        match (profile, self) {
            (PkgProfile::Debug, _) => RustProfile::Debug,
            (PkgProfile::Release, BuildTarget::Xde) => RustProfile::ReleaseLto,
            (PkgProfile::Release, _) => RustProfile::Release,
        }
    }

    fn build(&self, profile: PkgProfile) -> Result<()> {
        let meta = cargo_meta();
        let rust_profile = self.rust_profile(profile);
        let p_name = rust_profile.name();
        let p_folder = rust_profile.folder();
        match self {
            Self::All => anyhow::bail!("'all' should have been filtered"),
            Self::OpteAdm => {
                println!("Building opteadm ({p_name}).");

                // While this *does* successfully build from `cwd = None`,
                // feature unification from across the workspace causes cargo
                // to end up re-enabling `engine` and related features.
                // Making sure these are cut out gives us a faster build and
                // smaller binaries.
                build_cargo_bin(
                    &["--bin", "opteadm"],
                    p_name,
                    Some("bin/opteadm"),
                    true,
                )
            }
            Self::Xde => {
                println!("Building xde ({p_name}).");
                build_cargo_bin(&[], p_name, Some("xde"), false)?;

                let out_name = match profile {
                    PkgProfile::Debug => "xde.dbg",
                    PkgProfile::Release => "xde",
                };
                let target_dir = meta
                    .target_directory
                    .join(format!("{KMOD_TARGET}/{p_folder}"));

                println!("Linking xde kmod...");
                Command::new("ld")
                    .args([
                        "-ztype=kmod",
                        "-Ndrv/dld",
                        "-Ndrv/ip",
                        "-Nmisc/dls",
                        "-Nmisc/mac",
                        "-z",
                        "allextract",
                        &format!("{target_dir}/xde.a"),
                        "-o",
                        &format!("{target_dir}/{out_name}"),
                    ])
                    .output_nocapture()
                    .context("failed to link XDE kernel module")?;
                Ok(())
            }
            Self::XdeLink => {
                println!("Building xde dev link helper ({p_name}).");
                build_cargo_bin(&[], p_name, Some("xde/xde-link"), false)?;

                // verify no panicking in the devfsadm plugin
                let nm_output = Command::new("nm")
                    .arg(meta.target_directory.join(format!(
                        "i686-unknown-illumos/{p_folder}/libxde_link.so"
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

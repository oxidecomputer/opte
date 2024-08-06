#!/bin/bash
#:
#: name = "opte-p5p"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "nightly-2024-06-27"
#: output_rules = [
#:   "=/out/opte.p5p",
#:   "=/out/opte.p5p.sha256",
#: ]
#: access_repos = [
#:  "oxidecomputer/illumos-rs",
#: ]
#:
#: [[publish]]
#: series = "repo"
#: name = "opte.p5p"
#: from_output = "/out/opte.p5p"
#:
#: [[publish]]
#: series = "repo"
#: name = "opte.p5p.sha256"
#: from_output = "/out/opte.p5p.sha256"
#:
#: [dependencies.xde]
#: job = "opte-xde"
#;
#: [dependencies.opteadm]
#: job = "opteadm"

set -o errexit
set -o pipefail
set -o xtrace

#
# TGT_BASE allows one to run this more easily in their local
# environment:
#
#   TGT_BASE=/var/tmp ./xde.sh
#
TGT_BASE=${TGT_BASE:=/work}

function header {
	echo "# ==== $* ==== #"
}

cargo --version
rustc --version

header "move artifacts for packaging"
# Copy in just-built artifacts
DBG_SRC=target/x86_64-illumos/debug
DBG_LINK_SRC=target/i686-unknown-illumos/debug
DBG_ADM_SRC=target/debug

REL_SRC=target/x86_64-illumos/release
REL_LINK_SRC=target/i686-unknown-illumos/release
REL_ADM_SRC=target/release

mkdir -p $REL_SRC
cp /input/xde/work/release/xde $REL_SRC
mkdir -p $DBG_SRC
cp /input/xde/work/debug/xde.dbg $DBG_SRC/xde

mkdir -p $REL_LINK_SRC
cp /input/xde/work/release/xde_link.so $REL_LINK_SRC/libxde_link.so
mkdir -p $DBG_LINK_SRC
cp /input/xde/work/debug/xde_link.dbg.so $DBG_LINK_SRC/libxde_link.so

mkdir -p $REL_ADM_SRC
cp /input/opteadm/work/release/opteadm $REL_ADM_SRC
mkdir -p $DBG_ADM_SRC
cp /input/opteadm/work/debug/opteadm $DBG_ADM_SRC

header "package opte"
cargo xtask package --skip-build

banner copy
pfexec mkdir -p /out
pfexec chown "$UID" /out
PKG_NAME="/out/opte.p5p"
mv pkg/packages/repo/*.p5p "$PKG_NAME"
sha256sum "$PKG_NAME" > "$PKG_NAME.sha256"

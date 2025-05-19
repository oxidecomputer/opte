#!/bin/bash
#:
#: name = "opte-p5p"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = true
#: output_rules = [
#:   "=/out/opte.p5p",
#:   "=/out/opte.p5p.sha256",
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

set -o errexit
set -o pipefail
set -o xtrace

source .github/buildomat/common.sh

#
# TGT_BASE allows one to run this more easily in their local
# environment:
#
#   TGT_BASE=/var/tmp ./xde.sh
#
TGT_BASE=${TGT_BASE:=/work}

REL_SRC=target/x86_64-unknown-unknown/release-lto
REL_TGT=$TGT_BASE/release

mkdir -p $REL_TGT

cargo --version
rustc --version

header "build xde and opteadm (release+debug)"
ptime -m cargo xtask build --profile all

#
# Inspect the kernel module for bad relocations in case the old
# codegen issue ever shows its face again.
#
if elfdump $REL_SRC/xde | grep GOTPCREL; then
	echo "found GOTPCREL relocation in release build"
	exit 1
fi

header "package opte"
cargo xtask package --skip-build --profile all

banner copy
pfexec mkdir -p /out
pfexec chown "$UID" /out
PKG_NAME="/out/opte.p5p"
mv pkg/packages/repo/*.p5p "$PKG_NAME"
sha256sum "$PKG_NAME" > "$PKG_NAME.sha256"

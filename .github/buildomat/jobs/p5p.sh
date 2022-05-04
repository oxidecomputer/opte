#!/bin/bash
#:
#: name = "opte-p5p"
#: variety = "basic"
#: target = "helios"
#: rust_toolchain = "nightly"
#: output_rules = [
#:   "/out/*",
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

#
# TGT_BASE allows one to run this more easily in their local
# environment:
#
#   TGT_BASE=/var/tmp ./xde.sh
#
TGT_BASE=${TGT_BASE:=/work}

REL_SRC=target/x86_64-unknown-unknown/release
REL_TGT=$TGT_BASE/release

mkdir -p $REL_TGT

function header {
	echo "# ==== $* ==== #"
}

cargo --version
rustc --version

pushd xde
header "build xde (release)"
ptime -m ./build.sh

#
# Inspect the kernel module for bad relocations in case the old
# codegen issue ever shows its face again.
#
if elfdump $REL_SRC/xde | grep GOTPCREL; then
	echo "found GOTPCREL relocation in release build"
	exit 1
fi
popd

pushd opteadm
cargo build --release
popd

pushd pkg
./build.sh

banner copy
pfexec mkdir -p /out
pfexec chown "$UID" /out
PKG_NAME="/out/opte.p5p"
mv packages/repo/*.p5p "$PKG_NAME"
sha256sum "$PKG_NAME" > "$PKG_NAME.sha256"

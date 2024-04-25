#!/bin/bash
#:
#: name = "opte-xde"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "nightly-2024-04-25"
#: output_rules = [
#:   "=/work/debug/xde.dbg",
#:   "=/work/debug/xde.dbg.sha256",
#:   "=/work/debug/xde_link.dbg.so",
#:   "=/work/debug/xde_link.dbg.so.sha256",
#:   "=/work/release/xde",
#:   "=/work/release/xde.sha256",
#:   "=/work/release/xde_link.so",
#:   "=/work/release/xde_link.so.sha256",
#:   "=/work/test/loopback",
#:   "=/work/xde.conf",
#: ]
#:
#: [[publish]]
#: series = "module"
#: name = "xde"
#: from_output = "/work/release/xde"
#
#: [[publish]]
#: series = "module"
#: name = "xde.sha256"
#: from_output = "/work/release/xde.sha256"

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

DBG_SRC=target/x86_64-unknown-unknown/debug
DBG_LINK_SRC=target/i686-unknown-illumos/debug
DBG_TGT=$TGT_BASE/debug

REL_SRC=target/x86_64-unknown-unknown/release
REL_LINK_SRC=target/i686-unknown-illumos/release
REL_TGT=$TGT_BASE/release

mkdir -p $DBG_TGT $REL_TGT

function header {
	echo "# ==== $* ==== #"
}

function install_pkg {
    set +o errexit
    pfexec pkg install $1
    exit_code=$?
    # 4 is the exit code returned from pkg when the package is already installed
    if [[ $exit_code -ne 0 ]] && [[ $exit_code -ne 4 ]]; then
        echo "package install failed for $1"
        exit 1
    fi
    set -o errexit
}

cargo --version
rustc --version

install_pkg jq

pushd xde

cp xde.conf /work/xde.conf

header "check style"
ptime -m cargo +nightly-2024-04-25 fmt -p xde -p xde-link -- --check

header "analyze"
ptime -m cargo clippy -- \
    --allow clippy::uninlined-format-args --allow clippy::bad_bit_mask

pushd xde-link
ptime -m cargo clippy -- \
    --allow clippy::uninlined-format-args --allow clippy::bad_bit_mask
popd

header "build xde (debug)"
ptime -m ./build-debug.sh

header "build xde (release)"
ptime -m ./build.sh

popd

#
# Inspect the kernel module for bad relocations in case the old
# codegen issue ever shows its face again.
#
if elfdump $DBG_SRC/xde.dbg | grep GOTPCREL; then
	echo "found GOTPCREL relocation in debug build"
	exit 1
fi

if elfdump $REL_SRC/xde | grep GOTPCREL; then
	echo "found GOTPCREL relocation in release build"
	exit 1
fi

cp $DBG_SRC/xde.dbg $DBG_TGT/
sha256sum $DBG_TGT/xde.dbg > $DBG_TGT/xde.dbg.sha256

cp $DBG_LINK_SRC/libxde_link.so $DBG_TGT/xde_link.dbg.so
sha256sum $DBG_TGT/xde_link.dbg.so > $DBG_TGT/xde_link.dbg.so.sha256

cp $REL_SRC/xde $REL_TGT/
sha256sum $REL_TGT/xde > $REL_TGT/xde.sha256

cp $REL_LINK_SRC/libxde_link.so $REL_TGT/xde_link.so
sha256sum $REL_TGT/xde_link.so > $REL_TGT/xde_link.so.sha256


header "build xde integration tests"
pushd xde-tests
cargo +nightly-2024-04-25 fmt -- --check
cargo clippy --all-targets
cargo build --test loopback
loopback_test=$(
    cargo build -q --test loopback --message-format=json |\
    jq -r "select(.profile.test == true) | .filenames[]"
)
mkdir -p /work/test
cp $loopback_test /work/test/loopback

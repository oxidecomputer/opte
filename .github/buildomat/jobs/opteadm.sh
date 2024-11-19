#!/bin/bash
#:
#: name = "opteadm"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "nightly-2024-11-18"
#: output_rules = [
#:   "=/work/debug/opteadm",
#:   "=/work/debug/opteadm.debug.sha256",
#:   "=/work/release/opteadm",
#:   "=/work/release/opteadm.release.sha256",
#: ]
#:
#: [[publish]]
#: series = "release"
#: name = "opteadm"
#: from_output = "/work/release/opteadm"

set -o errexit
set -o pipefail
set -o xtrace

function header {
	echo "# ==== $* ==== #"
}

cargo --version
rustc --version

pushd bin/opteadm

header "check style"
ptime -m cargo +nightly-2024-11-18 fmt -- --check

header "analyze"
ptime -m cargo clippy --all-targets

header "debug build"
ptime -m cargo build

header "release build"
ptime -m cargo build --release

popd

for x in debug release
do
    mkdir -p /work/$x
    cp target/$x/opteadm /work/$x/
    sha256sum "target/$x/opteadm" > "/work/$x/opteadm.$x.sha256"
done

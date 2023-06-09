#!/bin/bash
#:
#: name = "opteadm"
#: variety = "basic"
#: target = "helios"
#: rust_toolchain = "nightly"
#: output_rules = [
#:   "=/work/debug/opteadm",
#:   "=/work/debug/opteadm.debug.sha256",
#:   "=/work/release/opteadm",
#:   "=/work/release/opteadm.release.sha256",
#: ]
#:

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
ptime -m cargo +nightly fmt -- --check

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

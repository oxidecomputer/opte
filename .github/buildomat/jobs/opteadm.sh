#!/bin/bash
#:
#: name = "opteadm"
#: variety = "basic"
#: target = "helios"
#: rust_toolchain = "nightly"
#: output_rules = [
#:   "/work/debug/*",
#:   "/work/release/*",
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

cd opteadm

header "check style"
ptime -m cargo +nightly fmt -- --check

header "analyze"
ptime -m cargo +nightly check

header "debug build"
ptime -m cargo +nightly build

header "release build"
ptime -m cargo +nightly build --release

header "test"
ptime -m cargo +nightly test

for x in debug release
do
    mkdir -p /work/$x
    cp target/$x/opteadm /work/$x/
done

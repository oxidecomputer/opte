#!/bin/bash
#:
#: name = "oxide-vpc"
#: variety = "basic"
#: target = "helios"
#: rust_toolchain = "nightly"
#: output_rules = []
#:

set -o errexit
set -o pipefail
set -o xtrace

function header {
	echo "# ==== $* ==== #"
}

cargo --version
rustc --version

cd oxide-vpc

header "check style"
ptime -m cargo fmt -- --check

header "analyze std + api + usdt"
ptime -m cargo check --features usdt

header "analyze no_std + engine"
ptime -m cargo check --no-default-features --features engine

header "test"
ptime -m cargo test

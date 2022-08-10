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

header "debug build std + api"
ptime -m cargo build

header "debug build no_std + engine"
ptime -m cargo build --no-default-features --features engine

header "release build std + api"
ptime -m cargo build --release

header "release build no_std + engine"
ptime -m cargo build --release --no-default-features --features engine

header "test"
ptime -m cargo test

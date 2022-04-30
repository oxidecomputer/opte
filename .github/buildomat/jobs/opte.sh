#!/bin/bash
#:
#: name = "opte"
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

cd opte

header "check style"
ptime -m cargo fmt -- --check

header "analyze std + api"
ptime -m cargo check

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

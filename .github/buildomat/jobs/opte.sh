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

header "analyze no_std + engine + kernel"
ptime -m cargo check --no-default-features --features engine,kernel

header "test"
ptime -m cargo test

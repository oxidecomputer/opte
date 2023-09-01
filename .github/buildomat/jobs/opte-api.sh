#!/bin/bash
#:
#: name = "opte-api"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "nightly-2023-01-12"
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

cd crates/opte-api

header "check API_VERSION"
./check-api-version.sh

header "check style"
ptime -m cargo +nightly-2023-01-12 fmt -- --check

header "analyze std"
ptime -m cargo clippy --all-targets

header "analyze no_std"
ptime -m cargo clippy --no-default-features --all-targets

header "test"
ptime -m cargo test

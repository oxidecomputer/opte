#!/bin/bash
#:
#: name = "opte-api"
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

cd crates/opte-api

header "check API_VERSION"
./check-api-version.sh

header "check style"
ptime -m cargo +nightly fmt -- --check

header "analyze std"
ptime -m cargo check

header "analyze no_std"
ptime -m cargo check --no-default-features

header "test"
ptime -m cargo test

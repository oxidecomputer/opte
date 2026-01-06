#!/bin/bash
#:
#: name = "opte-api"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = true
#: output_rules = []
#:

set -o errexit
set -o pipefail
set -o xtrace

source .github/buildomat/common.sh

cargo --version
rustc --version

cd crates/opte-api

header "check API_VERSION"
./check-api-version.sh

header "check style"
ptime -m cargo +$NIGHTLY fmt -- --check

header "analyze std"
ptime -m cargo clippy --all-targets

header "analyze no_std"
ptime -m cargo clippy --no-default-features --all-targets -- --deny warnings

header "test"
ptime -m cargo test

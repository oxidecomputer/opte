#!/bin/bash
#:
#: name = "opte-ioctl"
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

cd lib/opte-ioctl

header "check style"
ptime -m cargo +$NIGHTLY fmt -- --check

header "analyze"
ptime -m cargo clippy --all-targets -- --deny warnings

#!/bin/bash
#:
#: name = "opte-ioctl"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "nightly-2023-10-23"
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

cd lib/opte-ioctl

header "check style"
ptime -m cargo +nightly-2023-10-23 fmt -- --check

header "analyze"
ptime -m cargo clippy --all-targets

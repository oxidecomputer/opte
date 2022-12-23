#!/bin/bash
#:
#: name = "opte-ioctl"
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

cd opte-ioctl

header "check style"
ptime -m cargo +nightly fmt -- --check

header "analyze"
ptime -m cargo check

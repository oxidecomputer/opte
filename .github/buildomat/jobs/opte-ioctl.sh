#!/bin/bash
#:
#: name = "opte-ioctl"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "nightly-2024-05-12"
#: output_rules = []
#: access_repos = [
#:  "oxidecomputer/illumos-rs",
#: ]
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

header "analyze"
ptime -m cargo clippy --all-targets

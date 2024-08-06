#!/bin/bash
#:
#: name = "lint"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "nightly-2024-06-27"
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

header "check style"
ptime -m cargo xtask fmt --check

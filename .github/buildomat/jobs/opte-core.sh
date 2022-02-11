#!/bin/bash
#:
#: name = "opte-core"
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

cd opte-core

header "check style"
ptime -m cargo +nightly fmt -- --check

header "analyze"
ptime -m cargo +nightly check

header "analyze no_std"
ptime -m cargo +nightly check --no-default-features

header "debug build"
ptime -m cargo +nightly build

header "debug build no_std"
ptime -m cargo +nightly build --no-default-features

header "release build"
ptime -m cargo +nightly build --release

header "release build no_std"
ptime -m cargo +nightly build --release --no-default-features

header "test"
ptime -m cargo +nightly test

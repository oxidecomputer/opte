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

header "check docs"
#
# I believe this means any doc warnings in deps will cause this to
# fail. Using a more targeted approach in the future might be nice.
#
RUSTDOCFLAGS="-D warnings" ptime -m \
	    cargo doc --no-default-features --features=api,engine,kernel

header "analyze std + api"
ptime -m cargo check

header "analyze no_std + engine + kernel"
ptime -m cargo check --no-default-features --features engine,kernel

header "test"
ptime -m cargo test

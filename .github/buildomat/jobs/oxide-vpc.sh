#!/bin/bash
#:
#: name = "oxide-vpc"
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

cd lib/oxide-vpc

header "check style"
ptime -m cargo +nightly fmt -- --check

header "check docs"
#
# I believe this means any doc warnings in deps will cause this to
# fail. Using a more targeted approach in the future might be nice.
#
# Use nightly which is needed for the `kernel` feature.
RUSTDOCFLAGS="-D warnings" ptime -m \
	    cargo +nightly doc --no-default-features --features=api,std,engine,kernel

header "analyze std + api + usdt"
ptime -m cargo clippy --features usdt --all-targets

header "analyze no_std + engine + kernel"
ptime -m cargo +nightly clippy --no-default-features --features engine,kernel

header "test"
ptime -m cargo test

#!/bin/bash
#:
#: name = "oxide-vpc"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "nightly-2024-06-27"
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

pfexec pkg install clang-15

cargo --version
rustc --version

cd lib/oxide-vpc

header "check docs"
#
# I believe this means any doc warnings in deps will cause this to
# fail. Using a more targeted approach in the future might be nice.
#
# Use nightly which is needed for the `kernel` feature.
RUSTDOCFLAGS="-D warnings" ptime -m \
	    cargo +nightly-2024-06-27 doc --no-default-features --features=api,std,engine,kernel

header "analyze std + api + usdt"
ptime -m cargo clippy --features usdt --all-targets

header "analyze no_std + engine + kernel"
ptime -m cargo +nightly-2024-06-27 clippy --no-default-features --features engine,kernel

header "test"
ptime -m cargo test

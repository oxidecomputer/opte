#!/bin/bash
#:
#: name = "opte"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "nightly-2024-10-12"
#: output_rules = []
#: access_repos = [
#:  "oxidecomputer/ingot",
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

cd lib/opte

header "check style"
ptime -m cargo +nightly-2024-10-12 fmt -- --check

header "check docs"
#
# I believe this means any doc warnings in deps will cause this to
# fail. Using a more targeted approach in the future might be nice.
#
# Use nightly which is needed for the `kernel` feature.
RUSTDOCFLAGS="-D warnings" ptime -m \
	    cargo +nightly-2024-10-12 doc --no-default-features --features=api,std,engine,kernel

header "analyze std + api"
ptime -m cargo clippy --all-targets

header "analyze no_std + engine + kernel"
ptime -m cargo +nightly-2024-10-12 clippy --no-default-features --features engine,kernel

header "test"
ptime -m cargo test

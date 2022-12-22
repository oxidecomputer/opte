#!/bin/bash
#:
#: name = "oxide-vpc"
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

cd oxide-vpc

header "check style"
ptime -m cargo +nightly fmt -- --check

header "check docs"
#
# I believe this means any doc warnings in deps will cause this to
# fail. Using a more targeted approach in the future might be nice.
#
RUSTDOCFLAGS="-D warnings" ptime -m \
	    cargo doc --no-default-features --features=api,std,engine,kernel

header "analyze std + api + usdt"
ptime -m cargo check --features usdt

header "analyze no_std + engine + kernel"
ptime -m cargo check --no-default-features --features engine,kernel

header "test"
ptime -m cargo test

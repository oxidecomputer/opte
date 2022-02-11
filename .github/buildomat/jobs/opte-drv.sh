#!/bin/bash
#:
#: name = "opte-drv"
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

cd opte-drv

header "check style"
ptime -m cargo +nightly fmt -- --check

header "analyze"
ptime -m cargo +nightly check

#
# XXX This might be something that should be controlled by buildomat
# itself through the config above. But for now I'll try to do it here.
#
# This is required for the unstable buid-std feature to work.
#
header "install rust-src"
ptime -m rustup component add rust-src --toolchain nightly

header "debug build"
ptime -m cargo +nightly -v rustc -Z build-std=core,alloc \
      --target x86_64-unknown-unknown.json
ld -r -dy -N"drv/mac" -z allextract \
   target/x86_64-unknown-unknown/debug/opte.a -o opte.debug

header "release build"
ptime -m cargo +nightly -v rustc -Z build-std=core,alloc \
      --target x86_64-unknown-unknown.json --release
ld -r -dy -N"drv/mac" -z allextract \
   target/x86_64-unknown-unknown/release/opte.a -o opte

#
# XXX Inspect kernel module for bad relocations in case old codegen
# issue ever shows its face again.
#

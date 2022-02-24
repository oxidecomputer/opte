#!/bin/bash
#:
#: name = "opte-xde"
#: variety = "basic"
#: target = "helios"
#: rust_toolchain = "nightly"
#: output_rules = [
#:   "/work/debug/*",
#:   "/work/release/*",
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

pushd xde

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

header "compile xde"
ptime -m ./compile.sh
ptime -m ./link.sh

for x in debug release
do
    mkdir -p /work/$x
done

cp xde /work/release/

header "compile opteadm"
popd
pushd opteadm
ptime -m cargo +nightly build
ptime -m cargo +nightly build --release

for x in debug release
do
    cp target/$x/opteadm /work/$x/
done

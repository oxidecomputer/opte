#!/bin/bash
#:
#: name = "image"
#: variety = "basic"
#: target = "helios"
#: rust_toolchain = "nightly"
#: output_rules = [
#:   "/out/*",
#: ]
#:
#: [[publish]]
#: series = "image"
#: name = "opte.tar.gz"
#: from_output = "/out/opte.tar.gz"
#:
#: [[publish]]
#: series = "image"
#: name = "opte.sha256.txt"
#: from_output = "/out/opte.sha256.txt"
#:

set -o errexit
set -o pipefail
set -o xtrace

cargo --version
rustc --version
rustup component add rust-src --toolchain nightly

banner build
pushd opteadm
ptime -m cargo build --release --verbose
popd

pushd xde
./build.sh
popd

banner image
pushd package
ptime -m cargo run

banner contents
tar tvfz out/opte.tar.gz

banner copy
pfexec mkdir -p /out
pfexec chown "$UID" /out
mv out/opte.tar.gz /out/opte.tar.gz
cd /out
digest -a sha256 opte.tar.gz > opte.sha256.txt

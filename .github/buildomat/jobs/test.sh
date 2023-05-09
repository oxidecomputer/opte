#!/bin/bash
#:
#: name = "test"
#: variety = "basic"
#: target = "lab-opte-0.22"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/*.log",
#: ]
#:

function cleanup {
    pfexec chown -R `id -un`:`id -gn` .
}
trap cleanup EXIT

set -o xtrace

cargo --version
rustc --version

uname -a
cat /etc/versions/build

dladm
ipadm

banner "install"
pkg info brand/sparse | grep -q installed
if [[ $? != 0 ]]; then
    pfexec pkg install brand/sparse
fi
pkg info entire | grep -q installed
if [[ $? != 0 ]]; then
    pfexec pkg install entire
fi

pfexec rem_drv xde
pfexec rm -f /dev/xde

set -o errexit
set -o pipefail

banner "test"
pushd xde
./build.sh
pfexec cp xde.conf /kernel/drv/
pfexec cp target/x86_64-unknown-unknown/release/xde /kernel/drv/amd64
pfexec add_drv xde
pfexec ln -s /devices/pseudo/xde@0:ctl /dev/xde
popd

pushd tests
pfexec cargo test -p opte-tests test_xde_loopback -- --nocapture

#!/bin/bash
#:
#: name = "test"
#: variety = "basic"
#: target = "lab-opte-0.22"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/*.log",
#: ]
#: skip_clone = true
#:
#: [dependencies.xde]
#: job = "opte-xde"
#:

function cleanup {
    pfexec chown -R `id -un`:`id -gn` .
}
trap cleanup EXIT

set -o xtrace

uname -a
cat /etc/versions/build

dladm
ipadm

pfexec rem_drv xde

set -o errexit
set -o pipefail

banner "prepare"
pfexec cp /input/xde/work/xde.conf /kernel/drv/
pfexec cp /input/xde/work/release/xde /kernel/drv/amd64
pfexec add_drv xde

banner "test"
pfexec chmod +x /input/xde/work/test/loopback
pfexec /input/xde/work/test/loopback --nocapture

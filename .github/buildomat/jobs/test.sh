#!/bin/bash
#:
#: name = "test"
#: variety = "basic"
#: target = "helios-2.0"
#: output_rules = [
#:   "/work/*.log",
#: ]
#:
#: [dependencies.xde]
#: job = "opte-xde"
#:

#### >>>>>>>>>>>>>>>>>>>>>>>>>>>> Local Usage >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
####
#### If you are running this locally, you must run the xde.sh job first to have
#### the artifacts at the expected spot.
####
#### <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

set -o xtrace

pfexec pkg install brand/omicron1 brand/omicron1/tools opte

if [[ -z $BUILDOMAT_JOB_ID ]]; then
    echo Note: if you are running this locally, you must run the xde.sh job first
    echo to have the artifacts at the expected spot.
    pfexec mkdir -p /input/xde
    pfexec ln -s /work /input/xde/work
fi

pfexec /usr/lib/brand/omicron1/baseline -w /var/run/brand/omicron1/baseline

function cleanup {
    pfexec chown -R `id -un`:`id -gn` .
    if [[ -z $BUILDOMAT_JOB_ID ]]; then
        pfexec rm -rf /input/xde
    fi
}
trap cleanup EXIT

function get_artifact {
    repo=$1
    series=$2
    commit=$3
    name=$4
    url=https://buildomat.eng.oxide.computer/public/file/oxidecomputer

    mkdir -p download
    pushd download
    if [[ ! -f $name ]]; then
        curl -fOL $url/$repo/$series/$commit/$name
    fi
    popd
}

banner "collect"
get_artifact softnpu image 88f5f1334364e5580fe778c44ac0746a35927351 softnpu
get_artifact sidecar-lite release 3fff53ae549ab1348b680845693e66b224bb5d2f libsidecar_lite.so
get_artifact sidecar-lite release 3fff53ae549ab1348b680845693e66b224bb5d2f scadm

if [[ $DOWNLOAD_ONLY -eq 1 ]]; then
    exit 0;
fi

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

# Multicast tests must run with --test-threads=1 because they share
# hardcoded device names (xde_test_sim0/1, xde_test_vnic0/1) that conflict
# when tests run in parallel
pfexec chmod +x /input/xde/work/test/multicast_rx
pfexec /input/xde/work/test/multicast_rx --nocapture --test-threads=1

pfexec chmod +x /input/xde/work/test/multicast_multi_sub
pfexec /input/xde/work/test/multicast_multi_sub --nocapture --test-threads=1

pfexec chmod +x /input/xde/work/test/multicast_validation
pfexec /input/xde/work/test/multicast_validation --nocapture --test-threads=1

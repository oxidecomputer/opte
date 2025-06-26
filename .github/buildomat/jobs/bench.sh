#!/bin/bash
#:
#: name = "bench"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = true
#: output_rules = [
#:   "=/work/bench-results.tgz",
#: ]
#:
#: [[publish]]
#: series = "benchmark" 
#: name = "bench-results.tgz"
#: from_output = "/work/bench-results.tgz"
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

source .github/buildomat/common.sh

pfexec pkg install brand/omicron1 opte iperf demangle flamegraph

svcadm enable /system/omicron/baseline

if [[ -z $BUILDOMAT_JOB_ID ]]; then
    echo Note: if you are running this locally, you must run the xde.sh job first
    echo to have the artifacts at the expected spot.
    pfexec mkdir -p /input/xde
    pfexec ln -s /work /input/xde/work
fi

function cleanup {
    pfexec chown -R `id -un`:`id -gn` .
    if [[ -z $BUILDOMAT_JOB_ID ]]; then
        pfexec rm -rf /input/xde
    fi
}
trap cleanup EXIT

function get_artifact {
    local curl_res

    repo=$1
    series=$2
    commit=$3
    name=$4
    url=https://buildomat.eng.oxide.computer/public/file/oxidecomputer

    mkdir -p download
    pushd download
    if [[ ! -f $name ]]; then
        curl -fOL $url/$repo/$series/$commit/$name
        curl_res=$?
    fi
    popd

    return $curl_res
}

OUT_DIR=/work/bench-results

mkdir -p $OUT_DIR
mkdir -p target/criterion
mkdir -p target/xde-bench

banner "collect"

# If we're on a PR, compare against master.
# If we're on master, compare against our parent.
BASELINE_COMMIT=`cat .git/refs/heads/master`
if [[ $GITHUB_BRANCH == "master" ]]; then
    BASELINE_COMMIT=`git log --pretty=%P -n 1 "$GITHUB_BRANCH"`
fi

if get_artifact opte benchmark $BASELINE_COMMIT bench-results.tgz; then
    # Illumos tar seems to lack --strip/--strip-components.
    tar -xf download/bench-results.tgz -C target
    mv target/bench-results/* target/
    rm -r target/bench-results
else
    echo "Baseline results not found for branch 'master'. Running without comparison."
fi

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

banner "bench"
cargo kbench local -b omicron1
cargo ubench

cp -r target/criterion $OUT_DIR
cp -r target/xde-bench $OUT_DIR

pushd /work
tar -caf bench-results.tgz bench-results
popd

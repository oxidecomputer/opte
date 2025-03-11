#!/bin/bash

# Install both toolchains required for OPTE.
# We pin to both a specific nightly *and* a stable compiler version
# due to XDE's reliance on unstable features.
rustup show active-toolchain || rustup toolchain install

pushd xde
rustup show active-toolchain || rustup toolchain install
export NIGHTLY=`rustup show active-toolchain -v | head -n 1 | cut -d' ' -f1`
popd

function header {
	echo "# ==== $* ==== #"
}

function install_pkg {
    set +o errexit
    pfexec pkg install $1
    exit_code=$?
    # 4 is the exit code returned from pkg when the package is already installed
    if [[ $exit_code -ne 0 ]] && [[ $exit_code -ne 4 ]]; then
        echo "package install failed for $1"
        exit 1
    fi
    set -o errexit
}

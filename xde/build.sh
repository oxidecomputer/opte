#!/bin/bash

set -xe

REL_DIR=../target/x86_64-unknown-unknown/release/

cargo -v build --release

ld -ztype=kmod \
   -N"drv/mac" \
   -N"drv/ip" \
   -N"misc/mac" \
   -N"misc/dls" \
   -N"misc/dld" \
   -z allextract $REL_DIR/xde.a \
   -o $REL_DIR/xde

# Also build devfsadm plugin
pushd xde-link
cargo -v build --release


# We don't want to panic in the devfsadm plugin but enforcing that
# is a bit tricky.  For now, just manually verify w/ nm:
set +e
nm ../../target/i686-unknown-illumos/release/libxde_link.so | grep panicking
if [ $? -eq 0 ]; then
    echo "ERROR: devfsadm plugin may panic!"
    exit 1
fi
popd

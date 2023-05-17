#!/bin/bash

REL_DIR=target/x86_64-unknown-unknown/release/

cargo -v rustc \
      -Z build-std=core,alloc \
      --target x86_64-unknown-unknown.json \
      --release

ld -ztype=kmod \
   -N"drv/mac" \
   -N"drv/ip" \
   -N"misc/mac" \
   -N"misc/dls" \
   -N"misc/dld" \
   -z allextract $REL_DIR/xde.a \
   -o $REL_DIR/xde

# Also build devfsadm plugin
cargo -v build \
    --release \
    --manifest-path xde-link/Cargo.toml \
    -Z build-std=core \
    --target xde-link/i686-unknown-illumos.json

# We don't want to panic in the devfsadm plugin but enforcing that
# is a bit tricky.  For now, just manually verify w/ nm:
nm xde-link/target/i686-unknown-illumos/release/libxde_link.so | grep rust_begin_unwind
if [ $? -eq 0 ]; then
    echo "ERROR: devfsadm plugin may panic!"
    exit 1
fi

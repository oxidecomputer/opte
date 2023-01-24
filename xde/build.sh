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
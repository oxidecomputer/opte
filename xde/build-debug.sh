#!/bin/bash

DBG_DIR=target/x86_64-unknown-unknown/debug/

cargo -v rustc \
      -Z build-std=core,alloc \
      --target x86_64-unknown-unknown.json

ld -ztype=kmod \
   -N"drv/mac" \
   -N"drv/ip" \
   -N"misc/mac" \
   -N"misc/dls" \
   -N"misc/dld" \
   -z allextract $DBG_DIR/xde.a \
   -o $DBG_DIR/xde.dbg

# Also build devfsadm plugin
cargo -v build \
    --manifest-path xde-link/Cargo.toml \
    -Z build-std=core \
    --target xde-link/i686-unknown-illumos.json
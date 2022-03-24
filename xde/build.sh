#!/bin/bash

REL_DIR=target/x86_64-unknown-unknown/release/

cargo +nightly -v rustc -Z build-std=core,alloc --target x86_64-unknown-unknown.json --release
ld -ztype=kmod \
   -N"drv/mac" \
   -N"drv/ip" \
   -N"misc/mac" \
   -N"misc/dls" \
   -N"misc/dld" \
   -z allextract $REL_DIR/xde.a \
   -o $REL_DIR/xde

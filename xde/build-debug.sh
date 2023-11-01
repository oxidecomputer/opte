#!/bin/bash

DBG_DIR=../target/x86_64-unknown-unknown/debug/

cargo -v build

ld -ztype=kmod \
   -N"drv/mac" \
   -N"drv/ip" \
   -N"misc/mac" \
   -N"misc/dls" \
   -N"misc/dld" \
   -z allextract $DBG_DIR/xde.a \
   -o $DBG_DIR/xde.dbg

# Also build devfsadm plugin
pushd xde-link
cargo -v build
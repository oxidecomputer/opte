#!/bin/bash

ld -r -dy \
    -N"drv/mac" \
    -N"drv/ip" \
    -N"misc/mac" \
    -N"misc/dls" \
    -N"misc/dld" \
    -z allextract target/x86_64-unknown-unknown/release/xde.a \
    -o xde

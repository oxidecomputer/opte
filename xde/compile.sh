#!/bin/bash

cargo +nightly -v rustc -Z build-std=core,alloc --target x86_64-unknown-unknown.json --release

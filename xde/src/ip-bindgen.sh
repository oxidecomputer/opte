#!/bin/bash

if [[ -z "$ILLUMOS_GATE" ]]; then
    echo "Must set ILLUMOS_GATE environment variable to gate source dir"
    exit 1
fi

export LD_LIBRARY_PATH=/opt/ooce/clang-12.0/lib/ 

bindgen ip.h \
    --no-layout-tests \
    --ctypes-prefix=illumos_sys_hdrs \
    --use-core \
    -- \
    -I$ILLUMOS_GATE/usr/src/uts/common \
    -D_KERNEL \
    > ip.rs

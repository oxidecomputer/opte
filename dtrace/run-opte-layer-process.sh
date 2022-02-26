#!/bin/bash
MYDIR=$(dirname "$0")

dtrace -L $MYDIR/lib -I $MYDIR -Cqs $MYDIR/opte-layer-process.d

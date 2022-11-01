#!/bin/sh
#
# This script assumes you are running it from the opte/pkg dir.

grep 'API_VERSION' ../opte-api/src/lib.rs | awk '{ print $6 }' | sed 's/;//'

#!/bin/bash

# This script can be helpful for catching issues locally before paying the CI
# tax.

./.github/buildomat/jobs/opte.sh
./.github/buildomat/jobs/opteadm.sh
./.github/buildomat/jobs/test.sh
./.github/buildomat/jobs/xde.sh
./.github/buildomat/jobs/oxide-vpc.sh

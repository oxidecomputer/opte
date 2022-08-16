#!/bin/bash
#
# Verify that the last commit incremented the API_VERSION.
git log -p -1 | awk -f check-api-version.awk

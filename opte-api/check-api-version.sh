#!/bin/bash
#
# If there is a change to an opte-api source file in the last commit,
# then verify that the API_VERSION value has increased.
if git log -1 -p master..HEAD | grep '^diff.*opte-api/src'
then
	git log -p -1 master..HEAD | awk -f check-api-version.awk
fi

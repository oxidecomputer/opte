#!/bin/bash
#
# If there is a change to an opte-api source file relative to the `master`
# branch, # then verify that the API_VERSION value has increased.
if git diff master..HEAD | grep '^diff.*opte-api/src'
then
	git diff master..HEAD | awk -f check-api-version.awk
fi

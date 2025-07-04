#!/usr/bin/env bash

set -eu -o pipefail

echo ">>> Listing files in Azure"

az storage blob list --auth-mode login --container demo --account-name kubeconna24demo | jq ".[0].name"

echo ">>> Showing contents of test.txt"

az storage blob download --no-progress --name test.txt --file /tmp/test-azure.txt --container demo --account-name kubeconna24demo --auth-mode login >/dev/null

cat /tmp/test-azure.txt

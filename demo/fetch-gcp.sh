#!/usr/bin/env bash

set -eu -o pipefail

echo ">>> Listing files in GCP"

gcloud storage ls gs://demo-venafi-testbucket

sleep 2

echo ">>> Showing contents of test.txt"

gcloud storage cat gs://demo-venafi-testbucket/test.txt

#!/usr/bin/env bash

set -eu -o pipefail

echo ">>> Listing files in AWS"

aws s3 ls s3://kubeconna24-testbucket

sleep 2

echo ">>> Showing contents of test.txt"

aws s3 cp s3://kubeconna24-testbucket/test.txt /tmp/test-aws.txt
cat /tmp/test-aws.txt

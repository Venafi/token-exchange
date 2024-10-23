#!/usr/bin/env bash

set -eu -o pipefail

kind create cluster --name token-exchange

make kind-load
make kind-load-deps
make kind-setup

#!/usr/bin/env bash

set -eu -o pipefail

cert_yaml=_bin/root.yaml

if [[ ! -f $cert_yaml ]]; then
	echo "Expected $cert_yaml to exist; exiting"
	exit 1
fi

kind delete clusters token-exchange || :
kind create cluster --name token-exchange

make kind-load
make kind-load-deps
make kind-setup

kubectl apply -f $cert_yaml

kubectl apply -f infrastructure/deployment.yaml

kubectl apply -f infrastructure/clientcert.yaml

kubectl wait --for=condition=Ready certificates/client-cert

kubectl get -n default secrets client-cert -ojson | jq -r '.data."tls.crt"' | base64 -d > _bin/client.crt
kubectl get -n default secrets client-cert -ojson | jq -r '.data."tls.key"' | base64 -d > _bin/client.key

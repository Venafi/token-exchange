#!/usr/bin/env bash

set -eu -o pipefail

cert_yaml=_bin/root.yaml
secretkey_yaml=_bin/secretkey.yaml

if [[ ! -f $cert_yaml ]]; then
	echo "Expected $cert_yaml to exist; exiting"
	exit 1
fi

if [[ ! -f $secretkey_yaml ]]; then
	echo "Expected $secretkey_yaml to exist; exiting"
	exit 1
fi

kind delete clusters token-exchange || :
kind create cluster --name token-exchange

make kind-load
make kind-load-deps
make kind-setup

kubectl apply -f $cert_yaml

kubectl get -n cert-manager secrets root-secret -ojson | jq -r '.data."tls.crt"' | base64 -d > _bin/root.crt

kubectl create -n cert-manager configmap root-cert-trust --from-file=root.pem=_bin/root.crt -oyaml --dry-run=client | kubectl apply -f -

kubectl apply -f infrastructure/deployment.yaml

kubectl apply -f $secretkey_yaml

kubectl apply -f infrastructure/clientcert.yaml

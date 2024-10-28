MAKEFLAGS += --warn-undefined-variables --no-builtin-rules
SHELL := /usr/bin/env bash
.SHELLFLAGS := -uo pipefail -c
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
.SUFFIXES:
FORCE:

ctr ?= docker

kind_cluster ?= token-exchange

bindir := _bin

host := $(shell go env GOARCH)

# cmd/token-exchange/main.go must go first
deps := cmd/token-exchange/main.go go.mod go.sum $(wildcard srvtool/*.go) $(wildcard tokenserver/*.go) $(wildcard wellknownserver/*.go) $(wildcard internal/rsagen/*.go)

.PHONY: build
build: $(bindir)/token-exchange

$(bindir)/token-exchange: $(deps) | $(bindir)
	CGO_ENABLED=0 go build -o $@ $<

.PHONY: build-linux-amd64
build-linux-amd64: $(bindir)/release/token-exchange-linux-amd64

.PHONY: build-linux-arm64
build-linux-arm64: $(bindir)/release/token-exchange-linux-arm64

$(bindir)/release/token-exchange-linux-amd64: $(deps) | $(bindir)/release
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $@ $<

$(bindir)/release/token-exchange-linux-arm64: $(deps) | $(bindir)/release
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o $@ $<

.PHONY: container-linux-amd64
container-linux-amd64: Containerfile $(bindir)/release/token-exchange-linux-amd64
	$(ctr) build -t cert-manager.local/token-exchange -f Containerfile --build-arg TARGETARCH=amd64 ./$(bindir)/release

.PHONY: container-linux-arm64
container-linux-arm64: Containerfile $(bindir)/release/token-exchange-linux-arm64
	$(ctr) build -t cert-manager.local/token-exchange -f Containerfile --build-arg TARGETARCH=arm64 ./$(bindir)/release

.PHONY: kind-load
kind-load: container-linux-$(host)
	kind load docker-image --name $(kind_cluster) cert-manager.local/token-exchange:latest

CERT_MANAGER_VERSION=v1.16.1
TRUST_MANAGER_VERSION=v0.12.0
CSI_DRIVER_SPIFFE_VERSION=v0.8.1

.PHONY: cluster
cluster:
	./cluster.sh

.PHONY: kind-load-deps
kind-load-deps:
	docker pull quay.io/jetstack/cert-manager-controller:$(CERT_MANAGER_VERSION)
	docker pull quay.io/jetstack/cert-manager-webhook:$(CERT_MANAGER_VERSION)
	docker pull quay.io/jetstack/cert-manager-acmesolver:$(CERT_MANAGER_VERSION)
	docker pull quay.io/jetstack/cert-manager-cainjector:$(CERT_MANAGER_VERSION)
	docker pull quay.io/jetstack/cert-manager-startupapicheck:$(CERT_MANAGER_VERSION)
	docker pull quay.io/jetstack/trust-manager:$(TRUST_MANAGER_VERSION)
	docker pull quay.io/jetstack/cert-manager-package-debian:20210119.0
	docker pull quay.io/jetstack/cert-manager-csi-driver-spiffe:$(CSI_DRIVER_SPIFFE_VERSION)
	docker pull quay.io/jetstack/cert-manager-csi-driver-spiffe-approver:$(CSI_DRIVER_SPIFFE_VERSION)
	kind load docker-image --name $(kind_cluster) quay.io/jetstack/cert-manager-controller:$(CERT_MANAGER_VERSION)
	kind load docker-image --name $(kind_cluster) quay.io/jetstack/cert-manager-webhook:$(CERT_MANAGER_VERSION)
	kind load docker-image --name $(kind_cluster) quay.io/jetstack/cert-manager-acmesolver:$(CERT_MANAGER_VERSION)
	kind load docker-image --name $(kind_cluster) quay.io/jetstack/cert-manager-cainjector:$(CERT_MANAGER_VERSION)
	kind load docker-image --name $(kind_cluster) quay.io/jetstack/cert-manager-startupapicheck:$(CERT_MANAGER_VERSION)
	kind load docker-image --name $(kind_cluster) quay.io/jetstack/trust-manager:$(TRUST_MANAGER_VERSION)
	docker pull quay.io/jetstack/cert-manager-package-debian:20210119.0
	kind load docker-image --name $(kind_cluster) quay.io/jetstack/cert-manager-csi-driver-spiffe:$(CSI_DRIVER_SPIFFE_VERSION)
	kind load docker-image --name $(kind_cluster) quay.io/jetstack/cert-manager-csi-driver-spiffe-approver:$(CSI_DRIVER_SPIFFE_VERSION)

.PHONY: kind-setup
kind-setup:
	helm install cert-manager jetstack/cert-manager \
		--namespace cert-manager \
		--create-namespace \
		--version $(CERT_MANAGER_VERSION) \
		--set crds.enabled=true
	helm install trust-manager jetstack/trust-manager \
		--version $(TRUST_MANAGER_VERSION) \
		--namespace cert-manager \
		--set "defaultPackageImage.tag=20210119.0" \
		--wait
	helm install cert-manager-csi-driver-spiffe jetstack/cert-manager-csi-driver-spiffe --wait \
		--namespace cert-manager \
		--version $(CSI_DRIVER_SPIFFE_VERSION) \
		--set "app.logLevel=1" \
		--set "app.trustDomain=my.trust.domain" \
		--set "app.issuer.name=" \
		--set "app.issuer.kind=" \
		--set "app.issuer.group=" \
		--set "app.runtimeIssuanceConfigMap=spiffe-issuer"

.PHONY: port-forward-token
port-forward-token:
	kubectl port-forward -n token-exchange $(shell kubectl get pods -n token-exchange -l app=token-exchange -ojson | jq -r '.items[0].metadata.name') 9966:9966

.PHONY: port-forward-wellknown
port-forward-wellknown:
	kubectl port-forward -n token-exchange $(shell kubectl get pods -n token-exchange -l app=token-exchange -ojson | jq -r '.items[0].metadata.name') 9119:9119

curl_flags=-sS --cacert infrastructure/root.pem

.PHONY: get-token
get-token:
	curl $(curl_flags) --cert _bin/client.crt --key _bin/client.key \
		-XPOST \
		-d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token_type=urn:ietf:params:oauth:token-type:tls-client-auth&aud=abc123" \
		https://localhost:9966/token \
		| jq

.PHONY: get-openid-configuration
get-openid-configuration:
	curl $(curl_flags) \
		https://localhost:9119/.well-known/78eb04b2a5e9b4a1e6f4bd4d31dcca7937ec1acb12c53f52e433adbfcfbcf178/openid-configuration \
		| jq

.PHONY: get-jwks
get-jwks:
	curl $(curl_flags) \
		https://localhost:9119/.well-known/78eb04b2a5e9b4a1e6f4bd4d31dcca7937ec1acb12c53f52e433adbfcfbcf178/jwks \
		| jq

$(bindir) $(bindir)/release:
	mkdir -p $@

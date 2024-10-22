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

# cmd/token-exchange/main.go must go first
deps := cmd/token-exchange/main.go go.mod go.sum $(wildcard srvtool/*.go) $(wildcard tokenserver/*.go) $(wildcard wellknownserver/*.go)

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
kind-load:
	kind load docker-image --name $(kind_cluster) cert-manager.local/token-exchange:latest

.PHONY: kind-load-deps
kind-load-deps:
	docker pull quay.io/jetstack/cert-manager-controller:v1.16.1
	docker pull quay.io/jetstack/cert-manager-webhook:v1.16.1
	docker pull quay.io/jetstack/cert-manager-acmesolver:v1.16.1
	docker pull quay.io/jetstack/cert-manager-cainjector:v1.16.1
	docker pull quay.io/jetstack/cert-manager-startupapicheck:v1.16.1
	docker pull quay.io/jetstack/trust-manager:v0.12.0
	docker pull quay.io/jetstack/cert-manager-csi-driver-spiffe:v0.8.1
	docker pull quay.io/jetstack/cert-manager-csi-driver-spiffe-approver:v0.8.1
	kind load docker-image --name $(kind_cluster) quay.io/jetstack/cert-manager-controller:v1.16.1
	kind load docker-image --name $(kind_cluster) quay.io/jetstack/cert-manager-webhook:v1.16.1
	kind load docker-image --name $(kind_cluster) quay.io/jetstack/cert-manager-acmesolver:v1.16.1
	kind load docker-image --name $(kind_cluster) quay.io/jetstack/cert-manager-cainjector:v1.16.1
	kind load docker-image --name $(kind_cluster) quay.io/jetstack/cert-manager-startupapicheck:v1.16.1
	kind load docker-image --name $(kind_cluster) quay.io/jetstack/trust-manager:v0.12.0
	kind load docker-image --name $(kind_cluster) quay.io/jetstack/cert-manager-csi-driver-spiffe:v0.8.1
	kind load docker-image --name $(kind_cluster) quay.io/jetstack/cert-manager-csi-driver-spiffe-approver:v0.8.1

.PHONY: kind-setup
kind-setup:
	helm install cert-manager jetstack/cert-manager \
		--namespace cert-manager \
		--create-namespace \
		--version v1.16.1 \
		--set crds.enabled=true
	helm upgrade trust-manager jetstack/trust-manager \
		--install \
		--namespace cert-manager \
		--wait
	helm upgrade -i -n cert-manager cert-manager-csi-driver-spiffe jetstack/cert-manager-csi-driver-spiffe --wait \
		--set "app.logLevel=1" \
		--set "app.trustDomain=my.trust.domain" \
		--set "app.issuer.name=" \
		--set "app.issuer.kind=" \
		--set "app.issuer.group=" \
		--set "app.runtimeIssuanceConfigMap=spiffe-issuer"

$(bindir)/release:
	mkdir -p $@

$(bindir):
	mkdir -p $@





.PHONY: build-testserver
build-testserver: $(bindir)/testserver

$(bindir)/testserver: $(wildcard cmd/testserver/*.go) $(deps) $(wildcard testserver/*.go) | $(bindir)
	CGO_ENABLED=0 go build -o $@ cmd/testserver/main.go

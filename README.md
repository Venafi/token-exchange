# token-exchange

This is the sister repo with demo code from our KubeCon NA 2024 talk in Salt Lake City, UT: [SPIFFE the Easy Way: Universal X509 and JWT Identities Using cert-manager](https://kccncna2024.sched.com/event/1i7rz).

## Running Locally

You'll need a root certificate to be configured; you can create this in any Kubernetes cluster running cert-manager by applying `infrastructure/spiffe_roots.yaml`.

Once created, you can extract the root using kubectl.

For example:

```text
kubectl apply -f infrastructure/spiffe_roots.yaml
mkdir _bin
kubectl get -n spiffe-roots-gen secrets root-secret-1 -oyaml > _bin/root.yaml
# Manually edit the file to remove:
# - metadata.annotations
# - metadata.labels
# - metadata.resourceVersion
# - metadata.uid
# - metadata.creationTimestamp
# Also change:
# - metadata.name to "root-secret"
# - metadata.namespace to "cert-manager"
```

Additionally, you'll need to create a 32 byte secret key. You can do this with:

```text
kubectl -n token-exchange create secret generic token-exchange-secret-key --from-literal=key=$(openssl rand -base64 32) -oyaml --dry-run=client > _bin/secretkey.yaml
```

Once completed, you can run `make cluster` to create a kind cluster running the example.

# Kubernetes

In a cluster, workloads need no key of their own: each pod proves who it is with its projected
service account token, and the issuer trusts the cluster's service account issuer as an upstream.
One rule maps every service account to a SPIFFE ID:

```yaml
rules:
  - require: [kubernetes.io/pod/name]
    spiffe_id: spiffe://example.org/ns/{kubernetes.io/namespace}/sa/{kubernetes.io/serviceaccount/name}
```

Nothing has to be registered per workload, so there is no operator and no custom resource; a new
service account has an identity the moment it exists. As written, that is every service account in
the cluster, `kube-system` included; narrow the rule with `match` (on `kubernetes.io/namespace`, for
one) if not all of them should get a JWT-SVID.

`require: [kubernetes.io/pod/name]` accepts only tokens bound to a pod running as that service
account, which is what the kubelet projects. That stops a plain `kubectl create token`, but anyone
allowed to create service account tokens can still bind one to an existing pod by hand
(`--bound-object-kind Pod`) and exchange it from anywhere; treat permission to create tokens as
permission to use the identity. The issuer also refuses tokens meant to live longer than an hour
(`max_token_lifetime`), so such a token is short-lived.

The issuer verifies tokens offline, against the cluster's published keys, so it does not notice when
a pod is deleted: a token taken from a pod keeps working until it expires, at most an hour later.

## The issuer

The manifests refer to the image `ghcr.io/petersr/spiffex:latest`. Until releases publish it, build
the image from a checkout and push it somewhere your cluster pulls from, then change the `image:`
lines:

```bash
docker build -t registry.example.org/spiffex:dev .
docker push registry.example.org/spiffex:dev
```

[deploy/kubernetes/issuer.yaml](../deploy/kubernetes/issuer.yaml) runs two issuer replicas behind a
Service at `https://spiffex-issuer.spiffex.svc`. It needs two Secrets first:

```bash
mkdir keys && spiffex key add -dir keys
kubectl create namespace spiffex
kubectl -n spiffex create secret generic spiffex-signing-keys --from-file=keys
kubectl -n spiffex create secret tls spiffex-issuer-tls --cert=tls.crt --key=tls.key
kubectl apply -f deploy/kubernetes/issuer.yaml
```

The certificate must be valid for `spiffex-issuer.spiffex.svc`; cert-manager can issue and renew it,
and the issuer picks up renewals without a restart. The issuer reads the cluster's keys with its own
service account token, which the default `system:service-account-issuer-discovery` binding allows;
some distributions remove that binding, and then the issuer needs one of its own. Check the upstream
`issuer` against your cluster's (`kubectl get --raw /.well-known/openid-configuration`); managed
clusters often use a public URL there, and then `discovery: true` without a bearer token is the
simpler choice.

Both replicas sign with the keys in the Secret. Each keeps its own record of used client assertions,
so with N replicas an intercepted assertion could be replayed up to N times within its lifetime of
at most five minutes; service account token exchange is not affected, as it uses no assertions.

## A workload

[deploy/kubernetes/workload.yaml](../deploy/kubernetes/workload.yaml) adds the agent to a pod as a
native sidecar (Kubernetes 1.29 or newer). It goes in the `shop` namespace and needs the issuer's CA
there, unless the issuer's certificate comes from a public CA (then drop `-ca-file` and the
`spiffex-ca` volume):

```bash
kubectl create namespace shop
kubectl -n shop create configmap spiffex-ca --from-file=ca.crt
kubectl apply -f deploy/kubernetes/workload.yaml
```

The pod gets:

- a projected service account token with the audience `spiffex`, which only the agent mounts;
- an in-memory volume for the socket, shared with the app container;
- `SPIFFE_ENDPOINT_SOCKET=unix:///run/spiffex/agent.sock` in the app container;
- a startup probe, `spiffex health`, so the app container starts only once the agent serves a trust
  bundle. It does not check that the issuer accepts the pod's token; a misconfigured identity shows
  up as `PermissionDenied` when the app asks for a JWT-SVID.

The app then uses the JWT-SVID side of any SPIFFE library as it would with SPIRE. The pod runs both
containers as the same user, so the socket's default `0600` permissions let the app in and nothing
else.

## Trying it on kind

[test/e2e/kind.sh](../test/e2e/kind.sh) builds the image, creates a kind cluster, deploys the issuer
and three workloads from these manifests, and checks that two of them can authenticate to each other
while the third, whose token carries the wrong audience, gets nothing. It also mints tokens by hand
with `kubectl create token` and checks that the issuer refuses those not bound to a pod, and those
bound to a pod but meant to live longer than the cap. It needs docker, kind, kubectl, openssl and
Go.

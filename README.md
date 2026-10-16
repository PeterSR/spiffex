# spiffex

**SPIFFE token exchange - workload identity from a plain OAuth 2.0 issuer.**

Your services prove who they are to one issuer and get short-lived, audience-bound
[JWT-SVIDs](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md) back. Workloads keep
using the stock SPIFFE libraries through the
[Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md).
Verifiers, cloud providers included, see an ordinary OpenID Connect issuer. There is no SPIRE
server, no privileged per-node agent and no registration database to run.

## Why

SPIFFE gets the identity model right: a SPIFFE ID per workload, short-lived signed documents, trust
bundles. Getting those documents to a workload, though, has in practice meant SPIRE, with a server,
a privileged agent on every node, process inspection and registration entries to keep in sync with
what is deployed. That is the right machinery at a certain scale. Below it, most teams skip SPIFFE
and pass API keys around instead.

spiffex is the small version:

- **The issuer is an OAuth 2.0 token endpoint.** A workload authenticates with `private_key_jwt` (it
  holds a private key, the issuer knows only the public key) or exchanges a proof it already has: a
  Kubernetes service account token, a GitHub Actions OIDC token, a cloud identity token. The issuer
  maps that proof to a SPIFFE ID and signs a JWT-SVID.
- **The agent serves one workload.** It sits next to the workload as a sidecar or a local process,
  speaks the Workload API on a Unix socket and fetches tokens from the issuer. Because it serves a
  single workload, it needs no workload attestation and no privileges.
- **The issuer is also an OIDC issuer.** It publishes OIDC discovery, a JWKS and a SPIFFE bundle
  endpoint, so API gateways, SPIFFE libraries and cloud federation (AWS `AssumeRoleWithWebIdentity`,
  within the limits in [SPEC.md section 11](SPEC.md#11-notes-for-aws-federation)) verify its tokens
  without any extra component.

## How it decides who is who

The issuer's **state** is one YAML document, which it rereads while it runs:

- An **origin** is one way identities come in: a Kubernetes cluster, GitHub Actions, a set of
  machines that hold keys. Each origin owns a path, so the cluster `prod` issues
  `spiffe://example.org/prod/ns/shop/sa/billing` and no other origin can issue anything under
  `/prod`.
- A **provider** describes a kind of origin: what counts as proof, who is admitted, how IDs are
  named. spiffex ships `keys`, `kubernetes`, `github`, `gitlab` and `oidc` as plain documents, and
  you can write your own, including ones that hand the proof to a verifier program you install.
- **Grants** let SPIFFE identities change the state through a management API, each on part of the
  path tree. Nobody is an administrator by configuration, and no grant lets its holder become
  someone with more.

<!-- check: state -->
```yaml
origins:
  prod:
    provider: kubernetes
  ci:
    provider: github
    with: { owner_id: "1234567", refs: [refs/heads/main] }
```

A new issuer starts with an empty state, which admits nobody.

## Install

Each release, listed on [the releases page](https://github.com/PeterSR/spiffex/releases), comes as:

- **Binaries** for Linux and macOS, amd64 and arm64: download the archive for your platform,
  `checksums.txt` and its signature, and verify them ([RELEASING.md](RELEASING.md#verifying-a-release))
  before unpacking `spiffex`.
- **An image**, `ghcr.io/petersr/spiffex:v0.1.1`, for `linux/amd64` and `linux/arm64`, distroless
  and running as a non-root user. Pin it by digest once you have verified it.
- **A Helm chart** for the issuer, `oci://ghcr.io/petersr/charts/spiffex`:

  ```bash
  helm install spiffex-issuer oci://ghcr.io/petersr/charts/spiffex --version 0.1.1 \
    --namespace spiffex -f values.yaml
  ```

  [docs/kubernetes.md](docs/kubernetes.md#with-helm) and the [chart's README](charts/spiffex/README.md)
  describe its values; [deploy/kubernetes](deploy/kubernetes) has plain manifests for clusters
  without Helm.

Releases made after the repository went public are signed with cosign and carry build
provenance; releases made while it is private are unsigned. With Go 1.26 or newer,
`go install github.com/PeterSR/spiffex/cmd/spiffex@latest` builds from source.

## Try it

With Go 1.26 or newer:

```bash
git clone https://github.com/PeterSR/spiffex && cd spiffex && go build ./cmd/spiffex

./spiffex dev -dir ./td                  # a local trust domain with two workloads, dev/orders and dev/billing
./spiffex issuer -config ./td/issuer.yaml -listen 127.0.0.1:8443
```

In another terminal, get a JWT-SVID for `billing` to call `orders` with:

```bash
./spiffex token -issuer http://127.0.0.1:8443 -client-id dev/billing -key-file ./td/workloads/billing.key \
  -audience spiffe://spiffex.test/dev/orders
```

That is a plain OAuth 2.0 exchange. Workloads normally leave it to an agent and use a stock SPIFFE
library instead:

```bash
./spiffex agent -issuer http://127.0.0.1:8443 \
  -client-id dev/orders -key-file ./td/workloads/orders.key -socket ./td/orders.sock
export SPIFFE_ENDPOINT_SOCKET=unix://$PWD/td/orders.sock
```

```go
source, err := workloadapi.NewJWTSource(ctx)                // stock go-spiffe
svid, err := source.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "spiffe://spiffex.test/dev/billing"})
req.Header.Set("Authorization", "Bearer "+svid.Marshal())
```

On the receiving side, verify with the same source (`jwtsvid.ParseAndValidate(token, source,
audiences)`), with the agent's `ValidateJWTSVID`, against the issuer's bundle endpoint, or with any
OIDC library pointed at the issuer.

A workload that already holds a token from an issuer spiffex trusts needs no key at all. In the
[Kubernetes setup](docs/kubernetes.md), the agent container of the `billing` pod holds the pod's
service account token, projected for the cluster origin's audience. Trading it for a token to call
`orders` with is one RFC 8693 token exchange, here made with `spiffex token` in that container:

```bash
kubectl -n shop exec deploy/billing -c spiffex-agent -- /spiffex token \
  -issuer https://spiffex-issuer.spiffex.svc -ca-file /etc/spiffex/ca.crt \
  -subject-token-file /var/run/secrets/spiffex/token \
  -audience spiffe://example.org/cluster/ns/shop/sa/orders
```

## Documentation

- **[Configuration and operations](docs/configuration.md):** the issuer's settings, where the state
  is kept, workloads with keys, the agent's flags, rotating signing keys.
- **[Providers](docs/providers.md):** the shipped providers and their parameters, writing your own,
  verifier programs for proofs spiffex does not understand itself, and owner pinning for upstreams
  that hand tokens to anyone.
- **[Kubernetes](docs/kubernetes.md):** pods prove themselves with their service account tokens, so
  nothing is registered per workload; the agent runs as a native sidecar.
- **[Managing the state](docs/management.md):** grants, the management API, `spiffex bootstrap`
  for the first grant and `spiffex manage` as a client.
- **[Examples](examples):** a complete settings file and state for an issuer with several origins.
- **[The specification](SPEC.md):** what any spiffex issuer and agent must do.

## Relation to the SPIFFE standards

| Standard | spiffex |
|---|---|
| [SPIFFE-ID](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md) | issued and validated |
| [JWT-SVID](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md) | issued and validated |
| [Trust bundles](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md) | served as an `https_web` bundle endpoint |
| [Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md) | the JWT-SVID profile only. Without X.509-SVIDs the agent is not a complete Workload API server; use your library's JWT source. |

## Status

Early development. The [specification](SPEC.md) is a draft at version 0, and breaking changes are
possible until version 1. The first release is 0.1.0; [CHANGELOG.md](CHANGELOG.md) lists
the changes and [RELEASING.md](RELEASING.md) how releases are made and verified.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Please report suspected vulnerabilities privately, as
described in [SECURITY.md](SECURITY.md).

## Licence

[Apache-2.0](LICENSE)

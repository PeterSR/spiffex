# spiffex

**SPIFFE workload identity from a plain OAuth 2.0 issuer.**

Your services prove who they are to one issuer and get short-lived, audience-bound
[JWT-SVIDs](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md) back. Workloads keep
using the stock SPIFFE libraries through the
[Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md).
Verifiers, cloud providers included, see an ordinary OpenID Connect issuer. There is no SPIRE
server, no privileged per-node agent and no registration database to run.

> Status: early development. The [specification](SPEC.md) is a draft and the code is not yet
> released.

## Why

SPIFFE gets the identity model right: a SPIFFE ID per workload, short-lived signed documents, trust
bundles. Getting those documents to a workload, though, has in practice meant SPIRE, with a server,
a privileged agent on every node, process inspection and registration entries to keep in sync with
what is deployed. That is the right machinery at a certain scale. Below it, most teams skip SPIFFE
and pass API keys around instead.

spiffex is the small version:

- **The issuer is an OAuth 2.0 token endpoint.** A workload authenticates with `private_key_jwt`
  (it holds a private key, the issuer knows only the public key) or exchanges a token it already
  has: a Kubernetes service account token, a GitHub Actions OIDC token, a cloud identity token.
  The issuer maps that proof to a SPIFFE ID and signs a JWT-SVID.
- **The agent serves one workload.** It sits next to the workload as a sidecar or a local process,
  speaks the Workload API on a Unix socket and fetches tokens from the issuer. Because it serves a
  single workload, it needs no workload attestation and no privileges.
- **The issuer is also an OIDC issuer.** It publishes OIDC discovery, a JWKS and a SPIFFE bundle
  endpoint, so API gateways, SPIFFE libraries and cloud federation (AWS `AssumeRoleWithWebIdentity`,
  within the limits in [SPEC.md section 7](SPEC.md#7-notes-for-aws-federation)) verify its tokens
  without any extra component.

## Try it

From a checkout (`go build ./cmd/spiffex`, Go 1.25 or newer):

```bash

spiffex dev -dir ./td                    # a local trust domain with two workloads
spiffex issuer -config ./td/issuer.yaml -listen 127.0.0.1:8443
```

In another terminal, run an agent for the `orders` workload and point any SPIFFE library at it:

```bash
spiffex agent -issuer http://127.0.0.1:8443 \
  -client-id orders -key-file ./td/workloads/orders.key -socket ./td/orders.sock
export SPIFFE_ENDPOINT_SOCKET=unix://$PWD/td/orders.sock
```

```go
source, err := workloadapi.NewJWTSource(ctx)                // stock go-spiffe
svid, err := source.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "spiffe://spiffex.test/billing"})
req.Header.Set("Authorization", "Bearer "+svid.Marshal())
```

On the receiving side, verify with the same source (`jwtsvid.ParseAndValidate(token, source,
audiences)`), with the agent's `ValidateJWTSVID`, against the issuer's bundle endpoint, or with any
OIDC library pointed at the issuer. A workload that cannot run an agent can speak OAuth 2.0 itself;
`spiffex token` shows the exchange.

## Running it

- **[Configuration and operations](docs/configuration.md):** the issuer's configuration file,
  registering workloads, the agent's flags, rotating signing keys.
- **[Kubernetes](docs/kubernetes.md):** pods prove themselves with their service account tokens,
  so nothing is registered per workload; the agent runs as a native sidecar.
- **Proving identity:** with a private key per workload (`private_key_jwt`), or by exchanging a
  token from an issuer the spiffex issuer trusts: a Kubernetes cluster, GitHub Actions, a cloud
  provider.

## Relation to the SPIFFE standards

| Standard | spiffex |
|---|---|
| [SPIFFE-ID](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md) | issued and validated |
| [JWT-SVID](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md) | issued and validated |
| [Trust bundles](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md) | served as an `https_web` bundle endpoint |
| [Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md) | the JWT-SVID profile only. Without X.509-SVIDs the agent is not a complete Workload API server; use your library's JWT source. |

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Please report suspected vulnerabilities privately, as
described in [SECURITY.md](SECURITY.md).

## Licence

[Apache-2.0](LICENSE)

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

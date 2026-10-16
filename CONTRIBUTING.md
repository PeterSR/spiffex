# Contributing

Thanks for considering a contribution. spiffex aims to stay small: one issuer, one agent, a short
specification. Contributions that keep it that way are the most welcome kind.

## Repository layout

| Path | What |
|---|---|
| [SPEC.md](SPEC.md) | the specification; as much the product as the code |
| `cmd/spiffex/` | the `spiffex` command: issuer, agent, keys, a local dev setup |
| `internal/` | the implementation, one package per concern |
| `providers/` | the providers spiffex ships with, as plain provider documents |
| `schema/` | the JSON Schemas of the state document, a provider and an origin |
| `conformance/` | the interoperability matrix against stock SPIFFE and OIDC libraries |
| `docs/` | configuration, operations and Kubernetes |
| `deploy/kubernetes/` | example manifests for the issuer and a workload |
| `test/e2e/` | the end-to-end test on a kind cluster |

## Development

You need Go 1.26 or newer.

```bash
go test ./...
gofmt -l .        # must print nothing
go vet ./...
```

CI also runs `go mod tidy -diff`, staticcheck and govulncheck, and the conformance matrix, which
needs Go and [uv](https://docs.astral.sh/uv/):

```bash
conformance/run.sh
```

The end-to-end test on a kind cluster (needs docker, kind, kubectl and openssl) runs locally:

```bash
test/e2e/kind.sh
```

## The interoperability contract

spiffex has one implementation, so its promise is not parity between languages but interoperability:
**a JWT-SVID obtained through any stock SPIFFE client must verify through every supported
verification path**. The conformance matrix checks this for go-spiffe and py-spiffe clients and
plain OAuth 2.0, with one audience and with two, against go-spiffe and py-spiffe validating through
an agent and against their own bundle sources, go-spiffe against the bundle endpoint, and PyJWT
through OIDC discovery; for issuers signing with ES256 and with RS256, with more than one key
published. Every verifier must also refuse each token for the wrong audience.

That has two consequences for contributors:

- A change to what the issuer emits or the agent serves lands together with tests against stock
  client libraries.
- A change that only works with one client library is a bug, not a feature.

## Changing the specification

[SPEC.md](SPEC.md) is versioned. Anything that changes what the issuer or agent emits or accepts
should start as an issue, not a pull request. Editorial fixes can go straight to a pull request.

## Pull requests

- Keep them focused. Separate behaviour changes from refactors.
- New behaviour comes with tests.
- Add a `CHANGELOG.md` entry under `[Unreleased]` for anything a user would notice.
- Commit subjects are declarative and capitalised, with no trailing period, for example
  `Reject client assertions without a jti`.
- CI must be green.

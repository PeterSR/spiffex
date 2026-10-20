# Contributing

Thanks for considering a contribution. spiffex aims to stay small: one issuer, one agent, a short
specification. Contributions that keep it that way are the most welcome kind.

## Repository layout

| Path | What |
|---|---|
| [SPEC.md](SPEC.md) | the specification; as much the product as the code |
| `cmd/spiffex/` | the `spiffex` command: issuer, agent, keys, state tools, a management client, a local dev setup |
| `internal/` | the implementation, one package per concern |
| `providers/` | the providers spiffex ships with, as plain provider documents |
| `schema/` | the JSON Schemas of the state document, a provider and an origin |
| `conformance/` | the interoperability matrix against stock SPIFFE and OIDC libraries |
| `docs/` | configuration, providers and verifiers, Kubernetes, the management API |
| `examples/` | complete settings files and states; a test validates them and the examples in `docs/` |
| `deploy/kubernetes/` | example manifests for the issuer and a workload |
| `charts/spiffex/` | the Helm chart for the issuer; `ci/` holds the value sets its tests render |
| `test/e2e/` | the end-to-end tests on a kind cluster, with the manifests and with the chart, and for X.509-SVIDs |
| `scripts/` | release helpers |

## Development

You need Go 1.26 or newer.

```bash
go test ./...
gofmt -l .        # must print nothing
go vet ./...
```

Many tests start processes: issuers, agents, verifiers, and children of those meant to be killed
with their process group. A bug in such a test can signal processes it never started, so run tests
and the conformance matrix in a PID namespace of their own, where they can reach nothing else. On
Linux, without root:

```bash
unshare --user --map-current-user --pid --fork --mount --mount-proc sh -c 'go test -race ./...'
```

YAML blocks in `docs/` that are complete documents carry a `<!-- check: ... -->` marker on the line
before them, and `go test ./cmd/spiffex` validates them; see `docs_test.go` there for the kinds.

CI also runs `go mod tidy -diff`, staticcheck and govulncheck, and the conformance matrix, which
needs Go and [uv](https://docs.astral.sh/uv/):

```bash
conformance/run.sh
```

The end-to-end test on a kind cluster (needs docker, kind, kubectl and openssl) runs locally, with
the plain manifests and with the Helm chart (which also needs helm):

```bash
test/e2e/kind.sh
test/e2e/kind-helm.sh
test/e2e/kind-x509.sh
```

The last one tests X.509-SVIDs with a chart-installed issuer and takes about six minutes, most of it
waiting for a CA rotation to reach the workloads. It uses a kubeconfig of its own and never touches
yours.

The `Makefile` has targets for all of this; `make help` lists them. `make test`, `make e2e` and
`make e2e-helm` run in a PID namespace of their own, as above. `make lint` runs every linter CI
runs, `make helm-lint` lints and renders the chart, and `make release-snapshot` builds the release
artifacts locally. [RELEASING.md](RELEASING.md) describes releases.

## The interoperability contract

spiffex has one implementation, so its promise is not parity between languages but interoperability:
**a JWT-SVID obtained through any stock SPIFFE client must verify through every supported
verification path**. The conformance matrix checks this for go-spiffe and py-spiffe clients and
plain OAuth 2.0, with one audience and with two, against go-spiffe and py-spiffe validating through
an agent and against their own bundle sources, go-spiffe against the bundle endpoint, and PyJWT
through OIDC discovery; for issuers signing with ES256 and with RS256, with more than one key
published. Every verifier must also refuse each token for the wrong audience.

The same holds for X.509-SVIDs. The matrix gets an X.509-SVID for the billing workload six ways:
through go-spiffe and py-spiffe over the Workload API, through `spiffex token -x509` (all three a
P-256 key made by the client), and by a CSR for a P-384, an Ed25519 and an RSA-2048 key, which only
the issuer client can ask for (`conformance/goissue`). Each SVID must then be accepted by the
verifiers, which read the identity themselves, from the certificate: go-spiffe chain verification
(`x509svid.Verify`), a go-spiffe mTLS server that verifies it as a client certificate, a go-spiffe
mTLS client that verifies it as a server certificate, and the same two with Python's `ssl` module
(py-spiffe has no TLS helper and does not verify chains, so it supplies the SVID and the bundle and
`ssl` does the verifying, strictly, and `client.py` checks that the one URI SAN is in the trust
domain). The mTLS verifiers come in two forms. The first trusts the bundle an agent serves, that of
trust domain A alone, so an SVID of a second issuer in trust domain B is refused because its chain
does not verify. The `-ab` form is given the CAs of both trust domains and authorizes only trust
domain A, so only the check of the SPIFFE ID can refuse the SVID of B; it is what shows that the check
exists. Every verifier must refuse the same six kinds of SVID from the second issuer, and a server
must log a refusal of its own, not a timeout or the client's alert. A server must also refuse a client
that sends no certificate. Last, the matrix checks that each leaf has the key type it is supposed to
and names the SPIFFE ID it is supposed to. All 54 pairs are accepted, all 54 pairs with the other
trust domain's SVID are refused, and so are the four clients without a certificate:

| Verifier | P-256 (go-spiffe, py-spiffe, `token -x509`) | P-384 | Ed25519 | RSA-2048 | SVID of trust domain B |
|---|---|---|---|---|---|
| go-spiffe `x509svid.Verify` | accepted | accepted | accepted | accepted | refused (chain) |
| go-spiffe mTLS server (client certificate) | accepted | accepted | accepted | accepted | refused (chain) |
| go-spiffe mTLS server, `-ab` | accepted | accepted | accepted | accepted | refused (trust domain) |
| go-spiffe mTLS client (server certificate) | accepted | accepted | accepted | accepted | refused (chain) |
| go-spiffe mTLS client, `-ab` | accepted | accepted | accepted | accepted | refused (trust domain) |
| Python `ssl` server (client certificate) | accepted | accepted | accepted | accepted | refused (chain) |
| Python `ssl` server, `-ab` | accepted | accepted | accepted | accepted | refused (trust domain) |
| Python `ssl` client (server certificate) | accepted | accepted | accepted | accepted | refused (chain) |
| Python `ssl` client, `-ab` | accepted | accepted | accepted | accepted | refused (trust domain) |

Not covered: verifiers other than go-spiffe and OpenSSL through Python (rustls-webpki, BoringSSL and
Java would exercise the name constraints of SPEC section 2.5 in other implementations), and a CA
that is an intermediate under a root; the matrix uses a root made by `spiffex ca init`.

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

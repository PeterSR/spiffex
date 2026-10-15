# Contributing

Thanks for considering a contribution. spiffex aims to stay small: one issuer, one agent, a short
specification. Contributions that keep it that way are the most welcome kind.

## Repository layout

| Path | What |
|---|---|
| [SPEC.md](SPEC.md) | the specification; as much the product as the code |
| `internal/` | the implementation, one package per concern |

## Development

You need Go 1.25 or newer.

```bash
go test ./...
gofmt -l .        # must print nothing
go vet ./...
```

CI also runs `go mod tidy -diff`, staticcheck and govulncheck.

## The interoperability contract

spiffex has one implementation, so its promise is not parity between languages but
interoperability: **a JWT-SVID obtained through any stock SPIFFE client must verify through every
supported verification path** (the agent's `ValidateJWTSVID`, the SPIFFE bundle endpoint, and the
plain OIDC JWKS).

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

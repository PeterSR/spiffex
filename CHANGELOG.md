# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The issuer: OIDC discovery and RFC 8414 metadata, a JWKS, a SPIFFE bundle endpoint, and a token
  endpoint that issues JWT-SVIDs to workloads authenticating with `private_key_jwt`.
- Signing keys as a directory of PEM files, reloaded while running, with activation delays and
  retirement so rotation never breaks a verifier.
- The agent: the JWT-SVID half of the SPIFFE Workload API on a Unix socket, for one workload,
  backed by the issuer. Stock go-spiffe and py-spiffe clients work against it unchanged.
- Token exchange: workloads trade a token from a trusted upstream (a Kubernetes service account
  token, a GitHub Actions or cloud identity token) for a JWT-SVID, mapped to a SPIFFE ID by
  configurable rules.
- The `spiffex` command: `issuer`, `agent`, `token`, `key` (generate workload keys, add, list and
  prune signing keys) and `dev`, which sets up a local trust domain to try spiffex with. Every
  flag can also be set from the environment.
- The issuer rereads its client registrations, their key files and its TLS certificate while
  running.
- Example Kubernetes manifests, with the agent as a native sidecar started behind a
  `spiffex health` probe, and an end-to-end test on kind.
- A conformance matrix: tokens from stock go-spiffe, py-spiffe and plain OAuth 2.0 clients verify
  through go-spiffe, py-spiffe and PyJWT, through an agent, a JWT source, the bundle endpoint and
  OIDC discovery.

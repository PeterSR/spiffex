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
- The agent: the JWT-SVID half of the SPIFFE Workload API on a Unix socket, for one workload, backed
  by the issuer. Stock go-spiffe and py-spiffe clients work against it unchanged.
- Token exchange: workloads trade a token from a trusted upstream (a Kubernetes service account
  token, a GitHub Actions or cloud identity token) for a JWT-SVID. The token's issuer and audience
  select exactly one origin, whose keys verify it and whose admission and name template decide the
  SPIFFE ID.
- Exec origins: proofs spiffex does not understand itself are checked by a verifier program the
  operator installs, run without a shell, with an empty environment, in a process group of its own
  and with a deadline, within per-origin, global and per-client-address limits.
- The `spiffex` command: `issuer`, `agent`, `token`, `health`, `key` (generate workload keys and
  print their public halves; add, list and prune signing keys) and `dev`, which sets up a local
  trust domain, settings and state to try spiffex with. Every flag can also be set from the
  environment. The agent and `token` take a proof from a file or from a command run for each
  request, as a JWT or for an exec origin.
- The issuer runs on the state: workloads with keys are members of `keys` origins, with client ids
  `<origin>/<member>`, and origins may restrict the audiences their identities request. The state is
  kept in a file, a directory tree with one file per object, or a Kubernetes ConfigMap read through
  the API, and is reread while the issuer runs; an invalid state leaves the last valid one in
  service. Writes to every form are compare-and-swap, ready for the management API.
- The issuer's settings file: issuer URL, trust domain, signing keys, token lifetime (at most an
  hour), where the state lives, the files and verifiers the state may use (bearer tokens limited to
  hosts and paths), key fetching that can refuse private addresses with named exceptions, verifier
  limits, the user verifiers run as, and the proxies trusted to name clients. Unknown fields are
  refused.
- The issuer rereads its signing keys and its TLS certificate while running.
- Example Kubernetes manifests, with the state in a ConfigMap that is all the issuer may read, the agent as a native sidecar started behind a `spiffex health` probe, and an
  end-to-end test on kind.
- The state model: origins, providers and grants in one document, with the shipped `keys`,
  `kubernetes`, `github`, `gitlab` and `oidc` providers as plain provider documents, JSON Schemas
  for the state, a provider and an origin, and full offline validation, the grant closure rule
  included. `spiffex check` validates a state, a provider or an origin, `spiffex provider` lists
  and prints the shipped providers, and `spiffex explain` shows how the state would treat a subject
  token.
- A conformance matrix: tokens from stock go-spiffe, py-spiffe and plain OAuth 2.0 clients verify
  through go-spiffe, py-spiffe and PyJWT, through an agent, a JWT source, the bundle endpoint and
  OIDC discovery.

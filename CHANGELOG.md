# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The specification describes X.509-SVIDs: a certificate authority next to the JWT signing keys
  (SPEC section 2.5), X.509 authorities in the SPIFFE bundle (section 2.3), token requests that take
  a `requested_token_type` and a `csr` (section 3.4), `svid_types` on origins and providers to
  choose which kinds of SVID an origin issues (section 4.5), and a complete Workload API server in
  the agent (section 9). The state accepts and checks the new `svid_types` field on origins and
  providers, and the token endpoint refuses a JWT-SVID to an origin whose list lacks `jwt`
  (`invalid_target`, after authentication). The token endpoint does not issue X.509-SVIDs yet.
- The certificate authority for X.509-SVIDs. The settings `ca_dir`, `ca_roots`,
  `ca_roots_dedicated` and `x509_svid_ttl` give the issuer a CA, a root it holds or an intermediate
  under the operator's own root. The issuer checks every CA certificate against the profile of SPEC
  section 2.5, chooses the signing CA with the rotation rules of the signing keys, rereads the
  directory while it runs, and publishes the trust anchors in the SPIFFE bundle as X.509
  authorities (`use: x509-svid`, with `x5c`), counted into `spiffe_sequence`. The JWKS never holds
  them. The discovery document says `spiffex_x509_svid_supported: true` while a CA can sign.
  `spiffex ca init`, `csr`, `import`, `list` and `prune` make and manage the CA files.

## [0.1.3] - 2026-10-19

### Changed

- The repository is public. This is the first release signed with cosign and carrying build
  provenance; 0.1.0-rc.1 to 0.1.2 were released before the repository went public and are
  unsigned. Verifying the signatures needs cosign 3.1 or newer (RELEASING.md).

## [0.1.3-rc.1] - 2026-10-17

### Changed

- The repository is public. This is the first release signed with cosign and carrying build
  provenance; 0.1.0-rc.1 to 0.1.2 were released before the repository went public and are
  unsigned.

## [0.1.2] - 2026-10-17

### Added

- Name template placeholders take operations: `{<claim>|trim_prefix:<text>}` and
  `|trim_suffix:<text>` cut a fixed text off a claim's value before it fills the segment, so one
  origin can name the pods of the namespaces `team-a`, `team-b` and so on `teams/a`, `teams/b`. A
  value without that text is refused, so two values never get the same SPIFFE ID (SPEC section
  4.1).

### Changed

- Inside a name template placeholder, the claim path now ends at the first `|`. A template whose
  claim path contained `|` is now refused, or read as one with operations.

### Fixed

- The Helm chart refuses a grant in `state.content` whose `on` key is written bare. Helm reads YAML
  1.1, where a bare `on` is the boolean true, so the state used to get a `"true"` key in its place
  and the issuer refused it only when it started. The chart README says to quote it as `"on"`.

## [0.1.1] - 2026-10-16

### Added

- The Helm chart can add an Ingress (`ingress`) that routes every path of a host to the issuer, for
  an issuer reached from outside the cluster. The chart then requires `issuer` to be
  `https://<ingress.host>`, and with TLS in the pod as well it tells ingress-nginx to speak HTTPS to
  the issuer. The chart README explains when `trustedProxies` matters (only for exec verifiers'
  per-address limits), what to list behind an ingress, and what that trusts.
- `extraObjects` in the Helm chart renders further manifests with the release, through `tpl`, for
  instance an ExternalSecret that makes the signing key Secret; the chart README has one that takes
  every parameter under an AWS Parameter Store path.
- `state.configMapAnnotations` in the Helm chart adds annotations to the state ConfigMap, such as
  Argo CD's; `Prune=false,Delete=false` is added to any Argo CD sync options given. The chart README describes the safe Argo CD setup for the state: `ignoreDifferences`
  on its data with `RespectIgnoreDifferences=true`.

## [0.1.0] - 2026-10-16

The first stable release: everything in 0.1.0-rc.1 below, and:

### Changed

- The Helm chart spreads the issuer's replicas across nodes and, where nodes carry a zone label,
  across zones by default, as a preference (`whenUnsatisfiable: ScheduleAnyway`) so that single-node
  clusters still schedule them. `topologySpreadConstraints` replaces the default when set. The plain
  manifest in `deploy/kubernetes` does the same.

## [0.1.0-rc.1] - 2026-10-16

The first version: an issuer, an agent and the `spiffex` command, following version 0 of
[the specification](SPEC.md).

### Added

- **The issuer.** OIDC discovery and RFC 8414 metadata, a JWKS, a SPIFFE bundle endpoint, and a
  token endpoint that issues JWT-SVIDs for two grants: client credentials with `private_key_jwt`,
  and token exchange of a proof the workload already has. Signing keys are a directory of PEM
  files, reread while running, with an activation delay and retirement so that rotation never
  breaks a verifier. The TLS certificate is reloaded when it changes.
- **The state.** Origins, providers and grants in one document, kept in a file, a directory tree
  with one file per object, or a Kubernetes ConfigMap, and reread while the issuer runs. A new
  state is put in service as a whole, and an invalid one leaves the last valid state in service.
  JSON Schemas for the state, a provider and an origin, and full offline validation, the grant
  closure rule included.
- **Origins and providers.** `keys` origins for workloads that hold a private key, with client ids
  `<origin>/<member>`; `jwt` origins for tokens from upstreams such as Kubernetes and CI providers,
  whose keys are fetched within fixed limits and, by default, only from public addresses; and `exec`
  origins, whose proofs a verifier program installed by the operator checks, run without a shell
  and with a deadline, within per-origin, global and per-client-address limits. Shipped providers
  `keys`, `kubernetes`, `github`, `gitlab` and `oidc`, as plain provider documents. Shared
  upstreams must pin an owner. Origins may restrict the audiences their identities request.
- **The management API**, at `<issuer>/manage` with `management: true`. SPIFFE identities change
  origins, members, providers and grants while the issuer runs, with five-minute JWT-SVIDs for the
  management audience. Grants give `read`, `write` and `delegate` on path scopes, with no
  escalation and the closure rule enforced. Answers hide what the caller may not read, and changes
  are compare-and-swap with ETags and `If-Match`, validated as a whole and logged.
- **The issuer's settings file**: issuer URL, trust domain, signing keys, token lifetime, where the
  state lives, the local files and verifiers the state may use, key fetching, verifier limits and
  the user verifiers run as, and the proxies trusted to name clients. Unknown fields are refused.
- **The agent.** The JWT-SVID half of the SPIFFE Workload API on a Unix socket, for one workload.
  Stock go-spiffe and py-spiffe clients work against it unchanged. It proves its workload with a
  private key, or with a proof read from a file or made by a command for each request.
- **The `spiffex` command**: `issuer`, `agent`, `token`, `health` for container probes, `key` for
  workload and signing keys, `check` to validate a state, provider or origin, `provider` to read
  the shipped providers, `explain` to show how the state treats a subject token, `bootstrap` for
  the first grant, `state` to export, import and convert the stored state, `manage` as a client of
  the management API, and `dev` for a local trust domain to try spiffex with. Every flag can also
  be set from the environment.
- Example Kubernetes manifests, with the state in a ConfigMap and the agent as a native sidecar,
  and an end-to-end test on kind.
- A Helm chart for the issuer, `oci://ghcr.io/petersr/charts/spiffex`, with the settings built
  from values, the state ConfigMap written on install and never overwritten afterwards, signing
  keys and TLS from existing Secrets or TLS from cert-manager. The end-to-end test runs with it
  too.
- Releases: binaries for Linux and macOS on amd64 and arm64 with checksums and SBOMs, a
  multi-architecture image at `ghcr.io/petersr/spiffex`, and the chart, signed keylessly with
  cosign and with build provenance attested once the repository is public. RELEASING.md describes
  how to verify them. A release from a private repository is unsigned and has no attestations, so
  this one has neither.
- Documentation of configuration, providers and verifiers, Kubernetes and the management API, and
  an example multi-origin setup. A test validates the examples and the documentation's examples.
- A conformance matrix: tokens from stock go-spiffe, py-spiffe and plain OAuth 2.0 clients verify
  through go-spiffe, py-spiffe and PyJWT, through an agent, a JWT source, the bundle endpoint and
  OIDC discovery.

[Unreleased]: https://github.com/PeterSR/spiffex/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/PeterSR/spiffex/releases/tag/v0.1.3
[0.1.3-rc.1]: https://github.com/PeterSR/spiffex/releases/tag/v0.1.3-rc.1
[0.1.2]: https://github.com/PeterSR/spiffex/releases/tag/v0.1.2
[0.1.1]: https://github.com/PeterSR/spiffex/releases/tag/v0.1.1
[0.1.0]: https://github.com/PeterSR/spiffex/releases/tag/v0.1.0
[0.1.0-rc.1]: https://github.com/PeterSR/spiffex/releases/tag/v0.1.0-rc.1

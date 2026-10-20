# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Removing the last JWT signing key from `keys_dir` stops the issuer signing JWT-SVIDs, as removing
  the key of the last CA stops X.509-SVIDs. Until now the running issuer kept the removed key and went on
  signing. The issuer keeps running: the token endpoint answers a request for a JWT-SVID with
  `invalid_request`, the JWKS and the bundle publish no JWT key, discovery lists no signing
  algorithm of its own (it lists ES256 and RS256), the management API admits nobody, and X.509-SVIDs are unaffected. A key added later
  signs at once. The removal is confirmed by a second poll that also sees no key file. An issuer with a `ca_dir` also starts with an empty `keys_dir` (and logs an error);
  without a CA it still refuses to start.
- The agent, and so `spiffex token -x509`, accepts a bundle that has X.509 authorities and no JWT
  authority, and tells open `FetchJWTBundles` streams when the last JWT key is gone. A bundle with
  no authority at all (every key and CA file deleted) is served with `"keys": []`, and the agent
  takes it too. The agent forgets the cached JWT-SVIDs whose signing key has left the bundle, so
  a removed key stops being handed out to workloads as well.
- A self-signed certificate without a key that appears in `ca_dir` while the issuer runs, with the
  subject of a CA in service (also one whose files turned bad) and another key, no longer displaces that CA: it is logged and not
  published, as a self-signed CA with a key already was.

### Added

- The specification describes X.509-SVIDs: a certificate authority next to the JWT signing keys
  (SPEC section 2.5), X.509 authorities in the SPIFFE bundle (section 2.3), token requests that take
  a `requested_token_type` and a `csr` (section 3.4), `svid_types` on origins and providers to
  choose which kinds of SVID an origin issues (section 4.5), and a complete Workload API server in
  the agent (section 9). The state accepts and checks the new `svid_types` field on origins and
  providers, and the token endpoint refuses a JWT-SVID to an origin whose list lacks `jwt`
  (`invalid_target`, after authentication).
- The certificate authority for X.509-SVIDs. The settings `ca_dir`, `ca_roots`,
  `ca_roots_dedicated` and `x509_svid_ttl` give the issuer a CA, a root it holds or an intermediate
  under the operator's own root. The issuer checks every CA certificate against the profile of SPEC
  section 2.5, chooses the signing CA with the rotation rules of the signing keys, rereads the
  directory while it runs, and publishes the trust anchors in the SPIFFE bundle as X.509
  authorities (`use: x509-svid`, with `x5c`), counted into `spiffe_sequence`. The JWKS never holds
  them. The discovery document says `spiffex_x509_svid_supported: true` while a CA can sign.
  `spiffex ca init`, `csr`, `import`, `list` and `prune` make and manage the CA files.
- The token endpoint issues X.509-SVIDs. A client credentials or token exchange request with
  `requested_token_type=urn:spiffex:token-type:x509-svid` and a `csr` (DER, base64url) gets the
  certificate chain in `access_token`, for the SPIFFE ID the origin would have named in a JWT-SVID.
  Only the CSR's public key is used (ECDSA P-256 or P-384, Ed25519, or RSA of 2048 to 4096 bits);
  keys the issuer already uses are refused. The certificate has the subject `O=<trust domain>, CN=<SPIFFE ID>`, one URI
  SAN and the lifetime `x509_svid_ttl`, shortened where the CA's chain ends sooner. An origin's
  `svid_types` is enforced for X.509-SVIDs, a `csr` without the X.509 type and an unknown
  `requested_token_type` are `invalid_request`, and each certificate is logged with its serial number.
- `spiffex token -x509 -key-out FILE -cert-out FILE [-bundle-out FILE]` fetches an X.509-SVID for a
  new P-256 key made in memory, written with mode 0600 and never over an existing file.
- The agent serves X.509-SVIDs over the Workload API when the issuer has a CA. `FetchX509SVID`
  streams the workload's certificate chain, a PKCS#8 key made in memory for each certificate, and
  the trust domain's X.509 bundle; the certificate is renewed at a random 40 to 50 percent of its
  life and sent to every open stream, which all share one key, and it is never sent with under a tenth
  of its life left. The agent retries with jittered exponential backoff while the issuer is down and
  remembers an issuer's refusal for a minute (`PermissionDenied`, so a JWT-only origin keeps its
  JWT-SVIDs). `FetchX509Bundles` streams the roots, and both streams follow a root being published or
  retired. Against an issuer without a CA the X.509 calls answer `Unimplemented`; the agent rereads the
  discovery flag at each bundle refresh. `FetchJWTBundles` no longer repeats an unchanged bundle when
  only the X.509 roots changed.
- The conformance matrix covers X.509-SVIDs. SVIDs obtained through go-spiffe, py-spiffe,
  `spiffex token -x509` and, for P-384, Ed25519 and RSA-2048 keys, a new `conformance/goissue`
  command are accepted by go-spiffe chain verification and by mTLS handshakes with go-spiffe and with
  Python's `ssl` module, in both directions. Every verifier refuses the SVID of an issuer in another
  trust domain, by chain verification and, for verifiers given both CAs, by the check of the SPIFFE
  ID alone, and servers refuse a client that sends no certificate.
- `test/e2e/kind-x509.sh` (`make e2e-x509`) tests X.509-SVIDs on a kind cluster with the chart: two
  pods talk mTLS with identities from the cluster origin, a pod with the wrong audience gets none, a
  removed origin stops new certificates, and a CA rotation drops no connection and moves new
  connections to the new CA.
- The Helm chart takes a certificate authority. `ca.existingSecret` is mounted at `ca_dir` with mode
  0440 like the signing keys, `ca.roots.configMap` or `ca.roots.secret` (with `ca.roots.key`)
  supplies `ca_roots`, `ca.rootsDedicated` sets `ca_roots_dedicated`, and `x509SVIDTTL` sets
  `x509_svid_ttl`. The chart refuses roots without a CA, both kinds of roots, and
  `readableFiles` under `/ca` or `/ca-roots`. Rotating the CA is replacing the Secret; the issuer
  takes it up without a restart.
- `POST /manage/check` reports `x509_under_restriction`: the origins that list `x509` under an
  audience restriction, which does not cover their X.509-SVIDs.

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

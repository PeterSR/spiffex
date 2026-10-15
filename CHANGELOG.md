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

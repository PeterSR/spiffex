# spiffex specification

Version 0, draft. Breaking changes are possible until version 1.

This document specifies how a spiffex **issuer** hands out SPIFFE JWT-SVIDs over plain OAuth 2.0,
and how a spiffex **agent** serves them to workloads through the SPIFFE Workload API. It is
deliberately small. Anything a compliant implementation must do is in here; everything else
(configuration format, storage, command line) is an implementation detail.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 ([RFC 2119], [RFC 8174]) when, and only when, they appear in all capitals, as
shown here.

## 1. Overview

```
 workload ──Workload API──▶ agent ──OAuth 2.0 token endpoint──▶ issuer
   (go-spiffe,             (proves the        (verifies the proof, maps it
    py-spiffe, ...)         workload)          to a SPIFFE ID, signs)

 verifier ──HTTPS GET──▶ issuer: OIDC discovery, JWKS, SPIFFE bundle
```

- The **issuer** is the trust domain's only signer. Verifiers see an OpenID Connect issuer in the
  sense that federation needs: a discovery document and a JWKS that its tokens verify against. It is
  not a full OpenID Provider; there is no authorization endpoint and no end user.
- A **workload** is anything that needs an identity. It either talks to an agent through the
  Workload API, or speaks OAuth 2.0 to the issuer directly.
- An **agent** acts for exactly one workload. It holds that workload's proof of identity, fetches
  JWT-SVIDs from the issuer and serves them over the Workload API.
- A **verifier** checks JWT-SVIDs offline against the issuer's keys, fetched as a SPIFFE bundle, as
  a JWKS, or through an agent.

Terms from the SPIFFE standards ([SPIFFE-ID], [JWT-SVID], [Trust Domain and Bundle],
[Workload API]) keep their meaning here.

## 2. The issuer

An issuer is identified by its **issuer URL**: an `https` URL with no query, no fragment, no user
information and no trailing slash. An `http` URL is acceptable only for local development. A trust
domain has exactly one issuer URL and an issuer URL serves exactly one trust domain. Several
processes MAY serve the same issuer URL, provided they share one set of signing keys.

The endpoints below have fixed paths relative to the issuer URL. Clients SHOULD nevertheless take
them from the discovery document.

### 2.1 Discovery

`GET <issuer>/.well-known/openid-configuration` returns a JSON object with at least the fields
below. The issuer also serves the same object as [RFC 8414] authorization server metadata: at
`<issuer>/.well-known/oauth-authorization-server` when the issuer URL has no path, and with the
well-known segment inserted after the host when it has one
(`https://host/.well-known/oauth-authorization-server/path`).

| Field | Value |
|---|---|
| `issuer` | the issuer URL, byte for byte |
| `jwks_uri` | `<issuer>/jwks` (section 2.2) |
| `token_endpoint` | `<issuer>/token` (section 3) |
| `grant_types_supported` | the grants of section 3 the issuer accepts |
| `token_endpoint_auth_methods_supported` | `private_key_jwt` when client credentials are accepted, `none` when token exchange is |
| `token_endpoint_auth_signing_alg_values_supported` | algorithms accepted on client assertions, when client credentials are accepted |
| `id_token_signing_alg_values_supported` | algorithms the issuer signs with |
| `response_types_supported` | `["id_token"]`, for consumers that require the field |
| `subject_types_supported` | `["public"]` |
| `claims_supported` | `["iss", "sub", "aud", "exp", "iat", "jti"]` |
| `spiffe_bundle_endpoint` | `<issuer>/bundle` (section 2.3); informational |
| `spiffe_trust_domain` | the trust domain name, e.g. `example.org`; informational |

The two `spiffe_` fields are conveniences for humans and tooling. A SPIFFE federation peer MUST
configure the trust domain and bundle endpoint URL out of band, as [SPIFFE Federation] requires, and
MUST NOT take them from this document.

### 2.2 JWKS

`GET <issuer>/jwks` returns a JSON Web Key Set ([RFC 7517]) holding every key the issuer publishes:
keys it signs with now, keys it will sign with after activation, and keys that signed tokens that
may still be valid (section 2.4). Each key carries `kid`, `alg` and `use: "sig"`. This is the
endpoint for OIDC consumers: cloud federation, API gateways, generic JWT libraries.

### 2.3 SPIFFE bundle

`GET <issuer>/bundle` returns the trust domain's bundle in the format of the [Trust Domain and
Bundle] standard: the same public keys as the JWKS, each with `use: "jwt-svid"` and `kid`, plus
`spiffe_sequence` and `spiffe_refresh_hint` (seconds). It is a bundle endpoint with the `https_web`
profile of [SPIFFE Federation].

`spiffe_sequence` MUST increase whenever the published key set changes, as observed from any one
issuer process. Processes serving the same issuer URL SHOULD report the same value for the same key
set, but nothing guarantees it, so verifiers MUST NOT conclude from the sequence alone that a bundle
from one process is older than a bundle from another.

### 2.4 Signing keys and rotation

The issuer signs with ES256 (ECDSA P-256) or RS256 (RSA, at least 2048 bits). Each key's `kid` is
its [RFC 7638] JWK thumbprint computed with SHA-256, base64url-encoded without padding.

Rotation MUST NOT break a verifier that refreshes on the published hint:

1. A new key is published in the JWKS and bundle for at least the **activation delay** before the
   issuer signs with it. The delay is measured from when the issuer first publishes the key, not
   from when the key was generated. The activation delay SHOULD be at least three times the
   `spiffe_refresh_hint`, and the JWKS `Cache-Control` max-age MUST NOT exceed the refresh hint.
2. A key the issuer stopped signing with stays published for at least the maximum JWT-SVID lifetime
   after its last use, plus an allowance for clock skew.

Whenever more than one published key has completed its activation delay, the issuer signs with the
newest. When none has, as in a newly created trust domain, it signs with the key it would have used
had it been running all along, or else with the oldest key.

A compromised key is the exception to rule 2: the operator removes it at once, accepting that tokens
it signed stop verifying.

## 3. The token endpoint

`POST <issuer>/token` with an `application/x-www-form-urlencoded` body, as in [RFC 6749]. An issuer
supports at least one of the two grants below.

Both grants take `audience`. For token exchange it is the [RFC 8693] parameter; for client
credentials it is a spiffex extension with the same meaning.

| Parameter | |
|---|---|
| `audience` | REQUIRED, MAY repeat. Each distinct value becomes an `aud` entry of the JWT-SVID. At most 5 values, each non-empty and at most 512 bytes. A single audience is RECOMMENDED, as the [JWT-SVID] standard advises. |

Parameters other than `audience` and `resource` MUST appear at most once. `scope` and `resource` are
ignored. `actor_token` is rejected with `invalid_request`: spiffex does not issue delegation tokens.

The issuer MUST reject, with `invalid_target`, an audience equal to its own issuer URL or token
endpoint, so a JWT-SVID can never pass for a client assertion or exchange input aimed at the issuer
itself.

A successful response is `200` with `Content-Type: application/json`, `Cache-Control: no-store` and
the body:

```json
{
  "access_token": "<JWT-SVID>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "Bearer",
  "expires_in": 300,
  "spiffe_id": "spiffe://example.org/billing"
}
```

`spiffe_id` duplicates the token's `sub` so a client need not parse the token to learn it.

### 3.1 Errors

Errors follow [RFC 6749] section 5.2: a JSON body with `error` and optionally `error_description`.

| Situation | `error` | Status |
|---|---|---|
| Malformed request: wrong content type, missing or repeated parameter (`grant_type` included), wrong `client_assertion_type`, bad audience value | `invalid_request` | 400 |
| A `grant_type` this issuer does not accept | `unsupported_grant_type` | 400 |
| Client credentials: any failure to authenticate the client with a well-formed assertion | `invalid_client` | 401 |
| Token exchange: the subject token is invalid or matches no mapping | `invalid_request` | 400 |
| The caller authenticated, but may not request this audience | `invalid_target` | 400 |
| Anything else | `server_error` | 500 |

The issuer MUST finish authenticating the caller before it returns `invalid_target`, so the response
does not reveal what a given client or token would be permitted. Authentication failures of one
grant MUST be indistinguishable from each other in status and body: an unknown client and a bad
signature get the same answer. Issuers SHOULD also keep their timing similar, for instance by
verifying an unknown client's assertion against a decoy key.

### 3.2 Client credentials with `private_key_jwt`

The workload holds a private key; the issuer knows only the public half, registered against a client
id and a SPIFFE ID.

| Parameter | |
|---|---|
| `grant_type` | `client_credentials` |
| `client_id` | OPTIONAL; if present it MUST equal the assertion's `iss` |
| `client_assertion_type` | `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` |
| `client_assertion` | a JWT signed with the workload's private key |

The client assertion follows [RFC 7523] as updated by [RFC 7523bis]. The issuer MUST reject it
unless all of the following hold, allowing 30 seconds of clock skew on every time comparison:

- It is a JWS signed with ES256 or RS256 by a key registered for the client. Registered RSA keys are
  at least 2048 bits.
- `iss` and `sub` both equal the client id.
- `aud` is the issuer URL and nothing else, either as a string or as a one-element array. The token
  endpoint URL is not accepted.
- `exp` is present, in the future, and no more than 5 minutes from now.
- `iat`, if present, is not in the future; `nbf`, if present, has passed.
- `jti` is present and the issuer has not accepted it from this client before. The issuer remembers
  each `jti` until the assertion expires.

Clients SHOULD set the JWS header `typ` to `client-authentication+jwt`. The issuer MUST NOT require
it.

An issuer running several processes without a shared replay store can only enforce `jti` uniqueness
per process, so an intercepted assertion could be used once per process within its lifetime of at
most 5 minutes. Such issuers SHOULD share the store, and MUST say so in their documentation if they
do not.

### 3.3 Token exchange

The workload presents a token from another issuer that this issuer is configured to trust, an
**upstream**: a Kubernetes service account token, a CI provider's OIDC token, a cloud identity
token. See [RFC 8693].

| Parameter | |
|---|---|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | the upstream token |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:jwt` or `urn:ietf:params:oauth:token-type:id_token`, processed identically; any other value is `invalid_request` |
| `requested_token_type` | OPTIONAL; if present MUST be `urn:ietf:params:oauth:token-type:jwt` |

The issuer MUST:

1. Select the upstream by exact match of the subject token's `iss` against its configuration, before
   fetching any key. It MUST fetch keys only from that upstream's configured JWKS or discovery
   location, never from a location named by the token.
2. Reject a subject token whose `iss` is its own issuer URL.
3. Verify the signature with an asymmetric algorithm consistent with the key (no `none`, no HMAC).
4. Require `exp`, and check `exp` and `nbf`. It SHOULD also refuse tokens meant to live longer than
   a configured maximum (`exp` minus `iat`), so that a long-lived token minted by hand is not a
   standing credential.
5. Check that `aud` contains the audience configured for that upstream.
6. Map the token's claims to exactly one SPIFFE ID in its own trust domain, or reject it.

When a mapping compares or copies a claim, only string values and integers count; integers are taken
exactly as written in the token, and any other value is treated as absent. When a mapping copies a
claim value into the SPIFFE ID, that value fills exactly one path segment. A value that is empty, is
`.` or `..`, or contains any character outside `A-Z a-z 0-9 . _ -` MUST cause the request to be
rejected; it is never escaped or rewritten. The resulting SPIFFE ID MUST NOT exceed 2048 bytes.
Keeping it within 255 characters is RECOMMENDED, the limit AWS places on federated subjects.

## 4. The JWT-SVID

The issued token is a JWT-SVID as defined by [JWT-SVID]:

- Header: `alg` (ES256 or RS256), `kid` (a key in the JWKS), `typ: "JWT"`.
- Claims: `iss` (the issuer URL), `sub` (the SPIFFE ID), `aud` (a string when one audience was
  requested, otherwise an array), `exp`, `iat`, `jti`. No other claims.

The lifetime is chosen by the issuer and SHOULD be a few minutes. Verifiers MUST check the
signature, `exp`, that `aud` contains their own expected audience, and that `sub` is a valid SPIFFE
ID in the trust domain the key belongs to. Verifiers that know the issuer URL SHOULD check `iss`.

## 5. The agent

An agent serves the `SpiffeWorkloadAPI` gRPC service of the [Workload API] on a Unix domain socket.
It MUST NOT listen on TCP: it performs no attestation, so whoever reaches the endpoint receives the
identity. Workloads find it through `SPIFFE_ENDPOINT_SOCKET=unix:///path/to/socket`.

The agent implements the JWT-SVID profile only, so it is not a complete Workload API server: the
standard makes the X.509-SVID profile mandatory. Workloads use the JWT parts of their SPIFFE library
(for go-spiffe, `workloadapi.NewJWTSource`, `FetchJWTSVID`, `ValidateJWTSVID`) and not the X.509 or
combined bundle sources, which retry `Unimplemented` until their deadline.

| RPC | Behaviour |
|---|---|
| `FetchJWTSVID` | Returns a JWT-SVID for the requested audiences, obtained from the token endpoint. If `spiffe_id` is set and differs from the workload's identity, fails with `PermissionDenied`. |
| `FetchJWTBundles` | Streams the trust domain's JWT bundle, keyed by the trust domain's SPIFFE ID (`spiffe://example.org`), and sends an update whenever the key set changes. Each key carries `kid` and `use: "jwt-svid"`. A bundle without keys is never sent: the agent keeps the last good bundle, and until it has one the stream waits. |
| `ValidateJWTSVID` | Validates the token against the bundle and the given audience, and returns its SPIFFE ID and all of its claims. |
| `FetchX509SVID`, `FetchX509Bundles`, `FetchWITSVID`, `FetchWITBundles` | Fail with `Unimplemented`. |

The agent's gRPC status codes:

| Situation | Code |
|---|---|
| Missing `workload.spiffe.io: true` metadata | `InvalidArgument` |
| `FetchJWTSVID` or `ValidateJWTSVID` without an audience, or an empty token | `InvalidArgument` |
| `ValidateJWTSVID` given a token that does not validate | `InvalidArgument` |
| The issuer refused the request (`invalid_client`, `invalid_request`, `invalid_target`, `unsupported_grant_type`) | `PermissionDenied` |
| The issuer is unreachable or failed, or no bundle has been fetched yet | `Unavailable` |
| The agent cannot produce its own proof of identity (an unreadable key or subject token file) | `FailedPrecondition` |

An agent supports both grants of section 3 and is configured to use one. It SHOULD reuse a JWT-SVID
for the same audiences until half its lifetime has passed, and SHOULD refresh the bundle at the
issuer's `spiffe_refresh_hint`.

Deployments MUST restrict access to the socket: file permissions, or a volume shared only with the
workload's own containers.

## 6. Security considerations

- **The issuer is the trust root.** Its signing keys can mint any identity in the trust domain.
  Store them like any CA key and rotate them (section 2.4). Whoever can write the issuer's
  configuration controls every identity.
- **Proofs, not shared secrets.** With `private_key_jwt` the issuer stores only public keys; with
  token exchange it stores nothing about the workload at all. Reading the issuer's registrations
  does not let anyone impersonate a workload.
- **JWT-SVIDs are bearer tokens.** Anyone holding one can use it against its audiences until it
  expires. Keep lifetimes short, request narrow audiences, and send them only over TLS.
- **Audience is the receiver's job to check.** An issuer may restrict which audiences a workload may
  request, but a receiver MUST still check `aud` itself.
- **Upstream trust is delegated trust.** Trusting an upstream means trusting everyone who can get a
  token from it with the configured audience. For a shared upstream (a public CI provider, a cloud
  provider's global issuer) anyone can obtain such a token, so the `aud` check proves nothing about
  who the caller is. Every mapping for a shared upstream MUST require a claim that identifies the
  owner, such as GitHub's `repository_owner_id`.
- **Chaining issuers.** Configuring another spiffex issuer as an upstream is legitimate but must be
  deliberate; section 3.3 rule 2 only prevents an issuer from exchanging its own tokens.

## 7. Notes for AWS federation

AWS IAM accepts the issuer as an OIDC identity provider when the issuer URL has no port and no
trailing slash, the JWKS is served with a certificate from a publicly trusted CA, and tokens carry
`iat` and a SPIFFE ID of at most 255 characters. The token's `aud` must match a client ID registered
on the provider; requesting that single audience is RECOMMENDED. Trust policies then condition on
`<issuer URL without https://>:sub` and `<issuer URL without https://>:aud`.

[SPIFFE-ID]: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md
[JWT-SVID]: https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md
[Trust Domain and Bundle]: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md
[SPIFFE Federation]: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md
[Workload API]: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC 6749]: https://www.rfc-editor.org/rfc/rfc6749
[RFC 7517]: https://www.rfc-editor.org/rfc/rfc7517
[RFC 7523]: https://www.rfc-editor.org/rfc/rfc7523
[RFC 7523bis]: https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/
[RFC 7638]: https://www.rfc-editor.org/rfc/rfc7638
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174
[RFC 8414]: https://www.rfc-editor.org/rfc/rfc8414
[RFC 8693]: https://www.rfc-editor.org/rfc/rfc8693

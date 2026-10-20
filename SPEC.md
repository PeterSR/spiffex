# spiffex specification

Version 0, draft. Breaking changes are possible until version 1.

This document specifies how a spiffex **issuer** hands out SPIFFE JWT-SVIDs and X.509-SVIDs over
plain OAuth 2.0, how it decides who gets which identity, how that decision is managed while it runs,
and how a spiffex **agent** serves the identities to workloads through the SPIFFE Workload API.
Anything a compliant implementation must do is in here. The issuer's own settings, where it stores
its state and its command line are implementation details, except where a section names a setting.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 ([RFC 2119], [RFC 8174]) when, and only when, they appear in all capitals, as
shown here.

## 1. Overview

```
 workload ──Workload API──▶ agent ──OAuth 2.0 token endpoint──▶ issuer
   (go-spiffe,             (proves the        (finds the origin for the proof,
    py-spiffe, ...)         workload)          checks it, names the identity, signs)

 verifier ──HTTPS GET──▶ issuer: OIDC discovery, JWKS, SPIFFE bundle
 operator ──HTTPS + JWT-SVID──▶ issuer: management API
```

- The **issuer** is the trust domain's only signer. Verifiers see an OpenID Connect issuer in the
  sense that federation needs: a discovery document and a JWKS that its tokens verify against. It is
  not a full OpenID Provider; there is no authorization endpoint and no end user.
- The issuer's **certificate authority**, when it has one, signs X.509-SVIDs. It is separate from
  the JWT signing keys and rotates on its own schedule (section 2.5).
- A **workload** is anything that needs an identity. It either talks to an agent through the
  Workload API, or speaks OAuth 2.0 to the issuer directly.
- An **origin** is one way identities come in: a Kubernetes cluster, a CI provider, a set of
  workload keys. It says what counts as proof, which holders of such proof are admitted, what
  SPIFFE ID each one gets, and which kinds of SVID they may obtain (section 4).
- A **provider** is a reusable description of a kind of origin, written as a plain document. Origins
  name a provider and fill in its parameters (section 5).
- An **agent** acts for exactly one workload. It holds that workload's proof of identity, fetches
  JWT-SVIDs and X.509-SVIDs from the issuer and serves them over the Workload API.
- A **verifier** checks JWT-SVIDs offline against the issuer's keys, and X.509-SVIDs against its
  certificate authorities, fetched as a SPIFFE bundle, as a JWKS (JWT-SVIDs only), or through an
  agent.
- **Grants** give SPIFFE identities permission to read and change the state through the management
  API (section 8).

Origins, providers and grants together are the issuer's **state** (section 6). An issuer starts with
empty state, in which it admits nobody.

Terms from the SPIFFE standards ([SPIFFE-ID], [JWT-SVID], [X.509-SVID], [Trust Domain and Bundle],
[Workload API]) keep their meaning here.

## 2. The issuer

An issuer is identified by its **issuer URL**: an `https` URL with no query, no fragment, no user
information and no trailing slash. An `http` URL is acceptable only for local development. A trust
domain has exactly one issuer URL and an issuer URL serves exactly one trust domain. Several
processes MAY serve the same issuer URL, provided they share one set of signing keys, one
certificate authority if there is one, and one state.

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
| `grant_types_supported` | `client_credentials` and `urn:ietf:params:oauth:grant-type:token-exchange` |
| `token_endpoint_auth_methods_supported` | `["private_key_jwt", "none"]` |
| `token_endpoint_auth_signing_alg_values_supported` | algorithms accepted on client assertions |
| `id_token_signing_alg_values_supported` | algorithms the issuer signs with |
| `response_types_supported` | `["id_token"]`, for consumers that require the field |
| `subject_types_supported` | `["public"]` |
| `claims_supported` | `["iss", "sub", "aud", "exp", "iat", "jti"]` |
| `spiffe_bundle_endpoint` | `<issuer>/bundle` (section 2.3); informational |
| `spiffe_trust_domain` | the trust domain name, e.g. `example.org`; informational |
| `spiffex_management_endpoint` | `<issuer>/manage` (section 8), when the management API is enabled |
| `spiffex_x509_svid_supported` | `true` when the issuer has a certificate authority and issues X.509-SVIDs (section 3.4); absent otherwise |

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
Bundle] standard: the same public keys as the JWKS, each with `use: "jwt-svid"` and `kid`, and, when
the issuer has a certificate authority, each anchor (section 2.5) as a key with `use: "x509-svid"`,
the certificate's public key parameters (`kty` and its key members) and the certificate in `x5c`,
one element, the certificate itself. It also carries `spiffe_sequence` and `spiffe_refresh_hint`
(seconds). It is a bundle endpoint with the `https_web` profile of
[SPIFFE Federation]. The JWKS (section 2.2) never contains X.509 authorities: OIDC consumers have no
use for them.

`spiffe_sequence` MUST increase whenever the published key set or the published anchors change, as
observed from any one issuer process. Processes serving the same issuer URL SHOULD report the same
value for the same published keys and anchors, but nothing guarantees it, so verifiers MUST NOT
conclude from the sequence alone that a bundle from one process is older than a bundle from
another.

### 2.4 Signing keys and rotation

The issuer signs with ES256 (ECDSA P-256) or RS256 (RSA, at least 2048 bits). Each key's `kid` is
its [RFC 7638] JWK thumbprint computed with SHA-256, base64url-encoded without padding.

Rotation MUST NOT break a verifier that refreshes on the published hint:

1. A new key is published in the JWKS and bundle for at least the **activation delay** before the
   issuer signs with it. The delay is measured from when the issuer first publishes the key, not
   from when the key was generated. The activation delay SHOULD be at least three times the
   `spiffe_refresh_hint`, and the JWKS `Cache-Control` max-age MUST NOT exceed the refresh hint.
2. A key the issuer stopped signing with stays published for at least the maximum JWT-SVID lifetime
   (section 7.1) after its last use, plus an allowance for clock skew.

Whenever more than one published key has completed its activation delay, the issuer signs with the
newest. When none has, as in a newly created trust domain, it signs with the key it would have used
had it been running all along, or else with the oldest key.

A compromised key is the exception to rule 2: the operator removes it at once, accepting that tokens
it signed stop verifying.

Signing keys are not part of the state (section 6) and the management API cannot read or change
them. The same holds for the certificate authority's keys and certificates (section 2.5).

### 2.5 The certificate authority

An issuer MAY have a **certificate authority** (CA) that signs X.509-SVIDs. Without one the issuer
issues no X.509-SVIDs, and everything else in this document is unchanged. The CA's certificates and
private keys are held like the JWT signing keys, but in a directory of their own (the setting
`ca_dir`), outside the state and out of reach of the management API.

The **signing CA** is the certificate whose key signs X.509-SVIDs. The **anchors** are the X.509
authorities the bundle publishes (section 2.3). The two are the same certificate or different ones,
depending on how the CA is set up:

- A **root**: the signing CA is self-signed. It is the anchor, and the issuer is the trust domain's
  own root of trust.
- An **intermediate**: the signing CA is signed by an operator's own CA. The operator's root
  certificates (the setting `ca_roots`) are the anchors and the bundle holds them, not the
  intermediate. Section 2.5.1 has the rest.

The anchors are every self-signed CA certificate in `ca_dir` and every certificate in `ca_roots`,
whether or not a signing CA chains to it yet, except those whose retention under rule 2 below has
ended. Both kinds may be present at once, as during a move from one setup to the other.

Both are supported. For production, an intermediate under an offline root is RECOMMENDED, because
the root can then replace a compromised intermediate; a root suits development and small setups.

**What a signing CA certificate is.** It:

- has a non-empty subject that differs between CA generations, a `subjectKeyIdentifier`, and MAY
  carry one URI SAN, `spiffe://<trust domain>`, with no path;
- has an ECDSA key on P-256 or P-384, or an RSA key of 2048 to 4096 bits, and signs with
  ecdsa-with-SHA256 (P-256), ecdsa-with-SHA384 (P-384) or sha256WithRSAEncryption (RSA). RSASSA-PSS
  is not used;
- has `basicConstraints`, marked critical, with `cA: true` and `pathLenConstraint: 0`, and
  `keyUsage`, marked critical, with `keyCertSign` and `cRLSign` only;
- carries a `nameConstraints` extension, marked critical, holding only these subtrees ([RFC 5280]
  section 4.2.1.10). Permitted: one `uniformResourceIdentifier` subtree whose base is the trust
  domain name (`<trust domain>`). Excluded: one `uniformResourceIdentifier` subtree
  `.<trust domain>`, so that verifiers which match URI constraints as domains do not also accept
  subdomains, which are other trust domains; one `dNSName` subtree with an empty base; `iPAddress`
  subtrees `0.0.0.0/0` and `::/0`; and one `rfc822Name` subtree with an empty base. It MUST NOT
  contain `directoryName` or any other name form.

Name constraints are the CA's fence: a CA that can only certify SPIFFE IDs of its own trust domain
limits the damage of a stolen CA key to that trust domain, in every verifier that enforces them. The
extension has no `directoryName` subtrees because Go's X.509 verifier refuses a CA with a critical
`directoryName` constraint outright, and because [RFC 5280] applies directory name constraints to a
certificate's subject, so a constraint that excluded directory names would make OpenSSL refuse every
X.509-SVID with a subject (section 3.4). The CA therefore leaves the subject unconstrained; section
3.4 fixes what the issuer puts there.

The issuer MUST refuse to start when a signing CA certificate does not meet this profile. When
`exec` verifiers run as a user of their own (section 5.4), the issuer MUST refuse to start if that
user can read a CA private key, and MUST stop signing with a CA key that becomes readable to it
later.

The issuer rereads `ca_dir` and `ca_roots` while it runs. A certificate that fails these checks or
those of section 2.5.1 at startup stops the issuer from starting; one that appears later is not used
or published, the issuer logs why, and it goes on with the CAs it already has. A CA certificate
whose key was removed is not such a failure: it never signs (the way to stop a compromised CA), the
issuer starts without it, and one left with anchors but no CA that can sign publishes the anchors and
issues no X.509-SVIDs.

**Rotation** follows the rules of section 2.4, applied to anchors rather than to every CA
certificate:

1. A new anchor is published in the bundle for at least the activation delay before the issuer
   issues any X.509-SVID that chains to it.
2. An anchor stays published until the latest `notAfter` of the X.509-SVIDs chaining to it, plus
   the clock skew allowance. An anchor past its own `notAfter` MAY be dropped.

As in section 2.4, the delay is measured from when the issuer first publishes the anchor, and when
no anchor has completed it, as in a newly created trust domain, the issuer signs with the signing CA
it would have used had it been running all along, or else with the oldest. The exception is an
anchor the issuer, while running, published again after it had left the bundle: no CA under it signs
until the delay has passed, even if that leaves no CA able to sign.

A new intermediate under an anchor whose activation delay has passed may sign at once. Among the
usable signing CAs the issuer signs with the newest. The activation delay SHOULD exceed the time
consumers that reload certificates from files need to pick up a new anchor.

**Expiry.** The issuer signs with the newest signing CA that may sign and does not fall back to an
older one, whose anchor may leave the bundle (rule 2) while the certificates it signed are valid.
When the newest CA's chain, up to and including the anchor, ends within a full X.509-SVID lifetime,
it issues the shorter X.509-SVID that section 3.4 allows, and logs a warning; it refuses X.509-SVID
requests with `server_error` only when the leaf's `notAfter` would be less than 5 minutes after the
current time. It SHOULD warn from 30 days before the earliest `notAfter` of the chain.

#### 2.5.1 With an intermediate

When the CA is an intermediate, every X.509-SVID response carries the signing CA, and any further
certificate between it and the anchor, after the leaf, so that verifiers can build the path
(section 3.4). The anchors are not sent. The issuer MUST refuse to start when the chain does not
verify against an anchor it publishes.

The anchor widens the trust domain to everything it signs: every verifier then accepts any chain to
that root that carries a `spiffe://<trust domain>/...` URI SAN, including chains through the
operator's other CAs, and the signing CA's name constraints protect nothing against a sibling that
has none. The issuer cannot see siblings, so it asks the operator. Each root MUST either carry the
full set of name constraints above, exactly, or be dedicated to this trust domain: every CA
certificate it certifies, directly or through other CAs, is one of this issuer's signing CAs or a CA
on the path to one, and those CAs certify no other CA. The issuer refuses to start with a root that
does not carry the full set unless the setting `ca_roots_dedicated` is `true`, by which the operator
states the second.

Even the full set does not stop a sibling CA under a shared root from minting
`spiffe://<trust domain>/...` identities: name constraints only confine what a root can certify to
this trust domain. A shared root is therefore safe only when every CA under it is the operator's own,
and `ca_roots_dedicated` is the operator's statement that it is.

## 3. The token endpoint

`POST <issuer>/token` with an `application/x-www-form-urlencoded` body, as in [RFC 6749]. The
issuer accepts two grants: client credentials, for origins whose proof is a workload key
(section 3.2), and token exchange, for origins whose proof is a token from another issuer
(section 3.3). The issuer MUST refuse a request body larger than 64 KiB.

Both grants take `audience`. For token exchange it is the [RFC 8693] parameter; for client
credentials it is a spiffex extension with the same meaning. It is REQUIRED when the requested token
is a JWT-SVID and MUST be absent when it is an X.509-SVID (section 3.4).

| Parameter | |
|---|---|
| `audience` | REQUIRED for a JWT-SVID, not allowed for an X.509-SVID. MAY repeat. Each distinct value becomes an `aud` entry of the JWT-SVID. At most 5 values, each non-empty and at most 512 bytes. A single audience is RECOMMENDED, as the [JWT-SVID] standard advises. |
| `requested_token_type` | OPTIONAL on both grants. `urn:ietf:params:oauth:token-type:jwt`, the default, asks for a JWT-SVID; `urn:spiffex:token-type:x509-svid` asks for an X.509-SVID (section 3.4). Any other value is `invalid_request`. For client credentials it is a spiffex extension. |
| `csr` | REQUIRED with `urn:spiffex:token-type:x509-svid`, not allowed otherwise: a PKCS#10 certificate signing request ([RFC 2986]), DER, base64url without padding. A spiffex extension. |

Parameters other than `audience` and `resource` MUST appear at most once. `scope` and `resource` are
ignored. `actor_token` is rejected with `invalid_request`: spiffex does not issue delegation tokens.

The issuer MUST reject, with `invalid_target`, an audience equal to its own issuer URL or token
endpoint, so a JWT-SVID can never pass for a client assertion or exchange input aimed at the issuer
itself. The management endpoint `<issuer>/manage` is a permitted audience, but only on its own: a
request that names it together with any other audience is rejected with `invalid_target`
(section 8.1).

When the origin restricts audiences (section 4.4), every requested audience MUST be allowed by it,
or the request fails with `invalid_target`. The origin's `svid_types` MUST include the type of SVID
requested, `jwt` for a JWT-SVID and `x509` for an X.509-SVID (section 4.5), or the request fails
with `invalid_target`.

A successful response for a JWT-SVID is `200` with `Content-Type: application/json`,
`Cache-Control: no-store` and the body:

```json
{
  "access_token": "<JWT-SVID>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "Bearer",
  "expires_in": 300,
  "spiffe_id": "spiffe://example.org/vms/billing"
}
```

`spiffe_id` duplicates the token's `sub` so a client need not parse the token to learn it. The
response for an X.509-SVID has the same shape and is described in section 3.4.

### 3.1 Errors

Errors follow [RFC 6749] section 5.2: a JSON body with `error` and optionally `error_description`.

| Situation | `error` | Status |
|---|---|---|
| Malformed request: wrong content type, missing or repeated parameter (`grant_type` included), wrong `client_assertion_type`, bad audience value, oversized body; an `audience` with an X.509-SVID request, a missing `csr` with one, a `csr` with a JWT-SVID request; a `requested_token_type` that is neither of the two; an X.509-SVID requested from an issuer without a certificate authority, or whose certificate authority has no CA left with a key | `invalid_request` | 400 |
| A `grant_type` other than the two above | `unsupported_grant_type` | 400 |
| Client credentials: any failure to authenticate the client with a well-formed assertion | `invalid_client` | 401 |
| Token exchange: the subject token is invalid, or its origin does not admit it | `invalid_request` | 400 |
| The caller authenticated, but may not request this audience | `invalid_target` | 400 |
| The caller authenticated, but its origin's `svid_types` lacks the type requested (section 4.5) | `invalid_target` | 400 |
| The caller authenticated, but the `csr` does not parse, its signature does not verify with its own key, or its key is not one section 3.4 accepts | `invalid_request` | 400 |
| Anything else, including an issuer whose certificate authority cannot issue an X.509-SVID of useful length (section 2.5) | `server_error` | 500 |

The issuer MUST finish authenticating the caller before it returns `invalid_target`, so the response
does not reveal what a given client or token would be permitted. The same holds for the contents of
a `csr`: a request with a bad `csr` and a bad proof is answered as a bad proof. Whether a `csr` is
present is a property of the request and is answered first, like a missing audience, and so is whether
the issuer has a certificate authority at all. After
authentication the issuer checks the origin's `svid_types` (section 4.5) before the audience
restriction (section 4.4) and before the contents of the `csr`. A request refused for its origin's
`svid_types` or for the contents of its `csr` has already consumed the assertion's `jti`
(section 3.2), as a request with a bad audience does. Authentication failures of one grant MUST be
indistinguishable from each other in status and body: an unknown client and a bad signature get the
same answer, and so do a token with no origin and a token its origin refuses.
Issuers SHOULD also keep their timing similar, for instance by verifying an unknown client's
assertion against a decoy key. The issuer SHOULD log the actual reason.

### 3.2 Client credentials with `private_key_jwt`

The workload holds a private key; the issuer knows only the public half, registered as a member of
a `keys` origin (section 4.2).

| Parameter | |
|---|---|
| `grant_type` | `client_credentials` |
| `client_id` | OPTIONAL; if present it MUST equal the assertion's `iss` |
| `client_assertion_type` | `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` |
| `client_assertion` | a JWT signed with the workload's private key |

The **client id** of a member is `<origin>/<member>`, for example `vms/billing`. It names exactly one
member of one origin.

The client assertion follows [RFC 7523] as updated by [RFC 7523bis]. The issuer MUST reject it
unless all of the following hold, allowing 30 seconds of clock skew on every time comparison:

- It is a JWS signed with ES256 or RS256 by a key registered for the member. Registered RSA keys are
  at least 2048 bits.
- `iss` and `sub` both equal the client id.
- `aud` is the issuer URL and nothing else, either as a string or as a one-element array. The token
  endpoint URL is not accepted.
- `exp` is present, in the future, and no more than 5 minutes from now.
- `iat`, if present, is not in the future; `nbf`, if present, has passed.
- `jti` is present and the issuer has not accepted it from this client before. The issuer remembers
  each `jti` until the assertion expires, plus the clock skew allowance.

Clients SHOULD set the JWS header `typ` to `client-authentication+jwt`. The issuer MUST NOT require
it.

An issuer running several processes without a shared replay store can only enforce `jti` uniqueness
per process, so an intercepted assertion could be used once per process within its lifetime of at
most 5 minutes. Such issuers SHOULD share the store, and MUST say so in their documentation if they
do not.

### 3.3 Token exchange

The workload presents a proof it already has as a subject token, as in [RFC 8693]. Usually this is
a token from another issuer, an **upstream**: a Kubernetes service account token, a CI provider's
OIDC token, a cloud identity token. For an `exec` origin it is whatever that origin's verifier
understands (section 5.4).

| Parameter | |
|---|---|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | the proof, at most 16 KiB |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:jwt` or `urn:ietf:params:oauth:token-type:id_token`, processed identically, for `jwt` origins; `urn:spiffex:token-type:exec` for an `exec` origin; any other value is `invalid_request` |
| `origin` | REQUIRED with `urn:spiffex:token-type:exec`, and not allowed otherwise: the name of the `exec` origin; a spiffex extension |

For an `exec` origin, the `origin` parameter names the origin. If no `exec` origin has that name,
the request is rejected as an invalid subject token; otherwise the issuer runs the origin's verifier
(section 5.4), checks its admission (section 4.3) and issues the SPIFFE ID it names.

For a JWT, no two `jwt` origins share both an upstream issuer and an audience (section 6.2), so the
token names at most one origin. The issuer MUST:

1. Reject a subject token whose `iss` is its own issuer URL.
2. Read the token's `iss` and `aud` without trusting them, and find the one `jwt` origin whose
   upstream issuer equals the `iss` exactly and whose audience is among the `aud` values. If there
   is none, or the `aud` values name more than one such origin, reject the request.
3. Verify the signature against that origin's keys, fetched only from its configured key location,
   never from a location named by the token, with an asymmetric algorithm consistent with the key
   (no `none`, no HMAC).
4. Require `exp` and `iat`, check `exp` and `nbf`, and refuse a token meant to live longer than the
   origin's `max_token_lifetime` plus 30 seconds (`exp` minus `iat`, section 5.2), so that a
   long-lived token minted by hand is not a standing credential. The allowance admits platforms
   that add a few seconds, as Kubernetes does with its 3607-second tokens.
5. Check the origin's admission (section 4.3) and issue the SPIFFE ID it names.

### 3.4 Requesting an X.509-SVID

A workload asks for an X.509-SVID by adding `requested_token_type=urn:spiffex:token-type:x509-svid`
and a `csr` to a token request for a JWT-SVID, in place of its `audience`. Authentication, origin
selection, admission and naming are exactly those of sections 3.2, 3.3 and 4: the certificate's
SPIFFE ID is the one a JWT-SVID would have carried. The origin's `svid_types` MUST include `x509`
(section 4.5); the audience restriction of section 4.4 does not apply, as an X.509-SVID has no
audience. `spiffex` is not a registered URN namespace, as for `urn:spiffex:token-type:exec`; no
registered token type names a certificate.

**The request.** After authentication the issuer MUST:

1. decode the `csr` and refuse it unless it is DER, at most 8 KiB and version 1 (the integer 0),
   and refuse a key that is not ECDSA on P-256 or P-384, Ed25519, or RSA of 2048 to 4096 bits with
   public exponent 65537, so that an unbounded modulus cannot be used to make the signature check
   expensive. An Ed25519 key MUST also be refused unless it is the canonical encoding of a point of
   the curve and the point is not of small order (its multiple by 8 is not the identity): for such a
   key a signature that verifies can be made without any private key, so the check in step 2 would
   prove nothing;
2. refuse the `csr` unless its signature verifies with the public key it contains, which proves the
   requester holds the private key. The signature algorithm is ecdsa-with-SHA256 for a P-256 key,
   ecdsa-with-SHA256 or ecdsa-with-SHA384 for a P-384 key (OpenSSL signs with SHA-256 by default),
   pure Ed25519 for an Ed25519 key, or sha256WithRSAEncryption, sha384WithRSAEncryption or
   sha512WithRSAEncryption for an RSA key; RSASSA-PSS is not accepted;
3. refuse a key equal to one of the issuer's own CA or JWT signing keys, or to a member key of any
   `keys` origin: a workload's certificate key is its own and new. This only catches clients that
   make their own keys, as an agent generates a new one every time;
4. ignore every other field of the CSR: its subject, its attributes, its requested extensions and
   names. Nothing in a CSR reaches the certificate except its public key.

**The certificate.** The issuer builds the certificate itself:

| Field | Value |
|---|---|
| Serial number | a positive integer of at most 20 octets: 128 bits from a cryptographic random source, with the top bit cleared |
| Issuer | the signing CA certificate's subject, byte for byte |
| Subject | `O=<trust domain>` then `CN=<SPIFFE ID>`, each one UTF8String attribute in its own RDN. `O` is omitted when the trust domain name exceeds 64 characters and `CN` when the SPIFFE ID does (the upper bounds of [RFC 5280]); neither is ever truncated. Nothing from the CSR |
| Validity | `notBefore` the current time minus 30 seconds, but not before the `notBefore` of any certificate in the chain; `notAfter` the earliest of the current time plus the X.509-SVID lifetime (section 7.2) and the `notAfter` of every certificate in the chain up to and including the anchor |
| Subject public key | the CSR's |
| `subjectAltName` | exactly one name, a URI: the SPIFFE ID; critical exactly when the subject is empty |
| `basicConstraints` | `cA: false`, critical |
| `keyUsage` | `digitalSignature`, plus `keyEncipherment` for an RSA key only; critical |
| `extKeyUsage` | `serverAuth` and `clientAuth`; not critical |
| `authorityKeyIdentifier` | `keyIdentifier` only: the signing CA's `subjectKeyIdentifier` |
| `subjectKeyIdentifier` | the SHA-1 digest of the subject public key bit string ([RFC 5280] section 4.2.1.2, method 1) |

The signature algorithm is the signing CA's (section 2.5). No other extension is added: in
particular there is no CRL distribution point, authority information access or OCSP, as an
X.509-SVID cannot be revoked (section 7.2). The result MUST be a valid leaf X.509-SVID as defined by
the [X.509-SVID] standard.

If `notAfter` would be less than 5 minutes after the current time, the issuer refuses the request
with `server_error` and logs why (section 2.5).

**The subject.** The SAN is the identity: verifiers MUST take the SPIFFE ID from the URI SAN
(section 7.2). The subject repeats it for consumers that read only the subject. Databases such as
PostgreSQL (`cert` authentication with a user name map), MariaDB (`REQUIRE SUBJECT`) and Valkey
(mapping the common name to an ACL user) map a client certificate to a user by its CN or DN, and
none of them reads a URI SAN, so without a subject an X.509-SVID could not authenticate to them.
The subject is built only from the trust domain and the SPIFFE ID, never from the CSR. Because path
segments cannot contain `/`, `,`, `=`, `+` or `\`, the common renderings of the subject are
unambiguous. A CN is left out rather than shortened when the SPIFFE ID exceeds 64 characters, so two
identities never share a CN and a consumer that matches on it fails closed. The issuer SHOULD log a
warning naming the origin the first time it issues a certificate without a CN.

**The response.** A successful response has the shape of section 3, with:

```json
{
  "access_token": "<the chain>",
  "issued_token_type": "urn:spiffex:token-type:x509-svid",
  "token_type": "N_A",
  "expires_in": 3600,
  "spiffe_id": "spiffe://example.org/prod/ns/shop/sa/billing"
}
```

`access_token` is the certificate chain, leaf first, any intermediate after it: the DER encodings of
the certificates concatenated, base64url-encoded without padding, as the Workload API's `x509_svid`
field carries it. `token_type: N_A` is the [RFC 8693] value for a token that is not an access token.
`expires_in` is the leaf's `notAfter` minus the current time, rounded up to whole seconds. Clients
schedule renewal from the certificate's own `notBefore` and `notAfter`, not from `expires_in`. The
private key never leaves the requester. The response does not include the bundle; clients fetch it
from the bundle endpoint.

The issuer MUST log every X.509-SVID it issues with its serial number, SPIFFE ID, origin and
`notAfter`: with no revocation the log is the only record.

**Proof reuse.** A client assertion's `jti` is consumed by an X.509-SVID request like any other
(section 3.2). A subject token may be exchanged for a JWT-SVID and an X.509-SVID in separate
requests within its lifetime, as it may already be exchanged for JWT-SVIDs of different audiences.

## 4. Origins

An origin has:

- a **name**: 1 to 63 characters from `a-z 0-9 -`, starting with a letter, unique in the state;
- a **provider** (section 5), whose proof, admission and naming it inherits, and values for the
  provider's parameters under `with`;
- optionally, its own **prefix** and **name template** (section 4.1), admission additions
  (section 4.3), an audience restriction (section 4.4) and the SVID types it issues
  (section 4.5);
- for a `keys` proof, its **members** (section 4.2).

An origin's **kind** is that of its provider's proof: `jwt`, `keys` or `exec`.

Origin names, prefixes, and the upstream issuer and audience of `jwt` origins are not secret: the
management API reveals them in conflicts (section 8.3). Providers are readable by every identity in
the trust domain, so a provider, an `exec` verifier's command included, is not secret either.

### 4.1 Naming: prefix and name template

Every SPIFFE ID an origin issues is

```
spiffe://<trust domain><prefix>/<name>
```

- The **prefix** is `/<origin name>` unless the origin sets another. A prefix is `/`, or one or more
  segments, each written as `/` followed by the segment.
- The **name** is the origin's name template filled in for the admitted proof. An origin uses its
  provider's template unless it sets `name`. When the template is empty, the ID is the prefix alone,
  and the prefix MUST NOT then be `/`.

A **segment** is 1 to 255 characters from `A-Z a-z 0-9 . _ -`, and is not `.` or `..`.

Two origins' prefixes MUST NOT overlap: no prefix may equal another, or extend another by whole
segments (`/a` overlaps `/a/b`, not `/ab`). `/` overlaps every other prefix, so an origin with
prefix `/` must be the only origin. Because of this rule, two origins can never issue the same
SPIFFE ID, and every identity's origin can be read from its path.

A **name template** is empty, or a `/`-separated sequence of parts. Each part is either a literal
segment, or a single placeholder `{...}` that fills one whole segment:

- in a `jwt` or `exec` origin, `{<claim path>}` is the value of a claim of the verified subject
  token, or of the claims the verifier returned (section 4.3);
- in a `keys` origin, `{member}` is the member's name, and is the only placeholder.

In a `jwt` or `exec` origin, a placeholder MAY list **operations** after its claim path, each
written `|<operation>:<argument>`, as in `{kubernetes.io/namespace|trim_prefix:team-}`. Within a
placeholder the claim path ends at the first `|` or `}`, so a claim whose name contains either
cannot fill a placeholder. The operations apply to the claim's value in the order written:

| Operation | Result |
|---|---|
| `trim_prefix:<text>` | the value without `<text>` at its start |
| `trim_suffix:<text>` | the value without `<text>` at its end |

The argument is 1 to 255 characters from `A-Z a-z 0-9 . _ -`. When the value does not start, or
end, with the argument, the request is rejected; the value is never passed through unchanged, or
`team-a` and `a` would both become `a`. Every operation is one-to-one in this way, so a template
with operations never gives two different values the same SPIFFE ID. An unknown operation makes
the template invalid.

A placeholder's value, after its operations, MUST be a valid segment, or the request is rejected;
it is never escaped or rewritten by any means other than its operations.

The resulting SPIFFE ID MUST NOT exceed 2048 bytes. Keeping it within 255 characters is
RECOMMENDED, the limit AWS places on federated subjects.

A `keys` origin whose template has no `{member}` gives all its members the same SPIFFE ID. That is
allowed; it is how several machines share one identity, each with its own key.

### 4.2 Members

A `keys` origin lists **members**, keyed by name. A member's name is a segment. Each member has
`keys`: one to ten public keys, ES256 keys on P-256 or RS256 keys of at least 2048 bits, each given
as a PEM `PUBLIC KEY` block or as a JWK. A JWK that carries private key members (`d`, `p`, `q`,
`dp`, `dq`, `qi` or `oth`) is refused. A member accepts an assertion signed by any of its keys,
which is how a workload's key is rotated.

### 4.3 Admission

A **claim path** names a claim of the subject token, or for an `exec` origin of the claims its
verifier returned. It is a `/`-separated list of JSON object
member names: `sub` is the top-level `sub` claim, and `kubernetes.io/namespace` is the `namespace`
member of the `kubernetes.io` object. As in a JSON Pointer ([RFC 6901]), `~1` in a name stands for
`/` and `~0` for `~`, so `oidc.circleci.com~1project-id` is the top-level claim
`oidc.circleci.com/project-id`. Any other `~` is an error. A
claim's **value** is its string value, or an integer exactly as written in the token; any other JSON
value, and an empty string, count as absent. Claim paths mean the same in `require`, `match`,
`deny` and name templates, except that in a name template a claim path ends at the first `|` or `}`
(section 4.1).

A `jwt` or `exec` origin admits a verified proof when:

1. every claim path in `require` has a value;
2. every entry of `match` holds;
3. no entry of `deny` holds;
4. every placeholder of the name template has a valid value (section 4.1).

`require`, `match` and `deny` come from the provider and from the origin, and both apply: an origin
can narrow its provider's admission but never widen it.

A `match` or `deny` entry maps a claim path to a **pattern** or a list of patterns. The entry holds
when the claim has a value that matches at least one of the patterns. A pattern is literal text in
which `*` stands for any run of characters, including none, and it must match the whole value. No
other character is special. A pattern without `*` is **exact**. Implementations MUST match patterns
in time linear in the length of the value and the pattern.

A `keys` origin admits a member whose assertion is valid (section 3.2). It has no `require`,
`match` or `deny`.

### 4.4 Audience restriction

An origin MAY list, as `audiences`, the audiences its identities may request, as patterns in the
sense of section 4.3; the provider MAY set a default, which an origin's own list replaces. When a
list is in effect, the token endpoint refuses any other audience with `invalid_target`. This is a
convenience for the operator; receivers still check `aud` themselves (section 10). The management
endpoint is allowed only when the list matches it. A list that is empty after expansion is a restriction that allows no audience. The
restriction applies to JWT-SVIDs only; an X.509-SVID has no audience (section 4.5).

### 4.5 SVID types

An origin MAY set `svid_types`: a non-empty list of distinct values from `jwt` and `x509`, the kinds
of SVID its identities may obtain. The provider MAY set a default, which the origin's own list
replaces. When an audience restriction is in effect for the origin (section 4.4), its own or its
provider's, the list is the origin's own `svid_types`, or `[jwt]` when the origin sets none; the
provider's `svid_types` does not apply to it. Otherwise the list is the origin's `svid_types`, else
the provider's, else `[jwt, x509]`. A request for a JWT-SVID from an origin without `jwt`, or for an
X.509-SVID from an origin without `x509`, fails with `invalid_target`, after authentication
(section 3.1). An empty list, a repeated value and any other value are invalid (section 6.2). An issuer without a certificate authority issues no
X.509-SVIDs whatever the list says (section 2.5).

The exception for audience restrictions is there because an X.509-SVID has no audience: any server
that trusts the bundle accepts it for as long as it lives, so it would escape a restriction that
says an origin's identities are for certain receivers only. An origin with a restriction therefore
gets JWT-SVIDs only unless it lists `x509` itself. Listing it is allowed, the restriction then does
not apply to the origin's X.509-SVIDs, and that SHOULD be avoided: the issuer SHOULD log such an
origin at startup and whenever a change introduces it, and the validator of section 6.3 SHOULD
report it without refusing the state. Every other origin gets both kinds, so enabling the issuer's
certificate authority gives them X.509-SVIDs; an operator who does not want a shared upstream's
identities to authenticate to every server that trusts the bundle sets `svid_types: [jwt]`.

## 5. Providers

A provider is a description of a kind of origin, held as a plain document. Its name follows the
rules for origin names. A provider has:

| Field | |
|---|---|
| `params` | the parameters an origin fills in under `with`: each with a `type`, `string` or `list` (of strings), and either `required: true` or a `default` |
| `proof` | exactly one of `jwt` (section 5.2), `keys` (an empty object) or `exec` (section 5.4) |
| `require`, `match`, `deny` | admission (section 4.3); `jwt` and `exec` proofs only |
| `name` | the default name template (section 4.1) |
| `audiences` | OPTIONAL default audience restriction (section 4.4) |
| `svid_types` | OPTIONAL default for the kinds of SVID an origin may obtain (section 4.5) |
| `description` | OPTIONAL text for humans |
| `overrides` | OPTIONAL: `true` when the provider takes the place of a shipped one of the same name |

Providers are not special. The providers an implementation ships with are ordinary provider
documents embedded in it, in the same format and checked by the same rules. An implementation MUST
let the operator read them out (for instance, `spiffex provider show github`), and MUST NOT give a
shipped provider any behaviour a provider in the state could not have.

A provider in the state may take the place of a shipped one of the same name only if it says so
with `overrides: true`; without it, the state is invalid. Overriding keeps the state's version even
when a later release changes the shipped one, so the management API and the validator MUST report
every override, and the issuer logs them at startup.

An implementation SHOULD ship at least:

- `keys`: a `keys` proof with name `{member}`;
- `kubernetes`: section 5.5;
- `github` and `gitlab`: shared, with the owner as a required parameter;
- `oidc`: a shared `jwt` proof using discovery, whose issuer and owner claims are parameters.
  Because it is shared, every origin using it must pin an owner with an exact `match` on one of
  those claims (section 5.3). An upstream that is not shared needs its own provider.

### 5.1 Parameters

Substitution is one pass over the provider document, before anything else reads it:

- A value that is exactly the string `$<param>` is replaced by the origin's value for that
  parameter: a `list` parameter only where a list is expected, a `string` parameter where a string
  is expected, including as an element of a list.
- A `$` anywhere else is literal text, and text that came from a parameter is never substituted
  again.
- There is no other templating: no conditionals, no loops, no concatenation.

Parameter names are 1 to 63 characters from `a-z 0-9 _ -`, starting with a letter. A whole value
`$<name>` naming a parameter the provider does not declare, or appearing in a field that cannot take
a parameter, is an error, not literal text. An origin that omits a required parameter, sets
one the provider does not declare, or gives one of the wrong type MUST be refused.

Only these fields may take a parameter: `issuer`, `audience`, `jwks_uri`, `owner_claims` (of a
`jwt` proof) and `audiences`, and the patterns of `match` and `deny`. All other fields, `shared` and `discovery` among them, are literal
in the provider.

### 5.2 The `jwt` proof

| Field | |
|---|---|
| `issuer` | the upstream's `iss`, compared exactly |
| `audience` | OPTIONAL: the audience the upstream's tokens must carry; the origin audience when absent (below) |
| `jwks`, `jwks_uri`, `jwks_file`, `discovery` | exactly one: an inline JWK Set; an `https` URL; a local file, reread when it changes; or `true` to read `jwks_uri` from the upstream's OIDC discovery document, whose `issuer` MUST equal `issuer` |
| `ca_file` | OPTIONAL: CA certificates to trust when fetching keys |
| `bearer_token_file` | OPTIONAL: a token sent when fetching keys, read at each fetch |
| `shared` | REQUIRED: whether anyone can obtain tokens from the upstream (section 5.3) |
| `owner_claims` | claim paths that name a token's owner; REQUIRED when `shared` is true, unless the issuer is well known (section 5.3) |
| `max_token_lifetime` | OPTIONAL: refuse subject tokens issued to live longer than this; a whole number of seconds, minutes or hours written as `90s`, `30m` or `1h`; `1h` when absent, at most `24h` |

**Audience.** The **origin audience** is the issuer URL followed by `/origins` and the origin's
prefix, for example `https://issuer.example.org/origins/kube`, or `<issuer URL>/origins` for prefix
`/`. It never equals one of the issuer's endpoints. A `jwt` origin's
audience is its origin audience unless the provider or origin sets another. Because prefixes do not
overlap, origin audiences never collide, and an upstream's tokens name the origin they are meant
for. An origin whose audience, after expansion, is anything else (whether written in the provider
or filled from a parameter) can be created or changed through the management API only by those who
hold `write` on `/` (section 8.3), so that a writer with a narrower scope cannot claim an audience
other origins' workloads already use.

**Local files.** `jwks_file`, `ca_file` and `bearer_token_file` name files on the issuer's machine.
The issuer MUST refuse any path not listed in its own settings, outside the state:

- a list of files that may be read as `jwks_file` or `ca_file`;
- a list of bearer token files, each with the hosts it may be sent to.

Its defaults allow exactly what the shipped `kubernetes` provider needs and nothing else: the
in-cluster service account CA as a `ca_file`, and the in-cluster service account token as a bearer
token for `kubernetes.default.svc.cluster.local`. No error message, log line or management response
may include a local file's content.

**Fetching keys.**

- Fetches use `https` and never follow redirects.
- A bearer token is sent only to a host its setting allows, and only when that host is the host of
  `jwks_uri`, or of `issuer` when `discovery` is used. It is never sent to a host a discovery
  document names.
- Responses are limited to 1 MiB and 100 keys, and each fetch to 15 seconds.
- Fetched keys are cached and refreshed periodically, and early when a token names a key the cache
  lacks, at most every 30 seconds. When the upstream cannot be reached, cached keys stay usable for
  at most 24 hours.
- Which addresses the issuer may fetch from is deployment policy. An implementation SHOULD offer a
  setting that refuses loopback, link-local and private addresses for fetches made for origins, on
by default, with a list of hosts and ports exempt from it.

### 5.3 Shared upstreams

An upstream is **shared** when anyone can obtain a token from it carrying the configured audience: a
public CI provider, a cloud provider's global issuer. Trusting a shared upstream means trusting
strangers, unless admission pins the owner. The same holds for an `exec` verifier that accepts
proofs anyone can obtain, such as any signed request from any cloud account. Therefore, for `jwt`
and `exec` proofs alike:

- An implementation MUST know a list of well-known public issuers, each with the claims that name
  the token's owner. Issuers on the list are treated as shared whatever the document says. The list
  MUST include at least these:

  | Issuer | Owner claims |
  |---|---|
  | `https://token.actions.githubusercontent.com/...` (GitHub, and GitHub Enterprise under it) | `repository_owner_id`, `repository_id`, `enterprise_id` |
  | `https://gitlab.com` | `namespace_id`, `project_id` |
  | `https://accounts.google.com`, `accounts.google.com` | `sub` |
  | `https://oidc.circleci.com/org/...` | `oidc.circleci.com~1project-id` |
  | `https://login.microsoftonline.com/...`, `https://sts.windows.net/...` | `tid`, `oid` |
  | `https://app.terraform.io` | `terraform_organization_id` |

  An entry written as `<url>/...` covers `<url>` itself and every issuer that continues `<url>`
  with `/`; other entries match exactly.

- Admission of a shared upstream MUST include a `match` entry with only exact patterns on one of
  its owner claims. For a well-known issuer the owner claims are those in the table, whatever the
  provider declares; for any other shared upstream they are the proof's `owner_claims`.
- No owner claim may be `iss`, `aud`, `azp`, `exp`, `iat`, `nbf` or `jti`, which say nothing about
  who obtained the token.

These checks apply to the expanded origin (section 6.2), whatever its key source, so neither a
provider nor an origin can avoid them. A provider for a shared upstream SHOULD make the owner a
required parameter.

### 5.4 The `exec` proof

The `exec` proof is the escape hatch for proofs spiffex does not understand itself: a signed cloud
API request, a TPM quote, a token format of its own. A local program, the **verifier**, turns the
proof into claims. Admission, naming, owner pinning, prefixes and grants then work as for a `jwt`
origin. Unlike a JWT, though, only the verifier can tell whether a proof was made for this issuer,
so binding the proof to its origin is the verifier's job (below).

| Field | |
|---|---|
| `command` | the verifier's argument vector: an absolute path followed by fixed arguments. Literal, never a parameter |
| `timeout` | OPTIONAL: how long the verifier may run; `5s` when absent, at most `30s`, in the format of `max_token_lifetime` |
| `shared` | REQUIRED: whether anyone can obtain a proof the verifier accepts (section 5.3) |
| `owner_claims` | as for `jwt` (section 5.2), literal |

**Installing a verifier.** A verifier runs inside the issuer's trust boundary, so only the operator
can install one. The issuer's own settings, outside the state, list the allowed verifiers as
complete argument vectors, and a provider's `command` MUST equal one of them exactly, compared as
strings, without resolving symbolic links. The list is empty by default. A state writer can choose
among the verifiers the operator installed, never add one or change their arguments. Because a
verifier runs with the issuer's network access and credentials, creating or changing an `exec`
origin through the management API requires `write` on `/` (section 8.3).

**Running it.** For each request, the issuer:

1. refuses the proof if it is not valid UTF-8 (`invalid_request`), or if it parses as a JWT whose
   `iss` is the issuer URL, so the issuer's own tokens never pass through a verifier;
2. runs the command directly, without a shell, with an empty environment, in a new process group,
   and with no open file descriptors other than standard input, output and error. Running
   verifiers as a separate, less privileged user is RECOMMENDED;
3. writes one JSON object to its standard input and closes it:

   ```json
   {
     "version": 1,
     "issuer": "https://issuer.example.org",
     "origin": "aws",
     "audience": "https://issuer.example.org/origins/aws",
     "subject_token": "<the proof, as sent>",
     "params": { "account": "123456789012", "regions": ["eu-north-1"] }
   }
   ```

   `audience` is the origin audience (section 5.2). `params` holds every parameter of the
   provider, with the origin's values or the defaults, strings as strings and lists as arrays of
   strings. Parameters reach the verifier only this way, as data, and a verifier MUST treat them as
   untrusted input: they come from the state, not from the operator who installed it;
4. reads its standard output, and kills the whole process group when the timeout passes;
5. accepts the proof only if the verifier exits with status 0 within the timeout, its standard
   output is at most 64 KiB, and that output is exactly one JSON object with a `claims` member that
   is a JSON object. Other members are ignored. A duplicated member name anywhere in the output is
   a rejection. Claims follow section 4.3: they may nest objects, and an integer counts exactly as
   the verifier wrote it.

Any other outcome is a rejected subject token, answered like any other (section 3.1). The issuer
MUST NOT pass the verifier's output or standard error to the client, and SHOULD log a bounded
excerpt of the standard error.

**What the verifier must check.** Besides the proof's own validity, a verifier MUST accept a proof
only if the proof itself names the `audience` it was given, in whatever way its format allows (a
signed header, a signed field, an audience claim). Without that, a proof made for another service,
or for another origin using the same verifier, could be replayed here. A verifier is also
responsible for refusing proofs that are stale or replayed, since only it understands them.

**Limits.** The issuer MUST bound the number of verifiers running at once, both for each origin and
in total, and answer `server_error` when a bound is reached, so one origin cannot starve another.
It MUST also limit the rate at which one client address can start verifiers.

Validation never runs a verifier.

### 5.5 Example

The `kubernetes` provider, as an implementation might ship it:

```yaml
description: Pods in the cluster the issuer runs in, by service account.
params:
  issuer: { type: string, default: https://kubernetes.default.svc.cluster.local }
  namespaces: { type: list, default: ["*"] }
  deny_namespaces: { type: list, default: [kube-system] }
proof:
  jwt:
    issuer: $issuer      # managed clusters (EKS, GKE, AKS) put another URL in their tokens
    jwks_uri: https://kubernetes.default.svc.cluster.local/openid/v1/jwks
    ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    shared: false
require: [kubernetes.io/pod/name]
match: { kubernetes.io/namespace: $namespaces }
deny: { kubernetes.io/namespace: $deny_namespaces }
name: ns/{kubernetes.io/namespace}/sa/{kubernetes.io/serviceaccount/name}
```

An origin using it:

```yaml
kube:
  provider: kubernetes
  with:
    namespaces: [customer-*, platform]
```

A pod of service account `backend` in namespace `customer-acme`, with a token projected for the
origin audience `https://issuer.example.org/origins/kube`, gets
`spiffe://example.org/kube/ns/customer-acme/sa/backend`.

## 6. State

### 6.1 The state document

The state is one document with three maps, each keyed by name:

```yaml
origins:
  kube:
    provider: kubernetes
    with: { namespaces: [customer-*, platform] }
  vms:
    provider: keys
    members:
      billing: { keys: ["-----BEGIN PUBLIC KEY-----\n..."] }
providers:
  partner-idp: { ... }        # section 5
grants:
  controller: { ... }         # section 8.2
```

The document is the unit of change. An issuer MUST apply a new state as a whole or not at all, so
it never acts on an origin whose provider or members are missing. How the document is stored (one
file, a directory of files, a Kubernetes ConfigMap) is up to the implementation, provided every
form converts to this one without loss. The document MUST NOT exceed 1 MiB, encoded as JSON, and
MUST NOT hold more than 256 grants, or a grant more than 16 scopes, which keeps the closure check of
section 8.2 cheap.

Whoever can write the stored state directly controls every identity. That access is the way in for
the first grant (section 8.5), and the way back when every granted identity is lost.

### 6.2 Validation

The state is valid when its documents match the published schemas (section 6.3) and, after each
origin is expanded with its provider and parameters, the following hold:

- every origin names a provider in the state or shipped with the implementation;
- a provider in the state with a shipped provider's name sets `overrides: true`, and no other does;
- parameters satisfy section 5.1;
- prefixes do not overlap (section 4.1);
- no two `jwt` origins have the same upstream issuer and the same audience;
- name templates, patterns and members satisfy sections 4.1 to 4.4;
- `jwt` proofs satisfy sections 5.2 and 5.3;
- `exec` proofs satisfy section 5.4, and their `shared` and `owner_claims` section 5.3;
- a `keys` origin has no `require`, `match` or `deny`, and only a `keys` origin has `members`;
- grants satisfy section 8.2, including its closure rule;
- no `jwt` upstream issuer equals the issuer URL, ignoring a trailing `/`, and no `jwt` audience is
  the issuer URL or under it, other than the origin's own origin audience, so no origin can claim
  the issuer's endpoints or another origin's audience;
- a `jwt` proof with `jwks` or `jwks_file` has no `ca_file` or `bearer_token_file`, which only
  apply to fetched keys;
- no pattern in `match`, `deny` or `audiences` is empty;
- `svid_types`, on a provider or an origin, is not empty and lists only `jwt` and `x509`, each at
  most once;
- a member key given as a JWK has `use` absent or `sig`, and an `alg`, if present, that fits the
  key;
- an `exec` command's path is absolute and clean (no `.` or `..` segments, no repeated `/`).

An issuer MUST refuse an invalid state as a whole: at startup it does not start, and while running
it keeps serving the last valid state and reports the error. The management API MUST refuse a
change that would make the state invalid (section 8.3). Validation MUST NOT fetch anything over the
network.

### 6.3 Schemas and checking

The formats of the state document, a provider and an origin are published as JSON Schema (draft
2020-12) documents with stable `$id`s, so editors can complete and check them as they are typed.
Schemas cover structure; the rules of section 6.2 that relate one part of the state to another are
beyond them.

An implementation MUST offer a way to run the full validation of section 6.2 without an issuer: on
a state, on a single provider, or on a single origin together with the providers it uses. Checks
that relate objects to each other (prefix overlap, audience uniqueness, closure) need a whole state
and are skipped, and reported as skipped, for a single object. It SHOULD
also offer, for a given subject token and state, an explanation of the origin the token reaches,
whether it is admitted and why not, and the SPIFFE ID it would get. The issuer and the management
API run the same validation.

## 7. Issued SVIDs

### 7.1 The JWT-SVID

The issued token is a JWT-SVID as defined by [JWT-SVID]:

- Header: `alg` (ES256 or RS256), `kid` (a key in the JWKS), `typ: "JWT"`.
- Claims: `iss` (the issuer URL), `sub` (the SPIFFE ID), `aud` (a string when one audience was
  requested, otherwise an array), `exp`, `iat`, `jti`. No other claims.

The lifetime is chosen by the issuer, SHOULD be a few minutes, and MUST NOT exceed one hour. A
token for the management endpoint MUST NOT live longer than five minutes. Verifiers MUST check the
signature, `exp`, that `aud` contains their own expected audience, and that `sub` is a valid SPIFFE
ID in the trust domain the key belongs to. Verifiers that know the issuer URL SHOULD check `iss`.

Removing an origin or member stops new tokens for it once the issuer has taken up the change
(section 8.3). Tokens already issued stay valid until they expire.

### 7.2 The X.509-SVID

The issued certificate is an X.509-SVID as defined by [X.509-SVID], built as section 3.4 says. Its
lifetime is chosen by the issuer, is one hour unless the issuer is set otherwise, and MUST be at
least 10 minutes and MUST NOT exceed 24 hours. Verifiers MUST validate the chain against the X.509
authorities of the trust domain's bundle, check validity times, and take the SPIFFE ID from the
single URI SAN, as the [X.509-SVID] standard requires. They MUST NOT take an identity from the
subject. They SHOULD enforce name constraints.

An X.509-SVID cannot be revoked. Removing an origin or a member stops new SVIDs for it once the
issuer has taken up the change (section 8.3); SVIDs already issued stay valid until they expire,
which is why their lifetime is short.

X.509-SVIDs never authenticate to the management API (section 8.1): it accepts only JWT-SVIDs
addressed to it.

## 8. The management API

The management API reads and changes the state while the issuer runs. An issuer MAY leave it
disabled, in which case the state changes only through its storage.

### 8.1 Authentication

Every request carries `Authorization: Bearer <JWT-SVID>`. The issuer MUST accept the token only if:

- it verifies against the issuer's own published keys, and `iss` is the issuer URL;
- `aud` is exactly the management endpoint URL `<issuer>/manage`, as a string or one-element array;
- `exp` has not passed, and `exp` minus `iat` is at most five minutes;
- the caller, the token's `sub`, is still issuable: its path is within the prefix of an origin and,
  when that is a `keys` origin, filling its name template for some current member gives the
  caller's SPIFFE ID.

Once the issuer has taken up the change (section 8.3), the last rule makes removing an origin or
member revoke its management access, rather than waiting for its tokens to expire. For a `jwt`
or `exec` origin the check looks only at the prefix: narrowing its admission does not revoke a token already
issued.

Callers obtain these tokens like any other, by requesting the audience `<issuer>/manage`, alone,
from the token endpoint. A token for that audience is useless anywhere else: a client assertion must
be addressed to the issuer URL (section 3.2), the token endpoint refuses its own tokens as subject
tokens (section 3.3), and the audience is never combined with another (section 3).

An identity whose origin's `svid_types` lacks `jwt` cannot obtain one, so grants to it give nothing;
removing `jwt` does not revoke a management token already issued.

A client certificate, an X.509-SVID included, is never a way to authenticate to the management API.

A missing or invalid token gets `401` with `WWW-Authenticate: Bearer`. The issuer SHOULD refuse a
management token whose `jti` it has already seen on a write that was authorized; recording `jti`s
before authorization would let any workload fill the record. Processes that do not share the record
let a token write once per process within its five minutes, and an implementation MUST say so in
its documentation.

### 8.2 Grants and permissions

A **grant** has a name, and:

| Field | |
|---|---|
| `who` | a SPIFFE ID pattern (below) |
| `can` | one or more of `read`, `write`, `delegate` |
| `on` | one or more **scopes**: paths in the sense of an origin prefix (section 4.1); `/` is everything |

A **SPIFFE ID pattern** is a SPIFFE ID in the trust domain whose path segments may be `*`, matching
any one segment, and whose last segment may be `**`, matching one or more segments. Its **literal
prefix** is the path before its first `*` or `**` segment.

| Permission | Allows, within the scope |
|---|---|
| `read` | reading origins (with their members) and grants; `write` and `delegate` imply it |
| `write` | creating, changing and removing origins and their members; with scope `/`, also providers |
| `delegate` | creating, changing and removing grants, subject to the rules below |

A path is **within** a scope when it equals the scope or extends it by whole segments. An origin is
within a scope when its prefix is, and a grant is when each of its scopes is. A caller **holds** a
permission on a path when a grant whose `who` matches the caller gives that permission on a scope
the path is within. Permissions are evaluated against the current state on every request.

**Writing is becoming.** `write` on `/vms` lets the caller create any origin under `/vms` and admit
anyone into it, so the caller can take on any SPIFFE ID under `/vms`. The rules below follow from
that, and from the prefix rule of section 4.1.

- **No escalation.** To create, change or remove a grant, the caller MUST hold `delegate` on each of
  the grant's scopes, and MUST hold every permission the grant gives, in its old and its new form,
  on each of its scopes.
- **Closure.** The set of grants MUST be closed: whenever a grant A gives `write` on a scope S, and
  some SPIFFE ID within S matches the `who` of a grant B, every identity matching A's `who` MUST
  hold every permission B gives, on each of B's scopes. Otherwise writing under S would be a way to
  become B's subject without holding what B gives. The check is part of validation (section 6.2),
  so it applies to every change of origins or grants, and to state written directly.

Closure is decided exactly as follows, so every implementation reaches the same answer. For every
pair of grants A and B (A and B may be the same grant) where A gives `write` on a scope S and S
**reaches** B's `who`, then for every permission p B gives and every scope s of B, there MUST be a
single grant G whose `who` **covers** A's `who`, which gives p (`write` and `delegate` give `read`
too), and one of whose scopes s
is within. G may be a different grant for each pair (p, s), but for any one pair a single grant's
`who` must cover A's `who` by itself: several grants whose patterns only together cover it do not
count.

Both relations compare the segments of the paths, with `*` and `**` as in a SPIFFE ID pattern:

- A scope S reaches a pattern W when some path within S matches W. Compare S's segments with W's
  from the start, pairwise, for as long as both have segments: a literal in W must equal the
  segment of S, `*` accepts any, and `**` accepts all that remains, so S reaches W. Otherwise, S
  reaches W when both run out together or S runs out first, and does not when W runs out first.
- A pattern P covers a pattern Q when every SPIFFE ID matching Q matches P. If P has no `**`, Q
  must have no `**` and the same number of segments as P, and each segment of P must be `*` or
  equal to the literal segment of Q in that place. If P ends in `**` after k other segments, Q must
  have more than k segments, none of its first k may be `**`, and each of P's first k segments must
  be `*` or equal to Q's literal segment there. A `*` in Q is covered only by `*` or `**` in P.

When a grant change is refused for breaking closure, the `422` reasons MUST name the grants
involved and the missing permission, so the operator can see which grant to remove first.

### 8.3 Endpoints

All bodies are JSON, in the shapes of section 6.1. Names in paths follow the rules for their kind.
Request bodies MUST NOT exceed 1 MiB.

| Request | Permission |
|---|---|
| `GET /manage/state` | none; returns the providers, and the origins and grants the caller may read |
| `GET /manage/origins/{name}` | `read` on the origin's prefix |
| `PUT /manage/origins/{name}` | `write` on the old and the new prefix; `write` on `/` when the expanded origin's audience is not its origin audience (section 5.2), or when it is an `exec` origin (section 5.4) |
| `DELETE /manage/origins/{name}` | `write` on the origin's prefix |
| `PUT /manage/origins/{name}/members/{member}` | `write` on the origin's prefix; body `{"keys": [...]}` as in section 4.2; `422` on a `jwt` origin |
| `DELETE /manage/origins/{name}/members/{member}` | `write` on the origin's prefix |
| `GET /manage/providers/{name}` | none; reports whether it overrides a shipped provider |
| `PUT /manage/providers/{name}` | `write` on `/` |
| `DELETE /manage/providers/{name}` | `write` on `/` |
| `GET /manage/grants/{name}` | `read` on each of the grant's scopes |
| `PUT /manage/grants/{name}` | section 8.2 |
| `DELETE /manage/grants/{name}` | section 8.2 |
| `POST /manage/check` | `read` on `/`; validates a proposed state document without applying it |

`PUT` creates or replaces. Every response that returns or changes the state carries its version in
an `ETag` header. A write MAY carry `If-Match` with a version, and clients SHOULD send it; if the
state has changed since, the write fails with `412` and changes nothing.

A write MUST be stored durably before it succeeds, and MUST be refused if the resulting state would
be invalid. Every process serving the issuer URL takes it up within a bounded time the
implementation documents.

| Situation | Status |
|---|---|
| Missing or invalid token | 401 |
| Valid token, permission missing for an object the caller may read | 403 |
| Read of an object that is absent or that the caller may not read | 404 |
| Write to a name, prefix, or upstream issuer and audience taken by an object the caller may not read | 409 |
| `If-Match` does not match | 412 |
| The change would make the state invalid | 422, with the reasons |
| A body that is not one JSON value of the expected shape, or has unknown fields | 400 |
| A body larger than 1 MiB | 413 |
| The caller is over its rate limit | 429, with `Retry-After` |
| The stored state cannot be read or is invalid, or a write kept losing to others | 503 |

The `422` reasons, and every other response, MUST NOT include any part of an object the caller may
not read, beyond the non-secret fields of section 4.

Every successful write MUST be logged with the caller's SPIFFE ID, the object changed and the new
version.

### 8.4 Wire format

Request and response bodies are JSON, `Content-Type: application/json`, in the shapes of section
6.1: an origin, a provider or a grant as it appears in the state document, a member as
`{"keys": [...]}`, and the state as the whole document.

- **Success.** A read answers `200` with the object. A `PUT` answers `201` when it created the
  object and `200` when it replaced it, with the object as stored. A `DELETE` answers `204`.
- **Versions.** The `ETag` is the state version as a quoted string. `If-Match` takes one or more
  such strings, or `*`, which matches any existing state.
- **Errors.** Every answer other than a success has the body
  `{"error": "<message>", "problems": [{"path": "<path>", "message": "<message>"}]}`, where
  `problems` is present only for `422` and `path` names a place in the state document, such as
  `origins.web.prefix`, or is absent for the document as a whole.
- **Check.** `POST /manage/check` answers `200` with
  `{"valid": <bool>, "problems": [...], "overrides": ["<provider>", ...]}`, without an `ETag`.
- **Providers.** `GET /manage/providers/{name}` serves shipped providers as well as those in the
  state, and says which with the header `Spiffex-Provider-Source: state` or `shipped`. Responses to
  `GET /manage/state` and `GET /manage/providers/{name}` carry `Spiffex-Overrides`, the names of
  the state's providers that take the place of shipped ones, separated by commas, when there are
  any.

### 8.5 Bootstrap

An issuer starts with empty state and no grants, so nobody can use the management API. The first
origin and the first grant are written to the stored state directly, by whoever has that access
(section 6.1). From then on, the granted identity can do the rest through the API.

## 9. The agent

An agent serves the `SpiffeWorkloadAPI` gRPC service of the [Workload API] on a Unix domain socket.
It MUST NOT listen on TCP: it performs no attestation, so whoever reaches the endpoint receives the
identity. Workloads find it through `SPIFFE_ENDPOINT_SOCKET=unix:///path/to/socket`.

When the issuer issues X.509-SVIDs (its discovery document has `spiffex_x509_svid_supported: true`,
which the agent reads at start and at each bundle refresh), the agent implements the X.509-SVID and
JWT-SVID profiles of the [Workload API] and is a complete Workload API server. When it does not, the
agent implements the JWT-SVID profile only and the X.509 RPCs fail with `Unimplemented`: workloads
then use the JWT parts of their SPIFFE library (for go-spiffe, `workloadapi.NewJWTSource`,
`FetchJWTSVID`, `ValidateJWTSVID`) and not the X.509 or combined bundle sources, which retry
`Unimplemented` until their deadline.

A workload whose origin's `svid_types` (section 4.5) lacks `x509`, as by default for an origin with
an audience restriction, gets `PermissionDenied` from `FetchX509SVID` and uses the JWT parts of its
library as above; one whose list lacks `jwt` gets `PermissionDenied` from `FetchJWTSVID`.

| RPC | Behaviour |
|---|---|
| `FetchJWTSVID` | Returns a JWT-SVID for the requested audiences, obtained from the token endpoint. If `spiffe_id` is set and differs from the workload's identity, fails with `PermissionDenied`. |
| `FetchJWTBundles` | Streams the trust domain's JWT bundle, keyed by the trust domain's SPIFFE ID (`spiffe://example.org`), and sends an update whenever the key set changes. Each key carries `kid` and `use: "jwt-svid"`. A bundle without keys is never sent: the agent keeps the last good bundle, and until it has one the stream waits. |
| `ValidateJWTSVID` | Validates the token against the bundle and the given audience, and returns its SPIFFE ID and all of its claims. |
| `FetchX509SVID` | Streams the workload's X.509-SVID: the certificate chain, the private key (PKCS#8 DER) and the trust domain's X.509 bundle, as the standard shapes them. The agent holds one current X.509-SVID for the workload and sends it to every open stream. It generates a new P-256 key for each SVID, and obtains a new SVID when the current one has lived between 40 and 50 percent of its lifetime (random within that window), measured from the certificate's `notBefore` and `notAfter`. It retries with backoff while the issuer fails, and never sends an SVID with less than a tenth of its lifetime left. It sends an update to every stream whenever the SVID or the trust domain's X.509 authorities change. `crl` and `federated_bundles` are empty. Until the first SVID exists a stream waits. When the issuer refuses a request, the first or a renewal (`PermissionDenied` below), every open stream ends with that code; the agent remembers the refusal for at least a minute and answers new streams with it without asking the issuer again. |
| `FetchX509Bundles` | Streams the X.509 authorities of the trust domain's bundle, keyed by the trust domain's SPIFFE ID, and sends an update whenever they change. |
| `FetchWITSVID`, `FetchWITBundles` | Fail with `Unimplemented`. |

The agent's gRPC status codes:

| Situation | Code |
|---|---|
| Missing `workload.spiffe.io: true` metadata | `InvalidArgument` |
| `FetchJWTSVID` or `ValidateJWTSVID` without an audience, or an empty token | `InvalidArgument` |
| `ValidateJWTSVID` given a token that does not validate | `InvalidArgument` |
| The issuer refused the request (`invalid_client`, `invalid_request`, `invalid_target`, `unsupported_grant_type`) | `PermissionDenied` |
| The issuer is unreachable or failed, or no bundle has been fetched yet | `Unavailable` |
| The issuer issues no X.509-SVIDs and `FetchX509SVID` or `FetchX509Bundles` is called | `Unimplemented` |
| The agent cannot produce its own proof of identity (an unreadable subject token file, or a subject token command that fails) | `FailedPrecondition` |

An agent supports both grants of section 3 and is configured to use one. For token exchange it
obtains the subject token for each request either by reading a file, which platforms such as
Kubernetes rotate in place, or by running a configured command without a shell and taking its
standard output, for proofs that must be made fresh (a signed cloud API request, for one). It sends
the subject token type its configuration names and, for an `exec` origin, the origin's name. For an
X.509-SVID it adds `requested_token_type` and a `csr` (section 3.4). It SHOULD reuse a JWT-SVID
for the same audiences until half its lifetime has passed, and SHOULD refresh the bundle at the
issuer's `spiffe_refresh_hint`.

The private keys of X.509-SVIDs exist only in the agent's memory and in the responses it sends over
the socket. An agent MUST NOT write them to disk.

Deployments MUST restrict access to the socket: file permissions, or a volume shared only with the
workload's own containers. A workload whose identity holds grants can obtain management tokens
through its agent, so the socket carries those permissions too, and it carries the private keys of
X.509-SVIDs.

## 10. Security considerations

- **The issuer is the trust root.** Its signing keys can mint any identity in the trust domain.
  Store them like any CA key and rotate them (section 2.4).
- **The state is the policy.** Whoever can write the stored state, and any identity holding `write`
  on `/`, controls every identity. Grant that sparingly and protect the storage like the signing
  keys. The issuer's settings (section 5.2) bound what even they can do with files on the issuer's
  machine.
- **Writing is becoming.** `write` on a scope is the power to take on any identity in it
  (section 8.2). Scope grants narrowly, and keep identities that hold grants in scopes nobody else
  can write.
- **Upstreams can be becoming too.** Closure reasons only about grants. Whoever controls an upstream
  can take on the identities its origin issues: whoever can create a service account in a namespace
  becomes the identity that service account maps to. Give grants to identities from `keys` origins,
  or from upstreams where creating such an identity is itself tightly controlled.
- **The certificate authority is a second trust root.** Its keys can mint any X.509 identity in the
  trust domain. Guard them like the JWT signing keys and keep them in separate directories, so that
  a mistake in one mount or Secret does not expose the other; both live in one process. Prefer an
  intermediate under an offline root, so the root can replace a compromised intermediate.
- **Name constraints are the CA's fence.** A verifier that does not enforce them trusts a stolen CA
  key for any name it accepts, not only SPIFFE IDs of this trust domain. Pin the trust domain's
  bundle only in the places that should accept these identities, never in a system trust store.
  Enforcement differs between verifiers: OpenSSL does not apply the excluded `rfc822Name` subtree to
  email SANs, so a verifier MUST take the identity from the URI SAN alone and ignore every other
  name. A shared root (section 2.5.1) is not fenced against sibling CAs minting identities of this
  trust domain, whatever its constraints say; only `ca_roots_dedicated` states that none exist.
- **X.509-SVIDs carry no DNS name.** So a server that must be reached by name keeps a certificate
  for its DNS name from another CA (a database with libpq `sslmode=verify-full`, for one). A TLS
  client that trusts the bundle but cannot authorize the server's SPIFFE ID (libpq with
  `sslmode=verify-ca`) accepts any workload of the trust domain as the server, as every X.509-SVID
  carries `serverAuth`.
- **The identity is the SAN.** The subject is a convenience for consumers that read only it
  (section 3.4); a verifier that takes an identity from the CN or DN instead of the URI SAN gives up
  the guarantee that a CSR cannot name anything.
- **A CSR is input from the requester.** Only its public key is used; an implementation that copies
  any requested name or extension into a certificate breaks the naming rules of section 4.
- **X.509-SVIDs have no audience.** An audience restriction does not apply to them (section 4.4), so
  an origin with one gets JWT-SVIDs only unless it lists `x509` (section 4.5). Set
  `svid_types: [jwt]` on any other origin whose identities should not be able to authenticate to
  every server that trusts the bundle.
- **The log is the only record.** X.509-SVIDs cannot be revoked; the issuer's log of serial numbers
  and SPIFFE IDs is how a stolen certificate is traced, and short lifetimes are the only other
  defence.
- **Proofs, not shared secrets.** A `keys` origin stores only public keys; a `jwt` origin stores
  nothing about the workload at all. Reading the state does not let anyone impersonate a workload.
- **JWT-SVIDs are bearer tokens.** Anyone holding one can use it against its audiences until it
  expires. Keep lifetimes short, request narrow audiences, and send them only over TLS. Management
  tokens carry the caller's permissions for up to five minutes.
- **Audience is the receiver's job to check.** An origin may restrict which audiences its
  identities may request, but a receiver MUST still check `aud` itself.
- **Upstream trust is delegated trust.** Trusting an upstream means trusting everyone who can get a
  token from it with the configured audience. Section 5.3 forces an owner pin for shared
  upstreams; for any other upstream, whoever can obtain its tokens (for Kubernetes, whoever may
  create service account tokens) can take on the identities it maps to.
- **Verifiers run inside the trust root.** An `exec` verifier runs with the issuer's privileges and
  reads proofs that anyone can send. Only the operator can install one (section 5.4); treat it as
  part of the issuer, keep it small, and make it refuse anything it does not fully understand.
- **Verifiers own the audience binding.** For a JWT the issuer checks that the proof was made for
  this origin; for an `exec` proof only the verifier can. A verifier that skips that check lets
  proofs made for other services, or for laxer origins, be replayed (section 5.4).
- **Origins make the issuer fetch URLs.** An identity allowed to create a `jwt` origin chooses a URL
  the issuer fetches keys from, which reaches whatever the issuer's network reaches. Section 5.2
  bounds those fetches and keeps the issuer's credentials from going there; restrict the issuer's
  outbound access as well.
- **Chaining issuers.** Using another spiffex issuer as an upstream is legitimate but must be
  deliberate; rule 1 of section 3.3 only prevents an issuer from exchanging its own tokens.

## 11. Notes for AWS federation

AWS IAM accepts the issuer as an OIDC identity provider when the issuer URL has no port and no
trailing slash, the JWKS is served with a certificate from a publicly trusted CA, and tokens carry
`iat` and a SPIFFE ID of at most 255 characters. The token's `aud` must match a client ID registered
on the provider; requesting that single audience is RECOMMENDED. Trust policies then condition on
`<issuer URL without https://>:sub` and `<issuer URL without https://>:aud`.

[SPIFFE-ID]: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md
[JWT-SVID]: https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md
[X.509-SVID]: https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md
[Trust Domain and Bundle]: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md
[SPIFFE Federation]: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md
[Workload API]: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC 2986]: https://www.rfc-editor.org/rfc/rfc2986
[RFC 5280]: https://www.rfc-editor.org/rfc/rfc5280
[RFC 6749]: https://www.rfc-editor.org/rfc/rfc6749
[RFC 6901]: https://www.rfc-editor.org/rfc/rfc6901
[RFC 7517]: https://www.rfc-editor.org/rfc/rfc7517
[RFC 7523]: https://www.rfc-editor.org/rfc/rfc7523
[RFC 7523bis]: https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/
[RFC 7638]: https://www.rfc-editor.org/rfc/rfc7638
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174
[RFC 8414]: https://www.rfc-editor.org/rfc/rfc8414
[RFC 8693]: https://www.rfc-editor.org/rfc/rfc8693

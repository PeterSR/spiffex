# Providers

An origin is one way identities come in. Most of what an origin does comes from its **provider**: a
plain YAML document that says what counts as proof, which holders of such proof are admitted, and
how their SPIFFE IDs are named. The origin names a provider, fills in the provider's parameters
under `with`, and can add its own prefix, name template and admission rules on top.

<!-- check: state -->
```yaml
origins:
  ci:                      # the origin, spiffe://example.org/ci/...
    provider: github       # the provider it uses
    with:                  # values for the provider's parameters
      owner_id: "1234567"
      refs: [refs/heads/main]
```

spiffex ships five providers, embedded in the binary. They are ordinary provider documents, in the
same format you write your own in and checked by the same rules; nothing about them is special.
`spiffex provider list` lists them and `spiffex provider show NAME` prints one as it ships. The
full rules are in [SPEC.md section 5](../SPEC.md#5-providers).

## The shipped providers

### keys

Workloads that hold a private key, one member per workload, authenticating with `private_key_jwt`.
It has no parameters. Each member has one to ten public keys (PEM `PUBLIC KEY` blocks or JWKs), and
its SPIFFE ID is `<prefix>/<member>`, its client id `<origin>/<member>`.

<!-- check: state -->
```yaml
origins:
  vms:
    provider: keys
    members:
      billing:
        keys:
          - |
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeMs6PtCLLbQKPBYlHNZ1qOhtZmqA
            qMfrEWbOfPLgAAByHe3Rn/PDiv7t8NGs6znhbm6vMUOx7EjavC8uVIHnVA==
            -----END PUBLIC KEY-----
```

`billing` authenticates as client `vms/billing` and is `spiffe://example.org/vms/billing`. Make a
key pair with `spiffex key generate -out billing.key > billing.pub`. A `keys` origin whose `name`
has no `{member}` gives every member the same identity, each with its own key.

### kubernetes

Pods in the cluster the issuer runs in, by service account. Tokens must be bound to a pod
(`kubernetes.io/pod/name` is required), as the kubelet projects them.

| Parameter | Default | |
|---|---|---|
| `issuer` | `https://kubernetes.default.svc.cluster.local` | the cluster's service account issuer; managed clusters (EKS, GKE, AKS) use another URL |
| `namespaces` | `["*"]` | patterns of the namespaces admitted |
| `deny_namespaces` | `[kube-system]` | patterns of the namespaces refused |

<!-- check: state -->
```yaml
origins:
  cluster:
    provider: kubernetes
    with:
      namespaces: [shop, customer-*]
```

A pod of service account `billing` in namespace `shop` is
`spiffe://example.org/cluster/ns/shop/sa/billing`. The provider reads the cluster's keys from the
API server with the issuer's own service account token, so it works only for an issuer running in
that cluster. See [kubernetes.md](kubernetes.md).

### github

GitHub Actions workflows of one user or organization, by repository.

| Parameter | Default | |
|---|---|---|
| `owner_id` | required | the numeric id of the owner, the `repository_owner_id` claim |
| `refs` | required | patterns of the git refs whose workflows are admitted, as in the `ref` claim |
| `repository_ids` | `["*"]` | patterns of the numeric repository ids admitted |
| `issuer` | `https://token.actions.githubusercontent.com` | for GitHub Enterprise, the issuer under it that your enterprise uses |

<!-- check: state -->
```yaml
origins:
  ci:
    provider: github
    with:
      owner_id: "1234567"
      repository_ids: ["600100200"]
      refs: [refs/heads/main, refs/tags/v*]
```

A workflow of repository 600100200 is `spiffe://example.org/ci/600100200`. Pin the owner and
repositories by number, never by name: a name can be renamed and then taken by someone else. In the
workflow, ask for a token with the origin audience, `https://issuer.example.org/origins/ci`, and
trade it in:

```yaml
permissions:
  id-token: write
steps:
  - run: |
      gh_token=$(curl -sH "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://issuer.example.org/origins/ci" | jq -r .value)
      svid=$(curl -s https://issuer.example.org/token \
        -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
        -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
        -d subject_token="$gh_token" \
        -d audience=https://deploy.example.org | jq -r .access_token)
```

### gitlab

GitLab CI/CD jobs of one group or user namespace, by project. It pins exactly that namespace:
projects in its subgroups have namespace ids of their own and are not admitted.

| Parameter | Default | |
|---|---|---|
| `namespace_id` | required | the numeric id of the namespace, the `namespace_id` claim |
| `refs` | required | patterns of the branches or tags admitted, as in the `ref` claim |
| `project_ids` | `["*"]` | patterns of the numeric project ids admitted |
| `issuer` | `https://gitlab.com` | for a self-managed instance, its URL |

<!-- check: state -->
```yaml
origins:
  gitlab:
    provider: gitlab
    with:
      namespace_id: "4455667"
      refs: [main]
```

A job of project 7788990 is `spiffe://example.org/gitlab/7788990`. In `.gitlab-ci.yml`, declare an
ID token with `aud: https://issuer.example.org/origins/gitlab` under `id_tokens` and exchange it.

### oidc

Any OpenID Connect issuer that hands out tokens to anyone, such as a public cloud or CI provider.
The keys are found through the issuer's discovery document.

| Parameter | Default | |
|---|---|---|
| `issuer` | required | the issuer URL, as in the `iss` claim |
| `owner_claims` | required | the claims that name a token's owner |

Because the provider is shared, the origin must pin an owner itself (see
[below](#owner-pinning-for-shared-upstreams)). Google, for example, gives an ID token to any
service account of any project, so pin the service account's numeric id:

<!-- check: state -->
```yaml
origins:
  gcp:
    provider: oidc
    with:
      issuer: https://accounts.google.com
      owner_claims: [sub]
    match:
      sub: ["112233445566778899000"]
```

That service account is `spiffe://example.org/gcp/112233445566778899000`, with a token from
`gcloud auth print-identity-token --audiences=https://issuer.example.org/origins/gcp`. An upstream
that is not shared, where only you can obtain tokens, needs a provider of its own with
`shared: false`.

## How an origin uses its provider

The provider gives the origin its proof, its name template (`name`) and its admission
(`require`, `match`, `deny`). The origin can add:

| Field | |
|---|---|
| `with` | values for the provider's parameters |
| `prefix` | where its SPIFFE IDs live, `/<origin name>` when absent; prefixes of two origins never overlap |
| `name` | a name template in place of the provider's |
| `require`, `match`, `deny` | more admission rules; they apply on top of the provider's, so an origin can narrow its provider but never widen it |
| `audiences` | patterns of the audiences its identities may request, in place of the provider's default |
| `svid_types` | the kinds of SVID its identities may obtain, a non-empty list of `jwt` and `x509` (SPEC section 4.5), in place of the provider's default; when absent, `[jwt]` for an origin with an audience restriction (the provider's default does not apply to it), otherwise the provider's default or `[jwt, x509]`. A request for a kind the list lacks is refused with `invalid_target`, and the agent passes that on as `PermissionDenied` |
| `members` | for a `keys` provider, the members |

A **claim path** names a claim: `sub`, or `kubernetes.io/namespace` for the `namespace` member of
the `kubernetes.io` object. Write `~1` for a `/` inside a claim name. A **pattern** is literal text
in which `*` stands for any run of characters; it must match the whole value.

A **name template** is a `/`-separated list of literal segments and placeholders such as
`{repository_id}`, each filling one whole segment of the SPIFFE ID with a claim's value. A value
that is not a valid segment (letters, digits, `.`, `_` and `-`) refuses the token rather than being
escaped. In a `keys` origin the only placeholder is `{member}`. A placeholder can trim a fixed
text off its value first, with `{<claim>|trim_prefix:<text>}` or `|trim_suffix:<text>`; a value
without that text is refused, never passed through. These pods in the namespaces `team-a`,
`team-b` and so on get `spiffe://<trust domain>/teams/a/api`, `/teams/b/api`:

<!-- check: state -->
```yaml
origins:
  teams:
    provider: kubernetes
    with:
      namespaces: ["team-*"]
    match:
      kubernetes.io/serviceaccount/name: api
    name: "{kubernetes.io/namespace|trim_prefix:team-}/api"
```

This origin narrows the `github` provider to tagged releases of one repository, and gives them one
fixed identity under its own prefix:

<!-- check: state -->
```yaml
origins:
  releases:
    provider: github
    with:
      owner_id: "1234567"
      repository_ids: ["600100200"]
      refs: [refs/tags/v*]
    prefix: /ci/shop
    name: release
    require: [job_workflow_ref]
    match:
      job_workflow_ref: ["octo-org/shop/.github/workflows/release.yml@refs/tags/*"]
```

## Writing your own provider

A provider in the state sits under `providers`, next to the origins that use it. This one trusts a
partner's identity provider, which issues tokens only to the partner's own services:

<!-- check: state -->
```yaml
providers:
  partner-idp:
    description: Services of our partner, by OAuth client, from their identity provider.
    params:
      clients: { type: list, required: true }
    proof:
      jwt:
        issuer: https://idp.partner.example/realms/services
        discovery: true
        shared: false
        max_token_lifetime: 10m
    require: [azp]
    match: { azp: $clients }
    name: "{azp}"

origins:
  partner:
    provider: partner-idp
    with:
      clients: [billing-sync, orders-export]
```

The partner's `billing-sync` client is `spiffe://example.org/partner/billing-sync`, given a token
with the audience `https://issuer.example.org/origins/partner`.

A provider has these fields:

| Field | |
|---|---|
| `description` | text for humans |
| `params` | the parameters an origin fills in: each with `type: string` or `type: list`, and either `required: true` or a `default` |
| `proof` | exactly one of `jwt`, `keys: {}` or `exec` |
| `require`, `match`, `deny`, `name`, `audiences`, `svid_types` | as for an origin, above |
| `overrides` | `true` when it takes the place of a shipped provider of the same name |

The `jwt` proof:

| Field | |
|---|---|
| `issuer` | the upstream's `iss`, compared exactly |
| `jwks`, `jwks_uri`, `jwks_file`, `discovery` | exactly one: an inline JWK Set, an `https` URL, a file on the issuer's machine (one the settings list in `readable_files`), or `true` to use the upstream's OIDC discovery |
| `audience` | the audience the upstream's tokens carry; the origin audience when absent, which is almost always what you want |
| `ca_file` | CA certificates for fetching the keys, from `readable_files` |
| `bearer_token_file` | a token to send when fetching the keys, from `bearer_token_files` |
| `shared` | required: whether anyone can obtain tokens from the upstream |
| `owner_claims` | the claims that name a token's owner; required when `shared` is true |
| `max_token_lifetime` | refuse tokens issued to live longer than this, such as `30m`; `1h` when absent, at most `24h` |

A token reaches an origin by its `iss` and `aud`, and the **origin audience** (the issuer URL,
`/origins` and the origin's prefix) is unique to each origin. Setting `audience` to anything else
takes `write` on `/` through the management API, because it could capture tokens meant for other
origins. An audience at or under the issuer URL, other than the origin's own origin audience, is
refused outright, whoever writes it: it could be one of the issuer's endpoints or another origin's
audience. So is an `issuer` equal to the issuer URL: the issuer never takes its own tokens.

**Parameters.** A value that is exactly `$<param>` is replaced by the origin's value. A list
parameter can fill a list, and a string parameter a string or one element of a list. Nothing else
is substituted: a `$` inside a longer string is literal, and there are no conditionals, loops or
concatenation. Only `issuer`, `audience`, `jwks_uri` and `owner_claims` of a `jwt` proof,
`audiences`, and the patterns of `match` and `deny` may take a parameter; every other field,
`shared`, `discovery` and the local files among them, is literal in the provider.

**Overriding a shipped provider.** A provider in the state with the name of a shipped one must set
`overrides: true`, or the state is invalid. It then keeps your version even when a later release
changes the shipped one, so `spiffex check`, the management API and the issuer's log all report it.
Start from `spiffex provider show kubernetes > kubernetes.yaml`.

**Checking.** `spiffex check` validates a whole state, or a single provider or origin, with the
same rules the issuer uses, and fetches nothing:

```bash
spiffex check -settings issuer.yaml state.yaml
spiffex check -settings issuer.yaml -provider partner-idp.yaml
spiffex check -settings issuer.yaml -origin partner.yaml partner-idp.yaml
```

For a single provider or origin, the checks that need the whole state (prefix overlap, audience
uniqueness and grant closure) are skipped and reported as such. `spiffex explain -state state.yaml
-token token.jwt -settings issuer.yaml` shows which `jwt` origin a given token reaches, whether it
is admitted or why not, and the SPIFFE ID it would get; it does not verify the token's signature,
and never runs a verifier. The JSON Schemas in [schema/](../schema) let
an editor complete and check providers and origins as you type.

## The exec proof

Some proofs spiffex does not understand itself: a signed cloud API request, a TPM quote, a token
format of its own. For those, a provider's proof is `exec`, and a local program installed with the
issuer, the **verifier**, checks the proof and turns it into claims. Admission, naming, owner
pinning and grants then work as for a JWT.

| Field | |
|---|---|
| `command` | the verifier's path, absolute and clean (no `.` or `..` segments, no repeated `/`), and fixed arguments; never a parameter |
| `timeout` | how long it may run; `5s` when absent, at most `30s` |
| `shared` | required: whether anyone can obtain a proof the verifier accepts |
| `owner_claims` | as for `jwt` |

A verifier runs inside the issuer's trust boundary, so only the operator installs one: the
issuer's settings list each verifier as its complete argument vector, and a provider's `command`
must equal one of them exactly. Nothing is installed by default. Writing a provider or origin with
an `exec` proof through the management API takes `write` on `/`. Every identity that may call the
management API can read every provider, so a verifier's command line is no place for a secret.

**Keep the signing keys from the verifier.** Unless the settings set `verifier_user`, a verifier runs
as the issuer's own user, so it can read the signing keys and sign any identity it likes.
The issuer warns about this at startup. Set `verifier_user` to a user of its own, and keep the files
in `keys_dir` and the TLS key unreadable to that user and its group: with `verifier_user` set, the
issuer refuses to start otherwise, judged by each file's owner, mode bits and POSIX ACL, and leaves
out any key added later that the user could read. The example settings
below run verifiers as user 65533; in Kubernetes, mount the key Secrets with `defaultMode: 0440` and
an `fsGroup` the verifier user is not in, as [deploy/kubernetes/issuer.yaml](../deploy/kubernetes/issuer.yaml)
does. See [configuration.md](configuration.md) for the privileges this needs.

### An example verifier

[examples/exec](../examples/exec) has a complete example. Machines there prove themselves with
**host tickets** from a provisioning service: a JSON payload naming the audience, an expiry, the
host and its site, followed by an HMAC of it under a key that only the provisioning service and the
verifier can read. The settings install the verifier:

<!-- check: settings -->
```yaml
issuer: https://issuer.example.org
trust_domain: example.org
keys_dir: keys
state:
  file: state.yaml
verifiers:
  - [/usr/libexec/spiffex/host-ticket-verifier]
verifier_user: { uid: 65533, gid: 65533 }
```

and the state has a provider for it and an origin using that provider:

<!-- check: state settings=examples/exec/issuer.yaml -->
```yaml
providers:
  host-ticket:
    description: Machines holding a host ticket from the provisioning service, by site and host name.
    params:
      sites: { type: list, default: ["*"] }
    proof:
      exec:
        command: [/usr/libexec/spiffex/host-ticket-verifier]
        timeout: 2s
        shared: false
    require: [host, site]
    match: { site: $sites }
    name: "{site}/{host}"

origins:
  fleet:
    provider: host-ticket
    with: { sites: [hel1, fra2] }
```

The verifier, `/usr/libexec/spiffex/host-ticket-verifier`:

<!-- check: file examples/exec/host-ticket-verifier -->
```python
#!/usr/bin/python3
"""A spiffex exec verifier for host tickets.

A ticket is base64url(payload) "." base64url(HMAC-SHA256 of the first part), where the
payload is JSON with aud, exp, host and site. The provisioning service makes tickets
with the key in KEY_FILE, which only it and this verifier can read.
"""
import base64
import hashlib
import hmac
import json
import sys
import time

KEY_FILE = "/etc/spiffex/host-ticket.key"
MAX_LIFETIME = 300  # seconds


def refuse(reason):
    print(reason, file=sys.stderr)  # the issuer logs it; the client never sees it
    sys.exit(1)


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


request = json.load(sys.stdin)
if request.get("version") != 1:
    refuse("unknown request version")
with open(KEY_FILE, "rb") as f:
    key = f.read().strip()

try:
    payload, mac = request["subject_token"].split(".")
    expected = hmac.new(key, payload.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(unb64(mac), expected):
        refuse("bad signature")
    ticket = json.loads(unb64(payload))
except ValueError:
    refuse("malformed ticket")
if not isinstance(ticket, dict):
    refuse("malformed ticket")

# The ticket must name this origin's audience, or a ticket made for another
# service or origin could be replayed here.
if ticket.get("aud") != request["audience"]:
    refuse("ticket made for another audience")
exp, now = ticket.get("exp"), time.time()
if not isinstance(exp, int) or not now < exp <= now + MAX_LIFETIME:
    refuse("ticket expired, or meant to live too long")
host, site = ticket.get("host"), ticket.get("site")
if not isinstance(host, str) or not isinstance(site, str):
    refuse("ticket without host or site")

json.dump({"claims": {"host": host, "site": site}}, sys.stdout)
```

A machine with host name `build-7` at site `hel1` gets `spiffe://example.org/fleet/hel1/build-7`;
a ticket for site `osl3` passes the verifier but is refused by the origin's `match`.

### The protocol

For each request, the issuer runs the verifier directly, without a shell, with an empty environment,
`/` as its working directory, and no open files but standard input, output and error. It writes one
JSON object to the verifier's standard input and closes it:

```json
{
  "version": 1,
  "issuer": "https://issuer.example.org",
  "origin": "fleet",
  "audience": "https://issuer.example.org/origins/fleet",
  "subject_token": "<the proof, as the client sent it>",
  "params": { "sites": ["hel1", "fra2"] }
}
```

`params` holds every parameter of the provider, with the origin's values or the defaults. They come
from the state, not from the operator, so treat them as untrusted input, like the proof itself.

The verifier accepts the proof by exiting with status 0 and printing exactly one JSON object with a
`claims` object, at most 64 KiB:

```json
{"claims": {"host": "build-7", "site": "hel1"}}
```

Other members of the object are ignored, and claims may nest objects. Anything else refuses the
proof: another exit status, no `claims` object, a duplicated member name, more output, or running
past the timeout, at which the issuer kills the verifier's whole process group. The client gets the
same `invalid_request` as for any refused proof, never the verifier's output; the issuer logs a
short excerpt of its standard error.

A verifier must check, besides the proof's own validity:

- **that the proof names the `audience` it was given**, in a signed part of it. Without that, a proof
  made for another service, or for another origin that uses the same verifier, could be replayed
  here. Only the verifier can do this; for a JWT the issuer does it itself.
- **freshness and replay.** The example accepts tickets for at most five minutes and lets a ticket
  be used again until it expires; a verifier that must refuse that remembers the tickets it has
  seen.

Keep verifiers small, and make them refuse anything they do not fully understand. Running them as a
user of their own (`verifier_user` in the settings) is recommended. The issuer bounds how many run
at once, per origin and in total, and how often one client address may start one
([configuration.md](configuration.md)).

Try a verifier by hand by feeding it a request:

```bash
echo '{"version": 1, "audience": "https://issuer.example.org/origins/fleet",
  "subject_token": "'"$(mint-host-ticket https://issuer.example.org/origins/fleet build-7 hel1)"'",
  "params": {}}' | /usr/libexec/spiffex/host-ticket-verifier
```

where `mint-host-ticket`, in [examples/exec](../examples/exec), stands in for the provisioning
service.

### Using an exec origin

A client names the origin, since an exec proof carries no issuer to find it by:

```bash
curl https://issuer.example.org/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token_type=urn:spiffex:token-type:exec \
  -d origin=fleet \
  --data-urlencode subject_token@ticket \
  -d audience=https://api.example.org
```

The agent and `spiffex token` take `-subject-token-type exec -origin fleet`, with the proof from a
file (`-subject-token-file`) or from a command run for every request (`-subject-token-command`),
which suits proofs that must be made fresh:

```bash
spiffex agent -issuer https://issuer.example.org -socket /run/spiffex/agent.sock \
  -subject-token-type exec -origin fleet -subject-token-command /usr/local/bin/get-host-ticket
```

## Owner pinning for shared upstreams

An upstream is **shared** when anyone can obtain a token from it with the audience you configured:
GitHub Actions, GitLab.com and Google hand tokens to every user, and a stranger's workflow can ask
for your origin audience as easily as yours. Trusting such an upstream means trusting strangers,
unless admission pins the owner. So for a shared upstream, and for an exec verifier that accepts
proofs anyone can obtain:

- the origin's admission must include a `match` entry with only exact patterns (no `*`) on one of
  the upstream's **owner claims**, the claims that say whose token it is;
- no owner claim may be `iss`, `aud`, `azp`, `exp`, `iat`, `nbf` or `jti`, which say nothing about
  who obtained the token.

The checks run on the expanded origin, whatever the provider says, so neither a provider nor an
origin can avoid them. spiffex knows these issuers, treats them as shared even when a provider says
`shared: false`, and uses these owner claims for them whatever the provider declares:

| Issuer | Owner claims |
|---|---|
| `https://token.actions.githubusercontent.com` and issuers under it | `repository_owner_id`, `repository_id`, `enterprise_id` |
| `https://gitlab.com` | `namespace_id`, `project_id` |
| `https://accounts.google.com`, `accounts.google.com` | `sub` |
| `https://oidc.circleci.com/org/...` | `oidc.circleci.com~1project-id` |
| `https://login.microsoftonline.com/...`, `https://sts.windows.net/...` | `tid`, `oid` |
| `https://app.terraform.io` | `terraform_organization_id` |

For any other shared upstream, the owner claims are the proof's `owner_claims`. The shipped `github`
and `gitlab` providers pin the owner through a required parameter. The `oidc` provider cannot know
which claim to pin, so each origin using it adds the `match` itself. Leaving the pin out, or making
it a wildcard, is refused:

<!-- check: state invalid -->
```yaml
origins:
  gcp:
    provider: oidc
    with: { issuer: https://accounts.google.com, owner_claims: [sub] }
  ci:
    provider: github
    with: { owner_id: "*", refs: [refs/heads/main] }
```

```
origins.ci.match: https://token.actions.githubusercontent.com is a well-known shared upstream: admission needs a match entry with only exact patterns on one of repository_owner_id, repository_id, enterprise_id
origins.gcp.match: https://accounts.google.com is a well-known shared upstream: admission needs a match entry with only exact patterns on one of sub
```

A provider for a shared upstream should make the owner a required parameter, as `github` does, so
that an origin cannot be written without one.

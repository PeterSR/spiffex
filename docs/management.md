# Managing the state

The issuer's state (its origins, providers and grants) can be changed while it runs, in two ways:

- **Through its storage.** Whoever can write the stored state (the file, the directory tree or the
  ConfigMap) controls every identity. `spiffex bootstrap` and `spiffex state` work this way, and so
  does editing the file by hand.
- **Through the management API**, at `<issuer>/manage`, by SPIFFE identities that hold **grants**.
  Nobody is an administrator by configuration: a caller may do what its grants say, checked against
  the state on every request. `spiffex manage` is a client for it.

The API is described in [SPEC.md section 8](../SPEC.md#8-the-management-api). This page is how to
use it.

## Turning it on

```yaml
# issuer.yaml
management: true
```

With `management: false`, the default, `/manage` does not exist and the discovery document does not
announce it. With `management: true`, discovery carries `spiffex_management_endpoint`, and the issuer
writes the state it stores: a file or directory must be writable by the issuer, and in Kubernetes its
service account needs `update` on the state ConfigMap.

## Who the caller is

A caller presents a JWT-SVID that this issuer signed for the audience `<issuer>/manage`, and that
audience alone. It gets one like any other token, from an agent's Workload API or from the token
endpoint, and it lives at most five minutes. The issuer accepts it only while the caller could still
be issued that identity: removing the member or the origin a caller belongs to ends its access at
once, not when its token expires. Each token makes at most one change, so the agent fetches a fresh
management token every time instead of reusing one.

Each issuer process remembers, until they expire, the tokens of the changes it authorized; a
refused request does not use its token up, so callers without permission cannot fill that record.
**The record is per process and not shared.** With several issuer processes, as in the Kubernetes
example with its two replicas, an intercepted management token could make one change on each
process within its five minutes. Keep management tokens as private as the identity behind them.

Each caller may make 5 requests a second on average, and 30 in a row after a quiet spell; more are
answered `429` with `Retry-After`.

## Grants

A grant gives identities matching `who` the permissions in `can` on the scopes in `on`:

```yaml
grants:
  operators:
    who: spiffe://example.org/operators/alice
    can: [read, write, delegate]
    on: [/]
  ci-deployers:
    who: spiffe://example.org/ci/*/deploy        # any one segment where the * is
    can: [write]
    on: [/apps/staging]
  customer-admins:
    who: spiffe://example.org/customers/acme/**    # one or more segments after /customers/acme
    can: [read, write]
    on: [/customers/acme]
```

A scope is a path like an origin prefix, and `/` is everything. An origin is within a scope when its
prefix is, and a grant is within a scope when all of its own scopes are. A state holds at most 256
grants, and a grant at most 16 scopes, which keeps checking them quick.

| Permission | Allows, within the scope |
|---|---|
| `read` | reading origins, with their members, and grants |
| `write` | creating, changing and removing origins and their members; with scope `/`, also providers |
| `delegate` | creating, changing and removing grants |

`write` and `delegate` include `read`. Providers can be read by every caller.

Three more rules close the obvious loopholes:

- **Origins that reach outside their prefix take `write` on `/`.** An `exec` origin runs a verifier
  inside the issuer, and an origin taking upstream tokens for an audience other than its origin
  audience could capture tokens meant for others. Creating or changing either takes `write` on `/`.
- **No escalation.** To create, change or remove a grant, the caller needs `delegate` on each of
  its scopes and every permission it gives, there, in the grant's old form and its new one.
- **Closure**, below.

## Closure

Writing is becoming. Whoever may write `/ci` can create an origin there that admits anyone, and so
take on any SPIFFE ID under `/ci`. If an identity under `/ci` holds a grant, the writer could become
it and use that grant. So the grants must be **closed**: whenever a grant gives `write` on a scope
that reaches the `who` of another grant, the writer's identities must already hold everything the
other grant gives, through a single grant whose `who` covers the writer's.

An example the issuer refuses:

```yaml
grants:
  ci-writers:
    who: spiffe://example.org/people/bob
    can: [write]
    on: [/ci]
  release:
    who: spiffe://example.org/ci/release
    can: [read, write, delegate]
    on: [/]
```

Bob may write `/ci`, so he could create an origin issuing `spiffe://example.org/ci/release`, become
it, and hold everything on `/`. The state is invalid, and the API answers a change that would make
it so with `422`, naming both grants and each missing permission:

```
grants.ci-writers: gives write on /ci, which reaches spiffe://example.org/ci/release, the who of grant release; grant release gives read on /, but no single grant gives every identity matching spiffe://example.org/people/bob read on /
grants.ci-writers: ... grant release gives write on /, but no single grant gives every identity matching spiffe://example.org/people/bob write on /
grants.ci-writers: ... grant release gives delegate on /, but no single grant gives every identity matching spiffe://example.org/people/bob delegate on /
```

The fix is to give `release` a narrower scope, move its `who` out of `/ci`, or narrow `ci-writers`.
Closure is part of validation, so it applies to a state written to storage by hand as well;
`spiffex check` reports the same.

Closure reasons only about grants. Whoever controls an upstream can still become the identities its
origin issues, so give grants to identities from `keys` origins, or from upstreams where creating
such an identity is itself tightly controlled.

## Bootstrap

A new issuer has no grants, so nobody can use the API. The first grant is written to the storage
directly. In the common case that is an operator's key pair, as a member of a `keys` origin, with a
grant on everything:

```bash
spiffex key generate -out alice.key > alice.pub
spiffex bootstrap -config /etc/spiffex/issuer.yaml -member alice -key alice.pub
```

```
member alice of origin operators is spiffe://example.org/operators/alice
grant operators gives read, write, delegate on / to spiffe://example.org/operators/alice
wrote file /etc/spiffex/state.yaml, version "3f1c..."
```

It reads the storage from the issuer's settings, adds the member to the origin `operators` (created
when missing), adds the grant, validates the whole result as the issuer would, and stores it with
compare-and-swap. It refuses when the state has grants already, unless given `-force`, and refuses
to replace a member or grant of the same name, unless given `-replace`; it then says what it
replaced.

| Flag | |
|---|---|
| `-config` | the issuer's settings file |
| `-origin` | the keys origin for the member, `operators` by default |
| `-member`, `-key` | the member, and its public keys: PEM blocks, or a JWK or JWK Set; `-` reads standard input |
| `-who` | the grant's SPIFFE ID or pattern, instead of the member's |
| `-grant` | the grant's name, `operators` by default |
| `-can` | its permissions, `read,write,delegate` by default |
| `-on` | a scope, `/` by default; repeat for several |
| `-force` | write even though the state has grants |
| `-replace` | replace a member or grant that exists already |

For an identity that exists already, such as a Kubernetes service account, give `-who` alone:
`spiffex bootstrap -config issuer.yaml -who spiffe://example.org/cluster/ns/ops/sa/admin`.

## The API from the command line

`spiffex manage` gets a management token, calls the API and prints the answer:

```bash
# with the operator's key, from the token endpoint
spiffex manage -issuer https://issuer.example.org -client-id operators/alice -key-file alice.key get state

# from inside a workload, through its agent (SPIFFE_ENDPOINT_SOCKET, or -socket PATH)
spiffex manage -issuer https://issuer.example.org get state
```

| Command | |
|---|---|
| `get state` | the providers, and the origins and grants you may read |
| `get origin\|grant\|provider NAME` | one object |
| `put origin\|grant\|provider NAME -f FILE` | create or replace it from a YAML or JSON file |
| `put member ORIGIN MEMBER -key FILE` | add or replace a member of a keys origin |
| `delete origin\|grant\|provider NAME` | remove it |
| `delete member ORIGIN MEMBER` | remove a member |
| `check -f FILE` | validate a whole state document without storing it; needs `read` on `/` |

Flags may come before or after the command. Every answer that returns or changes the state carries
its version, which `get` prints to standard error and `put` and `delete` print with their result.
Pass it back as `-if-match VERSION` to make a change only if nobody else changed the state since:

```bash
$ spiffex manage ... get origin web > web.yaml
version "41"
$ vi web.yaml
$ spiffex manage ... put origin web -f web.yaml -if-match 41
updated origin web, version "42"
```

Refusals are printed with the API's reasons:

```
spiffex: grant cluster-writers: 422 Unprocessable Entity: the change would make the state invalid
  grants.cluster-writers: gives write on /cluster, which reaches spiffe://example.org/cluster/ns/ops/sa/admin, ...
```

| Status | Meaning |
|---|---|
| 401 | no token, or not a valid management token for an identity the state still issues |
| 403 | you may read the object, but lack a permission the change needs; the reason names it |
| 404 | the object does not exist, or you may not read it |
| 409 | the name, prefix or upstream issuer and audience is taken by an object you may not read |
| 412 | the state is no longer at the version `-if-match` named |
| 422 | the change would make the state invalid; the reasons follow |
| 429 | too many requests from you; try again after `Retry-After` |

Reasons never describe what you may not read, beyond the names and prefixes of origins and the
upstream issuer and audience of `jwt` origins, which are not secret. A closure problem involving a
grant you may not read is reported as one fixed reason, which does not say which grant that is, what
part it plays or what it gives. A change is authorized before it is examined: an origin you may not
write at its prefix, or a grant giving what you do not hold, is refused with `403` before anything
else about it is checked or reported.

`get provider` serves the providers that ship with spiffex as well as those in the state, and says
which it got: the API's `Spiffex-Provider-Source` header is `state` or `shipped`, and
`Spiffex-Overrides` names the state's providers that take the place of shipped ones, on `get state`
too. `spiffex manage` prints both as notes.

## How changes are made

Reads are answered from the state the issuer process serves, which is the state it last reloaded or
stored, so they may lag a change made through another process by up to one reload interval. Callers
are checked against that same state before anything reads the storage.

A change reads the stored state, checks the caller's permissions against it, applies the change,
validates the whole result with the issuer's settings, and stores it with compare-and-swap. The
process that stored it serves the new state at once; other processes serving the same issuer URL
take it up at their next reload, within `-reload-interval` (10 seconds by default, twice that for a
file or directory, which must look the same on two checks in a row). If another change got in first,
a request without `-if-match` starts over against the newer state, permissions included; one with
`-if-match` fails with `412`. Every change is logged with the caller's SPIFFE ID, the object and the
new version.

The API refuses every change while the stored state cannot be read or is invalid under the
issuer's settings, since it cannot tell then who may do what, and keeps answering reads from the
last valid state. Repair it in storage. A process never goes back to an older state than one it
has served: a reload that read the state before a change was stored is set aside and tried again.

## Working on the storage

These commands use the storage named in the issuer's settings directly, as the operator, and do not
need the issuer to run:

```bash
spiffex state export -config issuer.yaml [-format json] > state.yaml   # prints the version to standard error
spiffex state import -config issuer.yaml -f state.yaml (-if-version VERSION | -force)
spiffex state convert -from-file state.yaml -to-dir state/              # or -from-dir and -to-file
```

`import` validates the document as the issuer would before storing it, and only replaces the
version given with `-if-version`. Without one it needs `-force`, and then replaces whatever is
stored. `convert` writes a
state in the other form without loss and refuses to overwrite anything.

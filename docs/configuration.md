# Configuration and operations

The issuer reads two things: its **settings**, a file only the operator changes, which take effect
on restart; and its **state**, the origins, providers and grants of [SPEC.md section 6](../SPEC.md#6-state),
which it rereads while it runs. [examples/](../examples) has a complete settings file and state for
an issuer with several origins.

## The settings file

<!-- check: settings -->
```yaml
issuer: https://issuer.example.org     # the issuer URL; tokens carry it as iss
trust_domain: example.org
keys_dir: /var/lib/spiffex/keys        # signing keys
token_ttl: 5m                          # lifetime of issued JWT-SVIDs (default 5m, at most 1h)
activation_delay: 30m                  # how long a new signing key is published before it signs (default 30m)

state:                                 # where the state lives: exactly one of
  file: /etc/spiffex/state.yaml        #   one YAML or JSON document
  # dir: /etc/spiffex/state            #   a directory tree, one file per object
  # configmap: { namespace: spiffex, name: spiffex-state }   # a Kubernetes ConfigMap

management: false                      # serve the management API at <issuer>/manage (docs/management.md)

# What the state may make the issuer do with files on its machine (SPEC section 5.2). Lists
# left out keep their defaults, which allow exactly what the shipped kubernetes provider needs.
readable_files:                        # may be named as jwks_file or ca_file
  - /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
bearer_token_files:                    # may be named as bearer_token_file, each only for these hosts
  - path: /var/run/secrets/kubernetes.io/serviceaccount/token
    hosts: [kubernetes.default.svc.cluster.local]
    paths: [/openid/v1/jwks, /.well-known/openid-configuration]   # optional: only these URL paths
verifiers:                             # the exec verifiers installed; none by default
  - [/usr/libexec/spiffex/aws-verifier, --partition, aws]

fetch:
  refuse_private_addresses: true       # refuse key fetches to loopback, link-local and private addresses (default true)
  allow_private_hosts:                 # host:port pairs exempt from that, port 443 when left out
    - kubernetes.default.svc.cluster.local:443   # the default, for the shipped kubernetes provider

verifier_limits:                       # bounds on exec verifiers (SPEC section 5.4)
  per_origin: 4                        # running at once for one origin
  total: 16                            # running at once in all
  per_address_per_minute: 60           # how often one client address may start one
  per_address_burst: 10                # and how many in a row
verifier_user: { uid: 65533, gid: 65533 }   # recommended with verifiers: run them as this user, without supplementary groups
trusted_proxies: [10.0.0.0/8]          # optional: peers, such as an ingress, whose X-Forwarded-For names the client
```

Run the issuer with `spiffex issuer -config issuer.yaml`. Relative paths in `keys_dir` and `state`
are relative to the settings file; the file lists must name absolute paths. Unknown fields are
refused. The issuer listens on `:8443`, serving TLS when given `-tls-cert` and `-tls-key`, and plain
HTTP otherwise, for use behind a TLS-terminating proxy, and reloads the TLS certificate when its
files change. The issuer URL must be what clients and verifiers actually reach, because it is
compared byte for byte.

Key fetches for origins refuse loopback, link-local, private and other non-public addresses unless
`refuse_private_addresses` is `false`. The check is on the address actually connected to, after
name resolution, and an IPv6 address that carries an IPv4 one (NAT64, 6to4, IPv4-compatible) is
judged by the latter. While it is on, any HTTP proxy is ignored, since a proxy would hide the
destination. The `allow_private_hosts` entries are exempt: each is a host and port, compared with
the host and port of the URL fetched, with port 443 when it names none. The default list exempts
`kubernetes.default.svc.cluster.local:443`, the in-cluster API server the shipped `kubernetes`
provider reads keys from; a list you give replaces it, so keep that entry when you need it.

**Verifiers and the signing keys.** An exec verifier runs as the issuer's own user unless
`verifier_user` is set, and can then read everything the issuer can, the signing keys included: a
compromised verifier could sign any identity. The issuer logs a warning at startup when verifiers are
installed without `verifier_user`. With it, the issuer refuses to start when that user, by its uid
or gid, could read any file in `keys_dir` or the TLS key, judged by each file's owner and mode bits
and its POSIX ACL: a file with an ACL naming further users or groups counts as readable unless the
ACL's mask grants nothing. A default ACL on `keys_dir` that would let the user read new files is
refused too. Keep those files readable by the issuer's user or group only, for instance mode `0440`
with a group the verifier user is not in, and without ACLs. Each time the issuer rereads `keys_dir`,
a new key the verifier user could read is logged as an error and neither published nor signed with.
A key already in service that becomes readable is marked exposed: it stays published, so the tokens
it signed still verify, but it never signs again while it stays in the directory, and the newest key
that is not exposed signs instead. With every key exposed, the token endpoint answers `server_error`
until you add a fresh key. A key removed and added back is checked like a new one. `verifier_user` also needs the issuer to run with the privilege to change user (CAP_SETUID and
CAP_SETGID), and to kill processes of that user (CAP_KILL), or a hung verifier could never be
stopped. The issuer checks this at startup, by starting a process as that user and killing it, and
refuses to start when it cannot.

**Behind an ingress or load balancer**, list its addresses in `trusted_proxies`. The per-address
verifier limit then applies to the client the proxy names: the rightmost address in
`X-Forwarded-For` that is not itself a trusted proxy. Without it, every request seems to come from
the proxy, and one busy client uses up the limit for all. Never list addresses that clients can
send from directly, or they can name any client they like. IPv6 clients are limited by their /64,
and each /48 as a whole by sixteen times the per-address limit, so moving between addresses or
/64s gains little.

When the issuer stops, it gives requests ten seconds to finish, then cancels those left, killing
their verifiers, and waits up to five seconds more for them to be gone. A verifier still running
then, one that somehow survived the kill, is logged, and the issuer exits without it.

Every flag of every command can also be set as an environment variable: `-reload-interval` is
`SPIFFEX_RELOAD_INTERVAL`, and so on. The names are shared between commands, so `SPIFFEX_DIR` means
`-dir` to every command that has one. A repeatable flag such as `-audience` takes a single value
from the environment.

## The state

The state starts out empty, and an empty state admits nobody. A state that does not exist yet is
empty, too. A file or directory is created on the first write; a ConfigMap is not, so that the
issuer needs no permission to create objects: create it first, even without a `state.yaml` key. The issuer checks the state every `-reload-interval` (10 seconds by default):

- A valid new state is put in service as a whole; requests already running finish with the old one.
- An invalid state is not. The issuer keeps serving the last valid state and logs the problems,
  once for each version. At startup, an invalid state keeps the issuer from starting.
- A state that disappears after one was loaded (a deleted file, directory or ConfigMap) is treated
  the same way. To empty the issuer, store an empty document.
- A file or directory is taken up once it has stayed the same for two checks in a row, so a file
  caught halfway through being written is not mistaken for the new state. A ConfigMap changes as a
  whole and is taken up at the next check.

`spiffex check -settings issuer.yaml state.yaml` runs the same validation as the issuer, without
one, and checks the settings file as the issuer would, though without requiring `keys_dir` and
`state`; `spiffex explain` shows how the state would treat a given subject token. Origins, the
providers they use and how to write your own are in [providers.md](providers.md).

With `management: true`, SPIFFE identities holding grants change the state through the management
API, and the issuer stores what they change, so it needs write access to the state. The issuer that
stores a change serves it at once; others take it up at their next check. `spiffex bootstrap`
writes the first grant, and `spiffex state` exports, imports and converts the stored state directly.
See [management.md](management.md).

In a **directory**, each object is a file of its own:

```
state/
  origins/kube.yaml                 the origin kube, as under origins in the document
  origins/vms.yaml
  origins/vms/members/billing.pub   member billing of origin vms: one PEM block per key
  origins/vms/members/orders.jwk    member orders: a JWK, or a JWK Set for several keys
  providers/partner-idp.yaml
  grants/operators.yaml
```

Files may end in `.yaml`, `.yml` or `.json`, names starting with a dot are ignored, and any other
file is an error rather than silently left out. A member is given in its origin's file or as a file
under `members`, not both, and two member files whose names differ only in case are an error. When
the issuer writes a tree, it reads it back, and puts the previous one back if they differ.

Whoever can write the stored state controls every identity: protect it like the signing keys.

## Workloads with keys

A `keys` origin lists workloads that hold a private key, each a member:

```bash
spiffex key generate -out billing.key > billing.pub
```

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

`billing.key` stays with the workload and nowhere else. The workload's client id is
`<origin>/<member>`, here `vms/billing`, and its SPIFFE ID `spiffe://example.org/vms/billing`. A
member can have up to ten keys, which is how its key is rotated: add the new public key, switch the
workload to the new private key, then remove the old public key. `-alg RS256` makes an RSA key
instead of the default ECDSA P-256 key.

## Tokens from other issuers

A `jwt` origin lets workloads trade a token they already have for a JWT-SVID. The shipped providers
cover Kubernetes (`kubernetes`), GitHub Actions (`github`), GitLab (`gitlab`) and any public OIDC
issuer (`oidc`); `spiffex provider list` and `spiffex provider show NAME` print them, and
[providers.md](providers.md) describes their parameters.

<!-- check: state -->
```yaml
origins:
  ci:
    provider: github
    with: { owner_id: "1234567", refs: [refs/heads/main] }
```

A token reaches an origin by its `iss` and its audience. Unless the provider says otherwise, the
audience is the **origin audience**: the issuer URL, `/origins` and the origin's prefix, here
`https://issuer.example.org/origins/ci`. Ask the upstream for tokens with that audience.

Fetched keys are cached for ten minutes and fetched again early when a token names a key the cache
lacks, at most every 30 seconds. When the upstream cannot be reached, the cached keys keep working
for up to 24 hours. Fetches use https, follow no redirects, and are limited to 1 MiB, 100 keys and
15 seconds. A bearer token is sent only to a host its `bearer_token_files` entry allows, and with
`discovery` only with the discovery request, never to the key location the discovery document names.

For a Kubernetes cluster, see [kubernetes.md](kubernetes.md).

## Proofs checked by a verifier

An `exec` origin hands the proof to a local program, the verifier, which answers with claims. Only
verifiers listed under `verifiers` in the settings can be named by a provider, with exactly the
same arguments. A verifier runs without a shell, with an empty environment, and with standard
input, output and error only, in a process group of its own that is killed at its timeout and
whenever it finishes. With verifiers installed, the issuer on Linux adopts and reaps whatever they
leave behind, also as a container's init.

Workloads ask for such an origin by name: `-subject-token-type exec -origin fleet` on the agent or
`spiffex token`, or the form parameters `subject_token_type=urn:spiffex:token-type:exec` and
`origin=fleet`. [providers.md](providers.md#the-exec-proof) has the protocol and an example
verifier.

## The agent

```bash
spiffex agent -issuer https://issuer.example.org \
  -client-id vms/billing -key-file billing.key \
  -socket /run/spiffex/billing.sock
```

| Flag | |
|---|---|
| `-issuer` | the issuer URL; `https` is required except on a loopback address |
| `-client-id`, `-key-file` | the workload's member, `<origin>/<member>`, and its private key, for `private_key_jwt` |
| `-subject-token-file` | a file holding a proof to exchange instead, read again for every request |
| `-subject-token-command` | a command whose output is the proof, run without a shell for every request: words separated by spaces, or a JSON array. It inherits the agent's environment, runs in a process group of its own that goes when it finishes, and must finish within 10 seconds |
| `-subject-token-type` | `jwt` (the default) or `exec` |
| `-origin` | with `-subject-token-type exec`, the origin whose verifier checks the proof |
| `-socket` | the Unix socket to serve the Workload API on |
| `-socket-mode` | the socket's permissions, `0600` by default |
| `-trust-domain` | refuse to start unless the issuer serves this trust domain |
| `-ca-file` | CA certificates to trust for the issuer instead of the system roots, read at startup |
| `-log-level` | `debug`, `info`, `warn` or `error` |

`spiffex token` takes the same proof flags and prints one JWT-SVID. `spiffex health -socket PATH`
exits 0 once an agent serves a trust bundle on that socket, for a container startup or readiness
probe.

The agent retries discovery until the issuer answers, and exits when the answer shows it was
misconfigured (a different issuer URL or trust domain).

Workloads find the agent through `SPIFFE_ENDPOINT_SOCKET=unix:///run/spiffex/billing.sock`. Anyone
who can connect to the socket gets the workload's identity, so keep it private to the workload: a
directory only its user can enter, or a volume shared only between its containers.

Use your SPIFFE library's JWT parts. The agent does not serve X.509-SVIDs yet (the specification
describes them in sections 2.5, 3.4 and 9, but this release does not implement them), and the X.509
and combined bundle sources of go-spiffe and py-spiffe wait for them until they time out.

## Rotating signing keys

Signing keys are PEM files in `keys_dir`, named after the second they were created in:

```bash
spiffex key add -dir /var/lib/spiffex/keys            # published at once, signing after activation_delay
spiffex key list -config /etc/spiffex/issuer.yaml     # which key signs, which wait, which can go
spiffex key prune -config /etc/spiffex/issuer.yaml    # delete keys no token can need any more
```

`list` and `prune` must know the issuer's `activation_delay` and `token_ttl`, so they read the
issuer's settings file; without it, give `-dir`, `-activation-delay` and `-token-ttl` explicitly.
With `-config`, the settings file wins over any of those three set in the environment. `prune
-dry-run` shows what would go. A key counts as retired once a newer key has been signing for
`token_ttl` plus ten minutes, which covers clock skew and issuers reloading their keys directory
every few minutes or more often.

The activation delay gives verifiers time to fetch a new key before tokens signed with it appear.
The issuer counts it from when a key arrived in its directory, not from the time in its file name,
so copying in a key generated elsewhere is safe, as long as the copy gets a fresh modification time
(a plain `cp`, not `cp -p` or `rsync -t`) or no issuer process restarts during the delay. Keep the
delay at least three times the bundle refresh hint (a fifth of the delay by default).

**Run `list` and `prune` against the directory the issuer reads, or a copy that is exactly as old.**
They judge from the files in front of them. If you keep the keys somewhere else and deploy them (a
Secret built from a local directory, say), the local copy does not know when the deployment
happened: after `key add`, deploy, wait the activation delay plus the token TTL plus ten minutes,
and only then prune and deploy again. Pruning the local copy early can delete the key the issuer is
signing with.

If a signing key is compromised, delete its file at once and accept that tokens it signed stop
verifying.

When the keys directory is a Kubernetes Secret, keep the key files under their own names in the
Secret and update the Secret as a whole; the issuer treats a rewrite of files it already knows as no
change.

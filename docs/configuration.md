# Configuration and operations

## The issuer

The issuer reads one YAML file:

```yaml
issuer: https://issuer.example.org     # the issuer URL; tokens carry it as iss
trust_domain: example.org
keys_dir: /var/lib/spiffex/keys        # signing keys; relative paths are relative to this file
token_ttl: 5m                          # lifetime of issued JWT-SVIDs (default 5m)
activation_delay: 30m                  # how long a new signing key is published before it signs (default 30m)

clients:                               # workloads that prove themselves with a private key
  - client_id: billing
    spiffe_id: spiffe://example.org/billing
    public_keys:
      - file: billing.pub              # or inline:  - pem: |  -----BEGIN PUBLIC KEY----- ...
    audiences: [spiffe://example.org/orders]   # optional: the only audiences billing may request

upstreams:                             # issuers whose tokens workloads may exchange
  - name: github
    issuer: https://token.actions.githubusercontent.com
    audience: https://issuer.example.org
    discovery: true
    shared: true
    rules:
      - match: {repository_owner_id: "1234567"}
        spiffe_id: spiffe://example.org/ci/{repository_id}
```

Run it with `spiffex issuer -config issuer.yaml`. It listens on `:8443`, serving TLS when given
`-tls-cert` and `-tls-key`, and plain HTTP otherwise, for use behind a TLS-terminating proxy. The
issuer URL must be what clients and verifiers actually reach, because it is compared byte for byte.

The `clients` list, and the public key files it refers to, are reread while the issuer runs (every
`-reload-interval`, 10 seconds by default), so registering, rotating or removing a workload key
needs no restart. A change is applied once the files have stayed the same for two checks in a row,
so a file caught halfway through being written is not mistaken for the new configuration; still,
replace the file atomically (write a new file and rename it over the old one, as a Kubernetes
ConfigMap update does) where you can. A change to `upstreams` takes effect at the next restart,
while client changes in the same edit apply at once. The other settings need a restart; a reload
that changes them is refused and logged. The TLS certificate is reloaded when its files change.

Every flag of every command can also be set as an environment variable: `-reload-interval` is
`SPIFFEX_RELOAD_INTERVAL`, and so on. The names are shared between commands, so `SPIFFEX_DIR` means
`-dir` to every command that has one. A repeatable flag such as `-audience` takes a single value
from the environment.

## Registering a workload

```bash
spiffex key generate -out billing.key > billing.pub
```

`billing.key` stays with the workload and nowhere else. `billing.pub` goes into the issuer's
configuration. `-alg RS256` makes an RSA key instead of the default ECDSA P-256 key.

A workload can have several public keys registered at once, which is how its key is rotated: add the
new public key, switch the workload to the new private key, then remove the old public key.

## Token exchange

An upstream lets workloads trade a token they already have for a JWT-SVID, with no key of their own
registered at the issuer. The issuer verifies the token against the upstream's keys, then tries the
rules in order; the first whose `match` claims all have the given values decides the SPIFFE ID.

| Field | |
|---|---|
| `name` | a label for logs |
| `issuer` | the `iss` the upstream's tokens carry, compared exactly |
| `audience` | the audience the tokens must carry: choose one used for nothing else |
| `jwks_file`, `jwks_uri`, `discovery` | where the upstream's keys are: a file (reread when it changes), a URL, or the issuer's own OIDC discovery. Exactly one. |
| `ca_file` | CA certificates to trust when fetching keys, instead of the system roots |
| `bearer_token_file` | a token to send when fetching keys, read at each fetch, and sent only to the host of `jwks_uri` or `issuer`, never to one a discovery document names |
| `shared` | whether anyone can get tokens from the upstream (GitHub Actions, a cloud provider). Required unless the keys come from a file. Well-known public issuers are always treated as shared. |
| `max_token_lifetime` | refuse subject tokens issued to live longer than this (`exp` minus `iat`); 1h by default |
| `rules` | `match`: claims and the exact values they must have; `require`: claims that must be present; `spiffe_id`: the template |

For a shared upstream every rule needs a `match`, and it should be on a claim the upstream controls
that names the owner, such as GitHub's `repository_owner_id`: spiffex cannot tell such a claim from
one the token's holder chooses, like a branch name.

Claims inside objects are named by their path with `/`, so `kubernetes.io/namespace` is the
`namespace` field of the `kubernetes.io` object. In `spiffe_id`, `{path}` is replaced by that
claim's value. A placeholder must fill a whole path segment, and a token whose value for it is
empty, `.`, `..`, or contains anything but letters, digits, `.`, `_` and `-` is refused rather than
escaped, so no two tokens can map to the same identity by way of a crafted value. Only string and
integer claims count, integers exactly as the token writes them; a claim holding a fraction, a
boolean, an object or a list is treated as absent.

Two upstreams whose rules produce the same SPIFFE IDs (two clusters with the same namespace and
service account names, say) give their workloads the same identities. Give each upstream its own
path prefix unless that is what you want; nothing warns about it.

Keys fetched over the network are cached for ten minutes and fetched again early when a token names
a key the cache lacks. When the upstream cannot be reached, the cached keys keep working for up to
24 hours, after which exchanges fail until it is back.

For a Kubernetes cluster, see [kubernetes.md](kubernetes.md).

## The agent

```bash
spiffex agent -issuer https://issuer.example.org \
  -client-id billing -key-file billing.key \
  -socket /run/spiffex/billing.sock
```

| Flag | |
|---|---|
| `-issuer` | the issuer URL; `https` is required except on a loopback address |
| `-client-id`, `-key-file` | the workload's registration, for `private_key_jwt` |
| `-subject-token-file` | a token file to exchange instead, read again for every request |
| `-socket` | the Unix socket to serve the Workload API on |
| `-socket-mode` | the socket's permissions, `0600` by default |
| `-trust-domain` | refuse to start unless the issuer serves this trust domain |
| `-ca-file` | CA certificates to trust for the issuer instead of the system roots, read at startup |
| `-log-level` | `debug`, `info`, `warn` or `error` |

`spiffex health -socket PATH` exits 0 once an agent serves a trust bundle on that socket, for a
container startup or readiness probe.

The agent retries discovery until the issuer answers, and exits when the answer shows it was
misconfigured (a different issuer URL or trust domain).

Workloads find the agent through `SPIFFE_ENDPOINT_SOCKET=unix:///run/spiffex/billing.sock`. Anyone
who can connect to the socket gets the workload's identity, so keep it private to the workload: a
directory only its user can enter, or a volume shared only between its containers.

Use your SPIFFE library's JWT parts. The agent does not serve X.509-SVIDs, and the X.509 and
combined bundle sources of go-spiffe and py-spiffe wait for them until they time out.

## Rotating signing keys

Signing keys are PEM files in `keys_dir`, named after the second they were created in:

```bash
spiffex key add -dir /var/lib/spiffex/keys            # published at once, signing after activation_delay
spiffex key list -config /etc/spiffex/issuer.yaml     # which key signs, which wait, which can go
spiffex key prune -config /etc/spiffex/issuer.yaml    # delete keys no token can need any more
```

`list` and `prune` must know the issuer's `activation_delay` and `token_ttl`, so they read the
issuer's configuration file; without it, give `-dir`, `-activation-delay` and `-token-ttl`
explicitly. With `-config`, the configuration file wins over any of those three set in the
environment. `prune -dry-run` shows what would go. A key counts as retired once a newer key has been
signing for `token_ttl` plus ten minutes, which covers clock skew and issuers reloading their keys
directory every few minutes or more often.

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

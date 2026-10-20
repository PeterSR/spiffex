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

# X.509-SVIDs, optional (see "The certificate authority" below): without ca_dir the issuer has no CA.
ca_dir: /var/lib/spiffex/ca            # the CA's certificates and keys, apart from keys_dir
ca_roots: /etc/spiffex/ca-roots.pem    # root certificates of your own CA, when the CA is an intermediate under it
# ca_roots_dedicated: false            # true: every CA those roots certify is this issuer's (SPEC section 2.5.1)
x509_svid_ttl: 1h                      # lifetime of issued X.509-SVIDs (default 1h, 10m to 24h)

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

Run the issuer with `spiffex issuer -config issuer.yaml`. Relative paths in `keys_dir`, `ca_dir`,
`ca_roots` and `state` are relative to the settings file; the file lists must name absolute paths. Unknown fields are
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

## The certificate authority

With `ca_dir` set, the issuer has a **certificate authority** (SPEC section 2.5; the
[X.509-SVIDs guide](x509.md) is the overview) that signs X.509-SVIDs, and publishes its trust
anchors in the bundle as X.509 authorities. Without it nothing about the issuer changes. `ca_dir` must be a directory of its own, neither `keys_dir` nor inside it or
containing it, so that a mistake in one mount or Secret does not expose both kinds of key. The
discovery document says `spiffex_x509_svid_supported: true` while the issuer has a CA that can sign.

The CA is either a **root**, a self-signed CA the issuer itself holds, or an **intermediate** signed
by a CA of your own, whose root certificates you list in `ca_roots`. A root suits development and
small setups; an intermediate under a root kept offline is the better production setup, because the
root can replace a compromised intermediate.

```bash
# A root:
spiffex ca init -dir /var/lib/spiffex/ca -trust-domain example.org

# An intermediate: make the key and a request, have the request signed as a CA by your own CA,
# then install the answer (the signed certificate first, then any CA certificates between it
# and the root, as PEM).
spiffex ca csr -dir /var/lib/spiffex/ca -trust-domain example.org -out ca.csr
spiffex ca import -cert signed.pem -dir /var/lib/spiffex/ca -trust-domain example.org -roots /etc/spiffex/ca-roots.pem
```

`ca import` takes `-config issuer.yaml` instead of the individual flags. The root is a P-256 key valid for five years by default, at least a day (`-valid-for`);
`ca csr` also takes `-alg ES384` and `-alg RS256`. Everything the issuer's CA signs with has to meet
the profile of SPEC section 2.5: a name-constrained CA with a path length of 0 whose key usage is
`keyCertSign` and `cRLSign` only, with an ECDSA key on P-256 or P-384 or an RSA key of 2048 to 4096
bits, and no RSASSA-PSS. The request made by `ca csr` asks for exactly that, but a CA is free to
ignore the request, so `ca import` checks what comes back, and the issuer checks it again every time
it reads the directory.

The newest CA is the one signed last, so a request imported out of order ranks by its certificate and
not by the time of its request. Each CA is a pair of files named after the moment it was made, `ca-20261015T120000Z.crt` (PEM: the
CA certificate, then any CA certificates between it and its root) and `ca-20261015T120000Z.key`
(PEM, mode 0600). A key without a certificate is a request waiting for `ca import`. A self-signed
certificate without a key is published as a trust anchor and never signs. Other files are ignored.
The subject of a CA must differ from every other CA's with a different key; `ca csr` and `ca init`
make unique ones, and the issuer refuses a CA your CA signed with a subject already in use. A running
issuer keeps the subject of its CA against a certificate that appears later: a self-signed certificate
with the same subject and another key is logged and not published, with or without a key file. Every
self-signed CA in `ca_dir` and every certificate in `ca_roots` is published as an X.509
authority; an intermediate is never published, only the root it chains to.

**Roots you bring.** The certificates in `ca_roots` must be self-signed CA certificates. The issuer
cannot see the other CAs such a root certifies, and a verifier that trusts the root accepts any chain
to it with a `spiffe://example.org/...` identity, so each root must either carry the full name
constraints of SPEC section 2.5 (critical; permitting only the URI `example.org`; excluding the URI
`.example.org`, every DNS name, IP address and mailbox; no directory names) or be declared dedicated to
the trust domain with `ca_roots_dedicated: true`. Even the full constraints do not stop another CA
under the same root from minting `spiffe://example.org/...` identities, so share a root only with CAs
that are yours; dedicated is your statement that every CA certificate the root certifies, directly or
through others, is one of this issuer's signing CAs or a CA on the path to one, and that those certify
no other CA. The issuer refuses to start with a root that is neither.

**Rotation** follows the rules of the signing keys. A new CA is published, as a root through the
bundle or through the root it chains to, for `activation_delay` before the issuer signs with anything
that chains to it; a new intermediate under a root that has been published that long signs as soon as
it appears. When no other CA with a key can sign, as in a new trust domain or after the only CA key
was removed, a new CA signs at once, and verifiers reject what it signs until they fetch the new
bundle. The issuer signs with the newest CA that may sign, and keeps an old root published until
`x509_svid_ttl` plus ten minutes after the last time it could have signed with it. The delay counts
from when the issuer first sees a certificate, whatever its file name or modification time says. To
replace a root: run `spiffex ca init` and wait for `activation_delay` (it then signs), or add the new
root to `ca_roots`, wait, and install an intermediate under it; then wait out the retention, run
`spiffex ca prune`, and remove the old root from `ca_roots` (`ca prune` reminds you).

The issuer keeps no state across a restart, and learns when it first saw a certificate from its
own run. Two cases follow. After adding a root to `ca_roots`, wait `activation_delay` before
restarting the issuer, or import the intermediate under it only after that time: a restart sooner
trusts the file name and certificate dates of the intermediate, which a ceremony at an offline root
can make old, and it signs under a root no verifier has seen. And a root that left the bundle needs
`activation_delay` after it returns, which the running issuer enforces but a restart forgets, so do not
import a CA under a root the bundle dropped and restart within that time (`ca import` warns).

```bash
spiffex ca list -config issuer.yaml      # each CA's state, and the anchors
spiffex ca prune -config issuer.yaml -dry-run
spiffex ca prune -config issuer.yaml
```

Like `spiffex key list` and `key prune`, these refuse to guess: they read the issuer's settings with
`-config`, or need `-dir`, `-trust-domain`, `-activation-delay` and `-x509-svid-ttl` all given, with
`-roots` and `-roots-dedicated` as the issuer has them. `ca prune` deletes the files of CAs no verifier
can need any more; run it only against the directory the issuer reads, after the retention has passed
there.

**Expiry.** The issuer signs with the newest CA that may sign. When its chain, up to and including its
root, ends within a full `x509_svid_ttl`, the issuer logs a warning and issues shorter X.509-SVIDs,
ending with the chain, and it refuses a request when less than five minutes would be left. An older
CA does not take over, not even when the newest has ended: its root leaves the bundle once the newest
has been active for the retention, and what it signed later would outlive that. It warns from thirty
days before the earliest end of the chain it signs with. A CA past its end signs nothing, and the root
`ca init` makes lasts five years (`-valid-for`) and is not renewed by anything. Add the successor
well before.

**While it runs.** The issuer rereads `ca_dir` and `ca_roots` every `-reload-interval`. At startup a
CA that fails its checks, or whose chain does not verify against a root the issuer publishes, keeps the
issuer from starting. Later, a new certificate that fails them is logged and not used or published,
and a CA in service whose files turn bad stays in service as it was, unless its key file was removed: that stops it,
as for a root. A root that left the bundle once nothing used it any more is published afresh, with the
activation delay, if a CA that chains to it appears again. The issuer never signs with a CA whose root
retention has dropped from the bundle. When the key of the last CA is
removed, the issuer goes on publishing the anchors but signs nothing until a CA is added, and
discovery leaves out `spiffex_x509_svid_supported`; it starts without a usable CA when every CA has
expired, and says so in the log. A CA that only has a certificate in `ca_dir`, without a key, never
signs: that is how a compromised key is taken out of service at once. A restart is similar: a
certificate without a key that is not a root is skipped with a warning (delete it too when you are done
with it), and a `ca_dir` that still has anchors but no CA with a key starts, logs an error, publishes
the anchors, signs no X.509-SVIDs and leaves JWT-SVIDs alone. A `ca_dir` and `ca_roots` with no anchor
at all do not start. The restart does not remember what the running issuer knew, though: if you remove
a key while an older CA is still in `ca_dir`, whose root had already left the bundle, a restart within
`activation_delay` lets that older CA sign at once, under a root verifiers may have dropped. After
removing a key, run `ca prune` to remove the older CAs that are retired, and wait `activation_delay`
before restarting the issuer. The issuer warns when it starts with such a CA.

**Verifiers and the CA keys.** With `verifier_user`, the issuer refuses to start if that user can read
a `.key` file in `ca_dir`, judged as for `keys_dir`, or if a default ACL on `ca_dir` lets it read new
ones; the certificates are public and not judged. A CA key that becomes readable to it later is marked
exposed: its certificate stays published, but it never signs again, and a new CA key it can read is
neither used nor published.

## Asking for an X.509-SVID

With a CA that can sign, a workload asks the token endpoint for a certificate instead of a JWT-SVID:
the same authentication and the same SPIFFE ID, with `requested_token_type` and a `csr` in place of
the `audience` (SPEC section 3.4). It works with both grants and with every kind of origin.

```bash
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out svid.key
openssl req -new -key svid.key -subj / -outform DER -out svid.csr
curl -s https://issuer.example.org/token \
  -d grant_type=client_credentials -d client_id=vms/billing \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode client_assertion="$ASSERTION" \
  -d requested_token_type=urn:spiffex:token-type:x509-svid \
  --data-urlencode csr="$(base64 -w0 < svid.csr | tr '+/' '-_' | tr -d =)"
```

The `access_token` of the answer is the certificate chain, leaf first and the root left out: the DER
certificates concatenated and encoded as base64url without padding. `issued_token_type` is
`urn:spiffex:token-type:x509-svid`, and `expires_in` the seconds to the leaf's `notAfter`.

Only the CSR's public key is used: an ECDSA key on P-256 or P-384, an Ed25519 key, or an RSA key of
2048 to 4096 bits with exponent 65537, signed with a matching algorithm (never RSASSA-PSS). Its
subject, names, extensions and attributes are ignored. The certificate gets `O=<trust domain>` and
`CN=<SPIFFE ID>` as its subject (either left out when longer than 64 characters), the SPIFFE ID as
its one URI SAN, and the lifetime in `x509_svid_ttl`, shortened where the CA's chain ends sooner. A key the issuer already uses, as a CA or JWT signing key or a member key, is refused.

| Answer | Meaning |
|---|---|
| `invalid_request` | a malformed request or `csr`, a `csr` without the X.509 type, an `audience` with it, or an issuer without a CA that holds a key |
| `invalid_client` | the same as for a JWT-SVID: the proof failed |
| `invalid_target` | the origin's `svid_types` lacks `x509`; origins with an audience restriction get JWT-SVIDs only unless they list `x509` |
| `server_error` | the CA's chain ends in under five minutes, or every CA is exposed or expired; discovery then leaves out `spiffex_x509_svid_supported` |

Every certificate is logged with its serial number, SPIFFE ID, origin and `notAfter`: that log is the
only record, as an X.509-SVID cannot be revoked.

`spiffex token` does the whole exchange, with a new P-256 key made in memory and never sent anywhere:

```bash
spiffex token -issuer https://issuer.example.org -client-id vms/billing -key-file billing.key \
  -x509 -key-out svid.key -cert-out svid.crt -bundle-out bundle.crt
```

`-key-out` is written with mode `0600` and `-cert-out` (the chain, PEM) and the optional
`-bundle-out` (the trust domain's X.509 authorities, PEM) with `0644`. None of the files may exist.
The command creates them all first, then fetches the bundle (so it needs the issuer's bundle
endpoint, and the bundle must hold X.509 authorities) before asking for a certificate, and verifies
the chain against the bundle before writing anything. If any step fails, none of the files is left
behind. A process killed outright (SIGKILL, a panic, power loss) can leave empty or partial files
behind, the key file always with mode `0600`; delete them before running the command again.

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
| `-log-level` | `debug`, `info`, `warn` or `error`. The record of each issued X.509-SVID is written at every level, as it is the only trace of the certificate |

`spiffex token` takes the same proof flags and prints one JWT-SVID, or with `-x509` writes an
X.509-SVID (see above). `spiffex health -socket PATH`
exits 0 once an agent serves a trust bundle on that socket, for a container startup or readiness
probe.

The agent retries discovery until the issuer answers, and exits when the answer shows it was
misconfigured (a different issuer URL or trust domain).

Workloads find the agent through `SPIFFE_ENDPOINT_SOCKET=unix:///run/spiffex/billing.sock`. Anyone
who can connect to the socket gets the workload's identity, so keep it private to the workload: a
directory only its user can enter, or a volume shared only between its containers.

### X.509-SVIDs from the agent

When the issuer has a certificate authority (its discovery document says
`spiffex_x509_svid_supported: true`), the agent serves the X.509-SVID profile next to the JWT-SVID
one. go-spiffe's `workloadapi.NewX509Source` with `tlsconfig.MTLSServerConfig` and `MTLSClientConfig`,
and py-spiffe's `X509Source`, are tested against it; other libraries are expected to work, as the
agent follows the standard, but are not tested ([the guide](x509.md#what-is-tested) says what is).
The agent rereads that flag at every bundle refresh, so a CA added to a running issuer is noticed
within the refresh hint.

- `FetchX509SVID` streams one certificate chain, its private key (PKCS#8 DER) and the trust domain's
  X.509 bundle. The agent makes a new P-256 key for each certificate, asks the issuer for it with the
  workload's own proof, and renews at a random point between 40 and 50 percent of the certificate's
  life. Every open stream is sent each renewal, and every stream of the workload gets the same
  certificate and key. It never sends a certificate with less than a tenth of its life left. A stream
  that opens before the first certificate exists waits for it.
- While the issuer is down the agent retries with waits that start at a second, double up to a minute
  and are jittered, and keeps serving the certificate it has until the tenth is reached. Nothing is
  asked of the issuer while no stream is open.
- When the issuer refuses the request (`invalid_client`, `invalid_request`, `invalid_target`,
  `unsupported_grant_type`), for instance because the origin's `svid_types` lacks `x509`, every open
  stream ends with `PermissionDenied`, the certificate is dropped, and new streams get the same
  answer for a minute without the issuer being asked again. The JWT calls are unaffected.
- `FetchX509Bundles` streams the roots, and `FetchX509SVID` carries them too, again whenever a root
  is published or retired.
- Without a certificate authority at the issuer both calls answer `Unimplemented`, and go-spiffe's
  X.509 and combined sources wait for it until their deadline: use the JWT parts of the library.

Issuer replicas must share `ca_dir` and `keys_dir`. Replicas that disagree about the CA make the
discovery flag and the bundle differ from one refresh to the next, and the agent sees X.509 support
flap and its SVIDs stop chaining to the bundle.

The private keys live in the agent's memory and in the responses on the socket. The agent writes no
file for them and logs no key material. It does not lock the memory (a key can reach swap) and cannot
zero it: Go gives no way to wipe a key out of the heap or out of gRPC's buffers, so use encrypted swap
where that matters. The agent logs the serial number, SPIFFE ID and validity of each
certificate it obtains.

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
verifying. That includes the only key: with no key file left for two polls in a row (a single poll
that finds none only logs a warning, so an editor that renames the file away and back does no harm, and
the response takes up to two `-reload-interval`s), the running issuer stops signing
JWT-SVIDs, as it stops signing X.509-SVIDs when the key of the last CA is removed. It logs an error
and keeps running; the token endpoint answers a request for a JWT-SVID with `invalid_request` ("this
issuer issues no JWT-SVIDs"), the JWKS and the bundle publish no JWT key, discovery goes on listing the
algorithms it can sign with, ES256 and RS256, and X.509-SVIDs are unaffected. The management API admits nobody meanwhile, since it
can no longer mint or verify a management token; edit the stored state through its files if you
must. Run `key add` to make a new key: it signs at once, as in a new trust domain, and the issuer
picks it up within `-reload-interval`.

An issuer started with an empty `keys_dir` does the same, if it has a `ca_dir` with anchors: it
starts, logs an error, publishes the anchors and issues X.509-SVIDs, and issues JWT-SVIDs once a key
appears. Without a CA there would be nothing to publish, and it refuses to start. Removing the key
of the last CA is the same story for X.509 (see "The certificate authority"). A key that is only
exposed, readable by the verifier user, is a different case: it stays published, and the endpoint
answers `server_error` until a key the issuer alone can read is added.

When the keys directory is a Kubernetes Secret, keep the key files under their own names in the
Secret and update the Secret as a whole; the issuer treats a rewrite of files it already knows as no
change.

# spiffex Helm chart

Deploys the [spiffex](https://github.com/PeterSR/spiffex) issuer: an OAuth 2.0 token endpoint that
issues SPIFFE JWT-SVIDs and, with a certificate authority ([below](#the-certificate-authority)),
X.509-SVIDs, with its state in a ConfigMap and its settings built from values. It
deploys what [deploy/kubernetes/issuer.yaml](../../deploy/kubernetes/issuer.yaml) does, with the
same hardening: a non-root, read-only container without capabilities, the signing keys and TLS key
mounted with mode `0440` for the pod's `fsGroup` alone, and a Role that lets the issuer get (and,
with management on, update) its own state ConfigMap and nothing else. The agent is not part of the
chart; add it to workloads as in [docs/kubernetes.md](../../docs/kubernetes.md#a-workload).

## Installing

The chart needs a Secret with the signing keys, which it never generates. Make the keys with
`spiffex key add` and store them in the namespace:

```bash
mkdir keys && spiffex key add -dir keys
kubectl create namespace spiffex
kubectl -n spiffex create secret generic spiffex-signing-keys --from-file=keys
```

Protect the local `keys` directory like the Secret, or delete it. To rotate, add a key with
`spiffex key add`, replace the Secret as a whole, and prune old keys only as
[docs/configuration.md](../../docs/configuration.md#rotating-signing-keys) describes: after the
activation delay, the token lifetime and ten minutes more.

Then install, here with TLS from an existing Secret and a cluster origin:

```bash
kubectl -n spiffex create secret tls spiffex-issuer-tls --cert=tls.crt --key=tls.key

cat > values.yaml <<'EOF'
trustDomain: example.org
signingKeys:
  existingSecret: spiffex-signing-keys
tls:
  existingSecret: spiffex-issuer-tls
state:
  content:
    origins:
      cluster:
        provider: kubernetes
        with:
          namespaces: [shop]
EOF

helm install spiffex-issuer oci://ghcr.io/petersr/charts/spiffex --version 0.2.0 \
  --namespace spiffex -f values.yaml
```

With the release named `spiffex-issuer` the issuer is `https://spiffex-issuer.spiffex.svc`, as in
the plain manifests, and a pod's projected token for the origin `cluster` needs the audience
`https://spiffex-issuer.spiffex.svc/origins/cluster`. The install notes print the issuer URL, the
origin audience and the command for the first grant of the management API.

Verify the chart before installing it; [RELEASING.md](../../RELEASING.md#verifying-a-release) has
the `cosign verify` command.

## TLS

One of three:

- `tls.existingSecret`: a `kubernetes.io/tls` Secret valid for the issuer's host name.
- `tls.certManager.enabled` with `tls.certManager.issuerRef`: the chart makes a cert-manager
  `Certificate` for `<fullname>.<namespace>.svc`, `<fullname>.<namespace>.svc.cluster.local` and
  `tls.certManager.dnsNames`. The issuer takes up renewed certificates without a restart.
- Neither: the issuer serves plain HTTP, for a TLS-terminating proxy in front of it, such as the
  chart's own [Ingress](#ingress). `issuer` must then be the URL clients reach through that proxy,
  and `trustedProxies` should list the proxy so per-client limits apply to clients. The install
  notes warn about it.

Without `issuer`, the issuer URL is `https://<fullname>.<namespace>.svc`. Whatever it is, it must be
exactly what workloads and verifiers use, since tokens carry it as `iss`.

## Ingress

`ingress.enabled` adds an Ingress that routes every path of `ingress.host` to the issuer's Service,
for an issuer that workloads and verifiers outside the cluster reach. The issuer URL is then
`https://<ingress.host>`, and the chart refuses any other `issuer`, since tokens carry it as `iss`
and it must be what clients reach. Workloads in the cluster use that public URL too, not the
Service's name. Usually the ingress terminates TLS and the issuer, with neither
`tls.existingSecret` nor `tls.certManager`, serves plain HTTP inside the cluster. With ingress-nginx
and cert-manager:

```yaml
issuer: https://spiffex.example.org
trustDomain: example.org
signingKeys:
  existingSecret: spiffex-signing-keys
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  host: spiffex.example.org
  tls:
    secretName: spiffex-public-tls
```

With `ingress.tls.secretName` empty the Ingress has no `tls` section, for a controller that serves a
default certificate or a load balancer in front that terminates TLS. With TLS in the pod as well,
the ingress must speak HTTPS to the issuer: the chart adds the ingress-nginx annotation
`nginx.ingress.kubernetes.io/backend-protocol: HTTPS` unless `ingress.annotations` sets it. Other
controllers need their own equivalent in `ingress.annotations`.

**`trustedProxies` behind an ingress.** Only the per-address limits on exec verifiers
(`verifierLimits.perAddressPerMinute` and `perAddressBurst`) use client addresses; nothing else in
the issuer does. Without exec origins, leave `trustedProxies` empty: that fails safe.

With exec origins, every request behind an ingress arrives from the ingress controller, so without
`trustedProxies` all clients share one limit, and one busy client uses it up for everyone. The
controller names the client in `X-Forwarded-For`, and the issuer believes that header only from
addresses in `trustedProxies`; it then takes the rightmost address in the header that is not
itself trusted, so addresses a client writes into the header itself are not believed. Set
`trustedProxies` to the addresses the controller's connections to the issuer come from:

- A controller in ordinary pods connects from its pod addresses, which change with every restart,
  so list the pod CIDR its pods get addresses from (the cluster's pod CIDR, when they can land on
  any node). It differs per distribution: RKE2 and k3s default to `10.42.0.0/16`, kind to
  `10.244.0.0/16`.
- A controller with `hostNetwork: true`, common for an ingress-nginx DaemonSet, connects from the
  node: its node IP, or, for an issuer pod on another node, often the CNI's tunnel or bridge address
  on that node, which with flannel or canal lies inside the pod CIDR. List the node addresses and
  the pod CIDR.

To check, see whether the controller uses the host network, and which addresses its pods have. Its
namespace varies (`ingress-nginx` for the upstream chart, `kube-system` for RKE2's built-in one),
so look in all of them:

```bash
kubectl get daemonset,deployment -A -l app.kubernetes.io/name=ingress-nginx \
  -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: hostNetwork={.spec.template.spec.hostNetwork}{"\n"}{end}'
kubectl get pods -A -l app.kubernetes.io/name=ingress-nginx -o wide
```

The issuer logs a client address only when the per-address limit refuses it (`token request
failed`, with `client <address>`); while `trustedProxies` is incomplete, that address is the
controller's, not the caller's.

The trade-off: every address in `trustedProxies` can name any client it likes. When it is a pod
CIDR, any pod that can reach the issuer's Service directly can spread its requests over invented
addresses to escape its own limit, or charge them to someone else's address to use up theirs. A
NetworkPolicy that admits only the ingress controller to the issuer closes that; in-cluster
workloads then go through the ingress, as they must anyway to reach the public issuer URL. Leaving
`trustedProxies` empty is safe but makes the per-address limits one shared limit. When a load
balancer in front of the controller hides the real client address, the controller must learn it
first (for ingress-nginx, PROXY protocol or `use-forwarded-headers`), or it names the load balancer
as the client.

## Signing keys from a secret manager

`extraObjects` renders further manifests with the release, each passed through `tpl`, so a GitOps
setup can ship the `signingKeys.existingSecret` Secret with the chart. Because of `tpl`, any `{{ }}`
meant for the object itself, such as an ExternalSecret's `target.template`, must be escaped so the
chart passes it through: write `{{ "{{ .password }}" }}` for `{{ .password }}`. With the
[External Secrets Operator](https://external-secrets.io) and AWS Systems Manager Parameter Store,
this ExternalSecret puts every parameter under `/spiffex/prod/signing-keys/` into the Secret, one file
per key named after the parameter:

```yaml
signingKeys:
  existingSecret: spiffex-signing-keys
extraObjects:
  - apiVersion: external-secrets.io/v1
    kind: ExternalSecret
    metadata:
      name: '{{ .Values.signingKeys.existingSecret }}'
      namespace: '{{ .Release.Namespace }}'
    spec:
      refreshInterval: 1h
      secretStoreRef: { kind: ClusterSecretStore, name: aws-parameter-store }
      target: { name: '{{ .Values.signingKeys.existingSecret }}' }
      dataFrom:
        - find:
            path: /spiffex/prod/signing-keys
            name: { regexp: '/key-[0-9]{8}T[0-9]{6}Z\.pem$' }
          rewrite:
            - regexp: { source: '^/spiffex/prod/signing-keys/(.*)$', target: '$1' }
```

The SecretStore's IAM role needs `ssm:DescribeParameters` on `*`, which `find` lists parameters with
and which AWS does not scope to a path, and `ssm:GetParameter*` on
`arn:aws:ssm:<region>:<account>:parameter/spiffex/prod/signing-keys/*`, plus `kms:Decrypt` on the
KMS key that encrypts the parameters. Store each key as a SecureString parameter named like the file `spiffex key add` writes:

```bash
spiffex key add -dir keys   # writes keys/key-20261016T120000Z.pem
aws ssm put-parameter --type SecureString \
  --name /spiffex/prod/signing-keys/key-20261016T120000Z.pem --value file://keys/key-20261016T120000Z.pem
```

Adding a key is then adding a parameter: the operator writes it into the Secret at the next refresh,
and the issuer takes it up and publishes it for the activation delay before it signs. Delete a
parameter only when the pruning rule in
[docs/configuration.md](../../docs/configuration.md#rotating-signing-keys) allows removing that key.

## The certificate authority

Without `ca.existingSecret` the issuer issues JWT-SVIDs only. To have it issue X.509-SVIDs too, give
it a certificate authority (the settings `ca_dir`, `ca_roots`, `ca_roots_dedicated` and
`x509_svid_ttl`, described with their rules in
[docs/configuration.md](../../docs/configuration.md#the-certificate-authority)). Like the signing
keys, the CA's files are made outside the chart and the chart never generates them. A root the
issuer holds itself:

```bash
mkdir ca && spiffex ca init -dir ca -trust-domain example.org
kubectl -n spiffex create secret generic spiffex-ca --from-file=ca
```

```yaml
ca:
  existingSecret: spiffex-ca
```

The Secret is mounted at the issuer's `ca_dir`, `/ca`, with `defaultMode: 0440` for the pod's
`fsGroup`, as the signing keys are, and one Secret key is one file: `ca-<time>.crt` and
`ca-<time>.key`. The directory is separate from the signing keys' on purpose, so that a mistake in
one Secret does not expose both kinds of key. Protect the local `ca` directory like the Secret, or
delete it.

An intermediate under a root you keep elsewhere is made with `spiffex ca csr` and `spiffex ca
import`, which write the same files, and the root certificates go in a ConfigMap (they are public)
or a Secret, named by `ca.roots`:

```bash
kubectl -n spiffex create configmap spiffex-ca-roots --from-file=ca-roots.pem=roots.pem
```

```yaml
ca:
  existingSecret: spiffex-ca
  roots:
    configMap: spiffex-ca-roots   # or secret: <name>
    key: ca-roots.pem             # the key of the file in it, the default
  rootsDedicated: false           # true only as docs/configuration.md describes
x509SVIDTTL: 1h
```

The chart refuses `ca.roots` or `ca.rootsDedicated` without `ca.existingSecret`, and both kinds of
roots at once. A missing ConfigMap, Secret or key keeps the pod from starting, which is the point.

**Rotation does not restart the issuer.** The issuer rereads `ca_dir` and `ca_roots` every
`reloadInterval`, and the kubelet updates a mounted Secret or ConfigMap within about a minute (not
a `subPath` mount, which the chart does not use). Replace the Secret as a whole, with the new CA's
files added next to the old ones, then follow the rotation rules in
[docs/configuration.md](../../docs/configuration.md#the-certificate-authority): the new CA is
published for `activationDelay` before the issuer signs with it, and an old one is removed only
when `spiffex ca prune` allows. Changing `x509SVIDTTL`, `ca.rootsDedicated` or which roots object
is used changes the settings and so restarts the issuer.

Workloads reach the CA through their agent, which serves the X.509-SVID and the bundle on the
Workload API as it does JWT-SVIDs; the agent is not part of the chart. An origin issues X.509-SVIDs
unless its `svid_types` leaves them out.

## The state ConfigMap

The state (origins, providers and grants) is in a ConfigMap, `<fullname>-state` by default, under
the key `state.yaml`. Once the issuer runs, the management API, `spiffex bootstrap` and
`kubectl edit` change it, so the chart must not put `state.content` back on every upgrade. It
therefore:

- creates the ConfigMap from `state.content` on install, and only when it does not exist yet;
- leaves it out of every later render: the template looks the ConfigMap up and renders nothing when
  it exists, so `helm upgrade` never compares or overwrites its data;
- marks it `helm.sh/resource-policy: keep`, so Helm does not delete it on the upgrade that stops
  rendering it, nor on `helm uninstall`. A later `helm install` into the same namespace takes up the
  kept state as it is. Delete the ConfigMap yourself to start over.

Changing `state.content` after install therefore changes nothing; change the state through the
management API or `kubectl edit`. `helm rollback` to the install revision fails with `no ConfigMap
with the name ... found` and leaves the state alone; roll back to a later revision instead.

Helm reads values as YAML 1.1, where a bare `on` is the boolean true. Quote the `on` key of every
grant in `state.content`, as in `"on": [/]`; the chart fails with a message naming the grant when
one is left bare. Quote any other name or value that is `on`, `off`, `yes`, `no`, `y` or `n` too,
since Helm silently turns those into booleans. A state written to a file or sent through the
management API needs no quotes.

To manage the ConfigMap entirely yourself, create it (with a `state.yaml` key, which may be `{}`)
and set `state.existingConfigMap`. The chart then creates no state ConfigMap, and the Role names
yours.

**Argo CD and other GitOps tools** render the chart with `helm template`, where the lookup finds
nothing, so the ConfigMap is always rendered with `state.content` and a sync would overwrite what
the management API wrote. The ConfigMap carries `argocd.argoproj.io/sync-options:
Prune=false,Delete=false`, so Argo CD never deletes it, but it still updates it. The safe setup is
to tell Argo CD to ignore the ConfigMap's data and to respect that when it syncs, not only when it
compares. Git then provides the initial state once, when Argo CD creates the ConfigMap, and never
overwrites what the management API writes afterwards:

```yaml
spec:
  ignoreDifferences:
    - kind: ConfigMap
      name: spiffex-issuer-state
      jsonPointers: [/data]
  syncPolicy:
    syncOptions: [RespectIgnoreDifferences=true]
```

Without `RespectIgnoreDifferences=true`, `ignoreDifferences` only hides the difference, and the
next sync still applies `state.content`. Alternatively, set `state.existingConfigMap` and keep the
state out of Git. `state.configMapAnnotations` adds further annotations to the ConfigMap, for
instance other Argo CD options. An `argocd.argoproj.io/sync-options` given there keeps its options,
and the chart adds `Prune=false` and `Delete=false` to them when missing.

Flux's helm-controller runs real installs and upgrades, where the lookup works as with `helm`.

## Values

| Value | Default | Description |
|---|---|---|
| `issuer` | `""` | The issuer URL. Empty: `https://<fullname>.<namespace>.svc`, which needs TLS. Required without TLS. |
| `trustDomain` | `""` | The trust domain (required). |
| `tokenTTL` | `5m` | Lifetime of issued JWT-SVIDs, at most `1h`. |
| `x509SVIDTTL` | unset | Lifetime of issued X.509-SVIDs, `10m` to `24h`. Unset keeps the issuer's default, `1h`. |
| `activationDelay` | `30m` | How long a new signing key or CA is published before it signs. |
| `management` | `true` | Serve the management API at `<issuer>/manage`. Off, the issuer may only get its state ConfigMap. |
| `reloadInterval` | `10s` | How often the issuer checks the state and the signing keys for changes. |
| `logLevel` | `info` | `debug`, `info`, `warn` or `error`. |
| `fetch.refusePrivateAddresses` | `true` | Refuse key fetches to non-public addresses. |
| `fetch.allowPrivateHosts` | `[kubernetes.default.svc.cluster.local:443]` | `host:port` pairs exempt from that; the default is the in-cluster API server. |
| `readableFiles` | unset | `readable_files` of the settings; unset keeps the issuer's default. The schema refuses paths that start with `/keys`, `/tls`, `/config`, `/ca` or `/ca-roots`, by name only: it does not see through `..` or symlinks, so it guards against mistakes, not against an operator. |
| `bearerTokenFiles` | unset | `bearer_token_files`, as `{path, hosts, paths}`; unset keeps the default. |
| `verifiers` | unset | Installed exec verifiers, each a list of an absolute path and fixed arguments. Mount them with `extraVolumes`. |
| `verifierLimits` | unset | `{perOrigin, total, perAddressPerMinute, perAddressBurst}`. |
| `verifierUser` | unset | `{uid, gid}` exec verifiers run as. Needs CAP_SETUID, CAP_SETGID and CAP_KILL in `securityContext`. |
| `trustedProxies` | `[]` | Addresses or CIDRs whose `X-Forwarded-For` names the client. Only exec verifiers' per-address limits use it; behind an ingress, the controller's source addresses. See [Ingress](#ingress). |
| `ingress.enabled` | `false` | Add an Ingress routing every path of `ingress.host` to the issuer. `issuer` must then be `https://<ingress.host>`. |
| `ingress.className` | `""` | The Ingress's `ingressClassName`, when set. |
| `ingress.annotations` | `{}` | For instance `cert-manager.io/cluster-issuer: letsencrypt-prod`. With TLS in the pod, `nginx.ingress.kubernetes.io/backend-protocol: HTTPS` is added unless set here. |
| `ingress.host` | `""` | The host clients reach the issuer at (required with the ingress). |
| `ingress.tls.secretName` | `""` | The Secret with the host's certificate. Empty leaves the `tls` section out. |
| `state.existingConfigMap` | `""` | A state ConfigMap you manage; the chart then creates none. |
| `state.content` | `{}` | The state written on install, and never again. Empty admits nobody. |
| `state.configMapAnnotations` | `{}` | Further annotations on the state ConfigMap the chart creates. `helm.sh/resource-policy: keep` is always set, and `Prune=false,Delete=false` is added to any `argocd.argoproj.io/sync-options` given. |
| `signingKeys.existingSecret` | `""` | The Secret with the signing keys (required). |
| `ca.existingSecret` | `""` | The Secret with the CA's files, mounted at `ca_dir`. Empty: no CA, JWT-SVIDs only. See [The certificate authority](#the-certificate-authority). |
| `ca.roots.configMap`, `ca.roots.secret` | `""` | The object holding the root certificates of your own CA (`ca_roots`); one of them, and only with `ca.existingSecret`. |
| `ca.roots.key` | `ca-roots.pem` | The key of the roots file in that object. |
| `ca.rootsDedicated` | `false` | `ca_roots_dedicated`: every CA those roots certify is this issuer's. Needs `ca.roots`. |
| `tls.existingSecret` | `""` | A TLS Secret for the issuer. |
| `tls.certManager.enabled` | `false` | Make a cert-manager `Certificate` instead. |
| `tls.certManager.issuerRef` | `{name: "", kind: Issuer, group: cert-manager.io}` | The cert-manager issuer; `name` is required when enabled. |
| `tls.certManager.dnsNames` | `[]` | Further names for the certificate. |
| `tls.certManager.duration`, `renewBefore` | `""` | Passed to the `Certificate` when set. |
| `image.repository` | `ghcr.io/petersr/spiffex` | |
| `image.tag` | `""` | Defaults to `v<appVersion>`. |
| `image.digest` | `""` | `sha256:...`; when set, the image is pulled by digest and the tag is ignored. |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | |
| `nameOverride`, `fullnameOverride` | `""` | |
| `replicas` | `2` | Each replica keeps its own replay records; see docs/kubernetes.md. |
| `serviceAccount.annotations` | `{}` | |
| `service.type` | `ClusterIP` | |
| `service.port` | `null` | 443 with TLS, 80 without. |
| `service.annotations` | `{}` | |
| `podDisruptionBudget.enabled` | `true` | |
| `podDisruptionBudget.minAvailable` | `1` | |
| `podAnnotations`, `podLabels` | `{}` | |
| `podSecurityContext` | non-root, `fsGroup: 65532`, `RuntimeDefault` seccomp | |
| `securityContext` | no privilege escalation, read-only root, all capabilities dropped | |
| `resources` | requests `50m`/`32Mi`, limit `128Mi` | |
| `readinessProbe`, `livenessProbe` | periods and thresholds | Merged into `httpGet /healthz` probes. |
| `nodeSelector`, `tolerations`, `affinity`, `priorityClassName` | empty | |
| `topologySpreadConstraints` | `[]` | Empty spreads the replicas across nodes (`kubernetes.io/hostname`) and zones (`topology.kubernetes.io/zone`), `maxSkew: 1`, `whenUnsatisfiable: ScheduleAnyway`, so a single-node cluster still schedules them. A list given replaces this default. |
| `extraVolumes`, `extraVolumeMounts`, `extraEnv` | `[]` | |
| `extraObjects` | `[]` | Further manifests, as maps or strings, each passed through `tpl`. See [Signing keys from a secret manager](#signing-keys-from-a-secret-manager). |

`values.schema.json` refuses unknown values. The settings these values become are described in
[docs/configuration.md](../../docs/configuration.md); the chart's tests render each value set in
`ci/` and run `spiffex check` on the settings and state they produce.

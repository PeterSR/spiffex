# spiffex Helm chart

Deploys the [spiffex](https://github.com/PeterSR/spiffex) issuer: an OAuth 2.0 token endpoint that
issues SPIFFE JWT-SVIDs, with its state in a ConfigMap and its settings built from values. It
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

helm install spiffex-issuer oci://ghcr.io/petersr/charts/spiffex --version 0.1.0-rc.1 \
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
- Neither: the issuer serves plain HTTP, for a TLS-terminating proxy in front of it. `issuer` must
  then be the URL clients reach through that proxy, and `trustedProxies` should list the proxy so
  per-client limits apply to clients. The install notes warn about it.

Without `issuer`, the issuer URL is `https://<fullname>.<namespace>.svc`. Whatever it is, it must be
exactly what workloads and verifiers use, since tokens carry it as `iss`.

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

To manage the ConfigMap entirely yourself, create it (with a `state.yaml` key, which may be `{}`)
and set `state.existingConfigMap`. The chart then creates no state ConfigMap, and the Role names
yours.

**Argo CD and other GitOps tools** render the chart with `helm template`, where the lookup finds
nothing, so the ConfigMap is always rendered with `state.content` and a sync would overwrite what
the management API wrote. The ConfigMap carries `argocd.argoproj.io/sync-options:
Prune=false,Delete=false`, so Argo CD never deletes it, but it still updates it. Either set
`state.existingConfigMap` and keep the state out of Git, or tell Argo CD to ignore the data:

```yaml
spec:
  ignoreDifferences:
    - kind: ConfigMap
      name: spiffex-issuer-state
      jsonPointers: [/data]
  syncPolicy:
    syncOptions: [RespectIgnoreDifferences=true]
```

Flux's helm-controller runs real installs and upgrades, where the lookup works as with `helm`.

## Values

| Value | Default | Description |
|---|---|---|
| `issuer` | `""` | The issuer URL. Empty: `https://<fullname>.<namespace>.svc`, which needs TLS. Required without TLS. |
| `trustDomain` | `""` | The trust domain (required). |
| `tokenTTL` | `5m` | Lifetime of issued JWT-SVIDs, at most `1h`. |
| `activationDelay` | `30m` | How long a new signing key is published before it signs. |
| `management` | `true` | Serve the management API at `<issuer>/manage`. Off, the issuer may only get its state ConfigMap. |
| `reloadInterval` | `10s` | How often the issuer checks the state and the signing keys for changes. |
| `logLevel` | `info` | `debug`, `info`, `warn` or `error`. |
| `fetch.refusePrivateAddresses` | `true` | Refuse key fetches to non-public addresses. |
| `fetch.allowPrivateHosts` | `[kubernetes.default.svc.cluster.local:443]` | `host:port` pairs exempt from that; the default is the in-cluster API server. |
| `readableFiles` | unset | `readable_files` of the settings; unset keeps the issuer's default. |
| `bearerTokenFiles` | unset | `bearer_token_files`, as `{path, hosts, paths}`; unset keeps the default. |
| `verifiers` | unset | Installed exec verifiers, each a list of an absolute path and fixed arguments. Mount them with `extraVolumes`. |
| `verifierLimits` | unset | `{perOrigin, total, perAddressPerMinute, perAddressBurst}`. |
| `verifierUser` | unset | `{uid, gid}` exec verifiers run as. Needs CAP_SETUID, CAP_SETGID and CAP_KILL in `securityContext`. |
| `trustedProxies` | `[]` | Addresses or CIDRs whose `X-Forwarded-For` names the client. |
| `state.existingConfigMap` | `""` | A state ConfigMap you manage; the chart then creates none. |
| `state.content` | `{}` | The state written on install, and never again. Empty admits nobody. |
| `signingKeys.existingSecret` | `""` | The Secret with the signing keys (required). |
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
| `nodeSelector`, `tolerations`, `affinity`, `topologySpreadConstraints`, `priorityClassName` | empty | |
| `extraVolumes`, `extraVolumeMounts`, `extraEnv` | `[]` | |

`values.schema.json` refuses unknown values. The settings these values become are described in
[docs/configuration.md](../../docs/configuration.md); the chart's tests render each value set in
`ci/` and run `spiffex check` on the settings and state they produce.

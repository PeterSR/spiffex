#!/usr/bin/env bash
# The single-quoted sh -c scripts below expand their own arguments, in the pod.
# shellcheck disable=SC2016
# End-to-end test on a kind cluster: the issuer runs in the cluster, keeps
# its state in a ConfigMap, trusts the cluster's service account tokens, and
# two workloads with agent sidecars, deployed from
# deploy/kubernetes/workload.yaml, get JWT-SVIDs and verify each other's. A
# third workload whose token carries the wrong audience must get nothing.
# Changes to the state are taken up while the issuer runs; an invalid state
# is not. Finally the management API: a grant bootstrapped for one pod lets
# it add an origin through its agent, a pod without one is refused, and a
# grant that would break closure is refused with its reasons.
#
# INSTALL=helm (or test/e2e/kind-helm.sh) installs the issuer with the chart in
# charts/spiffex instead of deploy/kubernetes/issuer.yaml, runs the same
# checks, and then checks that upgrading, rolling back to the install
# revision, uninstalling and reinstalling the chart leave the state the
# management API wrote alone. It also has the API server check the chart rendered with the ingress
# on, which kind cannot route.
#
# Needs docker, kind, kubectl, openssl and Go, and helm with INSTALL=helm.
# KEEP=1 leaves the cluster up after the run, for a look around.
set -euo pipefail
cd "$(dirname "$0")/../.."
INSTALL=${INSTALL:-manifests}
case $INSTALL in
  manifests) CLUSTER=spiffex-e2e STATE_CM=spiffex-state ;;
  helm) CLUSTER=spiffex-e2e-helm STATE_CM=spiffex-issuer-state ;;
  *) echo "INSTALL is manifests or helm, not $INSTALL" >&2; exit 2 ;;
esac
WORK="$(mktemp -d)"
# Our own kubeconfig, so the run never touches the user's contexts.
export KUBECONFIG="$WORK/kubeconfig"
TD=example.org
ISSUER=https://spiffex-issuer.spiffex.svc
ORIGIN_AUD=$ISSUER/origins/cluster

cleanup() {
  if [ -z "${KEEP:-}" ]; then
    kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1 || true
    docker image rm spiffex:e2e spiffex-e2e-client:e2e >/dev/null 2>&1 || true
    rm -rf "$WORK"
  else
    echo "KEEP set: cluster $CLUSTER is kept; its kubeconfig is $KUBECONFIG"
  fi
}
trap cleanup EXIT

echo "== cluster"
# Always a fresh cluster: a left-over one holds the previous run's certificates.
kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" --wait 120s
K8S_ISSUER=$(kubectl get --raw /.well-known/openid-configuration | sed -n 's/.*"issuer":"\([^"]*\)".*/\1/p')
echo "cluster service account issuer: $K8S_ISSUER"

echo "== images"
docker build -q -t spiffex:e2e . >/dev/null
CGO_ENABLED=0 go build -o "$WORK/goclient" ./conformance/goclient
CGO_ENABLED=0 go build -o "$WORK/spiffex" ./cmd/spiffex
docker build -q -t spiffex-e2e-client:e2e -f test/e2e/Dockerfile "$WORK" >/dev/null
kind load docker-image --name "$CLUSTER" spiffex:e2e spiffex-e2e-client:e2e >/dev/null

echo "== issuer"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=spiffex-e2e-ca \
  -keyout "$WORK/ca.key" -out "$WORK/ca.crt" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=spiffex-issuer \
  -keyout "$WORK/tls.key" -out "$WORK/tls.csr" 2>/dev/null
openssl x509 -req -in "$WORK/tls.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" -CAcreateserial -days 1 \
  -extfile <(printf 'subjectAltName=DNS:spiffex-issuer.spiffex.svc') -out "$WORK/tls.crt" 2>/dev/null
mkdir "$WORK/keys" && "$WORK/spiffex" key add -dir "$WORK/keys" >/dev/null

kubectl create namespace spiffex --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n spiffex create secret generic spiffex-signing-keys --from-file="$WORK/keys" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n spiffex create secret tls spiffex-issuer-tls --cert="$WORK/tls.crt" --key="$WORK/tls.key" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
if [ "$INSTALL" = helm ]; then
  cat >"$WORK/values.yaml" <<VALUES
trustDomain: $TD
image: { repository: spiffex, tag: e2e }
signingKeys: { existingSecret: spiffex-signing-keys }
tls: { existingSecret: spiffex-issuer-tls }
state:
  content:
    origins:
      cluster:
        provider: kubernetes
        with:
          issuer: $K8S_ISSUER
          namespaces: [shop]
VALUES
  helm_issuer() { # install or upgrade, then extra helm flags
    helm "$1" spiffex-issuer charts/spiffex -n spiffex -f "$WORK/values.yaml" "${@:2}" >/dev/null
  }
  helm_issuer install
else
  sed -e "s#ghcr.io/petersr/spiffex:v[^ ]*\$#spiffex:e2e#" \
      -e "s#issuer: https://kubernetes.default.svc.cluster.local\$#issuer: $K8S_ISSUER#" deploy/kubernetes/issuer.yaml | kubectl apply -f - >/dev/null
fi
kubectl -n spiffex rollout status deploy/spiffex-issuer --timeout=120s

echo "== workloads"
kubectl create namespace shop --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n shop create configmap spiffex-ca --from-file=ca.crt="$WORK/ca.crt" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
workload() { # name audience
  sed -e "s#billing#$1#g" \
      -e "s#audience: $ORIGIN_AUD#audience: $2#" \
      -e "s#ghcr.io/petersr/spiffex:v[^ ]*\$#spiffex:e2e#" \
      -e "s#image: registry.example.org/$1:1.0#image: spiffex-e2e-client:e2e\n          command: [sleep, \"86400\"]#" \
      deploy/kubernetes/workload.yaml | kubectl apply -f - >/dev/null
}
workload billing "$ORIGIN_AUD"
workload orders "$ORIGIN_AUD"
workload intruder "$ISSUER/origins/elsewhere"
for w in billing orders intruder; do kubectl -n shop rollout status deploy/$w --timeout=120s; done

app() { local w=$1; shift; kubectl -n shop exec deploy/"$w" -c app -- "$@"; }
# The token exchange the README shows, run as it shows it.
out=$(kubectl -n shop exec deploy/billing -c spiffex-agent -- /spiffex token \
  -issuer https://spiffex-issuer.spiffex.svc -ca-file /etc/spiffex/ca.crt \
  -subject-token-file /var/run/secrets/spiffex/token \
  -audience spiffe://example.org/cluster/ns/shop/sa/orders) || { echo "FAIL: the README's token exchange: $out"; exit 1; }
sub=$(printf '%s' "$out" | cut -d. -f2 | tr '_-' '/+' | { b=$(cat); while [ $(( ${#b} % 4 )) -ne 0 ]; do b="$b="; done; printf '%s' "$b"; } | base64 -d 2>/dev/null | sed -n 's/.*"sub":"\([^"]*\)".*/\1/p')
[ "$sub" = "spiffe://$TD/cluster/ns/shop/sa/billing" ] || { echo "FAIL: the README's token exchange gave sub '$sub'"; exit 1; }
echo "ok: the README's token exchange works"
check() { # description want got
  if [ "$2" != "$3" ]; then echo "FAIL: $1: got '$3', want '$2'"; exit 1; fi
  echo "ok: $1"
}

echo "== checks"
AUD="spiffe://$TD/cluster/ns/shop/sa/orders"
BILLING="spiffe://$TD/cluster/ns/shop/sa/billing"
# No retry: the startup probe holds the app back until the agent is ready.
TOKEN=$(app billing /goclient fetch "$AUD")
check "billing's agent validates billing's token as billing" "$BILLING" \
  "$(app billing /goclient validate-agent "$AUD" "$TOKEN")"
check "orders' agent validates billing's token" "$BILLING" \
  "$(app orders /goclient validate-agent "$AUD" "$TOKEN")"
check "the bundle endpoint validates billing's token" "$BILLING" \
  "$(kubectl -n shop exec -i deploy/orders -c app -- sh -c \
      'cat > /tmp/ca.crt && SSL_CERT_FILE=/tmp/ca.crt /goclient validate-bundle "$@"' - \
      "$ISSUER/bundle" "$TD" "$AUD" "$TOKEN" <"$WORK/ca.crt")"
if app orders /goclient validate-agent "spiffe://$TD/cluster/ns/shop/sa/elsewhere" "$TOKEN" >/dev/null 2>&1; then
  echo "FAIL: a token was accepted for the wrong audience"; exit 1
fi
echo "ok: the wrong audience is refused"
out=$(app intruder /goclient fetch "$AUD" 2>&1) && {
  echo "FAIL: a pod whose token has the wrong audience got a JWT-SVID"; exit 1
}
case $out in
  *PermissionDenied*) echo "ok: a token with the wrong audience gets PermissionDenied" ;;
  *) echo "FAIL: the wrong-audience pod failed for another reason: $out"; exit 1 ;;
esac

# Tokens anyone with RBAC to mint them can make: not bound to a pod, and
# long-lived. The issuer must refuse both.
exchange() { # token
  kubectl -n shop exec -i deploy/billing -c app -- sh -c \
    'cat > /tmp/ca.crt && echo "$1" > /tmp/t && /spiffex token -issuer "$2" -subject-token-file /tmp/t -audience x -ca-file /tmp/ca.crt' - \
    "$1" "$ISSUER" <"$WORK/ca.crt" 2>&1
}
for duration in 10m 48h; do
  out=$(exchange "$(kubectl -n shop create token billing --audience "$ORIGIN_AUD" --duration "$duration")") && {
    echo "FAIL: a $duration token not bound to a pod was exchanged"; exit 1
  }
  case $out in
    *invalid_request*) echo "ok: a $duration token not bound to a pod is refused" ;;
    *) echo "FAIL: the $duration token failed for another reason: $out"; exit 1 ;;
  esac
done
pod=$(kubectl -n shop get pod -l app=billing -o jsonpath='{.items[0].metadata.name}')
uid=$(kubectl -n shop get pod "$pod" -o jsonpath='{.metadata.uid}')
bound() { kubectl -n shop create token billing --audience "$ORIGIN_AUD" --duration "$1" \
  --bound-object-kind Pod --bound-object-name "$pod" --bound-object-uid "$uid"; }
out=$(exchange "$(bound 48h)") && { echo "FAIL: a 48h pod-bound token was exchanged"; exit 1; }
case $out in
  *invalid_request*) echo "ok: a pod-bound token meant to live 48h is refused" ;;
  *) echo "FAIL: the 48h pod-bound token failed for another reason: $out"; exit 1 ;;
esac
check "a pod-bound token within the lifetime cap is exchanged" ok \
  "$(exchange "$(bound 30m)" >/dev/null && echo ok)"

echo "== state changes"
set_state() { # state.yaml content
  kubectl -n spiffex create configmap "$STATE_CM" --from-literal=state.yaml="$1" --dry-run=client -o yaml |
    kubectl apply -f - >/dev/null 2>&1
}
# Both replicas must have taken up the change, so wait for several answers in
# a row to agree.
until_exchange() { # want: ok or refused
  local streak=0
  for _ in $(seq 60); do
    if exchange "$(bound 30m)" >/dev/null; then got=ok; else got=refused; fi
    if [ "$got" = "$1" ]; then streak=$((streak + 1)); else streak=0; fi
    [ "$streak" -ge 6 ] && return 0
    sleep 1
  done
  return 1
}
STATE="origins:
  cluster:
    provider: kubernetes
    with:
      issuer: $K8S_ISSUER"
set_state "$STATE
      deny_namespaces: [kube-system, shop]"
until_exchange refused || { echo "FAIL: denying namespace shop did not take effect"; exit 1; }
echo "ok: a change to the state is taken up while the issuer runs"
set_state "origins: { cluster: { provider: kubernetes, prefix: nope } }"
sleep 25
check "an invalid state leaves the last valid one in service" ok "$(until_exchange refused && echo ok)"
kubectl -n spiffex logs deploy/spiffex-issuer | grep -q "the stored state is invalid" ||
  { echo "FAIL: the issuer did not log the invalid state"; exit 1; }
echo "ok: the invalid state is logged"
set_state "$STATE"
until_exchange ok || { echo "FAIL: restoring the state did not take effect"; exit 1; }
echo "ok: restoring the state is taken up"

echo "== management"
# The first grant is written straight to the state, here from inside an
# issuer pod, whose service account may update the state ConfigMap.
kubectl -n spiffex exec deploy/spiffex-issuer -- /spiffex bootstrap -config /config/issuer.yaml \
  -grant shop-admin -who "$BILLING" >/dev/null
echo "ok: bootstrapped a grant for $BILLING"
manage() { # workload, then spiffex manage arguments; the token comes from the pod's agent
  local w=$1; shift
  kubectl -n shop exec -i deploy/"$w" -c app -- sh -c \
    'cat > /tmp/ca.crt && issuer=$1 && shift && /spiffex manage -issuer "$issuer" -ca-file /tmp/ca.crt "$@"' - \
    "$ISSUER" "$@" <"$WORK/ca.crt" 2>&1
}
in_pod() { kubectl -n shop exec deploy/"$1" -c app -- sh -c "$2"; }
in_pod billing 'echo "{\"provider\": \"keys\"}" > /tmp/vms.json'
out=$(manage billing put origin vms -f /tmp/vms.json) || { echo "FAIL: billing could not add an origin: $out"; exit 1; }
case $out in
  "created origin vms, version"*) echo "ok: billing adds an origin through its agent" ;;
  *) echo "FAIL: adding an origin answered: $out"; exit 1 ;;
esac
in_pod billing '/spiffex key generate -out /tmp/m1.key > /tmp/m1.pub'
out=$(manage billing put member vms m1 -key /tmp/m1.pub) || { echo "FAIL: billing could not add a member: $out"; exit 1; }
# Both replicas must issue to the new member: the one that stored it at
# once, the other at its next reload.
member_token() {
  kubectl -n shop exec -i deploy/billing -c app -- sh -c \
    'cat > /tmp/ca.crt && /spiffex token -issuer "$1" -client-id vms/m1 -key-file /tmp/m1.key -audience x -ca-file /tmp/ca.crt' - \
    "$ISSUER" <"$WORK/ca.crt" >/dev/null 2>&1
}
streak=0
for _ in $(seq 60); do
  if member_token; then streak=$((streak + 1)); else streak=0; fi
  [ "$streak" -ge 6 ] && break
  sleep 1
done
[ "$streak" -ge 6 ] || { echo "FAIL: the member added through the API gets no token"; exit 1; }
echo "ok: the issuer takes up the change"
out=$(manage orders get state) || { echo "FAIL: orders could not read the state: $out"; exit 1; }
case $out in
  *vms*) echo "FAIL: orders sees an origin it has no grant for: $out"; exit 1 ;;
  *) echo "ok: orders sees nothing it has no grant for" ;;
esac
in_pod orders 'echo "{\"provider\": \"keys\"}" > /tmp/other.json'
out=$(manage orders put origin other -f /tmp/other.json) && { echo "FAIL: orders, without a grant, added an origin"; exit 1; }
case $out in
  *"403 Forbidden"*) echo "ok: a pod without a grant is refused" ;;
  *) echo "FAIL: orders was refused for another reason: $out"; exit 1 ;;
esac
# Anyone who may write /cluster could become billing, which may do more.
in_pod billing "echo '{\"who\": \"spiffe://$TD/cluster/**\", \"can\": [\"write\"], \"on\": [\"/cluster\"]}' > /tmp/grant.json"
out=$(manage billing put grant cluster-writers -f /tmp/grant.json) && { echo "FAIL: a grant breaking closure was stored"; exit 1; }
case $out in
  *"422 Unprocessable Entity"*"grants.cluster-writers"*"grant shop-admin"*) echo "ok: a grant breaking closure gets a 422 naming the grants" ;;
  *) echo "FAIL: the closure-breaking grant was refused for another reason: $out"; exit 1 ;;
esac
if [ "$INSTALL" = helm ]; then
  echo "== helm lifecycle"
  eventually() { for _ in $(seq 30); do "$@" && return 0; sleep 1; done; return 1; }
  has_vms() { kubectl -n spiffex get configmap "$STATE_CM" -o jsonpath='{.data.state\.yaml}' | grep -q '^  vms:'; }
  has_vms || { echo "FAIL: the state ConfigMap lacks the origin added through the API"; exit 1; }
  # A settings change restarts the issuer; the state must survive the upgrade.
  helm_issuer upgrade --set logLevel=debug
  kubectl -n spiffex rollout status deploy/spiffex-issuer --timeout=120s >/dev/null
  has_vms || { echo "FAIL: helm upgrade overwrote the state"; exit 1; }
  eventually member_token || { echo "FAIL: after helm upgrade, the member gets no token"; exit 1; }
  echo "ok: helm upgrade leaves the state alone"
  # Revision 1 rendered the state ConfigMap, the current one does not, so Helm refuses to roll back
  # to revision 1 when it reaches that ConfigMap ("no ConfigMap with the name ... found") and
  # marks the rollback failed. Resources Helm updated before it reached that one, in its install
  # order (the ServiceAccount, and ConfigMaps whose names sort first, such as the settings), may
  # then hold revision 1's content; the Deployment, which comes later, keeps the current one. The
  # next helm upgrade puts everything back in line.
  generation=$(kubectl -n spiffex get deploy/spiffex-issuer -o jsonpath='{.metadata.generation}')
  out=$(helm rollback spiffex-issuer 1 -n spiffex 2>&1) && { echo "FAIL: helm rollback to the install revision succeeded"; exit 1; }
  case $out in
    *"no ConfigMap with the name \"$STATE_CM\" found"*) ;;
    *) echo "FAIL: helm rollback failed for another reason: $out"; exit 1 ;;
  esac
  has_vms || { echo "FAIL: helm rollback overwrote the state"; exit 1; }
  [ "$(kubectl -n spiffex get deploy/spiffex-issuer -o jsonpath='{.metadata.generation}')" = "$generation" ] ||
    { echo "FAIL: the failed rollback changed the Deployment"; exit 1; }
  echo "ok: helm rollback to the install revision is refused and leaves the state alone"
  helm_issuer upgrade --set logLevel=debug
  kubectl -n spiffex rollout status deploy/spiffex-issuer --timeout=120s >/dev/null
  has_vms || { echo "FAIL: the upgrade after the rollback overwrote the state"; exit 1; }
  eventually member_token || { echo "FAIL: after the upgrade that follows the rollback, the member gets no token"; exit 1; }
  echo "ok: an upgrade after the failed rollback restores the release"
  helm uninstall spiffex-issuer -n spiffex --wait >/dev/null
  has_vms || { echo "FAIL: helm uninstall removed the state"; exit 1; }
  echo "ok: helm uninstall keeps the state ConfigMap"
  helm_issuer install
  kubectl -n spiffex rollout status deploy/spiffex-issuer --timeout=120s >/dev/null
  has_vms || { echo "FAIL: reinstalling the chart overwrote the state"; exit 1; }
  eventually member_token || { echo "FAIL: after reinstalling, the member gets no token"; exit 1; }
  echo "ok: reinstalling the chart takes up the kept state"
  # kind has no ingress controller, so the ingress value set is only rendered and checked by the
  # API server, without its ExternalSecret, whose CRD the cluster lacks.
  helm template spiffex-issuer charts/spiffex -n spiffex -f charts/spiffex/ci/ingress-values.yaml --set extraObjects=null |
    kubectl apply --dry-run=server --server-side --force-conflicts --field-manager=e2e-ingress -f - >/dev/null || { echo "FAIL: the API server refuses the ingress value set"; exit 1; }
  echo "ok: the API server accepts the chart with the ingress on"
fi
echo "== all checks passed"

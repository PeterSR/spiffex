#!/usr/bin/env bash
# End-to-end test on a kind cluster: the issuer runs in the cluster, trusts
# the cluster's service account tokens, and two workloads with agent
# sidecars, deployed from deploy/kubernetes/workload.yaml, get JWT-SVIDs and
# verify each other's. A third workload whose token carries the wrong
# audience must get nothing.
#
# Needs docker, kind, kubectl, openssl and Go. KEEP=1 leaves the cluster up
# after the run, for a look around.
set -euo pipefail
cd "$(dirname "$0")/../.."
CLUSTER=spiffex-e2e
WORK="$(mktemp -d)"
TD=example.org
ISSUER=https://spiffex-issuer.spiffex.svc

cleanup() {
  rm -rf "$WORK"
  if [ -z "${KEEP:-}" ]; then kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

echo "== cluster"
# Always a fresh cluster: a left-over one holds the previous run's certificates.
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --wait 120s
kubectl config use-context "kind-$CLUSTER" >/dev/null
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
sed -e "s#ghcr.io/petersr/spiffex:latest#spiffex:e2e#" \
    -e "s#https://kubernetes.default.svc.cluster.local\$#$K8S_ISSUER#" deploy/kubernetes/issuer.yaml | kubectl apply -f - >/dev/null
kubectl -n spiffex rollout status deploy/spiffex-issuer --timeout=120s

echo "== workloads"
kubectl create namespace shop --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n shop create configmap spiffex-ca --from-file=ca.crt="$WORK/ca.crt" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
workload() { # name audience
  sed -e "s#billing#$1#g" \
      -e "s#audience: spiffex#audience: $2#" \
      -e "s#ghcr.io/petersr/spiffex:latest#spiffex:e2e#" \
      -e "s#image: registry.example.org/$1:1.0#image: spiffex-e2e-client:e2e\n          command: [sleep, \"86400\"]#" \
      deploy/kubernetes/workload.yaml | kubectl apply -f - >/dev/null
}
workload billing spiffex
workload orders spiffex
workload intruder not-spiffex
for w in billing orders intruder; do kubectl -n shop rollout status deploy/$w --timeout=120s; done

app() { local w=$1; shift; kubectl -n shop exec deploy/"$w" -c app -- "$@"; }
check() { # description want got
  if [ "$2" != "$3" ]; then echo "FAIL: $1: got '$3', want '$2'"; exit 1; fi
  echo "ok: $1"
}

echo "== checks"
AUD="spiffe://$TD/ns/shop/sa/orders"
# No retry: the startup probe holds the app back until the agent is ready.
TOKEN=$(app billing /goclient fetch "$AUD")
check "billing's agent validates billing's token as billing" "spiffe://$TD/ns/shop/sa/billing" \
  "$(app billing /goclient validate-agent "$AUD" "$TOKEN")"
check "orders' agent validates billing's token" "spiffe://$TD/ns/shop/sa/billing" \
  "$(app orders /goclient validate-agent "$AUD" "$TOKEN")"
check "the bundle endpoint validates billing's token" "spiffe://$TD/ns/shop/sa/billing" \
  "$(kubectl -n shop exec -i deploy/orders -c app -- sh -c \
      'cat > /tmp/ca.crt && SSL_CERT_FILE=/tmp/ca.crt /goclient validate-bundle "$@"' - \
      "$ISSUER/bundle" "$TD" "$AUD" "$TOKEN" <"$WORK/ca.crt")"
if app orders /goclient validate-agent "spiffe://$TD/ns/shop/sa/elsewhere" "$TOKEN" >/dev/null 2>&1; then
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
  out=$(exchange "$(kubectl -n shop create token billing --audience spiffex --duration "$duration")") && {
    echo "FAIL: a $duration token not bound to a pod was exchanged"; exit 1
  }
  case $out in
    *invalid_request*) echo "ok: a $duration token not bound to a pod is refused" ;;
    *) echo "FAIL: the $duration token failed for another reason: $out"; exit 1 ;;
  esac
done
pod=$(kubectl -n shop get pod -l app=billing -o jsonpath='{.items[0].metadata.name}')
uid=$(kubectl -n shop get pod "$pod" -o jsonpath='{.metadata.uid}')
bound() { kubectl -n shop create token billing --audience spiffex --duration "$1" \
  --bound-object-kind Pod --bound-object-name "$pod" --bound-object-uid "$uid"; }
out=$(exchange "$(bound 48h)") && { echo "FAIL: a 48h pod-bound token was exchanged"; exit 1; }
case $out in
  *invalid_request*) echo "ok: a pod-bound token meant to live 48h is refused" ;;
  *) echo "FAIL: the 48h pod-bound token failed for another reason: $out"; exit 1 ;;
esac
check "a pod-bound token within the lifetime cap is exchanged" ok \
  "$(exchange "$(bound 30m)" >/dev/null && echo ok)"
echo "== all checks passed"

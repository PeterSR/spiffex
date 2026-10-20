#!/usr/bin/env bash
# The single-quoted sh -c scripts below expand their own arguments, in the pod.
# shellcheck disable=SC2016
# End-to-end test of X.509-SVIDs on a kind cluster, with the issuer installed
# by the Helm chart with a certificate authority from a Secret
# (ca.existingSecret). Two workloads, each with an agent sidecar and each
# serving mTLS on port 9443 with go-spiffe, take their identities from the
# issuer's cluster origin (the pod's projected service account token):
#
#  - each reaches the other over mTLS, both ways, and learns the other's SPIFFE
#    ID and which CA signed its certificate;
#  - a pod whose token has the wrong audience gets no X.509-SVID;
#  - an origin removed from the state stops new certificates, and putting it
#    back starts them again;
#  - a CA rotation, done as the chart README says, by replacing the Secret as a
#    whole: a connection opened before it goes on working through the whole
#    rotation, and connections opened after the new CA has taken over use
#    certificates it signed.
#
# The rotation waits for the kubelet to update the mounted Secret and for the
# workloads' certificates (10 minutes, the shortest the issuer allows) to be
# renewed at 40 to 50 percent of their life, so the test takes about six
# minutes.
#
# Needs docker, kind, kubectl, helm, openssl and Go. KEEP=1 leaves the cluster
# up after the run. The run uses a kubeconfig of its own and never reads or
# changes yours.
set -euo pipefail
cd "$(dirname "$0")/../.."
CLUSTER=spiffex-e2e-x509
STATE_CM=spiffex-issuer-state
WORK="$(mktemp -d)"
export KUBECONFIG="$WORK/kubeconfig"
TD=example.org
ISSUER=https://spiffex-issuer.spiffex.svc
ORIGIN_AUD=$ISSUER/origins/cluster
BILLING="spiffe://$TD/cluster/ns/shop/sa/billing"
ORDERS="spiffe://$TD/cluster/ns/shop/sa/orders"

cleanup() {
  if [ -z "${KEEP:-}" ]; then
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
    docker image rm spiffex:e2e spiffex-e2e-client:e2e >/dev/null 2>&1 || true
    rm -rf "$WORK"
  else
    echo "the cluster $CLUSTER is left up; its kubeconfig is $WORK/kubeconfig"
  fi
}
trap cleanup EXIT

check() { # description want got
  if [ "$2" != "$3" ]; then echo "FAIL: $1: got '$3', want '$2'"; exit 1; fi
  echo "ok: $1"
}
eventually() { # seconds command...
  local deadline=$((SECONDS + $1)); shift
  while [ "$SECONDS" -lt "$deadline" ]; do "$@" && return 0; sleep 3; done
  return 1
}

echo "== cluster"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" --wait 120s
K8S_ISSUER=$(kubectl get --raw /.well-known/openid-configuration | sed -n 's/.*"issuer":"\([^"]*\)".*/\1/p')

echo "== images"
docker build -q -t spiffex:e2e . >/dev/null
CGO_ENABLED=0 go build -o "$WORK/goclient" ./conformance/goclient
CGO_ENABLED=0 go build -o "$WORK/spiffex" ./cmd/spiffex
docker build -q -t spiffex-e2e-client:e2e -f test/e2e/Dockerfile "$WORK" >/dev/null
kind load docker-image --name "$CLUSTER" spiffex:e2e spiffex-e2e-client:e2e >/dev/null

echo "== issuer, with a certificate authority"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=spiffex-e2e-ca \
  -keyout "$WORK/ca.key" -out "$WORK/ca.crt" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=spiffex-issuer \
  -keyout "$WORK/tls.key" -out "$WORK/tls.csr" 2>/dev/null
openssl x509 -req -in "$WORK/tls.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" -CAcreateserial -days 1 \
  -extfile <(printf 'subjectAltName=DNS:spiffex-issuer.spiffex.svc') -out "$WORK/tls.crt" 2>/dev/null
mkdir "$WORK/keys" && "$WORK/spiffex" key add -dir "$WORK/keys" >/dev/null
mkdir "$WORK/svid-ca" && "$WORK/spiffex" ca init -dir "$WORK/svid-ca" -trust-domain "$TD" >/dev/null

ca_key_id() { # the subject key identifier of the CA certificate in FILE, as the leaf's authority key identifier
  openssl x509 -in "$1" -noout -ext subjectKeyIdentifier | tail -n 1 | tr -d ' :' | tr 'A-F' 'a-f'
}
apply_ca_secret() {
  kubectl -n spiffex create secret generic spiffex-ca --from-file="$WORK/svid-ca" --dry-run=client -o yaml |
    kubectl apply -f - >/dev/null
}
CA1=$(ca_key_id "$WORK"/svid-ca/ca-*.crt)

kubectl create namespace spiffex --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n spiffex create secret generic spiffex-signing-keys --from-file="$WORK/keys" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n spiffex create secret tls spiffex-issuer-tls --cert="$WORK/tls.crt" --key="$WORK/tls.key" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
apply_ca_secret
cat >"$WORK/values.yaml" <<VALUES
trustDomain: $TD
image: { repository: spiffex, tag: e2e }
signingKeys: { existingSecret: spiffex-signing-keys }
tls: { existingSecret: spiffex-issuer-tls }
ca: { existingSecret: spiffex-ca }
x509SVIDTTL: 10m
activationDelay: 30s
reloadInterval: 5s
state:
  content:
    origins:
      cluster:
        provider: kubernetes
        with:
          issuer: $K8S_ISSUER
          namespaces: [shop]
VALUES
helm install spiffex-issuer charts/spiffex -n spiffex -f "$WORK/values.yaml" >"$WORK/notes.txt"
grep -q "X.509-SVIDs: the issuer has a certificate authority" "$WORK/notes.txt" ||
  { echo "FAIL: the install notes do not mention the certificate authority"; exit 1; }
echo "ok: the install notes mention the certificate authority"
kubectl -n spiffex rollout status deploy/spiffex-issuer --timeout=120s
[ "$(kubectl -n spiffex get deploy/spiffex-issuer -o jsonpath='{.spec.template.spec.volumes[?(@.name=="ca")].secret.defaultMode}')" = 288 ] ||
  { echo "FAIL: the CA Secret is not mounted with mode 0440"; exit 1; }
echo "ok: the CA Secret is mounted with mode 0440"
kubectl -n spiffex exec deploy/spiffex-issuer -- /spiffex ca list -config /config/issuer.yaml >"$WORK/ca-list.txt"
if ! grep -q signing "$WORK/ca-list.txt" || ! grep -q anchor "$WORK/ca-list.txt"; then
  echo "FAIL: ca list does not show a signing CA and its anchor:"; cat "$WORK/ca-list.txt"; exit 1
fi
echo "ok: the issuer has a signing CA and publishes its anchor: $(head -n 3 "$WORK/ca-list.txt" | tr '\n' ' ')"

echo "== workloads"
kubectl create namespace shop --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n shop create configmap spiffex-ca --from-file=ca.crt="$WORK/ca.crt" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
workload() { # name audience command
  sed -e "s#billing#$1#g" \
      -e "s#audience: $ORIGIN_AUD#audience: $2#" \
      -e "s#ghcr.io/petersr/spiffex:v[^ ]*\$#spiffex:e2e#" \
      -e "s#image: registry.example.org/$1:1.0#image: spiffex-e2e-client:e2e\n          command: $3#" \
      deploy/kubernetes/workload.yaml | kubectl apply -f - >/dev/null
}
serve='[/goclient, x509-serve, /tmp/addr, "0.0.0.0:9443"]'
workload billing "$ORIGIN_AUD" "$serve"
workload orders "$ORIGIN_AUD" "$serve"
workload intruder "$ISSUER/origins/elsewhere" '[sleep, "86400"]'
for w in billing orders; do
  kubectl -n shop expose deploy/$w --port 9443 >/dev/null
  kubectl -n shop rollout status deploy/$w --timeout=180s
done
app() { local w=$1; shift; kubectl -n shop exec deploy/"$w" -c app -- "$@"; }
field() { # name line: the value of name= in the line
  printf '%s\n' "$2" | sed -n "s/.*\\(^\\| \\)$1=\\([^ ]*\\).*/\\2/p"
}

echo "== mutual TLS"
# A pod is ready before its app has its first certificate and listens.
dial_when_up() { # from to
  local out
  for _ in $(seq 40); do
    out=$(app "$1" /goclient x509-dial "$2.shop.svc:9443" $TD 2>&1) && { printf '%s\n' "$out"; return 0; }
    sleep 3
  done
  echo "FAIL: $1 cannot reach $2: $out" >&2
  return 1
}
out=$(dial_when_up orders billing)
check "orders reaches billing, which sees orders" "$ORDERS" "$(field client "$out")"
check "orders sees billing's identity" "$BILLING" "$(field server "$out")"
check "billing's certificate was signed by the CA" "$CA1" "$(field server_ca "$out")"
out=$(dial_when_up billing orders)
check "billing reaches orders, which sees billing" "$BILLING" "$(field client "$out")"
check "orders' certificate was signed by the CA" "$CA1" "$(field server_ca "$out")"

kubectl -n shop rollout status deploy/intruder --timeout=120s
out=$(app intruder /goclient x509-fetch /tmp/svid 2>&1) && { echo "FAIL: a pod whose token has the wrong audience got an X.509-SVID"; exit 1; }
case $out in
  *PermissionDenied*) echo "ok: a token with the wrong audience gets no X.509-SVID" ;;
  *) echo "FAIL: the wrong-audience pod failed for another reason: $out"; exit 1 ;;
esac

echo "== a removed origin"
pod=$(kubectl -n shop get pod -l app=billing -o jsonpath='{.items[0].metadata.name}')
uid=$(kubectl -n shop get pod "$pod" -o jsonpath='{.metadata.uid}')
bound() { kubectl -n shop create token billing --audience "$ORIGIN_AUD" --duration 30m \
  --bound-object-kind Pod --bound-object-name "$pod" --bound-object-uid "$uid"; }
x509_exchange() { # a certificate for a new key, with the pod's bound token
  kubectl -n shop exec -i deploy/billing -c app -- sh -c \
    'cat > /tmp/ca.crt && echo "$1" > /tmp/t && rm -f /tmp/k /tmp/c && /spiffex token -issuer "$2" -subject-token-file /tmp/t -ca-file /tmp/ca.crt -x509 -key-out /tmp/k -cert-out /tmp/c' - \
    "$(bound)" "$ISSUER" <"$WORK/ca.crt" 2>&1
}
set_state() { # state.yaml content
  kubectl -n spiffex create configmap "$STATE_CM" --from-literal=state.yaml="$1" --dry-run=client -o yaml |
    kubectl apply -f - >/dev/null 2>&1
}
# Both replicas must have taken up the change, so wait for several answers in a row to agree.
until_x509() { # want: ok or refused
  local streak=0 got
  for _ in $(seq 60); do
    if x509_exchange >/dev/null; then got=ok; else got=refused; fi
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
      issuer: $K8S_ISSUER
      namespaces: [shop]"
until_x509 ok || { echo "FAIL: billing cannot get a certificate with its token"; exit 1; }
echo "ok: billing gets a certificate for a new key with its token"
set_state "origins: {}"
until_x509 refused || { echo "FAIL: removing the origin did not stop new certificates"; exit 1; }
out=$(x509_exchange) && { echo "FAIL: a certificate was issued with the origin removed"; exit 1; }
case $out in
  *invalid_client*|*invalid_request*|*invalid_target*) echo "ok: with the origin removed, no new certificate is issued ($(printf '%s' "$out" | head -n 1))" ;;
  *) echo "FAIL: the refusal does not say why: $out"; exit 1 ;;
esac
set_state "$STATE"
until_x509 ok || { echo "FAIL: putting the origin back did not restore certificates"; exit 1; }
echo "ok: putting the origin back restores certificates"
# The agents refused during the gap may have a refusal cached for a minute.
eventually 120 sh -c '[ "$(kubectl -n shop exec deploy/orders -c app -- /goclient x509-dial billing.shop.svc:9443 '"$TD"' 2>/dev/null | wc -l)" = 1 ]' ||
  { echo "FAIL: the workloads do not talk to each other after the origin came back"; exit 1; }
echo "ok: the workloads still talk to each other"

echo "== a CA rotation"
# One connection from orders to billing, opened now with certificates of the
# first CA, which pings once a second for a long time.
app orders sh -c 'rm -f /tmp/hold.log; /goclient x509-hold billing.shop.svc:9443 '"$TD"' 3000 >/tmp/hold.log 2>&1 &'
held() { app orders cat /tmp/hold.log; }
eventually 30 sh -c 'kubectl -n shop exec deploy/orders -c app -- grep -q " client=" /tmp/hold.log' ||
  { echo "FAIL: the held connection does not work: $(held)"; exit 1; }
check "the held connection was opened with a certificate of the first CA" "$CA1" "$(held | sed -n 's/.*connected server_ca=\([^ ]*\).*/\1/p')"
held >"$WORK/hold.log"
before=$(grep -c ' client=' "$WORK/hold.log")

sleep 1  # CA files are named by the second
"$WORK/spiffex" ca init -dir "$WORK/svid-ca" -trust-domain "$TD" >/dev/null
CA2=
for f in "$WORK"/svid-ca/ca-*.crt; do
  [ "$(ca_key_id "$f")" = "$CA1" ] || CA2=$(ca_key_id "$f")
done
[ -n "$CA2" ] || { echo "FAIL: ca init did not make a second CA"; exit 1; }
apply_ca_secret
echo "the Secret now holds two CAs; waiting for the kubelet, the activation delay and the workloads' renewal"
# A new connection must work at every moment of the rotation, with either chain.
rotated() {
  local out
  out=$(app orders /goclient x509-dial billing.shop.svc:9443 $TD 2>&1) || { echo "FAIL: during the rotation a new connection failed: $out"; exit 1; }
  [ "$(field client "$out")" = "$ORDERS" ] || { echo "FAIL: during the rotation a new connection gave: $out"; exit 1; }
  [ "$(field server_ca "$out")" = "$CA2" ]
}
eventually 900 rotated || { echo "FAIL: after 15 minutes new connections still use the old CA"; kubectl -n spiffex logs deploy/spiffex-issuer | tail -n 20; exit 1; }
echo "ok: new connections use certificates of the new CA, and worked all along"
out=$(app billing /goclient x509-dial orders.shop.svc:9443 $TD)
echo "orders' certificate is signed by $(field server_ca "$out") (the old CA is $CA1, the new one $CA2)"
sleep 4
held >"$WORK/hold.log"
check "the held connection is the one opened before, not a new one" 1 "$(grep -c ' connected ' "$WORK/hold.log")"
after=$(grep -c ' client=' "$WORK/hold.log")
if grep -q '^goclient:' "$WORK/hold.log"; then echo "FAIL: the held connection broke: $(tail -n 3 "$WORK/hold.log")"; exit 1; fi
[ "$after" -gt "$before" ] || { echo "FAIL: the held connection stopped answering ($before, then $after answers)"; exit 1; }
# More answers now than before the rotation, on the one connection (a single "connected" line, no
# error line), mean its process lived and exchanged data after the rotation.
echo "ok: the connection opened before the rotation answered $after times and was never dropped"
check "the held connection still sees orders" "$ORDERS" "$(field client "$(tail -n 1 "$WORK/hold.log")")"
echo "== all checks passed"

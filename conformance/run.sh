#!/usr/bin/env bash
# The conformance matrix. A JWT-SVID obtained through each stock client
# (go-spiffe and py-spiffe over the Workload API, plain OAuth 2.0 without an
# agent, with one audience and with two) must verify through each
# verification path (go-spiffe and py-spiffe through an agent and against a
# JWT source's bundle, go-spiffe against the SPIFFE bundle endpoint, PyJWT
# against OIDC discovery), and each verifier must refuse it for an audience it
# was not issued for. The matrix runs twice: an issuer signing with ES256 that
# also publishes a second, not yet active RS256 key, and one signing with RS256.
#
# Then the X.509 matrix, against an issuer with a certificate authority. An
# X.509-SVID obtained each way (go-spiffe and py-spiffe over the Workload API,
# "spiffex token -x509", and a CSR for a P-384, Ed25519 or RSA-2048 key, which
# only the issuer client can ask for) is presented to each verifier (go-spiffe
# chain verification, and mTLS handshakes with go-spiffe and with Python's ssl
# module, each as the server that verifies a client and as the client that
# verifies a server). Each verifier must also refuse an SVID of a second issuer
# in another trust domain. A verifier that trusts only the first issuer's CA
# refuses it by chain verification; a variant that trusts both CAs and
# authorizes only the first trust domain refuses it by the check of the SPIFFE
# ID alone. A server must refuse a client that sends no certificate.
#
# Needs Go, uv and openssl.
set -euo pipefail
cd "$(dirname "$0")"
REPO="$(cd .. && pwd)"
WORK="$(mktemp -d)"   # short, so socket paths stay under the Unix limit
PORT="${SPIFFEX_CONFORMANCE_PORT:-18443}"
PORT_B=$((PORT + 1))
ISSUER="http://127.0.0.1:$PORT"
ISSUER_B="http://127.0.0.1:$PORT_B"
TD=spiffex.test
TD_B=spiffex.test2   # shares the first domain's name as a prefix, so a check without the "/" fails
AUD="spiffe://$TD/dev/orders"
WANT="spiffe://$TD/dev/billing"

pids=()
stop() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  pids=()
}
trap 'stop; rm -rf "$WORK"' EXIT

echo "== building"
(cd "$REPO" && go build -o "$WORK/spiffex" ./cmd/spiffex && go build -o "$WORK/goclient" ./conformance/goclient &&
  go build -o "$WORK/goissue" ./conformance/goissue)
(cd python && uv sync --quiet --locked)

as() { local w=$1; shift; SPIFFE_ENDPOINT_SOCKET="unix://$WORK/$w.sock" "$@"; }
py() { uv run --quiet --frozen --project "$REPO/conformance/python" python "$REPO/conformance/python/client.py" "$@"; }
until_ok() { # what command...
  local what=$1; shift
  for _ in $(seq 100); do "$@" >/dev/null 2>&1 && return 0; sleep 0.1; done
  echo "timed out waiting for $what"; exit 1
}

start() { # algorithm
  local td="$WORK/td-$1"
  "$WORK/spiffex" dev -dir "$td" -trust-domain "$TD" -listen "127.0.0.1:$PORT" -alg "$1" >/dev/null
  if [ "$1" = ES256 ]; then
    # A second key, published but not yet signing: verifiers must pick by kid.
    sleep 1   # key files are named by the second
    "$WORK/spiffex" key add -dir "$td/keys" -alg RS256 >/dev/null
  fi
  "$WORK/spiffex" issuer -config "$td/issuer.yaml" -listen "127.0.0.1:$PORT" -log-level warn &
  pids+=($!)
  until_ok "the issuer" curl -fs "$ISSUER/healthz"
  for w in orders billing; do
    "$WORK/spiffex" agent -issuer "$ISSUER" -client-id "dev/$w" -key-file "$td/workloads/$w.key" \
      -socket "$WORK/$w.sock" -log-level warn &
    pids+=($!)
  done
  # Ready means the agent issues tokens and has a bundle to validate them.
  for w in orders billing; do
    until_ok "the $w agent" sh -c "t=\$(SPIFFE_ENDPOINT_SOCKET=unix://$WORK/$w.sock $WORK/goclient fetch x) &&
      SPIFFE_ENDPOINT_SOCKET=unix://$WORK/$w.sock $WORK/goclient validate-agent x \$t"
  done
  TOKEN_KEYS="$td/workloads"
}

fetch() {
  case $1 in
    go-spiffe) as billing "$WORK/goclient" fetch "$AUD" ;;
    py-spiffe) as billing py fetch "$AUD" ;;
    oauth) "$WORK/spiffex" token -issuer "$ISSUER" -client-id dev/billing -key-file "$TOKEN_KEYS/billing.key" -audience "$AUD" ;;
    oauth-2-audiences) "$WORK/spiffex" token -issuer "$ISSUER" -client-id dev/billing -key-file "$TOKEN_KEYS/billing.key" \
      -audience "spiffe://$TD/dev/inventory" -audience "$AUD" ;;
  esac
}

verify() { # verifier audience token
  case $1 in
    go-spiffe-agent) as orders "$WORK/goclient" validate-agent "$2" "$3" ;;
    go-spiffe-source) as orders "$WORK/goclient" validate-source "$2" "$3" ;;
    py-spiffe-agent) as orders py validate-agent "$2" "$3" ;;
    py-spiffe-source) as orders py validate-source "$2" "$3" ;;
    go-spiffe-bundle) "$WORK/goclient" validate-bundle "$ISSUER/bundle" "$TD" "$2" "$3" ;;
    pyjwt-oidc) py validate-oidc "$ISSUER" "$2" "$3" ;;
  esac
}

clients=(go-spiffe py-spiffe oauth oauth-2-audiences)
verifiers=(go-spiffe-agent go-spiffe-source py-spiffe-agent py-spiffe-source go-spiffe-bundle pyjwt-oidc)
failures=0
pairs=0
for alg in ES256 RS256; do
  echo "== matrix, issuer signing with $alg"
  start "$alg"
  for c in "${clients[@]}"; do
    token=$(fetch "$c")
    for v in "${verifiers[@]}"; do
      pairs=$((pairs + 1))
      printf "%-17s -> %-17s " "$c" "$v"
      got=$(verify "$v" "$AUD" "$token" 2>&1) || true
      if [ "$got" != "$WANT" ]; then
        echo "FAIL: got $got"
        failures=$((failures + 1))
        continue
      fi
      code=0
      verify "$v" "spiffe://$TD/dev/elsewhere" "$token" >/dev/null 2>&1 || code=$?
      if [ "$code" != 3 ]; then
        echo "FAIL: the wrong audience gave exit code $code, want 3 (refused)"
        failures=$((failures + 1))
        continue
      fi
      echo "ok"
    done
  done
  stop
done


# ---- X.509 ----------------------------------------------------------------

PYBIN="$REPO/conformance/python/.venv/bin/python"
ADDRFILE="$WORK/addr"
BUNDLE_A="$WORK/bundle-a.pem"
BUNDLE_AB="$WORK/bundle-ab.pem"   # both CAs in one file, for Python
BUNDLE_GO_AB="$BUNDLE_A,$TD_B=$WORK/bundle-b.pem"   # one bundle per domain, for go-spiffe

start_ca_issuer() { # dir trust-domain port
  "$WORK/spiffex" dev -dir "$1" -trust-domain "$2" -listen "127.0.0.1:$3" >/dev/null
  "$WORK/spiffex" ca init -dir "$1/ca" -trust-domain "$2" >/dev/null
  printf 'ca_dir: ca\n' >>"$1/issuer.yaml"
  # Audit lines are logged whatever the level, and would fill the matrix's output.
  "$WORK/spiffex" issuer -config "$1/issuer.yaml" -listen "127.0.0.1:$3" -log-level warn 2>"$1/issuer.log" &
  pids+=($!)
  until_ok "the issuer of $2" curl -fs "http://127.0.0.1:$3/healthz"
}

start_agent() { # dir issuer workload socket-name
  "$WORK/spiffex" agent -issuer "$2" -client-id "dev/$3" -key-file "$1/workloads/$3.key" \
    -socket "$WORK/$4.sock" -log-level warn &
  pids+=($!)
  until_ok "the $4 agent" as "$4" "$WORK/goclient" x509-fetch "$WORK/ready-$4"
}

# cert_id DIR: the SPIFFE ID in the URI SAN of the leaf in DIR, read from the
# certificate and not from what a producer reports.
cert_id() {
  openssl x509 -in "$1/chain.pem" -noout -ext subjectAltName | sed -n 's/.*URI://p'
}

# produce PRODUCER DOMAIN DIR: a key and a certificate chain of the billing
# workload in DIR, from trust domain A or B.
produce() {
  local producer=$1 dir=$3 issuer=$ISSUER keys="$WORK/td-a/workloads" td=$TD sock=billing
  if [ "$2" = B ]; then issuer=$ISSUER_B keys="$WORK/td-b/workloads" td=$TD_B sock=foreign; fi
  mkdir -p "$dir"
  case $producer in
    go-spiffe) as "$sock" "$WORK/goclient" x509-fetch "$dir" ;;
    py-spiffe) as "$sock" py x509-fetch "$dir" ;;
    token-x509) "$WORK/spiffex" token -issuer "$issuer" -client-id dev/billing -key-file "$keys/billing.key" \
      -x509 -key-out "$dir/key.pem" -cert-out "$dir/chain.pem" >/dev/null ;;
    issue-p384) "$WORK/goissue" P-384 "$issuer" "$td" dev/billing "$keys/billing.key" "$dir" ;;
    issue-ed25519) "$WORK/goissue" Ed25519 "$issuer" "$td" dev/billing "$keys/billing.key" "$dir" ;;
    issue-rsa2048) "$WORK/goissue" RSA-2048 "$issuer" "$td" dev/billing "$keys/billing.key" "$dir" ;;
  esac
}

# leaf_key PRODUCER: what the leaf's public key should be, as openssl prints it.
leaf_key() {
  case $1 in
    issue-p384) echo secp384r1 ;;
    issue-ed25519) echo ED25519 ;;
    issue-rsa2048) echo "Public-Key: (2048 bit)" ;;
    *) echo prime256v1 ;;
  esac
}

key_label() {
  case $1 in
    issue-p384) echo P-384 ;;
    issue-ed25519) echo Ed25519 ;;
    issue-rsa2048) echo RSA-2048 ;;
    *) echo P-256 ;;
  esac
}

# tls_pair FIELD SERVER-COMMAND... -- DIAL-COMMAND...: runs the server, waits
# for it to listen, dials it (@ADDR@ in the dial command is the address) and
# prints the field (server or client) of the answer. A refusal is exit status
# 3, as the clients give it. It fails with 1 if the server did not survive.
tls_pair() {
  local field=$1 server=() dial=() code=0 out alive=0
  shift
  while [ "$1" != -- ]; do server+=("$1"); shift; done
  shift
  dial=("$@")
  rm -f "$ADDRFILE" "$ADDRFILE.tmp"
  "${server[@]}" 2>"$WORK/server.log" &
  local spid=$!
  if ! until_ok "the TLS server" test -s "$ADDRFILE"; then kill "$spid" 2>/dev/null; return 1; fi
  local addr
  addr=$(cat "$ADDRFILE")
  for i in "${!dial[@]}"; do dial[i]=${dial[i]//@ADDR@/$addr}; done
  out=$("${dial[@]}" 2>"$WORK/dial.log") || code=$?
  if kill -0 "$spid" 2>/dev/null; then alive=1; fi
  kill "$spid" 2>/dev/null || true
  wait "$spid" 2>/dev/null || true
  if [ "$alive" != 1 ]; then echo "the server died: $(tail -n 3 "$WORK/server.log")"; return 1; fi
  if [ "$code" != 0 ]; then
    cat "$WORK/dial.log" >&2
    return "$code"
  fi
  # The answer is "server=ID client=ID" and perhaps more words.
  echo "$out" | sed -n "s/.*\(^\| \)$field=\([^ ]*\).*/\2/p"
}

# verify_x509 VERIFIER DIR [anon]: the SPIFFE ID of the SVID in DIR, as the
# verifier itself read it, if the verifier accepts it; exit status 3 if it
# refuses it. With "anon" a TLS client sends no certificate (and DIR is not
# used), which only a server can refuse. The -ab verifiers trust the CAs of
# both trust domains and authorize only trust domain A, so only that check can
# refuse an SVID of trust domain B; the others trust A's CA alone.
verify_x509() {
  local v=$1 d=$2 key chain
  key="$d/key.pem" chain="$d/chain.pem"
  local osock="SPIFFE_ENDPOINT_SOCKET=unix://$WORK/orders.sock"
  local okey="$WORK/svid-orders/key.pem" ochain="$WORK/svid-orders/chain.pem" py="$REPO/conformance/python/client.py"
  local peer=("$WORK/goclient" x509-dial-files @ADDR@ "$key" "$chain" "$BUNDLE_A" "$TD")
  if [ "${3:-}" = anon ]; then peer=("$WORK/goclient" x509-dial-anon @ADDR@ "$BUNDLE_A" "$TD"); fi
  case $v in
    go-spiffe-verify) as orders "$WORK/goclient" x509-verify "$chain" ;;
    go-spiffe-tls-server) tls_pair client env "$osock" "$WORK/goclient" x509-serve "$ADDRFILE" -- "${peer[@]}" ;;
    go-spiffe-tls-server-ab) tls_pair client "$WORK/goclient" x509-serve-files "$ADDRFILE" "$okey" "$ochain" "$BUNDLE_GO_AB" "$TD" -- "${peer[@]}" ;;
    ssl-tls-server) tls_pair client env "$osock" "$PYBIN" "$py" x509-serve "$ADDRFILE" -- "${peer[@]}" ;;
    ssl-tls-server-ab) tls_pair client env "$osock" "$PYBIN" "$py" x509-serve "$ADDRFILE" "$BUNDLE_AB" -- "${peer[@]}" ;;
    go-spiffe-tls-client) tls_pair peer "$WORK/goclient" x509-serve-files "$ADDRFILE" "$key" "$chain" "$BUNDLE_A" "$TD" -- \
      env "$osock" "$WORK/goclient" x509-dial @ADDR@ "$TD" ;;
    go-spiffe-tls-client-ab) tls_pair peer "$WORK/goclient" x509-serve-files "$ADDRFILE" "$key" "$chain" "$BUNDLE_A" "$TD" -- \
      "$WORK/goclient" x509-dial-files @ADDR@ "$okey" "$ochain" "$BUNDLE_GO_AB" "$TD" ;;
    ssl-tls-client) tls_pair peer "$WORK/goclient" x509-serve-files "$ADDRFILE" "$key" "$chain" "$BUNDLE_A" "$TD" -- \
      env "$osock" "$PYBIN" "$py" x509-dial @ADDR@ "$TD" ;;
    ssl-tls-client-ab) tls_pair peer "$WORK/goclient" x509-serve-files "$ADDRFILE" "$key" "$chain" "$BUNDLE_A" "$TD" -- \
      env "$osock" "$PYBIN" "$py" x509-dial @ADDR@ "$TD" "$BUNDLE_AB" ;;
  esac
}

x509_producers=(go-spiffe py-spiffe token-x509 issue-p384 issue-ed25519 issue-rsa2048)
x509_verifiers=(go-spiffe-verify go-spiffe-tls-server go-spiffe-tls-client ssl-tls-server ssl-tls-client
  go-spiffe-tls-server-ab go-spiffe-tls-client-ab ssl-tls-server-ab ssl-tls-client-ab)
x509_failures_before=$failures
echo "== X.509 matrix, two issuers with certificate authorities, trust domains $TD and $TD_B"
td_a="$WORK/td-a"
td_b="$WORK/td-b"
start_ca_issuer "$td_a" "$TD" "$PORT"
start_ca_issuer "$td_b" "$TD_B" "$PORT_B"
start_agent "$td_a" "$ISSUER" orders orders
start_agent "$td_a" "$ISSUER" billing billing
start_agent "$td_b" "$ISSUER_B" billing foreign
as billing "$WORK/goclient" x509-bundle "$BUNDLE_A"
as foreign "$WORK/goclient" x509-bundle "$WORK/bundle-b.pem"
cat "$BUNDLE_A" "$WORK/bundle-b.pem" >"$BUNDLE_AB"
as orders "$WORK/goclient" x509-fetch "$WORK/svid-orders" >/dev/null

for domain in A B; do
  for p in "${x509_producers[@]}"; do
    dir="$WORK/svid-$domain-$p"
    out=$(produce "$p" "$domain" "$dir" 2>&1) || { echo "FAIL: $p could not get an X.509-SVID from $domain: $out"; exit 1; }
    want=$(leaf_key "$p")
    if ! openssl x509 -in "$dir/chain.pem" -noout -text | grep -qF "$want"; then
      echo "FAIL: the leaf $p got from $domain is not a $want key"; exit 1
    fi
    td=$TD; if [ "$domain" = B ]; then td=$TD_B; fi
    id=$(cert_id "$dir")
    if [ "$id" != "spiffe://$td/dev/billing" ]; then echo "FAIL: the certificate $p got from $domain names $id"; exit 1; fi
  done
done

# A server must refuse a client that sends no certificate.
for v in "${x509_verifiers[@]}"; do
  case $v in
    *tls-server*)
      pairs=$((pairs + 1))
      printf "%-28s %-26s " "no client certificate" "-> $v"
      code=0
      verify_x509 "$v" "" anon >/dev/null 2>"$WORK/verdict.log" || code=$?
      if [ "$code" != 3 ]; then
        echo "FAIL: the exit code is $code, want 3"
        failures=$((failures + 1))
        continue
      fi
      if ! grep -q "refused:" "$WORK/server.log"; then
        echo "FAIL: the server log has no refusal: $(tail -n 2 "$WORK/server.log")"
        failures=$((failures + 1))
        continue
      fi
      echo "ok" ;;
  esac
done

for p in "${x509_producers[@]}"; do
  for v in "${x509_verifiers[@]}"; do
    pairs=$((pairs + 1))
    printf "%-14s %-13s -> %-24s " "$p" "$(key_label "$p")" "$v"
    got=$(verify_x509 "$v" "$WORK/svid-A-$p" 2>&1) || true
    if [ "$got" != "$WANT" ]; then
      echo "FAIL: got $got"
      failures=$((failures + 1))
      continue
    fi
    code=0
    verify_x509 "$v" "$WORK/svid-B-$p" >/dev/null 2>"$WORK/verdict.log" || code=$?
    if [ "$code" != 3 ]; then
      echo "FAIL: the SVID of another trust domain gave exit code $code, want 3 (refused)"
      failures=$((failures + 1))
      continue
    fi
    # What the verifier says it refused for: a refusal of its own, not a timeout.
    case $v in
      *tls-server*)
        if ! grep -q "refused:" "$WORK/server.log"; then
          echo "FAIL: the server did not log a refusal of the other trust domain's SVID: $(tail -n 2 "$WORK/server.log")"
          failures=$((failures + 1))
          continue
        fi ;;
    esac
    case $v in
      *-ab)
        if ! cat "$WORK/server.log" "$WORK/verdict.log" | grep -Eq "(unexpected trust domain|not one SPIFFE ID)"; then
          echo "FAIL: the trust domain check did not refuse it: $(tail -n 2 "$WORK/server.log" "$WORK/verdict.log")"
          failures=$((failures + 1))
          continue
        fi ;;
    esac
    echo "ok"
  done
done
stop
if [ "$failures" -gt "$x509_failures_before" ]; then
  echo "== $((failures - x509_failures_before)) X.509 pairs failed"
fi

if [ "$failures" -gt 0 ]; then
  echo "== $failures of $pairs pairs failed"
  exit 1
fi
echo "== all $pairs pairs verified, and every verifier refused the wrong audience or the other trust domain"

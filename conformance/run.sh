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
# Needs Go and uv.
set -euo pipefail
cd "$(dirname "$0")"
REPO="$(cd .. && pwd)"
WORK="$(mktemp -d)"   # short, so socket paths stay under the Unix limit
PORT="${SPIFFEX_CONFORMANCE_PORT:-18443}"
ISSUER="http://127.0.0.1:$PORT"
TD=spiffex.test
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
(cd "$REPO" && go build -o "$WORK/spiffex" ./cmd/spiffex && go build -o "$WORK/goclient" ./conformance/goclient)
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

if [ "$failures" -gt 0 ]; then
  echo "== $failures of $pairs pairs failed"
  exit 1
fi
echo "== all $pairs pairs verified, and every verifier refused the wrong audience"

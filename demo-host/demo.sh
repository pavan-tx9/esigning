#!/usr/bin/env bash
#
# Bring the whole thing up for a human: database, migrations, development PKI, a registered host,
# the sample templates, the API, the worker, the built signing UI and the stand-in EHR. Then print
# where to click and stay in the foreground until Ctrl-C.
#
# Everything it does is safe to repeat. The host registration is kept in .demo/env and reused for
# as long as its API key still works, because `esign hosts create` prints the key exactly once.
#
# Environment:
#   ESIGN_API_PORT   (8000)   the API and the signing UI
#   DEMO_HOST_PORT   (8100)   the stand-in EHR
#   DEMO_SKIP_BUILD  (unset)  do not rebuild the signing UI even if it looks stale
#   DEMO_QUIET       (unset)  no banner; used by the end-to-end runner

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

API_PORT="${ESIGN_API_PORT:-8000}"
DEMO_PORT="${DEMO_HOST_PORT:-8100}"
API_URL="http://localhost:${API_PORT}"
DEMO_URL="http://localhost:${DEMO_PORT}"

RUN_DIR="$ROOT/.demo"
LOG_DIR="$RUN_DIR/logs"
STATE="$RUN_DIR/env"
mkdir -p "$LOG_DIR"

BOLD=$'\033[1m'; DIM=$'\033[2m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
step() { printf '%s==>%s %s\n' "$CYAN" "$RESET" "$*"; }
fail() { printf '\n%sdemo: %s%s\n' "$BOLD" "$*" "$RESET" >&2; exit 1; }

pids=()
cleanup() {
  trap - EXIT INT TERM
  for pid in "${pids[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait_for() {  # wait_for <url> <seconds> <what>
  local url="$1" limit="$2" what="$3" waited=0
  until curl -fsS -o /dev/null "$url" 2>/dev/null; do
    waited=$((waited + 1))
    if [ "$waited" -ge "$limit" ]; then
      fail "$what did not come up. Its log is in ${LOG_DIR#"$ROOT"/}."
    fi
    sleep 1
  done
}

# ------------------------------------------------------------------ 1. database
step "starting Postgres on 54329"
docker compose up -d db >/dev/null
for _ in $(seq 1 60); do
  docker compose exec -T db pg_isready -U esign_owner -d esign >/dev/null 2>&1 && break
  sleep 1
done
docker compose exec -T db pg_isready -U esign_owner -d esign >/dev/null 2>&1 ||
  fail "Postgres never became ready. Try 'make up' on its own to see why."

step "applying migrations"
uv --directory backend run python -m esign.migrate >"$LOG_DIR/migrate.log" 2>&1 ||
  fail "migrations failed; see ${LOG_DIR#"$ROOT"/}/migrate.log"

# ------------------------------------------------------------------ 2. keys and disclosure
if [ ! -f "$ROOT/.dev-pki/trust-roots.pem" ]; then
  step "generating the development PKI (never for production)"
  uv --directory backend run esign dev-pki >"$LOG_DIR/dev-pki.log" 2>&1 ||
    fail "could not generate the development PKI; see ${LOG_DIR#"$ROOT"/}/dev-pki.log"
fi

step "seeding the ESIGN disclosure"
uv --directory backend run esign consent add --default >"$LOG_DIR/consent.log" 2>&1 ||
  fail "could not seed the disclosure; see ${LOG_DIR#"$ROOT"/}/consent.log"

# ------------------------------------------------------------------ 3. the signing UI
DIST="$ROOT/frontend/dist/index.html"
if [ -z "${DEMO_SKIP_BUILD:-}" ]; then
  if [ ! -f "$DIST" ] || [ -n "$(find "$ROOT/frontend/src" "$ROOT/frontend/index.html" -newer "$DIST" -print -quit)" ]; then
    step "building the signing UI"
    (cd frontend && bun install >/dev/null 2>&1 && bun run build) >"$LOG_DIR/build.log" 2>&1 ||
      fail "the signing UI did not build; see ${LOG_DIR#"$ROOT"/}/build.log"
  else
    step "signing UI is already built"
  fi
fi

# ------------------------------------------------------------------ 4. the API
step "starting the API on ${API_PORT}"
# `esign serve` rather than uvicorn directly: it drops uvicorn's log config, so its own loggers
# propagate to the allowlisted structured handler instead of writing straight to stdout.
(
  cd backend
  exec uv run esign serve --host 127.0.0.1 --port "$API_PORT"
) >"$LOG_DIR/api.log" 2>&1 &
pids+=($!)
wait_for "$API_URL/healthz" 60 "the API"

# ------------------------------------------------------------------ 5. the host registration
register_host() {
  step "registering the demo host"
  local output
  output="$(uv --directory backend run esign hosts create \
    --name "Riverside Clinic (demo)" \
    --origin "$DEMO_URL" \
    --webhook-url "$DEMO_URL/webhooks/esign" 2>"$LOG_DIR/hosts.log")" ||
    fail "could not register the host; see ${LOG_DIR#"$ROOT"/}/hosts.log"
  {
    echo "DEMO_ESIGN_HOST_ID=$(awk '/^host id:/ {print $3}' <<<"$output")"
    echo "DEMO_ESIGN_API_KEY=$(awk '/^api key:/ {print $3}' <<<"$output")"
    echo "DEMO_ESIGN_WEBHOOK_SECRET=$(awk '/^webhook secret:/ {print $3}' <<<"$output")"
  } >"$STATE"
  chmod 600 "$STATE"
}

key_works() {
  [ -f "$STATE" ] || return 1
  # shellcheck disable=SC1090
  set -a; source "$STATE"; set +a
  [ -n "${DEMO_ESIGN_API_KEY:-}" ] || return 1
  [ "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $DEMO_ESIGN_API_KEY" "$API_URL/v1/templates")" = "200" ]
}

if key_works; then
  step "reusing the host registration in ${STATE#"$ROOT"/}"
else
  register_host
  set -a; source "$STATE"; set +a
fi

# ------------------------------------------------------------------ 6. the sample templates
published="$(curl -s -H "Authorization: Bearer $DEMO_ESIGN_API_KEY" "$API_URL/v1/templates")"
missing=0
for key in hipaa_acknowledgement patient_consent procedure_consent; do
  grep -q "\"$key\"" <<<"$published" || missing=1
done
if [ "$missing" = "1" ]; then
  step "importing the sample templates"
  uv --directory backend run esign templates import --host "$DEMO_ESIGN_HOST_ID" \
    >"$LOG_DIR/templates.log" 2>&1 ||
    fail "the templates would not import; see ${LOG_DIR#"$ROOT"/}/templates.log.
If it says 'blob_missing', the database has rows for blobs whose files are gone: 'make clean-db'
gives you a clean start."
else
  step "sample templates are already published"
fi

# ------------------------------------------------------------------ 7. the worker
step "starting the worker (sealing, expiry sweeps, webhooks)"
(
  cd backend
  exec uv run esign worker
) >"$LOG_DIR/worker.log" 2>&1 &
pids+=($!)

# ------------------------------------------------------------------ 8. the stand-in EHR
step "starting the demo host on ${DEMO_PORT}"
(
  cd demo-host
  export DEMO_ESIGN_API_URL="$API_URL"
  export DEMO_ESIGN_UI_URL="$API_URL"
  export DEMO_PUBLIC_URL="$DEMO_URL"
  export DEMO_HOST_PORT="$DEMO_PORT"
  exec uv run python -m demo_host
) >"$LOG_DIR/demo-host.log" 2>&1 &
pids+=($!)
wait_for "$DEMO_URL/healthz" 60 "the demo host"

# ------------------------------------------------------------------ ready
if [ -z "${DEMO_QUIET:-}" ]; then
  cat <<BANNER

  ${BOLD}The demo is up.${RESET}

  ${BOLD}Open ${DEMO_URL}${RESET}

  Sign in as any of these. The password is ${BOLD}${DEMO_PASSWORD:-demo1234}${RESET} for all of them.

    ${BOLD}maria${RESET}   a patient. Has a privacy acknowledgement to sign, and a procedure
              consent that also needs a witness and a clinician.
    ${BOLD}grace${RESET}   a parent, signing a consent to treatment on behalf of her child.
    ${BOLD}ben${RESET}     the witness on the procedure consent. His turn comes after Maria's.
    ${BOLD}priya${RESET}   the clinician on it. Signing in a professional capacity, so she is asked
              for her password again before the signature is taken.
    ${BOLD}tomas${RESET}   the other clinician. Can open a chart and re-verify anything in it.
    ${BOLD}alice${RESET}   the front desk. Starts the clinic tablet from "Clinic tablet".

  ${DIM}Worth watching: the Webhooks page, which shows each delivery and whether its signature
  checked out, and any document in a chart, which has a button that re-verifies the seal, every
  stored hash and the whole audit chain on the spot.${RESET}

  ${DIM}API ${API_URL}  ·  logs in ${LOG_DIR#"$ROOT"/}  ·  Ctrl-C stops everything${RESET}

BANNER
fi

wait

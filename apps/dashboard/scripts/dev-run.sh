#!/usr/bin/env bash
# Runs the dashboard locally with DEVELOPMENT settings: http://localhost:3000,
# the Docker Compose PostgreSQL (database `dashboard`), and the local Vault
# and app API as spiffe://jarvis.local/dashboard-api (its certificate comes
# from the Vault's development CA).
#
# Every DASHBOARD_* variable can be overridden from the environment, e.g.
# DASHBOARD_ORIGIN=https://<mac>.<tailnet>.ts.net:8444 behind Tailscale Serve.
# DASHBOARD_MODE=start serves a production build (`next build` first).
set -euo pipefail

cd "$(dirname "$0")/.."
VAULT_CERTS=../../services/vault/.dev/certs
CERTS=.dev/certs
[[ -f $VAULT_CERTS/dashboard-api.pem ]] || {
  echo "The Vault's development certificates are missing; start the Vault once: pnpm nx run vault:serve" >&2
  exit 1
}
# (Re)copy the identity when missing or from an older development CA.
if [[ ! -f $CERTS/dashboard-api.pem ]] || ! cmp -s "$VAULT_CERTS/ca.pem" "$CERTS/ca.pem"; then
  mkdir -p "$CERTS"
  chmod 700 .dev "$CERTS"
  cp "$VAULT_CERTS/ca.pem" "$VAULT_CERTS/dashboard-api.pem" "$VAULT_CERTS/dashboard-api-key.pem" "$CERTS/"
  chmod 600 "$CERTS/dashboard-api-key.pem"
fi

COMPOSE_ENV=../../deploy/compose/.env
# Read single keys; never `source` the file.
compose_setting() { { grep -E "^$1=" "$COMPOSE_ENV" || true; } | tail -n1 | cut -d= -f2-; }
if [[ -z ${DASHBOARD_DATABASE_URL:-} && -z ${DASHBOARD_DATABASE_URL_FILE:-} ]]; then
  [[ -f $COMPOSE_ENV ]] || {
    echo "deploy/compose/.env not found. Start the infrastructure first: pnpm nx run infra:up" >&2
    exit 1
  }
  db_password=$(compose_setting DASHBOARD_DB_PASSWORD)
  [[ -n $db_password ]] || {
    echo "DASHBOARD_DB_PASSWORD missing from deploy/compose/.env; run: pnpm nx run infra:up" >&2
    exit 1
  }
  db_port=$(compose_setting JARVIS_POSTGRES_PORT)
  export DASHBOARD_DATABASE_URL="postgres://dashboard:${db_password}@127.0.0.1:${db_port:-55432}/dashboard"
fi

export DASHBOARD_ORIGIN="${DASHBOARD_ORIGIN:-http://localhost:3000}"
export DASHBOARD_TLS_CA="${DASHBOARD_TLS_CA:-$CERTS/ca.pem}"
export DASHBOARD_TLS_CERT="${DASHBOARD_TLS_CERT:-$CERTS/dashboard-api.pem}"
export DASHBOARD_TLS_KEY="${DASHBOARD_TLS_KEY:-$CERTS/dashboard-api-key.pem}"
export DASHBOARD_VAULT_ADDR="${DASHBOARD_VAULT_ADDR:-127.0.0.1:50051}"
export DASHBOARD_APP_ADMIN_ADDR="${DASHBOARD_APP_ADMIN_ADDR:-127.0.0.1:50055}"
export NEXT_TELEMETRY_DISABLED=1
# The WebAuthn library probes experimental Web Crypto APIs; not our warnings.
export NODE_OPTIONS="${NODE_OPTIONS:-} --disable-warning=ExperimentalWarning"

port=${DASHBOARD_PORT:-3000}
if [[ ${DASHBOARD_MODE:-dev} == start ]]; then
  exec pnpm exec next start --hostname localhost --port "$port"
fi
exec pnpm exec next dev --hostname localhost --port "$port"

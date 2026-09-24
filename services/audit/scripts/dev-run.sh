#!/usr/bin/env bash
# Runs the audit service locally with DEVELOPMENT settings against the Docker
# Compose PostgreSQL (`pnpm nx run infra:up`, database `audit`) and the
# Vault's development CA (`pnpm nx run vault:serve` once).
#
# Every AUDIT_* variable can be overridden from the environment; AUDIT_BIN
# runs a prebuilt binary instead of `go run`.
set -euo pipefail

cd "$(dirname "$0")/.."
VAULT_CERTS=../vault/.dev/certs
# (Re)issue certificates when missing or signed by an older development CA.
if [[ ! -f .dev/certs/server.pem ]] || ! openssl verify -CAfile "$VAULT_CERTS/ca.pem" .dev/certs/server.pem >/dev/null 2>&1; then
  scripts/dev-certs.sh "$VAULT_CERTS" .dev/certs
fi

COMPOSE_ENV=../../deploy/compose/.env
# Read single keys; never `source` the file.
compose_setting() { { grep -E "^$1=" "$COMPOSE_ENV" || true; } | tail -n1 | cut -d= -f2-; }
if [[ -z ${AUDIT_DATABASE_URL:-} && -z ${AUDIT_DATABASE_URL_FILE:-} ]]; then
  [[ -f $COMPOSE_ENV ]] || {
    echo "deploy/compose/.env not found. Start the infrastructure first: pnpm nx run infra:up" >&2
    exit 1
  }
  db_password=$(compose_setting AUDIT_DB_PASSWORD)
  [[ -n $db_password ]] || { echo "AUDIT_DB_PASSWORD missing from deploy/compose/.env; run: pnpm nx run infra:up" >&2; exit 1; }
  db_port=$(compose_setting JARVIS_POSTGRES_PORT)
  export AUDIT_DATABASE_URL="postgres://audit:${db_password}@127.0.0.1:${db_port:-55432}/audit"
fi

export AUDIT_LISTEN_ADDR="${AUDIT_LISTEN_ADDR:-127.0.0.1:50056}"
export AUDIT_METRICS_ADDR="${AUDIT_METRICS_ADDR:-127.0.0.1:9097}"
export AUDIT_TLS_CERT="${AUDIT_TLS_CERT:-.dev/certs/server.pem}"
export AUDIT_TLS_KEY="${AUDIT_TLS_KEY:-.dev/certs/server-key.pem}"
export AUDIT_TLS_CLIENT_CA="${AUDIT_TLS_CLIENT_CA:-.dev/certs/ca.pem}"
export AUDIT_AUTHZ_POLICY="${AUDIT_AUTHZ_POLICY:-config/authz.dev.toml}"
export AUDIT_REFLECTION="${AUDIT_REFLECTION:-true}"
export AUDIT_LOG_FORMAT="${AUDIT_LOG_FORMAT:-text}"

exec ${AUDIT_BIN:-go run ./cmd/audit}

#!/usr/bin/env bash
# Runs the Vault locally with DEVELOPMENT settings against the Docker Compose
# PostgreSQL (`pnpm nx run infra:up`): dev certificates, dev policy, a fixed
# dev master passphrase and gRPC reflection enabled.
# Every VAULT_* variable can be overridden from the environment.
set -euo pipefail

cd "$(dirname "$0")/.."
# Regenerated when a newer service identity (e.g. the Vault's own) is missing;
# the other services then reissue theirs from the new CA.
[[ -f .dev/certs/vault-client.pem ]] || scripts/dev-certs.sh .dev/certs

COMPOSE_ENV=../../deploy/compose/.env
# Read single keys; never `source` the file.
compose_setting() { { grep -E "^$1=" "$COMPOSE_ENV" || true; } | tail -n1 | cut -d= -f2-; }

if [[ -z ${VAULT_DATABASE_URL:-} ]]; then
  if [[ ! -f $COMPOSE_ENV ]]; then
    echo "deploy/compose/.env not found. Start the infrastructure first: pnpm nx run infra:up" >&2
    exit 1
  fi
  db_password=$(compose_setting VAULT_DB_PASSWORD)
  db_port=$(compose_setting JARVIS_POSTGRES_PORT)
  export VAULT_DATABASE_URL="postgres://vault:${db_password}@127.0.0.1:${db_port:-55432}/vault"
fi
export VAULT_LISTEN_ADDR="${VAULT_LISTEN_ADDR:-127.0.0.1:50051}"
# Development only. Changing either value locks you out of keys stored with the old one.
export VAULT_MASTER_PASSPHRASE="${VAULT_MASTER_PASSPHRASE:-development-only-passphrase-do-not-use-in-prod}"
export VAULT_MASTER_SALT="${VAULT_MASTER_SALT:-amFydmlzLWRldi1zYWx0LTAwMQ==}"
export VAULT_TLS_CERT="${VAULT_TLS_CERT:-.dev/certs/server.pem}"
export VAULT_TLS_KEY="${VAULT_TLS_KEY:-.dev/certs/server-key.pem}"
export VAULT_TLS_CLIENT_CA="${VAULT_TLS_CLIENT_CA:-.dev/certs/ca.pem}"
export VAULT_AUTHZ_POLICY="${VAULT_AUTHZ_POLICY:-config/authz.dev.toml}"
export VAULT_ENABLE_REFLECTION="${VAULT_ENABLE_REFLECTION:-true}"
export VAULT_LOG_FORMAT="${VAULT_LOG_FORMAT:-pretty}"
# The audit service (services/audit); events wait while it is not running.
export VAULT_AUDIT_ADDR="${VAULT_AUDIT_ADDR:-127.0.0.1:50056}"
export VAULT_AUDIT_TLS_CERT="${VAULT_AUDIT_TLS_CERT:-.dev/certs/vault-client.pem}"
export VAULT_AUDIT_TLS_KEY="${VAULT_AUDIT_TLS_KEY:-.dev/certs/vault-client-key.pem}"

exec cargo run --quiet -p jarvis-vault

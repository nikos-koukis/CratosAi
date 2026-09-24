#!/usr/bin/env bash
# Runs the orchestrator locally with DEVELOPMENT settings against the Docker
# Compose PostgreSQL (`pnpm nx run infra:up`) and the other local services:
#
#   Vault           pnpm nx run vault:serve        127.0.0.1:50051
#   MCP router      pnpm nx run mcp-router:serve   127.0.0.1:50052
#   Knowledge       pnpm nx run knowledge:serve    127.0.0.1:50053
#   Agent sidecar   pnpm nx run agent:serve        ../agent/.dev/agent.sock
#
# Every ORCH_* variable can be overridden from the environment; ORCH_BIN runs
# a prebuilt binary instead of `go run`.
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
if [[ -z ${ORCH_DATABASE_URL:-} && -z ${ORCH_DATABASE_URL_FILE:-} ]]; then
  [[ -f $COMPOSE_ENV ]] || {
    echo "deploy/compose/.env not found. Start the infrastructure first: pnpm nx run infra:up" >&2
    exit 1
  }
  db_password=$(compose_setting ORCH_DB_PASSWORD)
  [[ -n $db_password ]] || { echo "ORCH_DB_PASSWORD missing from deploy/compose/.env; run: pnpm nx run infra:up" >&2; exit 1; }
  db_port=$(compose_setting JARVIS_POSTGRES_PORT)
  export ORCH_DATABASE_URL="postgres://orchestrator:${db_password}@127.0.0.1:${db_port:-55432}/orchestrator"
fi

export ORCH_LISTEN_ADDR="${ORCH_LISTEN_ADDR:-127.0.0.1:50054}"
export ORCH_ADMIN_ADDR="${ORCH_ADMIN_ADDR:-127.0.0.1:9094}"
export ORCH_TLS_CERT="${ORCH_TLS_CERT:-.dev/certs/server.pem}"
export ORCH_TLS_KEY="${ORCH_TLS_KEY:-.dev/certs/server-key.pem}"
export ORCH_TLS_CLIENT_CA="${ORCH_TLS_CLIENT_CA:-.dev/certs/ca.pem}"
export ORCH_AUTHZ_POLICY="${ORCH_AUTHZ_POLICY:-config/authz.dev.toml}"
export ORCH_REFLECTION="${ORCH_REFLECTION:-true}"
export ORCH_CLIENT_CERT="${ORCH_CLIENT_CERT:-.dev/certs/client.pem}"
export ORCH_CLIENT_KEY="${ORCH_CLIENT_KEY:-.dev/certs/client-key.pem}"
export ORCH_CLIENT_CA="${ORCH_CLIENT_CA:-.dev/certs/ca.pem}"
export ORCH_VAULT_ADDR="${ORCH_VAULT_ADDR:-127.0.0.1:50051}"
export ORCH_VAULT_SERVER_NAME="${ORCH_VAULT_SERVER_NAME:-localhost}"
export ORCH_MCP_ROUTER_ADDR="${ORCH_MCP_ROUTER_ADDR:-127.0.0.1:50052}"
export ORCH_MCP_ROUTER_SERVER_NAME="${ORCH_MCP_ROUTER_SERVER_NAME:-localhost}"
export ORCH_AUDIT_ADDR="${ORCH_AUDIT_ADDR:-127.0.0.1:50056}"
export ORCH_KNOWLEDGE_ADDR="${ORCH_KNOWLEDGE_ADDR:-127.0.0.1:50053}"
export ORCH_KNOWLEDGE_SERVER_NAME="${ORCH_KNOWLEDGE_SERVER_NAME:-localhost}"
export ORCH_AGENT_SOCKET="${ORCH_AGENT_SOCKET:-$(cd ../agent && pwd)/.dev/agent.sock}"
# The Mac daemon of Phase 2.1 may run on this machine during development.
export ORCH_ALLOW_LOOPBACK_DEVICES="${ORCH_ALLOW_LOOPBACK_DEVICES:-true}"
export ORCH_LOG_FORMAT="${ORCH_LOG_FORMAT:-text}"

exec ${ORCH_BIN:-go run ./cmd/orchestrator}

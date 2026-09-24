#!/usr/bin/env bash
# Runs the MCP router locally with DEVELOPMENT settings against the Docker
# Compose PostgreSQL and DragonflyDB (`pnpm nx run infra:up`) and the
# development Vault (`pnpm nx run vault:serve`).
#
#   scripts/dev-run.sh               public MCP servers only
#   LOCAL_MCP=1 scripts/dev-run.sh   also servers on this machine, e.g. the fake
#                                    server of `go run ./cmd/mcpctl dev-server`
#
# Every MCP_* variable can be overridden from the environment; MCP_ROUTER_BIN
# runs a prebuilt binary instead of `go run`.
set -euo pipefail

cd "$(dirname "$0")/.."
VAULT_CERTS=../vault/.dev/certs
[[ -f $VAULT_CERTS/mcp-router.pem ]] || {
  echo "The Vault's development certificates (with mcp-router.pem) are missing; start the Vault first: pnpm nx run vault:serve" >&2
  exit 1
}
# (Re)issue the router's certificates when missing or signed by an older CA.
if [[ ! -f .dev/certs/server.pem ]] || ! openssl verify -CAfile "$VAULT_CERTS/ca.pem" .dev/certs/server.pem >/dev/null 2>&1; then
  scripts/dev-certs.sh "$VAULT_CERTS" .dev/certs
fi

COMPOSE_ENV=../../deploy/compose/.env
# Read single keys; never `source` the file.
compose_setting() { { grep -E "^$1=" "$COMPOSE_ENV" || true; } | tail -n1 | cut -d= -f2-; }
if [[ -z ${MCP_DATABASE_URL:-} || -z ${MCP_REDIS_PASSWORD:-} ]]; then
  [[ -f $COMPOSE_ENV ]] || {
    echo "deploy/compose/.env not found. Start the infrastructure first: pnpm nx run infra:up" >&2
    exit 1
  }
fi
if [[ -z ${MCP_DATABASE_URL:-} ]]; then
  db_password=$(compose_setting MCP_DB_PASSWORD)
  [[ -n $db_password ]] || { echo "MCP_DB_PASSWORD missing from deploy/compose/.env; run: pnpm nx run infra:up" >&2; exit 1; }
  db_port=$(compose_setting JARVIS_POSTGRES_PORT)
  export MCP_DATABASE_URL="postgres://mcp_router:${db_password}@127.0.0.1:${db_port:-55432}/mcp"
fi
if [[ -z ${MCP_REDIS_PASSWORD:-} ]]; then
  MCP_REDIS_PASSWORD=$(compose_setting DRAGONFLY_PASSWORD)
  export MCP_REDIS_PASSWORD
fi
redis_port=$(compose_setting JARVIS_DRAGONFLY_PORT)

export MCP_LISTEN_ADDR="${MCP_LISTEN_ADDR:-127.0.0.1:50052}"
export MCP_ADMIN_ADDR="${MCP_ADMIN_ADDR:-127.0.0.1:9092}"
export MCP_TLS_CERT="${MCP_TLS_CERT:-.dev/certs/server.pem}"
export MCP_TLS_KEY="${MCP_TLS_KEY:-.dev/certs/server-key.pem}"
export MCP_TLS_CLIENT_CA="${MCP_TLS_CLIENT_CA:-.dev/certs/ca.pem}"
export MCP_AUTHZ_POLICY="${MCP_AUTHZ_POLICY:-config/authz.dev.toml}"
export MCP_REFLECTION="${MCP_REFLECTION:-true}"
export MCP_REDIS_ADDR="${MCP_REDIS_ADDR:-127.0.0.1:${redis_port:-56379}}"
export MCP_VAULT_ADDR="${MCP_VAULT_ADDR:-127.0.0.1:50051}"
export MCP_VAULT_SERVER_NAME="${MCP_VAULT_SERVER_NAME:-localhost}"
export MCP_VAULT_CA="${MCP_VAULT_CA:-$VAULT_CERTS/ca.pem}"
export MCP_VAULT_CERT="${MCP_VAULT_CERT:-$VAULT_CERTS/mcp-router.pem}"
export MCP_VAULT_KEY="${MCP_VAULT_KEY:-$VAULT_CERTS/mcp-router-key.pem}"
# `mcpctl connect` receives the OAuth redirect here.
export MCP_OAUTH_REDIRECT_URI="${MCP_OAUTH_REDIRECT_URI:-http://127.0.0.1:8765/callback}"
export MCP_ALLOW_CUSTOM_SERVERS="${MCP_ALLOW_CUSTOM_SERVERS:-true}"
if [[ ${LOCAL_MCP:-0} == 1 ]]; then
  export MCP_ALLOW_LOOPBACK_SERVERS=true
fi
export MCP_LOG_FORMAT="${MCP_LOG_FORMAT:-text}"

exec ${MCP_ROUTER_BIN:-go run ./cmd/mcp-router}

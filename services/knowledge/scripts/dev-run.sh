#!/usr/bin/env bash
# Runs the knowledge service locally with DEVELOPMENT settings against the
# Docker Compose Neo4j and Qdrant (`pnpm nx run infra:up`). The embedding
# model is downloaded (and verified) into .dev/models on first run.
# Every KNOWLEDGE_* variable can be overridden from the environment.
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
if [[ -z ${KNOWLEDGE_NEO4J_PASSWORD:-} || -z ${KNOWLEDGE_QDRANT_API_KEY:-} ]]; then
  [[ -f $COMPOSE_ENV ]] || {
    echo "deploy/compose/.env not found. Start the infrastructure first: pnpm nx run infra:up" >&2
    exit 1
  }
  KNOWLEDGE_NEO4J_PASSWORD="${KNOWLEDGE_NEO4J_PASSWORD:-$(compose_setting NEO4J_PASSWORD)}"
  KNOWLEDGE_QDRANT_API_KEY="${KNOWLEDGE_QDRANT_API_KEY:-$(compose_setting QDRANT_API_KEY)}"
  export KNOWLEDGE_NEO4J_PASSWORD KNOWLEDGE_QDRANT_API_KEY
fi
bolt_port=$(compose_setting JARVIS_NEO4J_BOLT_PORT)
qdrant_http=$(compose_setting JARVIS_QDRANT_HTTP_PORT)
qdrant_grpc=$(compose_setting JARVIS_QDRANT_GRPC_PORT)

export KNOWLEDGE_LISTEN_ADDR="${KNOWLEDGE_LISTEN_ADDR:-127.0.0.1:50053}"
export KNOWLEDGE_ADMIN_ADDR="${KNOWLEDGE_ADMIN_ADDR:-127.0.0.1:9093}"
export KNOWLEDGE_TLS_CERT="${KNOWLEDGE_TLS_CERT:-.dev/certs/server.pem}"
export KNOWLEDGE_TLS_KEY="${KNOWLEDGE_TLS_KEY:-.dev/certs/server-key.pem}"
export KNOWLEDGE_TLS_CLIENT_CA="${KNOWLEDGE_TLS_CLIENT_CA:-.dev/certs/ca.pem}"
export KNOWLEDGE_AUTHZ_POLICY="${KNOWLEDGE_AUTHZ_POLICY:-config/authz.dev.toml}"
export KNOWLEDGE_REFLECTION="${KNOWLEDGE_REFLECTION:-true}"
export KNOWLEDGE_NEO4J_URI="${KNOWLEDGE_NEO4J_URI:-bolt://127.0.0.1:${bolt_port:-57687}}"
export KNOWLEDGE_QDRANT_URL="${KNOWLEDGE_QDRANT_URL:-http://127.0.0.1:${qdrant_http:-56333}}"
export KNOWLEDGE_QDRANT_GRPC_PORT="${KNOWLEDGE_QDRANT_GRPC_PORT:-${qdrant_grpc:-56334}}"
export KNOWLEDGE_MODEL_DIR="${KNOWLEDGE_MODEL_DIR:-.dev/models}"
export KNOWLEDGE_MODEL_DOWNLOAD="${KNOWLEDGE_MODEL_DOWNLOAD:-true}"
export KNOWLEDGE_LOG_FORMAT="${KNOWLEDGE_LOG_FORMAT:-text}"

exec uv run --frozen --package jarvis-knowledge jarvis-knowledge

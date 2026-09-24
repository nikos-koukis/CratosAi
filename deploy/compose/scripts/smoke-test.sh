#!/usr/bin/env bash
# Verifies the running local infrastructure: every service is healthy, accepts
# its credentials, rejects wrong or missing ones, and is published on
# 127.0.0.1 only. Exits non-zero if any check fails.
#
# Secrets are passed to child processes through the environment or stdin,
# never on a command line.
set -uo pipefail

cd "$(dirname "$0")/.."
[[ -f .env ]] || { echo "deploy/compose/.env is missing; run: pnpm nx run infra:up" >&2; exit 1; }

compose() { docker compose -f compose.yaml "$@"; }
export -f compose
setting() { grep -E "^$1=" .env | tail -n1 | cut -d= -f2-; }
port() { local value; value=$(setting "$1"); echo "${value:-$2}"; }

VAULT_DB_PASSWORD=$(setting VAULT_DB_PASSWORD)
MCP_DB_PASSWORD=$(setting MCP_DB_PASSWORD)
ORCH_DB_PASSWORD=$(setting ORCH_DB_PASSWORD)
DRAGONFLY_PASSWORD=$(setting DRAGONFLY_PASSWORD)
NEO4J_PASSWORD=$(setting NEO4J_PASSWORD)
QDRANT_API_KEY=$(setting QDRANT_API_KEY)
# Exported so subshells inherit them without putting them in any argv.
export VAULT_DB_PASSWORD MCP_DB_PASSWORD ORCH_DB_PASSWORD DRAGONFLY_PASSWORD NEO4J_PASSWORD QDRANT_API_KEY
QDRANT_HTTP_PORT=$(port JARVIS_QDRANT_HTTP_PORT 56333)
QDRANT_GRPC_PORT=$(port JARVIS_QDRANT_GRPC_PORT 56334)

failures=0
pass() { printf '  \033[32mok\033[0m    %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; failures=$((failures + 1)); }
expect_ok() { local name=$1; shift; if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi; }
expect_refused() { local name=$1; shift; if "$@" >/dev/null 2>&1; then fail "$name"; else pass "$name"; fi; }

echo "containers"
for service in postgres dragonfly neo4j qdrant; do
  health=$(compose ps --format '{{.Health}}' "$service" 2>/dev/null)
  if [[ $health == healthy ]]; then pass "$service is healthy"; else fail "$service is healthy (got: ${health:-not running})"; fi
done
published=$(compose ps --format '{{range .Publishers}}{{if .PublishedPort}}{{.URL}} {{end}}{{end}}')
if [[ -n $published && -z $(tr ' ' '\n' <<<"$published" | grep -v -E '^(127\.0\.0\.1)?$') ]]; then
  pass "all ports published on 127.0.0.1 only"
else
  fail "all ports published on 127.0.0.1 only (got: $published)"
fi

echo "postgres"
psql_as() { # psql_as <password> <user> <db> <sql>
  PGPASSWORD=$1 compose exec -T -e PGPASSWORD postgres \
    psql --no-psqlrc -h 127.0.0.1 -U "$2" -d "$3" -v ON_ERROR_STOP=1 -tAc "$4"
}
expect_ok "vault role logs in to its database (scram-sha-256)" psql_as "$VAULT_DB_PASSWORD" vault vault "SELECT 1"
expect_ok "vault role can create tables in its database" \
  psql_as "$VAULT_DB_PASSWORD" vault vault "CREATE TABLE smoke_probe (id int); DROP TABLE smoke_probe"
expect_refused "wrong password is rejected" psql_as "not-the-password" vault vault "SELECT 1"
expect_refused "vault role cannot open the postgres database" psql_as "$VAULT_DB_PASSWORD" vault postgres "SELECT 1"
expect_ok "mcp_router role logs in to its database" psql_as "$MCP_DB_PASSWORD" mcp_router mcp "SELECT 1"
expect_refused "mcp_router role cannot open the vault database" psql_as "$MCP_DB_PASSWORD" mcp_router vault "SELECT 1"
expect_ok "orchestrator role logs in to its database" psql_as "$ORCH_DB_PASSWORD" orchestrator orchestrator "SELECT 1"
expect_refused "orchestrator role cannot open the vault database" psql_as "$ORCH_DB_PASSWORD" orchestrator vault "SELECT 1"
expect_refused "mcp_router role cannot open the orchestrator database" psql_as "$MCP_DB_PASSWORD" mcp_router orchestrator "SELECT 1"

echo "dragonfly"
redis_as() { # redis_as <password|""> <command...>
  local auth=$1; shift
  REDISCLI_AUTH=$auth compose exec -T -e REDISCLI_AUTH dragonfly redis-cli "$@"
}
export -f redis_as
expect_ok "authenticated SET/GET round-trips" bash -c '
  [[ $(redis_as "$DRAGONFLY_PASSWORD" SET smoke:probe ok EX 10) == OK &&
     $(redis_as "$DRAGONFLY_PASSWORD" GET smoke:probe) == ok ]]
'
expect_refused "unauthenticated commands are rejected" bash -c '[[ $(redis_as "" PING) == PONG ]]'
expect_refused "wrong password is rejected" bash -c '[[ $(redis_as not-the-password PING) == PONG ]]'

echo "neo4j"
cypher_as() { # cypher_as <password> <query>
  NEO4J_PASSWORD=$1 compose exec -T -e NEO4J_USERNAME=neo4j -e NEO4J_PASSWORD neo4j \
    cypher-shell -a bolt://localhost:7687 --format plain "$2"
}
export -f cypher_as
expect_ok "authenticated Cypher over Bolt" \
  bash -c '[[ $(cypher_as "$NEO4J_PASSWORD" "RETURN 40 + 2 AS answer" | tail -n1) == 42 ]]'
expect_refused "wrong password is rejected" cypher_as "not-the-password" "RETURN 1"

echo "qdrant"
qdrant_get() { # qdrant_get <api-key|""> <path>
  if [[ -n $1 ]]; then
    printf 'api-key: %s\n' "$1" | curl -fsS -H @- "http://127.0.0.1:$QDRANT_HTTP_PORT$2"
  else
    curl -fsS "http://127.0.0.1:$QDRANT_HTTP_PORT$2"
  fi
}
expect_ok "API key grants access to collections" qdrant_get "$QDRANT_API_KEY" /collections
expect_refused "requests without the API key are rejected" qdrant_get "" /collections
expect_refused "a wrong API key is rejected" qdrant_get "not-the-key" /collections
expect_ok "gRPC port accepts connections" bash -c "exec 3<>/dev/tcp/127.0.0.1/$QDRANT_GRPC_PORT"

echo
if ((failures)); then
  echo "$failures check(s) failed."
  exit 1
fi
echo "All infrastructure checks passed."

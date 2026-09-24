#!/bin/sh
# One database and one login role per service; no service uses the superuser.
# Idempotent: runs on first initialisation (docker-entrypoint-initdb.d) and on
# every `pnpm nx run infra:up`, so services added later get their database on
# existing volumes too. Passwords of existing roles are not changed.
set -eu

: "${VAULT_DB_PASSWORD:?VAULT_DB_PASSWORD is not set}"
: "${MCP_DB_PASSWORD:?MCP_DB_PASSWORD is not set}"
: "${ORCH_DB_PASSWORD:?ORCH_DB_PASSWORD is not set}"
: "${APP_DB_PASSWORD:?APP_DB_PASSWORD is not set}"

# psql variables (:'name') quote passwords safely; SQL comes from stdin.
psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
  --username "${POSTGRES_USER:-postgres}" --dbname postgres \
  --set=vault_password="$VAULT_DB_PASSWORD" \
  --set=mcp_password="$MCP_DB_PASSWORD" \
  --set=orch_password="$ORCH_DB_PASSWORD" \
  --set=app_password="$APP_DB_PASSWORD" <<'SQL'
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;

SELECT format('CREATE ROLE vault LOGIN PASSWORD %L', :'vault_password')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault') \gexec
SELECT 'CREATE DATABASE vault OWNER vault'
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'vault') \gexec
REVOKE ALL ON DATABASE vault FROM PUBLIC;

SELECT format('CREATE ROLE mcp_router LOGIN PASSWORD %L', :'mcp_password')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mcp_router') \gexec
SELECT 'CREATE DATABASE mcp OWNER mcp_router'
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'mcp') \gexec
REVOKE ALL ON DATABASE mcp FROM PUBLIC;

SELECT format('CREATE ROLE orchestrator LOGIN PASSWORD %L', :'orch_password')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'orchestrator') \gexec
SELECT 'CREATE DATABASE orchestrator OWNER orchestrator'
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'orchestrator') \gexec
REVOKE ALL ON DATABASE orchestrator FROM PUBLIC;

SELECT format('CREATE ROLE app_api LOGIN PASSWORD %L', :'app_password')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_api') \gexec
SELECT 'CREATE DATABASE app OWNER app_api'
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'app') \gexec
REVOKE ALL ON DATABASE app FROM PUBLIC;
SQL

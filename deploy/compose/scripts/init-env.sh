#!/usr/bin/env bash
# Creates deploy/compose/.env with random secrets for local development, and
# adds secrets for services introduced later to an existing .env.
#
# Existing values are never changed: the databases in the Docker volumes were
# initialised with them. To start over, run `pnpm nx run infra:reset`,
# delete .env, then run this again.
set -euo pipefail

cd "$(dirname "$0")/.."

SECRETS=(POSTGRES_PASSWORD VAULT_DB_PASSWORD MCP_DB_PASSWORD ORCH_DB_PASSWORD APP_DB_PASSWORD DASHBOARD_DB_PASSWORD AUDIT_DB_PASSWORD DRAGONFLY_PASSWORD NEO4J_PASSWORD QDRANT_API_KEY)

umask 077
if [[ ! -f .env ]]; then
  printf '# Local development secrets for deploy/compose/compose.yaml.\n# Generated %s by scripts/init-env.sh. Never commit.\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > .env
fi

added=()
for name in "${SECRETS[@]}"; do
  if ! grep -qE "^${name}=" .env; then
    printf '%s=%s\n' "$name" "$(openssl rand -hex 24)" >> .env
    added+=("$name")
  fi
done

if ((${#added[@]})); then
  echo "deploy/compose/.env: added ${added[*]}"
else
  echo "deploy/compose/.env is complete; keeping it."
fi

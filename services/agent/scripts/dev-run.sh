#!/usr/bin/env bash
# Runs the agent sidecar locally with DEVELOPMENT settings. It listens on a
# Unix socket (mode 0600) that only the orchestrator of this user connects
# to; `pnpm nx run orchestrator:serve` uses the same default path.
#
# The sidecar holds no keys: the orchestrator passes the tenant's key with
# each call. AGENT_OPENAI_BASE_URL / AGENT_XAI_BASE_URL may point at a local
# fake provider (loopback http is allowed) to avoid spending API credits.
# Every AGENT_* variable can be overridden from the environment.
set -euo pipefail

cd "$(dirname "$0")/.."
export AGENT_SOCKET="${AGENT_SOCKET:-$(pwd)/.dev/agent.sock}"
export AGENT_ADMIN_ADDR="${AGENT_ADMIN_ADDR:-127.0.0.1:9095}"
export AGENT_LOG_FORMAT="${AGENT_LOG_FORMAT:-text}"

exec uv run --frozen --package jarvis-agent jarvis-agent

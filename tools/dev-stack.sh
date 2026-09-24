#!/usr/bin/env bash
# Runs the whole Jarvis stack on this machine for development and manual
# testing, in the background, with FAKE providers (no API costs):
#
#   tools/dev-stack.sh up            start everything; prints the dev tenant and next steps
#   tools/dev-stack.sh down          stop everything
#   tools/dev-stack.sh status        what is listening
#   tools/dev-stack.sh logs NAME     follow a service's log (vault, orchestrator, app-api, ...)
#
# The LLM is jarvis-fake-llm and the realtime voice is voicectl's echo
# provider; both accept only the dev tenant's fake key. FAKE_LLM_DELAY=5 makes
# each background-task step take 5 s (e.g. so a task ends after you hang up,
# which sends a push notification). ECHO_SAVE=1 saves what you say to the echo
# provider as WAV files in .dev/stack/echo. A fake OAuth + MCP server
# (mcpctl dev-server) stands in for Jira & co. Logs and pids live in .dev/stack.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
STATE=$ROOT/.dev/stack
BIN=$STATE/bin
DEV_TENANT=${DEV_TENANT:-0199e2e0-0000-7000-8000-000000000001}
DEV_USER=${DEV_USER:-me}
DEV_KEY=sk-dev-fake-0001
PORTS="vault:50051 audit:50056 mcp-router:50052 mcp-dev-server:8931 knowledge:50053 fake-llm:9910 agent:9095 orchestrator:50054 echo-provider:9900 voice-gateway:8080 app-api:8081 dashboard:3000"

start() { # start NAME DIR COMMAND...
  local name=$1 dir=$2
  shift 2
  (cd "$dir" && exec nohup "$@") >"$STATE/$name.log" 2>&1 &
  echo "$! $name" >>"$STATE/pids"
}

wait_port() { # wait_port NAME PORT SECONDS
  local deadline=$((SECONDS + ${3:-60}))
  until nc -z 127.0.0.1 "$2" 2>/dev/null; do
    if ((SECONDS > deadline)); then
      echo "  $1 did not start; last lines of $STATE/$1.log:" >&2
      tail -n 20 "$STATE/$1.log" >&2
      exit 1
    fi
    sleep 0.3
  done
  echo "  $1 on :$2"
}

up() {
  if [[ -f $STATE/pids ]] && [[ -s $STATE/pids ]]; then
    echo "The stack seems to be running (see: tools/dev-stack.sh status); run down first." >&2
    exit 1
  fi
  mkdir -p "$BIN"
  : >"$STATE/pids"
  echo "Infrastructure (Docker)…"
  (cd "$ROOT" && pnpm nx run infra:up >/dev/null)
  echo "Building…"
  (cd "$ROOT" && cargo build --quiet -p jarvis-vault)
  for service in audit mcp-router orchestrator voice-gateway app-api; do
    (cd "$ROOT/services/$service" && go build -o "$BIN/" ./cmd/...)
  done
  echo "Starting…"
  start vault "$ROOT/services/vault" scripts/dev-run.sh
  wait_port vault 50051 120
  # The audit trail: every service records there (and holds events until it is up).
  start audit "$ROOT/services/audit" env AUDIT_BIN="$BIN/audit" scripts/dev-run.sh
  wait_port audit 50056
  # OAuth redirects come back to the dashboard; LOCAL_MCP lets the router
  # reach the fake MCP server on this machine.
  start mcp-router "$ROOT/services/mcp-router" env MCP_ROUTER_BIN="$BIN/mcp-router" LOCAL_MCP=1 \
    MCP_OAUTH_REDIRECT_URI="${DASHBOARD_ORIGIN:-http://localhost:3000}/integrations/callback" scripts/dev-run.sh
  wait_port mcp-router 50052
  start mcp-dev-server "$ROOT/services/mcp-router" "$BIN/mcpctl" dev-server
  wait_port mcp-dev-server 8931
  start knowledge "$ROOT/services/knowledge" scripts/dev-run.sh
  wait_port knowledge 50053 600 # downloads the embedding model on first run
  start fake-llm "$ROOT/services/agent" uv run --frozen --package jarvis-agent jarvis-fake-llm --key "$DEV_KEY" \
    --delay "${FAKE_LLM_DELAY:-0}"
  wait_port fake-llm 9910
  start agent "$ROOT/services/agent" env AGENT_OPENAI_BASE_URL=http://127.0.0.1:9910/v1 \
    AGENT_XAI_BASE_URL=http://127.0.0.1:9910/v1 scripts/dev-run.sh
  wait_port agent 9095
  start orchestrator "$ROOT/services/orchestrator" env ORCH_BIN="$BIN/orchestrator" scripts/dev-run.sh
  wait_port orchestrator 50054
  start echo-provider "$ROOT/services/voice-gateway" "$BIN/voicectl" echo-provider -key "$DEV_KEY" \
    ${ECHO_SAVE:+-save "$STATE/echo"}
  wait_port echo-provider 9900
  start voice-gateway "$ROOT/services/voice-gateway" env ECHO=1 GATEWAY_BIN="$BIN/voice-gateway" scripts/dev-run.sh
  wait_port voice-gateway 8080
  start app-api "$ROOT/services/app-api" env APP_API_BIN="$BIN/app-api" scripts/dev-run.sh
  wait_port app-api 8081
  start dashboard "$ROOT/apps/dashboard" scripts/dev-run.sh
  wait_port dashboard 3000 120
  (cd "$ROOT" && uv run --frozen python tools/dev-tenant.py "$DEV_TENANT" "$DEV_KEY")
  if grep -q "Push notifications on" "$STATE/app-api.log"; then
    grep "Push notifications on" "$STATE/app-api.log" | sed 's/^/  /'
  else
    echo "  Push notifications off (no APNs key in ~/.config/jarvis/apns, or no apps/ios/Config/Local.xcconfig)"
  fi
  cat <<INFO

Jarvis is running. Dev tenant $DEV_TENANT, user $DEV_USER.

  Dashboard:     ${DASHBOARD_ORIGIN:-http://localhost:3000} (create an account with a passkey)
  Audit trail:   the dashboard's Audit trail page (owners see everything, members their own)
  Test MCP:      http://127.0.0.1:8931/mcp (Integrations → Another MCP server; signs in by itself)
  Pair the app:  (cd services/app-api && go run ./cmd/appctl pair -tenant $DEV_TENANT -user $DEV_USER)
  Talk in text:  (cd services/orchestrator && go run ./cmd/orchctl converse -tenant $DEV_TENANT -user $DEV_USER)
  Stop:          tools/dev-stack.sh down
INFO
}

down() {
  [[ -f $STATE/pids ]] || { echo "Nothing is running."; return; }
  tail -r "$STATE/pids" | while read -r pid name; do
    pkill -TERM -P "$pid" 2>/dev/null || true
    kill -TERM "$pid" 2>/dev/null && echo "stopped $name" || true
  done
  rm -f "$STATE/pids"
}

status() {
  for entry in $PORTS; do
    name=${entry%%:*} port=${entry##*:}
    if nc -z 127.0.0.1 "$port" 2>/dev/null; then echo "up    $name :$port"; else echo "down  $name :$port"; fi
  done
}

case ${1:-} in
up) up ;;
down) down ;;
status) status ;;
logs) tail -n 100 -f "$STATE/${2:?logs NAME}.log" ;;
*)
  sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
  ;;
esac

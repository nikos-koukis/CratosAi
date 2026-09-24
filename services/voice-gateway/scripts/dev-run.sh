#!/usr/bin/env bash
# Runs the voice gateway locally against the development Vault.
#
#   scripts/dev-run.sh          real providers (OpenAI / xAI) with the keys in the Vault
#   ECHO=1 scripts/dev-run.sh   the local echo provider (voicectl echo-provider), no API costs
#
# Needs: the Vault running (pnpm nx run vault:serve), which also creates the
# Vault's development certificates, including the gateway's client certificate.
# Jarvis's tools come from the orchestrator (pnpm nx run orchestrator:serve);
# without it sessions still work, without tools. GATEWAY_ORCHESTRATOR_ADDR=
# (empty) turns tools off.
# Every GATEWAY_* variable can be overridden from the environment.
set -euo pipefail

cd "$(dirname "$0")/.."
VAULT_CERTS=../vault/.dev/certs
[[ -f $VAULT_CERTS/voice-gateway.pem ]] || {
  echo "Vault development certificates not found; start the Vault first: pnpm nx run vault:serve" >&2
  exit 1
}
if [[ ! -f .dev/tokens/jwks.json ]]; then
  go run ./cmd/voicectl keygen -out .dev/tokens
fi

export GATEWAY_LISTEN_ADDR="${GATEWAY_LISTEN_ADDR:-127.0.0.1:8080}"
export GATEWAY_ADMIN_ADDR="${GATEWAY_ADMIN_ADDR:-127.0.0.1:9091}"
export GATEWAY_TOKEN_JWKS="${GATEWAY_TOKEN_JWKS:-.dev/tokens/jwks.json}"
export GATEWAY_TOKEN_ISSUER="${GATEWAY_TOKEN_ISSUER:-https://id.jarvis.local}"
export GATEWAY_VAULT_ADDR="${GATEWAY_VAULT_ADDR:-127.0.0.1:50051}"
export GATEWAY_VAULT_SERVER_NAME="${GATEWAY_VAULT_SERVER_NAME:-localhost}"
export GATEWAY_VAULT_CA="${GATEWAY_VAULT_CA:-$VAULT_CERTS/ca.pem}"
export GATEWAY_VAULT_CERT="${GATEWAY_VAULT_CERT:-$VAULT_CERTS/voice-gateway.pem}"
export GATEWAY_VAULT_KEY="${GATEWAY_VAULT_KEY:-$VAULT_CERTS/voice-gateway-key.pem}"
export GATEWAY_ORCHESTRATOR_ADDR="${GATEWAY_ORCHESTRATOR_ADDR-127.0.0.1:50054}"
export GATEWAY_ORCHESTRATOR_SERVER_NAME="${GATEWAY_ORCHESTRATOR_SERVER_NAME:-localhost}"
export GATEWAY_LOG_FORMAT="${GATEWAY_LOG_FORMAT:-text}"
if [[ ${ECHO:-0} == 1 ]]; then
  export GATEWAY_PROVIDERS=openai
  export GATEWAY_OPENAI_URL="${GATEWAY_OPENAI_URL:-ws://127.0.0.1:9900/v1/realtime}"
  echo "Using the local echo provider at $GATEWAY_OPENAI_URL (run: go run ./cmd/voicectl echo-provider -key <key in vault> [-tool recall_memory -tool-args '{\"query\":\"...\"}'])"
fi

exec ${GATEWAY_BIN:-go run ./cmd/voice-gateway}

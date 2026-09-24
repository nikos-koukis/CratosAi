#!/usr/bin/env bash
# Runs the app API locally with DEVELOPMENT settings against the Docker
# Compose PostgreSQL (`pnpm nx run infra:up`) and the local orchestrator
# (`pnpm nx run orchestrator:serve`).
#
# It signs user tokens with the voice gateway's development key
# (services/voice-gateway/.dev/tokens), so the gateway accepts its voice
# tokens. The public API listens on plain HTTP on 127.0.0.1, which the iOS
# simulator reaches; see the README for a real iPhone.
#
# Every APP_* variable can be overridden from the environment; APP_API_BIN
# runs a prebuilt binary instead of `go run`.
set -euo pipefail

cd "$(dirname "$0")/.."
VAULT_CERTS=../vault/.dev/certs
# (Re)issue certificates when missing or signed by an older development CA.
if [[ ! -f .dev/certs/server.pem ]] || ! openssl verify -CAfile "$VAULT_CERTS/ca.pem" .dev/certs/server.pem >/dev/null 2>&1; then
  scripts/dev-certs.sh "$VAULT_CERTS" .dev/certs
fi
TOKENS=../voice-gateway/.dev/tokens
if [[ ! -f $TOKENS/signing-key.pem ]]; then
  (cd ../voice-gateway && go run ./cmd/voicectl keygen -out .dev/tokens)
fi

COMPOSE_ENV=../../deploy/compose/.env
# Read single keys; never `source` the file.
compose_setting() { { grep -E "^$1=" "$COMPOSE_ENV" || true; } | tail -n1 | cut -d= -f2-; }
if [[ -z ${APP_DATABASE_URL:-} && -z ${APP_DATABASE_URL_FILE:-} ]]; then
  [[ -f $COMPOSE_ENV ]] || {
    echo "deploy/compose/.env not found. Start the infrastructure first: pnpm nx run infra:up" >&2
    exit 1
  }
  db_password=$(compose_setting APP_DB_PASSWORD)
  [[ -n $db_password ]] || { echo "APP_DB_PASSWORD missing from deploy/compose/.env; run: pnpm nx run infra:up" >&2; exit 1; }
  db_port=$(compose_setting JARVIS_POSTGRES_PORT)
  export APP_DATABASE_URL="postgres://app_api:${db_password}@127.0.0.1:${db_port:-55432}/app"
fi

export APP_PUBLIC_ADDR="${APP_PUBLIC_ADDR:-127.0.0.1:8081}"
export APP_PUBLIC_URL="${APP_PUBLIC_URL:-http://$APP_PUBLIC_ADDR}"
export APP_ADMIN_ADDR="${APP_ADMIN_ADDR:-127.0.0.1:50055}"
export APP_ADMIN_TLS_CERT="${APP_ADMIN_TLS_CERT:-.dev/certs/server.pem}"
export APP_ADMIN_TLS_KEY="${APP_ADMIN_TLS_KEY:-.dev/certs/server-key.pem}"
export APP_ADMIN_TLS_CLIENT_CA="${APP_ADMIN_TLS_CLIENT_CA:-.dev/certs/ca.pem}"
export APP_AUTHZ_POLICY="${APP_AUTHZ_POLICY:-config/authz.dev.toml}"
export APP_REFLECTION="${APP_REFLECTION:-true}"
export APP_TOKEN_SIGNING_KEY="${APP_TOKEN_SIGNING_KEY:-$TOKENS/signing-key.pem}"
export APP_TOKEN_KEY_ID="${APP_TOKEN_KEY_ID:-dev}"
export APP_TOKEN_ISSUER="${APP_TOKEN_ISSUER:-https://id.jarvis.local}"
export APP_VOICE_URL="${APP_VOICE_URL:-ws://127.0.0.1:8080/v1/voice}"
export APP_ORCHESTRATOR_ADDR="${APP_ORCHESTRATOR_ADDR:-127.0.0.1:50054}"
export APP_AUDIT_ADDR="${APP_AUDIT_ADDR:-127.0.0.1:50056}"
export APP_ORCHESTRATOR_SERVER_NAME="${APP_ORCHESTRATOR_SERVER_NAME:-localhost}"
export APP_CLIENT_CERT="${APP_CLIENT_CERT:-.dev/certs/client.pem}"
export APP_CLIENT_KEY="${APP_CLIENT_KEY:-.dev/certs/client-key.pem}"
export APP_CLIENT_CA="${APP_CLIENT_CA:-.dev/certs/ca.pem}"
export APP_LOG_FORMAT="${APP_LOG_FORMAT:-text}"

# Push notifications, when an APNs auth key is in ~/.config/jarvis/apns
# (AuthKey_<KEY ID>.p8): the team and bundle id come from the iOS app's
# Config/Local.xcconfig. Set APP_APNS_* yourself to override.
if [[ -z ${APP_APNS_KEY_FILE:-} ]]; then
  keys=("$HOME"/.config/jarvis/apns/AuthKey_*.p8)
  local_xcconfig=../../apps/ios/Config/Local.xcconfig
  xc_setting() { { grep -E "^[[:space:]]*$1[[:space:]]*=" "$local_xcconfig" || true; } | tail -n1 | cut -d= -f2- | tr -d '[:space:]'; }
  if [[ ${#keys[@]} == 1 && -f ${keys[0]} && -f $local_xcconfig ]]; then
    team=$(xc_setting DEVELOPMENT_TEAM)
    prefix=$(xc_setting JARVIS_BUNDLE_ID_PREFIX)
    if [[ -n $team && -n $prefix ]]; then
      export APP_APNS_KEY_FILE="${keys[0]}"
      key_name=$(basename "${keys[0]}" .p8)
      export APP_APNS_KEY_ID="${key_name#AuthKey_}"
      export APP_APNS_TEAM_ID="$team"
      export APP_APNS_TOPIC="$prefix.jarvis"
      echo "Push notifications on: key $APP_APNS_KEY_ID, team $APP_APNS_TEAM_ID, app $APP_APNS_TOPIC"
    fi
  fi
fi

exec ${APP_API_BIN:-go run ./cmd/app-api}

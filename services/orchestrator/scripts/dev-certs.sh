#!/usr/bin/env bash
# Issues the orchestrator's DEVELOPMENT certificates from the Vault's
# development CA (one trust domain for all local services). Never use them
# outside a developer machine.
#
#   ca.pem                        development CA (copied)
#   server.pem, server-key.pem    orchestrator listener (localhost, 127.0.0.1)
#   client.pem, client-key.pem    its identity towards the Vault, the MCP router
#                                 and the knowledge service:
#                                 spiffe://jarvis.local/orchestrator
#   voice-gateway.pem, -key.pem   client: spiffe://jarvis.local/voice-gateway (copied)
#   dashboard-api.pem, -key.pem   client: spiffe://jarvis.local/dashboard-api (copied)
#
# Usage: scripts/dev-certs.sh [vault-certs-dir] [output-dir]
set -euo pipefail

VAULT_CERTS="${1:-../vault/.dev/certs}"
OUT="${2:-.dev/certs}"
TRUST_DOMAIN="jarvis.local"
DAYS=30

[[ -f $VAULT_CERTS/ca-key.pem ]] || {
  echo "Vault development CA not found in $VAULT_CERTS; start the Vault once first: pnpm nx run vault:serve" >&2
  exit 1
}
mkdir -p "$OUT"
chmod 700 "$OUT"
for principal in voice-gateway dashboard-api; do
  cp "$VAULT_CERTS/$principal.pem" "$VAULT_CERTS/$principal-key.pem" "$OUT/"
  chmod 600 "$OUT/$principal-key.pem"
done
cp "$VAULT_CERTS/ca.pem" "$OUT/"
CA_KEY="$(cd "$VAULT_CERTS" && pwd)/ca-key.pem"
cd "$OUT"

# issue <name> <common-name> <extendedKeyUsage> <subjectAltName>
issue() {
  local name=$1 cn=$2 eku=$3 san=$4
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$name-key.pem" 2>/dev/null
  chmod 600 "$name-key.pem"
  openssl req -new -key "$name-key.pem" -out "$name.csr" -subj "/CN=$cn"
  openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey "$CA_KEY" -CAcreateserial \
    -out "$name.pem" -days "$DAYS" 2>/dev/null \
    -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\nsubjectAltName=%s\n' "$eku" "$san")
  rm "$name.csr"
}

issue server orchestrator serverAuth "DNS:localhost,IP:127.0.0.1"
issue client orchestrator clientAuth "URI:spiffe://$TRUST_DOMAIN/orchestrator"
rm -f ca.srl

echo "Orchestrator development certificates written to $(pwd) (valid $DAYS days)."

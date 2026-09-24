#!/usr/bin/env bash
# Issues the router's DEVELOPMENT certificates from the Vault's development CA
# (one trust domain for all local services). Never use them outside a
# developer machine.
#
#   ca.pem                       development CA (copied)
#   server.pem, server-key.pem   router listener (localhost, 127.0.0.1)
#   orchestrator.pem, -key.pem   client: spiffe://jarvis.local/orchestrator
#   dashboard-api.pem, -key.pem  client: spiffe://jarvis.local/dashboard-api (copied)
#
# The router's own client certificate for the Vault (mcp-router.pem) stays in
# the Vault's directory.
#
# Usage: scripts/dev-certs.sh [vault-certs-dir] [output-dir]
set -euo pipefail

VAULT_CERTS="${1:-../vault/.dev/certs}"
OUT="${2:-.dev/certs}"
TRUST_DOMAIN="jarvis.local"
DAYS=30

[[ -f $VAULT_CERTS/ca-key.pem ]] || {
  echo "Vault development CA not found in $VAULT_CERTS; start the Vault first: pnpm nx run vault:serve" >&2
  exit 1
}
mkdir -p "$OUT"
chmod 700 "$OUT"
cp "$VAULT_CERTS/ca.pem" "$VAULT_CERTS/dashboard-api.pem" "$VAULT_CERTS/dashboard-api-key.pem" "$OUT/"
chmod 600 "$OUT/dashboard-api-key.pem"
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

issue server mcp-router serverAuth "DNS:localhost,IP:127.0.0.1"
issue orchestrator orchestrator clientAuth "URI:spiffe://$TRUST_DOMAIN/orchestrator"
rm -f ca.srl

echo "Router development certificates written to $(pwd) (valid $DAYS days)."

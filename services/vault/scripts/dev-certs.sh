#!/usr/bin/env bash
# Generates a throwaway DEVELOPMENT PKI for the Vault's mTLS listener.
# Never use these certificates outside a developer machine.
#
#   ca.pem, ca-key.pem                     development CA
#   server.pem, server-key.pem             Vault server (localhost, 127.0.0.1)
#   dashboard-api.pem, -key.pem            client: spiffe://jarvis.local/dashboard-api
#   voice-gateway.pem, -key.pem            client: spiffe://jarvis.local/voice-gateway
#   mcp-router.pem, -key.pem               client: spiffe://jarvis.local/mcp-router
#
# Usage: scripts/dev-certs.sh [output-dir]   (default: .dev/certs)
set -euo pipefail

OUT="${1:-.dev/certs}"
TRUST_DOMAIN="jarvis.local"
DAYS=30

mkdir -p "$OUT"
chmod 700 "$OUT"
cd "$OUT"

new_key() {
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null
  chmod 600 "$1"
}

new_key ca-key.pem
openssl req -x509 -new -key ca-key.pem -out ca.pem -days "$DAYS" \
  -subj "/CN=Jarvis Development CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# issue <name> <common-name> <extendedKeyUsage> <subjectAltName>
issue() {
  local name=$1 cn=$2 eku=$3 san=$4
  new_key "$name-key.pem"
  openssl req -new -key "$name-key.pem" -out "$name.csr" -subj "/CN=$cn"
  openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out "$name.pem" -days "$DAYS" 2>/dev/null \
    -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\nsubjectAltName=%s\n' "$eku" "$san")
  rm "$name.csr"
}

issue server vault serverAuth "DNS:localhost,IP:127.0.0.1"
issue dashboard-api dashboard-api clientAuth "URI:spiffe://$TRUST_DOMAIN/dashboard-api"
issue voice-gateway voice-gateway clientAuth "URI:spiffe://$TRUST_DOMAIN/voice-gateway"
issue mcp-router mcp-router clientAuth "URI:spiffe://$TRUST_DOMAIN/mcp-router"
rm -f ca.srl

echo "Development certificates written to $(pwd) (valid $DAYS days)."

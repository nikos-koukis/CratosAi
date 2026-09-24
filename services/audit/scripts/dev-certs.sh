#!/usr/bin/env bash
# Issues the audit service's DEVELOPMENT server certificate from the Vault's
# development CA (one trust domain for all local services). Never use it
# outside a developer machine.
#
#   ca.pem                        development CA (copied)
#   server.pem, server-key.pem    gRPC listener (localhost, 127.0.0.1)
#   dashboard-api.pem, -key.pem   client: spiffe://jarvis.local/dashboard-api (copied, for grpcurl)
#
# Usage: scripts/dev-certs.sh [vault-certs-dir] [output-dir]
set -euo pipefail

VAULT_CERTS="${1:-../vault/.dev/certs}"
OUT="${2:-.dev/certs}"
DAYS=30

[[ -f $VAULT_CERTS/ca-key.pem ]] || {
  echo "Vault development CA not found in $VAULT_CERTS; start the Vault once first: pnpm nx run vault:serve" >&2
  exit 1
}
mkdir -p "$OUT"
chmod 700 "$OUT"
cp "$VAULT_CERTS/ca.pem" "$VAULT_CERTS/dashboard-api.pem" "$VAULT_CERTS/dashboard-api-key.pem" "$OUT/"
chmod 600 "$OUT/dashboard-api-key.pem"
CA_KEY="$(cd "$VAULT_CERTS" && pwd)/ca-key.pem"
cd "$OUT"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server-key.pem 2>/dev/null
chmod 600 server-key.pem
openssl req -new -key server-key.pem -out server.csr -subj "/CN=audit"
openssl x509 -req -in server.csr -CA ca.pem -CAkey "$CA_KEY" -CAcreateserial -out server.pem -days "$DAYS" 2>/dev/null \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
rm -f server.csr ca.srl

echo "Audit service development certificates written to $(pwd) (valid $DAYS days)."

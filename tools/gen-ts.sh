#!/usr/bin/env bash
# Generates the TypeScript the dashboard uses into <out>/gen/ts (default: this
# repo): the contracts of the services its server calls as dashboard-api.
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:-.}
rm -rf "$out/gen/ts/src"
mkdir -p "$out/gen/ts/src"
pnpm exec buf generate --template buf.gen.es.yaml -o "$out" \
  --path proto/jarvis/common/v1/provider.proto \
  --path proto/jarvis/vault/v1/vault.proto \
  --path proto/jarvis/app/v1/admin.proto \
  --path proto/jarvis/mcp/v1/mcp.proto \
  --path proto/jarvis/audit/v1/audit.proto

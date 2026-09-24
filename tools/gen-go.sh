#!/usr/bin/env bash
# Generates Go code from /proto into <out>/gen/go (default: this repo).
# Plugins are pinned in tools/go/go.mod.
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:-.}
pnpm exec buf generate -o "$out"
pnpm exec buf generate --template buf.gen.connect.yaml --path proto/jarvis/app/v1/app.proto -o "$out"

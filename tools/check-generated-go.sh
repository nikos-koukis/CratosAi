#!/usr/bin/env bash
# Fails if gen/go is stale: regenerates into a temp dir and compares.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tools/gen-go.sh "$tmp" >/dev/null
if ! diff -r "$tmp/gen/go/jarvis" gen/go/jarvis >/dev/null; then
  echo "gen/go is out of date with /proto; run: pnpm nx run proto:generate" >&2
  exit 1
fi

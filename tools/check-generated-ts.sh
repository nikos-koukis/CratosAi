#!/usr/bin/env bash
# Fails if gen/ts is stale: regenerates into a temp dir and compares.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tools/gen-ts.sh "$tmp" >/dev/null
if ! diff -r "$tmp/gen/ts/src" gen/ts/src >/dev/null; then
  echo "gen/ts is out of date with /proto; run: pnpm nx run proto:generate" >&2
  exit 1
fi

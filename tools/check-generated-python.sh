#!/usr/bin/env bash
# Fails if gen/python is stale: regenerates into a temp dir and compares.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tools/gen-python.sh "$tmp" >/dev/null
if ! diff -r -x __pycache__ "$tmp/jarvis" gen/python/jarvis >/dev/null; then
  echo "gen/python is out of date with /proto; run: pnpm nx run proto:generate" >&2
  exit 1
fi

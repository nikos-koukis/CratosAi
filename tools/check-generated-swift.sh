#!/usr/bin/env bash
# Fails if gen/swift is stale: regenerates into a temp dir and compares.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tools/gen-swift.sh "$tmp" >/dev/null
if ! diff -r "$tmp/gen/swift/Sources/JarvisProto" gen/swift/Sources/JarvisProto >/dev/null; then
  echo "gen/swift is out of date with /proto; run: pnpm nx run proto:generate" >&2
  exit 1
fi

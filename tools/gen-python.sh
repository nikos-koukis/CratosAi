#!/usr/bin/env bash
# Generates Python messages (+ .pyi types) and gRPC stubs for /proto into
# gen/python (or the directory given). Generators are pinned in
# gen/python/pyproject.toml (dependency group `codegen`).
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="$(mkdir -p "${1:-gen/python}" && cd "${1:-gen/python}" && pwd)"
rm -rf "$OUT/jarvis"

run() { uv run --quiet --frozen --package jarvis-proto --group codegen "$@"; }
wkt=$(run python -c 'import grpc_tools, os; print(os.path.join(os.path.dirname(grpc_tools.__file__), "_proto"))')
# shellcheck disable=SC2046
if ! log=$(run python -m grpc_tools.protoc -I proto -I "$wkt" \
  --python_out="$OUT" --mypy_out="$OUT" --grpc_python_out="$OUT" --mypy_grpc_out="$OUT" \
  $(cd proto && find jarvis -name '*.proto' | sort) 2>&1); then
  echo "$log" >&2
  exit 1
fi

# Regular packages (with py.typed) so type checkers use the generated .pyi.
find "$OUT/jarvis" -type d -exec touch {}/__init__.py \;
touch "$OUT/jarvis/py.typed"

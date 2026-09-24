#!/usr/bin/env bash
# Calls the development daemon as the orchestrator would (needs grpcurl).
#
#   scripts/grpc.sh GetCapabilities
#   scripts/grpc.sh ExecuteCommand '{"program":"/usr/bin/git","args":["status","--short"]}'
#
# ADDRESS defaults to 127.0.0.1:7443; for tailscale mode pass the tailnet IP,
# e.g. ADDRESS=100.x.y.z:7443 scripts/grpc.sh GetCapabilities
set -euo pipefail

cd "$(dirname "$0")/.."
command -v grpcurl >/dev/null || { echo "grpcurl is required: brew install grpcurl" >&2; exit 1; }

method=${1:?usage: grpc.sh <GetCapabilities|ExecuteCommand> [json]}
body=${2:-'{}'}
certs=.dev/orchestrator

exec grpcurl \
  -cacert "$certs/ca.pem" -cert "$certs/client.pem" -key "$certs/client-key.pem" \
  -servername localhost \
  -d "$body" "${ADDRESS:-127.0.0.1:7443}" "jarvis.device.v1.DeviceService/$method"

#!/usr/bin/env bash
# Generates the Swift messages the apps use into <out>/gen/swift (default:
# this repo): the voice protocol, the app API and the device approval payload.
# The protoc plugin is built from the version pinned in tools/swift.
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:-.}
swift build -c release --product protoc-gen-swift --package-path tools/swift >/dev/null
rm -rf "$out/gen/swift/Sources/JarvisProto"
mkdir -p "$out/gen/swift/Sources/JarvisProto"
pnpm exec buf generate --template buf.gen.swift.yaml -o "$out" \
  --path proto/jarvis/common/v1/provider.proto \
  --path proto/jarvis/voice/v1/voice.proto \
  --path proto/jarvis/device/v1/device.proto \
  --path proto/jarvis/app/v1/app.proto

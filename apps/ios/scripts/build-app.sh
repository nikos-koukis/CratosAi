#!/usr/bin/env bash
# Builds the iPhone app for the simulator. Needs Xcode (not only the Command
# Line Tools) and XcodeGen; without Xcode it says so and succeeds, since
# JarvisKit (everything but the app shell) builds and tests without it.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $(xcode-select -p 2>/dev/null) == */CommandLineTools ]] || ! xcodebuild -version >/dev/null 2>&1; then
  echo "Xcode is not installed or not selected (sudo xcode-select -s /Applications/Xcode.app); skipping the app build."
  exit 0
fi
xcodegen generate --quiet
exec xcodebuild -project Jarvis.xcodeproj -scheme Jarvis -destination 'generic/platform=iOS Simulator' \
  -configuration Debug build CODE_SIGNING_ALLOWED=NO "$@"

#!/usr/bin/env bash
# Runs JarvisKit's tests on macOS. With only the Command Line Tools (no
# Xcode), Swift Testing lives in a framework directory SwiftPM does not search,
# so it is passed explicitly; with Xcode, plain `swift test` works.
set -euo pipefail
cd "$(dirname "$0")/../JarvisKit"
developer=$(xcode-select -p 2>/dev/null || true)
if [[ $developer == */CommandLineTools ]]; then
  frameworks=$developer/Library/Developer/Frameworks
  libraries=$developer/Library/Developer/usr/lib
  exec swift test "$@" \
    -Xswiftc -F -Xswiftc "$frameworks" \
    -Xlinker -F -Xlinker "$frameworks" \
    -Xlinker -rpath -Xlinker "$frameworks" \
    -Xlinker -rpath -Xlinker "$libraries"
fi
exec swift test "$@"

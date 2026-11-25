#!/bin/bash
# Generates the Xcode project and builds the app for the simulator.
# Usage: ios/build.sh [simulator name]
set -euo pipefail
cd "$(dirname "$0")"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
if command -v xcodegen >/dev/null; then xcodegen generate --quiet; else nix shell nixpkgs#xcodegen -c xcodegen generate --quiet; fi
xcodebuild -project Isudo.xcodeproj -scheme Isudo -configuration Debug \
  -destination "platform=iOS Simulator,name=${1:-iPhone 18 Pro}" -derivedDataPath build build 2>&1 \
  | grep -E "^/.*: (error|warning):|^error:|BUILD (SUCCEEDED|FAILED)" | cut -c1-400 | sort -u

#!/bin/bash
# Launches the debug build with sample data and saves screenshots.
# Usage: ios/screenshots.sh OUTPUT_DIR [fixture:appearance ...]
set -euo pipefail
cd "$(dirname "$0")"
BUNDLE_ID=$(sed -n 's/^ISUDO_BUNDLE_ID *= *//p' Local.xcconfig Config.xcconfig 2>/dev/null | head -1)
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
OUT=$1; shift
DEVICE="${ISUDO_SIM:-iPhone 18 Pro}"
APP=build/Build/Products/Debug-iphonesimulator/isudo.app
mkdir -p "$OUT"
xcrun simctl boot "$DEVICE" 2>/dev/null || true
xcrun simctl bootstatus "$DEVICE" -b >/dev/null
xcrun simctl install "$DEVICE" "$APP"
[ $# -gt 0 ] || set -- empty:light quiet:light plain:light plain:dark risky:light risky:dark long:light multi:light waiting:light code:light claimed:light otherphone:light paired:dark simulator:light
for shot in "$@"; do
  fixture=${shot%%:*}; appearance=${shot##*:}
  xcrun simctl terminate "$DEVICE" "$BUNDLE_ID" 2>/dev/null || true
  xcrun simctl launch "$DEVICE" "$BUNDLE_ID" -fixture "$fixture" -appearance "$appearance" >/dev/null
  sleep 3
  xcrun simctl io "$DEVICE" screenshot "$OUT/$fixture-$appearance.png" >/dev/null 2>&1
  echo "$OUT/$fixture-$appearance.png"
done

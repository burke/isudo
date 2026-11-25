#!/bin/bash
# Builds a release of the phone app, with the watch app inside it, and sends
# it to App Store Connect for TestFlight.
#
#   ios/testflight.sh archive     build and sign, locally
#   ios/testflight.sh upload      send the last archive to App Store Connect
#
# TestFlight is the way onto a watch that Xcode cannot reach: nothing has to
# be registered or put in Developer Mode. It needs an app record for your
# bundle identifier in App Store Connect, and Xcode signed in to the account
# that owns it. Uploading creates a distribution certificate and profiles in
# that account if there are none.
set -euo pipefail
cd "$(dirname "$0")"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
# Xcode's packaging step runs `rsync` with options only Apple's understands.
# One from Nix or Homebrew earlier on PATH makes it fail with "Copy failed".
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
TEAM=$(sed -n 's/^DEVELOPMENT_TEAM *= *//p' Local.xcconfig 2>/dev/null | head -1)
[ -n "$TEAM" ] || { echo "set DEVELOPMENT_TEAM in ios/Local.xcconfig first"; exit 1; }
OUT=build/testflight
ARCHIVE="$OUT/isudo.xcarchive"
brief() { grep -E "^/.*: (error|warning):|error:|ARCHIVE (SUCCEEDED|FAILED)|EXPORT (SUCCEEDED|FAILED)|Upload|upload|Uploaded|ITMS" | cut -c1-400 | sort -u; }

case "${1:-}" in
archive)
  # Every upload needs a build number App Store Connect has not seen.
  BUILD="${BUILD_NUMBER:-$(date +%Y%m%d%H%M)}"
  if command -v xcodegen >/dev/null; then xcodegen generate --quiet; else nix shell nixpkgs#xcodegen -c xcodegen generate --quiet; fi
  mkdir -p "$OUT"
  xcodebuild archive -project Isudo.xcodeproj -scheme Isudo -configuration Release \
    -destination 'generic/platform=iOS' -archivePath "$ARCHIVE" -derivedDataPath build \
    -allowProvisioningUpdates CURRENT_PROJECT_VERSION="$BUILD" >"$OUT/archive.log" 2>&1 || { brief <"$OUT/archive.log"; exit 1; }
  echo "archived build $BUILD at ios/$ARCHIVE"
  ;;
upload)
  [ -d "$ARCHIVE" ] || { echo "run 'ios/testflight.sh archive' first"; exit 1; }
  cat >"$OUT/export.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>method</key><string>app-store-connect</string>
	<key>destination</key><string>upload</string>
	<key>teamID</key><string>$TEAM</string>
	<key>signingStyle</key><string>automatic</string>
	<key>manageAppVersionAndBuildNumber</key><false/>
	<key>uploadSymbols</key><true/>
</dict>
</plist>
PLIST
  xcodebuild -exportArchive -archivePath "$ARCHIVE" -exportOptionsPlist "$OUT/export.plist" \
    -exportPath "$OUT/export" -allowProvisioningUpdates >"$OUT/upload.log" 2>&1 || { brief <"$OUT/upload.log"; exit 1; }
  brief <"$OUT/upload.log"
  echo "uploaded. It appears in TestFlight once App Store Connect has processed it."
  ;;
*)
  echo "usage: ios/testflight.sh archive|upload"; exit 1 ;;
esac

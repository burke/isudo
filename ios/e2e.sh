#!/bin/bash
# A real end-to-end pass: the app in the Simulator, a local relay, and a
# development build of isudo. Pairs (with the typed code), approves one
# command and denies another, all through the app's interface.
#
# Needs the Rust binaries in ../target/debug, including the development
# build `isudo-dev` (cargo build -p isudo --features dev-unprivileged).
# Usage: ios/e2e.sh
set -u
cd "$(dirname "$0")"
BUNDLE_ID=$(sed -n 's/^ISUDO_BUNDLE_ID *= *//p' Local.xcconfig Config.xcconfig 2>/dev/null | head -1)
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
B=$(cd ../target/debug && pwd); D=$(mktemp -d); PORT=18799
DEVICE="${ISUDO_SIM:-iPhone 18 Pro}"
cleanup() { kill $(jobs -p) 2>/dev/null; }
trap cleanup EXIT
await() { for _ in $(seq $(( $2 * 4 ))); do [ -s "$1" ] && return 0; sleep 0.25; done; echo "FAIL: timed out waiting for $(basename "$1")"; return 1; }

ISUDO_RELAY_LISTEN=127.0.0.1:$PORT "$B/isudo-relay" 2>"$D/relay.log" &
sleep 1
mkfifo "$D/code"
"$B/isudo-admin" pair --relay http://127.0.0.1:$PORT --config "$D/pairing.conf" --name e2e-host <"$D/code" >"$D/admin.out" 2>&1 &
ADMIN=$!
exec 3>"$D/code"
for _ in $(seq 50); do grep -q '^isudo://pair' "$D/admin.out" 2>/dev/null && break; sleep 0.1; done
grep '^isudo://pair' "$D/admin.out" > "$D/link.txt" || { echo "FAIL: no pairing link"; exit 1; }

xcrun simctl boot "$DEVICE" 2>/dev/null; xcrun simctl bootstatus "$DEVICE" -b >/dev/null
xcrun simctl uninstall "$DEVICE" "$BUNDLE_ID" 2>/dev/null
# Enrol a face in the Simulator, so that approving asks for Face ID.
xcrun simctl spawn "$DEVICE" notifyutil -s com.apple.BiometricKit.enrollmentChanged 1
xcrun simctl spawn "$DEVICE" notifyutil -p com.apple.BiometricKit.enrollmentChanged
# Presents a matching face a few times once the app has asked for one.
face() { await "$1" 90 || return 1; for _ in 1 2 3 4 5 6; do sleep 1; xcrun simctl spawn "$DEVICE" notifyutil -p com.apple.BiometricKit_Sim.pearl.match; done; }
TEST_RUNNER_ISUDO_E2E_DIR="$D" xcodebuild test -project Isudo.xcodeproj -scheme Isudo \
  -destination "platform=iOS Simulator,name=$DEVICE" -derivedDataPath build \
  -only-testing:IsudoUITests/EndToEndTests >"$D/xcodebuild.log" 2>&1 &
TEST=$!

await "$D/code.txt" 240 || { tail -30 "$D/xcodebuild.log"; exit 1; }
echo "code shown by the app: $(cat "$D/code.txt")"
cat "$D/code.txt" >&3; echo >&3
wait $ADMIN; echo "isudo-admin exit: $?"; tail -1 "$D/admin.out"
exec 3>&-
await "$D/paired.txt" 60 || exit 1

run() { ISUDO_DEV_CONFIG="$D/pairing.conf" ISUDO_DEV_HELPER="$B/isudo-helper" "$B/isudo-dev" "$@"; }
face "$D/approve-tapped.txt" &
OUT=$(run echo e2e-approved 2>"$D/approve.err"); CODE=$?
echo "approved command: exit $CODE, output: $OUT"
await "$D/approved.txt" 60 || exit 1
face "$D/deny-tapped.txt" &
run echo e2e-denied >"$D/deny.out" 2>"$D/deny.err"; CODE2=$?
echo "denied command: exit $CODE2, $(grep denied "$D/deny.err")"
wait $TEST; TESTCODE=$?
grep -E "Test Case.*(passed|failed)|error:" "$D/xcodebuild.log" | cut -c1-200
[ "$OUT" = "e2e-approved" ] && [ $CODE -eq 0 ] && [ $CODE2 -eq 1 ] && grep -q 'use staging' "$D/deny.err" && [ ! -s "$D/deny.out" ] && [ $TESTCODE -eq 0 ] \
  && echo "E2E PASS" || { echo "E2E FAIL (logs in $D)"; exit 1; }


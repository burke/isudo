#!/bin/bash
# The watch, end to end, in Simulators: a phone and its paired watch, a
# local relay, and a development build of isudo. The phone pairs with the
# computer and authorises the watch; the watch then approves one command by
# holding its button, and denies another that only the phone could approve.
# Both apps are driven only through their interfaces.
#
# Needs the Rust binaries in ../target/debug, including `isudo-dev`
# (cargo build -p isudo --features dev-unprivileged), and a watch Simulator
# paired with a phone Simulator (xcrun simctl list pairs).
# Usage: ios/e2e-watch.sh
set -u
cd "$(dirname "$0")"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
B=$(cd ../target/debug && pwd); D=$(mktemp -d); PORT=18798
PHONE="${ISUDO_SIM:-iPhone Air}"
WATCH="${ISUDO_WATCH_SIM:-Apple Watch Series 12 (42mm)}"
PIDS=()
cleanup() { kill "${PIDS[@]}" 2>/dev/null; }
trap cleanup EXIT
await() { for _ in $(seq $(( $2 * 4 ))); do [ -s "$1" ] && return 0; sleep 0.25; done; echo "FAIL: timed out waiting for $(basename "$1")"; return 1; }
# What each app logged about its link to the other.
links() {
  xcrun simctl spawn "$PHONE" log show --last 6m --style compact --predicate 'category == "watch"' 2>/dev/null | grep "link\|watch" | tail -6 | cut -c1-200
  xcrun simctl spawn "$WATCH" log show --last 6m --style compact --predicate 'category == "phone"' 2>/dev/null | grep "link" | tail -4 | cut -c1-200
}
fail() {
  echo "E2E-WATCH FAIL: $1 (logs in $D)"
  grep -hE "error:|XCTAssert|failed" "$D"/*.log 2>/dev/null | cut -c1-220 | tail -12
  links
  exit 1
}

echo "== build"
if command -v xcodegen >/dev/null; then xcodegen generate --quiet; else nix shell nixpkgs#xcodegen -c xcodegen generate --quiet; fi
xcodebuild build-for-testing -project Isudo.xcodeproj -scheme Isudo \
  -destination "platform=iOS Simulator,name=$PHONE" -derivedDataPath build >"$D/build-phone.log" 2>&1 || fail "the phone app did not build"
xcodebuild build-for-testing -project Isudo.xcodeproj -scheme IsudoWatch \
  -destination "platform=watchOS Simulator,name=$WATCH" -derivedDataPath build >"$D/build-watch.log" 2>&1 || fail "the watch app did not build"

echo "== computer"
ISUDO_RELAY_LISTEN=127.0.0.1:$PORT ISUDO_RELAY_STATE="$D/relay.json" "$B/isudo-relay" 2>"$D/relay.log" & PIDS+=($!)
sleep 1
mkfifo "$D/code"
"$B/isudo-admin" pair --relay http://127.0.0.1:$PORT --config "$D/pairing.conf" --name e2e-host <"$D/code" >"$D/admin.out" 2>&1 &
ADMIN=$!; PIDS+=($ADMIN)
exec 3>"$D/code"
for _ in $(seq 50); do grep -q '^isudo://pair' "$D/admin.out" 2>/dev/null && break; sleep 0.1; done
grep '^isudo://pair' "$D/admin.out" > "$D/link.txt" || fail "no pairing link"

echo "== simulators"
xcrun simctl boot "$PHONE" 2>/dev/null; xcrun simctl boot "$WATCH" 2>/dev/null
xcrun simctl bootstatus "$PHONE" -b >/dev/null; xcrun simctl bootstatus "$WATCH" -b >/dev/null
BUNDLE_ID=$(sed -n 's/^ISUDO_BUNDLE_ID *= *//p' Local.xcconfig Config.xcconfig 2>/dev/null | head -1)
xcrun simctl uninstall "$PHONE" "$BUNDLE_ID" 2>/dev/null; xcrun simctl uninstall "$WATCH" "$BUNDLE_ID.watch" 2>/dev/null
xcrun simctl spawn "$PHONE" notifyutil -s com.apple.BiometricKit.enrollmentChanged 1
xcrun simctl spawn "$PHONE" notifyutil -p com.apple.BiometricKit.enrollmentChanged
# Presents a matching face to the phone a few times.
face() { for _ in 1 2 3 4 5 6; do sleep 1; xcrun simctl spawn "$PHONE" notifyutil -p com.apple.BiometricKit_Sim.pearl.match; done; }

echo "== watch app, then phone app"
TEST_RUNNER_ISUDO_E2E_DIR="$D" xcodebuild test-without-building -project Isudo.xcodeproj -scheme IsudoWatch \
  -destination "platform=watchOS Simulator,name=$WATCH" -derivedDataPath build \
  -only-testing:IsudoWatchUITests/WatchApproveTests >"$D/test-watch.log" 2>&1 &
WTEST=$!; PIDS+=($WTEST)
TEST_RUNNER_ISUDO_E2E_DIR="$D" xcodebuild test-without-building -project Isudo.xcodeproj -scheme Isudo \
  -destination "platform=iOS Simulator,name=$PHONE" -derivedDataPath build \
  -only-testing:IsudoUITests/WatchEndToEndTests >"$D/test-phone.log" 2>&1 &
PTEST=$!; PIDS+=($PTEST)

await "$D/code.txt" 300 || fail "the phone never showed a pairing code"
cat "$D/code.txt" >&3; echo >&3
wait $ADMIN || fail "pairing did not complete"
exec 3>&-
echo "paired: $(tail -1 "$D/admin.out")"

echo "== the phone authorises the watch"
await "$D/watch-open.txt" 300 || fail "the watch app never opened"
# Each time the phone asks, present a face for its signature.
( for attempt in 1 2 3 4 5 6; do
    await "$D/watch-tapped-$attempt.txt" 400 >/dev/null || exit; face
  done ) & PIDS+=($!)
await "$D/watch-allowed.txt" 300 || fail "the phone never finished allowing the watch"
await "$D/watch-ready.txt" 60 || fail "the watch never received its authorisation"
"$B/isudo-admin" watch on --config "$D/pairing.conf" | head -1

# With no input attached: input arriving on a pipe is one of the things that
# makes a request the phone's alone to approve.
run() { ISUDO_DEV_CONFIG="$D/pairing.conf" ISUDO_DEV_HELPER="$B/isudo-helper" "$B/isudo-dev" "$@" </dev/null; }
echo "== a simple request, approved on the watch"
OUT=$(run echo e2e-watch 2>"$D/approve.err"); CODE=$?
echo "exit $CODE, output: $OUT"
grep -q "or its watch" "$D/approve.err" || fail "the computer did not mark the request as one a watch may approve"
await "$D/watch-approved.txt" 60 || fail "the watch never showed the approval"

echo "== a request only the phone may approve, denied on the watch"
run DEBUG=1 echo e2e-phone-only >"$D/deny.out" 2>"$D/deny.err"; CODE2=$?
echo "exit $CODE2, $(grep denied "$D/deny.err")"
grep -q "or its watch" "$D/deny.err" && fail "the computer marked a phone-only request for the watch"
await "$D/watch-denied.txt" 60 || fail "the watch never showed the denial"

echo done > "$D/finished.txt"
wait $WTEST; WCODE=$?; wait $PTEST; PCODE=$?
grep -hE "Test Case.*(passed|failed)" "$D/test-watch.log" "$D/test-phone.log" | cut -c1-160
[ "$OUT" = "e2e-watch" ] && [ $CODE -eq 0 ] && [ $CODE2 -eq 1 ] && grep -q 'denied on .*: "Ask me on my phone"' "$D/deny.err" \
  && [ ! -s "$D/deny.out" ] && [ $WCODE -eq 0 ] && [ $PCODE -eq 0 ] \
  && echo "E2E-WATCH PASS" || fail "see above"

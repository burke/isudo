#!/bin/bash
# Real setuid-root integration test, run as root inside a Linux container:
#
#   docker run --rm -v "$PWD":/src:ro -v isudo-target:/target \
#     -v isudo-registry:/usr/local/cargo/registry rust:1 bash /src/tests/setuid/run.sh
#
# It builds the release binaries, installs isudo setuid root, pairs with the
# terminal test phone through a local relay, and then checks what an
# unprivileged user can and cannot make happen.
set -u
export CARGO_TARGET_DIR=/target
PORT=8787
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok    $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL  $1"; [ -n "${2:-}" ] && echo "$2" | sed 's/^/        | /'; }
check() { # check NAME EXPECTED_SUBSTRING ACTUAL
  case "$3" in *"$2"*) ok "$1";; *) bad "$1" "wanted: $2
got: $3";; esac; }
refute() { case "$3" in *"$2"*) bad "$1" "must not contain: $2
got: $3";; *) ok "$1";; esac; }

echo "== build"
cd /src
cargo build --release --locked --workspace 2>&1 | tail -2
[ -x /target/release/isudo ] || { echo "build failed"; exit 1; }

echo "== install"
install -d /usr/local/libexec /etc/isudo
install -o root -g root -m 4755 /target/release/isudo /usr/local/bin/isudo
install -o root -g root -m 0755 /target/release/isudo-helper /usr/local/libexec/isudo-helper
for b in isudo-admin isudo-relay isudo-devphone; do install -m 0755 /target/release/$b /usr/local/bin/$b; done
useradd -m -u 1000 agent 2>/dev/null
D=$(mktemp -d); chmod 755 $D
as_agent() { setpriv --reuid 1000 --regid 1000 --init-groups --inh-caps=-all env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/home/agent "$@"; }

ISUDO_RELAY_LISTEN=127.0.0.1:$PORT isudo-relay 2>$D/relay.log &
sleep 1

echo "== installation"
OUT=$(isudo-admin check 2>&1); check "the installation passes its own check" "All good." "$OUT"

echo "== before pairing"
OUT=$(as_agent isudo true 2>&1); check "unpaired machine explains itself" "isudo-admin pair" "$OUT"
OUT=$(as_agent isudo-admin pair --relay http://127.0.0.1:$PORT 2>&1); check "pairing requires root" "must be run as root" "$OUT"

echo "== pair"
mkfifo $D/code
isudo-admin pair --relay http://127.0.0.1:$PORT --name testbox --timeout 20 <$D/code >$D/admin.out 2>&1 &
ADMIN=$!
exec 3>$D/code
for i in $(seq 50); do grep -q '^isudo://pair' $D/admin.out 2>/dev/null && break; sleep 0.1; done
LINK=$(grep '^isudo://pair' $D/admin.out)
isudo-devphone pair "$LINK" --state $D/phone.json --name "Test Phone" >$D/phone.out 2>&1 &
PHONE=$!
for i in $(seq 50); do grep -q 'Type this code' $D/phone.out 2>/dev/null && break; sleep 0.1; done
grep 'Type this code' $D/phone.out | grep -oE '[0-9]{3} [0-9]{3}' >&3
wait $ADMIN; A=$?; wait $PHONE; P=$?; exec 3>&-
[ $A = 0 ] && [ $P = 0 ] && ok "pairing completes" || bad "pairing completes" "$(cat $D/admin.out $D/phone.out)"
check "pairing file is root-only" "-rw------- 1 root root" "$(ls -l /etc/isudo/pairing.conf)"
OUT=$(as_agent cat /etc/isudo/pairing.conf 2>&1); check "agent cannot read the host key" "Permission denied" "$OUT"

# Start the test phone for one request; `settle` waits for it to finish.
approve() { isudo-devphone watch --state $D/phone.json --approve --once >$D/watch.out 2>&1 & WATCH=$!; sleep 0.3; }
deny()    { isudo-devphone watch --state $D/phone.json "--deny=$1" --once >$D/watch.out 2>&1 & WATCH=$!; sleep 0.3; }
settle()  { wait $WATCH 2>/dev/null; }

echo "== approved command runs as root, fully"
approve; OUT=$(as_agent isudo id 2>&1); settle
check "uid, gid and groups are root's" "uid=0(root) gid=0(root) groups=0(root)" "$OUT"
approve; OUT=$(as_agent isudo sh -c 'grep -E "^(Uid|Gid|Groups):" /proc/self/status' 2>&1); settle
check "real, effective and saved uid are 0" "$(printf 'Uid:\t0\t0\t0\t0')" "$OUT"
check "real, effective and saved gid are 0" "$(printf 'Gid:\t0\t0\t0\t0')" "$OUT"
approve; OUT=$(as_agent isudo sh -c 'echo "$SUDO_USER:$SUDO_UID:$USER:$HOME:$PATH"' 2>&1); settle
check "environment is constructed" "agent:1000:root:/root:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "$OUT"
approve; as_agent isudo sh -c 'exit 7' 2>/dev/null; RC=$?; settle
[ $RC = 7 ] && ok "exit status is the command's" || bad "exit status is the command's" "got $RC"

echo "== denial"
deny "use staging"; OUT=$(as_agent isudo id 2>&1); RC=$?; settle
check "denied command reports the signed reason" 'denied on Test Phone: "use staging"' "$OUT"
refute "denied command did not run" "uid=0" "$OUT"
[ $RC = 1 ] && ok "denial exits 1" || bad "denial exits 1" "got $RC"

echo "== hostile inherited state"
approve; OUT=$(as_agent env LD_PRELOAD=/tmp/evil.so LD_LIBRARY_PATH=/tmp BASH_ENV=/tmp/evil PYTHONPATH=/tmp SECRET=x isudo env 2>&1); settle
refute "LD_PRELOAD is not passed" "LD_PRELOAD" "$OUT"
refute "LD_LIBRARY_PATH is not passed" "LD_LIBRARY_PATH" "$OUT"
refute "BASH_ENV is not passed" "BASH_ENV" "$OUT"
refute "unnamed variables are not passed" "SECRET" "$OUT"
approve; OUT=$(as_agent env FOO=bar isudo --preserve-env=FOO DEBUG=1 env 2>&1); settle
check "named variables are passed" "FOO=bar" "$OUT"; check "assigned variables are passed" "DEBUG=1" "$OUT"
check "the phone was shown them" "sets FOO=bar" "$(cat $D/watch.out)"
approve; OUT=$(as_agent bash -c 'exec 7</etc/hostname 8</etc/hostname; isudo ls /proc/self/fd' 2>&1); settle
refute "inherited descriptors are closed" "7" "$(echo "$OUT" | grep -v isudo: | tr '\n' ' ')"
approve; OUT=$(as_agent bash -c 'exec 0<&-; isudo sh -c "ls -l /proc/self/fd/0"' 2>&1); settle
# glibc reopens a closed stdin on /dev/full, write-only, so that reads fail.
check "a closed stdin is reopened on a harmless device" "/proc/self/fd/0 -> /dev/" "$OUT"
refute "a closed stdin is not left for the command to reuse" "No such file" "$OUT"
approve; OUT=$(as_agent bash -c 'umask 000; isudo sh -c umask' 2>&1); settle
check "umask is reset" "0022" "$OUT"
approve; OUT=$(as_agent bash -c 'trap "" PIPE CHLD HUP TERM; isudo sh -c "grep SigIgn /proc/self/status"' 2>&1); settle
check "ignored signals are not passed on" "SigIgn:	0000000000000000" "$OUT"
# With SIGCHLD ignored the kernel reaps children itself; isudo must not
# depend on, or be confused by, the disposition it was started with.
approve; OUT=$(as_agent bash -c 'trap "" CHLD; isudo id' 2>&1); settle
check "an ignored SIGCHLD changes nothing" "uid=0(root)" "$OUT"
approve; OUT=$(as_agent bash -c 'cd /tmp && printf "#!/bin/sh\necho hijacked\n" > id && chmod +x id && PATH=/tmp:$PATH isudo id' 2>&1); settle
refute "the caller's PATH is not searched" "hijacked" "$OUT"; check "the secure path is" "uid=0" "$OUT"
approve; OUT=$(as_agent bash -c 'cd /tmp && isudo ./id' 2>&1); settle
check "a caller-writable program is flagged to the approver" "can be changed without root" "$(cat $D/watch.out)"

echo "== the caller learns nothing it could not see for itself"
install -d -m 0700 /root/hidden
install -m 0755 /usr/bin/id /root/hidden/tool
install -m 0644 /etc/hostname /root/hidden/plain
for name in tool plain missing; do
  OUT=$(as_agent isudo /root/hidden/$name 2>&1); RC=$?
  check "a path in a directory the caller cannot enter is just not found ($name)" "command not found" "$OUT"
  [ $RC = 127 ] && ok "and exits 127 ($name)" || bad "and exits 127 ($name)" "got $RC"
done

echo "== a writable directory on the search path is skipped"
cp /etc/isudo/pairing.conf $D/before-path.conf
sed -i 's|^secure_path = .*|secure_path = /home/agent/bin:/usr/local/bin:/usr/bin:/bin|' /etc/isudo/pairing.conf
as_agent bash -c 'mkdir -p ~/bin && printf "#!/bin/sh\necho hijacked\n" > ~/bin/id && chmod +x ~/bin/id'
approve; OUT=$(as_agent isudo id 2>&1); settle
refute "a command planted in a caller-owned search directory is not run" "hijacked" "$OUT"
check "the real command is found further along" "uid=0(root)" "$OUT"
cp $D/before-path.conf /etc/isudo/pairing.conf

echo "== while waiting"
as_agent isudo sleep 30 >$D/wait.out 2>&1 &
WAITER=$!
sleep 1.5
PS=$(ps -eo ruid,euid,comm | grep -E 'isudo( |$)|isudo-helper')
check "isudo waits as real root" "    0     0 isudo" "$PS"
check "the helper runs as the caller" " 1000  1000 isudo-helper" "$PS"
ISUDO_PID=$(pgrep -x isudo | head -1)
OUT=$(as_agent kill -STOP $ISUDO_PID 2>&1); check "the caller cannot signal isudo" "not permitted" "$OUT"
as_agent pkill -x isudo-helper; wait $WAITER 2>/dev/null
check "killing the helper cancels the request" "not approved" "$(cat $D/wait.out)"
pgrep -x isudo >/dev/null && bad "isudo exited after cancel" || ok "isudo exited after cancel"
pgrep -x sleep >/dev/null && bad "the command never ran" || ok "the command never ran"

echo "== timeout"
START=$(date +%s); OUT=$(as_agent isudo id 2>&1); RC=$?; TOOK=$(( $(date +%s) - START ))
check "an unanswered request times out" "no answer before the timeout" "$OUT"
refute "a timed-out command did not run" "uid=0" "$OUT"
[ $TOOK -ge 19 ] && [ $TOOK -le 32 ] && ok "timeout is honoured (${TOOK}s)" || bad "timeout is honoured" "took ${TOOK}s"
pgrep -x isudo-helper >/dev/null && bad "no helper is left behind" || ok "no helper is left behind"

echo "== a late or replayed approval is useless"
# The phone approves a request whose process has already gone.
as_agent isudo id >$D/gone.out 2>&1 &
GONE=$!
sleep 1; as_agent pkill -x isudo-helper; wait $GONE
isudo-devphone watch --state $D/phone.json --approve --once >$D/late.out 2>&1 &
LATE=$!
sleep 2.5; kill $LATE 2>/dev/null; wait $LATE 2>/dev/null
refute "an approval for a dead request runs nothing" "uid=0" "$(cat $D/gone.out)"

echo "== sandboxes and misconfiguration"
OUT=$(as_agent setpriv --no-new-privs isudo id 2>&1); check "no_new_privs is explained" "no new privileges" "$OUT"
refute "no_new_privs runs nothing" "uid=0" "$OUT"
chmod 644 /etc/isudo/pairing.conf
OUT=$(as_agent isudo id 2>&1); check "a readable pairing file is refused" "readable only by root" "$OUT"
chmod 600 /etc/isudo/pairing.conf; chown 1000 /etc/isudo/pairing.conf
OUT=$(as_agent isudo id 2>&1); check "a pairing file not owned by root is refused" "owned by root" "$OUT"
chown root /etc/isudo/pairing.conf
cp /etc/isudo/pairing.conf $D/saved.conf
# Pin a different, valid key: the phone's encryption key is a P-256 point
# too, and the phone's signatures certainly do not verify under it.
OTHER=$(grep '^phone_kem_pub' /etc/isudo/pairing.conf | cut -d' ' -f3)
sed -i "s/^phone_sign_pub = .*/phone_sign_pub = $OTHER/" /etc/isudo/pairing.conf
grep -q "^phone_sign_pub = $OTHER" /etc/isudo/pairing.conf && ok "a different key is pinned for this test" || bad "a different key is pinned for this test"
approve; OUT=$(as_agent isudo id 2>&1); settle
check "an approval from a key other than the pinned one is called out" "not signed by the paired phone" "$OUT"
refute "an approval from a key other than the pinned one runs nothing" "uid=0" "$OUT"
# A pinned key that is not a curve point at all is refused before asking.
sed -i 's/^phone_sign_pub = ....\(.*\)/phone_sign_pub = 04ff\1/' /etc/isudo/pairing.conf
grep '^phone_sign_pub' /etc/isudo/pairing.conf | cut -c1-30
OUT=$(as_agent isudo id 2>&1); check "an invalid pinned key is refused" "invalid phone key" "$OUT"
cp $D/saved.conf /etc/isudo/pairing.conf
OUT=$(as_agent isudo -u nobody id 2>&1); check "other target users are refused" "only runs commands as root" "$OUT"
OUT=$(as_agent isudo -E id 2>&1); check "passing the whole environment is refused" "preserve-env=NAME" "$OUT"

echo "== a watch the phone authorised"
# The stand-in watch has keys of its own and the phone's signature over them.
as_watch() { isudo-devphone watch --state $D/watch.json "$@" --once >$D/wwatch.out 2>&1 & WWATCH=$!; sleep 0.3; }
OUT=$(as_agent isudo-admin watch on 2>&1); check "only root can turn the watch on" "must be run as root" "$OUT"
OUT=$(isudo-devphone add-watch $D/watch.json --state $D/phone.json --name "Test Watch" 2>&1)
check "the phone authorises a watch" "Authorised Test Watch" "$OUT"
# Authorised by the phone, but root has not allowed a watch: it is sent nothing.
as_watch --approve; approve; OUT=$(as_agent isudo id 2>&1); settle; kill $WWATCH 2>/dev/null; wait $WWATCH 2>/dev/null
check "with the watch off, the phone still approves" "uid=0(root)" "$OUT"
refute "with the watch off, the watch is shown nothing" "wants to run" "$(cat $D/wwatch.out)"
OUT=$(isudo-admin watch on 2>&1); check "root turns the watch on" "may now approve simple requests" "$OUT"
grep -q '^watch = yes$' /etc/isudo/pairing.conf && ok "the setting is in the root-owned pairing file" || bad "the setting is in the root-owned pairing file"
[ "$(stat -c '%U:%a' /etc/isudo/pairing.conf)" = "root:600" ] && ok "the pairing file is still root's alone" || bad "the pairing file is still root's alone" "$(stat -c '%U:%a' /etc/isudo/pairing.conf)"
OUT=$(isudo-admin status 2>&1); check "status says the watch is allowed" "Watch:        allowed" "$OUT"
# A simple request: the watch alone approves it, and it runs as root.
as_watch --approve; OUT=$(as_agent isudo id 2>&1); wait $WWATCH 2>/dev/null
check "a simple request approved on the watch runs as root" "uid=0(root) gid=0(root)" "$OUT"
check "the caller is told that a watch may answer this one" "or its watch (up to" "$OUT"
check "the watch showed the request" "wants to run as root" "$(cat $D/wwatch.out)"
# A request naming a variable is one only the phone may approve.
as_watch --approve; (sleep 2; isudo-devphone watch --state $D/phone.json --approve --once >$D/watch.out 2>&1) & LATE=$!
OUT=$(as_agent isudo DEBUG=1 id 2>&1); wait $WWATCH $LATE 2>/dev/null
check "the watch will not approve what only the phone may" "only the phone may approve this" "$(cat $D/wwatch.out)"
check "and the phone then approves it" "uid=0(root)" "$OUT"
refute "the caller is not told a watch may answer what only the phone may" "or its watch" "$OUT"
# The same for a program that could be replaced without root.
as_watch --approve; (sleep 2; isudo-devphone watch --state $D/phone.json --approve --once >$D/watch.out 2>&1) & LATE=$!
OUT=$(as_agent bash -c 'cd /tmp && isudo ./id' 2>&1); wait $WWATCH $LATE 2>/dev/null
check "nor a program that can be changed without root" "only the phone may approve this" "$(cat $D/wwatch.out)"
# A watch may deny anything, and the caller is told which device said no.
as_watch "--deny=not from my wrist"; OUT=$(as_agent isudo id 2>&1); RC=$?; wait $WWATCH 2>/dev/null
check "a denial on the watch reports the watch and its signed reason" 'denied on Test Watch: "not from my wrist"' "$OUT"
refute "a command denied on the watch did not run" "uid=0" "$OUT"
[ $RC = 1 ] && ok "a denial on the watch exits 1" || bad "a denial on the watch exits 1" "got $RC"
as_watch --deny; OUT=$(as_agent isudo DEBUG=1 id 2>&1); wait $WWATCH 2>/dev/null
check "a watch may deny what it could not approve, and a bare denial says so" "denied on Test Watch (no reason given)" "$OUT"
OUT=$(isudo-admin watch off 2>&1); check "root turns the watch off" "Only Test Phone can answer now" "$OUT"
as_watch --approve; approve; OUT=$(as_agent isudo id 2>&1); settle; kill $WWATCH 2>/dev/null; wait $WWATCH 2>/dev/null
refute "once off, the watch is shown nothing again" "wants to run" "$(cat $D/wwatch.out)"
check "and the phone carries on" "uid=0(root)" "$OUT"

echo "== unpair"
isudo-admin unpair >/dev/null 2>&1
OUT=$(as_agent isudo id 2>&1); check "after unpairing nothing can be approved" "isudo-admin pair" "$OUT"

kill $(jobs -p) 2>/dev/null
echo
echo "passed: $PASS   failed: $FAIL"
[ $FAIL = 0 ]

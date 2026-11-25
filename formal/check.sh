#!/bin/sh
# Checks the symbolic models of isudo's protocols with ProVerif.
#
#   ./formal/check.sh          (needs proverif on PATH, e.g. `nix shell nixpkgs#proverif`)
#
# Three runs:
#   1. isudo.pv, the protocol as implemented. Its seven properties must be
#      proved, and its two sanity events must be reachable (so the proofs
#      are not about a protocol that can never complete).
#   2. pairing-v0.pv, the first pairing design. Its property must FAIL: that
#      is the attack the acknowledgement step was added to stop.
#   3. pairing-v1.pv, the second pairing design. Its property must FAIL too:
#      that is the attack the commitment was added to stop, which an earlier
#      version of the model missed by assuming too little of the attacker.
# Keeping the failing runs shows the model is able to find both attacks.
set -eu
cd "$(dirname "$0")"

results() { proverif "$1" | grep '^RESULT'; }

echo "== isudo.pv (as implemented)"
out=$(results isudo.pv)
echo "$out"
proved=$(echo "$out" | grep -c ' is true\.$' || true)
reachable=$(echo "$out" | grep -c '^RESULT not event.* is false\.$' || true)
total=$(echo "$out" | grep -c '^RESULT' || true)
[ "$proved" = 7 ] || { echo "expected 7 proved properties, got $proved"; exit 1; }
[ "$reachable" = 2 ] || { echo "expected 2 reachable sanity events, got $reachable"; exit 1; }
[ "$total" = 9 ] || { echo "expected 9 results in all, got $total"; exit 1; }

echo "== pairing-v0.pv (the first design; its property must fail)"
out=$(results pairing-v0.pv)
echo "$out"
echo "$out" | grep -q 'event(Pinned(.*)) ==> event(PhoneScanned(.*)) is false\.$' \
  || { echo "expected the pinning property to fail in the first design"; exit 1; }

echo "== pairing-v1.pv (the second design; its property must fail)"
out=$(results pairing-v1.pv)
echo "$out"
echo "$out" | grep -q 'event(Pinned(.*)) ==> event(PhoneKey(.*)) is false\.$' \
  || { echo "expected the pinning property to fail in the second design"; exit 1; }

echo "ok"

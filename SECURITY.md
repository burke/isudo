# Security

isudo installs a setuid-root program and decides when commands run as root.
Reports of anything that weakens that are very welcome.

## Reporting

Please report privately, not in a public issue: use **Report a
vulnerability** under this repository's Security tab (GitHub private
vulnerability reporting). Include what you did, what happened, and the
platform. A proof of concept helps but is not required.

## What isudo is meant to guarantee

Against an unprivileged local user (often an AI agent running as the same
user as the person at the keyboard) who can run `isudo` with any arguments,
environment, working directory, open files, limits and signal state, can
tamper with the unprivileged helper, and controls the relay and the network:

1. A command runs as root only if the paired phone's key signed an approval
   of that exact request (or, within the limits of point 7, the key of a
   watch that phone authorised did), and the path, arguments and environment
   executed are the ones in the signed request.
2. Nothing short of that signature makes root code execute, read or write
   anything.
3. An approval cannot be used twice, for a different invocation, or after
   the window the approver was shown.
4. Text shown to the caller as a denial reason was signed by the phone.
   Nothing the relay or the helper says reaches the caller's terminal as
   free text.
5. Every failure before `execve` ends without running the command.
6. The computer pins a phone's key only if that phone read this computer's
   pairing code and is the one whose six digits the person at the computer
   typed. This holds against someone who runs the relay, saw the pairing
   code, and can put a pairing code of their own in front of the phone (a
   link, a synced clipboard, another QR code). Their one remaining move is a
   blind guess at six digits: one chance in a million, and each try needs
   the person to agree on the phone and then type a code that fails.

7. If a watch is in use: a command runs on a watch's approval only if root
   on the computer has allowed a watch, the computer itself marked that
   request as one a watch may approve, the paired phone signed for that
   watch's key for this pairing, and that signature has not run out. A watch
   can do nothing a phone could not, and nobody but the paired phone can
   appoint one: not the relay, not the watch itself, not someone holding
   the computer's key.

A way to break any of these is a vulnerability.

## What is out of scope

These are documented limits, not bugs:

- Files named by an approved request changing between approval and
  execution. The phone warns when a program or its directory can be changed
  without root; it cannot freeze the filesystem.
- Other routes to root on the same machine (passwordless `sudo`, the
  `docker` group, a writable shell startup file).
- A person approving a request without reading it.
- What an authorised watch does within its limits. A watch cannot check a
  face: whoever is wearing your unlocked watch can approve a simple request
  on it. If a watch is lost, turn the watch off on each computer (`sudo
  isudo-admin watch off`, effective at once); the phone's permission
  otherwise lasts until it runs out, up to ninety days, whatever the relay
  is told.
- Pairing while something hostile can type into the terminal running
  `isudo-admin pair`. Pairing takes whoever types the six digits to be the
  person holding the phone. (Anything that can do that can usually ride the
  `sudo` session you paired with anyway.)
- A phone paired with something other than your computer. Anyone can write
  a pairing code, and a phone that answers one will show that "computer's"
  requests. The app asks before answering a pairing code and says when one
  arrived as a link. Approvals given to such a pairing mean nothing to any
  real computer.
- Denial of service by the relay, the network or the helper: any of them
  can stop approvals arriving.
- An attacker who already has root, or the phone's unlocked Secure Enclave
  key.

## Where to look

`crates/isudo` is the only code that runs as root. `crates/core` holds the
decisions it relies on, with no `unsafe` and no I/O. `formal/isudo.pv` is
the protocol model, and `crates/sim/src/pairing_tests.rs` replays the known
pairing attacks against the real code. `tests/setuid/run.sh` is the test
that runs the real setuid binary.

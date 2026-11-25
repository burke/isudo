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
   of that exact request, and the path, arguments and environment executed
   are the ones in the signed request.
2. Nothing short of that signature makes root code execute, read or write
   anything.
3. An approval cannot be used twice, for a different invocation, or after
   the window the approver was shown.
4. Text shown to the caller as a denial reason was signed by the phone.
   Nothing the relay or the helper says reaches the caller's terminal as
   free text.
5. Every failure before `execve` ends without running the command.
6. The computer pins a phone's key only if that phone is the one whose code
   the person at the computer typed, even against someone who runs the relay
   and saw the QR code.

A way to break any of these is a vulnerability.

## What is out of scope

These are documented limits, not bugs:

- Files named by an approved request changing between approval and
  execution. The phone warns when a program or its directory can be changed
  without root; it cannot freeze the filesystem.
- Other routes to root on the same machine (passwordless `sudo`, the
  `docker` group, a writable shell startup file).
- A person approving a request without reading it.
- Denial of service by the relay, the network or the helper: any of them
  can stop approvals arriving.
- An attacker who already has root, or the phone's unlocked Secure Enclave
  key.

## Where to look

`crates/isudo` is the only code that runs as root. `crates/core` holds the
decisions it relies on, with no `unsafe` and no I/O. `formal/isudo.pv` is
the protocol model. `tests/setuid/run.sh` is the test that runs the real
setuid binary.

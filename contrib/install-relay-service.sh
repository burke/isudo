#!/bin/sh
# Runs isudo-relay as a service: a launchd agent on macOS, a systemd unit on
# Linux. Safe to run again; it replaces the service definition and restarts
# the relay, and never overwrites an existing settings file or state.
#
#   macOS:  contrib/install-relay-service.sh            (as yourself)
#   Linux:  sudo contrib/install-relay-service.sh
#
# Environment:
#   BINDIR   where isudo-relay is installed (default: /opt/isudo/bin on
#            macOS, /usr/local/bin on Linux)
#   STATE    macOS only: where to keep pairings (default:
#            ~/Library/Application Support/isudo/relay-state.json). Point it
#            at an existing state file to keep the pairings in it.
set -eu
here=$(cd "$(dirname "$0")" && pwd)

fill() { # fill TEMPLATE: substitute @NAME@ placeholders from the environment
  sed -e "s|@BINDIR@|$BINDIR|g" -e "s|@CONFIG@|${CONFIG:-}|g" \
      -e "s|@STATE@|${STATE:-}|g" -e "s|@LOG@|${LOG:-}|g" "$1"
}

case "$(uname -s)" in
Darwin)
  [ "$(id -u)" != 0 ] || { echo "run this as yourself, not root: the relay needs no privilege" >&2; exit 1; }
  BINDIR=${BINDIR:-/opt/isudo/bin}
  [ -x "$BINDIR/isudo-relay" ] || { echo "$BINDIR/isudo-relay not found; run 'sudo make install' first" >&2; exit 1; }
  CONFIG="$HOME/.config/isudo/relay.conf"
  STATE=${STATE:-"$HOME/Library/Application Support/isudo/relay-state.json"}
  LOG="$HOME/Library/Logs/isudo-relay.log"
  agent="$HOME/Library/LaunchAgents/dev.isudo.relay.plist"
  mkdir -p "$(dirname "$CONFIG")" "$(dirname "$STATE")" "$(dirname "$agent")" "$(dirname "$LOG")"
  if [ ! -e "$CONFIG" ]; then
    cp "$here/relay.conf.example" "$CONFIG"
    chmod 600 "$CONFIG"
    echo "wrote $CONFIG"
  fi
  fill "$here/dev.isudo.relay.plist" > "$agent"
  # Replace any earlier copy of the agent, then start it.
  launchctl bootout "gui/$(id -u)/dev.isudo.relay" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$agent"
  echo "isudo-relay is running and will start at login."
  echo "  settings: $CONFIG"
  echo "  pairings: $STATE"
  echo "  log:      $LOG"
  echo "  stop it:  launchctl bootout gui/$(id -u)/dev.isudo.relay"
  ;;
Linux)
  [ "$(id -u)" = 0 ] || { echo "run this as root: sudo $0" >&2; exit 1; }
  BINDIR=${BINDIR:-/usr/local/bin}
  [ -x "$BINDIR/isudo-relay" ] || { echo "$BINDIR/isudo-relay not found; run 'sudo make install' first" >&2; exit 1; }
  install -d -m 0755 /etc/isudo
  if [ ! -e /etc/isudo/relay.conf ]; then
    install -m 0644 "$here/relay.conf.example" /etc/isudo/relay.conf
    echo "wrote /etc/isudo/relay.conf"
  fi
  fill "$here/isudo-relay.service" > /etc/systemd/system/isudo-relay.service
  systemctl daemon-reload
  systemctl enable isudo-relay.service
  systemctl restart isudo-relay.service
  echo "isudo-relay is running and will start at boot."
  echo "  settings: /etc/isudo/relay.conf"
  echo "  pairings: /var/lib/isudo-relay/state.json"
  echo "  log:      journalctl -u isudo-relay"
  ;;
*)
  echo "no service definition for $(uname -s); run isudo-relay under your own supervisor" >&2
  exit 1
  ;;
esac

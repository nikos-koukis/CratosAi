#!/usr/bin/env bash
# Installs jarvisd as a per-user LaunchAgent (runs as you, never as root).
#
#   scripts/launchagent.sh install     build, install binary + agent, start
#   scripts/launchagent.sh uninstall   stop and remove the agent (config is kept)
#   scripts/launchagent.sh status      show launchd's view of the agent
#
# Expects the production config at ~/Library/Application Support/Jarvis/daemon/daemon.toml
# (see config/daemon.example.toml). Logs go to ~/Library/Logs/Jarvis/jarvisd.log.
set -euo pipefail

cd "$(dirname "$0")/.."
LABEL=local.jarvis.daemon
SUPPORT="$HOME/Library/Application Support/Jarvis"
BINARY="$SUPPORT/bin/jarvisd"
CONFIG="$SUPPORT/daemon/daemon.toml"
LOG="$HOME/Library/Logs/Jarvis/jarvisd.log"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
DOMAIN="gui/$(id -u)"

case ${1:-} in
  install)
    [[ -f $CONFIG ]] || { echo "Missing $CONFIG (start from config/daemon.example.toml)." >&2; exit 1; }
    cargo build --quiet --release -p jarvis-daemon --bin jarvisd
    "../../target/release/jarvisd" --config "$CONFIG" check
    mkdir -p "$(dirname "$BINARY")" "$(dirname "$LOG")" "$(dirname "$PLIST")"
    install -m 755 ../../target/release/jarvisd "$BINARY"
    sed -e "s|@BINARY@|$BINARY|" -e "s|@CONFIG@|$CONFIG|" -e "s|@LOG@|$LOG|" \
      launchd/$LABEL.plist.template > "$PLIST"
    plutil -lint "$PLIST" >/dev/null
    launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
    launchctl bootstrap "$DOMAIN" "$PLIST"
    echo "Installed and started $LABEL. Logs: $LOG"
    ;;
  uninstall)
    launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
    rm -f "$PLIST"
    echo "Removed $LABEL (binary and config left in $SUPPORT)."
    ;;
  status)
    launchctl print "$DOMAIN/$LABEL" | grep -E "state|pid|last exit" || echo "$LABEL is not loaded."
    ;;
  *)
    echo "usage: $0 install|uninstall|status" >&2
    exit 2
    ;;
esac

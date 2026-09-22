#!/bin/sh
# antiflock-agent package pre-remove. Stops the unit only. State, keys, and
# config are left in place: `antiflock-agent uninstall --yes` removes them
# explicitly. Firewall state is never touched by packaging.
set -eu

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now antiflock-agent.service >/dev/null 2>&1 || true
fi

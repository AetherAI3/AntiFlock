#!/bin/sh
# antiflock-agent package post-install. No user input is read; every path
# and name below is a literal. Safe to run repeatedly.
set -eu

if ! getent group antiflock >/dev/null 2>&1; then
  groupadd --system antiflock
fi
if ! getent passwd antiflock >/dev/null 2>&1; then
  useradd --system --gid antiflock --home-dir /var/lib/antiflock \
    --shell /usr/sbin/nologin --comment "AntiFlock agent" antiflock
fi

install -d -m 0755 -o root -g root /etc/antiflock
install -d -m 0700 -o antiflock -g antiflock /var/lib/antiflock
install -d -m 0700 -o antiflock -g antiflock /var/lib/antiflock/queue
install -d -m 0700 -o antiflock -g antiflock /var/log/antiflock

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi

cat <<'MSG'
antiflock-agent installed (observe mode only; enforcement is not available).
Next steps, as root:
  antiflock-agent init --node-id <id> --deployment-id <id> --core-url https://core.example.test:8787
  chown -R antiflock:antiflock /var/lib/antiflock
  antiflock-agent doctor
  antiflock-agent enroll --enrollment-token-file /path/to/private/token
  systemctl enable --now antiflock-agent.service
See /usr/share/doc/antiflock-agent/quickstart-linux.md.
MSG

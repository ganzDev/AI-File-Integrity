#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run: sudo bash deployment/install.sh" >&2
  exit 1
fi

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
DASH_USER="${SUDO_USER:-admin}"
if [[ "$DASH_USER" == root ]]; then
  echo "Run with sudo as your normal admin user, not directly as root." >&2
  exit 1
fi
if ! id "$DASH_USER" >/dev/null 2>&1; then
  echo "User does not exist: $DASH_USER" >&2
  exit 1
fi
if [[ ! -x "$PROJECT_DIR/.venv/bin/python" || ! -f "$PROJECT_DIR/src/monitor.py" ]]; then
  echo "Run from the project with its existing .venv and src files." >&2
  exit 1
fi
if [[ ! -f "$PROJECT_DIR/logs/security_events.db" ]]; then
  echo "Missing existing SQLite database; stopping without creating one." >&2
  exit 1
fi
if [[ "$PROJECT_DIR" == *$'\n'* || "$PROJECT_DIR" == *' '* ]]; then
  echo "Project path cannot contain spaces or newlines." >&2
  exit 1
fi
mkdir -p /etc/ai-file-integrity
printf '%s\n' "$PROJECT_DIR" >/etc/ai-file-integrity/project-path
chown root:root /etc/ai-file-integrity/project-path
chmod 600 /etc/ai-file-integrity/project-path
install -o root -g root -m 0755 "$PROJECT_DIR/deployment/afi-admin" /usr/local/sbin/afi-admin

cat >/etc/systemd/system/ai-file-integrity-monitor.service <<UNIT
[Unit]
Description=AI File Integrity Watchdog monitor
After=local-fs.target

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_DIR
Environment=PYTHONPATH=src
ExecStart=$PROJECT_DIR/.venv/bin/python -u $PROJECT_DIR/src/monitor.py
Restart=on-failure
RestartSec=3
KillSignal=SIGINT
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/ai-file-integrity-detector.service <<UNIT
[Unit]
Description=AI File Integrity continuous rule detector
After=local-fs.target auditd.service

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_DIR
Environment=PYTHONPATH=src
ExecStart=$PROJECT_DIR/.venv/bin/python -u $PROJECT_DIR/src/detector.py --continuous --interval 5
Restart=on-failure
RestartSec=3
KillSignal=SIGINT
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/sudoers.d/ai-file-integrity-dashboard <<SUDOERS
# Local-only dashboard: narrowly scoped root-owned helper, never a shell.
$DASH_USER ALL=(root) NOPASSWD: /usr/local/sbin/afi-admin *
SUDOERS
chmod 0440 /etc/sudoers.d/ai-file-integrity-dashboard
if ! visudo -cf /etc/sudoers.d/ai-file-integrity-dashboard; then
  rm -f /etc/sudoers.d/ai-file-integrity-dashboard
  echo "Invalid sudoers rule, removed." >&2
  exit 1
fi
systemctl daemon-reload

cat <<EOF
Installed successfully.
Project: $PROJECT_DIR
Dashboard user: $DASH_USER

IMPORTANT: Stop manually launched monitor.py and detector.py first.
Then start managed services:
  sudo systemctl start ai-file-integrity-monitor ai-file-integrity-detector
Check:
  systemctl is-active ai-file-integrity-monitor ai-file-integrity-detector

Launch dashboard as $DASH_USER (NOT root):
  cd $PROJECT_DIR
  .venv/bin/python dashboard/app.py
Open http://127.0.0.1:8765

Services are NOT automatically started/enabled by installer.
EOF

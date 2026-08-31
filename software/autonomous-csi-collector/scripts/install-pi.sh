#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: sudo $0 [--operator USER]" >&2
}

operator="${SUDO_USER:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator) operator="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

if [[ "$EUID" -ne 0 ]]; then
  echo "Run this installer with sudo." >&2
  exit 2
fi
if [[ -z "$operator" || "$operator" == "root" ]] || ! id "$operator" >/dev/null 2>&1; then
  echo "Specify the normal SSH operator with --operator USER." >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_root="$(cd "$script_dir/.." && pwd)"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3-venv python3-serial python3-setuptools python3-wheel

getent group cws-collector >/dev/null || groupadd --system cws-collector
if ! id cws-collector >/dev/null 2>&1; then
  useradd --system --gid cws-collector --groups dialout --home-dir /var/lib/cws-collector \
    --shell /usr/sbin/nologin cws-collector
fi
usermod -a -G cws-collector "$operator"

install -d -o root -g root -m 0755 /opt/cws-collector
python3 -m venv --system-site-packages /opt/cws-collector/venv
/opt/cws-collector/venv/bin/pip install --no-deps --no-build-isolation --upgrade "$source_root"
ln -sfn /opt/cws-collector/venv/bin/cws-collector /usr/local/bin/cws-collector

install -d -o root -g cws-collector -m 0750 /etc/cws-collector
if [[ ! -e /etc/cws-collector/config.json ]]; then
  install -o root -g cws-collector -m 0640 "$source_root/config/multi-source.example.json" \
    /etc/cws-collector/config.json
fi
install -d -o cws-collector -g cws-collector -m 2770 /var/lib/cws-collector
install -o root -g root -m 0644 "$source_root/systemd/cws-collector.service" \
  /etc/systemd/system/cws-collector.service

systemctl daemon-reload
systemctl enable --now cws-collector.service

echo "Installed. Reconnect the SSH session so $operator receives the cws-collector group."
echo "Then run: cws-collector inventory"

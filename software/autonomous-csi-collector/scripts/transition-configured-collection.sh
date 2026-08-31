#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: sudo $0 SOURCE_ID CONFIG PREVIOUS_RUN DURATION [LABEL]" >&2
}

if [[ "$EUID" -ne 0 || $# -lt 4 || $# -gt 5 ]]; then
  usage
  exit 2
fi

source_id=$1
config=$2
previous_run=$3
duration=$4
label=${5:-collection-transition}
state_dir=/var/lib/cws-collector
collector=/opt/cws-collector/venv/bin/cws-collector
operator=${CWS_OPERATOR:?set CWS_OPERATOR to the service operator}

exec 9>"/run/lock/cws-collection-transition-${source_id}.lock"
flock -n 9 || { echo "another collection transition is running" >&2; exit 75; }

test -x "$collector"
test -f "$config"
test -d "$previous_run"
if [[ -e "$state_dir/active.json" ]]; then
  echo "refusing to interrupt an active collection" >&2
  exit 75
fi

run_operator() {
  runuser -u "$operator" -- "$@"
}

echo "Verifying completed predecessor run: $previous_run"
run_operator "$collector" --state-dir "$state_dir" verify "$previous_run"

echo "Installing the supplied configuration for $source_id"
systemctl stop cws-collector.service
restart_collector=true
trap 'if [[ "$restart_collector" == true ]]; then systemctl start cws-collector.service; fi' EXIT

install -o root -g cws-collector -m 0640 "$config" /etc/cws-collector/config.json
systemctl start cws-collector.service
restart_collector=false
trap - EXIT

run_operator "$collector" --state-dir "$state_dir" preflight \
  --config /etc/cws-collector/config.json --duration "$duration"
run_operator "$collector" --state-dir "$state_dir" arm \
  --config /etc/cws-collector/config.json --duration "$duration" --label "$label"
run_operator "$collector" --state-dir "$state_dir" event collection-transition-start
run_operator "$collector" --state-dir "$state_dir" status

echo "$source_id collection transition complete"

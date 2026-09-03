#!/usr/bin/env bash
# CTest helper: fresh model_server + one test binary
set -euo pipefail
EXE="${1:?exe}"
CFG="${2:?model_cfg.yml}"
NAME="$(basename "$EXE")"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Prefer venv next to libtropic
VENV="${SCRIPT_DIR}/../../libtropic/scripts/tropic01_model/.venv"
if [ -f "$VENV/bin/activate" ]; then
  # shellcheck disable=SC1091
  source "$VENV/bin/activate"
  export PATH="$VENV/bin:$PATH"
fi

pkill -x model_server 2>/dev/null || true
sleep 0.5
model_server tcp -c "$CFG" >/tmp/model_${NAME}.log 2>&1 &
MPID=$!
cleanup() { kill "$MPID" 2>/dev/null || true; }
trap cleanup EXIT

up=0
for _ in $(seq 1 50); do
  if python3 -c 'import socket;s=socket.socket();s.settimeout(0.3);s.connect(("127.0.0.1",28992));s.close()' 2>/dev/null; then
    up=1
    break
  fi
  sleep 0.2
done
if [ "$up" -ne 1 ]; then
  echo "model_server did not start" >&2
  exit 1
fi

"$EXE"

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FW_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MODEL_SCRIPTS="$FW_ROOT/libtropic/scripts/tropic01_model"

# shellcheck disable=SC1091
source "$MODEL_SCRIPTS/.venv/bin/activate"
export PATH="$VIRTUAL_ENV/bin:$PATH"
pkill -f 'model_server' 2>/dev/null || true
sleep 2

cd /tmp
model_server tcp -c "$MODEL_SCRIPTS/model_cfg.yml" > /tmp/model.log 2>&1 &
MPID=$!
for i in $(seq 1 30); do
  if python3 -c 'import socket; s=socket.socket(); s.settimeout(0.5); s.connect(("127.0.0.1",28992)); s.close()' 2>/dev/null; then
    echo "model up after ${i} tries"
    break
  fi
  sleep 0.3
done

cd "$SCRIPT_DIR/build"
make -j"$(nproc)" se_tropic_host test_a_session 2>&1 | tail -20
echo "Running test_a_session..."
./test_a_session; EC=$?
echo "test exit: $EC"
kill $MPID 2>/dev/null || true
tail -30 /tmp/model.log || true
exit $EC

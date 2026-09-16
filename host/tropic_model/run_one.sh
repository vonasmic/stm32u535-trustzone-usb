#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FW_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MODEL_SCRIPTS="$FW_ROOT/libtropic/scripts/tropic01_model"

# shellcheck disable=SC1091
source "$MODEL_SCRIPTS/.venv/bin/activate"
cd "$SCRIPT_DIR/build"
export PYTHONPATH="$MODEL_SCRIPTS"
export PATH="$VIRTUAL_ENV/bin:$PATH"
pkill -f 'model_server' 2>/dev/null || true
pkill -f 'test_a_session' 2>/dev/null || true
sleep 1
rm -rf run_logs_manual
mkdir -p run_logs_manual
timeout 90 python -m model_runner \
  -e ./test_a_session \
  -c "$MODEL_SCRIPTS/model_cfg.yml" \
  -o ./run_logs_manual
echo "runner exit: $?"
echo "=== exe log ==="
cat run_logs_manual/test_a_session.log || true

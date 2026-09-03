#!/usr/bin/env bash
set -euo pipefail
source /mnt/c/tmp/SE_firmware/libtropic/scripts/tropic01_model/.venv/bin/activate
cd /mnt/c/tmp/SE_firmware/host/tropic_model/build
export PYTHONPATH=/mnt/c/tmp/SE_firmware/libtropic/scripts/tropic01_model
export PATH="$VIRTUAL_ENV/bin:$PATH"
pkill -f 'model_server' 2>/dev/null || true
pkill -f 'test_a_session' 2>/dev/null || true
sleep 1
rm -rf run_logs_manual
mkdir -p run_logs_manual
timeout 90 python -m model_runner \
  -e ./test_a_session \
  -c /mnt/c/tmp/SE_firmware/libtropic/scripts/tropic01_model/model_cfg.yml \
  -o ./run_logs_manual
echo "runner exit: $?"
echo "=== exe log ==="
cat run_logs_manual/test_a_session.log || true

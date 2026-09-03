#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/tmp/SE_firmware/host/tropic_model/build
cmake .. -DLT_LOG_LVL=Error
make -j$(nproc) test_a_session

source /mnt/c/tmp/SE_firmware/libtropic/scripts/tropic01_model/.venv/bin/activate
export PATH="$VIRTUAL_ENV/bin:$PATH"
pkill -f model_server 2>/dev/null || true
sleep 1
model_server tcp -c /mnt/c/tmp/SE_firmware/libtropic/scripts/tropic01_model/model_cfg.yml >/tmp/model.log 2>&1 &
MPID=$!
for i in $(seq 1 40); do
  python3 -c 'import socket;s=socket.socket();s.settimeout(0.3);s.connect(("127.0.0.1",28992));s.close()' 2>/dev/null && break
  sleep 0.25
done
echo "=== run ==="
./test_a_session; EC=$?
echo exit:$EC
kill $MPID 2>/dev/null || true
exit $EC

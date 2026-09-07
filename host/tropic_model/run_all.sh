#!/usr/bin/env bash
set -uo pipefail
# Kill leftovers without killing this script
for p in model_server model_runner test_a_session test_b_ecc test_c_rmem test_d_pin test_e_mcounter test_f_mlkem test_g_ingest test_h_pairing test_i_post_tls test_j_peers brick_lab se_host; do
  pkill -x "$p" 2>/dev/null || true
done
sleep 1

cd /mnt/c/tmp/SE_firmware/host/tropic_model/build
make -j$(nproc) test_a_session test_b_ecc test_c_rmem test_d_pin test_e_mcounter test_f_mlkem test_g_ingest test_h_pairing test_i_post_tls test_j_peers brick_lab se_host
EC_BUILD=$?
if [ "$EC_BUILD" -ne 0 ]; then
  echo "BUILD FAIL"
  exit 1
fi

source /mnt/c/tmp/SE_firmware/libtropic/scripts/tropic01_model/.venv/bin/activate
export PATH="$VIRTUAL_ENV/bin:$PATH"
export PYTHONPATH=/mnt/c/tmp/SE_firmware/libtropic/scripts/tropic01_model
mkdir -p run_logs

# Increase wait in model_runner by wrapping: start model ourselves for reliability
run_one() {
  local name="$1"
  echo "======== $name ========"
  pkill -x model_server 2>/dev/null || true
  sleep 1
  model_server tcp -c /mnt/c/tmp/SE_firmware/libtropic/scripts/tropic01_model/model_cfg.yml \
    >/tmp/model_${name}.log 2>&1 &
  local mpid=$!
  local up=0
  for i in $(seq 1 50); do
    if python3 -c 'import socket;s=socket.socket();s.settimeout(0.3);s.connect(("127.0.0.1",28992));s.close()' 2>/dev/null; then
      up=1
      break
    fi
    sleep 0.2
  done
  if [ "$up" -ne 1 ]; then
    echo "model failed to start for $name"
    kill $mpid 2>/dev/null || true
    return 1
  fi
  "./$name" > "run_logs/${name}.log" 2>&1
  local ec=$?
  kill $mpid 2>/dev/null || true
  wait $mpid 2>/dev/null || true
  if [ "$ec" -ne 0 ]; then
    echo "FAIL $name (exit $ec)"
    tail -60 "run_logs/${name}.log" || true
    return 1
  fi
  echo "PASS $name"
  return 0
}

FAIL=0
for t in test_a_session test_b_ecc test_c_rmem test_d_pin test_e_mcounter test_f_mlkem test_g_ingest test_h_pairing test_i_post_tls test_j_peers brick_lab; do
  run_one "$t" || FAIL=1
done

if [ "$FAIL" -ne 0 ]; then
  echo "SOME_FAILED"
  exit 1
fi
echo ALL_PASS

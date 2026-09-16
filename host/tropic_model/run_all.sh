#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FW_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LIBTROPIC="$FW_ROOT/libtropic"
MODEL_SCRIPTS="$LIBTROPIC/scripts/tropic01_model"
BUILD_DIR="$SCRIPT_DIR/build"
TESTS=(
  test_a_session test_b_ecc test_c_rmem test_d_pin test_e_mcounter
  test_f_mlkem test_g_ingest test_h_pairing test_i_post_tls test_j_peers
  test_k_owner brick_lab
)

# Kill leftovers without killing this script
for p in model_server model_runner "${TESTS[@]}" se_host; do
  pkill -x "$p" 2>/dev/null || true
done
sleep 1

cd "$BUILD_DIR"
make -j"$(nproc)" "${TESTS[@]}" se_host
EC_BUILD=$?
if [ "$EC_BUILD" -ne 0 ]; then
  echo "BUILD FAIL"
  exit 1
fi

# shellcheck disable=SC1091
source "$MODEL_SCRIPTS/.venv/bin/activate"
export PATH="$VIRTUAL_ENV/bin:$PATH"
export PYTHONPATH="$MODEL_SCRIPTS"
mkdir -p run_logs

run_one() {
  local name="$1"
  echo "======== $name ========"
  pkill -x model_server 2>/dev/null || true
  sleep 1
  model_server tcp -c "$MODEL_SCRIPTS/model_cfg.yml" \
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
for t in "${TESTS[@]}"; do
  run_one "$t" || FAIL=1
done

if [ "$FAIL" -ne 0 ]; then
  echo "SOME_FAILED"
  exit 1
fi
echo ALL_PASS

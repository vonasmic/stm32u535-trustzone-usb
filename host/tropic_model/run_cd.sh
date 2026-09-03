#!/usr/bin/env bash
set -euo pipefail
source /mnt/c/tmp/SE_firmware/libtropic/scripts/tropic01_model/.venv/bin/activate
export PATH="$VIRTUAL_ENV/bin:$PATH"
cd /mnt/c/tmp/SE_firmware/host/tropic_model/build
for t in test_c_rmem test_d_pin; do
  bash ../run_with_model.sh "./$t" /mnt/c/tmp/SE_firmware/libtropic/scripts/tropic01_model/model_cfg.yml
  echo "PASS $t"
done

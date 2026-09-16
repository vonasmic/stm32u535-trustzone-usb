#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FW_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MODEL_SCRIPTS="$FW_ROOT/libtropic/scripts/tropic01_model"
CFG="$MODEL_SCRIPTS/model_cfg.yml"

# shellcheck disable=SC1091
source "$MODEL_SCRIPTS/.venv/bin/activate"
export PATH="$VIRTUAL_ENV/bin:$PATH"
cd "$SCRIPT_DIR/build"
for t in test_c_rmem test_d_pin; do
  bash "$SCRIPT_DIR/run_with_model.sh" "./$t" "$CFG"
  echo "PASS $t"
done

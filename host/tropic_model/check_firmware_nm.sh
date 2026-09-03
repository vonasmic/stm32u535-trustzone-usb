#!/usr/bin/env bash
# Link-time gate: Secure firmware must not pull irreversible Tropic APIs.
set -euo pipefail
ELF="${1:?usage: check_firmware_nm.sh SE_firmware_Secure.elf}"

if ! command -v nm >/dev/null 2>&1; then
  echo "nm not found" >&2
  exit 1
fi

HITS=$(nm -C "$ELF" 2>/dev/null | grep -E 'lt_i_config_write|lt_mutable_fw_update' || true)
if [ -n "$HITS" ]; then
  echo "FAIL: brick APIs linked into firmware:" >&2
  echo "$HITS" >&2
  exit 1
fi
echo "PASS: no brick APIs in $(basename "$ELF")"

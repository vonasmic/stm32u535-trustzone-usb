#!/usr/bin/env bash
set -euo pipefail
grep -E 'HAVE_AESGCM|HAVE_CURVE25519|NO_OPTIONS|DEFINES' \
  /mnt/c/tmp/SE_firmware/host/tropic_model/build/libtropic/CMakeFiles/tropic.dir/flags.make | head -40
echo '---'
grep -E 'HAVE_AESGCM|HAVE_CURVE25519|NO_OPTIONS|DEFINES' \
  /mnt/c/tmp/SE_firmware/host/tropic_model/build/CMakeFiles/se_tropic_host.dir/flags.make | head -40
echo '--- interface ---'
grep -E 'HAVE_CURVE25519|HAVE_AESGCM' \
  /mnt/c/tmp/SE_firmware/host/tropic_model/build/wolfssl/CMakeFiles/Export/*/wolfssl-targets.cmake 2>/dev/null | head -20 || true
# Also try openssl CAL as quick alternate - first diagnose session with mbedtls hello_world

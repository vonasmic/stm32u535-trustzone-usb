#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPS="$SCRIPT_DIR/_deps"
rm -rf "$DEPS"
mkdir -p "$DEPS"

py_unzip() {
  local zip="$1"
  local dest="$2"
  python3 - <<PY
import zipfile
with zipfile.ZipFile(r"""$zip""") as z:
    z.extractall(r"""$dest""")
PY
}

echo "Downloading ed25519..."
curl -L -o "$DEPS/ed25519.zip" "https://github.com/orlp/ed25519/archive/b1f19fab4aebe607805620d25a5e42566ce46a0e.zip"
EXPECTED="75f39e64f22ec7474e7881315a3f9135afe6c990737388fb16a6950911b55721"
ACTUAL=$(sha256sum "$DEPS/ed25519.zip" | awk '{print $1}')
[ "$EXPECTED" = "$ACTUAL" ] || { echo "ed25519 checksum mismatch"; exit 1; }
py_unzip "$DEPS/ed25519.zip" "$DEPS"
mv "$DEPS/ed25519-b1f19fab4aebe607805620d25a5e42566ce46a0e" "$DEPS/ed25519"
rm "$DEPS/ed25519.zip"

echo "Downloading WolfSSL..."
curl -L -o "$DEPS/wolfssl.zip" "https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.8.4-stable.zip"
EXPECTED="9f52b92b2937acdbb03f2a731160d70f23f74a375f651de057214783c266fbeb"
ACTUAL=$(sha256sum "$DEPS/wolfssl.zip" | awk '{print $1}')
[ "$EXPECTED" = "$ACTUAL" ] || { echo "wolfssl checksum mismatch"; exit 1; }
py_unzip "$DEPS/wolfssl.zip" "$DEPS"
mv "$DEPS/wolfssl-5.8.4-stable" "$DEPS/wolfssl"
rm "$DEPS/wolfssl.zip"

echo "Deps ready in $DEPS"

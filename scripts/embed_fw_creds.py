#!/usr/bin/env python3
"""Generate fw_creds.h (Secure TLS) and wrapped_client_key.h (Secure).

Usage:
  embed_fw_creds.py <certs_dir> <out_s_creds_header> <out_s_wrap_header>

Expects:
  <certs_dir>/client/client-cert.pem
  <certs_dir>/client/client-key.pem
  <certs_dir>/root-ca.pem
  <certs_dir>/Alice.pem
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import subprocess
import sys
from pathlib import Path

WRAP_VERSION = 1
DWK_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
HKDF_INFO = b"SE_firmware_wrap_v1"
CLIENT_KEY_ID = bytes([0x53, 0x45, 0x5F, 0x74, 0x6C, 0x73, 0x5F, 0x63, 0x6C, 0x69])  # "SE_tls_cli"


def run(cmd: list[str]) -> bytes:
    return subprocess.check_output(cmd)


def pem_to_der(path: Path) -> bytes:
    return run(["openssl", "x509" if "cert" in path.name or path.name.endswith(".pem") and "key" not in path.name else "pkey",
                "-in", str(path), "-outform", "DER"])


def cert_der(path: Path) -> bytes:
    return run(["openssl", "x509", "-in", str(path), "-outform", "DER"])


def read_asn1_len(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        return 0, pos
    b = data[pos]
    pos += 1
    if b < 0x80:
        return b, pos
    n = b & 0x7F
    val = 0
    for _ in range(n):
        val = (val << 8) | data[pos]
        pos += 1
    return val, pos


def spki_raw_from_cert_der(der: bytes) -> bytes:
    """Return raw subjectPublicKey bytes (BIT STRING payload, no unused-bits byte)."""
    pos = 0
    best = b""

    while pos < len(der):
        tag = der[pos]
        pos += 1
        ln, pos = read_asn1_len(der, pos)
        if pos + ln > len(der):
            break
        body = der[pos:pos + ln]
        pos += ln

        if tag == 0x03 and ln > 32:  # BIT STRING
            if body and body[0] == 0x00:
                payload = body[1:]
            else:
                payload = body
            if len(payload) > len(best):
                best = payload
        elif tag in (0x30, 0x31):  # SEQUENCE / SET: recurse
            inner = 0
            while inner < len(body):
                sub_tag = body[inner]
                inner += 1
                sub_ln, inner = read_asn1_len(body, inner)
                if inner + sub_ln > len(body):
                    break
                sub_body = body[inner:inner + sub_ln]
                inner += sub_ln
                if sub_tag == 0x03 and sub_ln > 32:
                    if sub_body and sub_body[0] == 0x00:
                        payload = sub_body[1:]
                    else:
                        payload = sub_body
                    if len(payload) > len(best):
                        best = payload

    if not best:
        raise RuntimeError("could not locate subjectPublicKey BIT STRING")
    return best


def spki_der_from_cert(path: Path) -> bytes:
    der = cert_der(path)
    return spki_raw_from_cert_der(der)


def key_der(path: Path) -> bytes:
    text = path.read_text(encoding="utf-8")
    if "BEGIN PRIVATE KEY" in text or "BEGIN ENCRYPTED PRIVATE KEY" in text:
        lines = [ln.strip() for ln in text.splitlines()
                 if ln and not ln.startswith("-----")]
        return base64.b64decode("".join(lines))
    return run(["openssl", "pkey", "-in", str(path), "-outform", "DER"])


def b64_no_nl(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, out_len: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    block = b""
    counter = 1
    while len(out) < out_len:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:out_len]


def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return ct[:-16], ct[-16:]


def c_array(name: bytes | str, data: bytes) -> str:
    if isinstance(name, str):
        name = name
    lines = []
    for i in range(0, len(data), 12):
        chunk = data[i:i + 12]
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    return (
        f"static const unsigned char {name}[] = {{\n"
        + "\n".join(lines)
        + f"\n}};\n"
        f"static const unsigned int {name}_len = {len(data)}u;\n"
    )


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2

    certs = Path(sys.argv[1])
    out_creds = Path(sys.argv[2])
    out_s = Path(sys.argv[3])

    client_cert = certs / "client" / "client-cert.pem"
    client_key = certs / "client" / "client-key.pem"
    root_ca = certs / "root-ca.pem"
    alice = certs / "Alice.pem"

    for p in (client_cert, client_key, root_ca, alice):
        if not p.is_file():
            print(f"missing: {p}", file=sys.stderr)
            return 1

    client_cert_der = cert_der(client_cert)
    root_ca_der = cert_der(root_ca)
    client_key_der = key_der(client_key)
    client_spki = spki_der_from_cert(client_cert)
    alice_spki = spki_der_from_cert(alice)

    client_b64 = b64_no_nl(client_spki)
    alice_b64 = b64_no_nl(alice_spki)
    json_payload = (
        '{"clientpublickey":"' + client_b64 +
        '","array":[{"secondPartyKey":"' + alice_b64 +
        '","nickname":"Alice"}]}'
    ).encode("utf-8")

    dwk = secrets.token_bytes(DWK_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)

    uid_hex = os.environ.get("SE_FIRMWARE_UID", "")
    if uid_hex:
        uid_bytes = bytes.fromhex(uid_hex)
        if len(uid_bytes) != 12:
            print("SE_FIRMWARE_UID must be 24 hex chars (96-bit UID)", file=sys.stderr)
            return 1
    else:
        uid_bytes = b"\x00" * 12
        print("warning: wrapping with zero UID salt (set SE_FIRMWARE_UID for production)", file=sys.stderr)

    wrap_key = hkdf_sha256(dwk, uid_bytes, HKDF_INFO, 32)
    ciphertext, tag = aes_gcm_encrypt(wrap_key, nonce, client_key_der)
    blob = bytes([WRAP_VERSION]) + nonce + ciphertext + tag

    creds_header = f"""/* Auto-generated by scripts/embed_fw_creds.py — do not edit */
#ifndef FW_CREDS_H
#define FW_CREDS_H

{c_array("fw_client_cert_der", client_cert_der)}
{c_array("fw_root_ca_der", root_ca_der)}
{c_array("fw_json_payload", json_payload)}

#endif /* FW_CREDS_H */
"""

    s_header = f"""/* Auto-generated by scripts/embed_fw_creds.py — do not edit */
#ifndef WRAPPED_CLIENT_KEY_H
#define WRAPPED_CLIENT_KEY_H

{c_array("secure_dwk", dwk)}
{c_array("secure_wrapped_client_key", blob)}

#endif /* WRAPPED_CLIENT_KEY_H */
"""

    out_creds.parent.mkdir(parents=True, exist_ok=True)
    out_s.parent.mkdir(parents=True, exist_ok=True)
    out_creds.write_text(creds_header, encoding="utf-8")
    out_s.write_text(s_header, encoding="utf-8")
    print(f"wrote {out_creds} ({len(client_cert_der)}+{len(root_ca_der)} cert bytes, JSON {len(json_payload)} bytes)")
    print(f"wrote {out_s} (wrapped key {len(blob)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

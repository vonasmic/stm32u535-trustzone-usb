#!/usr/bin/env python3
"""Host helper: PEM→DER, SPKI extract, and AES-GCM wrap for OWNER/CREDS payloads.

Not a CubeIDE/firmware compile step. Silicon enrolls at runtime
(OWNER SET, CREDS SAE, CREDS DEVICE). This script still packs certs from
the CertGenerator tree for tests and USB ingest.

Usage:
  embed_fw_creds.py <certs_dir> <out_s_creds_header> <out_s_wrap_header>
                    [--tropic-cert DER] [--mlkem-pk BIN]
                    [--drop-provisioned]

Expects (CertGenerator layout under <certs_dir>):
  client/client-cert.pem           (or --client-dir client2 → client2/client-cert.pem)
  client/client-key.pem
  ca/root-ca.pem                   SAE application CA (PROVISION)
  user/user-cert.pem               home-PC user leaf = owner key (ENCRYPT/DECRYPT pin)
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import re
import secrets
import subprocess
import sys
from pathlib import Path

WRAP_VERSION = 2
DWK_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
HKDF_INFO = b"SE_firmware_wrap_v2"
MLKEM768_PK_LEN = 1184


def run(cmd: list[str]) -> bytes:
    return subprocess.check_output(cmd)


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


def der_children(body: bytes) -> list[tuple[int, bytes]]:
    """Split a DER constructed value into its (tag, content) children."""
    out = []
    pos = 0
    while pos < len(body):
        tag = body[pos]
        pos += 1
        ln, pos = read_asn1_len(body, pos)
        if pos + ln > len(body):
            break
        out.append((tag, body[pos:pos + ln]))
        pos += ln
    return out


def spki_raw_from_cert_der(der: bytes) -> bytes:
    """Return raw subjectPublicKey bits (BIT STRING payload, no unused-bits byte).

    Walks Certificate -> tbsCertificate and picks the child SEQUENCE shaped like a
    SubjectPublicKeyInfo (an AlgorithmIdentifier SEQUENCE followed by a BIT STRING).
    Picking the longest BIT STRING instead would return the certificate signature,
    which for ML-DSA is larger than the public key.
    """
    certificate = der_children(der)
    if not certificate or certificate[0][0] != 0x30:
        raise RuntimeError("not a DER Certificate")
    tbs = der_children(certificate[0][1])
    if not tbs or tbs[0][0] != 0x30:
        raise RuntimeError("missing tbsCertificate")

    for tag, body in der_children(tbs[0][1]):
        if tag != 0x30:
            continue
        fields = der_children(body)
        if len(fields) == 2 and fields[0][0] == 0x30 and fields[1][0] == 0x03:
            bits = fields[1][1]
            return bits[1:] if bits and bits[0] == 0x00 else bits

    raise RuntimeError("could not locate subjectPublicKeyInfo")


def spki_der_from_cert(path: Path) -> bytes:
    return spki_raw_from_cert_der(cert_der(path))


def key_der(path: Path) -> bytes:
    text = path.read_text(encoding="utf-8")
    if "BEGIN PRIVATE KEY" in text or "BEGIN ENCRYPTED PRIVATE KEY" in text:
        lines = [ln.strip() for ln in text.splitlines()
                 if ln and not ln.startswith("-----")]
        return base64.b64decode("".join(lines))
    return run(["openssl", "pkey", "-in", str(path), "-outform", "DER"])


def hkdf_sha384(ikm: bytes, info: bytes, out_len: int) -> bytes:
    # RFC 5869: omitted salt => HashLen zeros (matches wolfSSL wc_HKDF NULL salt)
    salt = b"\x00" * hashlib.sha384().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha384).digest()
    out = b""
    block = b""
    counter = 1
    while len(out) < out_len:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha384).digest()
        out += block
        counter += 1
    return out[:out_len]


def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return ct[:-16], ct[-16:]


def c_array(name: str, data: bytes, section: str | None = None) -> str:
    """A zero-length array is illegal in C, so empty data emits a 1-byte dummy."""
    body = data if data else b"\x00"
    lines = []
    for i in range(0, len(body), 12):
        chunk = body[i:i + 12]
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    attr = ""
    if section:
        attr = f' __attribute__((section("{section}"), aligned(4)))'
    return (
        f"static const unsigned char {name}[]{attr} = {{\n"
        + "\n".join(lines)
        + "\n};\n"
        f"static const unsigned int {name}_len = {len(data)}u;\n"
    )


def parse_existing_array(header: Path, name: str) -> bytes | None:
    """Recover a previously embedded array so re-running does not drop provisioning."""
    if not header.is_file():
        return None
    text = header.read_text(encoding="utf-8")
    match = re.search(
        rf"static const unsigned char {name}\[\][^=]*= \{{(.*?)\}};\s*"
        rf"static const unsigned int {name}_len = (\d+)u;",
        text,
        re.DOTALL,
    )
    if match is None:
        return None
    declared = int(match.group(2))
    if declared == 0:
        return None
    data = bytes(int(tok, 16) for tok in re.findall(r"0x([0-9a-fA-F]{2})", match.group(1)))
    return data[:declared]


def main() -> int:
    ap = argparse.ArgumentParser(description="Embed firmware credentials")
    ap.add_argument("certs_dir")
    ap.add_argument("out_creds_header")
    ap.add_argument("out_wrap_header")
    ap.add_argument("--client-dir", metavar="DIR", default="client",
                    help="device leaf folder under certs_dir (default: client)")
    ap.add_argument("--tropic-cert", metavar="DER",
                    help="optional TROPIC01 P-256 certificate DER (unused for now)")
    ap.add_argument("--mlkem-pk", metavar="BIN",
                    help="1184-byte ML-KEM-768 public key from TROPIC KEM PUB")
    ap.add_argument("--drop-provisioned", action="store_true",
                    help="clear fw_tropic_cert_der / fw_mlkem_pk instead of carrying them forward")
    ap.add_argument("--new-dwk", action="store_true",
                    help="rotate secure_dwk; makes every sealed R-MEM blob unreadable")
    args = ap.parse_args()

    if "/" in args.client_dir or "\\" in args.client_dir or args.client_dir in ("", ".", ".."):
        print("invalid --client-dir (use a folder name such as client or client2)", file=sys.stderr)
        return 1

    certs = Path(args.certs_dir)
    out_creds = Path(args.out_creds_header)
    out_wrap = Path(args.out_wrap_header)

    client_dir = certs / args.client_dir
    client_cert = client_dir / "client-cert.pem"
    client_key = client_dir / "client-key.pem"
    root_ca = certs / "ca" / "root-ca.pem"
    client_ca = certs / "ca" / "client_ca.pem"
    user_cert = certs / "user" / "user-cert.pem"

    for p in (client_cert, client_key, root_ca, client_ca, user_cert):
        if not p.is_file():
            print(f"missing: {p}", file=sys.stderr)
            return 1

    client_cert_der = cert_der(client_cert)
    root_ca_der = cert_der(root_ca)
    client_ca_der = cert_der(client_ca)
    client_key_der = key_der(client_key)
    client_spki = spki_der_from_cert(client_cert)
    user_spki = spki_der_from_cert(user_cert)

    if args.tropic_cert:
        tropic_cert = Path(args.tropic_cert).read_bytes()
    elif args.drop_provisioned:
        tropic_cert = b""
    else:
        tropic_cert = parse_existing_array(out_creds, "fw_tropic_cert_der") or b""

    if args.mlkem_pk:
        mlkem_pk = Path(args.mlkem_pk).read_bytes()
    elif args.drop_provisioned:
        mlkem_pk = b""
    else:
        mlkem_pk = parse_existing_array(out_creds, "fw_mlkem_pk") or b""

    if mlkem_pk and len(mlkem_pk) != MLKEM768_PK_LEN:
        print(f"ML-KEM public key must be {MLKEM768_PK_LEN} bytes, got {len(mlkem_pk)}",
              file=sys.stderr)
        return 1

    # secure_dwk also keys the R-MEM seal, so rotating it orphans the PIN NVM and
    # the KEK-wrapped ML-KEM seed already on the chip. Reuse it across passes.
    dwk = None if args.new_dwk else parse_existing_array(out_wrap, "secure_dwk")
    reused_dwk = dwk is not None and len(dwk) == DWK_LEN
    if not reused_dwk:
        dwk = secrets.token_bytes(DWK_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    wrap_key = hkdf_sha384(dwk, HKDF_INFO, 32)
    ciphertext, tag = aes_gcm_encrypt(wrap_key, nonce, client_key_der)
    blob = bytes([WRAP_VERSION]) + nonce + ciphertext + tag

    creds_header = f"""/* Auto-generated by scripts/embed_fw_creds.py — do not edit */
#ifndef FW_CREDS_H
#define FW_CREDS_H

{c_array("fw_client_cert_der", client_cert_der, ".fw_creds")}
{c_array("fw_root_ca_der", root_ca_der)}
{c_array("fw_client_ca_der", client_ca_der)}
/* Raw home-PC user public-key bits: ENCRYPT/DECRYPT pin the TLS peer to this. */
{c_array("fw_user_spki", user_spki, ".fw_creds")}
/* Raw ML-DSA subject public key bits: hashed into client_hash, never sent. */
{c_array("fw_client_spki", client_spki, ".fw_creds")}
/* TROPIC01 P-256 certificate; unused for now (key generated on chip). */
{c_array("fw_tropic_cert_der", tropic_cert)}
/* ML-KEM-768 public key (TROPIC KEM PUB); len 0 until provisioned. */
{c_array("fw_mlkem_pk", mlkem_pk)}
#endif /* FW_CREDS_H */
"""

    wrap_header = f"""/* Auto-generated by scripts/embed_fw_creds.py — do not edit */
#ifndef WRAPPED_CLIENT_KEY_H
#define WRAPPED_CLIENT_KEY_H

{c_array("secure_dwk", dwk)}
{c_array("secure_wrapped_client_key", blob)}

#endif /* WRAPPED_CLIENT_KEY_H */
"""

    out_creds.parent.mkdir(parents=True, exist_ok=True)
    out_wrap.parent.mkdir(parents=True, exist_ok=True)
    out_creds.write_text(creds_header, encoding="utf-8")
    out_wrap.write_text(wrap_header, encoding="utf-8")

    print(f"wrote {out_creds}")
    print(f"  client cert {len(client_cert_der)} B, SAE CA {len(root_ca_der)} B, "
          f"client CA {len(client_ca_der)} B, user SPKI {len(user_spki)} B, "
          f"client SPKI {len(client_spki)} B")
    print(        f"  tropic cert {len(tropic_cert)} B, ML-KEM pk {len(mlkem_pk)} B")
    print(f"wrote {out_wrap} (wrapped key {len(blob)} bytes, secure_dwk "
          f"{'reused' if reused_dwk else 'NEW — sealed R-MEM blobs are now unreadable'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

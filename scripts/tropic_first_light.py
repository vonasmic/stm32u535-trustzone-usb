#!/usr/bin/env python3
"""Stage 1.7 acceptance: first light on TS13 silicon over the USB CDC console.

Runs TROPIC INFO / PUB / SIGN against the device, verifies the returned P-256
signature off-device, and writes the raw public key.

Usage:
  tropic_first_light.py <port> [--keygen] [--out tropic_pub.bin] [--message TEXT]

  <port>       serial device, e.g. COM7 or /dev/ttyACM0
  --keygen     also run TROPIC KEYGEN first if the ECC slot is empty
  --out        where to write the 64-byte raw X||Y public key
  --message    string whose SHA-384 is signed (default "tropic-first-light")

TROPIC KEYGEN generates the device identity key inside the chip when the slot
is empty. Occupied slots refuse without a PIN (`TROPIC KEYGEN <pin>`).
It is only attempted when --keygen is passed explicitly.
"""
from __future__ import annotations

import argparse
import hashlib
import sys

from tropic_console import DeviceError, open_port, read_pub, sign_digest, step


def verify_p256(pub_xy: bytes, digest: bytes, rs: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + pub_xy)
    der_sig = utils.encode_dss_signature(
        int.from_bytes(rs[:32], "big"), int.from_bytes(rs[32:], "big")
    )
    # P-256 with SHA-384: the leftmost 256 bits of the digest are what the chip signed.
    try:
        pub.verify(der_sig, digest, ec.ECDSA(utils.Prehashed(hashes.SHA384())))
    except InvalidSignature as exc:
        raise DeviceError("signature did NOT verify") from exc


def main() -> int:
    ap = argparse.ArgumentParser(description="TROPIC01 silicon first light")
    ap.add_argument("port")
    ap.add_argument("--keygen", action="store_true",
                    help="run TROPIC KEYGEN (empty slot only; occupied needs PIN)")
    ap.add_argument("--out", default="tropic_pub.bin",
                    help="write raw 64-byte X||Y public key here")
    ap.add_argument("--message", default="tropic-first-light")
    ap.add_argument("--baud", type=int, default=115200)
    args = ap.parse_args()

    try:
        ser = open_port(args.port, args.baud)
    except Exception as exc:
        print(f"cannot open {args.port}: {exc}", file=sys.stderr)
        return 1

    try:
        step(ser, "TROPIC INFO", 4.0)

        if args.keygen:
            lines = step(ser, "TROPIC KEYGEN", 5.0)
            if any("slot occupied" in ln for ln in lines):
                print("slot already holds a key; skipping KEYGEN")

        pub = read_pub(ser)
        digest = hashlib.sha384(args.message.encode("utf-8")).digest()
        # TROPIC SIGN takes exactly 32 bytes, the same leftmost half the verifier uses.
        rs = sign_digest(ser, digest[:32])
        verify_p256(pub, digest, rs)
    except DeviceError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    finally:
        ser.close()

    with open(args.out, "wb") as fh:
        fh.write(pub)

    print()
    print(f"public key : {pub.hex()}")
    print(f"message    : {args.message!r}")
    print(f"sha384     : {digest.hex()}")
    print(f"signature  : {rs.hex()}")
    print(f"wrote      : {args.out}")
    print("PASS: signature verifies against the chip's public key")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

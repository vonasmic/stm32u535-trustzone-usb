#!/usr/bin/env python3
"""Generate the TROPIC01 identity key on the chip.

CA-signed certificates are not used yet. The private key is created inside the
TROPIC01 and never exported; this script only drives the USB CDC console.

Usage:
  make_tropic_cert.py --port <serial> [--keygen] [--out tropic_pub.bin]

  --keygen     send TROPIC KEYGEN if the ECC slot is empty
  --out        write the 64-byte raw X||Y public key here

Without --keygen the script only reads TROPIC PUB. Occupied KEYGEN is refused
unless PIN is supplied (`TROPIC KEYGEN <pin>`).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tropic_console import DeviceError, open_port, read_pub, step


def maybe_keygen(ser, do_keygen: bool) -> None:
    if not do_keygen:
        return
    lines = step(ser, "TROPIC KEYGEN", 5.0)
    if any("slot occupied" in ln for ln in lines):
        print("slot already holds a key; skipping KEYGEN")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate (or read) the TROPIC01 P-256 identity key on chip"
    )
    ap.add_argument("--port", required=True, help="serial port, e.g. COM7 or /dev/ttyACM0")
    ap.add_argument("--keygen", action="store_true",
                    help="run TROPIC KEYGEN (empty slot only; occupied needs PIN)")
    ap.add_argument("--out", default="tropic_pub.bin",
                    help="write raw 64-byte X||Y public key here")
    ap.add_argument("--baud", type=int, default=115200)
    args = ap.parse_args()

    try:
        ser = open_port(args.port, args.baud)
    except Exception as exc:
        print(f"cannot open {args.port}: {exc}", file=sys.stderr)
        return 1

    try:
        maybe_keygen(ser, args.keygen)
        pub = read_pub(ser)
    except DeviceError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    finally:
        ser.close()

    out = Path(args.out)
    out.write_bytes(pub)
    print()
    print(f"public key : {pub.hex()}")
    print(f"wrote      : {out} ({len(pub)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

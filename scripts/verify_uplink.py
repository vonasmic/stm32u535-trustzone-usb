#!/usr/bin/env python3
"""Stage 3.5: SAE/server-side verification of the device session uplink.

Reference implementation of the checks the SAE application must perform. The
point of the exercise is that a man-in-the-middle terminating TLS on both sides
derives a different exporter, so a forwarded uplink cannot verify here.

Uplink v1 items, by position:
  1  session signature, raw R||S             64 B
  2  TROPIC01 P-256 public key, X||Y         64 B
  3  client hash                             32 B
  4,6,8..  peer hash = SHA256(peer_spki)     32 B
  5,7,9..  peer name, UTF-8

Usage:
  verify_uplink.py --uplink FILE --client-cert PEM --exporter HEX
                   [--peer NAME=PEM]...
  verify_uplink.py --selftest
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from embed_fw_creds import spki_raw_from_cert_der
from secure_lv import SECURE_LV_UPLINK_FIXED_ITEMS, LvError, LvVersionError, decode, encode

EXPORTER_LABEL = b"EXPORTER-tropic-binding"
EXPORTER_LEN = 32
SIG_LEN = 64
ECC_PUB_LEN = 64
HASH_LEN = 32


class UplinkError(ValueError):
    pass


def _verify_p256(pub_xy: bytes, digest: bytes, rs: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + pub_xy)
    der = utils.encode_dss_signature(
        int.from_bytes(rs[:32], "big"), int.from_bytes(rs[32:], "big")
    )
    try:
        pub.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except InvalidSignature as exc:
        raise UplinkError("session signature does not verify") from exc


def verify_uplink(data: bytes, mldsa_spki: bytes, exporter: bytes,
                  peer_registry: dict[str, bytes] | None = None) -> dict:
    """Return the authenticated identity, or raise. Version errors surface as LvVersionError."""
    items = decode(data)

    if len(items) < SECURE_LV_UPLINK_FIXED_ITEMS:
        raise UplinkError(f"expected at least {SECURE_LV_UPLINK_FIXED_ITEMS} items, "
                          f"got {len(items)}")
    trailing = len(items) - SECURE_LV_UPLINK_FIXED_ITEMS
    if trailing % 2 != 0:
        raise UplinkError("peer entries must be hash/name pairs")

    signature, ecc_pub, client_hash_wire = items[0], items[1], items[2]
    if len(signature) != SIG_LEN:
        raise UplinkError(f"signature must be {SIG_LEN} bytes, got {len(signature)}")
    if len(ecc_pub) != ECC_PUB_LEN:
        raise UplinkError(f"ECC public key must be {ECC_PUB_LEN} bytes, got {len(ecc_pub)}")
    if len(exporter) != EXPORTER_LEN:
        raise UplinkError(f"exporter must be {EXPORTER_LEN} bytes, got {len(exporter)}")

    # Recompute rather than trust field 3; the wire copy is only a cross-check.
    client_hash = hashlib.sha256(mldsa_spki + ecc_pub).digest()
    if client_hash_wire != client_hash:
        raise UplinkError("client_hash mismatch: uplink is not bound to this mTLS identity")

    _verify_p256(ecc_pub, hashlib.sha256(client_hash + exporter).digest(), signature)

    registry = {name: hashlib.sha256(spki).digest() for name, spki in (peer_registry or {}).items()}
    by_hash = {digest: name for name, digest in registry.items()}

    peers = []
    for i in range(SECURE_LV_UPLINK_FIXED_ITEMS, len(items), 2):
        digest, raw_name = items[i], items[i + 1]
        if len(digest) != HASH_LEN:
            raise UplinkError(f"peer hash must be {HASH_LEN} bytes, got {len(digest)}")
        name = raw_name.decode("utf-8")
        known = by_hash.get(digest)
        if registry and known is None:
            raise UplinkError(f"peer {name!r} not in the configured registry")
        if known is not None and known != name:
            raise UplinkError(f"peer hash matches {known!r} but uplink says {name!r}")
        peers.append({"name": name, "hash": digest.hex(), "known": known is not None})

    return {
        "ecc_pub": ecc_pub.hex(),
        "client_hash": client_hash.hex(),
        "signature": signature.hex(),
        "peers": peers,
    }


def build_uplink(signer, ecc_pub: bytes, mldsa_spki: bytes, exporter: bytes,
                 peers: list[tuple[str, bytes]]) -> bytes:
    """Device-side encoder, mirrored here so the verifier is testable without hardware."""
    client_hash = hashlib.sha256(mldsa_spki + ecc_pub).digest()
    signature = signer(hashlib.sha256(client_hash + exporter).digest())
    items = [signature, ecc_pub, client_hash]
    for name, spki in peers:
        items.append(hashlib.sha256(spki).digest())
        items.append(name.encode("utf-8"))
    return encode(items)


def selftest() -> int:
    import os

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    ecc_pub = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")

    def signer(digest: bytes) -> bytes:
        der = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    mldsa_spki = os.urandom(2420)
    exporter = os.urandom(EXPORTER_LEN)
    alice_spki = os.urandom(2420)
    registry = {"Alice": alice_spki}

    uplink = build_uplink(signer, ecc_pub, mldsa_spki, exporter, [("Alice", alice_spki)])
    result = verify_uplink(uplink, mldsa_spki, exporter, registry)
    assert result["peers"] == [{"name": "Alice",
                                "hash": hashlib.sha256(alice_spki).digest().hex(),
                                "known": True}]
    print("ok: genuine uplink verifies")

    # A MitM re-derives a different exporter from its own TLS session.
    try:
        verify_uplink(uplink, mldsa_spki, os.urandom(EXPORTER_LEN), registry)
    except UplinkError:
        print("ok: forwarded uplink rejected under a different exporter")
    else:
        raise AssertionError("forwarded uplink accepted")

    # Swapping in another device's mTLS identity breaks client_hash.
    try:
        verify_uplink(uplink, os.urandom(2420), exporter, registry)
    except UplinkError:
        print("ok: uplink rejected against a different mTLS identity")
    else:
        raise AssertionError("wrong mTLS identity accepted")

    try:
        decode(b"\x02" + uplink[1:])
    except LvVersionError:
        print("ok: unknown envelope version rejected before parsing items")
    else:
        raise AssertionError("unknown version accepted")

    try:
        verify_uplink(uplink, mldsa_spki, exporter, {"Bob": os.urandom(2420)})
    except UplinkError:
        print("ok: peer outside the configured registry rejected")
    else:
        raise AssertionError("unknown peer accepted")

    print("PASS verify_uplink selftest")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify a device session uplink")
    ap.add_argument("--uplink", help="file holding the raw LV uplink bytes")
    ap.add_argument("--client-cert", help="mTLS client certificate (PEM) the server holds")
    ap.add_argument("--exporter", help="32-byte exporter from the server's TLS session, hex")
    ap.add_argument("--peer", action="append", default=[], metavar="NAME=PEM")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not (args.uplink and args.client_cert and args.exporter):
        ap.error("--uplink, --client-cert and --exporter are required")

    import subprocess

    cert_der = subprocess.check_output(
        ["openssl", "x509", "-in", args.client_cert, "-outform", "DER"]
    )
    registry = {}
    for item in args.peer:
        if "=" not in item:
            ap.error(f"--peer expects NAME=PEM, got {item!r}")
        name, path = item.split("=", 1)
        peer_der = subprocess.check_output(["openssl", "x509", "-in", path, "-outform", "DER"])
        registry[name] = spki_raw_from_cert_der(peer_der)

    try:
        result = verify_uplink(
            Path(args.uplink).read_bytes(),
            spki_raw_from_cert_der(cert_der),
            bytes.fromhex(args.exporter),
            registry,
        )
    except (LvVersionError, LvError, UplinkError) as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1

    print(f"ecc_pub     : {result['ecc_pub']}")
    print(f"client_hash : {result['client_hash']}")
    for peer in result["peers"]:
        mark = "known" if peer["known"] else "unverified"
        print(f"peer        : {peer['name']} ({mark}) {peer['hash']}")
    print("ACCEPT: session signature is bound to this TLS session and mTLS identity")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

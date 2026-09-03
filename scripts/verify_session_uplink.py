#!/usr/bin/env python3
"""Stage 3.5 reference: SAE/server-side verification of the session uplink.

The device sends the versioned LV envelope from Secure/Core/Inc/secure_lv.h:

  u8  version
  u16 count
  count times: u16 len, u8 value[len]

Version 1 items, by position:
  1  session signature, raw R||S                   64 B
  2  TROPIC01 P-256 public key, X||Y               64 B
  3  client hash                                   32 B
  4,6,8..  peer hash = SHA256(peer_spki)           32 B
  5,7,9..  peer nickname, UTF-8                    variable

Verification order, per the plan:
  1. Reject an unknown version before reading count or any item.
  2. Derive the exporter from the local TLS session with the same label and
     length the device used, and pass it in with --exporter.
  3. Extract the ML-DSA subject public key from the mTLS client certificate the
     server already holds. Never take it from the wire.
  4. Recompute client_hash = SHA256(mldsa_spki || ecc_pub) from that SPKI and
     item 2, and compare against item 3. Item 3 is a cross-check, not an input.
  5. Verify item 1 over SHA256(client_hash || exporter) using item 2.

A man-in-the-middle terminates TLS on both sides, so its exporter differs from
the one the device signed and a forwarded uplink fails at step 5.

Usage:
  verify_session_uplink.py --uplink FILE --exporter HEX --client-cert FILE
                           [--peer NAME=CERT ...]
  verify_session_uplink.py --self-test
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import sys
from pathlib import Path

LV_VERSION = 1
UPLINK_FIXED_ITEMS = 3
EXPORTER_LABEL = b"EXPORTER-tropic-binding"
EXPORTER_LEN = 32
SIG_LEN = 64
ECC_PUB_LEN = 64
CLIENT_HASH_LEN = 32
PEER_HASH_LEN = 32


class UplinkError(RuntimeError):
    pass


class VersionError(UplinkError):
    pass


def parse_lv(data: bytes) -> list[bytes]:
    """Parse the shared LV envelope. Version is checked before anything else."""
    if len(data) < 3:
        raise UplinkError("uplink shorter than the envelope header")
    version = data[0]
    if version != LV_VERSION:
        raise VersionError(f"unsupported LV version {version}, expected {LV_VERSION}")

    count = int.from_bytes(data[1:3], "little")
    items: list[bytes] = []
    pos = 3
    for index in range(count):
        if pos + 2 > len(data):
            raise UplinkError(f"truncated length prefix for item {index + 1}")
        length = int.from_bytes(data[pos:pos + 2], "little")
        pos += 2
        if pos + length > len(data):
            raise UplinkError(f"truncated value for item {index + 1}")
        items.append(data[pos:pos + length])
        pos += length
    if pos != len(data):
        raise UplinkError(f"{len(data) - pos} trailing bytes after {count} items")
    return items


# --- certificate helpers -------------------------------------------------


def read_asn1_len(data: bytes, pos: int) -> tuple[int, int]:
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
    """Raw subjectPublicKey bits; must match fw_client_spki on the device."""
    certificate = der_children(der)
    if not certificate or certificate[0][0] != 0x30:
        raise UplinkError("not a DER certificate")
    tbs = der_children(certificate[0][1])
    if not tbs or tbs[0][0] != 0x30:
        raise UplinkError("missing tbsCertificate")
    for tag, body in der_children(tbs[0][1]):
        if tag != 0x30:
            continue
        fields = der_children(body)
        if len(fields) == 2 and fields[0][0] == 0x30 and fields[1][0] == 0x03:
            bits = fields[1][1]
            return bits[1:] if bits and bits[0] == 0x00 else bits
    raise UplinkError("could not locate subjectPublicKeyInfo")


def load_cert_der(path: Path) -> bytes:
    raw = path.read_bytes()
    if raw[:1] == b"\x30":
        return raw
    text = raw.decode("ascii", errors="replace")
    body = "".join(ln.strip() for ln in text.splitlines() if ln and not ln.startswith("-----"))
    return base64.b64decode(body)


# --- verification --------------------------------------------------------


def verify_p256(pub_xy: bytes, digest: bytes, rs: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + pub_xy)
    der_sig = utils.encode_dss_signature(
        int.from_bytes(rs[:32], "big"), int.from_bytes(rs[32:], "big")
    )
    try:
        pub.verify(der_sig, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except InvalidSignature:
        return False
    return True


def verify_uplink(data: bytes, exporter: bytes, client_spki: bytes,
                  peer_registry: dict[str, bytes] | None = None) -> dict:
    items = parse_lv(data)
    if len(items) < UPLINK_FIXED_ITEMS:
        raise UplinkError(f"expected at least {UPLINK_FIXED_ITEMS} items, got {len(items)}")
    if (len(items) - UPLINK_FIXED_ITEMS) % 2 != 0:
        raise UplinkError("peer items must come in hash/name pairs")
    if len(exporter) != EXPORTER_LEN:
        raise UplinkError(f"exporter must be {EXPORTER_LEN} bytes")

    signature, ecc_pub, client_hash = items[0], items[1], items[2]
    if len(signature) != SIG_LEN:
        raise UplinkError(f"signature must be {SIG_LEN} bytes, got {len(signature)}")
    if len(ecc_pub) != ECC_PUB_LEN:
        raise UplinkError(f"ECC public key must be {ECC_PUB_LEN} bytes, got {len(ecc_pub)}")
    if len(client_hash) != CLIENT_HASH_LEN:
        raise UplinkError(f"client hash must be {CLIENT_HASH_LEN} bytes")

    # Recomputed from the mTLS identity, never trusted from the wire.
    expected_hash = hashlib.sha256(client_spki + ecc_pub).digest()
    if expected_hash != client_hash:
        raise UplinkError("client hash does not match the mTLS client certificate")

    to_sign = hashlib.sha256(client_hash + exporter).digest()
    if not verify_p256(ecc_pub, to_sign, signature):
        raise UplinkError("session signature does not verify (forwarded or replayed?)")

    peers = []
    registry = {name: hashlib.sha256(spki).digest() for name, spki in (peer_registry or {}).items()}
    reverse = {digest: name for name, digest in registry.items()}
    for i in range(UPLINK_FIXED_ITEMS, len(items), 2):
        digest, name_bytes = items[i], items[i + 1]
        if len(digest) != PEER_HASH_LEN:
            raise UplinkError(f"peer hash must be {PEER_HASH_LEN} bytes")
        name = name_bytes.decode("utf-8")
        known = reverse.get(digest)
        if registry and known is None:
            raise UplinkError(f"peer {name!r} hash is not in the configured registry")
        if known is not None and known != name:
            raise UplinkError(f"peer hash matches {known!r} but the uplink says {name!r}")
        peers.append({"name": name, "hash": digest.hex(), "known": known is not None})

    return {
        "ecc_pub": ecc_pub.hex(),
        "client_hash": client_hash.hex(),
        "signature": signature.hex(),
        "peers": peers,
    }


# --- self test -----------------------------------------------------------


def build_uplink(sign, ecc_pub: bytes, client_spki: bytes, exporter: bytes,
                 peers: list[tuple[str, bytes]]) -> bytes:
    """Encode what se_tropic_session.c streams, for round-trip testing."""
    client_hash = hashlib.sha256(client_spki + ecc_pub).digest()
    signature = sign(hashlib.sha256(client_hash + exporter).digest())

    items = [signature, ecc_pub, client_hash]
    for name, spki in peers:
        items.append(hashlib.sha256(spki).digest())
        items.append(name.encode("utf-8"))

    out = bytes([LV_VERSION]) + len(items).to_bytes(2, "little")
    for item in items:
        out += len(item).to_bytes(2, "little") + item
    return out


def self_test() -> int:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    ecc_pub = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")

    def sign(digest: bytes) -> bytes:
        der = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    client_spki = b"\xa5" * 1312
    exporter = bytes(range(EXPORTER_LEN))
    peers = [("Alice", b"\x11" * 1312), ("Bob", b"\x22" * 1312)]
    registry = dict(peers)

    uplink = build_uplink(sign, ecc_pub, client_spki, exporter, peers)
    result = verify_uplink(uplink, exporter, client_spki, registry)
    assert [p["name"] for p in result["peers"]] == ["Alice", "Bob"]
    assert all(p["known"] for p in result["peers"])
    print(f"ok: valid uplink accepted ({len(uplink)} bytes, {len(peers)} peers)")

    def expect_reject(label: str, fn) -> None:
        try:
            fn()
        except UplinkError as exc:
            print(f"ok: {label} rejected ({exc})")
            return
        raise AssertionError(f"{label} was accepted")

    expect_reject("version 2 envelope",
                  lambda: verify_uplink(b"\x02" + uplink[1:], exporter, client_spki, registry))
    expect_reject("forwarded uplink (different exporter)",
                  lambda: verify_uplink(uplink, bytes(EXPORTER_LEN), client_spki, registry))
    expect_reject("wrong mTLS identity",
                  lambda: verify_uplink(uplink, exporter, b"\xa6" * 1312, registry))
    expect_reject("unknown peer",
                  lambda: verify_uplink(uplink, exporter, client_spki, {"Alice": b"\x11" * 1312}))
    expect_reject("peer name/hash mismatch",
                  lambda: verify_uplink(uplink, exporter, client_spki,
                                        {"Alice": b"\x11" * 1312, "Mallory": b"\x22" * 1312}))
    expect_reject("truncated uplink",
                  lambda: verify_uplink(uplink[:-1], exporter, client_spki, registry))

    tampered = bytearray(uplink)
    tampered[3 + 2] ^= 0x01
    expect_reject("tampered signature",
                  lambda: verify_uplink(bytes(tampered), exporter, client_spki, registry))

    print("PASS self-test")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify a TROPIC01 session uplink")
    ap.add_argument("--uplink", help="raw LV uplink bytes as received over TLS")
    ap.add_argument("--exporter", help="32-byte exporter from the local TLS session, hex")
    ap.add_argument("--client-cert", help="mTLS client certificate (PEM or DER)")
    ap.add_argument("--peer", action="append", default=[], metavar="NAME=CERT")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if not (args.uplink and args.exporter and args.client_cert):
        ap.error("--uplink, --exporter and --client-cert are required")

    registry = {}
    for spec in args.peer:
        if "=" not in spec:
            ap.error(f"--peer expects NAME=CERT, got {spec!r}")
        name, _, path = spec.partition("=")
        registry[name] = spki_raw_from_cert_der(load_cert_der(Path(path)))

    client_spki = spki_raw_from_cert_der(load_cert_der(Path(args.client_cert)))
    try:
        result = verify_uplink(Path(args.uplink).read_bytes(),
                               bytes.fromhex(args.exporter), client_spki, registry)
    except VersionError as exc:
        print(f"REJECT (schema mismatch): {exc}", file=sys.stderr)
        return 2
    except UplinkError as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1

    print(f"ECC public key : {result['ecc_pub']}")
    print(f"client hash    : {result['client_hash']}")
    for peer in result["peers"]:
        print(f"peer           : {peer['name']} ({'known' if peer['known'] else 'unmatched'})")
    print("PASS: session signature is bound to this TLS session and this device")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

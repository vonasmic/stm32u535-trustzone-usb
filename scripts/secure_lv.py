#!/usr/bin/env python3
"""Host-side encoder/decoder for the shared LV envelope (Secure/Core/Inc/secure_lv.h).

Used by the SAE application for both directions: the session uplink it receives
from the device, the QKD downlink it sends back, and the OTP encrypt reply.

TLS session role is not on this channel. Host USB commands
``PROVISION / ENCRYPT / DECRYPT <unix>`` select the post-handshake path and
set the clock. Encrypt app data is ``u8 pin_len | pin | u32 msg_len LE`` then
raw plaintext. Decrypt app data is ``u8 pin_len | pin`` plus the encrypt reply
unchanged. Encrypt reply is ``u16 n_pads`` then slot/len/chunk records.
Decrypt reply is ``u16 n_pads`` then len/chunk plaintext records (no slots).
Downlink v2 item 1 is ``decrypt_half`` (0 = first pad
half decrypt, 1 = second).

  u8   version
  u16  count            (LE)
  repeat count times:
    u16 len             (LE)
    u8  value[len]
"""
from __future__ import annotations

SECURE_LV_VERSION = 1
SECURE_LV_DOWNLINK_VERSION = 2
SECURE_LV_UPLINK_VERSION = 3
SECURE_LV_UPLINK_FIXED_ITEMS = 7
# Mirrors SECURE_QKD_MAX_BYTES on the device.
SECURE_LV_MAX_BYTES = 200 * 1024


class LvError(ValueError):
    """Malformed or oversized envelope."""


class LvVersionError(LvError):
    """Envelope version this build does not understand — never parse further."""


def encode(items: list[bytes], version: int = SECURE_LV_VERSION) -> bytes:
    if len(items) > 0xFFFF:
        raise LvError(f"too many items: {len(items)}")
    out = bytearray()
    out.append(version)
    out += len(items).to_bytes(2, "little")
    for item in items:
        if len(item) > 0xFFFF:
            raise LvError(f"item too long: {len(item)}")
        out += len(item).to_bytes(2, "little")
        out += item
    return bytes(out)


def decode(data: bytes, max_bytes: int = SECURE_LV_MAX_BYTES,
           expected_version: int = SECURE_LV_VERSION) -> list[bytes]:
    """Version is checked before anything else; an unknown layout is never parsed."""
    if len(data) < 1:
        raise LvError("empty envelope")
    if data[0] != expected_version:
        raise LvVersionError(
            f"schema mismatch: got v{data[0]}, expect v{expected_version}")
    if len(data) < 3:
        raise LvError("truncated count")

    count = int.from_bytes(data[1:3], "little")
    pos = 3
    total = 0
    items: list[bytes] = []
    for index in range(count):
        if pos + 2 > len(data):
            raise LvError(f"truncated length for item {index}")
        length = int.from_bytes(data[pos:pos + 2], "little")
        pos += 2
        total += length
        if total > max_bytes:
            raise LvError(f"envelope exceeds {max_bytes} bytes")
        if pos + length > len(data):
            raise LvError(f"truncated value for item {index}")
        items.append(data[pos:pos + length])
        pos += length

    if pos != len(data):
        raise LvError(f"{len(data) - pos} trailing bytes after {count} items")
    return items


def encode_otp_encrypt_reply(records: list[tuple[int, bytes]]) -> bytes:
    """ENCRYPT reply: u16 n_pads LE then (logical_slot, chunk_len, ciphertext) records."""
    if not records or len(records) > 0xFFFF:
        raise LvError("OTP stream empty" if not records else f"too many pads: {len(records)}")
    out = bytearray()
    out += len(records).to_bytes(2, "little")
    for slot, chunk in records:
        if not chunk or len(chunk) > 0xFFFF:
            raise LvError(f"OTP chunk length {len(chunk) if chunk else 0} out of range")
        if slot < 0 or slot > 0xFFFF:
            raise LvError(f"OTP slot {slot} out of range")
        out += slot.to_bytes(2, "little")
        out += len(chunk).to_bytes(2, "little")
        out += chunk
    return bytes(out)


def encode_otp_encrypt_request(pin: bytes, msg: bytes) -> bytes:
    """ENCRYPT request: PIN + u32 LE len(msg) + plaintext. SAE does not split pads."""
    if not pin or len(pin) < 4 or len(pin) > 8:
        raise LvError(f"OTP PIN length {len(pin) if pin else 0} out of range")
    if not msg:
        raise LvError("OTP payload empty")
    return bytes([len(pin)]) + pin + len(msg).to_bytes(4, "little") + msg


def encode_otp_decrypt_request(pin: bytes, encrypt_reply: bytes) -> bytes:
    """DECRYPT request: PIN then the previous encrypt reply, unchanged."""
    if not pin or len(pin) < 4 or len(pin) > 8:
        raise LvError(f"OTP PIN length {len(pin) if pin else 0} out of range")
    if not encrypt_reply:
        raise LvError("empty OTP stream")
    return bytes([len(pin)]) + pin + encrypt_reply


def encode_otp_decrypt_reply(chunks: list[bytes]) -> bytes:
    """DECRYPT reply: pad count then (chunk_len, plaintext) records. No slots."""
    if not chunks or len(chunks) > 0xFFFF:
        raise LvError("OTP stream empty" if not chunks else f"too many pads: {len(chunks)}")
    out = bytearray()
    out += len(chunks).to_bytes(2, "little")
    for chunk in chunks:
        if not chunk or len(chunk) > 0xFFFF:
            raise LvError(f"OTP chunk length {len(chunk) if chunk else 0} out of range")
        out += len(chunk).to_bytes(2, "little")
        out += chunk
    return bytes(out)


def decode_otp_encrypt_reply(data: bytes) -> list[tuple[int, bytes]]:
    """Return [(logical slot, ciphertext), ...] from an ENCRYPT reply (also the DECRYPT request body)."""
    if not data or len(data) < 2:
        raise LvError("empty OTP stream")
    n_pads = int.from_bytes(data[0:2], "little")
    if n_pads < 1:
        raise LvError("OTP stream has no records")
    pos = 2
    records: list[tuple[int, bytes]] = []
    for _ in range(n_pads):
        if pos + 4 > len(data):
            raise LvError("truncated OTP record header")
        slot = int.from_bytes(data[pos:pos + 2], "little")
        length = int.from_bytes(data[pos + 2:pos + 4], "little")
        pos += 4
        if length < 1:
            raise LvError("empty OTP chunk")
        if pos + length > len(data):
            raise LvError("truncated OTP chunk")
        records.append((slot, data[pos:pos + length]))
        pos += length
    if pos != len(data):
        raise LvError(f"{len(data) - pos} trailing bytes after {n_pads} pads")
    return records


def decode_otp_decrypt_reply(data: bytes) -> bytes:
    """Concatenate plaintext chunks from a DECRYPT reply (no slots)."""
    if not data or len(data) < 2:
        raise LvError("empty OTP stream")
    n_pads = int.from_bytes(data[0:2], "little")
    if n_pads < 1:
        raise LvError("OTP stream has no records")
    pos = 2
    chunks: list[bytes] = []
    for _ in range(n_pads):
        if pos + 2 > len(data):
            raise LvError("truncated OTP chunk length")
        length = int.from_bytes(data[pos:pos + 2], "little")
        pos += 2
        if length < 1:
            raise LvError("empty OTP chunk")
        if pos + length > len(data):
            raise LvError("truncated OTP chunk")
        chunks.append(data[pos:pos + length])
        pos += length
    if pos != len(data):
        raise LvError(f"{len(data) - pos} trailing bytes after {n_pads} pads")
    return b"".join(chunks)

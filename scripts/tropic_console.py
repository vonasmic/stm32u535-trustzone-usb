#!/usr/bin/env python3
"""Shared helpers for driving the SE_firmware USB CDC console.

The device answers host commands with "DEBUG: " prefixed ASCII lines. Values
longer than one line (public keys, signatures) are printed as a marker line
followed by hex-only continuation lines.
"""
from __future__ import annotations

import re
import time

DEBUG_PREFIX = "DEBUG: "
HEX_LINE = re.compile(r"^[0-9a-fA-F]+$")

PUB_MARKER = "TROPIC P-256 pub:"
SIG_MARKER = "TROPIC sig:"
KEM_PUB_MARKER = "TROPIC KEM pub:"
OTP_MARKER = "TROPIC OTP out:"

PUB_BYTES = 64
SIG_BYTES = 64
MLKEM_PK_BYTES = 1184


class DeviceError(RuntimeError):
    pass


def open_port(port: str, baud: int = 115200):
    try:
        import serial  # type: ignore
    except ImportError:
        raise DeviceError("pyserial is required: pip install pyserial")
    ser = serial.Serial(port, baud, timeout=0.2)
    ser.dtr = True
    time.sleep(0.3)
    ser.reset_input_buffer()
    return ser


def send(ser, line: str) -> None:
    ser.write((line + "\n").encode("ascii"))
    ser.flush()


def read_lines(ser, seconds: float) -> list[str]:
    """Collect DEBUG lines for a fixed window; the device is free-running."""
    deadline = time.time() + seconds
    buf = b""
    out: list[str] = []
    while time.time() < deadline:
        chunk = ser.read(256)
        if not chunk:
            continue
        buf += chunk
        while b"\n" in buf:
            raw, buf = buf.split(b"\n", 1)
            text = raw.decode("ascii", errors="replace").strip()
            if not text:
                continue
            if text.startswith(DEBUG_PREFIX):
                text = text[len(DEBUG_PREFIX):]
            out.append(text)
    return out


def collect_hex_after(lines: list[str], marker: str, want_bytes: int) -> bytes:
    """Device prints a marker line, then the value split across hex-only lines."""
    for i, line in enumerate(lines):
        if line != marker:
            continue
        acc = ""
        for tail in lines[i + 1:]:
            if not HEX_LINE.match(tail):
                break
            acc += tail
            if len(acc) >= want_bytes * 2:
                break
        if len(acc) >= want_bytes * 2:
            return bytes.fromhex(acc[: want_bytes * 2])
    raise DeviceError(f"did not find {want_bytes} bytes of hex after {marker!r}")


def step(ser, command: str, window: float, echo: bool = True) -> list[str]:
    if echo:
        print(f"--> {command}")
    send(ser, command)
    lines = read_lines(ser, window)
    if echo:
        for line in lines:
            print(f"    {line}")
    return lines


def read_pub(ser, echo: bool = True) -> bytes:
    """TROPIC PUB -> raw 64-byte X||Y."""
    return collect_hex_after(step(ser, "TROPIC PUB", 3.0, echo), PUB_MARKER, PUB_BYTES)


def sign_digest(ser, digest: bytes, echo: bool = True) -> bytes:
    """TROPIC SIGN <hash> -> raw 64-byte R||S."""
    if len(digest) != 32:
        raise DeviceError("digest must be 32 bytes")
    lines = step(ser, f"TROPIC SIGN {digest.hex()}", 4.0, echo)
    return collect_hex_after(lines, SIG_MARKER, SIG_BYTES)


def read_kem_pub(ser, echo: bool = True) -> bytes:
    """TROPIC KEM PUB -> raw 1184-byte ML-KEM-768 public key."""
    lines = step(ser, "TROPIC KEM PUB", 6.0, echo)
    return collect_hex_after(lines, KEM_PUB_MARKER, MLKEM_PK_BYTES)

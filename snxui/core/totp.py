"""TOTP/HOTP implementation (RFC 6238 / RFC 4226) using stdlib only."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time


def _hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    """Compute HOTP code. Raises ValueError on invalid secret."""
    secret_b32 = secret_b32.upper().strip()
    padding = (8 - len(secret_b32) % 8) % 8
    key = base64.b32decode(secret_b32 + "=" * padding)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def generate_totp(secret_b32: str, digits: int = 6, step: int = 30) -> str:
    """Return current TOTP code."""
    return _hotp(secret_b32, int(time.time()) // step, digits)


def seconds_remaining(step: int = 30) -> int:
    """Seconds until the current TOTP code expires."""
    return step - (int(time.time()) % step)

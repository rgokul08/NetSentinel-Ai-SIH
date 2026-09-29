"""RFC 6238 TOTP implementation (no third-party dependency).

Used for optional multi-factor authentication. Secrets are base32 encoded and
stored server side only; provisioning payloads are never written to the ledger.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
from typing import Optional
from urllib.parse import quote

PERIOD = 30
DIGITS = 6
ALGORITHM = "SHA1"
DRIFT_STEPS = 1  # accept one step of clock drift in either direction


def generate_secret(length: int = 32) -> str:
    """Return a base32 secret suitable for authenticator apps."""
    raw = os.urandom(length)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    padding = "=" * (-len(secret) % 8)
    try:
        key = base64.b32decode(secret.upper() + padding)
    except Exception:  # pragma: no cover - invalid secret
        raise ValueError("Invalid TOTP secret encoding")
    message = struct.pack(">Q", counter)
    digest = hmac.new(key, message, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** DIGITS)).zfill(DIGITS)


def current_code(secret: str, at: Optional[float] = None) -> str:
    now = time.time() if at is None else at
    return _hotp(secret, int(now // PERIOD))


def verify_code(secret: str, code: Optional[str], at: Optional[float] = None, drift: int = DRIFT_STEPS) -> bool:
    """Constant-time-ish verification allowing a small clock drift window."""
    if not secret or not code:
        return False
    candidate = str(code).strip()
    if not candidate.isdigit() or len(candidate) != DIGITS:
        return False
    now = time.time() if at is None else at
    step = int(now // PERIOD)
    for offset in range(-drift, drift + 1):
        if hmac.compare_digest(_hotp(secret, step + offset), candidate):
            return True
    return False


def seconds_remaining(at: Optional[float] = None) -> int:
    now = time.time() if at is None else at
    return PERIOD - int(now % PERIOD)


def provisioning_uri(secret: str, account: str, issuer: str) -> str:
    label = quote(f"{issuer}:{account}", safe="")
    return (
        f"otpauth://totp/{label}?secret={secret}"
        f"&issuer={quote(issuer, safe='')}&algorithm={ALGORITHM}&digits={DIGITS}&period={PERIOD}"
    )


def qr_png_base64(uri: str) -> Optional[str]:
    """Render the provisioning URI as a PNG data payload when qrcode is available."""
    try:
        import io

        import qrcode
    except Exception:
        return None
    try:
        image = qrcode.make(uri, box_size=8, border=2)
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return base64.b64encode(buffer.getvalue()).decode("ascii")
    except Exception:
        return None

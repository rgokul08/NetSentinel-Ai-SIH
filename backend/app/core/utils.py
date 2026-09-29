"""Small shared helpers: IDs, timestamps, safe parsing, pagination math."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

_ID_ALPHABET = string.ascii_lowercase + string.digits


def new_id(prefix: str = "", length: int = 20) -> str:
    """Appwrite-compatible unique id (lowercase alphanumeric, <= 36 chars)."""
    raw = "".join(secrets.choice(_ID_ALPHABET) for _ in range(length))
    return f"{prefix}{raw}"[:36] if prefix else raw


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_utc(value: Any) -> Optional[datetime]:
    """Parse datetime / ISO string / epoch seconds into a timezone-aware UTC datetime."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        if re.fullmatch(r"\d+(\.\d+)?", text):
            return datetime.fromtimestamp(float(text), tz=timezone.utc)
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%d/%m/%Y %H:%M", "%Y-%m-%d"):
                try:
                    parsed = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
            else:
                return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def iso(value: Any) -> Optional[str]:
    dt = to_utc(value)
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def as_naive_utc(value: Any) -> Optional[datetime]:
    """SQLAlchemy DateTime columns store naive UTC; this normalizes input."""
    dt = to_utc(value)
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt else None


def parse_range(value: Any) -> Optional[str]:
    """Accept '1h'/'24h'/'7d'/'30d'/seconds and return a normalized window key."""
    if value is None:
        return None
    text = str(value).strip().lower()
    mapping = {"1h": "1h", "24h": "24h", "7d": "7d", "30d": "30d", "all": "all"}
    if text in mapping:
        return mapping[text]
    if text.endswith("h"):
        return f"{int(float(text[:-1]))}h"
    if text.endswith("d"):
        return f"{int(float(text[:-1]))}d"
    if text.endswith("m"):
        return f"{int(float(text[:-1]))}m"
    if text.isdigit():
        return f"{int(text)}s"
    return None


def window_start(window: Optional[str], now: Optional[datetime] = None) -> Optional[datetime]:
    """Return the inclusive start datetime for a range key (None == unbounded)."""
    now = now or utcnow()
    if not window or window == "all":
        return None
    unit = window[-1]
    try:
        amount = float(window[:-1])
    except ValueError:
        return None
    delta = {
        "s": timedelta(seconds=amount),
        "m": timedelta(minutes=amount),
        "h": timedelta(hours=amount),
        "d": timedelta(days=amount),
    }.get(unit)
    return now - delta if delta else None


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        result = float(value)
        return default if result != result else result  # NaN guard
    except (TypeError, ValueError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def sha256_hex(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def canonical_json(data: Any) -> str:
    """Deterministic JSON used for hashing (stable key order, no float noise)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def paginate(total: int, limit: int, offset: int) -> Dict[str, Any]:
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    pages = max(1, -(-total // limit))
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "page": (offset // limit) + 1,
        "pages": pages,
        "has_more": offset + limit < total,
    }


def dedupe(items: Iterable[Any]) -> List[Any]:
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def mask_ip(ip: Optional[str]) -> str:
    """Abstract an IP for privacy-preserving visualizations (keeps /16 prefix)."""
    if not ip:
        return "unknown"
    parts = str(ip).split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.0.0/16"
    return str(ip)[:6] + "::/32"


def compact_number(value: float) -> str:
    for unit, cutoff in (("B", 1e9), ("M", 1e6), ("K", 1e3)):
        if abs(value) >= cutoff:
            return f"{value / cutoff:.2f}{unit}"
    return f"{value:.0f}"

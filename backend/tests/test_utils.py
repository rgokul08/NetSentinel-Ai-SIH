"""Core helpers shared by every service (canonicalization, windows, masking)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.core.utils import (
    canonical_json,
    clamp,
    compact_number,
    dedupe,
    iso,
    mask_ip,
    new_id,
    paginate,
    parse_range,
    safe_float,
    safe_int,
    to_utc,
    window_start,
)


def test_canonical_json_is_order_independent_and_compact():
    first = canonical_json({"b": 2, "a": 1, "nested": {"z": [1, 2], "y": "x"}})
    second = canonical_json({"a": 1, "nested": {"y": "x", "z": [1, 2]}, "b": 2})
    assert first == second
    assert " " not in first.replace('" "', "")  # compact separators
    assert first.startswith("{")


def test_iso_and_to_utc_round_trip():
    moment = datetime(2026, 9, 29, 1, 2, 3, tzinfo=timezone.utc)
    text = iso(moment)
    assert text.endswith("Z")
    assert to_utc(text) == moment
    assert to_utc("2026-09-29 01:02:03") == moment          # naive strings are UTC
    assert to_utc(moment.timestamp()) == moment.replace(microsecond=0)
    assert to_utc("not-a-date") is None
    assert to_utc(None) is None


@pytest.mark.parametrize("window,expected_minutes", [
    ("15m", 15), ("1h", 60), ("24h", 1440), ("7d", 10080), ("30d", 43200),
])
def test_window_start_is_relative_to_now(window, expected_minutes):
    start = window_start(window)
    delta = datetime.now(timezone.utc) - start
    assert abs(delta - timedelta(minutes=expected_minutes)) < timedelta(seconds=5)


def test_window_start_handles_unknown_values():
    assert window_start(None) is None
    assert window_start("nonsense") is None


@pytest.mark.parametrize("raw,expected", [
    ("24h", "24h"), ("7d", "7d"), ("all", "all"), ("1.5h", "1h"), ("45m", "45m"),
    ("3600", "3600s"), ("NONSENSE", None), (None, None), (["2026-09-01", "2026-09-02"], None),
])
def test_parse_range_normalizes_window_keys(raw, expected):
    assert parse_range(raw) == expected


def test_mask_ip_hides_the_host_octets():
    """Privacy-preserving abstraction used by the threat map and reports."""
    assert mask_ip("192.168.4.77") == "192.168.0.0/16"
    assert mask_ip(None) == "unknown"
    assert mask_ip("2001:db8::1").endswith("::/32")
    assert "77" not in mask_ip("192.168.4.77")


def test_paginate_reports_pages_and_flags():
    assert paginate(95, 20, 0) == {"total": 95, "limit": 20, "offset": 0, "page": 1, "pages": 5, "has_more": True}
    assert paginate(95, 20, 80)["has_more"] is False
    assert paginate(0, 20, 0)["pages"] in (0, 1)


def test_numeric_coercion_is_safe():
    assert safe_float("1.5") == 1.5
    assert safe_float(None, 2.0) == 2.0
    assert safe_float("abc", 0.0) == 0.0
    assert safe_int("12") == 12
    assert safe_int(3.9) == 3
    assert safe_int("nope", 7) == 7
    assert clamp(1.7) == 1.0 and clamp(-0.4) == 0.0 and clamp(0.42) == 0.42


def test_compact_number_is_human_readable():
    assert compact_number(950).startswith("950")
    assert "K" in compact_number(12_400) or "k" in compact_number(12_400)
    assert "M" in compact_number(3_400_000) or "m" in compact_number(3_400_000)


def test_new_id_is_unique_and_url_safe():
    ids = {new_id() for _ in range(500)}
    assert len(ids) == 500
    assert all(value.replace("-", "").replace("_", "").isalnum() for value in ids)
    assert new_id("evt-").startswith("evt-")


def test_dedupe_preserves_order():
    assert dedupe(["b", "a", "b", "c", "a"]) == ["b", "a", "c"]
    assert dedupe([]) == []

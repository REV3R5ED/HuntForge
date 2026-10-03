"""UTC helpers for HuntForge.

Every timestamp HuntForge stores or emits is UTC ISO-8601
(``YYYY-MM-DDTHH:MM:SSZ``). Naive datetimes are assumed UTC and
documented as such at each call site.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

log = logging.getLogger("huntforge")


def utc_now() -> datetime:
    """Current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    """Current time as a UTC ISO-8601 string ending in ``Z``."""
    return to_utc_iso(utc_now())


def to_utc_iso(dt: datetime) -> str:
    """Format a datetime as UTC ISO-8601 ending in ``Z``."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class TimestampError(ValueError):
    """Raised when a timestamp cannot be normalized to UTC."""


def normalize_timestamp(value: str) -> tuple[str, str]:
    """Normalize an ingested timestamp to UTC ISO-8601.

    Accepts ISO-8601 with ``Z`` or numeric offsets; naive values are
    assumed UTC. Returns ``(utc_iso, original)``. Raises
    :class:`TimestampError` for unparseable input.
    """
    original = value
    text = value.strip()
    if not text:
        raise TimestampError("empty timestamp")
    # datetime.fromisoformat on Python 3.10 does not accept a trailing "Z".
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        # Fall back to a couple of common log formats before giving up.
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            raise TimestampError(f"unparseable timestamp: {original!r}") from None
    return to_utc_iso(parsed), original

"""Unified chronological timeline across all ingested sources (v0.4).

:func:`build_timeline` merges every event in a case into one view
sorted by (timestamp, row id). Events whose parser could not recover
an original timestamp (``timestamp_original`` empty — the stored
timestamp is only the ingest time) go into the ``untimed`` section:
they are never dropped and never placed on the timeline.

Observation only: no verdicts, no inferred timestamps.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from huntforge.core.logging import TimestampError, normalize_timestamp
from huntforge.store.db import CaseDB


@dataclass
class TimelineOptions:
    from_ts: str | None = None
    to_ts: str | None = None
    source: str | None = None
    limit: int = 500

    def __post_init__(self) -> None:
        if self.limit is not None:
            if not isinstance(self.limit, int) or self.limit < 1:
                raise ValueError("limit must be a positive int")
            self.limit = min(self.limit, 10_000)


def _summarize(event: dict[str, Any]) -> str:
    """One human-readable line describing an event (observation only)."""
    source = event.get("source") or "?"
    event_id = event.get("event_id") or "?"
    proc = event.get("process_name") or "-"
    pid = event.get("process_id")
    proc_bit = f"{proc}({pid})" if pid is not None else proc
    host = event.get("host") or "-"
    user = event.get("user") or "-"

    if event_id == "1" and event.get("parent_name"):
        return (
            f"{proc}({pid}) started by {event['parent_name']}({event.get('parent_id')})"
        )
    if event_id == "4688" and event.get("parent_name"):
        return f"{proc}({pid}) created (parent {event['parent_name']})"
    if event_id == "3" and event.get("dst_ip"):
        return (
            f"{proc_bit} -> {event['dst_ip']}:{event.get('dst_port') or '?'} "
            f"(from {event.get('src_ip') or '?'})"
        )
    if event_id == "11" and event.get("file_path"):
        return f"{proc_bit} created file {event['file_path']}"
    if event_id in ("12", "13", "14") and event.get("registry_key"):
        return f"{proc_bit} registry {event['registry_key']}"
    if event_id == "4104":
        return f"{proc_bit} logged script block ({len(event.get('raw') or '')} chars)"
    if source.startswith("prefetch"):
        raw = event.get("raw") or ""
        runs = re.search(r"run_count=(\d+)", raw)
        detail = f", {runs.group(0)}" if runs else ""
        return f"{proc} executed (prefetch evidence{detail})"
    if source.startswith("registry"):
        return f"persistence: {event.get('registry_key') or event_id}"
    if source == "tasks":
        raw = (event.get("raw") or "").split(",")[0]
        return f"scheduled task: {raw or event_id}"
    if source == "services":
        raw = (event.get("raw") or "").split(",")[0]
        return f"service: {raw or event_id}"
    return f"{source}:{event_id} host={host} user={user} process={proc_bit}"


def _entry(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": event.get("id"),
        "timestamp": event.get("timestamp"),
        "timestamp_original": event.get("timestamp_original"),
        "source": event.get("source"),
        "event_id": event.get("event_id"),
        "host": event.get("host"),
        "user": event.get("user"),
        "process_name": event.get("process_name"),
        "process_id": event.get("process_id"),
        "summary": _summarize(event),
        "flags": event.get("flags") or [],
    }


def _parse_bound(label: str, value: str | None) -> str | None:
    if value is None:
        return None
    try:
        utc, _ = normalize_timestamp(value)
    except TimestampError as exc:
        raise ValueError(f"invalid --{label} timestamp: {exc}") from exc
    return utc


@dataclass
class TimelineResult:
    timed: list[dict[str, Any]] = field(default_factory=list)
    untimed: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "timed": self.timed,
            "untimed": self.untimed,
            "coverage": self.coverage,
            "truncated": self.truncated,
        }


def build_timeline(db: CaseDB, options: TimelineOptions) -> TimelineResult:
    """Build the unified timeline for a case (observation only)."""
    from_utc = _parse_bound("from", options.from_ts)
    to_utc = _parse_bound("to", options.to_ts)
    if from_utc and to_utc and from_utc > to_utc:
        raise ValueError("--from must not be later than --to")

    source_filter = options.source.lower() if options.source else None

    timed: list[dict[str, Any]] = []
    untimed: list[dict[str, Any]] = []
    per_source: dict[str, dict[str, Any]] = {}

    for event in db.all_events():
        source = str(event.get("source") or "")
        if source_filter and not source.lower().startswith(source_filter):
            continue
        entry = _entry(event)
        stat = per_source.setdefault(source, {"events": 0, "first": None, "last": None})
        stat["events"] += 1
        ts = entry["timestamp"]
        if stat["first"] is None or ts < stat["first"]:
            stat["first"] = ts
        if stat["last"] is None or ts > stat["last"]:
            stat["last"] = ts

        if not entry["timestamp_original"]:
            # No original timestamp: the stored timestamp is only the
            # ingest time. Never place it on the timeline.
            untimed.append(entry)
            continue
        if from_utc and ts < from_utc:
            continue
        if to_utc and ts > to_utc:
            continue
        timed.append(entry)

    # db.all_events() is already (timestamp, id) ordered; the filters
    # above preserve that order. Untimed keeps id order too.
    total = len(timed)
    truncated = total > options.limit
    timed = timed[: options.limit]

    coverage = {
        "sources": per_source,
        "timed_count": total,
        "untimed_count": len(untimed),
        "range": (
            {"from": timed[0]["timestamp"], "to": timed[-1]["timestamp"]}
            if timed
            else None
        ),
        "time_filter": {"from": from_utc, "to": to_utc},
        "note": (
            "untimed events carry no original timestamp and are not "
            "affected by --from/--to"
        ),
    }
    return TimelineResult(
        timed=timed, untimed=untimed, coverage=coverage, truncated=truncated
    )

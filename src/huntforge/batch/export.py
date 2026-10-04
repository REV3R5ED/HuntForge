"""JSONL export for SIEM ingestion (v0.9).

``export_events`` / ``export_findings`` stream one JSON object per line
to a binary-or-text writable. Ordering is deterministic (event row id /
finding UID order) so exports are reproducible; each line is a complete
self-describing record (``record_type``, ``tool``, ``version``) that a
SIEM can parse without sidecar metadata.

Nothing is executed, resolved, or fetched — export is a pure read of
what the case already holds.
"""

from __future__ import annotations

import json
from typing import Any, TextIO

from huntforge import __version__
from huntforge.schemas import SCHEMA_EVENT, SCHEMA_FINDING
from huntforge.store.db import CaseDB


def _envelope(record_type: str, schema: str, record: dict[str, Any]) -> str:
    """One JSONL line: self-describing wrapper + the record itself."""
    return json.dumps(
        {
            "record_type": record_type,
            "schema": schema,
            "tool": "huntforge",
            "version": __version__,
            "record": record,
        },
        sort_keys=True,
        default=str,
    )


def export_events(db: CaseDB, dest: TextIO) -> int:
    """Write every normalized event as JSONL; returns the line count."""
    count = 0
    for event in db.all_events():
        dest.write(_envelope("event", SCHEMA_EVENT, event) + "\n")
        count += 1
    return count


def export_findings(db: CaseDB, dest: TextIO) -> int:
    """Write every stored finding as JSONL; returns the line count."""
    count = 0
    for finding in db.list_findings():
        dest.write(_envelope("finding", SCHEMA_FINDING, finding) + "\n")
        count += 1
    return count


def export_what(db: CaseDB, what: str, dest: TextIO) -> int:
    """Dispatch on ``what`` (``events`` | ``findings``)."""
    if what == "events":
        return export_events(db, dest)
    if what == "findings":
        return export_findings(db, dest)
    raise ValueError(f"unknown export target {what!r} (events|findings)")

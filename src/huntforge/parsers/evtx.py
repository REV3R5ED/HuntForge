"""EVTX ingestion adapter (v0.2).

HuntForge does **not** parse the binary EVTX format — doing that
correctly in stdlib-only Python is out of scope. Instead this adapter:

- detects binary EVTX by magic bytes and fails with a clean,
  actionable error (the exact ``wevtutil`` command to export XML);
- parses **exported Windows Event XML** (``wevtutil qe /f:xml``) and
  JSON exports into the normalized event model with full provenance.

The limitation is documented in the README and every error message.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from huntforge.models.events import EventValidationError, NormalizedEvent
from huntforge.parsers.common import (
    EVTX_MAGIC,
    MAX_PARSE_BYTES,
    blank,
    child_text,
    event_data_map,
    excerpt,
    find_child,
    fresh_ingest_time,
    localname,
    make_provenance,
    truncate_fractional_seconds,
)

PARSER_NAME = "evtx-xml"
PARSER_VERSION = "0.2.0"

WEVTUTIL_GUIDANCE = (
    "binary EVTX is not parsed directly: export it to XML first with "
    'wevtutil qe "C:\\path\\to\\file.evtx" /lf:true /f:xml > exported.xml '
    "and ingest the XML"
)


class EvtxBinaryError(ValueError):
    """Raised when a binary .evtx file is offered to the XML adapter."""


def is_evtx_binary(path: Path) -> bool:
    """True when *path* starts with the EVTX magic (``ElfFile\\0``)."""
    with path.open("rb") as fh:
        return fh.read(len(EVTX_MAGIC)) == EVTX_MAGIC


def parse_evtx_xml(
    path: Path,
    *,
    source_sha256: str,
    ingest_time: str | None = None,
) -> tuple[list[NormalizedEvent], list[str]]:
    """Parse exported Windows Event XML into normalized events.

    Returns ``(events, warnings)``. Malformed records are skipped with
    a warning — one bad record never aborts the file.
    """
    ingest_time = ingest_time or fresh_ingest_time()
    if path.stat().st_size > MAX_PARSE_BYTES:
        return [], [f"{path.name}: exceeds {MAX_PARSE_BYTES} byte parse limit"]
    events: list[NormalizedEvent] = []
    warnings: list[str] = []
    try:
        tree = ET.parse(str(path))
    except ET.ParseError as exc:
        return [], [f"{path.name}: malformed XML ({exc}); no events parsed"]
    root = tree.getroot()
    records = (
        [root]
        if localname(root.tag) == "Event"
        else [el for el in root.iter() if localname(el.tag) == "Event"]
    )
    for index, record in enumerate(records):
        try:
            event = _parse_event_record(
                record,
                source_file=str(path),
                record_index=index,
                source_sha256=source_sha256,
                ingest_time=ingest_time,
            )
        except EventValidationError as exc:
            warnings.append(f"{path.name}: record {index} skipped ({exc})")
            continue
        if event is not None:
            events.append(event)
    return events, warnings


def _parse_event_record(
    record: ET.Element,
    *,
    source_file: str,
    record_index: int,
    source_sha256: str,
    ingest_time: str,
) -> NormalizedEvent | None:
    system = find_child(record, "System")
    if system is None:
        raise EventValidationError("record has no System section")
    time_created = find_child(system, "TimeCreated")
    system_time = time_created.get("SystemTime") if time_created is not None else None
    if not system_time:
        # Timestamp is mandatory in the normalized model; without it the
        # record cannot be placed on a timeline.
        raise EventValidationError("record has no SystemTime")
    event_id = child_text(system, "EventID") or "0"
    channel = child_text(system, "Channel")
    computer = child_text(system, "Computer")
    security = find_child(system, "Security")
    user_id = security.get("UserID") if security is not None else None
    data = event_data_map(find_child(record, "EventData"))
    data_keys = ",".join(sorted(data.keys())[:8])
    return NormalizedEvent(
        timestamp=truncate_fractional_seconds(system_time),
        timestamp_original=system_time,
        source=f"evtx:{channel}" if channel else "evtx",
        event_id=event_id,
        provenance=make_provenance(
            source_file=source_file,
            record_index=record_index,
            parser_name=PARSER_NAME,
            parser_version=PARSER_VERSION,
            ingest_time=ingest_time,
            source_sha256=source_sha256,
        ),
        host=blank(computer),
        user=blank(user_id),
        raw=excerpt(
            [
                f"channel={channel or '?'}",
                f"event_id={event_id}",
                f"data_keys={data_keys or '-'}",
            ]
        ),
    )


def parse_evtx_json(
    path: Path,
    records: list[dict[str, Any]],
    *,
    source_sha256: str,
    ingest_time: str | None = None,
) -> tuple[list[NormalizedEvent], list[str]]:
    """Parse a JSON export of Windows events (list of record dicts).

    Accepted shape per record: ``{"EventID", "Channel", "Computer",
    "TimeCreated", "UserID", "EventData": {...}}``. Unknown extra keys
    are ignored.
    """
    ingest_time = ingest_time or fresh_ingest_time()
    events: list[NormalizedEvent] = []
    warnings: list[str] = []
    for index, item in enumerate(records):
        if not isinstance(item, dict):
            warnings.append(f"{path.name}: record {index} is not an object; skipped")
            continue
        system_time = item.get("TimeCreated") or item.get("SystemTime")
        if not system_time:
            warnings.append(f"{path.name}: record {index} has no timestamp; skipped")
            continue
        channel = item.get("Channel")
        try:
            events.append(
                NormalizedEvent(
                    timestamp=truncate_fractional_seconds(str(system_time)),
                    timestamp_original=str(system_time),
                    source=f"evtx:{channel}" if channel else "evtx",
                    event_id=str(item.get("EventID") or "0"),
                    provenance=make_provenance(
                        source_file=str(path),
                        record_index=index,
                        parser_name="evtx-json",
                        parser_version=PARSER_VERSION,
                        ingest_time=ingest_time,
                        source_sha256=source_sha256,
                    ),
                    host=blank(item.get("Computer")),
                    user=blank(item.get("UserID")),
                    raw=excerpt(
                        [
                            f"channel={channel or '?'}",
                            f"event_id={item.get('EventID')}",
                        ]
                    ),
                )
            )
        except EventValidationError as exc:
            warnings.append(f"{path.name}: record {index} skipped ({exc})")
    return events, warnings

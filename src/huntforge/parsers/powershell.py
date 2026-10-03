"""PowerShell operational log parser (v0.2).

Parses the ``Microsoft-Windows-PowerShell/Operational`` channel XML/JSON
exports. Covered EventIDs:

- 4104 script block logging — captures ``ScriptBlockText`` (Windows may
  split large blocks across several 4104 records; each record notes its
  ``ScriptBlockId`` so an analyst can reassemble them);
- 4103 command invocation details (``ContextInfo``);
- 4105/4106 script block start/stop;
- 4100 pipeline execution details.

PowerShell *process creation* (4688 with ``powershell.exe``) is parsed
by ``security.py`` — including the ``encoded-command`` parser
observation. Any other PowerShell-channel EventID is parsed generically.
Source label is ``powershell``.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from huntforge.models.events import EventValidationError, NormalizedEvent
from huntforge.parsers.common import (
    basename,
    blank,
    event_data_map,
    excerpt,
    find_child,
    fresh_ingest_time,
    json_records,
    localname,
    make_provenance,
    system_fields,
    truncate_fractional_seconds,
)

PARSER_NAME_XML = "powershell-xml"
PARSER_NAME_JSON = "powershell-json"
PARSER_VERSION = "0.2.0"

SOURCE = "powershell"

#: Script blocks arrive decoded already; nothing to flag here.
_SCRIPT_BLOCK_IDS = ("4104",)


def _build(
    *,
    data: dict[str, str],
    event_id: str,
    system_time: str,
    computer: str | None,
    user_id: str | None,
    source_file: str,
    record_index: int,
    parser_name: str,
    source_sha256: str,
    ingest_time: str,
) -> NormalizedEvent:
    if not system_time.strip():
        raise EventValidationError("record has no usable timestamp")

    kwargs: dict[str, Any] = {
        "timestamp": truncate_fractional_seconds(system_time),
        "timestamp_original": system_time,
        "source": SOURCE,
        "event_id": event_id,
        "host": blank(computer),
        "user": blank(user_id),
        "flags": [],
    }
    raw_bits = [f"powershell event {event_id}"]

    if event_id in _SCRIPT_BLOCK_IDS:
        script = data.get("ScriptBlockText", "")
        # 4104 payloads are already-decoded script text; keep an excerpt in
        # raw (full text stays in the evidence file) and note reassembly.
        excerpt_text = script[:500]
        kwargs["command_line"] = excerpt_text or None
        block_id = blank(data.get("ScriptBlockId"))
        if block_id:
            raw_bits.append(f"script_block_id={block_id}")
        raw_bits.append(
            "note=large script blocks are split across multiple 4104 records "
            "sharing one ScriptBlockId"
        )
        path = blank(data.get("Path"))
        if path:
            kwargs["file_path"] = path
            raw_bits.append(f"path={path}")
    elif event_id == "4103":
        context = blank(data.get("ContextInfo"))
        if context:
            raw_bits.append(f"context={context[:200]}")
            kwargs["command_line"] = context[:500]
    elif event_id in ("4105", "4106"):
        block_id = blank(data.get("ScriptBlockId"))
        if block_id:
            raw_bits.append(f"script_block_id={block_id}")
    elif event_id == "4100":
        host_name = blank(data.get("HostName"))
        if host_name:
            kwargs["process_name"] = basename(host_name)
            raw_bits.append(f"host_application={host_name}")

    kwargs["raw"] = excerpt(raw_bits)
    kwargs["provenance"] = make_provenance(
        source_file=source_file,
        record_index=record_index,
        parser_name=parser_name,
        parser_version=PARSER_VERSION,
        ingest_time=ingest_time,
        source_sha256=source_sha256,
    )
    return NormalizedEvent(**kwargs)


def _user_id(record: ET.Element) -> str | None:
    system = find_child(record, "System")
    if system is None:
        return None
    security = find_child(system, "Security")
    return security.get("UserID") if security is not None else None


def parse_powershell_xml(
    path: Path,
    *,
    source_sha256: str,
    ingest_time: str | None = None,
) -> tuple[list[NormalizedEvent], list[str]]:
    ingest_time = ingest_time or fresh_ingest_time()
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
            fields = system_fields(record)
            data = event_data_map(find_child(record, "EventData"))
            events.append(
                _build(
                    data=data,
                    event_id=fields["event_id"],
                    system_time=fields["system_time"] or "",
                    computer=fields["computer"],
                    user_id=_user_id(record),
                    source_file=str(path),
                    record_index=index,
                    parser_name=PARSER_NAME_XML,
                    source_sha256=source_sha256,
                    ingest_time=ingest_time,
                )
            )
        except EventValidationError as exc:
            warnings.append(f"{path.name}: record {index} skipped ({exc})")
    return events, warnings


def parse_powershell_json(
    path: Path,
    *,
    source_sha256: str,
    ingest_time: str | None = None,
) -> tuple[list[NormalizedEvent], list[str]]:
    ingest_time = ingest_time or fresh_ingest_time()
    records, warnings = json_records(path)
    events: list[NormalizedEvent] = []
    for index, item in enumerate(records):
        data = item.get("EventData")
        data_map = (
            {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
        )
        try:
            events.append(
                _build(
                    data=data_map,
                    event_id=str(item.get("EventID") or "0"),
                    system_time=str(item.get("TimeCreated") or ""),
                    computer=item.get("Computer"),
                    user_id=item.get("UserID"),
                    source_file=str(path),
                    record_index=index,
                    parser_name=PARSER_NAME_JSON,
                    source_sha256=source_sha256,
                    ingest_time=ingest_time,
                )
            )
        except EventValidationError as exc:
            warnings.append(f"{path.name}: record {index} skipped ({exc})")
    return events, warnings

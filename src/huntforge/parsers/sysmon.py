"""Sysmon event parser (v0.2).

Parses Sysmon XML exports (``wevtutil qe Microsoft-Windows-Sysmon/Operational
/f:xml``) and JSON exports into the normalized event model.

Covered EventIDs: 1 (process creation), 3 (network connection),
7 (image load), 11 (file creation), 12/13/14 (registry). Any other
Sysmon EventID is parsed generically (timestamps, host, user, image)
so future Sysmon versions degrade gracefully instead of dropping data.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from huntforge.models.events import EventValidationError, NormalizedEvent
from huntforge.parsers.common import (
    MAX_PARSE_BYTES,
    basename,
    blank,
    clean_ip,
    event_data_map,
    excerpt,
    find_child,
    flag_encoded_command,
    fresh_ingest_time,
    json_records,
    localname,
    make_provenance,
    parse_hashes,
    parse_pid,
    parse_port,
    system_fields,
    truncate_fractional_seconds,
)

PARSER_NAME_XML = "sysmon-xml"
PARSER_NAME_JSON = "sysmon-json"
PARSER_VERSION = "0.2.0"

SOURCE = "sysmon"

# Sysmon EventData field names per EventID (authoritative subset).
_PROCESS_CREATE = "1"
_NETWORK_CONNECT = "3"
_IMAGE_LOAD = "7"
_FILE_CREATE = "11"
_REGISTRY = ("12", "13", "14")


def _build(
    *,
    data: dict[str, str],
    event_id: str,
    system_time: str,
    computer: str | None,
    source_file: str,
    record_index: int,
    parser_name: str,
    source_sha256: str,
    ingest_time: str,
) -> NormalizedEvent:
    """Map one Sysmon record's EventData dict to a NormalizedEvent."""
    if not system_time:
        # Fall back to Sysmon's own UtcTime field when TimeCreated is absent.
        system_time = data.get("UtcTime", "")
    if not system_time.strip():
        raise EventValidationError("record has no usable timestamp")

    kwargs: dict[str, Any] = {
        "timestamp": truncate_fractional_seconds(system_time),
        "timestamp_original": system_time,
        "source": SOURCE,
        "event_id": event_id,
        "host": blank(computer),
        "user": blank(data.get("User")),
        "process_name": basename(data.get("Image")),
        "process_id": parse_pid(data.get("ProcessId")),
        "parent_name": basename(data.get("ParentImage")),
        "parent_id": parse_pid(data.get("ParentProcessId")),
        "command_line": blank(data.get("CommandLine")),
        "hashes": parse_hashes(data.get("Hashes")),
    }
    raw_bits = [f"sysmon event {event_id}"]

    if event_id == _NETWORK_CONNECT:
        kwargs["src_ip"] = clean_ip(data.get("SourceIp"))
        kwargs["src_port"] = parse_port(data.get("SourcePort"))
        kwargs["dst_ip"] = clean_ip(data.get("DestinationIp"))
        kwargs["dst_port"] = parse_port(data.get("DestinationPort"))
        raw_bits.append(f"protocol={blank(data.get('Protocol')) or '?'}")
        src = kwargs["src_ip"] or "?"
        dst = kwargs["dst_ip"] or "?"
        raw_bits.append(
            f"{src}:{kwargs['src_port'] or '?'} -> {dst}:{kwargs['dst_port'] or '?'}"
        )
    elif event_id == _IMAGE_LOAD:
        kwargs["file_path"] = blank(data.get("ImageLoaded"))
        raw_bits.append(f"signed={blank(data.get('Signed')) or '?'}")
    elif event_id == _FILE_CREATE:
        kwargs["file_path"] = blank(data.get("TargetFilename"))
    elif event_id in _REGISTRY:
        kwargs["registry_key"] = blank(data.get("TargetObject"))
        raw_bits.append(f"type={blank(data.get('EventType')) or '?'}")
        details = blank(data.get("Details"))
        if details:
            raw_bits.append(f"details={details[:120]}")

    command_line = kwargs.get("command_line")
    flags = flag_encoded_command(
        command_line if isinstance(command_line, str) else None
    )

    kwargs["flags"] = flags
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


def parse_sysmon_xml(
    path: Path,
    *,
    source_sha256: str,
    ingest_time: str | None = None,
) -> tuple[list[NormalizedEvent], list[str]]:
    """Stream-parse a Sysmon XML export (memory-safe for large files)."""
    ingest_time = ingest_time or fresh_ingest_time()
    if path.stat().st_size > MAX_PARSE_BYTES:
        return [], [f"{path.name}: exceeds {MAX_PARSE_BYTES} byte parse limit"]
    events: list[NormalizedEvent] = []
    warnings: list[str] = []
    try:
        context = ET.iterparse(str(path), events=("end",))
    except ET.ParseError as exc:
        return [], [f"{path.name}: malformed XML ({exc}); no events parsed"]
    index = 0
    try:
        for _, element in context:
            if localname(element.tag) != "Event":
                continue
            try:
                fields = system_fields(element)
                data = event_data_map(find_child(element, "EventData"))
                events.append(
                    _build(
                        data=data,
                        event_id=fields["event_id"],
                        system_time=fields["system_time"] or "",
                        computer=fields["computer"],
                        source_file=str(path),
                        record_index=index,
                        parser_name=PARSER_NAME_XML,
                        source_sha256=source_sha256,
                        ingest_time=ingest_time,
                    )
                )
            except EventValidationError as exc:
                warnings.append(f"{path.name}: record {index} skipped ({exc})")
            index += 1
            element.clear()
    except ET.ParseError as exc:
        warnings.append(f"{path.name}: XML truncated ({exc}); parsed {len(events)}")
    return events, warnings


def parse_sysmon_json(
    path: Path,
    *,
    source_sha256: str,
    ingest_time: str | None = None,
) -> tuple[list[NormalizedEvent], list[str]]:
    """Parse a Sysmon JSON export.

    Accepted shape per record: ``{"EventID", "Computer", "TimeCreated",
    "EventData": {...}}`` where EventData maps Sysmon field names to values.
    """
    ingest_time = ingest_time or fresh_ingest_time()
    if path.stat().st_size > MAX_PARSE_BYTES:
        return [], [f"{path.name}: exceeds {MAX_PARSE_BYTES} byte parse limit"]
    records, warnings = json_records(path)
    events: list[NormalizedEvent] = []
    for index, item in enumerate(records):
        data = item.get("EventData")
        data_map = (
            {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
        )
        system_time = str(item.get("TimeCreated") or "")
        try:
            events.append(
                _build(
                    data=data_map,
                    event_id=str(item.get("EventID") or "0"),
                    system_time=system_time,
                    computer=item.get("Computer"),
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

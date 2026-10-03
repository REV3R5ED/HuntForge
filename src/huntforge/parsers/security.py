"""Windows Security log parser (v0.2).

Parses Security-channel XML/JSON exports. Covered EventIDs:

- 4624 successful logon, 4625 failed logon, 4634/4647 logoff —
  user, logon type, source IP / workstation;
- 4688 process creation — image, PID (hex like ``0x1a2b``), parent,
  command line, subject user.

Any other Security EventID is parsed generically so the log degrades
gracefully. Source label is ``evtx:Security``.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from huntforge.models.events import EventValidationError, NormalizedEvent
from huntforge.parsers.common import (
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
    parse_pid,
    system_fields,
    truncate_fractional_seconds,
)

PARSER_NAME_XML = "security-xml"
PARSER_NAME_JSON = "security-json"
PARSER_VERSION = "0.2.0"

SOURCE = "evtx:Security"


def _qualified_user(domain: str | None, name: str | None) -> str | None:
    name = blank(name)
    if not name:
        return None
    domain = blank(domain)
    if domain and domain != "-":
        return f"{domain}\\{name}"
    return name


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
    if not system_time.strip():
        raise EventValidationError("record has no usable timestamp")

    kwargs: dict[str, Any] = {
        "timestamp": truncate_fractional_seconds(system_time),
        "timestamp_original": system_time,
        "source": SOURCE,
        "event_id": event_id,
        "host": blank(computer),
    }
    raw_bits = [f"security event {event_id}"]

    if event_id in ("4624", "4625"):
        kwargs["user"] = _qualified_user(
            data.get("TargetDomainName"), data.get("TargetUserName")
        )
        kwargs["src_ip"] = clean_ip(data.get("IpAddress"))
        workstation = blank(data.get("WorkstationName"))
        if workstation:
            raw_bits.append(f"workstation={workstation}")
        logon_type = blank(data.get("LogonType"))
        if logon_type:
            raw_bits.append(f"logon_type={logon_type}")
        if event_id == "4625":
            for key in ("Status", "SubStatus", "FailureReason"):
                value = blank(data.get(key))
                if value:
                    raw_bits.append(f"{key.lower()}={value}")
    elif event_id in ("4634", "4647"):
        kwargs["user"] = _qualified_user(
            data.get("TargetDomainName"), data.get("TargetUserName")
        )
        logon_type = blank(data.get("LogonType"))
        if logon_type:
            raw_bits.append(f"logon_type={logon_type}")
    elif event_id == "4688":
        kwargs["process_name"] = basename(data.get("NewProcessName"))
        kwargs["process_id"] = parse_pid(data.get("NewProcessId")) or parse_pid(
            data.get("ProcessId")
        )
        kwargs["parent_name"] = basename(data.get("ParentProcessName"))
        # 4688 has no ParentProcessId field: the creating process is the parent.
        kwargs["parent_id"] = parse_pid(data.get("ProcessId"))
        kwargs["command_line"] = blank(data.get("CommandLine"))
        kwargs["user"] = _qualified_user(
            data.get("SubjectDomainName"), data.get("SubjectUserName")
        )
        token_type = blank(data.get("TokenElevationType"))
        if token_type:
            raw_bits.append(f"token_elevation={token_type}")
        command_line = kwargs["command_line"]
        kwargs["flags"] = flag_encoded_command(
            command_line if isinstance(command_line, str) else None
        )
    else:
        # Generic Security record: keep what the schema guarantees.
        kwargs["user"] = _qualified_user(
            data.get("TargetDomainName"), data.get("TargetUserName")
        ) or _qualified_user(data.get("SubjectDomainName"), data.get("SubjectUserName"))

    kwargs.setdefault("flags", [])
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


def parse_security_xml(
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


def parse_security_json(
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

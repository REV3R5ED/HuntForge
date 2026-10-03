"""Shared helpers for HuntForge artifact parsers (v0.2).

All parsers are stdlib-only and fully offline: XML via
:mod:`xml.etree.ElementTree`, JSON via :mod:`json`. No network calls,
no subprocesses, no binary EVTX parsing (see ``evtx.py``).
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from huntforge.core.logging import utc_now_iso
from huntforge.models.events import EventValidationError, Provenance

#: Magic bytes of a binary EVTX file ("ElfFile\\0").
EVTX_MAGIC = b"ElfFile\x00"

#: Parsers never read more than this when sniffing a file's kind.
DETECT_HEAD_BYTES = 65536

#: Refuse to parse single telemetry files larger than this (DoS guard).
MAX_PARSE_BYTES = 100 * 1024 * 1024

#: Cap on warnings per parsed file (malformed input must not flood output).
MAX_WARNINGS_PER_FILE = 25

#: "-EncodedCommand", "-enc", "/enc" (word-boundary aware, case-insensitive).
_ENCODED_RE = re.compile(
    r"(?:^|\s)(?:-|/)(?:encodedcommand|enc|e)(?:\s|$|=|:)", re.IGNORECASE
)


def localname(tag: str) -> str:
    """Strip an XML namespace: ``{ns}Event`` -> ``Event``."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def find_child(element: ET.Element, name: str) -> ET.Element | None:
    """First direct child whose local tag name is *name* (namespace-agnostic)."""
    for child in element:
        if localname(child.tag) == name:
            return child
    return None


def find_children(element: ET.Element, name: str) -> list[ET.Element]:
    """All direct children whose local tag name is *name*."""
    return [c for c in element if localname(c.tag) == name]


def child_text(element: ET.Element | None, name: str) -> str | None:
    """Text of the first child named *name*, stripped; ``None`` if absent/blank."""
    if element is None:
        return None
    child = find_child(element, name)
    if child is None or child.text is None:
        return None
    text = child.text.strip()
    return text or None


def event_data_map(event_data: ET.Element | None) -> dict[str, str]:
    """Map ``<Data Name="X">v</Data>`` to ``{X: v}`` (unnamed -> ``data_N``)."""
    result: dict[str, str] = {}
    if event_data is None:
        return result
    for index, data in enumerate(find_children(event_data, "Data")):
        key = data.get("Name") or f"data_{index}"
        result[key] = (data.text or "").strip()
    return result


def truncate_fractional_seconds(value: str) -> str:
    """Cut fractional-second digits beyond 6 (Windows emits 7)."""
    match = re.search(r"\.(\d+)", value)
    if match and len(match.group(1)) > 6:
        value = value[: match.start()] + "." + match.group(1)[:6] + value[match.end() :]
    return value


def basename(path: str | None) -> str | None:
    """File name from a Windows or POSIX path (``C:\\...\\x.exe`` -> ``x.exe``)."""
    if not path:
        return None
    name = re.split(r"[\\/]", path.strip())[-1]
    return name or None


def parse_hashes(text: str | None) -> dict[str, str]:
    """Parse Sysmon-style ``"SHA256=ab..,MD5=cd..,IMPHASH=ef.."`` into a dict."""
    hashes: dict[str, str] = {}
    if not text:
        return hashes
    for part in text.split(","):
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        key, value = key.strip().lower(), value.strip()
        if key and value and value != "-":
            hashes[key] = value
    return hashes


def parse_pid(text: str | None) -> int | None:
    """Parse a PID that may be decimal (Sysmon) or hex like ``0x1a2b`` (4688)."""
    if text is None:
        return None
    text = text.strip()
    if not text or text == "-":
        return None
    try:
        number = int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None
    return number if number > 0 else None  # 0 is the idle pseudo-process


def parse_port(text: str | None) -> int | None:
    """Parse a port; Sysmon uses ``-`` for "not applicable"."""
    if text is None:
        return None
    text = text.strip()
    if not text or text == "-":
        return None
    try:
        port = int(text)
    except ValueError:
        return None
    return port if 0 <= port <= 65535 else None


def clean_ip(text: str | None) -> str | None:
    """Return the IP unless blank/placeholder (``-``)."""
    if text is None:
        return None
    text = text.strip()
    return text if text and text != "-" else None


def flag_encoded_command(command_line: str | None) -> list[str]:
    """Parser observation (NOT a verdict): command line uses an encoded-command switch.

    v0.5 detections may act on this; v0.2 only records the observation.
    """
    if command_line and _ENCODED_RE.search(command_line):
        return ["encoded-command"]
    return []


def blank(value: str | None) -> str | None:
    """Normalize blank/``-`` placeholders to ``None``."""
    if value is None:
        return None
    value = value.strip()
    return value if value and value != "-" else None


def make_provenance(
    *,
    source_file: str,
    record_index: int,
    parser_name: str,
    parser_version: str,
    ingest_time: str,
    source_sha256: str,
) -> Provenance:
    return Provenance(
        source_file=source_file,
        record_index=record_index,
        parser_name=parser_name,
        parser_version=parser_version,
        ingest_time=ingest_time,
        source_sha256=source_sha256,
    )


def fresh_ingest_time() -> str:
    return utc_now_iso()


def excerpt(parts: list[str], limit: int = 300) -> str:
    """Join non-blank parts into a short raw excerpt."""
    text = " | ".join(p for p in parts if p)
    return text[:limit] if len(text) > limit else text


def system_fields(record: ET.Element) -> dict[str, Any]:
    """Extract ``System`` section fields from a Windows Event XML record.

    Returns ``{"system_time", "event_id", "computer"}``; raises
    :class:`EventValidationError` when the System section is missing.
    """
    system = find_child(record, "System")
    if system is None:
        raise EventValidationError("record has no System section")
    time_created = find_child(system, "TimeCreated")
    system_time = time_created.get("SystemTime") if time_created is not None else None
    return {
        "system_time": system_time,
        "event_id": child_text(system, "EventID") or "0",
        "computer": child_text(system, "Computer"),
    }


def json_records(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Load a JSON telemetry export: array, ``{"Events": [...]}``, or JSONL."""
    text = path.read_text(encoding="utf-8")
    try:
        payload: Any = json.loads(text)
    except json.JSONDecodeError:
        records: list[dict[str, Any]] = []
        errors: list[str] = []
        for index, line in enumerate(text.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"{path.name}: line {index + 1} invalid JSON ({exc.msg})")
                continue
            if isinstance(item, dict):
                records.append(item)
            else:
                errors.append(f"{path.name}: line {index + 1} is not an object")
        return records, errors
    if isinstance(payload, dict) and isinstance(payload.get("Events"), list):
        payload = payload["Events"]
    if not isinstance(payload, list):
        return [], [f"{path.name}: expected a JSON array of event objects"]
    records = []
    errors = []
    for index, item in enumerate(payload):
        if isinstance(item, dict):
            records.append(item)
        else:
            errors.append(f"{path.name}: record {index} is not an object")
    return records, errors

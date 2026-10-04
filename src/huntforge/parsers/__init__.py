"""HuntForge artifact parsers (v0.3).

Each parser turns one telemetry source into :class:`NormalizedEvent`
records with full provenance. Supported sources:

- ``sysmon`` — Sysmon XML/JSON exports (process, network, image-load,
  file, registry events);
- ``security`` — Windows Security log XML/JSON exports
  (logon/logoff, 4688 process creation);
- ``powershell`` — PowerShell operational log XML/JSON exports
  (4103/4104 script block logging);
- ``evtx-xml`` — any other exported Windows Event XML/JSON;
- ``prefetch`` — Windows Prefetch (.pf) binaries, versions 23/26/30;
- ``registry`` — offline registry hives: Run/RunOnce persistence scan
  plus services;
- ``tasks`` — Task Scheduler XML exports (``schtasks /query /xml``);
- ``services`` — services JSON exports, or the Services key of an
  offline SYSTEM hive.

Binary ``.evtx`` files are detected by magic bytes and rejected with a
clean error: export them to XML with ``wevtutil`` first (see
:mod:`huntforge.parsers.evtx`). Compressed (MAM) prefetch is likewise
rejected with guidance. Everything here is stdlib-only and fully
offline — no network calls, no subprocesses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from huntforge import __version__
from huntforge.core import plugins as plugins_mod
from huntforge.models.events import NormalizedEvent
from huntforge.parsers import evtx as evtx_mod
from huntforge.parsers import persistence as persistence_mod
from huntforge.parsers import powershell as powershell_mod
from huntforge.parsers import prefetch as prefetch_mod
from huntforge.parsers import registry as registry_mod
from huntforge.parsers import security as security_mod
from huntforge.parsers import sysmon as sysmon_mod
from huntforge.parsers.common import DETECT_HEAD_BYTES, EVTX_MAGIC, check_parse_size

PARSER_VERSION = "0.3.0"

#: Source kinds recognized by :func:`detect_source` / accepted by ``--source``.
SOURCE_KINDS = (
    "sysmon",
    "security",
    "powershell",
    "evtx-xml",
    "prefetch",
    "registry",
    "tasks",
    "services",
)

_CHANNEL_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("sysmon", re.compile(r"Microsoft-Windows-Sysmon", re.IGNORECASE)),
    ("powershell", re.compile(r"Microsoft-Windows-PowerShell", re.IGNORECASE)),
    ("security", re.compile(r"<Channel>\s*Security\s*</Channel>", re.IGNORECASE)),
)


@dataclass
class ParserResult:
    """Outcome of parsing one evidence file."""

    source_kind: str
    events: list[NormalizedEvent] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    records_seen: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_kind": self.source_kind,
            "events": len(self.events),
            "warnings": self.warnings,
            "records_seen": self.records_seen,
        }


def detect_source(path: Path) -> str | None:
    """Sniff *path* and return a source kind, ``"evtx-binary"``, or ``None``.

    Detection is content-based (magic bytes, XML root/markers, JSON
    keys) — never by file extension. Returns ``None`` for unrecognized
    content; the file is still registered as evidence, just not parsed.
    """
    with path.open("rb") as fh:
        head_bytes = fh.read(DETECT_HEAD_BYTES)
    if head_bytes.startswith(EVTX_MAGIC):
        return "evtx-binary"
    if head_bytes.startswith(registry_mod.REGF_MAGIC):
        return "registry"
    if head_bytes[4:8] == prefetch_mod.PREFETCH_MAGIC:
        return "prefetch"
    if head_bytes.startswith(prefetch_mod.MAM_MAGIC):
        return "prefetch"  # parser rejects compressed MAM with guidance
    try:
        head = head_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None
    stripped = head.lstrip("\ufeff \t\r\n")
    if stripped.startswith("<"):
        return _detect_xml_kind(stripped)
    if stripped.startswith(("[", "{")):
        return _detect_json_kind(stripped)
    return None


def _detect_xml_kind(head: str) -> str | None:
    # Task Scheduler exports: root element is <Task> (Windows Event XML
    # also contains <Task> inside <System>, so require the root tag).
    # Skip an XML declaration and leading comments/PIs before the root tag.
    root = head
    while True:
        stripped = re.sub(r"\A<\?.*?\?>\s*", "", root, flags=re.DOTALL)
        stripped = re.sub(r"\A<!--.*?-->\s*", "", stripped, flags=re.DOTALL)
        if stripped == root:
            break
        root = stripped
    if re.match(r"<Task[\s>]", root):
        return "tasks"
    if not re.search(r"<Events[\s>]|<Event[\s>]", head):
        return None
    for kind, pattern in _CHANNEL_MARKERS:
        if pattern.search(head):
            return kind
    return "evtx-xml"


def _detect_json_kind(head: str) -> str | None:
    lowered = head.lower()
    if re.search(r'"image_?path"\s*:', lowered):
        return "services"
    if "EventID" not in head:
        return None
    # Provider/channel markers first: file paths inside records (e.g.
    # "...\\powershell.exe" in a Security log) must not misdirect.
    if (
        '"channel":"security"' in lowered.replace(" ", "")
        or "microsoft-windows-security-auditing" in lowered
    ):
        return "security"
    if "microsoft-windows-sysmon" in lowered:
        return "sysmon"
    if "microsoft-windows-powershell" in lowered:
        return "powershell"
    return "evtx-xml"


def parse_file(
    path: Path,
    kind: str,
    *,
    source_sha256: str,
    ingest_time: str | None = None,
) -> ParserResult:
    """Parse *path* as *kind*; raises :class:`EvtxBinaryError` for binary EVTX."""
    if kind == "evtx-binary":
        raise evtx_mod.EvtxBinaryError(f"{path.name}: {evtx_mod.WEVTUTIL_GUIDANCE}")
    if kind not in SOURCE_KINDS:
        raise ValueError(
            f"unknown source kind {kind!r}; expected one of {SOURCE_KINDS}"
        )
    oversize = check_parse_size(path)
    if oversize:
        # Uniform DoS guard for every parser: registered as evidence with
        # a warning, never parsed (ingest turns this into a warning).
        return ParserResult(
            source_kind=kind, events=[], warnings=[oversize], records_seen=0
        )
    suffix = path.suffix.lower()
    is_json = suffix == ".json" or _looks_like_json(path)
    kwargs: dict[str, Any] = {
        "source_sha256": source_sha256,
        "ingest_time": ingest_time,
    }
    if kind == "sysmon":
        events, warnings = (
            sysmon_mod.parse_sysmon_json(path, **kwargs)
            if is_json
            else sysmon_mod.parse_sysmon_xml(path, **kwargs)
        )
    elif kind == "security":
        events, warnings = (
            security_mod.parse_security_json(path, **kwargs)
            if is_json
            else security_mod.parse_security_xml(path, **kwargs)
        )
    elif kind == "powershell":
        events, warnings = (
            powershell_mod.parse_powershell_json(path, **kwargs)
            if is_json
            else powershell_mod.parse_powershell_xml(path, **kwargs)
        )
    elif kind == "prefetch":
        events, warnings = prefetch_mod.parse_prefetch_file(path, **kwargs)
    elif kind == "registry":
        events, warnings = persistence_mod.scan_registry_file(path, **kwargs)
    elif kind == "tasks":
        events, warnings = persistence_mod.parse_tasks_xml(path, **kwargs)
    elif kind == "services":
        events, warnings = persistence_mod.parse_services_file(path, **kwargs)
    else:  # evtx-xml
        if is_json:
            from huntforge.parsers.common import json_records

            records, json_warnings = json_records(path)
            events, warnings = evtx_mod.parse_evtx_json(
                path, records, source_sha256=source_sha256, ingest_time=ingest_time
            )
            warnings = json_warnings + warnings
        else:
            events, warnings = evtx_mod.parse_evtx_xml(path, **kwargs)
    return ParserResult(
        source_kind=kind, events=events, warnings=warnings, records_seen=len(events)
    )


def _looks_like_json(path: Path) -> bool:
    with path.open("rb") as fh:
        head = fh.read(64).lstrip(b"\xef\xbb\xbf \t\r\n")
    return head.startswith((b"[", b"{"))


def ensure_registered() -> None:
    """Register the parsers module with the plugin registry (idempotent)."""
    try:
        plugins_mod.register(
            plugins_mod.ModuleInfo(
                name="parsers",
                description=(
                    "Windows telemetry parsers: Sysmon, Security log, "
                    "PowerShell, exported Event XML/JSON, Prefetch, "
                    "offline registry hives, scheduled tasks, services"
                ),
                version=PARSER_VERSION,
                commands=["ingest"],
            )
        )
    except ValueError:
        pass  # already registered


ensure_registered()

__all__ = [
    "PARSER_VERSION",
    "SOURCE_KINDS",
    "ParserResult",
    "detect_source",
    "ensure_registered",
    "parse_file",
    "__version__",
]

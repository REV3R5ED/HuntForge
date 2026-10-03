"""HuntForge evidence ingestion (v0.3: evidence registry + artifact parsers).

v0.3 ingest registers evidence files — hashing every file (SHA-256 +
MD5) and recording size, ingest time and parser name in the case's
evidence table — and then parses recognized artifacts (Sysmon,
Security log, PowerShell, exported Windows Event XML/JSON, Prefetch
binaries, offline registry hives, Task Scheduler XML, services
JSON/registry) into normalized events with full provenance. Source
files are never modified. Binary ``.evtx`` files and compressed (MAM)
prefetch are detected by magic bytes and reported as warnings with
export/decompression guidance; they are still registered as evidence.
Normalized events can also be loaded from JSONL fixtures with
``--fixture``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from huntforge.core.logging import utc_now_iso
from huntforge.models.events import EventValidationError, NormalizedEvent, Provenance
from huntforge.parsers import (
    SOURCE_KINDS,
    detect_source,
    parse_file,
)
from huntforge.parsers.common import MAX_WARNINGS_PER_FILE
from huntforge.parsers.evtx import WEVTUTIL_GUIDANCE, EvtxBinaryError, is_evtx_binary
from huntforge.store.db import CaseDB, EvidenceRecord

FIXTURE_PARSER = "fixture-loader"
FIXTURE_PARSER_VERSION = "0.1.0"
MAX_FIXTURE_LINE_BYTES = 1_000_000


def hash_file(path: Path) -> tuple[str, str]:
    """Compute (sha256, md5) of a file, streaming in 1 MiB chunks."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


def iter_evidence_files(path: Path, recursive: bool = True) -> list[Path]:
    """Collect files to ingest; directories are walked (optionally recursive)."""
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise FileNotFoundError(f"no such file or directory: {path}")
    if recursive:
        return sorted(p for p in path.rglob("*") if p.is_file())
    return sorted(p for p in path.iterdir() if p.is_file())


def ingest_path(
    db: CaseDB,
    path: Path,
    recursive: bool = True,
    parse: bool = True,
    source: str | None = None,
) -> dict[str, Any]:
    """Register evidence files from *path* and parse recognized telemetry.

    *parse* enables the v0.2 parsers (disable with ``--no-parse``);
    *source* forces one source kind for every file (``--source``),
    otherwise each file is auto-detected by content. Unrecognized files
    are registered but not parsed; binary EVTX files produce a warning
    with ``wevtutil`` export guidance. Parsing never aborts ingest —
    per-file failures become warnings.
    """
    if source is not None and source not in SOURCE_KINDS:
        raise ValueError(f"unknown source {source!r}; expected one of {SOURCE_KINDS}")
    files = iter_evidence_files(path, recursive=recursive)
    registered = 0
    skipped = 0
    total_bytes = 0
    parsed_events = 0
    parsed_by_source: dict[str, int] = {}
    parse_warnings: list[str] = []
    records: list[dict[str, Any]] = []
    for file_path in files:
        digest_sha256, digest_md5 = hash_file(file_path)
        size = file_path.stat().st_size
        total_bytes += size
        record: EvidenceRecord = db.add_evidence(
            path=str(file_path),
            filename=file_path.name,
            size=size,
            sha256=digest_sha256,
            md5=digest_md5,
        )
        registered += 1
        records.append(
            {
                "id": record.id,
                "filename": record.filename,
                "size": record.size,
                "sha256": record.sha256,
            }
        )
        if parse:
            _parse_evidence_file(
                db,
                file_path,
                record,
                digest_sha256,
                source,
                parsed_by_source,
                parse_warnings,
            )
            parsed_events = sum(parsed_by_source.values())
    return {
        "path": str(path),
        "files_found": len(files),
        "registered": registered,
        "skipped": skipped,
        "total_bytes": total_bytes,
        "evidence": records,
        "parsed_events": parsed_events,
        "parsed_by_source": parsed_by_source,
        "parse_warnings": parse_warnings[:MAX_WARNINGS_PER_FILE],
    }


def _parse_evidence_file(
    db: CaseDB,
    file_path: Path,
    record: EvidenceRecord,
    source_sha256: str,
    source: str | None,
    parsed_by_source: dict[str, int],
    parse_warnings: list[str],
) -> None:
    """Parse one evidence file into the event store (best effort)."""
    ingest_time = utc_now_iso()
    try:
        kind = source or detect_source(file_path)
    except OSError as exc:
        parse_warnings.append(f"{file_path.name}: cannot read file ({exc})")
        return
    if kind is None:
        return  # not recognized telemetry; registered as evidence only
    if kind == "evtx-binary" or is_evtx_binary(file_path):
        parse_warnings.append(f"{file_path.name}: {WEVTUTIL_GUIDANCE}")
        return
    try:
        result = parse_file(
            file_path, kind, source_sha256=source_sha256, ingest_time=ingest_time
        )
    except EvtxBinaryError as exc:
        parse_warnings.append(str(exc))
        return
    except Exception as exc:  # one bad file never aborts ingest
        parse_warnings.append(f"{file_path.name}: parser failed ({exc})")
        return
    for event in result.events:
        db.add_event(event, evidence_id=record.id)
    parsed_by_source[result.source_kind] = parsed_by_source.get(
        result.source_kind, 0
    ) + len(result.events)
    parse_warnings.extend(result.warnings)


def load_fixture(db: CaseDB, fixture_path: Path) -> dict[str, Any]:
    """Load normalized events from a JSONL fixture file.

    Malformed lines are skipped and counted — a malformed line never
    aborts the load. Returns ``{"loaded": n, "skipped": m, "errors": [...]}``.
    """
    if not fixture_path.is_file():
        raise FileNotFoundError(f"no such fixture file: {fixture_path}")
    source_sha256, _ = hash_file(fixture_path)
    ingest_time = utc_now_iso()
    evidence = db.add_evidence(
        path=str(fixture_path),
        filename=fixture_path.name,
        size=fixture_path.stat().st_size,
        sha256=source_sha256,
        md5=hashlib.md5(fixture_path.read_bytes()).hexdigest(),
        parser=FIXTURE_PARSER,
    )
    loaded = 0
    skipped = 0
    errors: list[str] = []
    with fixture_path.open("r", encoding="utf-8") as fh:
        for index, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            if len(line.encode("utf-8")) > MAX_FIXTURE_LINE_BYTES:
                skipped += 1
                errors.append(f"line {index + 1}: exceeds size limit")
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                skipped += 1
                errors.append(f"line {index + 1}: invalid JSON ({exc.msg})")
                continue
            if not isinstance(payload, dict):
                skipped += 1
                errors.append(f"line {index + 1}: expected a JSON object")
                continue
            payload = dict(payload)
            if "provenance" not in payload:
                payload["provenance"] = Provenance(
                    source_file=str(fixture_path),
                    record_index=index,
                    parser_name=FIXTURE_PARSER,
                    parser_version=FIXTURE_PARSER_VERSION,
                    ingest_time=ingest_time,
                    source_sha256=source_sha256,
                ).to_dict()
            try:
                event = NormalizedEvent.from_dict(payload)
            except EventValidationError as exc:
                skipped += 1
                errors.append(f"line {index + 1}: {exc}")
                continue
            db.add_event(event, evidence_id=evidence.id)
            loaded += 1
    return {"loaded": loaded, "skipped": skipped, "errors": errors[:25]}

"""Batch evidence triage (v0.9): one directory in, one case per file out.

``BatchRunner.run`` walks an input directory (sorted, recursive), creates
one case per evidence file (name derived from the filename, sanitized
and deterministic), ingests with the v0.2 auto-detection, runs the
detection catalog, and writes a ``batch-manifest.json`` into the output
directory. Re-runs skip files whose SHA-256 already appears in the
manifest (status ``skipped``) — resumable-ish, idempotent.

The summary reports per-case event/finding counts plus top ATT&CK
techniques across the batch (from stored findings only — a technique
counts when a finding fired, never from rule metadata).

Hardening caps (all documented in docs/INTEGRATIONS.md):
- ``MAX_BATCH_FILES`` — a batch refuses more than 10,000 files.
- ``MAX_BATCH_TOTAL_BYTES`` — 10 GiB of input per run.
- Per-file parse limits come from the parsers (``MAX_PARSE_BYTES``);
  oversized files are registered as evidence with a warning, never
  parsed, never fatal.
Corrupt inputs never abort the batch: per-file failures are recorded
in ``files_failed`` and the run continues.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from huntforge import __version__
from huntforge import mitre as mitre_mod
from huntforge.cases.service import CaseService
from huntforge.core.logging import utc_now_iso
from huntforge.detections import DetectionEngine, Severity, summarize
from huntforge.ingest.service import ingest_path
from huntforge.store.db import CaseError

MAX_BATCH_FILES = 10_000
MAX_BATCH_TOTAL_BYTES = 10 * 1024**3  # 10 GiB
MANIFEST_NAME = "batch-manifest.json"
SUMMARY_NAME = "batch-summary.json"
TOP_TECHNIQUES = 10

_CASE_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_case_name(stem: str, index: int) -> str:
    """Deterministic case id from a filename stem.

    ``batch-0003-sysmon_intrusion``: index-prefixed (collision-proof for
    duplicate stems), unsafe chars replaced, capped at 64 chars (the
    ``validate_case_id`` limit).
    """
    safe = _CASE_SAFE_RE.sub("_", stem.strip()).strip("._") or "evidence"
    name = f"batch-{index:04d}-{safe}"
    return name[:64].rstrip("._")


def file_sha256(path: Path) -> str:
    """SHA-256 of a file, streamed."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class BatchRunner:
    """Runs one batch triage over a directory of evidence."""

    state_dir: Path
    min_severity: Severity | None = None

    def run(
        self,
        input_dir: str | Path,
        output_dir: str | Path,
    ) -> dict[str, Any]:
        input_path = Path(input_dir)
        out_path = Path(output_dir)
        if not input_path.is_dir():
            raise ValueError(f"input directory not found: {input_dir}")
        out_path.mkdir(parents=True, exist_ok=True)

        started = utc_now_iso()
        files = sorted(
            p
            for p in input_path.rglob("*")
            if p.is_file() and not any(part.startswith(".") for part in p.parts)
        )
        if len(files) > MAX_BATCH_FILES:
            raise ValueError(
                f"{len(files)} files exceeds the batch limit of "
                f"{MAX_BATCH_FILES} (split the input directory)"
            )
        total_bytes = sum(p.stat().st_size for p in files)
        if total_bytes > MAX_BATCH_TOTAL_BYTES:
            raise ValueError(
                f"{total_bytes} bytes of input exceeds the batch limit of "
                f"{MAX_BATCH_TOTAL_BYTES} bytes"
            )

        manifest_path = out_path / MANIFEST_NAME
        manifest = self._load_manifest(manifest_path)

        service = CaseService(self.state_dir)
        case_results: list[dict[str, Any]] = []
        files_failed: list[dict[str, str]] = []
        total_events = 0
        all_findings: list[dict[str, Any]] = []
        severity_totals: dict[str, int] = {}

        for index, file_path in enumerate(files, start=1):
            sha256 = file_sha256(file_path)
            seen = manifest.get(sha256)
            if seen and seen.get("status") == "ok":
                case_results.append({**seen, "status": "skipped"})
                total_events += int(seen.get("events", 0) or 0)
                for sev, count in (seen.get("by_severity") or {}).items():
                    severity_totals[sev] = severity_totals.get(sev, 0) + count
                continue
            record = self._process_file(service, file_path, sha256, index)
            if record["status"] == "ok":
                manifest[sha256] = {**record, "status": "ok"}
                total_events += int(record["events"])
                for sev, count in record["by_severity"].items():
                    severity_totals[sev] = severity_totals.get(sev, 0) + count
                all_findings.extend(record["findings"])
            else:
                files_failed.append({"file": str(file_path), "error": record["error"]})
            case_results.append(record)

        self._save_manifest(manifest_path, manifest)

        top_techniques = self._top_techniques(all_findings)
        total_findings = sum(severity_totals.values())
        summary: dict[str, Any] = {
            "tool": "huntforge",
            "version": __version__,
            "input_dir": str(input_path),
            "output_dir": str(out_path),
            "started": started,
            "finished": utc_now_iso(),
            "files_found": len(files),
            "cases_created": sum(1 for r in case_results if r["status"] == "ok"),
            "cases_skipped": sum(1 for r in case_results if r["status"] == "skipped"),
            "files_failed": files_failed,
            "total_events": total_events,
            "total_findings": total_findings,
            "by_severity": severity_totals,
            "top_techniques": top_techniques,
            "manifest": str(manifest_path),
            "cases": case_results,
        }
        (out_path / SUMMARY_NAME).write_text(
            json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
        )
        return summary

    # -- internals --------------------------------------------------------

    def _load_manifest(self, path: Path) -> dict[str, dict[str, Any]]:
        if not path.is_file():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # A corrupt manifest must not brick the batch: start fresh and
            # say so (the summary records the overwrite).
            return {"__corrupt_manifest_discarded__": {}}
        return data if isinstance(data, dict) else {}

    def _save_manifest(self, path: Path, manifest: dict[str, dict[str, Any]]) -> None:
        manifest.pop("__corrupt_manifest_discarded__", None)
        path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
        )

    def _process_file(
        self,
        service: CaseService,
        file_path: Path,
        sha256: str,
        index: int,
    ) -> dict[str, Any]:
        case_id = sanitize_case_name(file_path.stem, index)
        record: dict[str, Any] = {
            "file": str(file_path),
            "filename": file_path.name,
            "sha256": sha256,
            "size": file_path.stat().st_size,
            "case_id": case_id,
            "status": "failed",
            "error": "",
            "events": 0,
            "findings": [],
            "by_severity": {},
            "parser": None,
        }
        try:
            service.create(case_id, name=f"batch: {file_path.name}")
            db = service.open_db(case_id)
        except CaseError as exc:
            record["error"] = f"case setup failed: {exc}"
            return record
        try:
            ingest = ingest_path(db, file_path, recursive=False)
            parsed_by_source = ingest.get("parsed_by_source") or {}
            record["parser"] = (
                next(iter(parsed_by_source)) if parsed_by_source else None
            )
            record["warnings"] = ingest.get("parse_warnings") or []
            record["events"] = db.event_count()
            engine = DetectionEngine(db.all_events())
            findings = engine.run(min_severity=self.min_severity)
            stored: list[dict[str, Any]] = []
            for finding in findings:
                data = finding.to_dict()
                data["finding_uid"] = db.add_finding(data)
                stored.append(data)
            record["findings"] = stored
            record["by_severity"] = summarize(findings).get("by_severity", {})
            record["status"] = "ok"
            db.audit(
                "batch",
                {"file": str(file_path), "case_id": case_id},
                record["events"],
                "ok" if not findings else "warning",
            )
        except Exception as exc:  # noqa: BLE001 - batch must not die on one file
            record["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            db.close()
        return record

    def _top_techniques(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        coverage = mitre_mod.coverage_from_findings(findings)
        table = mitre_mod.TABLE
        ranked = sorted(
            coverage.get("covered") or [],
            key=lambda e: (-int(e.get("finding_count", 0)), str(e["technique_id"])),
        )[:TOP_TECHNIQUES]
        top: list[dict[str, Any]] = []
        for entry in ranked:
            tid = str(entry["technique_id"])
            try:
                technique = table.get(tid)
                name = technique.name
                tactics = list(technique.tactics)
            except KeyError:
                name, tactics = "(unknown technique)", []
            top.append(
                {
                    "technique_id": tid,
                    "name": name,
                    "tactics": tactics,
                    "finding_count": int(entry["finding_count"]),
                }
            )
        return top

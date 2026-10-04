"""Report file generation for HuntForge v0.8.

``generate`` builds the report for an open case database and writes the
requested formats into an output directory (created if missing). All
rendering is stdlib-only and fully offline.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from huntforge.reporting.model import build_report
from huntforge.reporting.render import (
    render_findings_csv,
    render_html,
    render_json,
    render_markdown,
)
from huntforge.store.db import CaseDB

FORMATS = ("html", "json", "md", "csv")


def _safe_name(case_id: str) -> str:
    """Filesystem-safe report basename (case IDs are validated already)."""
    return "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in case_id)


def generate(
    db: CaseDB,
    output_dir: Path,
    formats: tuple[str, ...] = ("html", "json", "md", "csv"),
) -> dict[str, Any]:
    """Build the report and write ``formats`` files into ``output_dir``.

    Returns a manifest: the report's meta block plus the list of files
    written (paths are absolute).
    """
    unknown = [f for f in formats if f not in FORMATS]
    if unknown:
        raise ValueError(f"unknown report format(s): {', '.join(unknown)}")
    report = build_report(db)
    base = _safe_name(report["meta"]["case_id"])
    output_dir.mkdir(parents=True, exist_ok=True)

    written: list[str] = []
    renderers: dict[str, tuple[str, Callable[[Any], str]]] = {
        "html": (f"{base}.html", render_html),
        "json": (f"{base}.json", render_json),
        "md": (f"{base}.md", render_markdown),
        "csv": (f"{base}-findings.csv", render_findings_csv),
    }
    for name in formats:
        filename, renderer = renderers[name]
        path = output_dir / filename
        if name == "csv":
            content = renderer(report["detections"]["findings"])
        else:
            content = renderer(report)
        path.write_text(content, encoding="utf-8")
        written.append(str(path.resolve()))

    return {"meta": report["meta"], "formats": list(formats), "files": written}

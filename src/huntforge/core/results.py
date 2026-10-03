"""Shared result envelope: every command returns this shape.

Human-readable rendering, ``--json`` and ``--csv`` all derive from the
same envelope so automation consumers see a stable contract::

    {
      "tool": "huntforge",
      "version": "0.1.0",
      "command": "events",
      "timestamp": "2026-10-03T02:00:00Z",
      "status": "ok" | "warning" | "error",
      "summary": "human one-liner",
      "data": {... command-specific ...},
      "findings": [...],
      "events": [...]
    }
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from huntforge import __version__
from huntforge.core.logging import utc_now_iso

Status = Literal["ok", "warning", "error"]


@dataclass
class Result:
    command: str
    status: Status = "ok"
    summary: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    tool: str = "huntforge"
    version: str = __version__
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def fail(self, summary: str) -> None:
        self.status = "error"
        self.summary = summary


# Structured exit codes shared by every command.
EXIT_OK = 0  # success
EXIT_FINDINGS = 1  # reserved: success with findings/warnings (v0.5+ detections)
EXIT_ERROR = 2  # usage or operational error


def exit_code_for(result: Result) -> int:
    if result.status == "error":
        return EXIT_ERROR
    if result.status == "warning":
        return EXIT_FINDINGS
    return EXIT_OK

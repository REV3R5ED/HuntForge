"""Curated ATT&CK technique table (v0.6).

The table ships as ``techniques.json`` inside this package — a local,
versioned snapshot, loaded with :mod:`importlib.resources` so it works
from a source checkout and an installed wheel alike.

This is a *curated subset* for endpoint forensics, not the full
ATT&CK matrix. The metadata block records which ATT&CK snapshot it
was curated from. Technique IDs are stable references; names, tactic
assignments, and descriptions are HuntForge's own summaries.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources
from typing import Any

TABLE_FILE = "techniques.json"

_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


@dataclass(frozen=True)
class Technique:
    """One curated ATT&CK technique."""

    id: str
    name: str
    tactics: list[str]
    description: str
    huntforge_sources: list[tuple[str, str]]
    detection_notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "tactics": list(self.tactics),
            "description": self.description,
            "huntforge_sources": [
                {"source": s, "event_id": e} for s, e in self.huntforge_sources
            ],
            "observable": bool(self.huntforge_sources),
            "detection_notes": self.detection_notes,
        }


@dataclass(frozen=True)
class TechniqueTable:
    """The loaded table plus its snapshot metadata."""

    techniques: list[Technique]
    attack_snapshot: str
    data_version: str
    note: str = ""

    def get(self, technique_id: str) -> Technique:
        """Look up a technique by ID (case-insensitive); KeyError if unknown."""
        needle = technique_id.strip().upper()
        for technique in self.techniques:
            if technique.id.upper() == needle:
                return technique
        raise KeyError(f"unknown technique {technique_id!r}")

    def ids(self) -> list[str]:
        return [t.id for t in self.techniques]

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_snapshot": self.attack_snapshot,
            "data_version": self.data_version,
            "technique_count": len(self.techniques),
            "note": self.note,
            "techniques": [t.to_dict() for t in self.techniques],
        }


def _validate(raw: dict[str, Any]) -> None:
    """Structural validation of the table; ValueError on any problem."""
    if not isinstance(raw, dict):
        raise ValueError("technique table must be a JSON object")
    metadata = raw.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError("technique table needs a 'metadata' object")
    for key in ("attack_snapshot", "data_version"):
        if not metadata.get(key):
            raise ValueError(f"technique table metadata needs {key!r}")
    techniques = raw.get("techniques")
    if not isinstance(techniques, list) or not techniques:
        raise ValueError("technique table needs a non-empty 'techniques' list")
    seen: set[str] = set()
    for index, item in enumerate(techniques):
        where = f"techniques[{index}]"
        if not isinstance(item, dict):
            raise ValueError(f"{where} must be an object")
        tid = item.get("id")
        if not isinstance(tid, str) or not _ID_RE.match(tid):
            raise ValueError(f"{where}.id must look like 'T1059' or 'T1059.001'")
        if tid in seen:
            raise ValueError(f"duplicate technique id {tid!r}")
        seen.add(tid)
        for key in ("name", "description"):
            if not item.get(key) or not isinstance(item[key], str):
                raise ValueError(f"{where} needs a non-empty {key!r}")
        tactics = item.get("tactics")
        if (
            not isinstance(tactics, list)
            or not tactics
            or not all(isinstance(t, str) and t for t in tactics)
        ):
            raise ValueError(f"{where}.tactics must be a non-empty string list")
        sources = item.get("huntforge_sources", [])
        if not isinstance(sources, list):
            raise ValueError(f"{where}.huntforge_sources must be a list")
        for source in sources:
            if (
                not isinstance(source, list)
                or len(source) != 2
                or not all(isinstance(part, str) and part for part in source)
            ):
                raise ValueError(
                    f"{where}.huntforge_sources entries must be "
                    "[source, event_id] string pairs"
                )


def load_table() -> TechniqueTable:
    """Load and validate the bundled technique table."""
    data = (resources.files(__package__) / TABLE_FILE).read_text(encoding="utf-8")
    raw = json.loads(data)
    _validate(raw)
    metadata = raw["metadata"]
    techniques = [
        Technique(
            id=item["id"],
            name=item["name"],
            tactics=list(item["tactics"]),
            description=item["description"],
            huntforge_sources=[
                (source[0], source[1]) for source in item.get("huntforge_sources", [])
            ],
            detection_notes=item.get("detection_notes", ""),
        )
        for item in raw["techniques"]
    ]
    return TechniqueTable(
        techniques=sorted(techniques, key=lambda t: t.id),
        attack_snapshot=str(metadata["attack_snapshot"]),
        data_version=str(metadata["data_version"]),
        note=str(metadata.get("note", "")),
    )


# Validated once at import: a corrupt bundled table is a build-time bug,
# and failing fast beats serving a half-loaded matrix.
TABLE = load_table()

#: Every technique ID the table knows, for mapping-completeness checks.
KNOWN_IDS = frozenset(TABLE.ids())

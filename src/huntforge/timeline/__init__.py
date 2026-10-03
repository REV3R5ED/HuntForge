"""Unified timeline, process lineage, and entity resolution (v0.4).

All three tools are **observation** tools: they reorganize what was
ingested — they never invent timestamps, never merge ambiguous
process instances silently, and never label activity malicious
(detections are v0.5).

- :mod:`huntforge.timeline.timeline` — one chronological view across
  every ingested source. Events whose parsers could not recover an
  original timestamp (``timestamp_original`` is empty — the stored
  timestamp is just the ingest time) are listed in a separate
  "untimed" section: never dropped, never placed on the timeline.
- :mod:`huntforge.timeline.lineage` — parent→child process trees
  from Sysmon EventID 1 / Security 4688 creation records. PID reuse
  is handled honestly: a PID observed starting different images at
  different times becomes separate instances, and a child whose
  parent PID has several candidates is linked to the latest-plausible
  one with an explicit ambiguity note.
- :mod:`huntforge.timeline.entities` — cross-source entity
  normalization (hosts case-insensitive, ``DOMAIN\\user`` →
  ``user@domain``, file paths case-insensitive, hashes lowercased)
  with per-source observation counts.
"""

from __future__ import annotations

from huntforge import __version__
from huntforge.core import plugins as plugins_mod
from huntforge.timeline import entities as entities_mod
from huntforge.timeline import lineage as lineage_mod
from huntforge.timeline import timeline as timeline_mod

TIMELINE_VERSION = "0.4.0"


def ensure_registered() -> None:
    """Register the timeline module with the plugin registry (idempotent)."""
    try:
        plugins_mod.register(
            plugins_mod.ModuleInfo(
                name="timeline",
                description=(
                    "Unified cross-source timeline, process lineage "
                    "trees, and entity resolution (observation only)"
                ),
                version=TIMELINE_VERSION,
                commands=["timeline", "lineage", "entities"],
            )
        )
    except ValueError:
        pass  # already registered


ensure_registered()

__all__ = [
    "TIMELINE_VERSION",
    "ensure_registered",
    "entities_mod",
    "lineage_mod",
    "timeline_mod",
    "__version__",
]

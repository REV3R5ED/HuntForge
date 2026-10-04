"""Case management reporting for HuntForge (v0.8).

- :mod:`huntforge.reporting.model` — the case report model: assembles
  case metadata, evidence, timeline highlights, process lineage,
  detections (OBSERVED/INFERRED labeled), ATT&CK coverage, correlations,
  entities, analyst notes, methodology, limitations, and chain of
  custody. The executive summary is machine-generated and marked as
  requiring analyst review.
- :mod:`huntforge.reporting.render` — stdlib-only renderers: JSON,
  Markdown, self-contained offline HTML (inline CSS, no external
  assets), and a formula-injection-safe CSV findings export.
- :mod:`huntforge.reporting.notes` — analyst note service (add/list).
- :mod:`huntforge.reporting.report` — file generation into an output
  directory.
"""

from __future__ import annotations

from huntforge import __version__
from huntforge.core import plugins as plugins_mod
from huntforge.reporting import model as model_mod
from huntforge.reporting import notes as notes_mod
from huntforge.reporting import render as render_mod
from huntforge.reporting import report as report_mod

REPORTING_VERSION = "1.0.0"


def ensure_registered() -> None:
    """Register the reporting module with the plugin registry (idempotent)."""
    try:
        plugins_mod.register(
            plugins_mod.ModuleInfo(
                name="reporting",
                description=(
                    "Case reports (HTML/JSON/Markdown/CSV) and analyst "
                    "notes; observations vs inferences labeled"
                ),
                version=REPORTING_VERSION,
                commands=["report", "notes"],
            )
        )
    except ValueError:
        pass  # already registered


ensure_registered()

__all__ = [
    "REPORTING_VERSION",
    "ensure_registered",
    "model_mod",
    "notes_mod",
    "render_mod",
    "report_mod",
    "__version__",
]

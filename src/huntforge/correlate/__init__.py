"""Cross-source correlation engine (v0.7).

Joins findings, events, and entities ACROSS sources into attack
narratives: a process-creation event (Sysmon 1) + its prefetch entry +
its persistence mechanism (Run key/task/service) + its network
connection become one correlated "activity cluster" with a timeline.

Every linkage is INFERRED — a deterministic, explainable hypothesis
with a confidence, a reason, and documented failure modes. Observed
events are facts; the links between them are not. The narrative keeps
the two in separate sections, and every cluster carries a "what's
missing" section naming evidence that would be expected but was not
observed.
"""

from __future__ import annotations

from huntforge import __version__
from huntforge.core import plugins as plugins_mod
from huntforge.correlate import engine as engine_mod
from huntforge.correlate import linkages as linkages_mod
from huntforge.correlate import model as model_mod

CORRELATE_VERSION = "0.7.0"


def ensure_registered() -> None:
    """Register the correlate module with the plugin registry (idempotent)."""
    try:
        plugins_mod.register(
            plugins_mod.ModuleInfo(
                name="correlate",
                description=(
                    "Cross-source correlation: activity clusters and "
                    "attack narratives (linkages are INFERRED)"
                ),
                version=CORRELATE_VERSION,
                commands=["correlate", "narrative"],
            )
        )
    except ValueError:
        pass  # already registered


ensure_registered()

__all__ = [
    "CORRELATE_VERSION",
    "ensure_registered",
    "engine_mod",
    "linkages_mod",
    "model_mod",
    "__version__",
]

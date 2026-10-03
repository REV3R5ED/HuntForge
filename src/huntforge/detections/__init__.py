"""Explainable detection rules (v0.5).

Registers the ``detections`` module and re-exports the public API:
the rule catalog, the engine, and the finding/severity model.
"""

from huntforge import __version__
from huntforge.core import plugins as plugins_mod
from huntforge.detections.engine import DetectionEngine, select_rules, summarize
from huntforge.detections.model import (
    EvidenceRef,
    Finding,
    Rule,
    Severity,
)
from huntforge.detections.rules import RULES, get_rule, list_rules

plugins_mod.register(
    plugins_mod.ModuleInfo(
        name="detections",
        description="Explainable detection rules over normalized events",
        version=__version__,
        commands=["detect", "rules"],
    )
)

__all__ = [
    "DetectionEngine",
    "EvidenceRef",
    "Finding",
    "RULES",
    "Rule",
    "Severity",
    "get_rule",
    "list_rules",
    "select_rules",
    "summarize",
]

"""Sigma-subset rule support (v0.6).

Load Sigma-inspired rules (JSON, or best-effort YAML via the subset
parser) and evaluate them over normalized events. See
:mod:`huntforge.sigma.model` for the documented supported subset.
"""

from pathlib import Path
from typing import Any

from huntforge import __version__
from huntforge.core import plugins as plugins_mod
from huntforge.sigma.engine import evaluate_rule
from huntforge.sigma.loader import load_rule_file, technique_ids_from_tags
from huntforge.sigma.model import SigmaError, SigmaRule

plugins_mod.register(
    plugins_mod.ModuleInfo(
        name="sigma",
        description="Sigma-subset rule loading and evaluation",
        version=__version__,
        commands=["sigma"],
    )
)

__all__ = [
    "SigmaError",
    "SigmaRule",
    "evaluate_rule",
    "list_samples",
    "load_rule_file",
    "technique_ids_from_tags",
]


def list_samples() -> list[dict[str, Any]]:
    """Bundled sample rules (loaded; entries carry errors, never raise)."""
    samples_dir = Path(__file__).parent / "samples"
    entries: list[dict[str, Any]] = []
    for path in sorted(samples_dir.glob("*")):
        if path.suffix.lower() not in (".json", ".yaml", ".yml"):
            continue
        try:
            rule = load_rule_file(path)
            entry = rule.to_dict()
            entry["techniques"] = technique_ids_from_tags(rule.tags)
        except SigmaError as exc:
            entry = {"file": path.name, "error": str(exc)}
        entries.append(entry)
    return entries

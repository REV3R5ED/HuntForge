"""HuntForge — endpoint threat-hunting and Windows forensics platform.

"Hunt the endpoint. Reconstruct the attack."

v0.5 adds explainable detection rules over the normalized event model:
ten named, versioned rules with full evidence chains, confidence with
reasoning, and observed-vs-inferred separation. No verdicts are final —
the analyst decides.

v0.6 adds MITRE ATT&CK mapping (curated local technique table, every
detection rule mapped, case coverage views) and Sigma-subset rule
support (documented JSON schema plus a best-effort YAML importer).

v0.7 adds cross-source correlation: deterministic, explainable linkage
heuristics (same-process, same-file, persistence-execution,
download-execution) join events into activity clusters; each cluster
gets an attack narrative with the observed timeline, the INFERRED
linkages, detections, techniques, and a "what's missing" section.

v0.8 adds case reporting: structured HTML/JSON/Markdown reports plus a
formula-safe CSV findings export, analyst notes stored in the case,
and chain-of-custody appendices. The executive summary is
machine-generated and marked as requiring analyst review; observed
facts and inferences stay labeled.

v0.9 adds batch triage (one case per evidence file, resumable via a
manifest), JSONL export for SIEM ingestion, an analyst config file
(``~/.huntforge/config.toml``), and a hardening pass: input size caps
are documented and corrupt inputs never abort a run.
"""

__version__ = "0.9.0"
__author__ = "Pouya Shini Karim"

from huntforge.core import appconfig, config, logging, plugins, results

__all__ = [
    "__version__",
    "appconfig",
    "config",
    "logging",
    "plugins",
    "results",
]

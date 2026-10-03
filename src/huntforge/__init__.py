"""HuntForge — endpoint threat-hunting and Windows forensics platform.

"Hunt the endpoint. Reconstruct the attack."

v0.5 adds explainable detection rules over the normalized event model:
ten named, versioned rules with full evidence chains, confidence with
reasoning, and observed-vs-inferred separation. No verdicts are final —
the analyst decides.

v0.6 adds MITRE ATT&CK mapping (curated local technique table, every
detection rule mapped, case coverage views) and Sigma-subset rule
support (documented JSON schema plus a best-effort YAML importer).
"""

__version__ = "0.6.0"
__author__ = "Pouya Shini Karim"

from huntforge.core import config, logging, plugins, results

__all__ = [
    "__version__",
    "config",
    "logging",
    "plugins",
    "results",
]

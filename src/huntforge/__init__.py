"""HuntForge — endpoint threat-hunting and Windows forensics platform.

"Hunt the endpoint. Reconstruct the attack."

v0.5 adds explainable detection rules: a unified cross-source timeline
(UTC-normalized, originals preserved, untimed events never dropped),
process lineage trees with honest PID-reuse handling, and
cross-source entity resolution. No verdicts — detections are v0.5.
"""

__version__ = "0.5.0"
__author__ = "Pouya Shini Karim"

from huntforge.core import config, logging, plugins, results

__all__ = [
    "__version__",
    "config",
    "logging",
    "plugins",
    "results",
]

"""HuntForge — endpoint threat-hunting and Windows forensics platform.

"Hunt the endpoint. Reconstruct the attack."

v0.3 is persistence artifacts: Prefetch (.pf) binaries, offline
registry hives (Run/RunOnce scan, targeted reads via ``huntforge
registry``), scheduled-task XML exports and service enumerations.
"""

__version__ = "0.3.0"
__author__ = "Pouya Shini Karim"

from huntforge.core import config, logging, plugins, results

__all__ = [
    "__version__",
    "config",
    "logging",
    "plugins",
    "results",
]

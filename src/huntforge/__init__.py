"""HuntForge — endpoint threat-hunting and Windows forensics platform.

"Hunt the endpoint. Reconstruct the attack."

v0.1: architectural foundation — core CLI, the normalized event model
(the v1.0-stable core everything else builds on), a per-case SQLite
event store, JSON output everywhere, and provenance on every event.

Later phases (v0.2+ parsers, v0.4 timeline, v0.5 detections, v0.6
ATT&CK/Sigma, v0.7 correlation, v0.8 cases/reports, v0.9 UI, v1.0
stable schemas) plug into the models defined here.
"""

__version__ = "0.1.0"
__author__ = "Pouya Shini Karim"

from huntforge.core import config, logging, plugins, results

__all__ = [
    "__version__",
    "config",
    "logging",
    "plugins",
    "results",
]
